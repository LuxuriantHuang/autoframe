import os
import subprocess
import tempfile
from collections import deque

from tqdm import tqdm

from config import *
from pyTracer import SeedTracer, InfoProcessor, cfg_loader

logger = logging.getLogger(LOGGER_NAME + __name__)


def afl_cov(prog, input_dir):
    with tempfile.NamedTemporaryFile() as f:
        cov_file = f.name
        cmd = [SHOWMAP_PATH, '-q', '-i', input_dir, '-o', cov_file, '-m', 'none', '-t', '5000', '-C', '--', prog, '@@']
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={'AFL_QUIET': '1'}
        )
        with open(cov_file, 'r') as f:
            return set(l.strip() for l in f)


def get_all_call_chains(data, target_function_name):
    functions = data["functions"]
    # 找到目标函数
    target_function = find_function_by_name(functions, target_function_name)
    if not target_function:
        return f"Error: Function {target_function_name} not found."

    target_id = target_function["id"]
    all_chains = []
    visited = set()  # 用于记录访问过的函数 ID

    # 从目标函数开始递归查找所有调用链
    visited.add(target_id)
    find_all_call_chains(functions, target_id, [target_function_name], all_chains, visited)

    # 格式化结果
    # ret = []
    for chain in all_chains:
        if chain[0] == "main":
            return chain


def find_function_by_name(functions, target_name):
    """根据函数名找到函数的字典和ID"""
    for func in functions:
        if func["name"] == target_name:
            return func
    return None


def find_all_call_chains(functions, target_id, current_chain, all_chains, visited):
    """递归查找所有调用链，避免循环调用"""
    has_caller = False
    for func in functions:
        if target_id in func["calls"] and func["id"] not in visited:
            visited.add(func["id"])  # 标记当前函数为已访问
            has_caller = True
            find_all_call_chains(functions, func["id"], [func["name"]] + current_chain, all_chains, visited)

    # 如果没有调用者，说明到达了根函数
    if not has_caller:
        all_chains.append(current_chain)


def get_call_chain(roadblock):
    bb = next((item for item in bbs if item.get("id") == roadblock), None)
    f = next((item for item in funcs if item.get("id") == bbs["function"]), None)
    fname = f["name"]
    call_chain = get_all_call_chains(static, fname)
    return call_chain


def get_code_snippet(call_chain: list, bottleneck_id):
    code_snippet = ""
    for i, fname in enumerate(call_chain):
        f = next((item for item in funcs if item.get("name") == fname), None)
        file = f['file_name']
        start = f['lineStart']
        end = f['lineEnd']
        with open(os.path.join('/', 'root', 'Project', 'src', file)) as f:
            code = f.readlines()
        function_snippet_list = code[start - 1:end]
        function_snippet = ''.join(function_snippet_list)
        code_snippet += function_snippet
        if i == len(call_chain) - 1:
            bcode = code[bbs[int(bottleneck_id)]['lineEnd'] - 1]
    return code_snippet, bcode


class CoverageTracer:
    def __init__(self, input_dir, output_dir, fuzzing_args, target_prog, trace_prog, bb, func):
        # self.shm_id = os.getenv(AFL_MAP_SHM_ENV)
        # if not self.shm_id:
        #     logger.error(f"环境变量${AFL_MAP_SHM_ENV}未配置，请先运行AFL再进行配置")
        #     raise EnvironmentError(f"环境变量${AFL_MAP_SHM_ENV}未配置，请先运行AFL再进行配置")
        # self.shm_id = int(self.shm_id)
        # logger.info(f"共享内存id：${self.shm_id}")

        # self.map = sysv_ipc.SharedMemory(self.shm_id)

        self.coverage_history = deque(maxlen=WINDOW_SIZE)
        self.last_coverage = 0
        self.last_growth_time = time.time()

        self.input_dir = input_dir
        self.output_dir = output_dir
        self.fuzzing_args = fuzzing_args
        self.target_prog = target_prog
        self.trace_prog = trace_prog
        self.info = InfoProcessor.InfoProcesser(STATIC_PATH)
        self.bb = bb
        self.func = func
        self.cfg_loader = None

    def get_edge_count(self) -> set:
        if not SHOWMAP_PATH.exists():
            logger.error(f"afl-showmap not found at {SHOWMAP_PATH}")
        return afl_cov(prog=self.target_prog, input_dir=self.input_dir)

    def check_coverage_growth(self):
        """通过滑动窗口获得瓶颈时间"""
        # 需要调用get_edge_count获得当前瓶颈，并利用时间基本单位返回统计的瓶颈时间(s)
        cov = self.get_edge_count()
        current_coverage = len(cov)
        growth = current_coverage - self.last_coverage
        now = time.time()
        self.coverage_history.append((now, current_coverage))
        if growth > THRESHOLD_COV_DELTA:
            logger.info(f"覆盖率增加到 {current_coverage} (新增 {growth} 条路径)")
            self.last_coverage = current_coverage
            self.last_growth_time = now
            return 0
        else:
            stagnation_time = now - self.last_growth_time
            logger.debug(f"无增长时间: {stagnation_time:.1f}s")
            return stagnation_time

    def get_trace(self, read_files: set, last_scan_time: int):  # 后续修改为多进程
        st = time.time()
        seed_dir = Path.joinpath(self.output_dir, FUZZER_NAME, "queue")
        seed_lst_to_run, resume_data_to_load, last_scan_time = get_new_seeds(seed_dir, read_files, last_scan_time)
        if len(seed_lst_to_run) <= 0:
            logging.error("为什么在没有更新的情况下触发了get_trace？")
            return False, last_scan_time, "在没有更新的情况下触发了get_trace"
        seed_tracer = SeedTracer.SeedTracer(self.trace_prog, " ".join(self.fuzzing_args))
        logger.info(f"本次添加共{len(seed_lst_to_run)}个新种子")
        for (i, seed_path) in tqdm(enumerate(seed_lst_to_run), total=len(seed_lst_to_run)):
            trace_data, retcode = seed_tracer.trace_seed(str(seed_path), TIMEOUT)
            logger.info(f"Tracer {i}: 完成种子覆盖信息采集")
            self.info.add(trace_data, bbs, "default", seed_path)
            logger.info(f"Tracer {i}: 完成种子覆盖整合")
        return True, last_scan_time, ""

    def get_roadblocks(self, static_path) -> list:
        if not self.cfg_loader:
            self.cfg_loader = cfg_loader.CFGLoader(self.bb, static_path)
        self.cfg_loader.read_freq(self.info.bitmap.bitmap)
        self.cfg_loader.build_graph(bbs)
        self.cfg_loader.calculate_depth()
        bottlenecks = [x for x in self.cfg_loader.get_roadblocks(DEPTH_THRESHOLD)]
        self.cfg_loader.dump(bottlenecks)
        return bottlenecks[:10]

    def get_rb_seed(self, roadblock_id):
        # 去数据库中搜索种子名(直接本地搜索？)
        hit_seed = self.info.hit_seed.hit_seed
        rb_seeds = hit_seed[roadblock_id]
        return rb_seeds

    def get_slice(self, roadblock, seed):
        # 使用treesitter切出源语言相关代码切片(目前为单纯的调用链提取)
        call_chain = get_call_chain(roadblock)
        code_snippet, bcode = get_code_snippet(call_chain, roadblock)
        return call_chain, code_snippet, bcode

    def get_rb_file_and_line(self, roadblock):
        rb_bb = self.bb[roadblock]
        rb_line = rb_bb["lineEnd"]
        rb_file = self.func[rb_bb["function"]]['file_name']
        return rb_file, int(rb_line)


def get_new_seeds(directory, read_files, last_scan_time):  # 添加去数据库找的功能
    files_to_run = []
    files_to_load = []
    sorted_pathdir = sorted(Path(directory).iterdir())
    for file_path in sorted_pathdir:
        if file_path.is_file() and file_path.stat().st_ctime_ns > last_scan_time and file_path not in read_files:
            ''' last scan time and read_files should not influence by resume data'''
            last_scan_time = max(last_scan_time, file_path.stat().st_mtime)
            read_files.add(file_path)
            # if rerun == False:
            #     resume_data_dir = Path.joinpath(Path(OUTPUT_PATH), "single", file_path.name)
            #     if resume_data_dir.exists() and check_resume_data(resume_data_dir):
            #         files_to_load.append(resume_data_dir)
            #         continue
            files_to_run.append(file_path)

    return files_to_run, files_to_load, last_scan_time
