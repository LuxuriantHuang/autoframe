import glob
import subprocess
import tempfile
import time
from asyncio import as_completed
from collections import deque
from concurrent.futures.thread import ThreadPoolExecutor

import ujson
from tqdm import tqdm

from config import *
from pyTracer import SeedTracer, InfoProcessor, cfg_loader

logger = logging.getLogger(LOGGER_NAME + __name__)


def afl_cov(prog, input_dir):
    with tempfile.NamedTemporaryFile() as f:
        cov_file = f.name
        cmd = [SHOWMAP_PATH, '-q', '-i', input_dir, '-o', cov_file, '-m', 'none', '-C', '--', prog, '@@']
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={'AFL_QUIET': '1'},
        )
        with open(cov_file, 'r') as f:
            return set(l.strip() for l in f)


class CoverageTracer:
    def __init__(self, input_dir, output_dir, fuzzing_args, target_prog):
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
        self.info = InfoProcessor.InfoProcesser()
        self.cfg_loader = None

    def get_edge_count(self):
        if not SHOWMAP_PATH.exists():
            logger.error(f"afl-showmap not found at {SHOWMAP_PATH}")
        combined_cov = {}
        with ThreadPoolExecutor(max_workers=64) as executor:
            worklist = []
            for file in glob.glob(self.output_dir / "default" / "queue" / "*"):
                if not Path(file).is_file():
                    continue
                worklist.append(file)
            futures = {}
            progress = tqdm(total=len(worklist), desc="Coverage")
            for file in worklist:
                future = executor.submit(afl_cov, self.target_prog, file)
                futures[future] = file
                future.add_done_callback(lambda _: progress.update)
            for future in as_completed(futures):
                file = futures[future]
                cov = future.result()
                combined_cov[file] = cov
            progress.close()

        cov_dict = {}
        for file, cov in combined_cov.items():
            if file not in cov_dict:
                cov_dict[file] = {}
            cov_dict[file] = list(cov)
        with open("test_cov", 'w') as f:
            ujson.dump(cov_dict, f)

    def check_coverage_growth(self) -> int:
        """通过滑动窗口获得瓶颈时间"""
        # 需要调用get_edge_count获得当前瓶颈，并利用时间基本单位返回统计的瓶颈时间(s)
        

    def get_trace(self, read_files: set, last_scan_time: int):  # 后续修改为多进程
        st = time.time()
        seed_dir = Path.joinpath(self.output_dir, FUZZER_NAME, "queue")
        seed_lst_to_run, resume_data_to_load, last_scan_time = get_new_seeds(seed_dir, read_files, last_scan_time)
        if len(seed_lst_to_run) <= 0:
            logging.error("为什么在没有更新的情况下触发了get_trace？")
            return False, last_scan_time, "在没有更新的情况下触发了get_trace", None
        seed_tracer = SeedTracer.SeedTracer(self.target_prog, " ".join(self.fuzzing_args))
        logger.info(f"本次添加共{len(seed_lst_to_run)}个新种子")
        for (i, seed_path) in tqdm(enumerate(seed_lst_to_run), total=len(seed_lst_to_run)):
            trace_data, retcode = seed_tracer.trace_seed(str(seed_path), TIMEOUT)
            logger.info(f"Tracer {i}: 完成种子覆盖信息采集")
            self.info.add(trace_data, )
            logger.info(f"Tracer {i}: 完成种子覆盖整合")
        return True, last_scan_time, ""

    def free(self):
        self.map.detach()

    def get_roadblocks(self, bb, static_path) -> list:
        if not self.cfg_loader:
            self.cfg_loader = cfg_loader.CFGLoader(bb, static_path)
        self.cfg_loader.read_freq(self.info.bitmap.bitmap)
        self.cfg_loader.build_graph(bb)
        self.cfg_loader.calculate_depth()
        bottlenecks = [x for x in self.cfg_loader.get_roadblocks(DEPTH_THRESHOLD)]
        self.cfg_loader.dump(bottlenecks)
        return bottlenecks[:10]

    def get_rb_seed(self, roadblock_id):
        # 去数据库中搜索种子名
        pass

    def get_slice(self, roadblock, seed):
        # 使用treesitter切出源语言相关代码切片
        pass


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
