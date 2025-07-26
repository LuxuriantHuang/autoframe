import os
import random
import re
import sys
import traceback

from CoverageTracer import CoverageTracer
from DSE_util import DSEUtil
from Excep.ScriptExtractError import ScriptExtractError
from Excep.ScriptNotFoundError import ScriptNotFoundError
from Excep.SeedNotFoundError import SeedNotFoundError
from FuzzerRunner import FuzzerRunner
from LLM.LLMUtil import LLMUtil, extract_generator, run_generator, get_coverage_report
from config import *


def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(LOGGING_LEVEL)

    os.makedirs(LOG_PATH, exist_ok=True)
    formatter = logging.Formatter(LOGGING_FORMAT)

    handler = logging.FileHandler(Path(LOG_PATH) / LOGGER_FILE_NAME)
    handler.setLevel(LOGGING_LEVEL)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(LOGGING_LEVEL)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


# def parse_args():
#     parse = ArgumentParser(description="The automation framework of fuzzing with LLM and Symbolic exec")
#     parse.add_argument("-i", dest="input_dir", required=True, type=valid_path, help="init corpus path")
#     parse.add_argument("-o", dest="output_dir", required=True, type=Path, help="fuzzing output path")
#     parse.add_argument("-a", dest="fuzzing_args", required=True, type=str, help="fuzzing args")
#     parse.add_argument("-t", dest="target_prog", required=True, type=valid_path, help="program under test path")
#     parse.add_argument("-t1", dest="trace_prog", required=True, type=valid_path, help="trace program under test path")
#     return parse.parse_args()


pass_roadblock = []


def extract_and_test(llm_util, resp, roadblock, seed_id, freq_global):
    global pass_roadblock
    global fuzzer, input_dir, output_dir, fuzzing_args, target_prog, trace_prog
    logger.info("extracting python script")
    script = extract_generator(resp)
    logger.info("running python script")
    stdout, stderr, new_seed_path = run_generator(script, roadblock, seed_id)
    while stderr:
        logger.info("fixing python scripts")
        fix_resp = llm_util.fix_chat(script, stderr)
        if "Error fixing seed" in fix_resp:
            continue
        fixed_generator_script = extract_generator(fix_resp)
        stdout, stderr, new_seed_path = run_generator(script, roadblock, seed_id)
        script = fixed_generator_script
    pattern = re.compile(r"id:(\d+),bid:(\d+)")
    match = re.match(pattern, Path(new_seed_path).name)
    if not match:
        raise SeedNotFoundError("种子命名格式不对")
    solved, execution_path, not_exec_bid = llm_util.test_seed(Path(new_seed_path).name, roadblock,
                                                              freq_global, trace_prog)
    return solved, execution_path, not_exec_bid, script


def handle_roadblock(roadblock, tracer: CoverageTracer, dse_util, llm_util: LLMUtil, freq_global):
    global pass_roadblock
    global fuzzer, input_dir, output_dir, fuzzing_args, target_prog, trace_prog
    logger.info(f"正处理roadblock{roadblock}")
    seeds = tracer.get_rb_seed(roadblock)
    rb_file, rb_line, rb_fname = tracer.get_rb_file_and_line(roadblock)

    for seed in random.sample(sorted(seeds), min(DSE_SEEDS_NUM, len(seeds))):
        logger.info(f"正使用seed{seed}进行突破")

        call_chain, code_slice, bcode = tracer.get_slice(roadblock, seed)
        logger.info(f"本次执行的call_chain：{'->'.join(call_chain)}")
        os.makedirs(LLM_TMP_PATH, exist_ok=True)
        seed_id = len(os.listdir(LLM_TMP_PATH))

        solved, times = False, 0
        script = None
        try:
            logger.info("start generate python script")
            first_resp = llm_util.first_solve(code_slice, call_chain, bcode)
            if "Error generating seed" in first_resp:
                times += 1
                continue
            solved, execution_path, not_exec_bid, script = extract_and_test(llm_util, first_resp, roadblock, seed_id,
                                                                            freq_global)
            if solved:
                pass_roadblock.append(roadblock)
                break
            rb_info = {"file": rb_file, "func_name": rb_fname, "code": rb_line}
            while not solved and times < MAX_TIME:
                coverage = get_coverage_report(execution_path, call_chain)
                advice = llm_util.get_advice(rb_info, not_exec_bid, coverage, script)
                improve_resp = llm_util.improve_script(script, coverage, advice)
                if "Error improve script" in improve_resp:
                    times += 1
                    continue
                solved, execution_path, not_exec_bid, script = extract_and_test(llm_util, first_resp, roadblock,
                                                                                seed_id, freq_global)

        except ScriptNotFoundError:
            # 利用大模型更正为包含代码的script
            pass
        except ScriptExtractError:
            # 重试跑脚本
            pass

        if solved:
            logger.info(f"Bottleneck {roadblock} is resolved.")
            return True, "LLM", id

    return False, "", -1


def resolve_coverage_stuck(tracer: CoverageTracer, last_scan_time, read_files):
    global pass_roadblock
    global fuzzer, input_dir, output_dir, fuzzing_args, target_prog, trace_prog
    ret, last_scan_time, error_info, freq_global = tracer.get_trace(read_files, last_scan_time)  # 慢，如何解决
    if not ret:
        logger.fatal(error_info)
        # raise Exception(error_info)

    roadblocks = tracer.get_roadblocks(STATIC_PATH)
    dse_util = DSEUtil()
    # llm_util = LLM_util(MODEL, API_KEY, BASE_URL)
    llm_util = LLMUtil(MODEL, API_KEY, BASE_URL)

    roadblocks = [rb for rb in roadblocks if rb not in pass_roadblock][:10]

    if not roadblocks:
        logger.info("没有roadblock需要突破了，程序即将退出")
        sys.exit(0)
    logger.info(f"roadblocks: {roadblocks}")
    for roadblock in roadblocks:
        ret, mode, id = handle_roadblock(roadblock, tracer, dse_util, llm_util, freq_global)
        if ret:
            if mode == "DSE":
                fuzzer.add_seed_DSE()
            else:
                fuzzer.add_seed_LLM(id, roadblock)
            return True, last_scan_time, read_files  # 成功解决了一个瓶颈，返回继续运行

    return False, last_scan_time, read_files  # 所有瓶颈都未能解决


def main():
    global fuzzer, input_dir, output_dir, fuzzing_args, target_prog, trace_prog
    # args = parse_args()
    read_files = set()  # 记录已读取的文件集合
    last_scan_time = 0  # 记录上次扫描时间戳
    input_dir = os.fspath(PROJECT_HOME / "in")
    output_dir = os.fspath(PROJECT_HOME / "out")
    fuzzing_args = EXEC_ARGS.split(sep=" ")
    target_prog = PROJECT_HOME / "target" / "afl" / f"{PROJECT}_fuzz"
    trace_prog = PROJECT_HOME / "target" / "trace" / f"{PROJECT}_trace"
    # input_dir = args.input_dir
    # output_dir = args.output_dir
    # fuzzing_args = args.fuzzing_args.split(sep=" ")
    # target_prog = args.target_prog
    # trace_prog = args.trace_prog
    logger.info(f"本次运行中，input_dir：{input_dir}")
    logger.info(f"本次运行中，output_dir：{output_dir}")
    logger.info(f"本次运行中，fuzzing_args：{EXEC_ARGS}")
    logger.info(f"本次运行中，target_prog：{target_prog}")
    logger.info(f"本次运行中，trace_prog：{trace_prog}")
    # with FuzzerRunner(input_dir, output_dir, target_prog, fuzzing_args) as fuzzer:
    fuzzer = FuzzerRunner(input_dir, output_dir, target_prog, fuzzing_args)
    if not test:
        fuzzer.run()
    logger.info("fuzzer已开始运行")
    time.sleep(1)  # 尚未生成种子，需要缓冲时间
    try:
        tracer = CoverageTracer(input_dir, output_dir, fuzzing_args, target_prog, trace_prog, bbs, funcs)
        while True:
            stuck_time = tracer.check_coverage_growth()
            if stuck_time < THRESHOLD_TIME:
                time.sleep(CHECK_INTERVAL)
                continue
            success, last_scan_time, read_files = resolve_coverage_stuck(tracer, last_scan_time, read_files)
            if success:
                continue
    except KeyboardInterrupt:
        logger.info("检测到用户中断(Ctrl+C)，正在终止...")
    except Exception as e:
        logger.exception(e)
        traceback.print_exc()
    # finally:
    #     if not config.test:
    # fuzzer.terminate()
    # logger.info("fuzzer 已终止")


setup_logger()
logger = logging.getLogger(LOGGER_NAME + __name__)
fuzzer = None
input_dir = None
output_dir = None
fuzzing_args = None
target_prog = None
trace_prog = None

if __name__ == '__main__':
    main()
