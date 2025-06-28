import os
import random
import re
import traceback

import config
from CoverageTracer import CoverageTracer
from DSE_util import DSEUtil
from FuzzerRunner import FuzzerRunner
from LLM.LLM_util import LLM_util
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


def handle_roadblock(roadblock, tracer, dse_util, llm_util, freq_global, trace_prog):
    seeds = tracer.get_rb_seed(roadblock)
    rb_file, rb_line = tracer.get_rb_file_and_line(roadblock)

    for seed in random.sample(sorted(seeds), min(DSE_SEEDS_NUM, len(seeds))):
        # logs = dse_util.dse_runner(seed, rb_file, rb_line)
        # if any("New testcase" in log for log in logs):
        #     # fuzzer.add_seed_DSE()
        #     return True, "DSE", None

        call_chain, code_slice, bcode = tracer.get_slice(roadblock, seed)
        os.makedirs(LLM_TMP_PATH, exist_ok=True)
        seed_id = len(os.listdir(LLM_TMP_PATH))

        solved, times = False, 0
        messages = None
        while not solved and times < MAX_TIME:
            out, err, new_seed_path, messages = llm_util.solve(call_chain, code_slice, bcode, roadblock, seed_id, None,
                                                               messages)
            match = re.match(r"id:(\d+),bid:(\d+)", Path(new_seed_path).name)
            if not match:
                raise ValueError("Invalid seed name format")

            id, _ = match.groups()
            solved, execution_path, not_exec_bid = llm_util.test_seed(Path(new_seed_path).name, freq_global, trace_prog)

            if not solved:
                logger.info("Getting advices to improve Python script")
                messages = llm_util.refine(roadblock, execution_path, messages, call_chain, not_exec_bid)
                messages.append(
                    {"role": "user", "content": "Please improve the Python script you generated previously."})
                times += 1

        if solved:
            logger.info(f"Bottleneck {roadblock} is resolved.")
            return True, "LLM", id

    return False


def resolve_coverage_stuck(tracer, last_scan_time, read_files):
    ret, last_scan_time, error_info, freq_global = tracer.get_trace(read_files, last_scan_time)
    if not ret:
        logger.fatal(error_info)
        # raise Exception(error_info)

    roadblocks = tracer.get_roadblocks(STATIC_PATH)
    dse_util = DSEUtil()
    llm_util = LLM_util(MODEL, API_KEY, BASE_URL)

    for roadblock in roadblocks:
        ret, mode, id = handle_roadblock(roadblock, tracer, dse_util, llm_util, freq_global, trace_prog)
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
    with FuzzerRunner(input_dir, output_dir, target_prog, fuzzing_args) as fuzzer:
        # if not config.test:
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
        finally:
            if not config.test:
                fuzzer.terminate()
                logger.info("fuzzer 已终止")


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
