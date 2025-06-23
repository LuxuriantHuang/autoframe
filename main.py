import time

import ujson
from argparse import ArgumentParser
from pathlib import Path

from DSE_util import DSEUtil
from CoverageTracer import CoverageTracer
from FuzzerRunner import FuzzerRunner
from LLM import LLM_util
from config import *
from utils import valid_path


def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(LOGGING_LEVEL)

    handler = logging.FileHandler(Path(LOG_PATH) / LOGGER_FILE_NAME)
    handler.setLevel(LOGGING_LEVEL)
    formatter = logging.Formatter(LOGGING_FORMAT)
    handler.setFormatter(formatter)

    logger.addHandler(handler)


def parse_args():
    parse = ArgumentParser(description="The automation framework of fuzzing with LLM and Symbolic exec")
    parse.add_argument("-i", dest="input_dir", required=True, type=valid_path, help="init corpus path")
    parse.add_argument("-o", dest="output_dir", required=True, type=Path, help="fuzzing output path")
    parse.add_argument("-a", dest="fuzzing_args", required=True, type=str, help="fuzzing args")
    parse.add_argument("-t", dest="target_prog", required=True, type=valid_path, help="program under test path")
    return parse.parse_args()


def main():
    setup_logger()
    logger = logging.getLogger(LOGGER_NAME + __name__)
    args = parse_args()
    read_files = set()  # 记录已读取的文件集合
    last_scan_time = 0  # 记录上次扫描时间戳
    input_dir = args.input_dir
    output_dir = args.output_dir
    fuzzing_args = args.fuzzing_args.split(sep=" ")
    target_prog = args.target_prog
    logger.info(f"本次运行中，input_dir：{input_dir}")
    logger.info(f"本次运行中，output_dir：{output_dir}")
    logger.info(f"本次运行中，fuzzing_args：{args.fuzzing_args}")
    logger.info(f"本次运行中，target_prog：{target_prog}")
    fuzzer = FuzzerRunner(input_dir, output_dir, target_prog, fuzzing_args)
    fuzzer.run()
    logger.info("fuzzer已开始运行")
    try:
        tracer = CoverageTracer(input_dir, output_dir, fuzzing_args, target_prog)
        # with open(STATIC_PATH / "static.json", 'r') as f:
        #     static = ujson.load(f)
        # bb = static["basic_blocks"]
        while True:
            stuck_time = tracer.check_coverage_growth()
            # if stuck_time < THRESHOLD_TIME:
            #     time.sleep(CHECK_INTERVAL)
            #     continue
            # continue
        #     # 使用multiprocessing构建多进程，运行tracer插桩后的程序，获得输出，并只统计Bitmap()/hitseed()并update间接调用（此处使用数据库优化）
        #     ret, last_scan_time, error_info = tracer.get_trace(read_files, last_scan_time)
        #     if not ret:
        #         time.sleep(5)
        #         continue
        #     # 使用瓶颈分析算法分析所有瓶颈并排序，返回瓶颈list（前10）
        #     roadblocks = tracer.get_roadblocks(bb, STATIC_PATH)
        #     # 按照顺序获得瓶颈点，并得到roadblocks所需的信息
        #     success = False
        #     for roadblock in roadblocks:
        #         seed = tracer.get_rb_seed(roadblock)
        #         dse_util = DSEUtil()
        #         result_dse, dse_seed = dse_util.dse_runner()
        #         if result_dse and dse_util.check():
        #             # 将dse生成的种子加入种子队列
        #             fuzzer.add_seed(dse_seed)
        #             success = True
        #             break
        #         # 符号执行没有突破，调用大模型
        #         code_slice = tracer.get_slice(roadblock, seed)
        #         llm_util = LLM_util()
        #         result_llm, llm_seed = llm_util.solve()  # 将检测放在llm_utils内检查
        #         if result_llm:
        #             fuzzer.add_seed(llm_seed)
        #             success = True
        #             break
        #     if success:
        #         continue
        # while True:
        #     time.sleep(1)
    except KeyboardInterrupt:
        logger.info("检测到用户中断(Ctrl+C)，正在终止...")
    finally:
        fuzzer.terminate()
        logger.info("fuzzer 已终止")


if __name__ == '__main__':
    main()
