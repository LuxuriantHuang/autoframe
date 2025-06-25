import os
import random
import traceback

from argparse import ArgumentParser

from DSE_util import DSEUtil
from CoverageTracer import CoverageTracer
from FuzzerRunner import FuzzerRunner
from LLM.LLM_util import LLM_util
from config import *
from utils import valid_path


def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(LOGGING_LEVEL)

    os.makedirs(LOG_PATH, exist_ok=True)
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
    parse.add_argument("-t1", dest="trace_prog", required=True, type=valid_path, help="trace program under test path")
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
    trace_prog = args.trace_prog
    logger.info(f"本次运行中，input_dir：{input_dir}")
    logger.info(f"本次运行中，output_dir：{output_dir}")
    logger.info(f"本次运行中，fuzzing_args：{args.fuzzing_args}")
    logger.info(f"本次运行中，target_prog：{target_prog}")
    logger.info(f"本次运行中，trace_prog：{trace_prog}")
    fuzzer = FuzzerRunner(input_dir, output_dir, target_prog, fuzzing_args)
    # fuzzer.run()
    logger.info("fuzzer已开始运行")
    try:
        tracer = CoverageTracer(input_dir, output_dir, fuzzing_args, target_prog, trace_prog, bbs, funcs)
        while True:
            # try:
            #     tracer.check_coverage_growth()
            # except Exception as inner_e:
            #     logger.error("tracer.get_edge_count() 出现异常，准备终止 fuzzer...")
            #     logger.exception(inner_e)
            #     raise inner_e
            stuck_time = tracer.check_coverage_growth()
            if stuck_time < THRESHOLD_TIME:
                time.sleep(CHECK_INTERVAL)
                continue
            else:
                # 使用multiprocessing构建多进程，运行tracer插桩后的程序，获得输出，并只统计Bitmap()/hitseed()并update间接调用（此处使用数据库优化）
                ret, last_scan_time, error_info = tracer.get_trace(read_files, last_scan_time)
                if not ret:
                    raise Exception(error_info)
                # 使用瓶颈分析算法分析所有瓶颈并排序，返回瓶颈list（前10）
                roadblocks = tracer.get_roadblocks(STATIC_PATH)
                # 按照顺序获得瓶颈点，并得到roadblocks所需的信息
                success = False
                for roadblock in roadblocks:
                    seeds = tracer.get_rb_seed(roadblock)
                    dse_util = DSEUtil()
                    llm_util = LLM_util()
                    rb_file, rb_line = tracer.get_rb_file_and_line(roadblock)
                    for seed in random.sample(sorted(seeds), min(DSE_SEEDS_NUM, len(seeds))):
                        logs = dse_util.dse_runner(seed, rb_file, rb_line)
                        solved = False
                        for log in logs:
                            if "New testcase" in log:
                                solved = True
                                break
                        if solved:
                            fuzzer.add_seed()
                            success = True
                            break
                        call_chain, code_slice, bcode = tracer.get_slice(roadblock, seed)
                        seed_id = 0
                        result_llm, llm_seed = llm_util.solve(call_chain, code_slice, bcode,
                                                              roadblock, seed_id)  # 将检测放在llm_utils内检查
                        if result_llm:
                            fuzzer.add_seed(llm_seed)
                            success = True
                            break
                    if success:
                        break
                    # for seed in random.sample(sorted(seeds), min(DSE_SEEDS_NUM, len(seeds))):
                    #     code_slice = tracer.get_slice(roadblock, seed)
                    #     result_llm, llm_seed = llm_util.solve(code_slice, rb_file, rb_line)  # 将检测放在llm_utils内检查
                    #     if result_llm:
                    #         fuzzer.add_seed(llm_seed)
                    #         success = True
                    #         break
                    # dse_util = DSEUtil()
                    # result_dse, dse_seed = dse_util.dse_runner()
                    # if result_dse and dse_util.check():
                    #     # 将dse生成的种子加入种子队列
                    #     fuzzer.add_seed(dse_seed)
                    #     success = True
                    #     break
                    # # 符号执行没有突破，调用大模型
                    # code_slice = tracer.get_slice(roadblock, seed)
                    # llm_util = LLM_util()
                    # result_llm, llm_seed = llm_util.solve()  # 将检测放在llm_utils内检查
                    # if result_llm:
                    #     fuzzer.add_seed(llm_seed)
                    #     success = True
                    #     break
                if success:
                    continue
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        logger.info("检测到用户中断(Ctrl+C)，正在终止...")
    except Exception as e:
        logger.exception(e)
        traceback.print_exc()
    finally:
        # fuzzer.terminate()
        logger.info("fuzzer 已终止")


if __name__ == '__main__':
    main()
