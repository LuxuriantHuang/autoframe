import time
from pathlib import Path

from LLM import prompt_combine
from Roadblock import select_roadblock
from symbolic_exec import DSE
from tree_sitter_util import get_slice

BASE_SEED_PATH = Path("")
FUZZER = ""


def main():
    seed_path = BASE_SEED_PATH / FUZZER / "queue"
    prev_seed_nums = sum(1 for item in seed_path.iterdir() if item.is_file())
    while True:
        time.sleep(90)  # 90秒后查看是否有增长
        cur_seed_nums = sum(1 for item in seed_path.iterdir() if item.is_file())
        if cur_seed_nums != prev_seed_nums or cur_seed_nums == 0:
            prev_seed_nums = cur_seed_nums
            continue
        roadblock = select_roadblock()  # 实时从tracer中动态取一个
        seed, retcode = DSE()
        if retcode == 0:
            # 验证新生成的种子是否成功突破
            pass
        else:
            code_slice = get_slice()
            prompt = prompt_combine()


if __name__ == '__main__':
    main()
