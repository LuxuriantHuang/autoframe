import logging
import time
from pathlib import Path

import ujson

# logger config
LOG_PATH = "./log"
LOGGER_NAME = "AutomationFramework@"
LOGGING_LEVEL = logging.INFO
LOGGER_FILE_NAME = "autoframe-" + time.strftime("%m-%d-%H_%M_%S", time.localtime()) + ".log"
LOGGING_FORMAT = "%(asctime)s - %(name)s:%(lineno)d %(funcName)s - %(levelname)s - %(message)s"

test = False

# Fuzzing config
FUZZER_NAME = "default"

# coverage tracer config
PWD = "/home/lab420/Desktop/autoframe"
AFL_PATH = Path(PWD) / "AFLplusplus"
SHOWMAP_PATH = AFL_PATH / "afl-showmap"
MAP_SIZE = 18
if test:
    THRESHOLD_TIME = 10
    THRESHOLD_COV_DELTA = 1  # 至少需要增加 1 个 edge 才算有效增长
else:
    THRESHOLD_TIME = 90  # 覆盖率无增长超过90s
    THRESHOLD_COV_DELTA = 100  # 至少需要增加 1 个 edge 才算有效增长
CHECK_INTERVAL = 5  # 每 5 秒检查一次
TIMEOUT = 30
PROJECT = "transform"
PROJECT_HOME = Path(PWD) / "benchmarks" / PROJECT
STATIC_PATH = Path(PROJECT_HOME) / "static"
SEED_PATH = Path(PROJECT_HOME) / "out" / FUZZER_NAME / "queue"
DEPTH_THRESHOLD = 0
with open(STATIC_PATH / "static.json", 'r') as f:
    static = ujson.load(f)
bbs = static["basic_blocks"]
funcs = static["functions"]
EXEC_ARGS = "@@"

# DSE config
DSE_SEEDS_NUM = 3
DSE_DOCKER_TMP_PATH = Path("/root/Project/sym_tmp")
DSE_TMP_PATH = PROJECT_HOME / "sym_tmp"
DSE_TARGET_PATH = PROJECT_HOME / "out" / "symbolic" / "queue"
DSE_PROGRAM = PROJECT_HOME / "target" / "symbolic" / "target_binary"

# LLM config
MODEL = "deepseek-chat"
API_KEY = "sk-440547e4c10e4c82b09d848a68d3b078"
BASE_URL = "https://api.deepseek.com"
MAX_TIME = 3
LLM_TMP_PATH = PROJECT_HOME / "llm_tmp"
LLM_TARGET_PATH = PROJECT_HOME / "out" / "LLM" / "queue"
