import logging
import time
from pathlib import Path
import ujson

# logger config
LOG_PATH = "./log"
LOGGER_NAME = "AutomationFramework@"
LOGGING_LEVEL = logging.INFO
LOGGER_FILE_NAME = "autoframe-" + time.strftime("%m-%d-%H_%M_%S", time.localtime()) + ".log"
LOGGING_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# coverage tracer config
AFL_PATH = Path("/home/lab420/Desktop/autoframe/AFLplusplus")
SHOWMAP_PATH = AFL_PATH / "afl-showmap"
AFL_MAP_SHM_ENV = "__AFL_SHM_ID"
MAP_SIZE = 18  # 通常为 64KB
THRESHOLD_TIME = 5  # 覆盖率无增长超过90s
THRESHOLD_COV_DELTA = 1  # 至少需要增加 1 个 edge 才算有效增长
CHECK_INTERVAL = 5  # 每 5 秒检查一次
WINDOW_SIZE = 30  # 保留最近 1 分钟的覆盖率记录
TIMEOUT = 30
PROJECT_HOME = "/home/lab420/Desktop/autoframe/benchmarks/libxml"
STATIC_PATH = Path(PROJECT_HOME) / "static"
SEED_PATH = Path(PROJECT_HOME) / "out" / "default" / "queue"
DEPTH_THRESHOLD = 5
with open(STATIC_PATH / "static.json", 'r') as f:
    static = ujson.load(f)
bbs = static["basic_blocks"]
funcs = static["functions"]
EXEC_ARGS = "@@"

# Fuzzing config
FUZZER_NAME = "default"

# DSE config
DSE_SEEDS_NUM = 3

# LLM config
MODEL = "deepseek-chat"
API_KEY = "sk-440547e4c10e4c82b09d848a68d3b078"
base_url = "https://api.deepseek.com"
MAX_TIME = 3