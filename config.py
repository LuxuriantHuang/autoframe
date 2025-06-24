import logging
from pathlib import Path
import sqlite3
import ujson

# logger config
LOG_PATH = "./log"
LOGGER_NAME = "AutomationFramework@"
LOGGING_LEVEL = logging.INFO
LOGGER_FILE_NAME = "autoframe"
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
PROJECT_HOME = "benchmarks/targets/libxml"
STATIC_PATH = Path(PROJECT_HOME) / "static"
DEPTH_THRESHOLD = 5
with open(STATIC_PATH / "static.json", 'r') as f:
    static = ujson.load(f)
bb = static["basic_blocks"]

# Fuzzing config
FUZZER_NAME = "default"
