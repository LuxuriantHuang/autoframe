import logging
from pathlib import Path
import sqlite3

# logger config
LOG_PATH = "."
LOGGER_NAME = "AutomationFramework@"
LOGGING_LEVEL = logging.INFO
LOGGER_FILE_NAME = "autoframe.log"
LOGGING_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# coverage tracer config
AFL_PATH = Path("/home/luxuh/auto_interact/AFLplusplus")
SHOWMAP_PATH = AFL_PATH / "afl-showmap"
AFL_MAP_SHM_ENV = "__AFL_SHM_ID"
MAP_SIZE = 1 << 18  # 通常为 64KB
THRESHOLD_TIME = 90  # 覆盖率无增长超过 5 分钟
THRESHOLD_COV_DELTA = 1  # 至少需要增加 1 个 edge 才算有效增长
CHECK_INTERVAL = 5  # 每 5 秒检查一次
WINDOW_SIZE = 30  # 保留最近 1 分钟的覆盖率记录
TIMEOUT = 30
PROJECT_HOME = ""
STATIC_PATH = Path(PROJECT_HOME) / "static"
DEPTH_THRESHOLD = 5

# Fuzzing config
FUZZER_NAME = "default"
