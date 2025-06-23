import os
import subprocess
from pathlib import Path

from config import *
from utils import valid_path

logger = logging.getLogger(LOGGER_NAME + __name__)


class FuzzerRunner:
    def __init__(self, input_dir: valid_path, output_dir: Path, target_prog: valid_path, fuzzing_args):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.target_prog = target_prog
        self.fuzzing_args = fuzzing_args
        self.fuzzer_process = None

    def run(self):
        cmd = [
            os.fspath(AFL_PATH),
            "-i", os.fspath(self.input_dir),
            "-o", os.fspath(self.output_dir),
            "--", os.fspath(self.target_prog),
            *self.fuzzing_args
        ]
        logger.info(f"Fuzzer执行命令：{' '.join(cmd)}")
        self.fuzzer_process = subprocess.Popen(cmd)
        logger.info(f"fuzzer在系统中的pid：{self.fuzzer_process.pid}")

    def terminate(self):
        if self.is_running():
            logger.error("没有启动fuzzer，请先启动fuzzer！")
            return
        logger.info("正在停止fuzzer")
        try:
            self.fuzzer_process.terminate()
            self.fuzzer_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            logger.warning("terminate时间过长，正在直接kill")
            self.fuzzer_process.kill()
            self.fuzzer_process.wait()
        finally:
            logger.info("fuzzer成功终止")
            self.fuzzer_process = None

    def is_running(self):
        if self.fuzzer_process is None:
            return False
        return self.fuzzer_process.poll() is None
