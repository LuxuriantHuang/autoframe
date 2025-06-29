import atexit
import os
import shutil
import signal
import subprocess

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

        atexit.register(self.terminate)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    # def __enter__(self):
    #     self.run()
    #     return self
    #
    # def __exit__(self, exc_type, exc_val, exc_tb):
    #     self.terminate()

    def run(self):
        cmd = [
            os.fspath(AFL_PATH / "afl-fuzz"),
            "-i", os.fspath(self.input_dir),
            "-o", os.fspath(self.output_dir),
            "--", os.fspath(self.target_prog),
            *self.fuzzing_args
        ]
        logger.info(f"Fuzzer执行命令：{' '.join(cmd)}")
        self.fuzzer_process = subprocess.Popen(cmd, env={"AFL_NO_UI": "1", "AFL_QUIET": "1"}, stdout=subprocess.DEVNULL,
                                               stderr=subprocess.DEVNULL)
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

    def _signal_handler(self, sig, frame):
        logger.info(f"收到信号 {sig}，正在终止 fuzzer...")
        self.terminate()
        logger.info("fuzzer 已终止")
        exit(0)

    def add_seed_LLM(self, id, bid):
        os.makedirs(LLM_TARGET_PATH, exist_ok=True)
        n = len(os.listdir(LLM_TARGET_PATH))
        src_file = os.path.join(LLM_TMP_PATH, f"id:{int(id):06},bid:{int(bid):06}")
        dest_file = os.path.join(LLM_TARGET_PATH, f"id:{int(n):06},bid:{int(bid):06}")
        shutil.move(src_file, dest_file)

    def add_seed_DSE(self):
        os.makedirs(DSE_TARGET_PATH, exist_ok=True)
        n = len(os.listdir(DSE_TARGET_PATH))
        for i, filename in enumerate(os.listdir(DSE_TMP_PATH)):
            src_file = os.path.join(DSE_TMP_PATH, filename)
            dest_file = os.path.join(DSE_TARGET_PATH, f"id:{int(n + i):06}")
            shutil.move(src_file, dest_file)
