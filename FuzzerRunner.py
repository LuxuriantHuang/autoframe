import atexit
import os
import re
import shutil
import signal
import subprocess

from config import *
from utils import valid_path
from pathlib import Path

logger = logging.getLogger(LOGGER_NAME + __name__)


class FuzzerRunner:
    def __init__(self, input_dir: valid_path, output_dir: Path, target_prog: valid_path, fuzzing_args):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.target_prog = target_prog
        self.fuzzing_args = fuzzing_args
        self.fuzzer_process = None
        self.fuzzer_pid_from_stats = None  # Cached PID from fuzzer_stats

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
        env = os.environ.copy()
        env['AFL_DISABLE_TRIM'] = '1'
        env['AFL_NO_UI'] = '1'
        env['AFL_QUIET'] = '1'
        logger.info(f"Fuzzer执行命令：{' '.join(cmd)}")
        self.fuzzer_process = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL,
                                               stderr=subprocess.DEVNULL)
        logger.info(f"fuzzer在系统中的pid：{self.fuzzer_process.pid}")

    def terminate(self):
        if not self.is_running():
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

    def get_fuzzer_stats_path(self):
        """Get the path to the fuzzer_stats file."""
        # 旧逻辑保留：
        # return Path(self.output_dir) / FUZZER_NAME / "fuzzer_stats"
        return FUZZER_STATS_PATH

    def load_fuzzer_pid(self):
        """
        Load and cache the fuzzer PID from fuzzer_stats file.
        Should be called once after the fuzzer has started.

        Returns:
            int: The fuzzer PID, or None if not found/readable
        """
        self.fuzzer_pid_from_stats = self._read_fuzzer_pid()
        return self.fuzzer_pid_from_stats

    def get_fuzzer_pid(self):
        """
        Get the cached fuzzer PID.

        Returns:
            int: The cached fuzzer PID, or None if not loaded
        """
        return self.fuzzer_pid_from_stats

    def _read_fuzzer_pid(self):
        """
        Read the fuzzer PID from fuzzer_stats file.

        Returns:
            int: The fuzzer PID, or None if not found/readable
        """
        fuzzer_stats_path = self.get_fuzzer_stats_path()

        try:
            with open(fuzzer_stats_path, 'r') as f:
                for line in f:
                    if 'fuzzer_pid' in line:
                        # Format: "fuzzer_pid        : xxx"
                        parts = line.split(':')
                        if len(parts) == 2:
                            pid_str = parts[1].strip()
                            return int(pid_str)
            logger.warning(f"[FUZZER] Could not find fuzzer_pid in fuzzer_stats")
            return None
        except FileNotFoundError:
            logger.warning(f"[FUZZER] fuzzer_stats file not found at {fuzzer_stats_path}")
            return None
        except Exception as e:
            logger.error(f"[FUZZER] Error reading fuzzer_stats: {e}")
            return None

    def _is_pid_alive(self, pid):
        """
        Check if a process with the given PID is still alive.

        Args:
            pid: Process ID to check

        Returns:
            bool: True if process is alive, False otherwise
        """
        if pid is None:
            return False

        try:
            # Send signal 0 to check if process exists
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def check_alive(self):
        """
        Check if the fuzzer process is still alive by reading its PID from fuzzer_stats.
        Returns True if alive, False otherwise.
        """
        # First check the internal process reference
        if self.fuzzer_process is not None and self.is_running():
            return True

        # Fallback: check cached PID from fuzzer_stats
        if self.fuzzer_pid_from_stats is not None:
            return self._is_pid_alive(self.fuzzer_pid_from_stats)

        # Could not determine fuzzer status
        return False

    def is_alive_from_stats(self):
        """
        Check if fuzzer is alive based on cached fuzzer_stats PID only.
        This is useful when the fuzzer process was started externally.

        Returns:
            bool: True if fuzzer is alive, False otherwise
        """
        if self.fuzzer_pid_from_stats is None:
            return False
        return self._is_pid_alive(self.fuzzer_pid_from_stats)

    def _signal_handler(self, sig, frame):
        logger.info(f"收到信号 {sig}，正在终止 fuzzer...")
        self.terminate()
        logger.info("fuzzer 已终止")
        exit(0)

    def add_seed_LLM(self, output_dir, id, bid):
        LLM_TARGET_PATH = Path(output_dir) / "LLM" / "queue"
        os.makedirs(LLM_TARGET_PATH, exist_ok=True)
        n = len(os.listdir(LLM_TARGET_PATH))
        src_file = os.path.join(LLM_TMP_PATH, f"id:{int(id):06},bid:{int(bid):06}")
        dest_file = os.path.join(LLM_TARGET_PATH, f"id:{int(n):06},bid:{int(bid):06}")
        shutil.move(src_file, dest_file)
        return dest_file

    def add_seed_DSE(self):
        os.makedirs(DSE_TARGET_PATH, exist_ok=True)
        n = len(os.listdir(DSE_TARGET_PATH))
        for i, filename in enumerate(os.listdir(DSE_TMP_PATH)):
            src_file = os.path.join(DSE_TMP_PATH, filename)
            dest_file = os.path.join(DSE_TARGET_PATH, f"id:{int(n + i):06}")
            shutil.move(src_file, dest_file)

    def add_seed_mut(self, output_dir, new_seed_path, orig_seed):
        MUT_TARGET_PATH = Path(output_dir) / "mut" / "queue"
        os.makedirs(MUT_TARGET_PATH, exist_ok=True)
        n = len(os.listdir(MUT_TARGET_PATH))
        src_file = new_seed_path
        orig_id = re.search(r'id:(\d+)', orig_seed).group(1)
        dest_file = os.path.join(MUT_TARGET_PATH, f"id:{int(n):06},src:{int(orig_id):06}")
        shutil.move(src_file, dest_file)
        return dest_file
