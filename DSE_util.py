import os
import shutil

from Container import Container
from config import *

logger = logging.getLogger(LOGGER_NAME + __name__)


class DSEUtil:
    def __init__(self):
        self.container = Container(image_name="contest",
                                   tag="symbolic",
                                   volume={
                                       PROJECT_HOME: {"bind": "/root/Project", "mode": "rw"}
                                   })

    def dse_runner(self, seed, code, line):
        if os.path.exists(DSE_TMP_PATH):
            shutil.rmtree(DSE_TMP_PATH)
        os.makedirs(DSE_TMP_PATH)
        env = {"SYMCC_ENABLE_LINEARIZATION": "1",
               "SYMCC_INPUT_FILE": os.fspath(Path("/root/Project/out/default/queue") / seed),
               "SYMCC_OUTPUT_DIR": DSE_DOCKER_TMP_PATH,
               "SYMCC_DIRECTED": "1",
               "SYMCC_NEGATE_TARGET_FILE": os.fspath("/root/build/" + code),
               "SYMCC_NEGATE_TARGET_LINE": str(line)}
        cmd_line = ["/root/Project/target/symbolic/target_binary",
                    os.fspath(Path("/root/Project/out/default/queue") / seed)]
        logger.info(f"待执行命令：{' '.join(cmd_line)}")
        logger.info(f"环境变量：{env}")

        self.container.start()
        result_log = self.container.run(cmd=' '.join(cmd_line), env=env, process_id="symcc")
        return result_log
