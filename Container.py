import logging

import docker

from config import LOGGER_NAME

logger = logging.getLogger(LOGGER_NAME + __name__)


class Container:
    def __init__(self, image_name: str, tag='latest', volume=None):
        if volume is None:
            volume = {}
        self.image_name = image_name
        self.container_name = image_name + '_c'
        self.tag = tag
        self.client = docker.from_env()
        self.container = None
        self.volume = volume
        self.image_not_found = False

    # def __del__(self):
    #     if self.image_not_found is False:
    #         self.container.stop()
    #         self.container.remove()
    #         print(f"{self.container_name} removed.")

    def finish(self):
        self.container.stop()
        self.container.remove()
        print(f"{self.container_name} removed.")

    def container_already_exist(self):
        containers = self.client.containers.list(all=True)
        for c in containers:
            if self.container_name in c.attrs['Name']:
                return True
        return False

    def start(self):
        if self.container_already_exist():
            logger.info(f'{self.container_name} already exists.')
            self.container = self.client.containers.get(self.container_name)
            # self.finish()
            return
        try:
            # create and run a container from an local image
            self.container = self.client.containers.run(
                image=f"{self.image_name}:{self.tag}",
                name=self.container_name,
                volumes=self.volume,
                command='bash -c "/root/init.sh; tail -f /dev/null"',
                detach=True
            )
            logger.info(f"Container {self.container.id} started.")
        except docker.errors.ImageNotFound:
            logger.info(f"Image {self.image_name}:{self.tag} not found.")
            self.image_not_found = True
            exit(1)
        except docker.errors.APIError as ae:
            logger.info(f"APIError: {ae}")
            exit(1)

    def run(self, cmd: str, env: dict, process_id: str):
        result_log = []
        try:
            # exec_log是一个包含(exec_id, socket._fileobject)的元组
            # signal.signal(signal.SIGINT, self.make_signal_handler())
            # signal.signal(signal.SIGTERM, self.make_signal_handler())
            exec_log = self.container.exec_run(
                cmd,
                environment=env,
                stream=True, stdout=True, stderr=True, tty=True
            )
            for output in exec_log[1]:
                # print("1111111111", "stdout_" + process_id, output.decode('utf-8').strip())
                logger.info(output.decode('utf-8').strip())
                result_log.append(output.decode('utf-8').strip())
                # sockets.emit("stdout_" + process_id, output.decode('utf-8').strip())
            # print(f"done")

        except docker.errors.APIError as ae:
            print(f"APIError: {ae}")
            logger.error(f"APIError: {ae}")
            exit()
        except KeyboardInterrupt or SystemExit:
            return
        return result_log
