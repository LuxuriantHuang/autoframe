import re
import sys
import errno
import subprocess
from shlex import split
import logging
from config import LOGGING_LEVEL, LOGGER_NAME
import threading

logger = logging.Logger(LOGGER_NAME + __name__, level=LOGGING_LEVEL)


class SeedTracer:
    def __init__(self, trace_bin, put_args):
        self.trace_bin = trace_bin
        self.reg_trace = re.compile(
            r'^\[(?P<type>.*)\]\s\((?P<rand_id>\d+),(?P<id>\d+)\): (?P<name>.*),(?P<begin>\d+),(?P<end>\d+),'
            r'(?P<flag>\d+).*$')
        self.reg_trace_funcret = re.compile(
            r'^\[(?P<type>.*)\] : (?P<id>\d+),(?P<name>.*)$'
        )

        # @@ as the placeholder for the seed path
        self.put_args = put_args

    def __dump_trace(self, trace_info):
        """Handle the execution path of a seed"""
        line_cnt = 0
        info = {"basic_blocks": [], "functions": []}
        for line in trace_info.splitlines():
            try:
                line = line.decode()
            except UnicodeDecodeError:
                continue
            line_cnt += 1

            matcher = self.reg_trace.match(line)
            ''' match the trace information '''
            if matcher is not None:
                typ = str(matcher.groupdict()['type'])
                parsed_info = {
                    "name": str(matcher.groupdict()['name']),
                    "id": int(matcher.groupdict()['id']),
                    "flag": int(matcher.groupdict()['flag']),
                    "en": True  # entry
                }
                if typ == 'F':
                    info["functions"].append(parsed_info)
                elif typ == 'B':
                    info["basic_blocks"].append(parsed_info)

            matcher = self.reg_trace_funcret.match(line)
            if matcher is not None:
                parsed_info = {
                    "name": str(matcher.groupdict()['name']),
                    "id": int(matcher.groupdict()['id']),
                    "en": False
                }
                info["functions"].append(parsed_info)

        return info

    def trace_seed(self, seed_path, timeo):
        def timeout(p, name, retcode):
            if p.poll() is None:
                try:
                    p.kill()
                    retcode[0] = -1
                except Exception as e:
                    if e.errno != errno.ESRCH:
                        raise

        """Trace new seeds and update execution tree"""
        trace_cmd = f"{self.trace_bin} {self.put_args.replace('@@', str(seed_path))}"
        retcode = [0]
        p = subprocess.Popen(split(trace_cmd), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        t = threading.Timer(timeo, timeout, args=(p, str(seed_path), retcode))
        t.start()
        try:
            _, trace_info = p.communicate()
        finally:
            t.cancel()
        return self.__dump_trace(trace_info), retcode[0]
