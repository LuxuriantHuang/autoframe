import re
import sys
import errno
import subprocess
from pathlib import Path
from shlex import split
import logging
from config import LOGGING_LEVEL, LOGGER_NAME
import threading
from dynamic_trace_summary import TraceSummaryBuilder

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

    def _build_trace_cmd(self, seed_path):
        return f"{self.trace_bin} {self.put_args.replace('@@', str(seed_path))}"

    def parse_trace_line(self, line):
        if not line or len(line) < 4:
            return None
        matcher = self.reg_trace.match(line)
        if matcher:
            g = matcher.groupdict()
            return {
                "event": g["type"],
                "name": g["name"],
                "id": int(g["id"]),
                "begin": int(g["begin"]),
                "end": int(g["end"]),
                "flag": int(g["flag"]),
            }
        matcher = self.reg_trace_funcret.match(line)
        if matcher:
            g = matcher.groupdict()
            return {
                "event": g["type"],
                "name": g["name"],
                "id": int(g["id"]),
            }
        return None

    def __dump_trace(self, trace_info):
        """Handle the execution path of a seed"""
        info = {"basic_blocks": [], "functions": []}
        try:
            decoded_text = trace_info.decode('utf-8', errors='ignore')
        except (UnicodeDecodeError, AttributeError):
            decoded_text = trace_info if isinstance(trace_info, str) else trace_info.decode('utf-8', errors='ignore')
        for line in decoded_text.splitlines():
            if not line or len(line)<10:
                continue
            matcher = self.reg_trace.match(line)
            if matcher:
                g = matcher.groupdict()
                typ = g['type']
                parsed_info = {
                    "name": g['name'],
                    "id": int(g['id']),
                    "flag": int(g['flag']),
                    "en": True
                }
                (info["functions"] if typ == 'F' else info["basic_blocks"]).append(parsed_info)
                continue
            matcher = self.reg_trace_funcret.match(line)
            if matcher:
                g = matcher.groupdict()
                info["functions"].append({
                    "name": g['name'],
                    "id": int(g['id']),
                    "en": False
                })
        # for line in trace_info.splitlines():
        #     try:
        #         line = line.decode()
        #     except UnicodeDecodeError:
        #         continue
        #     line_cnt += 1
        #
        #     matcher = self.reg_trace.match(line)
        #     ''' match the trace information '''
        #     if matcher is not None:
        #         typ = str(matcher.groupdict()['type'])
        #         parsed_info = {
        #             "name": str(matcher.groupdict()['name']),
        #             "id": int(matcher.groupdict()['id']),
        #             "flag": int(matcher.groupdict()['flag']),
        #             "en": True  # entry
        #         }
        #         if typ == 'F':
        #             info["functions"].append(parsed_info)
        #         elif typ == 'B':
        #             info["basic_blocks"].append(parsed_info)
        #
        #     matcher = self.reg_trace_funcret.match(line)
        #     if matcher is not None:
        #         parsed_info = {
        #             "name": str(matcher.groupdict()['name']),
        #             "id": int(matcher.groupdict()['id']),
        #             "en": False
        #         }
        #         info["functions"].append(parsed_info)

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
        trace_cmd = self._build_trace_cmd(seed_path)
        retcode = [0]
        p = subprocess.Popen(split(trace_cmd), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        t = threading.Timer(timeo, timeout, args=(p, str(seed_path), retcode))
        t.start()
        try:
            _, trace_info = p.communicate()
        finally:
            t.cancel()
        return self.__dump_trace(trace_info), retcode[0]

    def trace_seed_stream(self, seed_path, timeo, line_handler):
        def timeout(p, retcode):
            if p.poll() is None:
                try:
                    p.kill()
                    retcode[0] = -1
                except Exception as e:
                    if getattr(e, "errno", None) != errno.ESRCH:
                        raise

        trace_cmd = self._build_trace_cmd(seed_path)
        retcode = [0]
        stopped_early = False
        p = subprocess.Popen(
            split(trace_cmd),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        t = threading.Timer(timeo, timeout, args=(p, retcode))
        t.start()
        try:
            assert p.stderr is not None
            for raw_line in p.stderr:
                if isinstance(raw_line, bytes):
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                else:
                    line = raw_line.rstrip("\r\n")
                should_continue = line_handler(line)
                if should_continue is False:
                    stopped_early = True
                    try:
                        p.kill()
                    except OSError:
                        pass
                    break
            p.wait()
        finally:
            t.cancel()
            if p.stderr is not None:
                p.stderr.close()
        return retcode[0], stopped_early

    def trace_seed_summary(self, seed_path, timeo, target_file, target_line, window=20, max_events=50000):
        builder = TraceSummaryBuilder(
            seed_name=Path(seed_path).name,
            target_file=target_file,
            target_line=target_line,
            window=window,
            max_events=max_events,
        )

        def handle_line(line):
            event = self.parse_trace_line(line)
            if event is None:
                return True
            return builder.consume_event(event)

        retcode, stopped_early = self.trace_seed_stream(seed_path, timeo, handle_line)
        trace_complete = (retcode == 0 or stopped_early)
        return builder.build(trace_complete=trace_complete)
