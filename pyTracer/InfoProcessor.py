import os
import re
import sys
from collections import defaultdict

import numpy as np
from config import *

logger = logging.getLogger(LOGGER_NAME + __name__)


class Bitmap:
    def __init__(self) -> None:
        self.bitmap = np.zeros((1 << MAP_SIZE), dtype=np.int32)
        self.bb_hit_count = 0
        self.branch_hit_count = 0
        self.branch_ids = defaultdict(int)

    def merge(self, other):
        _, seed_info = other.values()
        last_id = -1
        prev_flag = -1
        for bb_info in seed_info['basic_blocks']:
            self.bb_hit_count += 1  # 全局bb hit count
            self.bitmap[bb_info['id']] += 1

            if bb_info['id'] != last_id and prev_flag != 0:
                if last_id != -1:
                    self.branch_hit_count += 1  # 全局branch hit count
                    branch_id = (last_id << MAP_SIZE) + bb_info['id']
                    self.branch_ids[branch_id] += 1
            last_id = bb_info['id']
            prev_flag = bb_info['flag']

    def merge_corpus(self, other: 'Bitmap'):
        self.bb_hit_count += other.bb_hit_count
        self.branch_hit_count += other.branch_hit_count
        self.bitmap = self.bitmap + other.bitmap
        for k, v in other.branch_ids.items():
            self.branch_ids[k] = v if k not in self.branch_ids else self.branch_ids[k] + v


class HitSeed:
    def __init__(self) -> None:
        self.hit_seed = defaultdict()  # dict[str][str]=list[str]

    def merge(self, other, output_dir, basic_block, fuzzer_name):
        pattern = re.compile(r'id[_:](\d+)')
        seed_path, seed_info = other.values()
        ppath = Path(PROJECT_HOME) / "out" / fuzzer_name / "queue" / seed_path
        for bb in seed_info['basic_blocks']:
            start = basic_block[bb["id"]]["lineStart"]
            end = basic_block[bb["id"]]["lineEnd"]
            for line in range(start, end + 1):
                if Path.is_file(ppath):
                    try:
                        match = pattern.match(seed_path)
                        seed_id = int(match.group(1))

                        name = bb['name']
                        if name not in self.hit_seed:
                            self.hit_seed[name] = defaultdict(list)
                        if line not in self.hit_seed[name]:
                            self.hit_seed[name][line] = []
                        self.hit_seed[bb['name']][line].append(seed_id)
                    except Exception:
                        print(seed_path)
                        sys.exit(1)
                else:
                    continue
                self.hit_seed[bb['name']][line] = list(set(self.hit_seed[bb['name']][line]))

    def merge_corpus(self, other: 'HitSeed'):
        for k1, file_content in other.hit_seed.items():
            if k1 not in self.hit_seed:
                self.hit_seed[k1] = file_content
                continue
            for k2, line_seed_list in file_content.items():
                if k2 not in self.hit_seed[k1]:
                    self.hit_seed[k1][k2] = line_seed_list
                    continue
                self.hit_seed[k1][k2] = list(set(self.hit_seed[k1][k2]) | set(line_seed_list))


class InfoProcesser:
    def __init__(self, output_dir):
        self._bitmap = Bitmap()
        self._hit_seed = HitSeed()
        self._output_dir = output_dir

    def add(self, trace_data, basic_block, fuzzer_name, seed_name):  # 将结果添加到数据库中
        if not trace_data:
            return
        new_info = {"seed": seed_name, "info": trace_data}
        self._bitmap.merge(new_info)
        self._hit_seed.merge(new_info, self._output_dir, basic_block, fuzzer_name)
        pass

    @property
    def bitmap(self):
        return self._bitmap
