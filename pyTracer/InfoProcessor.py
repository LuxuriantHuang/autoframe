import re
import re
import sys
from collections import defaultdict

import numpy as np

from config import *
from pyTracer.callgraph import CallEdge

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
        self.hit_seed = defaultdict(set)

    def merge(self, other, output_dir, basic_block, fuzzer_name):
        pattern = re.compile(r'id[_:](\d+)')
        seed_path, seed_info = other.values()
        if Path.is_file(seed_path):
            # seed-bb to bb-seed
            match = pattern.match(seed_path.name)
            seed_id = int(match.group(1))
            # line-seed
            for bb in seed_info['basic_blocks']:
                try:
                    self.hit_seed[bb["id"]].add(seed_path.name)
                except Exception:
                    print(seed_path)
                    sys.exit(1)
            pass

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


class CodeHeat:
    def __init__(self) -> None:
        self.code_heat = defaultdict()  # dict[str][str] = int

    def merge(self, other, basic_block, batch_size=50):
        _, seed_info = other.values()
        for bb in seed_info['basic_blocks']:
            start = basic_block[bb["id"]]["lineStart"]
            end = basic_block[bb["id"]]["lineEnd"]
            if start == 0 or end == 0:
                continue
            for line in range(start, end + 1):
                name = bb['name']
                if name not in self.code_heat:
                    self.code_heat[name] = defaultdict(int)
                if line not in self.code_heat[name]:
                    self.code_heat[name][line] = 0
                self.code_heat[bb['name']][line] += 1

    def merge_corpus(self, other: 'CodeHeat'):
        for k1, file_content in other.code_heat.items():
            if k1 not in self.code_heat:
                self.code_heat[k1] = file_content
                continue
            for k2, line_hit_count in file_content.items():
                self.code_heat[k1][k2] = line_hit_count if k2 not in self.code_heat[k1] else self.code_heat[k1][
                                                                                                 k2] + line_hit_count


class InfoProcesser:
    def __init__(self, output_dir):
        self._bitmap = Bitmap()
        self._hit_seed = HitSeed()
        self._output_dir = output_dir
        self._call_edges = CallEdge()

    def add(self, trace_data, basic_block, fuzzer_name, seed_name):  # 将结果添加到数据库中
        if not trace_data:
            return
        new_info = {"seed": seed_name, "info": trace_data}
        self._bitmap.merge(new_info)
        self._hit_seed.merge(new_info, self._output_dir, basic_block, fuzzer_name)
        self._call_edges.merge(new_info)

    def dump_single(self, seed_path=None):
        addi = Path.joinpath(self._output_dir, "single")
        if not Path.exists(addi):
            Path.mkdir(addi)

        dir_path = Path.joinpath(addi, seed_path.name)
        if not Path.exists(dir_path):
            Path.mkdir(dir_path)
        count = {'bb_hit_count': self._bitmap.bb_hit_count, "branch_hit_count": self._bitmap.branch_hit_count,
                 "branch_ids": self._bitmap.branch_ids}
        with open(Path.joinpath(dir_path, 'count.json'), 'w') as f:
            ujson.dump(count, f)
        block_freq = {"freq": self._bitmap.bitmap.tolist()}
        with open(Path.joinpath(dir_path, 'block_freq.json'), 'w') as f:
            ujson.dump(block_freq, f)
        # with open(Path.joinpath(dir_path, 'hit_seed.json'), 'w') as f:
        #     ujson.dump(self._hit_seed.hit_seed, f)
        self._call_edges.dump(Path.joinpath(dir_path, 'call_edges.json'))

    @property
    def bitmap(self):
        return self._bitmap

    @property
    def hit_seed(self):
        return self._hit_seed


def update_indirect_calls(static_func, new_edges):
    # static_func = {[{"id":xx, "calls":[1,2,3,4],}, {}....]}
    # new_edges = {1:{2,3,4,5}}
    # for k, v in new_edges.items():
    #     for vv in v:
    #         print(k," -> ", vv)
    for func in static_func:
        if func["id"] in new_edges:
            func["calls"] = list(set(func["calls"]) | set(new_edges[func["id"]]))
