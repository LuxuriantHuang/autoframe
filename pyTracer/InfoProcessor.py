import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from tqdm import tqdm

from config import *

logger = logging.getLogger(LOGGER_NAME + __name__)


class Bitmap:
    def __init__(self) -> None:
        # self.bitmap = np.zeros((1 << MAP_SIZE), dtype=np.int32)
        self.bitmap = defaultdict(int)
        # self.bb_hit_count = 0
        # self.branch_hit_count = 0
        # self.branch_ids = defaultdict(int)

    def merge(self, other):
        _, seed_info = other.values()
        # last_id = -1
        # prev_flag = -1
        for bb_info in seed_info['basic_blocks']:
            # self.bb_hit_count += 1  # 全局bb hit count
            self.bitmap[bb_info['id']] += 1

            # if bb_info['id'] != last_id and prev_flag != 0:
            #     if last_id != -1:
            #         self.branch_hit_count += 1  # 全局branch hit count
            #         branch_id = (last_id << MAP_SIZE) + bb_info['id']
            #         self.branch_ids[branch_id] += 1
            # last_id = bb_info['id']
            # prev_flag = bb_info['flag']

    def merge_corpus(self, other: 'Bitmap'):
        # self.bb_hit_count += other.bb_hit_count
        # self.branch_hit_count += other.branch_hit_count
        # self.bitmap = self.bitmap + other.bitmap
        for bb_id, count in other.bitmap.items():
            self.bitmap[bb_id] += count
        # for k, v in other.branch_ids.items():
        #     self.branch_ids[k] = v if k not in self.branch_ids else self.branch_ids[k] + v


class HitSeed:
    def __init__(self) -> None:
        self.hit_seed = defaultdict(set)

    def merge(self, other):
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
        for bb_id, filenames in other.hit_seed.items():
            self.hit_seed[bb_id].update(filenames)


class InfoProcesser:
    def __init__(self, output_dir):
        self._bitmap = Bitmap()
        self._hit_seed = HitSeed()
        self._output_dir = output_dir
        # self._call_edges = CallEdge()

        self._bitmap_lock = Lock()
        self._hit_seed_lock = Lock()
        self.addi = Path.joinpath(self._output_dir, "single")
        if not Path.exists(self.addi):
            Path.mkdir(self.addi)

    def process_single_data(self, trace_data, fuzzer_name, seed_name):
        local_bitmap = Bitmap()
        local_hitseed = HitSeed()

        new_info = {"seed": seed_name, "info": trace_data}
        if trace_data:
            local_bitmap.merge(new_info)
            local_hitseed.merge(new_info)

        return local_bitmap, local_hitseed

    def process_seed(self, seed_path, seed_tracer, TIMEOUT):
        trace_data, retcode = seed_tracer.trace_seed(str(seed_path), TIMEOUT)
        # 假设 self.process_single_data 是无状态的，可以作为普通函数调用
        local_bitmap, local_hitseed = self.process_single_data(trace_data, "default", seed_path)
        return local_bitmap, local_hitseed

    def parallel_add(self, seed_lst_to_run, seed_tracer, max_workers=4):
        local_bitmaps = []
        local_hitseeds = []
        futures = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.process_seed, seed_path, seed_tracer, TIMEOUT): seed_path
                for seed_path in seed_lst_to_run
            }
            # for future in as_completed(futures):
            for future in tqdm(as_completed(futures), total=len(futures)):
                try:
                    local_bitmap, local_hitseed = future.result()
                    local_bitmaps.append(local_bitmap)
                    local_hitseeds.append(local_hitseed)
                except Exception as exc:
                    seed_path = futures[future]
                    logger.error(f"Seed {seed_path} generated an exception: {exc}")
        for lb in tqdm(local_bitmaps, total=len(local_bitmaps)):
            self._bitmap.merge_corpus(lb)
        for hs in tqdm(local_hitseeds, total=len(local_hitseeds)):
            self._hit_seed.merge_corpus(hs)

    def dump_single(self, seed_path=None):
        addi = Path.joinpath(self._output_dir, "single")
        if not Path.exists(addi):
            Path.mkdir(addi)

        dir_path = Path.joinpath(addi, seed_path.name)
        if not Path.exists(dir_path):
            Path.mkdir(dir_path)
        # count = {'bb_hit_count': self._bitmap.bb_hit_count, "branch_hit_count": self._bitmap.branch_hit_count,
        #          "branch_ids": self._bitmap.branch_ids}
        # with open(Path.joinpath(dir_path, 'count.json'), 'w') as f:
        #     ujson.dump(count, f)
        block_freq = {"freq": self._bitmap.bitmap.tolist()}
        with open(Path.joinpath(dir_path, 'block_freq.json'), 'w') as f:
            ujson.dump(block_freq, f)
        # with open(Path.joinpath(dir_path, 'hit_seed.json'), 'w') as f:
        #     ujson.dump(self._hit_seed.hit_seed, f)
        # self._call_edges.dump(Path.joinpath(dir_path, 'call_edges.json'))

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
