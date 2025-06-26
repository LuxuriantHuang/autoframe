from collections import defaultdict


class CodeHeat:
    def __init__(self) -> None:
        self.code_heat = defaultdict()  # dict[str][str] = int

    def merge(self, seed_info, basic_block, batch_size=50):
        # _, seed_info = other.values()
        for bb in seed_info:
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
