import os

import ujson
from pathlib import Path
from config import *

def iterate_files(dirpath):
    for subdir, dirs, files in os.walk(dirpath):
        for file in files:
            yield os.path.join(subdir, file)
        break


def parse_filename(name):
    name = name.split("/")[-1]
    src = None
    id = int(name[3: name.find(",")])
    i = name.find("src:") if name.find("src:") != -1 else name.find("src_")
    # print(i)
    orig = 1 if name.find("orig") != -1 else 0
    # print(i, orig)
    if i >= 0 and (orig == 0 or (orig == 1 and name.find("orig") < i)):
        src = name[i + 4: name.find(",", i)]
        src = src.split("+")[0]
        # print(name, src)
        src = list(map(int, src.split("+")))

    return id, src


class VariationTree:
    def __init__(self) -> None:
        self.graph = {}
        self.file_list = {"files": []}
        self.roots = []

    def visit(self, id):
        return {
            "id": id,
            "ch": self.graph[id]
        }

    def generation(self, seed_path):
        for f in sorted(iterate_files(seed_path)):
            id, src = parse_filename(f)

            self.file_list["files"].append({"id": id, "name": f.split("/")[-1]})

            self.graph[id] = self.graph.get(id, [])
            if src is not None:
                for srcid in src:
                    self.graph[srcid] = self.graph.get(srcid, [])
                    self.graph[srcid] += [id]
                    self.graph[srcid] = list(set(self.graph[srcid]))
                    break
            else:
                self.roots.append(id)

    def dump(self):
        output_graph = {"tree": {}, "roots": self.roots}
        for name in self.graph:
            output_graph["tree"][name] = self.visit(name)

        # with open(Path.joinpath(output_path, "generation_graph.json"), "w") as f:
        #     ujson.dump(output_graph, f)
        # print("generation graph done")
        return output_graph

if __name__ == '__main__':
    variation_tree = VariationTree()
    variation_tree.generation(SEED_PATH)
    tree = variation_tree.dump()