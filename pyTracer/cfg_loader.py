import queue
from collections import defaultdict

import ujson

from config import *

logger = logging.Logger(LOGGER_NAME + __name__)


class Graph:
    def __init__(self) -> None:
        self.nodes_freq = {}
        self.nodes_size = {}
        self.nodes_succ = {}
        self.edges = defaultdict(set)
        self.vis = set()  # nodes that are successors

    def add_edge(self, node1, node2):
        '''node1 -> node2'''
        self.edges[node1].add(node2)
        self.vis.add(node2)


class CFGLoader:
    def __init__(self, raw_static, output_dir):

        self.graph = Graph()
        for basicBlockInfo in raw_static:
            bb_id = int(basicBlockInfo["id"])
            self.graph.nodes_freq[bb_id] = 0
            self.graph.nodes_size[bb_id] = len(set(basicBlockInfo["successors"]))
            self.graph.nodes_succ[bb_id] = list(set(basicBlockInfo["successors"]))
        self._output_dir = output_dir
        # depth
        self.bfs_vis = set()
        self.bfs_vis.add(0)
        self.bfs_pending = queue.Queue()
        self.bfs_pending.put(0)
        self.depth_map = defaultdict()
        self.depth_map[0] = 0

    def build_graph(self, bb):
        for bb_info in bb:
            curr = bb_info['id']
            for succ in bb_info['successors']:
                self.graph.add_edge(int(curr), int(succ))
        logger.debug("CFGLoader build graph done")

    def bfs(self, node_id):
        self.bfs_pending.put(node_id)
        self.depth_map[node_id] = 0
        while not self.bfs_pending.empty():
            curr = self.bfs_pending.get()
            for succ in self.graph.nodes_succ[curr]:
                if succ in self.bfs_vis:
                    continue
                if curr not in self.depth_map.keys():
                    self.depth_map[succ] = 0
                else:
                    self.depth_map[succ] = self.depth_map[curr] + 1
                self.bfs_vis.add(succ)
                self.bfs_pending.put(succ)

    def calculate_depth(self):
        self.bfs_vis.clear()
        self.depth_map.clear()
        self.bfs(0)
        for node_id in self.graph.nodes_freq.keys():
            if node_id not in self.bfs_vis:
                self.bfs_vis.add(node_id)
                self.bfs(node_id)

    def read_freq(self, block_frep):
        for node_id in self.graph.nodes_freq.keys():
            self.graph.nodes_freq[node_id] = int(block_frep[node_id])

    def get_roadblocks(self, depth_threshold):
        roadblocks = []
        for cur in self.graph.nodes_freq.keys():
            succ = self.graph.nodes_succ[cur]

            if len(succ) == 1 or len(list(self.graph.edges[cur])) < 2 or self.graph.nodes_freq[cur] == 0:
                continue
            tm = 1
            for ch in list(self.graph.edges[cur]):
                if self.graph.nodes_freq[ch] == 0:
                    tm = 0
            if tm != 0:
                continue

            zero_count = succ.count(0)
            avg = sum(succ) / len(succ)
            variance = sum([(x - avg) ** 2 for x in succ]) / len(succ)
            if self.depth_map[cur] > depth_threshold:
                roadblocks.append({"id": cur, "z": zero_count, "a": avg, "v": variance})
        roadblocks.sort(key=lambda x: (-x["z"], -x["v"], -x["a"]))
        roadblocks = [x["id"] for x in roadblocks]

        return roadblocks

    def dump(self, bottlenecks):
        with open(Path.joinpath(self._output_dir, "bottlenecks.json"), "w") as f:
            ujson.dump(bottlenecks, f)
        logger.debug("bottlenecks dumped")

