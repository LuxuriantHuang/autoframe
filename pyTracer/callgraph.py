from collections import defaultdict

import ujson


class CallEdge:
    def __init__(self):
        self.call_edges = defaultdict(list)
        self.call_graph = CallGraph()
        self.has_new_call_edge = False

    def load(self, raw_data):  # raw = {"id":xx, "calls":[1,2,3,4], ....}
        self.call_edges[raw_data["id"]] = list(set(raw_data["calls"]) | set(raw_data["refs"]))

    def merge(self, info):
        # print(info['info'])
        # {u : [v1, v2, v3]}
        self.call_graph.parse(info)
        self.call_edges = self.call_graph.graph

    def merge_corpus(self, other):
        for other_k, other_v in other.call_edges.items():
            if other_k not in self.call_edges:
                self.has_new_call_edge = True;
                self.call_edges[other_k] = other_v
            elif set(other_v) != set(self.call_edges[other_k]):
                self.has_new_call_edge = True;
                self.call_edges[other_k] = list(set(other_v) | set(self.call_edges[other_k]))

    def dump(self, path):
        self.call_graph.dump(path)


class CallGraph:
    def __init__(self):
        self.graph = defaultdict(list)
        self.func_trace = []
        self.seed_name = ""

    def parse(self, new_info):
        self.seed_name = new_info['seed']
        info_func = new_info['info']['functions']

        stack = []
        for func in info_func:
            self.func_trace.append(func['id'])
            # entry
            if func['en'] == True:
                if self.graph.get(func['id']) is None:
                    self.graph[func['id']] = []
                if len(stack) > 0:
                    self.graph[stack[-1]].append(func['id'])
                stack.append(func['id'])
            # exit
            else:
                if len(stack) == 0:
                    continue
                elif stack[-1] != func['id']:
                    if func['id'] not in stack:
                        continue
                    while len(stack) > 0 and stack[-1] != func['id']:
                        stack.pop()
                else:
                    stack.pop()

    def dump(self, path):
        with open(path, 'w') as f:
            ujson.dump(self.graph, f)
