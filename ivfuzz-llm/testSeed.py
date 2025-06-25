from collections import defaultdict
import errno
import json
import os
import re
from shlex import split
import subprocess
import threading
from LLM import improve_both_no_cover, improve_geneator

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
                    "en": True # entry
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
        t = threading.Timer(timeo, timeout, args=(p,str(seed_path),retcode))
        t.start()
        try:
            _, trace_info = p.communicate()
        finally:
            t.cancel()
        return self.__dump_trace(trace_info), retcode[0]

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

with open("/root/Project/static/static.json",'r') as f:
    static_data = json.load(f)

seed_path = os.path.join('/','root','Project','out','LLM', "queue")
def extract_generator(generator_text):
    code_pattern = r"```python(.*?)```"
    code_match = re.search(code_pattern, generator_text, re.DOTALL)
    
    if not code_match:
        raise ValueError("生成文本中未找到有效的Python代码块")
        
    raw_code = code_match.group(1).strip()
    return raw_code

def run_generator(generator, bottleneck_id, id):
    # 将generator代码写入.py文件中
    file_path = os.path.join('/','root','Project','generator.py')
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(generator)
    
    os.makedirs(seed_path,exist_ok=True)
    # 使用 subprocess 运行文件并捕获输出
    try:
        # 运行命令，捕获标准输出和标准错误
        result = subprocess.run(
            ["python", file_path, os.path.join(seed_path, f"id:{int(id):06},bid:{int(bottleneck_id):06}")],  # 执行的命令
            text=True,  # 以文本形式返回输出
            capture_output=True, # 捕获标准输出和标准错误
            encoding = "utf-8" # 显式指定编码为 UTF-8
        )
        return result.stdout, result.stderr
    except Exception as e:
        print(f"运行generator代码的子线程异常: {e}")
        return None

def count_dicts_by_id(list_of_dicts, target_id):
    count = 0
    for d in list_of_dicts:
        if d.get('id') == target_id:
            count += 1
    return count

def test_seed(id, bid, exec_args):
    exec_path = os.path.join('/','root','Project','target','trace','target_binary')
    
    tracer = SeedTracer(exec_path, exec_args)
    print(os.path.join('/','root','Project','out','LLM','queue',f"id:{id:06},bid:{bid:06}"))
    trace_data, _ = tracer.trace_seed(os.path.join('/','root','Project','out','LLM','queue',f"id:{id:06},bid:{bid:06}"), 60.0)
    cmd_lines = cmd_line = ["python3", "/root/Tracer/id_tracer.py",
            "-tp", "single",
            "-o", "/root/Project/out",
            "-a", 'LLM',
            "-t", "/root/Project/target/trace/target_binary",
            "-arg", "@@",
            "-s", os.path.join("/root/Project/out",
                                "LLM",
                                "queue", os.path.join('/','root','Project','out','LLM','queue',f"id:{id:06},bid:{bid:06}"))]
    process0 = subprocess.Popen(cmd_line, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process0.wait()
    bb_data = trace_data['basic_blocks']
    
    bb_static = static_data['basic_blocks']
    bottleneck_next = next((item for item in bb_static if item.get("id") == bid), None)
    # print(bottleneck_next)
    successor = bottleneck_next['successors']
    # print(successor)
    if len(successor) != 2:
        print("skip")
        return True, bb_data
    print(successor[0], successor[1])
    with open(os.path.join('/','root','Project','static','single', f"id:{id:06},bid:{bid:06}", 'block_freq.json'),'r') as f:
        bb_freq1 = json.load(f)['freq']
    # print(bb_freq1)
    sum_s1 = bb_freq1[int(successor[0])]
    sum_s2 = bb_freq1[int(successor[1])]
    print(sum_s1,sum_s2)
    
    with open(os.path.join('/','root','Project','static','global','block_freq.json'),'r') as f:
        bb_freq = json.load(f)['freq']
    print(bb_freq[successor[0]], bb_freq[successor[1]])
    def check_conditions(left0,right0,left1,right1):
        case1 = (left0 > 0 and left1 > 0) and (right0 == 0 and right1 == 0)
        case2 = (left0 == 0 and left1 == 0) and (right0 > 0 and right1 > 0)
        return case1 or case2
    if check_conditions(bb_freq[successor[0]], bb_freq[successor[1]], sum_s1, sum_s2):
        return False, bb_data, [successor[0] if sum_s1==0 else successor[1]]
    if(sum_s1==0 and sum_s2==0):
        return False, bb_data, [successor[0], successor[1]]
    return True, bb_data, []

def refine(bid, execution_path, messages, call_chain, not_exec_bid):
    function_coverage = ""
    fs = static_data['functions']
    bbs = static_data['basic_blocks']
    code_heat = CodeHeat()
    code_heat.merge(execution_path, bbs)
    # print(code_heat.code_heat)
    for fname in call_chain:
        f = next((item for item in fs if item.get("name") == fname), None)
        filename = f['file_name']
        start = f['lineStart']
        end = f['lineEnd']
        fid = f['id']
        with open(os.path.join('/','root','Project','src', filename)) as f:
            code = [line.rstrip('\n') for line in f.readlines()]
        file_heat = code_heat.code_heat[filename]
        # print(code)
        # print(file_heat)
        for key in file_heat:
            code[key-1] += f'  // coverage: {file_heat[key]}'
        
        function_snippet_list = code[start-1:end]
        function_snippet = '\n'.join(function_snippet_list)
        function_coverage += function_snippet
        function_coverage += '\n\n'
        # function_snippet = function_snippet.split("\n")
        # bb_in_funcs = list(set([bb["id"] for bb in bbs if bb.get("function") == fid]))
        # print(function_snippet[0])
        # print(bb_in_funcs)
        # for bb in bb_in_funcs:
        #     freq = count_dicts_by_id(execution_path, bb)
        #     bb_dict = next((item for item in bbs if item.get("id") == bb), None)
        #     bb_start = bb_dict["lineStart"]
        #     bb_end = bb_dict['lineEnd']
        #     for i in range(bb_start-1, bb_end):
        #         code[i] += f"    // coverage: {freq}"
        # function_snippet_list = code[start-1:end]
        # function_snippet = '\n'.join(function_snippet_list)
        # function_coverage += function_snippet
        # function_coverage += '\n\n'
    
    bb = next((item for item in bbs if item.get("id") == bid), None)
    f = next((item for item in fs if item.get("id") == bb["function"]), None)
    filename = f["file_name"]
    fname = f['name']
    with open(os.path.join('/','root','Project','src', filename)) as f:
        code = [line.rstrip('\n') for line in f.readlines()]
    bottleneck_code = code[bb['lineEnd']-1]
    if len(not_exec_bid)>1:
        print("not reach branch")
        not_cover = []
        for i in not_exec_bid:
            not_cover.append(code[bbs[int(i)]['lineStart']-1])
        advices = improve_both_no_cover(messages, bottleneck_code, fname, not_cover, function_coverage)
        return advices
    # print(bottleneck_code.strip())
    # print(filename, bbs[int(not_exec_bid)]['lineStart'])
    not_cover = code[bbs[int(not_exec_bid[0])]['lineStart']-1]
    # print(not_cover.strip())
    advices = improve_geneator(messages, bottleneck_code, fname, not_cover, function_coverage)
    # with open("test.txt",'w') as f:
    #     f.write(function_coverage)
    return advices

def main():
    # run_generator(generator)使用方法
    a,b,c = test_seed(19,"@@")

if __name__ == "__main__":
    main()