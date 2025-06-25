import json

with open("/root/Project/static/static.json", 'r') as f:
    data = json.load(f)

bbs = data['basic_blocks']
fs = data['functions']


def find_function_by_name(functions, target_name):
    """根据函数名找到函数的字典和ID"""
    for func in functions:
        if func["name"] == target_name:
            return func
    return None


def find_all_call_chains(functions, target_id, current_chain, all_chains, visited):
    """递归查找所有调用链，避免循环调用"""
    has_caller = False
    for func in functions:
        if target_id in func["calls"] and func["id"] not in visited:
            visited.add(func["id"])  # 标记当前函数为已访问
            has_caller = True
            find_all_call_chains(functions, func["id"], [func["name"]] + current_chain, all_chains, visited)

    # 如果没有调用者，说明到达了根函数
    if not has_caller:
        all_chains.append(current_chain)


def get_all_call_chains(data, target_function_name):
    """获取从目标函数到根函数的所有调用链"""
    functions = data["functions"]
    # 找到目标函数
    target_function = find_function_by_name(functions, target_function_name)
    if not target_function:
        return f"Error: Function {target_function_name} not found."

    target_id = target_function["id"]
    all_chains = []
    visited = set()  # 用于记录访问过的函数 ID

    # 从目标函数开始递归查找所有调用链
    visited.add(target_id)
    find_all_call_chains(functions, target_id, [target_function_name], all_chains, visited)

    # 格式化结果
    # ret = []
    for chain in all_chains:
        if chain[0] == "main":
            return chain


def get_call_chain(bottleneck_id: int) -> list:
    bb = next((item for item in bbs if item.get("id") == bottleneck_id), None)
    f = next((item for item in fs if item.get("id") == bb["function"]), None)
    fname = f["name"]
    call_chain = get_all_call_chains(data, fname)
    # print(call_chain)
    return call_chain


if __name__ == "__main__":
    get_call_chain(4341)  # test
