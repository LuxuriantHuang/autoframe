#!/usr/bin/env python3
"""
AFL++种子变异树追踪工具
用于追踪种子在变异树上的根节点路径
"""

import os
from typing import Optional, Dict, List


def parse_seed_name(seed_name: str) -> Dict[str, str]:
    """
    解析AFL++种子文件名，提取其中的信息

    例如：
    - id:000000,src:000123,op:havoc,rep:128
    - id:000000,sync:aaa,src:000123,op:havoc,rep:128
    - id:000000,src:000001+000002,op:splice,rep:1

    Args:
        seed_name: 种子文件名

    Returns:
        包含解析信息的字典
    """
    seed_info = {}
    # 去掉文件扩展名（如果有）
    base_name = seed_name.rsplit('.', 1)[0]

    # 分割各个字段
    parts = base_name.split(',')
    for part in parts:
        if ':' in part:
            key, value = part.split(':', 1)
            seed_info[key] = value

    return seed_info


def find_seed_file_by_id(queue_path: str, src_id: str) -> Optional[str]:
    """
    在队列目录中根据src_id查找对应的种子文件

    Args:
        queue_path: 队列路径
        src_id: 源种子ID（如 000123）

    Returns:
        找到的种子文件名，如果找不到则返回None
    """
    if not os.path.exists(queue_path):
        return None

    # 匹配 id:000123, 开头的文件
    prefix = f"id:{src_id},"
    for filename in os.listdir(queue_path):
        if filename.startswith(prefix):
            return filename

    return None


def find_seed_root(queue_path: str, seed_name: str, base_output_path: str = None, visited: set = None) -> Optional[str]:
    """
    找到种子在变异树上的树根的种子路径

    Args:
        queue_path: AFL++种子队列路径
        seed_name: 种子文件名或完整路径
        base_output_path: AFL++输出目录的基础路径（用于处理sync的种子）
                         如果为None，则自动从queue_path推断
        visited: 已访问的种子集合（用于检测循环）

    Returns:
        树根种子的完整路径，如果找不到则返回None
    """
    # 初始化visited集合
    if visited is None:
        visited = set()

    # 提取文件名（如果传入的是完整路径）
    seed_filename = os.path.basename(seed_name)
    current_path = os.path.join(queue_path, seed_filename)

    # 检查是否已经访问过（防止循环）
    if current_path in visited:
        print(f"Warning: Detected circular reference at {current_path}")
        return current_path

    visited.add(current_path)

    # 检查文件是否存在
    if not os.path.exists(current_path):
        return None

    # 解析种子信息
    seed_info = parse_seed_name(seed_filename)

    # 如果没有src字段或者src是000000，说明是原始种子（树根）
    if 'src' not in seed_info or seed_info['src'] == '000000':
        return current_path

    # 如果有sync字段，说明是从其他fuzzer同步过来的
    if 'sync' in seed_info:
        # 推断base_output_path
        if base_output_path is None:
            # queue_path通常是 /path/to/output/default/queue
            # 我们需要找到 /path/to/output
            base_output_path = os.path.normpath(queue_path)
            for _ in range(2):  # 往上两层，从queue目录往上
                base_output_path = os.path.dirname(base_output_path)

        # 构建源fuzzer的队列路径
        source_fuzzer = seed_info['sync']
        source_queue_path = os.path.join(base_output_path, source_fuzzer, 'queue')

        # 在源fuzzer队列中找src对应的种子
        src_id = seed_info['src']
        src_filename = find_seed_file_by_id(source_queue_path, src_id)

        if src_filename is None:
            # 在源fuzzer中找不到，可能是因为该种子没有src字段（如LLM生成的种子）
            # 这种情况下，该种子本身就是树根
            root_candidate = os.path.join(source_queue_path, f"id:{src_id},*")
            # 使用glob来查找匹配的文件
            import glob
            matches = glob.glob(root_candidate)
            if matches:
                return matches[0]
            return None

        # 递归查找树根
        return find_seed_root(source_queue_path, src_filename, base_output_path, visited)

    # 处理splice操作（有两个父种子）
    if '+' in seed_info['src']:
        # 取第一个父种子作为主要路径
        src_ids = seed_info['src'].split('+')
        first_src_id = src_ids[0]

        src_filename = find_seed_file_by_id(queue_path, first_src_id)
        if src_filename is None:
            return None

        # 递归查找树根
        return find_seed_root(queue_path, src_filename, base_output_path, visited)

    # 普通情况，有src字段但没有sync字段
    # 在当前队列中找src对应的种子
    src_id = seed_info['src']
    src_filename = find_seed_file_by_id(queue_path, src_id)

    if src_filename is None:
        return None

    # 递归查找树根
    return find_seed_root(queue_path, src_filename, base_output_path, visited)


def get_seed_lineage(queue_path: str, seed_name: str, base_output_path: str = None) -> List[str]:
    """
    获取种子的完整变异链路径（从种子到树根）

    Args:
        queue_path: AFL++种子队列路径
        seed_name: 种子文件名或完整路径
        base_output_path: AFL++输出目录的基础路径

    Returns:
        从种子到树根的完整路径列表（第一个是种子本身，最后一个是树根）
    """
    lineage = []
    visited = set()

    current_queue = queue_path
    current_seed = seed_name

    while True:
        # 提取文件名
        seed_filename = os.path.basename(current_seed)
        current_path = os.path.join(current_queue, seed_filename)

        # 检查循环或文件不存在
        if current_path in visited or not os.path.exists(current_path):
            break

        visited.add(current_path)
        lineage.append(current_path)

        # 解析种子信息
        seed_info = parse_seed_name(seed_filename)

        # 如果是树根，停止
        if 'src' not in seed_info or seed_info['src'] == '000000':
            break

        # 处理sync
        if 'sync' in seed_info:
            if base_output_path is None:
                base_output_path = os.path.normpath(current_queue)
                for _ in range(2):
                    base_output_path = os.path.dirname(base_output_path)

            source_fuzzer = seed_info['sync']
            current_queue = os.path.join(base_output_path, source_fuzzer, 'queue')
            src_id = seed_info['src']
        else:
            # 处理splice（取第一个父节点）
            if '+' in seed_info['src']:
                src_id = seed_info['src'].split('+')[0]
            else:
                src_id = seed_info['src']

        # 查找下一个种子
        src_filename = find_seed_file_by_id(current_queue, src_id)
        if src_filename is None:
            break

        current_seed = src_filename

    return lineage


# 测试示例
if __name__ == "__main__":
    base_path = "/home/lab420/Desktop/autoframe/benchmarks/libpng/out"
    queue_path = os.path.join(base_path, "default/queue")

    print("=" * 80)
    print("测试1: 普通变异链")
    print("=" * 80)
    test_seed_1 = "id:000675,src:000674,time:8294668,execs:83970824,op:havoc,rep:2"
    result_1 = find_seed_root(queue_path, test_seed_1, base_path)
    print(f"种子: {test_seed_1}")
    print(f"树根: {result_1}")
    lineage_1 = get_seed_lineage(queue_path, test_seed_1, base_path)
    print(f"变异链长度: {len(lineage_1)}")
    for i, path in enumerate(lineage_1):
        print(f"  {i}: {os.path.basename(path)}")
    print()

    print("=" * 80)
    print("测试2: 同步种子（从LLM同步）")
    print("=" * 80)
    test_seed_2 = "id:000682,sync:LLM,src:000053,+cov"
    result_2 = find_seed_root(queue_path, test_seed_2, base_path)
    print(f"种子: {test_seed_2}")
    print(f"树根: {result_2}")
    lineage_2 = get_seed_lineage(queue_path, test_seed_2, base_path)
    print(f"变异链长度: {len(lineage_2)}")
    for i, path in enumerate(lineage_2):
        print(f"  {i}: {os.path.basename(path)}")
    print()

    print("=" * 80)
    print("测试3: Splice操作（两个父节点）")
    print("=" * 80)
    test_seed_3 = "id:000690,src:000682+000152,time:12186217,execs:122960966,op:splice,rep:4,+cov"
    result_3 = find_seed_root(queue_path, test_seed_3, base_path)
    print(f"种子: {test_seed_3}")
    print(f"树根: {result_3}")
    lineage_3 = get_seed_lineage(queue_path, test_seed_3, base_path)
    print(f"变异链长度: {len(lineage_3)}")
    for i, path in enumerate(lineage_3):
        print(f"  {i}: {os.path.basename(path)}")
    print()

    print("=" * 80)
    print("测试4: 树根种子")
    print("=" * 80)
    test_seed_4 = "id:000000,time:0,execs:0,orig:seed.png"
    result_4 = find_seed_root(queue_path, test_seed_4, base_path)
    print(f"种子: {test_seed_4}")
    print(f"树根: {result_4}")
    print()

    print("=" * 80)
    print("测试5: 长变异链")
    print("=" * 80)
    test_seed_5 = "id:000691,src:000666+000636,time:12371835,execs:124824834,op:splice,rep:2,+cov"
    result_5 = find_seed_root(queue_path, test_seed_5, base_path)
    print(f"种子: {test_seed_5}")
    print(f"树根: {result_5}")
    lineage_5 = get_seed_lineage(queue_path, test_seed_5, base_path)
    print(f"变异链长度: {len(lineage_5)}")
    if len(lineage_5) <= 10:
        for i, path in enumerate(lineage_5):
            print(f"  {i}: {os.path.basename(path)}")
    else:
        for i, path in enumerate(lineage_5[:5]):
            print(f"  {i}: {os.path.basename(path)}")
        print(f"  ... (省略 {len(lineage_5) - 10} 个中间节点)")
        for i, path in enumerate(lineage_5[-5:], len(lineage_5) - 5):
            print(f"  {i}: {os.path.basename(path)}")
