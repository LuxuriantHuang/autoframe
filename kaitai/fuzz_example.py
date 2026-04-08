#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
示例：在 fuzzing 流程中使用 robust parser

展示如何：
1. 解析种子文件
2. 模拟变异过程
3. 部分解析非法文件
4. 追踪变异谱系
"""

import json
import random
from pathlib import Path
from extract import build_output_with_metadata, MutationTree


def simulate_bit_flip(input_file: str, output_file: str, position: int):
    """模拟位翻转变异"""
    with open(input_file, "rb") as f:
        data = bytearray(f.read())

    if position < len(data):
        data[position] ^= 0xFF  # Flip all bits at position

    with open(output_file, "wb") as f:
        f.write(data)


def main():
    # 初始化变异树
    tree = MutationTree("example_mutation_tree.json")

    # 1. 解析种子文件
    seed_file = "seed.png"
    print(f"=== Parsing seed file: {seed_file} ===")

    seed_result = build_output_with_metadata(
        seed_file,
        parent_id=None,  # 种子文件没有父节点
        generation=0,
        mutation_info=None
    )

    # 保存种子解析结果
    seed_output = "seed_result.json"
    Path(seed_output).write_text(
        json.dumps(seed_result, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    # 添加到变异树
    tree.add_node(seed_result)
    print(f"Seed ID: {seed_result['file_id']}")
    print(f"Fields parsed: {len(seed_result['fields'])}")
    print(f"Is valid: {seed_result['metadata']['is_valid']}\n")

    # 2. 模拟多代变异
    current_file = seed_file
    current_id = seed_result['file_id']
    current_generation = 0

    for gen in range(1, 4):  # 3代变异
        print(f"=== Generation {gen} ===")

        # 选择随机变异位置（模拟 fuzzer）
        with open(current_file, "rb") as f:
            file_size = len(f.read())
        mutation_pos = random.randint(0, file_size - 1)

        # 应用变异
        mutated_file = f"mutated_gen{gen}.png"
        simulate_bit_flip(current_file, mutated_file, mutation_pos)

        # 解谱变异后的文件（可能是非法的！）
        mutated_result = build_output_with_metadata(
            mutated_file,
            parent_id=current_id,
            generation=gen,
            mutation_info={
                "type": "bit_flip",
                "position": mutation_pos
            }
        )

        # 保存结果
        mutated_output = f"mutated_gen{gen}_result.json"
        Path(mutated_output).write_text(
            json.dumps(mutated_result, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

        # 添加到变异树
        tree.add_node(mutated_result)

        # 输出信息
        print(f"File: {mutated_file}")
        print(f"Mutation: bit_flip at byte {mutation_pos}")
        print(f"File ID: {mutated_result['file_id']}")
        print(f"Fields parsed: {len(mutated_result['fields'])}")
        print(f"Is valid: {mutated_result['metadata']['is_valid']}")

        # 显示解析错误（如果有）
        if not mutated_result['metadata']['is_valid']:
            print(f"Parse errors ({len(mutated_result['metadata']['parse_errors'])}):")
            for err in mutated_result['metadata']['parse_errors'][:3]:  # 显示前3个
                print(f"  - {err['field']}: {err['error']}")
        print()

        # 更新当前文件和ID，继续下一代变异
        current_file = mutated_file
        current_id = mutated_result['file_id']

    # 3. 追溯变异谱系
    print("=== Mutation Lineage ===")
    final_id = current_id
    lineage = tree.get_lineage(final_id)

    for i, node in enumerate(lineage):
        gen = node["metadata"]["generation"]
        path = node["path"] if "path" in node else node["file_path"]
        mut_info = node["metadata"].get("mutation_info", {})
        mut_type = mut_info.get("type", "seed")
        mut_pos = mut_info.get("position", "N/A")

        print(f"Gen {gen}: {path}")
        print(f"  Type: {mut_type}, Position: {mut_pos}")
        print(f"  Fields: {node['field_count']}, Valid: {node['metadata']['is_valid']}")

    # 4. 查找种子文件
    seed_id = tree.get_seed_id(final_id)
    print(f"\nOriginal seed ID: {seed_id}")

    # 5. 输出变异树摘要
    print(f"\n=== Mutation Tree Summary ===")
    print(f"Total nodes: {len(tree.tree)}")
    print(f"Tree saved to: example_mutation_tree.json")


if __name__ == "__main__":
    main()
