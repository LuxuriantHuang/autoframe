#!/usr/bin/env python3
"""调试脚本：遍历 out_1/default 内 +cov 的 seed，运行 autobug get-branch

用法: python debug_autobug.py [项目名] [输出目录]
示例: python debug_autobug.py calc out_1
"""

import os
import sys
import subprocess
import tempfile
import logging
import time
from pathlib import Path

# 添加项目路径
ROOT_DIR = Path(__file__).resolve().parent

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def has_cov_marker(seed_name: str) -> bool:
    """检查 seed 文件名是否包含 +cov 标记"""
    name_parts = [part.strip() for part in str(seed_name).split(",") if part.strip()]
    return any(part == "+cov" or part.endswith("+cov") for part in name_parts)


def build_seed_invocation(subject: str, fuzzing_args: list[str], seed_path: Path) -> tuple[list[str], bytes | None]:
    """构建运行 seed 的命令

    返回: (command_list, stdin_data)
    - 如果通过 stdin 传递，stdin_data 是 seed 内容
    - 如果通过命令行传递，stdin_data 是 None
    """
    command = [os.fspath(subject)]

    # 检查是否有 @@ 占位符
    has_atat = "@@" in fuzzing_args

    if has_atat:
        # 有 @@ 占位符，通过命令行传递
        for arg in fuzzing_args:
            if arg == "@@":
                command.append(os.fspath(seed_path))
            else:
                command.append(arg)
        return command, None
    else:
        # 没有 @@ 占位符，通过 stdin 传递（calc 的情况）
        command.extend(fuzzing_args)
        stdin_data = seed_path.read_bytes()
        return command, stdin_data


def run_get_branch_for_seed(analyzer: Path, subject: Path, seed_path: Path,
                             fuzzing_args: list, src_path: Path) -> dict:
    """对单个 seed 运行 autobug get-branch"""

    result = {
        "seed_name": seed_path.name,
        "has_cov": has_cov_marker(seed_path.name),
        "success": False,
        "error": None,
        "trace_generated": False,
        "get_branch_returncode": None,
        "branches_found": 0,
    }

    with tempfile.TemporaryDirectory(prefix="debug-autobug-") as tmpdir:
        tmpdir_path = Path(tmpdir)
        trace_path = tmpdir_path / "TRACE.dump"

        # 步骤1: 运行目标程序生成 TRACE.dump
        command, stdin_data = build_seed_invocation(os.fspath(subject), fuzzing_args, seed_path)

        try:
            if stdin_data is not None:
                logger.info(f"  运行目标程序: {' '.join(command)} (通过 stdin, {len(stdin_data)} bytes)")
            else:
                logger.info(f"  运行目标程序: {' '.join(command)}")

            run_result = subprocess.run(
                command,
                input=stdin_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "TRACE_DUMP": os.fspath(trace_path)},
                check=False,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            result["error"] = "目标程序运行超时"
            logger.warning(f"  {result['error']}")
            return result
        except Exception as e:
            result["error"] = f"运行异常: {e}"
            logger.warning(f"  {result['error']}")
            return result

        # 检查 TRACE.dump 是否生成
        if not trace_path.exists():
            result["error"] = f"TRACE.dump 未生成 (returncode={run_result.returncode})"
            logger.warning(f"  {result['error']}")
            return result

        trace_size = trace_path.stat().st_size
        result["trace_generated"] = True
        logger.info(f"  TRACE.dump 生成成功 (大小: {trace_size} bytes)")

        # 步骤2: 运行 get-branch 分析
        branch_cmd = [
            os.fspath(analyzer),
            "get-branch",
            os.fspath(src_path),
            os.fspath(trace_path),
            "--output",
            "/dev/null",
        ]

        try:
            logger.info(f"  运行 get-branch...")
            branch_result = subprocess.run(
                branch_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                check=False,
                cwd=tmpdir,
                timeout=60,
            )
            result["get_branch_returncode"] = branch_result.returncode
        except subprocess.TimeoutExpired:
            result["error"] = "get-branch 超时"
            logger.warning(f"  {result['error']}")
            return result
        except Exception as e:
            result["error"] = f"get-branch 异常: {e}"
            logger.warning(f"  {result['error']}")
            return result

        # 检查 BRANCH.dump 是否生成
        dump_path = tmpdir_path / "BRANCH.dump"
        if branch_result.returncode != 0 or not dump_path.exists():
            stderr = (branch_result.stderr or branch_result.stdout or "").strip()[:400]
            result["error"] = f"get-branch 失败 (returncode={branch_result.returncode}): {stderr}"
            logger.warning(f"  {result['error']}")
            if branch_result.stderr:
                logger.warning(f"  stderr: {branch_result.stderr[:500]}")
            return result

        # 解析 BRANCH.dump
        try:
            dump_content = dump_path.read_text(encoding="utf-8", errors="replace")
            # 格式: path:line [covered]/total
            lines = dump_content.strip().splitlines()
            result["branches_found"] = len(lines)

            # 统计完全覆盖的分支（covered == total）
            fully_covered = 0
            for line in lines:
                # 格式: path:line [covered]/total
                if ']/' in line:
                    try:
                        # 提取 [x]/y 部分
                        import re
                        match = re.search(r'\[(\d+)\]/(\d+)', line)
                        if match:
                            covered = int(match.group(1))
                            total = int(match.group(2))
                            if covered == total:
                                fully_covered += 1
                    except:
                        pass

            result["success"] = True
            result["fully_covered"] = fully_covered
            logger.info(f"  成功! 共 {len(lines)} 个分支，其中 {fully_covered} 个完全覆盖")
        except Exception as e:
            result["error"] = f"读取 BRANCH.dump 失败: {e}"
            logger.warning(f"  {result['error']}")

    return result


def main():
    # 解析命令行参数
    project_name = sys.argv[1] if len(sys.argv) > 1 else "calc"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "out_1"

    # 计算路径
    project_home = ROOT_DIR / "benchmarks" / project_name
    src_path = project_home / "src"
    autobug_dir = project_home / "target" / "autobug"
    queue_dir = project_home / output_dir / "default" / "queue"
    cmdline_path = project_home / output_dir / "default" / "cmdline"
    analyzer_path = ROOT_DIR / "AutoBug" / "autobug"

    logger.info("=" * 60)
    logger.info("AutoBug get-branch 调试脚本")
    logger.info("=" * 60)
    logger.info(f"项目: {project_name}")
    logger.info(f"输出目录: {output_dir}")
    logger.info(f"项目目录: {project_home}")
    logger.info(f"Analyzer: {analyzer_path}")
    logger.info(f"Autobug 目录: {autobug_dir}")
    logger.info(f"Queue: {queue_dir}")
    logger.info(f"SRC: {src_path}")
    logger.info("=" * 60)

    # 检查必要文件
    if not analyzer_path.exists():
        logger.error(f"找不到 analyzer: {analyzer_path}")
        return 1

    if not autobug_dir.exists():
        logger.error(f"找不到 autobug 目录: {autobug_dir}")
        return 1

    # 查找 .autotrace 文件
    autotrace_files = sorted(autobug_dir.glob("*.autotrace"))
    autotrace_files = [f for f in autotrace_files if f.is_file()]

    if not autotrace_files:
        logger.error(f"找不到 .autotrace 文件在 {autobug_dir}")
        return 1

    subject = autotrace_files[0]  # 使用第一个找到的
    logger.info(f"Subject: {subject}")
    logger.info("")

    # 读取 fuzzing_args 从 cmdline 文件
    fuzzing_args = []
    if cmdline_path.exists():
        with open(cmdline_path, "r") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        # 跳过第一行（目标程序），从第二行开始是参数
        fuzzing_args = lines[1:] if len(lines) > 1 else []
        logger.info(f"从 cmdline 读取参数: {fuzzing_args}")
    else:
        logger.info("cmdline 文件不存在，使用空参数")

    if not queue_dir.exists():
        logger.error(f"队列目录不存在: {queue_dir}")
        return 1

    logger.info("")

    # 收集所有 +cov 的 seed
    cov_seeds = []
    all_seeds = []

    for seed_file in sorted(queue_dir.iterdir()):
        if not seed_file.is_file():
            continue
        seed_name = seed_file.name
        all_seeds.append(seed_file)
        if has_cov_marker(seed_name):
            cov_seeds.append(seed_file)

    logger.info(f"总 seed 数: {len(all_seeds)}")
    logger.info(f"+cov seed 数: {len(cov_seeds)}")
    logger.info("")

    if not cov_seeds:
        logger.warning("没有找到 +cov 的 seed，列出所有 seed:")
        for s in all_seeds[:10]:
            logger.info(f"  - {s.name}")
        return 0

    # 遍历 +cov seeds
    results = []
    success_count = 0
    fail_count = 0

    st = time.time()
    for i, seed_path in enumerate(cov_seeds, 1):
        sinst = time.time()
        logger.info(f"[{i}/{len(cov_seeds)}] 处理: {seed_path.name}")
        result = run_get_branch_for_seed(analyzer_path, subject, seed_path, fuzzing_args, src_path)
        results.append(result)

        if result["success"]:
            success_count += 1
        else:
            fail_count += 1
        logger.info(f"单seed耗时：{time.time()-sinst}")
        logger.info("")
    logger.info(f"总时间：{time.time()-st}")
    # 汇总
    logger.info("=" * 60)
    logger.info("汇总:")
    logger.info(f"  总数: {len(cov_seeds)}")
    logger.info(f"  成功: {success_count}")
    logger.info(f"  失败: {fail_count}")
    logger.info("")

    # 显示失败的
    if fail_count > 0:
        logger.info("失败的 seeds:")
        for r in results:
            if not r["success"]:
                logger.info(f"  - {r['seed_name']}: {r['error']}")
        logger.info("")

    return 0


if __name__ == "__main__":
    sys.exit(main())
