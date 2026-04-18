import concurrent.futures
import csv
import hashlib
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
from collections import defaultdict, deque
from input_adapter import build_seed_invocation
import time
import config
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from shlex import split

from LLM.LLMUtil import LLMUtil
from config import *
from parse import extract_single_path_from_function, rewrite_if_to_assert_false_branch
from pyTracer import InfoProcessor, cfg_loader, SeedTracer
from tree_sitter_languages import get_parser, get_language

from dynamic_trace_summary import DynamicTraceCache, DynamicTraceSummary
from pyTracer.callgraph import CallEdge
from slice import llvm_slice

# 添加新的路径常量
SRC_PATH = PROJECT_HOME / "src"
SRC_BEAR_PATH = PROJECT_HOME / "src_bear"

logger = logging.getLogger(LOGGER_NAME + __name__)
parser = get_parser('c')
C_LANGUAGE = get_language('c')
TRACE_PROGRESS_FILE = "trace_progress.json"
_TRACE_DRIVEN_SLICE_MODULE = None
_SOURCE_AST_CACHE: dict[str, tuple[bytes, object]] = {}
_LLVM_SLICE_CACHE: dict[tuple[str, int, int | None, bool], str] = {}
_CALLGRAPH_DOT_CACHE: dict[tuple[str, int, int], dict[str, object]] = {}
_NULL_COMPARE_RE = re.compile(
    r"""
    (
        ==\s*(?:NULL|nullptr|\(\(void\*\)0\)|0)
        |
        !=\s*(?:NULL|nullptr|\(\(void\*\)0\)|0)
        |
        (?:NULL|nullptr|\(\(void\*\)0\)|0)\s*==
        |
        (?:NULL|nullptr|\(\(void\*\)0\)|0)\s*!=
    )
    """,
    re.VERBOSE,
)


def _log_full_slice_result(tag: str, file_name: str, line: int, content: str):
    if not content:
        logger.warning(f"[SLICE] {tag} produced empty content for {file_name}:{line}")
        return
    logger.info(
        f"[SLICE] {tag} full output for {file_name}:{line} ({len(content)} chars)\n"
        f"{content}"
    )


def _extract_source_slice_body(content: str) -> str:
    text = str(content or "")
    match = re.search(
        r"=== Source Slice ===\s*(?P<body>.*?)\s*=== End Source Slice ===",
        text,
        re.DOTALL,
    )
    if match:
        return match.group("body").strip()
    return text.strip()


def _slice_has_meaningful_content(content: str) -> bool:
    return bool(_extract_source_slice_body(content))


def get_text(source_bytes, node):
    return source_bytes[node.start_byte:node.end_byte].decode("utf8")


def collect_identifiers(node, source_bytes, acc):
    """递归收集某个表达式里出现的所有 identifier 名字"""
    if node.type == "identifier":
        acc.append(get_text(source_bytes, node))
    for ch in node.children:
        collect_identifiers(ch, source_bytes, acc)



def find_if_at_line(root, line):
    """找到包含该行的if_statement节点"""
    for node in root.children:
        res = find_if_at_line(node, line) if len(node.children) else None
        if res:
            return res

        if node.type == "if_statement":
            sr, _ = node.start_point
            er, _ = node.end_point
            if sr <= line <= er:
                return node
    return None


def _get_cached_source_ast(path_like) -> tuple[bytes, object] | tuple[None, None]:
    resolved = resolve_source_path(path_like)
    if resolved is None or not resolved.exists():
        return None, None

    cache_key = resolved.as_posix()
    cached = _SOURCE_AST_CACHE.get(cache_key)
    if cached is not None:
        return cached

    try:
        source_bytes = resolved.read_bytes()
    except OSError:
        return None, None

    tree = parser.parse(source_bytes)
    cached = (source_bytes, tree)
    _SOURCE_AST_CACHE[cache_key] = cached
    return cached


def _find_first_identifier(node, source_bytes):
    if node is None:
        return None
    if node.type == "identifier":
        return get_text(source_bytes, node)
    for child in getattr(node, "children", []) or []:
        found = _find_first_identifier(child, source_bytes)
        if found:
            return found
    return None


def _find_enclosing_node_by_type(node, node_type: str):
    cur = node
    while cur is not None:
        if getattr(cur, "type", None) == node_type:
            return cur
        cur = getattr(cur, "parent", None)
    return None


def _function_name_from_definition_node(function_node, source_bytes) -> str:
    if function_node is None:
        return ""

    declarator = function_node.child_by_field_name("declarator")
    func_name = _find_first_identifier(declarator, source_bytes)
    if func_name:
        return func_name

    stack = [function_node]
    while stack:
        node = stack.pop()
        if getattr(node, "type", None) == "function_declarator":
            nested_name = _find_first_identifier(node, source_bytes)
            if nested_name:
                return nested_name
        for child in reversed(getattr(node, "children", []) or []):
            stack.append(child)
    return ""


def find_enclosing_function_metadata(path_like, line: int) -> dict[str, object] | None:
    if int(line or 0) <= 0:
        return None
    source_bytes, tree = _get_cached_source_ast(path_like)
    if source_bytes is None or tree is None:
        return None

    target_line0 = int(line) - 1
    root = tree.root_node
    target_point = (target_line0, 0)

    descendant = None
    try:
        descendant = root.descendant_for_point_range(target_point, target_point)
    except Exception:
        descendant = None

    best_node = _find_enclosing_node_by_type(descendant, "function_definition")
    if best_node is None:
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "function_definition":
                start_row = int(node.start_point[0])
                end_row = int(node.end_point[0])
                if start_row <= target_line0 <= end_row:
                    if best_node is None or (end_row - start_row) < (best_node.end_point[0] - best_node.start_point[0]):
                        best_node = node
            for child in reversed(getattr(node, "children", []) or []):
                child_start = int(child.start_point[0])
                child_end = int(child.end_point[0])
                if child_start <= target_line0 <= child_end:
                    stack.append(child)

    if best_node is None:
        return None

    func_name = _function_name_from_definition_node(best_node, source_bytes)
    resolved = resolve_source_path(path_like)
    return {
        "name": func_name,
        "file_name": os.fspath(resolved if resolved is not None else path_like),
        "lineStart": int(best_node.start_point[0]) + 1,
        "lineEnd": int(best_node.end_point[0]) + 1,
    }


def _is_pointer_like_negation(condition_text: str) -> bool:
    text = condition_text.strip()
    if not text.startswith("!"):
        return False
    inner = text[1:].strip()
    if inner.startswith("(") and inner.endswith(")"):
        inner = inner[1:-1].strip()
    if not inner:
        return False
    return re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:->|\.)\s*[A-Za-z_][A-Za-z0-9_]*)*",
        inner,
    ) is not None


def _looks_like_null_guard_condition(condition_text: str) -> bool:
    normalized = " ".join((condition_text or "").split())
    if not normalized:
        return False
    if _NULL_COMPARE_RE.search(normalized):
        return True
    return _is_pointer_like_negation(normalized)


def _is_immediate_exit_statement(node) -> tuple[bool, str]:
    if node is None:
        return False, ""

    if node.type == "compound_statement":
        stmts = [child for child in node.children if child.type not in {"{", "}"}]
        if len(stmts) != 1:
            return False, ""
        return _is_immediate_exit_statement(stmts[0])

    if node.type == "return_statement":
        return True, "return"
    if node.type == "goto_statement":
        return True, "goto"
    return False, ""


def analyze_low_value_guard_roadblock(roadblock: dict) -> dict[str, object]:
    if roadblock.get("group_type") == "switch":
        return {"should_skip": False}

    status = _canonicalize_roadblock_status(roadblock)
    if status not in {"only_true", "only_false"}:
        return {"should_skip": False}

    line = int(roadblock.get("line", 0) or 0)
    if line <= 0:
        return {"should_skip": False}

    source_bytes, tree = _get_cached_source_ast(roadblock.get("filename"))
    if source_bytes is None or tree is None:
        return {"should_skip": False}

    if_node = find_if_at_line(tree.root_node, line - 1)
    if if_node is None:
        return {"should_skip": False}

    cond_node = if_node.child_by_field_name("condition")
    cons_node = if_node.child_by_field_name("consequence")
    alt_node = if_node.child_by_field_name("alternative")
    if cond_node is None:
        return {"should_skip": False}

    condition_text = get_text(source_bytes, cond_node)
    if not _looks_like_null_guard_condition(condition_text):
        return {"should_skip": False}

    cons_exit, cons_exit_kind = _is_immediate_exit_statement(cons_node)
    alt_exit, alt_exit_kind = _is_immediate_exit_statement(alt_node)

    target_side = None
    exit_kind = ""
    if cons_exit and status == "only_false":
        target_side = "true"
        exit_kind = cons_exit_kind
    elif alt_exit and status == "only_true":
        target_side = "false"
        exit_kind = alt_exit_kind
    else:
        return {"should_skip": False}

    return {
        "should_skip": True,
        "kind": "null_guard_immediate_exit",
        "target_side": target_side,
        "exit_kind": exit_kind,
        "condition": " ".join(condition_text.split()),
        "reason": (
            f"null-guard immediate {exit_kind} on the uncovered {target_side} side"
        ),
    }


def get_first_line_in_if_body(if_node):
    """返回if语句块内部第一条语句的行号(1-based)，若无则返回None"""
    cons = if_node.child_by_field_name("consequence")
    if cons is None:
        return None

    # 情况 A: { ... } 块：compound_statement
    if cons.type == "compound_statement":
        # 找block内部第一个语句
        for ch in cons.children:
            # 跳过 { 和 }
            if ch.type in ("{", "}"):
                continue
            # 这个节点就是第一条语句或语句块
            return ch.start_point[0]

    # 情况 B: 单语句
    return cons.start_point[0]


def find_if_body_first_line(src, target_line):
    source_bytes = src.encode("utf8")
    tree = parser.parse(source_bytes)
    root = tree.root_node

    # 行号转换为 0-based
    line0 = target_line

    if_node = find_if_at_line(root, line0)
    if if_node is None:
        return None

    return get_first_line_in_if_body(if_node)


def extract_function_header_from_code(function_code: str) -> str:
    """
    从函数代码中提取函数头（返回类型、函数名、参数列表）

    参数:
        function_code: 完整的函数定义代码

    返回:
        函数头字符串，格式如: "int main(int argc, char* argv[])"
    """
    if not function_code:
        return "// Unknown function"

    source_bytes = function_code.encode('utf8')
    tree = parser.parse(source_bytes)
    root = tree.root_node

    # 查找函数定义节点
    query = C_LANGUAGE.query(r"""
    (
      function_definition
        type: (_) @type
        declarator: (function_declarator
          declarator: (identifier) @func_name
          parameters: (parameter_list) @params
        ) @declarator
    )
    """)

    captures = query.captures(root)

    if not captures:
        # 如果无法解析，尝试简单提取第一行
        lines = function_code.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('//') and not line.startswith('/*'):
                # 移除开头的 { 和结尾的 {
                return line.rstrip('{').strip()

        return function_code.split('\n')[0].strip()

    # 提取各个部分
    func_info = {}
    for node, capture_name in captures:
        if capture_name in ['type', 'func_name', 'params', 'declarator']:
            func_info[capture_name] = get_text(source_bytes, node)

    # 组合函数头
    if 'type' in func_info and 'declarator' in func_info:
        # 返回类型 + 函数声明
        header = f"{func_info['type'].strip()} {func_info['declarator']}"
    elif 'declarator' in func_info:
        header = func_info['declarator']
    else:
        # 备选方案：提取到第一个 { 之前的内容
        first_brace = function_code.find('{')
        if first_brace != -1:
            header = function_code[:first_brace].strip()
        else:
            header = function_code.split('\n')[0].strip()

    return header


def afl_cov(prog, input_dir):
    cmd = [
        SHOWMAP_PATH,
        "-q", "-i", Path(input_dir) / "default" / "queue",
        "-o", "/dev/null",
        "-m", "none",
        "-C",
        "--", prog, "@@"
    ]
    # 执行命令
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,  # 忽略错误输出
        text=True
    )

    output = result.stdout
    # logger.info(f"afl-showmap 输出: {output}")

    # 正则匹配关键指标
    captured_match = re.search(r"coverage of (\d+) edges were achieved out of (\d+)", output)
    percent_match = re.search(r"\(([\d.]+)%\)", output)

    if not captured_match or not percent_match:
        raise ValueError("无法从 afl-showmap 输出中提取覆盖率信息")

    captured = int(captured_match.group(1))

    return captured


def _get_callsites():
    return globals().get("callsites", [])


def _chain_node_name(node):
    if isinstance(node, dict):
        return node.get("function") or node.get("name")
    return node


def _chain_node_callsite(node):
    if isinstance(node, dict):
        return node.get("via_callsite")
    return None


def format_call_chain(chain):
    return ' -> '.join(_chain_node_name(node) for node in chain)


def _same_source_file(lhs: str, rhs: str) -> bool:
    if not lhs or not rhs:
        return False
    return Path(lhs).name == Path(rhs).name or lhs == rhs


def _make_chain_node(functions, func_id, via_callsite=None, edge_kind=None):
    func = next((item for item in functions if item.get("id") == func_id), None)
    if not func:
        return {"function": str(func_id), "function_id": func_id}
    node = {
        "function": func["name"],
        "function_id": func_id,
    }
    if via_callsite is not None:
        node["via_callsite"] = via_callsite
    if edge_kind is not None:
        node["edge_kind"] = edge_kind
    return node


def _is_sliceable_function(func):
    return bool(func and func.get("file_name") and func.get("lineStart", 0) > 0 and func.get("lineEnd", 0) > 0)


def _get_callee_ids(func, include_refs=False):
    callees = set(func.get("calls", []))
    if include_refs:
        callees.update(func.get("refs", []))
    return callees


def find_all_call_chains(functions, target_id, current_chain, all_chains, visited, include_refs=False,
                         max_depth=None, search_state=None):
    """递归查找所有调用链，避免循环调用"""
    if max_depth is not None and len(current_chain) >= max_depth:
        all_chains.append(current_chain)
        return
    if search_state is not None:
        if search_state["expansions"] >= search_state["max_expansions"]:
            return
        if len(all_chains) >= search_state["max_chains"]:
            return

    has_caller = False
    for func in functions:
        if not _is_sliceable_function(func):
            continue
        if search_state is not None:
            if search_state["expansions"] >= search_state["max_expansions"]:
                break
            if len(all_chains) >= search_state["max_chains"]:
                break
        callee_ids = _get_callee_ids(func, include_refs)
        if target_id in callee_ids and func["id"] not in visited:
            if search_state is not None:
                search_state["expansions"] += 1
            visited.add(func["id"])  # 标记当前函数为已访问
            has_caller = True
            find_all_call_chains(functions, func["id"], [_make_chain_node(functions, func["id"])] + current_chain,
                                 all_chains, visited, include_refs=include_refs, max_depth=max_depth,
                                 search_state=search_state)
            visited.remove(func["id"])

    # 如果没有调用者，说明到达了根函数
    if not has_caller:
        all_chains.append(current_chain)


def _build_callsite_chains(functions, target_id, include_refs=False, max_depth=None, search_state=None):
    callsites = _get_callsites()
    if not callsites:
        return []

    incoming = {}
    for cs in callsites:
        caller_id = cs.get("function")
        if caller_id is None:
            continue
        edge_kind = cs.get("kind", "direct")
        if edge_kind == "direct":
            callee_id = cs.get("callee")
            if callee_id is None:
                continue
            incoming.setdefault(callee_id, []).append((caller_id, cs.get("id"), "direct"))
            continue
        if not include_refs:
            continue
        for callee_id in cs.get("resolved_targets", []):
            incoming.setdefault(callee_id, []).append((caller_id, cs.get("id"), "indirect"))

    all_chains = []
    visited = {target_id}
    current_chain = [_make_chain_node(functions, target_id)]

    def dfs(cur_id, chain):
        if max_depth is not None and len(chain) >= max_depth:
            all_chains.append(chain)
            return
        if search_state is not None:
            if search_state["expansions"] >= search_state["max_expansions"]:
                return
            if len(all_chains) >= search_state["max_chains"]:
                return

        has_caller = False
        for caller_id, callsite_id, edge_kind in incoming.get(cur_id, []):
            if search_state is not None:
                if search_state["expansions"] >= search_state["max_expansions"]:
                    break
                if len(all_chains) >= search_state["max_chains"]:
                    break
            caller_func = next((item for item in functions if item.get("id") == caller_id), None)
            if not _is_sliceable_function(caller_func):
                continue
            if caller_id in visited:
                continue
            if search_state is not None:
                search_state["expansions"] += 1
            visited.add(caller_id)
            has_caller = True
            caller_node = _make_chain_node(functions, caller_id)
            cur_node = dict(chain[0])
            cur_node["via_callsite"] = callsite_id
            cur_node["edge_kind"] = edge_kind
            dfs(caller_id, [caller_node, cur_node] + chain[1:])
            visited.remove(caller_id)
        if not has_caller:
            all_chains.append(chain)

    dfs(target_id, current_chain)
    return all_chains


def _dedupe_call_chains(call_chains):
    deduped = []
    seen = set()
    for chain in call_chains:
        key = tuple(
            (
                _chain_node_name(node),
                node.get("function_id") if isinstance(node, dict) else None,
                node.get("via_callsite") if isinstance(node, dict) else None,
            )
            for node in chain
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(chain)
    return deduped


def _load_callgraph_dot_data(callgraph_path: Path) -> dict[str, object]:
    try:
        stat = callgraph_path.stat()
    except OSError:
        return {"incoming": {}, "nodes": set()}

    cache_key = (callgraph_path.as_posix(), int(stat.st_mtime_ns), int(stat.st_size))
    cached = _CALLGRAPH_DOT_CACHE.get(cache_key)
    if cached is not None:
        return cached

    incoming: dict[str, list[tuple[str, str]]] = defaultdict(list)
    nodes: set[str] = set()
    edge_re = re.compile(
        r'^\s*"(?P<caller>[^"]+)"\s*->\s*"(?P<callee>[^"]+)"\s*\[label="(?P<label>[^"]+)"\];\s*$'
    )
    node_re = re.compile(r'^\s*"(?P<name>[^"]+)"\s*;\s*$')
    try:
        lines = callgraph_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"incoming": {}, "nodes": set()}

    for line in lines:
        edge_match = edge_re.match(line)
        if edge_match:
            caller = edge_match.group("caller")
            callee = edge_match.group("callee")
            label = edge_match.group("label")
            nodes.add(caller)
            nodes.add(callee)
            incoming[callee].append((caller, label))
            continue
        node_match = node_re.match(line)
        if node_match:
            nodes.add(node_match.group("name"))

    payload = {"incoming": dict(incoming), "nodes": nodes}
    _CALLGRAPH_DOT_CACHE.clear()
    _CALLGRAPH_DOT_CACHE[cache_key] = payload
    return payload


def _get_callgraph_dot_path() -> Path:
    return STATIC_PATH / "callgraph.dot"


def _build_call_chains_from_dot(
    target_function_name: str,
    *,
    include_refs: bool = False,
    max_depth: int = 12,
    max_chains: int = 20,
) -> list[list[str]]:
    callgraph_path = _get_callgraph_dot_path()
    if not callgraph_path.exists():
        return []

    payload = _load_callgraph_dot_data(callgraph_path)
    incoming = payload.get("incoming", {})
    nodes = payload.get("nodes", set())
    if target_function_name not in nodes:
        return []

    valid_entry_points = {"LLVMFuzzerTestOneInput", "main", "fuzz", "fuzzer_initialize", "fuzzer_test_one_input"}
    chains: list[list[str]] = []
    visited = {target_function_name}

    def dfs(current: str, suffix: list[str]):
        if len(chains) >= max_chains:
            return
        if len(suffix) >= max_depth:
            if suffix[0] in valid_entry_points:
                chains.append(list(suffix))
            return

        callers = incoming.get(current, [])
        expanded = False
        for caller, label in callers:
            if label == "ref" and not include_refs:
                continue
            if caller in visited:
                continue
            expanded = True
            visited.add(caller)
            dfs(caller, [caller] + suffix)
            visited.remove(caller)
            if len(chains) >= max_chains:
                return

        if not expanded and suffix[0] in valid_entry_points:
            chains.append(list(suffix))

    dfs(target_function_name, [target_function_name])
    return _dedupe_call_chains(chains)


def get_all_call_chains(functions, target_function_name, include_refs=False,
                        max_depth=None, max_chains=20, max_expansions=2000):
    # 找到目标函数
    target_function = find_function_by_name(functions, target_function_name)
    if not target_function:
        return []

    target_id = target_function["id"]
    search_state = {
        "expansions": 0,
        "max_expansions": max_expansions,
        "max_chains": max_chains,
    }

    all_chains = _build_callsite_chains(
        functions, target_id, include_refs=include_refs, max_depth=max_depth, search_state=search_state
    )
    if not all_chains:
        all_chains = []
        visited = set()
        visited.add(target_id)
        find_all_call_chains(
            functions, target_id, [_make_chain_node(functions, target_id)], all_chains, visited,
            include_refs=include_refs, max_depth=max_depth, search_state=search_state
        )

    valid_entry_points = {"LLVMFuzzerTestOneInput", "main", "fuzz", "fuzzer_initialize", "fuzzer_test_one_input"}
    ret = []
    for chain in _dedupe_call_chains(all_chains):
        if _chain_node_name(chain[0]) in valid_entry_points:
            ret.append(chain)
        if len(ret) >= max_chains:
            break
    return ret


def find_function_by_name(functions, target_name):
    """根据函数名找到函数的字典和ID"""
    for func in functions:
        if func["name"] == target_name:
            return func
    return None


def find_function_content_by_name(root, target_func, source_bytes):
    query = C_LANGUAGE.query(r"""
    (
      function_definition
        declarator: (function_declarator
          declarator: (identifier) @func_name
        )
    )
    """)

    captures = query.captures(root)

    for node, cap in captures:
        if cap != "func_name":
            continue

        func_name = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
        if func_name != target_func:
            continue

        # 向上找到 enclosing function_definition
        cur = node
        while cur is not None and cur.type != "function_definition":
            cur = cur.parent

        if cur is None:
            return None  # 理论上不该发生

        # 输出完整函数内容（含返回类型/签名/函数体）
        return source_bytes[cur.start_byte:cur.end_byte].decode("utf-8", errors="replace")

    return None


def get_call_chain(fname, include_refs=False) -> list | None:
    dot_chains = _build_call_chains_from_dot(
        fname,
        include_refs=include_refs,
        max_depth=12 if not include_refs else 8,
        max_chains=20 if not include_refs else 10,
    )
    if dot_chains:
        logger.info(f"[CALLCHAIN] DOT callgraph chains found for {fname}: {len(dot_chains)}")
        return dot_chains

    if include_refs:
        direct_chains = get_all_call_chains(
            funcs, fname, include_refs=False, max_depth=12, max_chains=20, max_expansions=1500
        )
        if direct_chains:
            logger.info(f"[CALLCHAIN] Direct/callsite chains found for {fname}: {len(direct_chains)}")
            return direct_chains

        logger.info(f"[CALLCHAIN] Direct/callsite chains not found for {fname}, trying refs-assisted fallback")
        ref_chains = get_all_call_chains(
            funcs, fname, include_refs=True, max_depth=8, max_chains=10, max_expansions=800
        )
        logger.info(f"[CALLCHAIN] Refs-assisted fallback result for {fname}: {len(ref_chains)} chain(s)")
        return ref_chains

    call_chain = get_all_call_chains(
        funcs, fname, include_refs=False, max_depth=12, max_chains=20, max_expansions=1500
    )
    return call_chain


def _normalize_dynamic_context(dynamic_context: dict | None) -> dict:
    if not dynamic_context:
        return {}
    normalized = dict(dynamic_context)
    normalized.setdefault("preferred_call_paths", [])
    normalized.setdefault("preferred_functions", [])
    normalized.setdefault("preferred_locations", {})
    normalized.setdefault("dynamic_call_edges", {})
    normalized.setdefault("representative_seed_path", None)
    normalized.setdefault("all_hit_seed_paths", [])
    normalized.setdefault("all_hit_seed_names", [])
    normalized.setdefault("trace_args", None)
    normalized["preferred_functions"] = list(normalized.get("preferred_functions") or [])
    normalized["preferred_call_paths"] = [list(path) for path in normalized.get("preferred_call_paths") or [] if path]
    normalized["all_hit_seed_paths"] = [str(path) for path in normalized.get("all_hit_seed_paths") or [] if path]
    normalized["all_hit_seed_names"] = [str(name) for name in normalized.get("all_hit_seed_names") or [] if name]
    normalized["dynamic_call_edges"] = {
        str(caller): set(callees or [])
        for caller, callees in (normalized.get("dynamic_call_edges") or {}).items()
    }
    normalized["preferred_locations"] = {
        str(file_name): sorted({int(line) for line in (lines or []) if int(line) > 0})
        for file_name, lines in (normalized.get("preferred_locations") or {}).items()
    }
    return normalized


def _load_trace_driven_slice_module():
    global _TRACE_DRIVEN_SLICE_MODULE
    if _TRACE_DRIVEN_SLICE_MODULE is not None:
        return _TRACE_DRIVEN_SLICE_MODULE
    module_path = Path(__file__).resolve().parent / "tools" / "trace_driven_slice.py"
    spec = importlib.util.spec_from_file_location("trace_driven_slice_runtime", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load trace-driven slicer from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _TRACE_DRIVEN_SLICE_MODULE = module
    return module


def _branch_cover_mode_from_only_side(only_side) -> str:
    if only_side == "only_true":
        return "true"
    if only_side == "only_false":
        return "false"
    return "auto"


def _canonicalize_roadblock_status(roadblock: dict) -> str:
    status = str(roadblock.get("status") or "").strip()
    if status in {"only_true", "only_false"}:
        return status

    side = str(roadblock.get("side") or "").strip().lower()
    if status in {"zero_covered", "one_covered"}:
        if side == "false":
            return "only_true"
        if side == "true":
            return "only_false"

    return status


def _try_trace_driven_slice(context: dict, file_name: str, line: int, only_side) -> str:
    seed_path = context.get("representative_seed_path")
    preferred_path = context.get("representative_call_path") or []
    trace_args = context.get("trace_args")
    if not trace_args:
        trace_args = globals().get("fuzzing_args", "")
    if not seed_path or not os.path.exists(seed_path):
        return ""
    try:
        module = _load_trace_driven_slice_module()
        summary, rendered = module.build_trace_driven_slice(
            trace_bin=str(TRACE_TARGET_PATH),
            trace_args=trace_args,
            seed_path=seed_path,
            static_json=os.fspath(STATIC_PATH / "static.json"),
            source_root=os.fspath(PROJECT_HOME),
            target_file=file_name,
            target_line=int(line),
            branch_cover=_branch_cover_mode_from_only_side(only_side),
        )
    except Exception as exc:
        logger.warning(f"[SLICE] Trace-driven slice failed for {file_name}:{line}: {exc}")
        return ""
    if not getattr(summary, "target_hit", False):
        logger.info(f"[SLICE] Trace-driven slice missed target {file_name}:{line}")
        return ""
    if preferred_path and list(getattr(summary, "call_path", []) or []) != list(preferred_path):
        logger.info(
            f"[SLICE] Trace-driven slice call path differs for {file_name}:{line}: "
            f"{getattr(summary, 'call_path', [])}"
        )
    if not rendered or len(rendered.strip()) < 80:
        return ""
    return rendered


def _rank_call_chains_with_dynamic_context(call_chains, dynamic_context, fallback_scorer=None):
    context = _normalize_dynamic_context(dynamic_context)
    if not context:
        if fallback_scorer:
            return sorted(call_chains, key=fallback_scorer, reverse=True)
        return call_chains

    preferred_paths = context.get("preferred_call_paths", [])
    preferred_functions = set(context.get("preferred_functions", []))
    dynamic_edges = context.get("dynamic_call_edges", {})

    def score(chain):
        chain_names = [_chain_node_name(node) for node in chain]
        prefix_overlap = 0
        for path in preferred_paths:
            overlap = 0
            for lhs, rhs in zip(chain_names, path):
                if lhs != rhs:
                    break
                overlap += 1
            prefix_overlap = max(prefix_overlap, overlap)
        function_overlap = sum(1 for name in chain_names if name in preferred_functions)
        edge_overlap = 0
        for caller, callee in zip(chain_names, chain_names[1:]):
            if callee in dynamic_edges.get(caller, set()):
                edge_overlap += 1
        base_score = fallback_scorer(chain) if fallback_scorer else ()
        return (prefix_overlap, function_overlap, edge_overlap, base_score)

    return sorted(call_chains, key=score, reverse=True)


def _extract_function_blocks(slice_text: str) -> list[tuple[str | None, list[str]]]:
    blocks = []
    current_name = None
    current_lines = []
    func_pattern = re.compile(r"^\s*(?:[A-Za-z_][\w\s\*\(\),]*\s+)?([A-Za-z_]\w*)\s*\([^;]*\)\s*\{")
    for line in slice_text.splitlines():
        if current_lines:
            match = func_pattern.match(line)
            if match and line.strip() and not line.lstrip().startswith("//"):
                blocks.append((current_name, current_lines))
                current_lines = [line]
                current_name = match.group(1)
                continue
            current_lines.append(line)
            continue
        current_lines = [line]
        match = func_pattern.match(line)
        current_name = match.group(1) if match else None
    if current_lines:
        blocks.append((current_name, current_lines))
    return blocks


def _post_filter_slice_with_dynamic_context(slice_text: str, dynamic_context: dict | None, target_file: str, target_line: int):
    context = _normalize_dynamic_context(dynamic_context)
    if not context or not slice_text:
        return slice_text

    preferred_functions = set(context.get("preferred_functions", []))
    preferred_locations = context.get("preferred_locations", {})
    target_locations = set(preferred_locations.get(target_file, []))
    if not preferred_functions and not target_locations:
        return slice_text

    blocks = _extract_function_blocks(slice_text)
    if len(blocks) <= 1:
        return slice_text

    kept_blocks = []
    for func_name, lines in blocks:
        block_text = "\n".join(lines)
        keep = False
        if func_name and func_name in preferred_functions:
            keep = True
        if f"{target_line}" in block_text and Path(target_file).name in block_text:
            keep = True
        if any(str(line_no) in block_text for line_no in target_locations):
            keep = True
        if not func_name:
            keep = True
        if keep:
            kept_blocks.append(block_text)

    filtered = "\n".join(block for block in kept_blocks if block.strip()).strip()
    if len(filtered) < max(120, int(len(slice_text) * 0.2)):
        return slice_text
    return filtered + "\n"


def _build_slice_cache_label(target_name: str, line: int, original_target_line: int | None, use_svf_callpath: bool) -> str:
    case_part = f"case_{int(original_target_line)}" if original_target_line else "case_none"
    svf_part = "svf_on" if use_svf_callpath else "svf_off"
    return f"{target_name}_{int(line)}_{case_part}_{svf_part}"


def get_function_slice(call_chain, rb_line, only_side, llm_util, dynamic_context=None, original_target_line=None, target_file=None):
    logger.info(
        f"[SLICE] get_function_slice called - call_chain: {call_chain}, rb_line: {rb_line}, "
        f"original_target_line: {original_target_line}, only_side: {only_side}")
    context = _normalize_dynamic_context(dynamic_context)
    target_meta = None
    target_name = None
    preferred_functions = set(context.get("preferred_functions", []))
    chain_nodes = list(reversed(call_chain))
    if preferred_functions:
        chain_nodes = sorted(
            chain_nodes,
            key=lambda node: (_chain_node_name(node) not in preferred_functions, 0),
        )
    for chain_node in chain_nodes:
        fname = _chain_node_name(chain_node)
        func_meta = next((item for item in funcs if item.get("name") == fname), None)
        if _is_sliceable_function(func_meta):
            target_meta = func_meta
            target_name = fname
            break

    if not target_meta:
        fallback_file = resolve_source_path(target_file) if target_file else None
        if fallback_file is None:
            logger.warning("[SLICE] No sliceable function found in call chain")
            return ""
        target_meta = find_enclosing_function_metadata(fallback_file, rb_line) or {
            "file_name": os.fspath(fallback_file),
            "lineStart": int(rb_line or 0),
            "lineEnd": int(rb_line or 0),
            "name": "",
        }
        target_name = str(target_meta.get("name") or Path(os.fspath(fallback_file)).stem)

    file = target_meta['file_name']
    line = rb_line
    if context.get("representative_seed_path"):
        trace_driven = _try_trace_driven_slice(context, file, line, only_side)
        if trace_driven:
            logger.info(f"[SLICE] Using trace-driven slice for {file}:{line}")
            _log_full_slice_result("trace-driven slice", file, line, trace_driven)
            return trace_driven + '\n'
    logger.info(f"[SLICE] Running single-pass slicer for bottleneck {target_name} at {file}:{line}")
    use_svf_callpath = len(call_chain) > 1
    cache_key = (
        file,
        int(line or 0),
        int(original_target_line or 0) or None,
        use_svf_callpath,
    )
    cached_snippet = _LLVM_SLICE_CACHE.get(cache_key)
    if cached_snippet:
        logger.info(
            f"[SLICE] Reusing cached LLVM slice for {file}:{line} "
            f"(case_line={original_target_line}, svf_callpath={use_svf_callpath})"
        )
        if _slice_has_meaningful_content(cached_snippet):
            function_snippet = _post_filter_slice_with_dynamic_context(cached_snippet, context, file, line)
            logger.info(f"[SLICE] get_function_slice completed - code_snippet length: {len(function_snippet)} chars")
            return function_snippet + '\n'
        logger.warning(f"[SLICE] Ignoring cached empty LLVM slice for {file}:{line}")
    slice_label = _build_slice_cache_label(target_name, line, original_target_line, use_svf_callpath)
    slice_path = config.get_slice_output_path(slice_label)
    if slice_path.exists():
        function_snippet = slice_path.read_text(encoding='utf-8', errors='ignore').strip()
        if _slice_has_meaningful_content(function_snippet) and "No matching instruction found" not in function_snippet:
            _LLVM_SLICE_CACHE[cache_key] = function_snippet
            logger.info(
                f"[SLICE] Reusing disk-cached LLVM slice for {file}:{line} "
                f"(case_line={original_target_line}, svf_callpath={use_svf_callpath})"
            )
            function_snippet = _post_filter_slice_with_dynamic_context(function_snippet, context, file, line)
            logger.info(f"[SLICE] get_function_slice completed - code_snippet length: {len(function_snippet)} chars")
            return function_snippet + '\n'
        if function_snippet and "No matching instruction found" not in function_snippet:
            logger.warning(f"[SLICE] Ignoring disk-cached empty LLVM slice for {file}:{line}")
    llvm_slice(
        file,
        line,
        bcfile_path.as_posix(),
        os.fspath(slice_path),
        case_line=original_target_line,
        use_svf_callpath=use_svf_callpath,
    )

    if slice_path.exists():
        with open(slice_path, 'r') as f:
            function_snippet = f.read().strip()
        if "No matching instruction found" in function_snippet:
            logger.warning(f"[SLICE] Slice failed for {file}:{line} - 'No matching instruction found'")
            return "No matching instruction found"
        if _slice_has_meaningful_content(function_snippet):
            _LLVM_SLICE_CACHE[cache_key] = function_snippet
            function_snippet = _post_filter_slice_with_dynamic_context(function_snippet, context, file, line)
            logger.info(f"[SLICE] get_function_slice completed - code_snippet length: {len(function_snippet)} chars")
            _log_full_slice_result("LLVM slice", file, line, function_snippet)
            return function_snippet + '\n'
        if function_snippet:
            logger.warning(f"[SLICE] LLVM slice markers were present but source body was empty for {file}:{line}")

    autobug_slice = str(context.get("autobug_slice") or "").strip()
    if _slice_has_meaningful_content(autobug_slice):
        autobug_slice = _post_filter_slice_with_dynamic_context(autobug_slice, context, file, line)
        logger.info(f"[SLICE] Falling back to autobug slice for {file}:{line}")
        _log_full_slice_result("autobug fallback slice", file, line, autobug_slice)
        return autobug_slice + '\n'

    logger.warning(f"[SLICE] Empty slice for {file}:{line}, falling back to target function source")
    start = target_meta['lineStart']
    end = target_meta['lineEnd']
    if os.path.exists(SRC_BEAR_PATH / file):
        with open(SRC_BEAR_PATH / file) as source_file:
            codee = source_file.readlines()
            code = ''.join(codee)
    else:
        with open(SRC_PATH / file) as source_file:
            codee = source_file.readlines()
            code = ''.join(codee)

    function = find_function_content_by_name(parser.parse(code.encode('utf-8')).root_node, target_name,
                                             code.encode('utf-8'))
    if function:
        function = _post_filter_slice_with_dynamic_context(function, context, file, line)
        _log_full_slice_result("fallback function source", file, line, function)
        return function + '\n'
    if start > 0 and end >= start:
        fallback = ''.join(codee[start - 1:end])
    else:
        metadata = find_enclosing_function_metadata(file, line)
        if metadata and metadata.get("lineStart") and metadata.get("lineEnd"):
            fallback = ''.join(codee[int(metadata["lineStart"]) - 1:int(metadata["lineEnd"])])
        else:
            window_start = max(0, int(line) - 5)
            window_end = min(len(codee), int(line) + 5)
            fallback = ''.join(codee[window_start:window_end])
    fallback = _post_filter_slice_with_dynamic_context(fallback, context, file, line)
    _log_full_slice_result("fallback raw range", file, line, fallback)
    return fallback + '\n'


def get_harness_code():
    """
    Extract the full source code of main and LLVMFuzzerTestOneInput functions.
    This is used when falling back to single function slice to provide full context.

    Returns:
        str: Combined source code of main and LLVMFuzzerTestOneInput, separated by comments.
             Returns None if both functions are not found.
    """
    harness_functions = ["main", "LLVMFuzzerTestOneInput"]
    harness_codes = []

    for func_name in harness_functions:
        # Find the function in static.json
        func_info = next((f for f in funcs if f.get("name") == func_name), None)
        if not func_info:
            logger.debug(f"[HARNESS] Function {func_name} not found in static.json")
            continue

        file_name = func_info.get('file_name', '')
        line_start = func_info.get('lineStart', 0)
        line_end = func_info.get('lineEnd', 0)

        if not file_name or line_start == 0:
            logger.warning(f"[HARNESS] Invalid metadata for {func_name}: {func_info}")
            continue

        try:
            src_path = config.resolve_source_path(file_name)
        except NameError:
            # Fall back to the directly imported symbol if the module alias is
            # unavailable in a long-running process.
            src_path = resolve_source_path(file_name)
        if not src_path:
            logger.warning(f"[HARNESS] Source file not found for {func_name}: {file_name}")
            continue

        try:
            with open(src_path, 'r') as f:
                lines = f.readlines()

            # Extract function content (1-indexed in static.json)
            func_lines = lines[line_start - 1:line_end]
            func_content = ''.join(func_lines)

            harness_codes.append(f"// ===== Function: {func_name} =====\n{func_content}")
            logger.debug(f"[HARNESS] Extracted {len(func_lines)} lines from {func_name}")

        except Exception as e:
            logger.error(f"[HARNESS] Error reading {func_name} from {src_path}: {e}")

    if harness_codes:
        combined_code = '\n\n'.join(harness_codes)
        logger.debug(f"[HARNESS] Combined harness code length: {len(combined_code)} chars")
        logger.debug(f"[HARNESS] Full harness code\n{combined_code}")
        return combined_code
    else:
        logger.warning("[HARNESS] No harness functions found")
        return None


class CoverageTracer:
    def __init__(self, input_dir, output_dir, fuzzing_args, target_prog, trace_prog, bb, func, input_adapter_spec=None):
        self.last_coverage = 0
        self.last_growth_time = time.time()

        self.input_dir = input_dir
        self.output_dir = output_dir
        self.fuzzing_args = fuzzing_args
        self.target_prog = target_prog
        self.trace_prog = trace_prog
        self.input_adapter_spec = input_adapter_spec
        self.info = InfoProcessor.InfoProcesser(STATIC_PATH)
        self.bb = bb
        self.func = func
        self.cfg_loader = None
        self.seed_tracer = SeedTracer.SeedTracer(trace_prog, " ".join(fuzzing_args))
        self.call_edge = CallEdge()
        self.trace_dir = RUN_TRACE_PATH
        self.trace_dir.mkdir(parents=True, exist_ok=True)
        self.trace_progress_path = self.trace_dir / TRACE_PROGRESS_FILE
        self.last_trace_timestamp_ns = self._load_trace_progress()

        # 初始化timing log路径和标志（整个运行周期只创建一次）
        self.timing_log_path = self.trace_dir / f"trace_timing_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self.timing_log_initialized = False
        self.total_seed_index = 0  # 全局种子索引计数器
        self._recent_trace_frontier = {
            "files": set(),
            "functions": set(),
        }
        self.dynamic_trace_cache = DynamicTraceCache(self.trace_dir / "cache")
        self._autobug_seed_branch_cache: dict[str, dict[str, object] | None] = {}
        self._autobug_seed_branch_cache_lock = threading.Lock()
        self._autobug_cache_dir = self.trace_dir / "autobug"
        self._autobug_cache_dir.mkdir(parents=True, exist_ok=True)
        self._autobug_branch_cache_path = self._autobug_cache_dir / "seed_branches.json"
        self._autobug_pending_seed_names: deque[str] = deque()
        self._autobug_pending_seed_name_set: set[str] = set()
        self._autobug_prime_lock = threading.Lock()
        self._autobug_queue_lock = threading.Lock()
        self._autobug_prime_thread = None  # 改用普通线程，不用 ThreadPoolExecutor
        self._autobug_prime_stop_event = threading.Event()
        self._autobug_queue_read_files: set[Path] = set()
        self._autobug_queue_last_scan_time_ns = 0
        self._autobug_last_queue_poll_at = 0.0
        # cond_status system (ported from hyllfuzz)
        self._cond_status_lock = threading.Lock()
        self._cond_status: dict[str, dict[str, set[str]]] = {}  # cond_key → {branch_key → {seed_names}}
        self._interest_lock = threading.Lock()
        self._interesting_conds: dict[str, float] = {}  # cond_key → score
        self._never_interest_lock = threading.Lock()
        self._never_interesting_conds: set[str] = set()
        self._agent_seed_registry_lock = threading.Lock()
        self._agent_seed_registry: dict[str, str] = {}  # seed_name → cond_key
        # Reward feedback: seed origin tracking (queue:seed_id → roadblock_key)
        self._seed_origin_lock = threading.Lock()
        self._seed_origin_map: dict[str, str] = {}  # "LLM:000003" → roadblock_key
        self._reward_state_path = self._autobug_cache_dir / "seed_reward_state.json"
        self._rewarded_sync_ids: set[str] = set()
        self._load_persisted_autobug_branch_cache()
        self._load_seed_origin_map()
        stats = self._read_fuzzer_stats_summary()
        if stats.get("edges_found") is not None:
            self.last_coverage = int(stats["edges_found"])
        self.last_growth_time = time.time()

    def _read_fuzzer_stats_summary(self) -> dict[str, int | None]:
        stats: dict[str, int | None] = {
            "edges_found": None,
            "time_wo_finds": None,
            "last_find": None,
        }
        try:
            with open(FUZZER_STATS_PATH, 'r') as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if ':' not in line:
                        continue
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    if key not in stats:
                        continue
                    try:
                        stats[key] = int(value)
                    except ValueError:
                        logger.warning(f"[COVERAGE] Invalid {key} value in {FUZZER_STATS_PATH}: {value}")
            return stats
        except FileNotFoundError:
            logger.warning(f"[COVERAGE] fuzzer_stats file not found at {FUZZER_STATS_PATH}")
        except Exception as e:
            logger.error(f"[COVERAGE] Error reading fuzzer_stats {FUZZER_STATS_PATH}: {e}")
        return stats

    @staticmethod
    def _serialize_autobug_branch_payload(payload: dict[str, dict[str, object]] | None):
        if payload is None:
            return None
        serialized: dict[str, dict[str, object]] = {}
        for cond_key, branch_payload in payload.items():
            serialized[cond_key] = {
                "branches": sorted(int(branch) for branch in branch_payload.get("branches", set())),
                "total": int(branch_payload.get("total", 0) or 0),
            }
        return serialized

    @staticmethod
    def _deserialize_autobug_branch_payload(payload):
        if payload is None:
            return None
        deserialized: dict[str, dict[str, object]] = {}
        for cond_key, branch_payload in (payload or {}).items():
            deserialized[str(cond_key)] = {
                "branches": {
                    int(branch)
                    for branch in (branch_payload.get("branches", []) or [])
                    if str(branch).isdigit()
                },
                "total": int(branch_payload.get("total", 0) or 0),
            }
        return deserialized

    def _load_persisted_autobug_branch_cache(self) -> None:
        if not self._autobug_branch_cache_path.exists():
            return
        try:
            payload = json.loads(self._autobug_branch_cache_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("[AUTOBUG] Failed to load branch cache %s: %s", self._autobug_branch_cache_path, exc)
            return

        seeds = payload.get("seeds", {})
        with self._autobug_seed_branch_cache_lock:
            for seed_name, seed_payload in seeds.items():
                self._autobug_seed_branch_cache[str(seed_name)] = self._deserialize_autobug_branch_payload(seed_payload)

    def _save_persisted_autobug_branch_cache(self) -> None:
        with self._autobug_seed_branch_cache_lock:
            cached_items = list(self._autobug_seed_branch_cache.items())
        payload = {
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "seeds": {
                seed_name: self._serialize_autobug_branch_payload(seed_payload)
                for seed_name, seed_payload in sorted(cached_items)
            },
        }
        try:
            self._autobug_branch_cache_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning("[AUTOBUG] Failed to save branch cache %s: %s", self._autobug_branch_cache_path, exc)

    # ── Reward feedback: seed origin tracking ──────────────────────────

    def _load_seed_origin_map(self) -> None:
        if not self._reward_state_path.exists():
            return
        try:
            payload = json.loads(self._reward_state_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("[REWARD] Failed to load seed origin state %s: %s", self._reward_state_path, exc)
            return
        origins = payload.get("origins", {})
        with self._seed_origin_lock:
            self._seed_origin_map.update(origins)
        rewarded = payload.get("rewarded_sync_ids", [])
        self._rewarded_sync_ids.update(rewarded)
        logger.info(
            "[REWARD] Loaded seed origin state: %d origins, %d already rewarded",
            len(self._seed_origin_map),
            len(self._rewarded_sync_ids),
        )

    def _save_seed_origin_map(self) -> None:
        with self._seed_origin_lock:
            origins = dict(self._seed_origin_map)
        rewarded = list(self._rewarded_sync_ids)
        payload = {
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "version": 1,
            "origins": origins,
            "rewarded_sync_ids": rewarded,
        }
        try:
            self._reward_state_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning("[REWARD] Failed to save seed origin state %s: %s", self._reward_state_path, exc)

    @staticmethod
    def _extract_seed_field(seed_name: str, field: str) -> str | None:
        """Extract a named field from an AFL seed filename (e.g. 'src' from 'id:001,sync:LLM,src:003,+cov')."""
        for part in seed_name.split(","):
            if part.startswith(f"{field}:"):
                return part[len(field) + 1:]
        return None

    def register_generated_seed(self, seed_name: str, roadblock_key: str, queue_name: str) -> None:
        """Record that a seed was generated targeting a specific roadblock.

        Args:
            seed_name: The seed filename (e.g. 'id:000003,path:direct_generation,bid:000042').
            roadblock_key: The roadblock_key this seed targets.
            queue_name: Which queue the seed is placed in ('LLM', 'mut', etc.).
        """
        seed_id = self._extract_seed_field(seed_name, "id")
        if not seed_id:
            logger.warning("[REWARD] Cannot extract seed id from '%s', skipping registration", seed_name)
            return
        lookup_key = f"{queue_name}:{seed_id}"
        with self._seed_origin_lock:
            self._seed_origin_map[lookup_key] = roadblock_key
        with self._agent_seed_registry_lock:
            self._agent_seed_registry[seed_name] = roadblock_key
        self._save_seed_origin_map()
        logger.info("[REWARD] Registered seed %s → %s (key=%s)", seed_name, roadblock_key, lookup_key)

    def _detect_and_apply_rewards(self, discovered_seed_names: list[str]) -> int:
        """Scan discovered seeds for sync:+cov entries and apply rewards to originating roadblocks.

        Returns the number of rewards applied.
        """
        rewards_applied = 0
        for seed_name in discovered_seed_names:
            if "sync:" not in seed_name or "+cov" not in seed_name:
                continue
            if seed_name in self._rewarded_sync_ids:
                continue

            sync_source = self._extract_seed_field(seed_name, "sync")
            src_id = self._extract_seed_field(seed_name, "src")
            if not sync_source or src_id is None:
                continue

            lookup_key = f"{sync_source}:{src_id}"
            with self._seed_origin_lock:
                rb_key = self._seed_origin_map.get(lookup_key)
            if not rb_key:
                continue

            self._rewarded_sync_ids.add(seed_name)
            self._apply_seed_reward(rb_key, seed_name)
            rewards_applied += 1

        if rewards_applied:
            self._save_seed_origin_map()
        return rewards_applied

    def _apply_seed_reward(self, roadblock_key: str, seed_name: str) -> None:
        """Write a reward record for a successful seed to the reward feed."""
        reward_delta = 5.0
        cond_key = roadblock_key  # For logging
        with self._interest_lock:
            self._interesting_conds[cond_key] = self._interesting_conds.get(cond_key, 0.0) + reward_delta

        # Append to reward feed (cross-process communication)
        reward_path = config.REWARD_FEED_PATH
        record = {
            "roadblock_key": roadblock_key,
            "reward": reward_delta,
            "seed_name": seed_name,
            "ts": time.time(),
        }
        try:
            reward_path.parent.mkdir(parents=True, exist_ok=True)
            with open(reward_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            logger.info(
                "[REWARD] +%.1f for roadblock %s (seed %s produced new coverage via AFL sync)",
                reward_delta,
                roadblock_key,
                seed_name,
            )
        except Exception as exc:
            logger.warning("[REWARD] Failed to write reward feed: %s", exc)

    def enqueue_autobug_seed_names(self, seed_names: list[str]) -> None:
        if not seed_names:
            return
        pending_after = 0
        with self._autobug_prime_lock:
            enqueued = 0
            for seed_name in seed_names:
                with self._autobug_seed_branch_cache_lock:
                    already_cached = seed_name in self._autobug_seed_branch_cache
                if already_cached:
                    continue
                if seed_name in self._autobug_pending_seed_name_set:
                    continue
                self._autobug_pending_seed_names.append(seed_name)
                self._autobug_pending_seed_name_set.add(seed_name)
                enqueued += 1
            pending_after = len(self._autobug_pending_seed_names)
        if enqueued > 0:
            logger.info(
                "[AUTOBUG] Enqueued %d seed(s) for async branch-cache priming (pending=%d)",
                enqueued,
                pending_after,
            )

    def poll_autobug_seed_queue(self) -> int:
        with self._autobug_queue_lock:
            now = time.time()
            if self._autobug_last_queue_poll_at > 0 and now - self._autobug_last_queue_poll_at < AUTOBUG_SCAN_INTERVAL:
                return 0
            self._autobug_last_queue_poll_at = now
            discovered_seed_names: list[str] = []
            latest_scan = int(self._autobug_queue_last_scan_time_ns or 0)
            queue_dir = SEED_PATH
            if queue_dir.exists() and queue_dir.is_dir():
                try:
                    files_to_run, _, latest_scan = get_new_seeds(
                        queue_dir,
                        self._autobug_queue_read_files,
                        latest_scan,
                        prof_dir=None,
                    )
                    discovered_seed_names.extend(path.name for path in files_to_run)
                except FileNotFoundError:
                    pass
            self._autobug_queue_last_scan_time_ns = latest_scan
            if discovered_seed_names:
                logger.info(
                    "[AUTOBUG] Queue scan discovered %d new seed(s) from %s for branch-cache backlog",
                    len(discovered_seed_names),
                    queue_dir,
                )
                self.enqueue_autobug_seed_names(discovered_seed_names)
                # Reward feedback: detect sync:+cov seeds from our generation
                rewards = self._detect_and_apply_rewards(discovered_seed_names)
                if rewards:
                    logger.info("[REWARD] Applied %d reward(s) from AFL sync seeds", rewards)
            else:
                logger.info(
                    "[AUTOBUG] Queue scan found no new seed in %s (interval=%ss)",
                    queue_dir,
                    AUTOBUG_SCAN_INTERVAL,
                )
            return len(discovered_seed_names)

    def kick_autobug_prime_async(self) -> bool:
        with self._autobug_prime_lock:
            if self._autobug_prime_thread is not None and self._autobug_prime_thread.is_alive():
                logger.info(
                    "[AUTOBUG] Async branch-cache priming already running (pending=%d)",
                    len(self._autobug_pending_seed_names),
                )
                return False

            pending_seed_names = list(self._autobug_pending_seed_names)
            with self._autobug_seed_branch_cache_lock:
                cached_seed_names = set(self._autobug_seed_branch_cache)
            pending_cov = [
                seed_name for seed_name in pending_seed_names
                if seed_name not in cached_seed_names and self._seed_has_cov(seed_name)
            ]
            if pending_cov:
                selected = set(pending_cov)
                batch = [seed_name for seed_name in pending_seed_names if seed_name in selected]
                mode = "all_cov"
            else:
                non_cov_pending = [
                    seed_name for seed_name in pending_seed_names
                    if seed_name not in cached_seed_names
                ]
                batch = non_cov_pending[:max(1, int(AUTOBUG_PRIME_MAX_SEEDS_PER_ROUND))]
                mode = "non_cov_batch"

            if batch:
                selected_names = set(batch)
                retained = deque()
                while self._autobug_pending_seed_names:
                    seed_name = self._autobug_pending_seed_names.popleft()
                    if seed_name in selected_names:
                        self._autobug_pending_seed_name_set.discard(seed_name)
                        continue
                    retained.append(seed_name)
                self._autobug_pending_seed_names = retained
        if not batch:
            return False
        logger.info(
            "[AUTOBUG] Scheduling async branch-cache priming for %d seed(s) from current backlog (mode=%s)",
            len(batch),
            mode,
        )
        # 使用普通线程而不是 ThreadPoolExecutor
        self._autobug_prime_stop_event.clear()
        self._autobug_prime_thread = threading.Thread(
            target=self._run_autobug_prime_batch,
            args=(batch,),
            name="autobug-prime",
            daemon=True
        )
        self._autobug_prime_thread.start()
        return True

    def shutdown_background_workers(self, wait: bool = False) -> None:
        with self._autobug_prime_lock:
            thread = self._autobug_prime_thread
            self._autobug_prime_thread = None
        if thread is not None and thread.is_alive():
            self._autobug_prime_stop_event.set()
            if wait:
                thread.join(timeout=5)
        # 不再需要 shutdown executor

    def _run_autobug_prime_batch(self, seed_names: list[str]) -> None:
        start_time = time.time()
        self._prime_autobug_seed_branches(seed_names)
        elapsed = max(time.time() - start_time, 0.0)
        with self._autobug_prime_lock:
            remaining = len(self._autobug_pending_seed_names)
        logger.info(
            "[AUTOBUG] Async branch-cache priming batch finished: processed=%d, elapsed=%.1fs, pending=%d",
            len(seed_names),
            elapsed,
            remaining,
        )

    def _prime_autobug_seed_branches(self, seed_names: list[str]) -> None:
        if not seed_names:
            return
        analyzer = self._autobug_analyzer_path()
        subject = self._autobug_subject_path()
        if analyzer is None or subject is None:
            return

        with self._autobug_seed_branch_cache_lock:
            cached_seed_names = set(self._autobug_seed_branch_cache)
        pending_seed_names = [
            seed_name for seed_name in seed_names
            if seed_name not in cached_seed_names
        ]
        if not pending_seed_names:
            logger.info("[AUTOBUG] Branch cache already warm for %d seed(s)", len(seed_names))
            return
        pending_seed_names.sort(
            key=lambda seed_name: (
                1 if self._seed_has_cov(seed_name) else 0,
                seed_name,
            ),
            reverse=True,
        )

        logger.info(
            "[AUTOBUG] Priming branch cache for %d seed(s) this round (+cov prioritized)",
            len(pending_seed_names),
        )
        updated = False
        start_time = time.time()
        total = len(pending_seed_names)
        progress_interval = 50  # 每 50 个 seed 打印一次进度
        for index, seed_name in enumerate(pending_seed_names, start=1):
            self._load_autobug_seed_branches(seed_name)
            updated = True

            # 每 50 个 seed 或最后一个打印进度
            should_log_progress = (
                index == 1
                or index == total
                or index % progress_interval == 0
            )
            if should_log_progress:
                elapsed = max(time.time() - start_time, 1e-6)
                rate = index / elapsed
                remaining = max(total - index, 0)
                eta_seconds = remaining / rate if rate > 0 else 0.0
                logger.info(
                    "[AUTOBUG] replay progress %d/%d (%.1f%%), elapsed=%.1fs, rate=%.2f seeds/s, eta=%.1fs, current=%s",
                    index,
                    total,
                    (index / total) * 100.0,
                    elapsed,
                    rate,
                    eta_seconds,
                    seed_name,
                )
        if updated:
            self._save_persisted_autobug_branch_cache()

    @staticmethod
    def _matching_summary_lines(line_map: dict[str, list[int]] | None, target_file: str) -> list[int]:
        if not line_map:
            return []
        matched: list[int] = []
        target_name = Path(target_file).name
        for file_name, lines in line_map.items():
            if file_name == target_file or Path(file_name).name == target_name:
                matched.extend(lines or [])
        return sorted(set(int(line) for line in matched if int(line) > 0))

    def _seed_locality_score(
        self,
        seed_path: Path,
        summary: DynamicTraceSummary | None,
        roadblock,
    ) -> tuple[tuple, dict[str, int | bool | str]]:
        target_file = roadblock.get("filename", "")
        target_line = int(roadblock.get("line", 0) or 0)
        try:
            stat = seed_path.stat()
        except OSError:
            stat = None

        file_size = int(stat.st_size) if stat else 0
        ctime_ns = int(stat.st_ctime_ns) if stat else 0
        seed_name = seed_path.name
        name_parts = [part.strip() for part in seed_name.split(",") if part.strip()]
        has_cov = self._seed_has_cov(seed_name)

        def _extract_numeric(prefix: str) -> int:
            for part in name_parts:
                if not part.startswith(prefix):
                    continue
                raw_value = part.removeprefix(prefix)
                try:
                    return int(raw_value)
                except ValueError:
                    return 0
            return 0

        afl_time = _extract_numeric("time:")
        afl_execs = _extract_numeric("execs:")

        if summary is None:
            metrics = {
                "target_hit": False,
                "branch_exact": False,
                "branch_window_lines": 0,
                "executed_near_target": 0,
                "executed_total": 0,
                "trace_complete": False,
                "call_depth": 0,
                "has_cov": has_cov,
                "afl_time": afl_time,
                "afl_execs": afl_execs,
                "file_size": file_size,
            }
            score = (0, 0, 1 if has_cov else 0, 0, 0, 0, 0, 0, afl_time, afl_execs, ctime_ns, -file_size, seed_name)
            return score, metrics

        branch_lines = self._matching_summary_lines(summary.branch_window, target_file)
        executed_lines = self._matching_summary_lines(summary.executed_locations, target_file)
        executed_near_target = sum(1 for line in executed_lines if abs(line - target_line) <= 10)
        branch_exact = target_line in branch_lines
        min_branch_distance = min((abs(line - target_line) for line in branch_lines), default=10**9)
        metrics = {
            "target_hit": bool(summary.target_hit),
            "branch_exact": branch_exact,
            "branch_window_lines": len(branch_lines),
            "executed_near_target": executed_near_target,
            "executed_total": len(executed_lines),
            "trace_complete": bool(summary.trace_complete),
            "call_depth": len(summary.call_path),
            "min_branch_distance": 0 if min_branch_distance == 10**9 else min_branch_distance,
            "has_cov": has_cov,
            "afl_time": afl_time,
            "afl_execs": afl_execs,
            "file_size": file_size,
        }
        score = (
            1 if summary.target_hit else 0,
            1 if branch_exact else 0,
            1 if has_cov else 0,
            len(branch_lines),
            executed_near_target,
            len(executed_lines),
            1 if summary.trace_complete else 0,
            -min_branch_distance,
            len(summary.call_path),
            afl_time,
            afl_execs,
            ctime_ns,
            -file_size,
            seed_name,
        )
        return score, metrics

    def rank_seed_candidates_for_roadblock(
        self,
        roadblock,
        seed_names=None,
        *,
        max_candidates: int = 24,
    ) -> list[dict[str, object]]:
        candidate_seed_names = seed_names if seed_names is not None else self._coarse_candidate_seed_names(
            roadblock,
            max_candidates=max(max_candidates, 48),
        )
        candidate_paths: list[Path] = []
        for seed_name in candidate_seed_names:
            seed_path = self._resolve_seed_candidate_path(seed_name)
            if seed_path is not None:
                candidate_paths.append(seed_path)

        if not candidate_paths:
            return []

        candidate_paths.sort(key=lambda path: (path.stat().st_ctime_ns, path.stat().st_size, path.name), reverse=True)
        if len(candidate_paths) > max_candidates:
            recent = candidate_paths[: max_candidates // 2]
            compact = sorted(candidate_paths, key=lambda path: (path.stat().st_size, -path.stat().st_ctime_ns, path.name))
            candidate_paths = []
            seen: set[str] = set()
            for path in recent + compact:
                path_key = os.fspath(path)
                if path_key in seen:
                    continue
                seen.add(path_key)
                candidate_paths.append(path)
                if len(candidate_paths) >= max_candidates:
                    break

        ranked: list[dict[str, object]] = []
        for seed_path in candidate_paths:
            summary = self._load_or_build_dynamic_summary(seed_path, roadblock)
            score, metrics = self._seed_locality_score(seed_path, summary, roadblock)
            ranked.append({
                "seed_path": seed_path,
                "seed_name": seed_path.name,
                "summary": summary,
                "score": score,
                "metrics": metrics,
            })

        ranked.sort(key=lambda item: item["score"], reverse=True)
        return ranked

    def _seed_candidate_search_dirs(self) -> list[Path]:
        search_dirs = [
            SEED_PATH,
            LLM_QUEUE_PATH,
            MUT_QUEUE_PATH,
            SYMBOLIC_QUEUE_PATH,
        ]
        for out_dir in sorted(PROJECT_HOME.glob("out_*")):
            search_dirs.append(out_dir / "default" / "queue")
        deduped: list[Path] = []
        seen: set[str] = set()
        for directory in search_dirs:
            dir_key = os.fspath(directory)
            if dir_key in seen:
                continue
            seen.add(dir_key)
            deduped.append(directory)
        return deduped

    def _recent_seed_candidates(self, limit: int = 96) -> list[str]:
        candidate_paths: list[Path] = []
        for directory in self._seed_candidate_search_dirs():
            if not directory.exists() or not directory.is_dir():
                continue
            try:
                for path in directory.iterdir():
                    if path.is_file():
                        candidate_paths.append(path)
            except OSError:
                continue
        candidate_paths.sort(
            key=lambda path: (
                1 if self._seed_has_cov(path.name) else 0,
                int(path.stat().st_mtime_ns),
                int(path.stat().st_size),
                path.name,
            ),
            reverse=True,
        )
        seen: set[str] = set()
        selected: list[str] = []
        for path in candidate_paths:
            if path.name in seen:
                continue
            seen.add(path.name)
            selected.append(path.name)
            if len(selected) >= limit:
                break
        return selected

    def _coarse_candidate_seed_names(self, roadblock, max_candidates: int = 64) -> list[str]:
        candidates = self._recent_seed_candidates(limit=max(max_candidates * 2, 96))
        if not candidates:
            return []
        ranked = self.rank_seed_candidates_for_roadblock(
            roadblock,
            seed_names=candidates,
            max_candidates=max_candidates,
        )
        if not ranked:
            return candidates[:max_candidates]
        selected = [str(item["seed_name"]) for item in ranked[:max_candidates]]
        logger.info(
            "[DYN_TRACE] Coarse candidate pool for %s:%s -> %d recent seeds, top-%d retained",
            roadblock.get("filename", ""),
            roadblock.get("line", 0),
            len(candidates),
            len(selected),
        )
        return selected

    def _resolve_seed_candidate_path(self, seed_name: str) -> Path | None:
        direct = SEED_PATH / seed_name
        if direct.exists() and direct.is_file():
            return direct

        seed_prefix = seed_name.split(",")[0]
        search_dirs = [
            SEED_PATH,
            LLM_QUEUE_PATH,
            MUT_QUEUE_PATH,
            SYMBOLIC_QUEUE_PATH,
        ]
        for out_dir in sorted(PROJECT_HOME.glob("out_*")):
            search_dirs.append(out_dir / "default" / "queue")

        seen_dirs: set[str] = set()
        for directory in search_dirs:
            dir_key = os.fspath(directory)
            if dir_key in seen_dirs or not directory.exists() or not directory.is_dir():
                continue
            seen_dirs.add(dir_key)
            matches = sorted(directory.glob(f"{seed_prefix}*"))
            if matches:
                return matches[0]
        return None

    def _autobug_analyzer_path(self) -> Path | None:
        analyzer = ROOT_DIR / "AutoBug" / "autobug"
        if analyzer.exists() and analyzer.is_file():
            return analyzer
        return None

    def _autobug_subject_path(self) -> Path | None:
        autobug_dir = PROJECT_HOME / "target" / "autobug"
        if not autobug_dir.exists() or not autobug_dir.is_dir():
            return None

        candidates = sorted(path for path in autobug_dir.glob("*.autotrace") if path.is_file())
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]

        target_base = Path(self.target_prog).name if self.target_prog else ""
        normalized_targets = {
            PROJECT,
            target_base,
            target_base.removesuffix("_fuzz"),
            f"{PROJECT}_ori",
        }

        def score(path: Path) -> tuple[int, int, str]:
            stem = path.name.removesuffix(".autotrace")
            exact = 1 if stem in normalized_targets else 0
            fuzzy = 1 if any(token and token in stem for token in normalized_targets) else 0
            return (exact, fuzzy, path.name)

        return sorted(candidates, key=score, reverse=True)[0]

    def _populate_cond_status_from_branches(self, seed_name: str, parsed: dict[str, dict[str, object]]) -> None:
        """Populate cond_status/interesting_conds from parsed BRANCH.dump data (ported from hyllfuzz globals.py)."""
        for cond_key, payload in parsed.items():
            branches = payload.get("branches", set())
            total = int(payload.get("total", 0))

            with self._never_interest_lock:
                if cond_key in self._never_interesting_conds:
                    continue

            # Fully covered → never_interesting
            if len(branches) >= total:
                with self._never_interest_lock:
                    self._never_interesting_conds.add(cond_key)
                with self._interest_lock:
                    self._interesting_conds.pop(cond_key, None)
                with self._cond_status_lock:
                    self._cond_status.pop(cond_key, None)
                continue

            with self._cond_status_lock:
                if cond_key not in self._cond_status:
                    self._cond_status[cond_key] = {}
                    with self._interest_lock:
                        self._interesting_conds[cond_key] = 0.0

                for branch_id in branches:
                    branch_key = str(branch_id)
                    if branch_key not in self._cond_status[cond_key]:
                        self._cond_status[cond_key][branch_key] = set()
                    self._cond_status[cond_key][branch_key].add(seed_name)

    def _shrink_cond_status(self, cond_key: str, total: int) -> None:
        """Remove fully covered cond from cond_status (ported from hyllfuzz globals.py)."""
        with self._never_interest_lock:
            if cond_key in self._never_interesting_conds:
                return

        with self._cond_status_lock:
            if cond_key in self._cond_status and len(self._cond_status[cond_key]) >= total:
                del self._cond_status[cond_key]
                with self._never_interest_lock:
                    self._never_interesting_conds.add(cond_key)
                with self._interest_lock:
                    self._interesting_conds.pop(cond_key, None)

    def _log_cond_status_summary(self) -> None:
        """Log a brief summary of cond_status for debugging."""
        with self._cond_status_lock:
            n_conds = len(self._cond_status)
        with self._interest_lock:
            n_interesting = len(self._interesting_conds)
        with self._never_interest_lock:
            n_never = len(self._never_interesting_conds)
        logger.info(
            "[COND_STATUS] conds=%d interesting=%d never_interesting=%d",
            n_conds, n_interesting, n_never,
        )

    def get_uncovered_branches(self, roadblock: dict) -> list[int]:
        """Get uncovered branch IDs for a roadblock from cond_status."""
        cond_key = self._roadblock_cond_key(roadblock)
        if not cond_key:
            return []
        with self._cond_status_lock:
            cond_data = self._cond_status.get(cond_key)
        if not cond_data:
            return []
        covered = {int(bk) for bk in cond_data if bk.isdigit()}
        # Branch IDs are 1..total; uncovered = all known branches minus covered
        # We also need total — get it from _autobug_seed_branch_cache
        total = None
        with self._autobug_seed_branch_cache_lock:
            seed_branch_payloads = list(self._autobug_seed_branch_cache.values())
        for seed_data in seed_branch_payloads:
            if seed_data and cond_key in seed_data:
                total = seed_data[cond_key].get("total")
                break
        if total is None:
            return []
        return [b for b in range(1, total + 1) if b not in covered]

    @staticmethod
    def _parse_autobug_branch_dump(dump_text: str) -> dict[str, dict[str, object]]:
        result: dict[str, dict[str, object]] = {}
        for raw_line in dump_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            match = re.match(r"^(?P<cond>.+?)\s+\[(?P<branches>[0-9,\s]*)\]/(?P<total>\d+)\s*$", line)
            if not match:
                continue
            cond_key = match.group("cond").strip()
            branches = {
                int(item.strip())
                for item in match.group("branches").split(",")
                if item.strip().isdigit()
            }
            result[cond_key] = {
                "branches": branches,
                "total": int(match.group("total")),
            }
        return result

    @staticmethod
    def _seed_has_cov(seed_name: str) -> bool:
        name_parts = [part.strip() for part in str(seed_name).split(",") if part.strip()]
        return any(part == "+cov" or part.endswith("+cov") for part in name_parts)

    @staticmethod
    def _roadblock_expected_branch_id(roadblock: dict) -> int | None:
        branch_id = int(roadblock.get("branch_id", 0) or 0)
        if branch_id > 0:
            return branch_id

        status = _canonicalize_roadblock_status(roadblock)
        if status == "only_false":
            return 1
        if status == "only_true":
            return 2
        return None

    @staticmethod
    def _autobug_cond_matches_roadblock(cond_key: str, roadblock: dict) -> bool:
        if ":" not in cond_key:
            return False
        try:
            file_name, line_text = cond_key.rsplit(":", 1)
            cond_line = int(line_text)
        except ValueError:
            return False
        rb_file = str(roadblock.get("filename", "") or "")
        rb_line = int(roadblock.get("line", 0) or 0)
        if cond_line != rb_line:
            return False
        return file_name == rb_file or Path(file_name).name == Path(rb_file).name

    @staticmethod
    def _roadblock_cond_key(roadblock: dict) -> str | None:
        """Build a cond_key from a roadblock dict for cond_status lookup."""
        rb_file = str(roadblock.get("filename", "") or "")
        rb_line = int(roadblock.get("line", 0) or 0)
        if not rb_file or not rb_line:
            return None
        return f"{rb_file}:{rb_line}"

    def _load_autobug_seed_branches(self, seed_name: str) -> dict[str, dict[str, object]] | None:
        with self._autobug_seed_branch_cache_lock:
            if seed_name in self._autobug_seed_branch_cache:
                return self._autobug_seed_branch_cache[seed_name]

        analyzer = self._autobug_analyzer_path()
        subject = self._autobug_subject_path()
        seed_path = self._resolve_seed_candidate_path(seed_name)
        if analyzer is None or subject is None or seed_path is None:
            with self._autobug_seed_branch_cache_lock:
                self._autobug_seed_branch_cache[seed_name] = None
            return None

        with tempfile.TemporaryDirectory(prefix="autobug-branch-", dir=self._autobug_cache_dir) as tmpdir:
            tmpdir_path = Path(tmpdir)
            trace_path = tmpdir_path / "TRACE.dump"

            # 照搬调试脚本的 build_seed_invocation 逻辑
            command = [os.fspath(subject)]
            has_atat = "@@" in self.fuzzing_args

            if has_atat:
                # 有 @@ 占位符，通过命令行传递
                for arg in self.fuzzing_args:
                    if arg == "@@":
                        command.append(os.fspath(seed_path))
                    else:
                        command.append(arg)
                stdin_data = None
            else:
                # 没有 @@ 占位符，通过 stdin 传递（calc 的情况）
                command.extend(self.fuzzing_args)
                stdin_data = seed_path.read_bytes()

            if stdin_data is not None:
                logger.debug("[AUTOBUG] Running target: %s (via stdin, %d bytes)",
                            " ".join(command), len(stdin_data))
            else:
                logger.debug("[AUTOBUG] Running target: %s", " ".join(command))

            try:
                # 使用 Popen 而不是 run，以便在超时时能够杀死进程
                # 使用 start_new_session=True 创建新的进程组，便于 Ctrl+C 时清理
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={**os.environ, "TRACE_DUMP": os.fspath(trace_path)},
                    start_new_session=True,  # 创建新的进程组
                )
                try:
                    stdout, stderr = process.communicate(input=stdin_data, timeout=30)
                except subprocess.TimeoutExpired:
                    # 超时时杀死整个进程组
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    except (ProcessLookupError, OSError):
                        pass  # 进程已经结束
                    process.kill()
                    try:
                        stdout, stderr = process.communicate(timeout=1)
                    except:
                        pass
                    logger.warning("[AUTOBUG] Trace replay timed out for seed %s, process group killed", seed_name)
                    with self._autobug_seed_branch_cache_lock:
                        self._autobug_seed_branch_cache[seed_name] = None
                    return None
            except Exception as e:
                logger.warning("[AUTOBUG] Failed to run target for seed %s: %s", seed_name, e)
                with self._autobug_seed_branch_cache_lock:
                    self._autobug_seed_branch_cache[seed_name] = None
                return None

            if process.returncode != 0 and not trace_path.exists():
                stderr = (stderr or b"").decode("utf-8", errors="replace").strip()[:400]
                logger.warning("[AUTOBUG] Trace replay failed for %s: %s", seed_name, stderr)
                with self._autobug_seed_branch_cache_lock:
                    self._autobug_seed_branch_cache[seed_name] = None
                return None
            if not trace_path.exists():
                logger.warning("[AUTOBUG] TRACE_DUMP not created for seed %s", seed_name)
                with self._autobug_seed_branch_cache_lock:
                    self._autobug_seed_branch_cache[seed_name] = None
                return None

            trace_size = trace_path.stat().st_size
            # 移除 TRACE 大小限制，不再跳过大的 seed
            # if trace_size > config.AUTOBUG_TRACE_SIZE_LIMIT:
            #     logger.warning(
            #         "[AUTOBUG] TRACE too large for seed %s (%.1fMB > %dMB limit), skipping get-branch",
            #         seed_name,
            #         trace_size / (1024 * 1024),
            #         config.AUTOBUG_TRACE_SIZE_LIMIT // (1024 * 1024),
            #     )
            #     self._autobug_seed_branch_cache[seed_name] = None
            #     return None

            branch_cmd = [
                os.fspath(analyzer),
                "get-branch",
                os.fspath(SRC_PATH),
                os.fspath(trace_path),
                "--output",
                "/dev/null",
            ]
            # 使用 Popen 创建进程组，便于 Ctrl+C 时清理
            branch_process = subprocess.Popen(
                branch_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                start_new_session=True,  # 创建新的进程组
                cwd=tmpdir,
            )
            branch_result = branch_process.communicate()
            dump_path = tmpdir_path / "BRANCH.dump"
            if branch_process.returncode != 0 or not dump_path.exists():
                stderr = (branch_result[1] or "").strip()[:400]
                logger.warning("[AUTOBUG] get-branch failed for %s: %s", seed_name, stderr)
                with self._autobug_seed_branch_cache_lock:
                    self._autobug_seed_branch_cache[seed_name] = None
                return None

            parsed = self._parse_autobug_branch_dump(dump_path.read_text(encoding="utf-8", errors="replace"))
            with self._autobug_seed_branch_cache_lock:
                self._autobug_seed_branch_cache[seed_name] = parsed
            self._populate_cond_status_from_branches(seed_name, parsed)
            return parsed

    def _autobug_slice_cache_path(self, roadblock: dict, seed_name: str) -> Path:
        target_file = Path(str(roadblock.get("filename", "unknown"))).name
        target_line = int(roadblock.get("line", 0) or 0)
        digest_input = f"{roadblock.get('roadblock_key') or target_file}:{target_line}:{seed_name}"
        digest = hashlib.sha1(digest_input.encode("utf-8", errors="ignore")).hexdigest()[:12]
        stem = config.sanitize_fs_component(f"{target_file}_{target_line}_{seed_name}_{digest}")
        slice_cache_dir = self._autobug_cache_dir / "slices"
        slice_cache_dir.mkdir(parents=True, exist_ok=True)
        return slice_cache_dir / f"{stem}.c"

    def _autobug_branch_coverage_arg(self, roadblock: dict, seed_name: str) -> str | None:
        # Fast path: use cond_status
        cond_key = self._roadblock_cond_key(roadblock)
        if cond_key:
            with self._cond_status_lock:
                cond_data = self._cond_status.get(cond_key)
            if cond_data:
                # Get branches covered by this specific seed
                covered = sorted(
                    int(bk) for bk, seeds in cond_data.items() if bk.isdigit() and seed_name in seeds
                )
                if covered:
                    return ",".join(str(b) for b in covered)

        # Fallback: iterate seed branch cache
        branches_by_cond = self._load_autobug_seed_branches(seed_name) or {}
        for ck, payload in branches_by_cond.items():
            if not self._autobug_cond_matches_roadblock(ck, roadblock):
                continue
            branches = sorted(int(branch_id) for branch_id in payload.get("branches", set()))
            if branches:
                return ",".join(str(branch_id) for branch_id in branches)
        expected_branch = self._roadblock_expected_branch_id(roadblock)
        return str(expected_branch) if expected_branch is not None else None

    def _build_autobug_slice_for_seed(self, roadblock: dict, seed_path: Path) -> str | None:
        analyzer = self._autobug_analyzer_path()
        subject = self._autobug_subject_path()
        if analyzer is None or subject is None:
            return None

        seed_name = seed_path.name
        cache_path = self._autobug_slice_cache_path(roadblock, seed_name)
        if cache_path.exists():
            cached = cache_path.read_text(encoding="utf-8", errors="ignore").strip()
            if _slice_has_meaningful_content(cached):
                return cached

        coverage_arg = self._autobug_branch_coverage_arg(roadblock, seed_name)
        if not coverage_arg:
            logger.info(
                "[AUTOBUG] No branch coverage metadata for %s on %s:%s",
                seed_name,
                roadblock.get("filename", ""),
                roadblock.get("line", 0),
            )
            return None

        with tempfile.TemporaryDirectory(prefix="autobug-slice-", dir=self._autobug_cache_dir) as tmpdir:
            tmpdir_path = Path(tmpdir)
            trace_path = tmpdir_path / "TRACE.dump"
            sliced_path = tmpdir_path / "SLICED_CODE.c"

            command, stdin_data = build_seed_invocation(
                os.fspath(subject),
                self.fuzzing_args,
                seed_path,
                self.input_adapter_spec,
            )
            try:
                run_result = subprocess.run(
                    command,
                    input=stdin_data,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={**os.environ, "TRACE_DUMP": os.fspath(trace_path)},
                    check=False,
                    timeout=TIMEOUT,
                )
            except subprocess.TimeoutExpired:
                logger.warning("[AUTOBUG] Slice replay timed out for seed %s", seed_name)
                return None

            if run_result.returncode != 0 and not trace_path.exists():
                stderr = (run_result.stderr or b"").decode("utf-8", errors="replace").strip()[:400]
                logger.warning("[AUTOBUG] Slice replay failed for %s: %s", seed_name, stderr)
                return None
            if not trace_path.exists():
                logger.warning("[AUTOBUG] TRACE_DUMP not created for autobug slice seed %s", seed_name)
                return None

            trace_size = trace_path.stat().st_size
            # 移除 TRACE 大小限制
            # if trace_size > config.AUTOBUG_TRACE_SIZE_LIMIT:
            #     logger.warning(
            #         "[AUTOBUG] TRACE too large for slice seed %s (%.1fMB > %dMB limit), skipping flip-branch",
            #         seed_name,
            #         trace_size / (1024 * 1024),
            #         config.AUTOBUG_TRACE_SIZE_LIMIT // (1024 * 1024),
            #     )
            #     return None

            target_loc = f"{roadblock.get('filename', '')}:{int(roadblock.get('line', 0) or 0)}"
            slice_cmd = [
                os.fspath(analyzer),
                "flip-branch",
                os.fspath(SRC_PATH),
                os.fspath(trace_path),
                "--target",
                target_loc,
                "--coverage",
                coverage_arg,
                "--output",
                os.fspath(sliced_path),
                "--comments",
                "--window",
                "10",
            ]
            try:
                slice_result = subprocess.run(
                    slice_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    check=False,
                    cwd=tmpdir,
                    timeout=config.AUTOBUG_FLIP_BRANCH_TIMEOUT,
                )
            except subprocess.TimeoutExpired:
                logger.warning(
                    "[AUTOBUG] flip-branch timed out (%ds) for seed %s at %s (trace %.1fMB)",
                    config.AUTOBUG_FLIP_BRANCH_TIMEOUT,
                    seed_name,
                    target_loc,
                    trace_size / (1024 * 1024),
                )
                return None
            if slice_result.returncode != 0 or not sliced_path.exists():
                stderr = (slice_result.stderr or slice_result.stdout or "").strip()[:400]
                logger.warning("[AUTOBUG] flip-branch failed for %s: %s", seed_name, stderr)
                return None

            slice_text = sliced_path.read_text(encoding="utf-8", errors="replace").strip()
            if not _slice_has_meaningful_content(slice_text):
                logger.warning(
                    "[AUTOBUG] flip-branch produced empty slice for %s at %s",
                    seed_name,
                    target_loc,
                )
                return None

            try:
                cache_path.write_text(slice_text, encoding="utf-8")
            except OSError as exc:
                logger.warning("[AUTOBUG] Failed to persist slice cache %s: %s", cache_path, exc)
            return slice_text

    def build_autobug_slice_context(
        self,
        roadblock: dict,
        seed_names: list[str] | None = None,
        *,
        max_attempts: int = 3,
    ) -> dict[str, object] | None:
        candidate_names = list(seed_names) if seed_names is not None else self.select_seed_names_for_roadblock(
            roadblock,
            max_seeds=max_attempts,
        )
        if not candidate_names:
            return None

        for seed_name in candidate_names[:max_attempts]:
            seed_path = self._resolve_seed_candidate_path(seed_name)
            if seed_path is None:
                continue
            slice_text = self._build_autobug_slice_for_seed(roadblock, seed_path)
            if not slice_text:
                continue
            return {
                "seed_name": seed_name,
                "seed_path": os.fspath(seed_path),
                "slice_text": slice_text,
            }
        return None

    def _autobug_matching_seed_names(
        self,
        roadblock: dict,
        candidate_names: list[str],
        *,
        limit: int,
    ) -> list[str]:
        expected_branch = self._roadblock_expected_branch_id(roadblock)
        if expected_branch is None:
            return []

        # Fast path: use cond_status for O(1) lookup
        cond_key = self._roadblock_cond_key(roadblock)
        if cond_key:
            with self._cond_status_lock:
                cond_data = self._cond_status.get(cond_key)
            if cond_data:
                branch_key = str(expected_branch)
                if branch_key in cond_data:
                    seeds = cond_data[branch_key] & set(candidate_names)
                    if seeds:
                        return list(seeds)[:limit]

        # Fallback: iterate seed branch cache
        matches: list[str] = []
        for seed_name in candidate_names:
            with self._autobug_seed_branch_cache_lock:
                branches_by_cond = self._autobug_seed_branch_cache.get(seed_name)
            if not branches_by_cond:
                continue
            for ck, payload in branches_by_cond.items():
                if not self._autobug_cond_matches_roadblock(ck, roadblock):
                    continue
                if expected_branch in payload.get("branches", set()):
                    matches.append(seed_name)
                    break
            if len(matches) >= limit:
                break
        return matches

    def select_seed_names_for_roadblock(self, roadblock, seed_names=None, max_seeds: int = 3) -> list[str]:
        candidate_names = list(seed_names) if seed_names is not None else self._recent_seed_candidates(limit=max(max_seeds * 4, 24))
        if not candidate_names:
            return []
        candidate_names.sort(
            key=lambda seed_name: (
                1 if self._seed_has_cov(seed_name) else 0,
                seed_name,
            ),
            reverse=True,
        )

        autobug_matches = self._autobug_matching_seed_names(roadblock, candidate_names, limit=max_seeds)
        if autobug_matches:
            logger.info(
                "[AUTOBUG] Selected %d AutoBug-confirmed seed(s) for %s:%s",
                len(autobug_matches),
                roadblock.get("filename", ""),
                roadblock.get("line", 0),
            )
            return autobug_matches

        # 不再有profdata fallback，直接返回候选seeds
        logger.info(
            "[AUTOBUG] No AutoBug-confirmed seeds, using top candidate seeds for %s:%s",
            roadblock.get("filename", ""),
            roadblock.get("line", 0),
        )
        return candidate_names[:max_seeds]

    def _dynamic_trace_fingerprint(self) -> str:
        return DynamicTraceCache.build_fingerprint(
            Path(self.trace_prog),
            SRC_PATH if SRC_PATH.exists() else PROJECT_HOME,
            FLAGREC_BITCODE if 'FLAGREC_BITCODE' in globals() else None,
        )

    def _select_representative_seeds(self, roadblock, max_seeds=3, seed_names=None) -> list[Path]:
        ranked = self.rank_seed_candidates_for_roadblock(roadblock, seed_names=seed_names)
        if ranked:
            preview = ", ".join(
                f"{item['seed_name']}("
                f"hit={int(item['metrics']['target_hit'])},"
                f"exact={int(item['metrics']['branch_exact'])},"
                f"win={item['metrics']['branch_window_lines']},"
                f"exec={item['metrics']['executed_near_target']})"
                for item in ranked[:min(max_seeds, 5)]
            )
            logger.info(f"[DYN_TRACE] Ranked representative seeds: {preview}")
        return [item["seed_path"] for item in ranked[:max_seeds]]

    def _load_or_build_dynamic_summary(self, seed_path: Path, roadblock) -> DynamicTraceSummary | None:
        roadblock_key = f"{roadblock.get('filename', '')}:{roadblock.get('line', 0)}"
        fingerprint = self._dynamic_trace_fingerprint()
        cached = self.dynamic_trace_cache.load(PROJECT, roadblock_key, seed_path.name, fingerprint)
        if cached is not None:
            return cached

        try:
            summary = self.seed_tracer.trace_seed_summary(
                str(seed_path),
                TIMEOUT,
                roadblock.get("filename", ""),
                int(roadblock.get("line", 0) or 0),
            )
        except Exception as exc:
            logger.warning("[DYN_TRACE] Failed to build dynamic summary for %s: %s", seed_path, exc)
            return None

        self.dynamic_trace_cache.save(PROJECT, roadblock_key, seed_path.name, fingerprint, summary)
        return summary

    def _aggregate_dynamic_summaries(self, summaries) -> dict | None:
        valid = [summary for summary in summaries if summary and summary.target_hit]
        if not valid:
            return None
        best = valid[0]

        preferred_call_paths = []
        seen_paths = set()
        preferred_functions = []
        seen_functions = set()
        preferred_locations = defaultdict(set)
        dynamic_call_edges = defaultdict(set)

        for summary in valid:
            if summary.call_path:
                key = tuple(summary.call_path)
                if key not in seen_paths:
                    preferred_call_paths.append(list(summary.call_path))
                    seen_paths.add(key)
            for func_name in summary.functions_seen:
                if func_name not in seen_functions:
                    preferred_functions.append(func_name)
                    seen_functions.add(func_name)
            for file_name, lines in summary.executed_locations.items():
                preferred_locations[file_name].update(lines)
            for file_name, lines in summary.branch_window.items():
                preferred_locations[file_name].update(lines)
            for caller, callees in summary.dynamic_call_edges.items():
                dynamic_call_edges[caller].update(callees)

        return {
            "preferred_call_paths": preferred_call_paths,
            "preferred_functions": preferred_functions,
            "preferred_locations": {file_name: sorted(lines) for file_name, lines in preferred_locations.items()},
            "dynamic_call_edges": {caller: sorted(callees) for caller, callees in dynamic_call_edges.items()},
            "representative_seed_path": os.fspath(self._resolve_seed_candidate_path(best.seed_name)) if self._resolve_seed_candidate_path(best.seed_name) else None,
            "representative_call_path": list(best.call_path),
            "trace_args": getattr(self.seed_tracer, "put_args", None),
        }

    def build_dynamic_context_for_roadblock(self, roadblock, max_seeds=3, seed_names=None, max_candidates: int = 32) -> dict | None:
        ranked = self.rank_seed_candidates_for_roadblock(
            roadblock,
            seed_names=seed_names,
            max_candidates=max(max_candidates, max_seeds),
        )
        if not ranked:
            return None
        hit_items = [item for item in ranked if item.get("summary") is not None and item["metrics"].get("target_hit")]
        if not hit_items:
            logger.info(
                "[DYN_TRACE] No target-hit seeds found in top-%d candidates for %s:%s",
                len(ranked),
                roadblock.get("filename", ""),
                roadblock.get("line", 0),
            )
            return None
        selected = hit_items[:max_seeds]
        context = self._aggregate_dynamic_summaries([item["summary"] for item in selected])
        if not context:
            return None
        context["all_hit_seed_paths"] = [os.fspath(item["seed_path"]) for item in hit_items]
        context["all_hit_seed_names"] = [str(item["seed_name"]) for item in hit_items]
        autobug_slice_context = self.build_autobug_slice_context(
            roadblock,
            [str(item["seed_name"]) for item in hit_items],
            max_attempts=max_seeds,
        )
        if autobug_slice_context:
            context["autobug_slice"] = autobug_slice_context["slice_text"]
            context["autobug_seed_name"] = autobug_slice_context["seed_name"]
            context["autobug_seed_path"] = autobug_slice_context["seed_path"]
            logger.info(
                "[AUTOBUG] Prepared fallback slice for %s:%s from %s",
                roadblock.get("filename", ""),
                roadblock.get("line", 0),
                autobug_slice_context["seed_name"],
            )
        logger.info(
            "[DYN_TRACE] Found %d target-hit seeds in top-%d candidates for %s:%s; using %d representative seed(s)",
            len(hit_items),
            len(ranked),
            roadblock.get("filename", ""),
            roadblock.get("line", 0),
            len(selected),
        )
        return context

    def get_edge_count(self):
        stats = self._read_fuzzer_stats_summary()
        edges_found = stats.get("edges_found")
        if edges_found is not None:
            return int(edges_found)
        logger.warning(f"[COVERAGE] Could not find edges_found in fuzzer_stats: {FUZZER_STATS_PATH}")
        return self.last_coverage

    def check_coverage_growth(self):
        """Use sampled edges_found deltas to determine stagnation."""
        stats = self._read_fuzzer_stats_summary()
        current_coverage = (
            int(stats["edges_found"]) if stats.get("edges_found") is not None else self.last_coverage
        )
        growth = current_coverage - self.last_coverage
        now = time.time()
        time_wo_finds = stats.get("time_wo_finds")
        last_find = stats.get("last_find")
        if growth >= THRESHOLD_COV_DELTA:
            logger.info(
                f"[COVERAGE] edges_found={current_coverage}, sample_delta={growth}, "
                f"last_find={last_find or 0}"
            )
            # logger.info(f"[COVERAGE] Coverage increased by {growth} edges since last sample")
            self.last_coverage = current_coverage
            self.last_growth_time = now
            return 0

        self.last_coverage = current_coverage
        stagnation_time = now - self.last_growth_time
        logger.info(
            f"[COVERAGE] edges_found={current_coverage}, sample_delta={growth}, "
            f"stagnation={stagnation_time:.1f}s, time_wo_finds={int(time_wo_finds) if time_wo_finds is not None else 0}s, "
            f"last_find={last_find or 0}"
        )
        return stagnation_time

    def get_trace(self, read_files: set, last_scan_time: int):
        """
        获取trace信息（完全使用autobug驱动）

        新逻辑：
        1. 轮询autobug队列获取新seed
        2. 触发autobug prime异步任务
        3. 从autobug缓存中获取roadblocks

        不再使用：
        - profraw生成
        - profdata merge
        - llvm-cov export

        Returns:
            tuple: (success: bool, last_scan_time: int, error_info: str, roadblocks: list[dict])
        """
        logger.debug("[TRACE] Starting autobug-driven trace extraction")

        # 获取新的seeds
        seed_dir = Path.joinpath(Path(self.output_dir), FUZZER_NAME, "queue")
        seed_lst_to_run, resume_data_to_load, last_scan_time = get_new_seeds(
            seed_dir,
            read_files,
            last_scan_time,
            prof_dir=None,  # 不再使用profdir
        )

        if len(seed_lst_to_run) == 0:
            logging.info("[TRACE] 没有新的seed需要追踪，等待AFL生成新seed...")
            # 即使没有新seeds，也尝试从autobug缓存获取已有roadblocks
            roadblocks = self.get_current_one_sided_branches()
            return True, last_scan_time, "没有新的seed", roadblocks

        # 将新发现的seeds加入autobug处理队列
        seed_names = [seed_path.name for seed_path in seed_lst_to_run]
        self.enqueue_autobug_seed_names(seed_names)

        # 触发异步autobug prime
        self.kick_autobug_prime_async()

        # 从autobug缓存获取roadblocks
        roadblocks = self.get_current_one_sided_branches()

        logger.info(
            f"[TRACE] Autobug-driven trace完成: "
            f"new_seeds={len(seed_lst_to_run)}, "
            f"roadblocks={len(roadblocks)}, "
            f"autobug_cache_size={self._get_autobug_seed_branch_cache_size()}"
        )

        # 更新最近追踪的前沿
        self._recent_trace_frontier = {
            "files": set(),  # 可以从autobug数据中提取
            "functions": set(),
        }

        return True, last_scan_time, "", roadblocks
    def get_recent_trace_frontier(self) -> dict:
        return {
            "files": set(self._recent_trace_frontier.get("files", set())),
            "functions": set(self._recent_trace_frontier.get("functions", set())),
        }

    def get_roadblocks(self, static_path) -> list:
        if not self.cfg_loader:
            self.cfg_loader = cfg_loader.CFGLoader(self.bb, static_path)
        self.cfg_loader.read_freq(self.info.bitmap.bitmap)
        self.cfg_loader.build_graph(bbs)
        self.cfg_loader.calculate_depth()
        bottlenecks = [x for x in self.cfg_loader.get_roadblocks(DEPTH_THRESHOLD)]
        self.cfg_loader.dump(bottlenecks)
        return bottlenecks

    @staticmethod
    def _roadblock_seed_key(roadblock: dict) -> tuple[str, int, object]:
        filename = roadblock.get("filename", "")
        group_type = roadblock.get("group_type")
        status = roadblock.get("status")
        if group_type == "switch":
            return (
                filename,
                "switch",
                int(roadblock.get("switch_statement_line", 0) or 0),
                int(roadblock.get("line", 0) or 0),
                int(roadblock.get("case_body_line", 0) or 0),
                int(roadblock.get("group_index", 0) or 0),
                str(roadblock.get("case_label", "") or "").strip(),
                status,
            )
        return (
            filename,
            "branch",
            int(roadblock.get("line", 0) or 0),
            str(roadblock.get("code", "") or "").strip(),
            status,
        )

    def _load_trace_progress(self) -> int:
        if not self.trace_progress_path.exists():
            return 0
        try:
            payload = json.loads(self.trace_progress_path.read_text(encoding='utf-8'))
            return int(payload.get("last_scan_time_ns", 0) or 0)
        except Exception as exc:
            logger.warning("[TRACE] Failed to load trace progress checkpoint %s: %s", self.trace_progress_path, exc)
            return 0

    def _save_trace_progress(self, last_scan_time_ns: int, seed_name: str | None = None) -> None:
        payload = {
            "last_scan_time_ns": int(last_scan_time_ns),
            "seed_name": seed_name or "",
            "updated_at": datetime.now().isoformat(timespec="seconds"),
        }
        try:
            self.trace_progress_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
        except Exception as exc:
            logger.warning("[TRACE] Failed to save trace progress checkpoint %s: %s", self.trace_progress_path, exc)

    def get_rb_seed(self, roadblock, *, top_k_confirm: int = 10, coarse_limit: int = 48):
        coarse_candidates = self._recent_seed_candidates(limit=max(coarse_limit, 48))
        if not coarse_candidates:
            return []

        autobug_matches = self._autobug_matching_seed_names(roadblock, coarse_candidates, limit=top_k_confirm)
        if autobug_matches:
            logger.info(
                "[AUTOBUG] Confirmed %d seed(s) for %s:%s via get-branch replay",
                len(autobug_matches),
                roadblock.get("filename", ""),
                roadblock.get("line", 0),
            )
            return autobug_matches

        fallback = coarse_candidates[: min(3, len(coarse_candidates))]
        if fallback:
            expected_branch = self._roadblock_expected_branch_id(roadblock)
            logger.info(
                "[AUTOBUG] No AutoBug-confirmed seed for %s:%s (expected_branch=%s, status=%s, side=%s), "
                "falling back to recent seeds: %s",
                roadblock.get("filename", ""),
                roadblock.get("line", 0),
                expected_branch if expected_branch is not None else "?",
                roadblock.get("status", ""),
                roadblock.get("side", ""),
                ", ".join(fallback),
            )
        return fallback

    def get_rb_file_and_line(self, roadblock):
        rb_bb = self.bb[roadblock]
        rb_line = rb_bb["lineEnd"]
        rb_fname = self.func[rb_bb["function"]]['name']
        rb_file = self.func[rb_bb["function"]]['file_name']
        return rb_file, int(rb_line), rb_fname

    def _find_function_for_location(self, filename: str, line: int):
        for func in self.func:
            func_file = func.get('file_name', '')
            if not func_file:
                continue
            same_file = func_file == filename or func_file.split('/')[-1] == filename.split('/')[-1]
            if same_file and func.get('lineStart', 0) <= line <= func.get('lineEnd', 0):
                return func
        return find_enclosing_function_metadata(filename, line)

    def _find_basic_block_id_for_location(self, func_id: int | None, line: int):
        if func_id is None:
            return None
        for bb in self.bb:
            if bb.get('function') == func_id and bb.get('lineStart', 0) <= line <= bb.get('lineEnd', 0):
                return bb.get('id')
        return None

    def get_current_one_sided_branches(self) -> list[dict]:
        """
        获取当前的单向分支（瓶颈分支）列表

        优先级（已切换为完全autobug驱动）：
        1. 从AutoBug缓存构建（主要数据源）
        2. 如果没有autobug数据，返回空列表

        Returns:
            list[dict]: 瓶颈分支列表，每个元素包含 {id, function, file, line, code, status}
        """
        # 完全使用AutoBug缓存作为主要数据源
        logger.info("[CoverageTracer] 从AutoBug缓存获取瓶颈分支")
        roadblocks = self._get_one_sided_branches_from_autobug_cache()

        if not roadblocks:
            logger.warning("[CoverageTracer] AutoBug缓存为空，可能需要先运行autobug prime")
        else:
            logger.info(f"[CoverageTracer] 从AutoBug获取到 {len(roadblocks)} 个瓶颈分支")

        return roadblocks

    def _get_one_sided_branches_from_autobug_cache(self) -> list[dict]:
        """
        从AutoBug缓存构建单向分支列表

        使用 _autobug_seed_branch_cache 和 cond_status 来识别瓶颈分支：
        - 遍历所有有分支信息的seed
        - 对每个条件，找出部分覆盖的分支
        - 这些部分覆盖的分支就是单向分支（瓶颈分支）

        Returns:
            list[dict]: 瓶颈分支列表
        """
        result = []
        seen_conditions = set()

        # 遍历AutoBug缓存
        with self._autobug_seed_branch_cache_lock:
            cached_seed_items = list(self._autobug_seed_branch_cache.items())
        for seed_name, seed_data in cached_seed_items:
            if seed_data is None:
                continue

            for cond_key, branch_info in seed_data.items():
                if cond_key in seen_conditions:
                    continue

                seen_conditions.add(cond_key)

                # 解析条件键获取位置信息
                # 格式类似 "file:line:condition_type"
                try:
                    parts = cond_key.split(':')
                    if len(parts) >= 2:
                        filename = parts[0]
                        line = int(parts[1])

                        # 检查是否有部分覆盖的分支
                        branches = branch_info.get('branches', set())
                        total = branch_info.get('total', 0)

                        if total > 1 and len(branches) < total:
                            # 这是一个有部分覆盖的条件，可能存在瓶颈分支
                            # 找到函数信息
                            func = self._find_function_for_location(filename, line)
                            if func is None:
                                continue

                            func_id = func.get('id')
                            bb_id = self._find_basic_block_id_for_location(func_id, line)

                            # 获取未覆盖的分支ID
                            covered_branches = branches
                            uncovered_branch_ids = [b for b in range(1, total + 1) if b not in covered_branches]

                            for branch_id in uncovered_branch_ids:
                                # 从源码提取代码片段
                                code = self._extract_source_code(filename, line)

                                # 映射branch_id到side（true/false）
                                # AutoBug使用1-based branch ID，llvm-cov使用true/false
                                # 假设：branch_id=1 对应 false，branch_id=2 对应 true
                                side = 'false' if branch_id == 1 else 'true'
                                status = 'only_true' if branch_id == 1 else 'only_false'

                                # 检查是否是switch类型
                                # switch类型的条件通常包含多个分支，group_type=switch
                                group_type = 'switch' if total > 2 else 'if'
                                case_body_line = line  # 默认使用条件行作为case body行
                                switch_statement_line = None

                                # 如果是switch类型，尝试获取switch语句行
                                if group_type == 'switch':
                                    # 可以从cond_key解析switch信息
                                    # cond_key格式: file:line:condition_type
                                    # 需要向前查找switch语句
                                    switch_statement_line = self._find_switch_statement_before_line(filename, line)

                                # 统一数据结构：与 llvm-cov 输出完全一致
                                result.append({
                                    'id': bb_id if bb_id is not None else line,
                                    'function': func.get('name', ''),
                                    'filename': filename,
                                    'file': filename,
                                    'line': line,
                                    'code': code,  # 从源码提取代码片段
                                    'status': status,
                                    'side': side,  # 映射branch_id到side
                                    'group_type': group_type,  # switch/if类型标识
                                    'case_body_line': case_body_line,  # case体行
                                    'switch_statement_line': switch_statement_line,  # switch语句行
                                    'condition_key': cond_key,
                                    'branch_id': branch_id,
                                    'total_branches': total,
                                })

                except (ValueError, IndexError) as e:
                    logger.debug(f"[CoverageTracer] Failed to parse cond_key '{cond_key}': {e}")
                    continue

        logger.info(f"[CoverageTracer] 从AutoBug缓存构建了 {len(result)} 个瓶颈分支")
        return result

    def _get_autobug_seed_branch_cache_size(self) -> int:
        with self._autobug_seed_branch_cache_lock:
            return len(self._autobug_seed_branch_cache)

    def _extract_source_code(self, filename: str, line: int) -> str:
        """
        从源文件中提取指定行的代码片段

        Args:
            filename: 源文件路径
            line: 行号

        Returns:
            str: 代码片段，如果无法提取返回空字符串
        """
        try:
            # 解析完整文件路径
            if not filename.startswith('/'):
                # 相对路径，需要转换为绝对路径
                for path in [SRC_PATH, SRC_BEAR_PATH]:
                    candidate = path / filename
                    if candidate.exists():
                        src_file = candidate
                        break
                else:
                    logger.debug(f"[CoverageTracer] Source file not found: {filename}")
                    return ""
            else:
                src_file = Path(filename)

            if not src_file.exists():
                logger.debug(f"[CoverageTracer] Source file not found: {filename}")
                return ""

            # 读取指定行
            with open(src_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                if 1 <= line <= len(lines):
                    code_line = lines[line - 1].strip()
                    # 去除行号前缀（如果有的话）
                    # 常见格式: "123:    code" 或 "code"
                    code_line = code_line.split(max(1, code_line.find(')') + 1))[-1].strip()
                    return code_line

        except Exception as e:
            logger.debug(f"[CoverageTracer] Failed to extract source code from {filename}:{line}: {e}")

        return ""

    def _find_switch_statement_before_line(self, filename: str, line: int) -> int | None:
        """
        在源文件中查找指定行之前的switch语句

        Args:
            filename: 源文件路径
            line: 起始行号

        Returns:
            int | None: switch语句的行号，如果找不到返回None
        """
        try:
            # 解析完整文件路径
            if not filename.startswith('/'):
                for path in [SRC_PATH, SRC_BEAR_PATH]:
                    candidate = path / filename
                    if candidate.exists():
                        src_file = candidate
                        break
                else:
                    return None
            else:
                src_file = Path(filename)

            if not src_file.exists():
                return None

            # 读取源文件
            with open(src_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # 向前查找switch语句（从指定行开始）
            for i in range(min(line - 1, len(lines)), 0, -1):
                line_text = lines[i].strip()
                # 查找switch关键字
                if re.match(r'switch\s*\(', line_text):
                    # 计算实际行号
                    return i + 1  # 1-based line number

        except Exception as e:
            logger.debug(f"[CoverageTracer] Failed to find switch statement before {filename}:{line}: {e}")

        return None

        result = []
        seen_keys = set()
        for file_entry in files:
            for branch in file_entry.get('one_sided_branches', []):
                if int(branch.get('true_count', 0) or 0) == 0 and int(branch.get('false_count', 0) or 0) == 0:
                    continue
                item = branch.copy()
                item.pop('false_count', None)
                item.pop('true_count', None)
                item.pop('col', None)
                item.setdefault('filename', file_entry.get('filename'))
                key = (item.get('filename'), item.get('line'), item.get('side'), item.get('status'))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                result.append(item)

        logger.info(f"[CoverageTracer] llvm-cov one-sided branch export completed: {len(result)} targets")
        return result


def get_new_seeds(directory, read_files, last_scan_time, prof_dir: Path | None = None):  # 添加去数据库找的功能
    files_to_run = []
    files_to_load = []
    latest_seen_timestamp_ns = int(last_scan_time or 0)
    # 按创建时间排序，先处理老的 seed（先落盘的）
    all_files = []
    for p in Path(directory).iterdir():
        if p.is_file():
            try:
                stat = p.stat()
                all_files.append((p, stat.st_ctime_ns))
            except OSError:
                pass
    sorted_pathdir = [p for p, _ in sorted(all_files, key=lambda x: x[1])]
    for file_path in sorted_pathdir:
        stat = file_path.stat()
        file_timestamp_ns = max(int(stat.st_ctime_ns), int(stat.st_mtime_ns))
        latest_seen_timestamp_ns = max(latest_seen_timestamp_ns, file_timestamp_ns)

        profdata_missing = False
        if prof_dir is not None:
            profdata_missing = not (prof_dir / f"{file_path.name}.profdata").exists()

        needs_incremental_trace = file_timestamp_ns > int(last_scan_time or 0) and file_path not in read_files
        needs_backfill_trace = profdata_missing
        if not needs_incremental_trace and not needs_backfill_trace:
            continue

        ''' last scan time and read_files should not influence by resume data'''
        read_files.add(file_path)
        files_to_run.append(file_path)

    return files_to_run, files_to_load, latest_seen_timestamp_ns


if __name__ == '__main__':
    print(get_function_slice(
        ['main', 'LLVMFuzzerTestOneInput', 'xmlSetGenericErrorFunc', '__xmlGenericErrorContext', 'xmlIsMainThread'],
        803, "only_true", LLMUtil(MODEL, API_KEY, BASE_URL)))
#     code = """int main(int argc, char* argv[]) {
#     // open file
#     FILE *f = fopen(argv[1], "rb");
#
#     // get file size
#     fseek(f, 0, SEEK_END);
#     long fsize = ftell(f);
#
#     // read file contents
#     fseek(f, 0, SEEK_SET);
#     char *string = (char*)malloc(fsize + 1);
#     fread(string, 1, fsize, f);
#     fclose(f);
#
#     // Now call into the harness
#     int retval = LLVMFuzzerTestOneInput((const uint8_t *)string, fsize);
#
#     free(string);
#     return retval;
# }"""
#
#     extract_function_header_from_code(code)
