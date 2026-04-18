#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tree_sitter_languages import get_parser
import sys
import re

# =========================
# Tree-sitter 初始化
# =========================

parser = get_parser('c')


class RawSpanNode:
    """
    伪造一个“节点”，用 start/end byte + point 表示一个语句片段，
    让后续逻辑继续复用 build_trace_guided_path 的其它分支。
    """
    __slots__ = ("type", "start_byte", "end_byte", "start_point", "end_point", "children", "is_named")

    def __init__(self, start_byte, end_byte, start_point, end_point):
        self.type = "raw_span_statement"
        self.start_byte = start_byte
        self.end_byte = end_byte
        self.start_point = start_point
        self.end_point = end_point
        self.children = []
        self.is_named = True

    def child_by_field_name(self, _name):
        return None


def _group_compound_children_into_spans(parent, src: bytes):
    """
    将 compound_statement 等容器的 named children，按源码中的 ';' 或 '}' 拼成“语句级”span。
    解决：`auto &x = ...;` 被拆成多个 child 的问题。
    """
    kids = [c for c in parent.children if getattr(c, "is_named", False)]
    if not kids:
        return []

    spans = []
    i = 0
    n = len(kids)

    def _strip_tail(b: bytes) -> bytes:
        return b.rstrip(b" \t\r\n")

    while i < n:
        start = kids[i].start_byte
        start_pt = kids[i].start_point

        j = i
        end = kids[j].end_byte
        end_pt = kids[j].end_point

        # 逐步扩展到遇到 ';' 或 '}' 为止（按源码判断）
        while True:
            seg = _strip_tail(src[start:end])
            if seg.endswith(b";") or seg.endswith(b"}"):
                break
            j += 1
            if j >= n:
                break
            end = kids[j].end_byte
            end_pt = kids[j].end_point

        spans.append(RawSpanNode(start, end, start_pt, end_pt))
        i = j + 1

    return spans


# ============================================================
# 基础工具
# ============================================================

def text_of(node, src: bytes) -> str:
    if node is None:
        return ""
    return src[node.start_byte:node.end_byte].decode()


def get_line_no(node):
    """
    从 AST 节点取起始行号（1-based）
    """
    if node is None:
        return None
    return node.start_point[0] + 1


def strip_outer_parens(s: str) -> str:
    """
    尽量去掉最外层多余的一对括号，例如：
    "(x < y)"      -> "x < y"
    "((x < y) + 1)"-> "(x < y) + 1"
    "(!func(x))"   -> "!func(x)"
    """
    s = s.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        balanced = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(s) - 1:
                    balanced = False
                    break
        if balanced and depth == 0:
            s = s[1:-1].strip()
        else:
            break
    return s


def negate_cond(cond: str) -> str:
    """
    生成“取反后的条件”字符串，同时简化括号和双重取反。
    """
    c = strip_outer_parens(cond)

    # 处理前导 '!' 的情况：!( !X ) => X
    if c.startswith("!"):
        rest = c[1:].lstrip()
        rest = strip_outer_parens(rest)
        return rest

    # 一般情况：!(...)
    return f"!({c})"


def indent_block(lines, indent="    "):
    """
    对循环体 / 子块整体加一个缩进。
    lines: List[(code, line_no)]
    """
    return [(indent + code, ln) for (code, ln) in lines]


def has_nonempty_lines(lines):
    """
    判断一个路径片段中是否有“非空内容”（不是纯空白，也不是只有花括号）。
    lines: List[(code, line_no)]
    """
    for code, _ in lines:
        s = code.strip()
        if s and s not in ("{", "}"):
            return True
    return False


def normalize_stmt_text(txt: str) -> str:
    """
    统一语句文本：去掉末尾所有分号，再补一个分号。
    """
    txt = (txt or "").strip()
    if not txt:
        return ""
    while txt.endswith(";"):
        txt = txt[:-1].rstrip()
    if not txt:
        return ""
    return f"{txt};"


# ============================================================
# 预处理节点辅助（宏展开用）
# ============================================================

def _first_named_child_of_type(node, t):
    if node is None:
        return None
    for ch in node.children:
        if ch.is_named and ch.type == t:
            return ch
    return None


def _all_named_children_of_type(node, t):
    if node is None:
        return []
    return [ch for ch in node.children if ch.is_named and ch.type == t]


def _preproc_cond_text(node, src: bytes) -> str:
    """
    尽量从 preproc_if / preproc_ifdef / preproc_ifndef 里取出“条件文本”
    不同版本 grammar 字段名可能不同，做多重兜底。
    """
    cond_node = (
            node.child_by_field_name("condition")
            or node.child_by_field_name("name")
            or _first_named_child_of_type(node, "identifier")
    )
    if cond_node is not None:
        return strip_outer_parens(text_of(cond_node, src).strip())

    first_line = text_of(node, src).splitlines()[0].strip()
    return first_line


def _get_preproc_then_else_groups(node):
    """
    从 preproc_if/preproc_ifdef/preproc_ifndef 节点里取 then_group / else_group
    then_group: preproc_group
    else_group: preproc_else -> preproc_group
    """
    groups = _all_named_children_of_type(node, "preproc_group")
    then_group = groups[0] if len(groups) >= 1 else None

    else_node = _first_named_child_of_type(node, "preproc_else")
    else_group = _first_named_child_of_type(else_node, "preproc_group") if else_node else None
    return then_group, else_group


# ============================================================
# 1) rewrite-if 功能（保留你原有逻辑）
# ============================================================

def find_if_by_line(node, target_line):
    """
    在语法树中寻找“覆盖 target_line 的 if_statement”：
    start_line <= target_line <= end_line
    并且优先返回最内层。
    target_line 为 1-based。
    """
    # 先在子节点里找最内层 if
    for ch in node.children:
        if not ch.is_named:
            continue
        res = find_if_by_line(ch, target_line)
        if res is not None:
            return res

    # 再看当前节点本身
    if node.type == "if_statement":
        start_line = get_line_no(node)
        end_line = node.end_point[0] + 1
        if start_line <= target_line <= end_line:
            return node

    return None


def rewrite_if_to_assert_false_branch(src: bytes, if_line: int) -> bytes:
    """
    在源码 src 中找到“覆盖 if_line 的 if_statement”，改写为走 false 分支：
        assert(!cond);
        else_body
    若没有 else，则只保留 assert(!cond);
    """
    tree = parser.parse(src)
    root = tree.root_node

    if_node = find_if_by_line(root, if_line)
    if if_node is None:
        raise RuntimeError(f"未在第 {if_line} 行找到 if_statement")

    cond_node = if_node.child_by_field_name("condition")
    alt_node = if_node.child_by_field_name("alternative")

    if cond_node is None:
        raise RuntimeError(f"第 {if_line} 行的 if 没有 condition？")

    raw_cond = text_of(cond_node, src)
    neg = negate_cond(raw_cond)

    if alt_node is not None:
        else_body = text_of(alt_node, src).rstrip()
        new_code = f"assert({neg});\n{else_body}\n"
    else:
        new_code = f"assert({neg});\n"

    new_bytes = (
            src[:if_node.start_byte] +
            new_code.encode("utf-8") +
            src[if_node.end_byte:]
    )
    return new_bytes


# ============================================================
# 2) 完整路径枚举（支持：return 终止 + 宏展开）
# ============================================================

# Path 结构：
#   Path = (lines, terminated)
#   lines: List[(code, line_no)]
#   terminated: bool  (return 后为 True)


def extract_paths_from_node(node, src: bytes):
    """
    从一个 AST 节点生成所有“结构化路径”，每条路径为 (lines, terminated)。
    """
    if node is None:
        return [([], False)]

    ntype = node.type

    # ---- 顶层 / 复合语句：顺序组合 ----
    if ntype in ("translation_unit", "compound_statement", "preproc_group", "preproc_else"):
        # stmts = [c for c in node.children if c.is_named]
        stmts = _group_compound_children_into_spans(node, src)
        return extract_paths_from_seq(stmts, src)

    # ---- 预处理分支：#if/#ifdef/#ifndef ----
    if ntype in ("preproc_if", "preproc_ifdef", "preproc_ifndef"):
        cond_text = _preproc_cond_text(node, src)
        cond_line = get_line_no(node)

        then_group, else_group = _get_preproc_then_else_groups(node)

        then_paths = extract_paths_from_node(then_group, src) if then_group else [([], False)]
        else_paths = extract_paths_from_node(else_group, src) if else_group else [([], False)]

        results = []
        # 用注释标注宏条件（不使用 assert，避免把编译期分支误当运行期）
        for (tp_lines, tp_term) in then_paths:
            results.append((
                [(f"/*#if {cond_text}*/", cond_line)] + tp_lines + [(f"/*#endif*/", cond_line)],
                tp_term
            ))
        for (ep_lines, ep_term) in else_paths:
            results.append((
                [(f"/*#if !({cond_text})*/", cond_line)] + ep_lines + [(f"/*#endif*/", cond_line)],
                ep_term
            ))
        return results

    # ---- 函数定义：只看函数体 ----
    if ntype == "function_definition":
        body = node.child_by_field_name("body")
        if body is None:
            return [([], False)]

        header_txt = src[node.start_byte:body.start_byte].decode().rstrip()
        header_line = get_line_no(node)
        end_line = body.end_point[0] + 1

        body_paths = extract_paths_from_node(body, src)  # List[(lines, term)]

        results = []
        for (bp_lines, bp_term) in body_paths:
            wrapped = []
            wrapped.append((header_txt + " {", header_line))
            wrapped += indent_block(bp_lines)
            wrapped.append(("}", end_line))
            results.append((wrapped, bp_term))
        return results

    # ---- return：路径终止 ----
    if ntype == "return_statement":
        txt = normalize_stmt_text(text_of(node, src))
        ln = get_line_no(node)
        if not txt:
            return [([], True)]
        return [([(txt, ln)], True)]

    # ---- if 语句 ----
    if ntype == "if_statement":
        cond_node = node.child_by_field_name("condition")
        cons_node = node.child_by_field_name("consequence")
        alt_node = node.child_by_field_name("alternative")

        raw_cond = text_of(cond_node, src).strip()
        cond_text = strip_outer_parens(raw_cond)
        cond_line = get_line_no(cond_node)

        then_paths = extract_paths_from_node(cons_node, src) if cons_node is not None else [([], False)]

        # 解包 alternative（拿到真正 body）
        else_paths = [([], False)]
        if alt_node is not None:
            alt_body = None
            for ch in alt_node.children:
                if ch.is_named:
                    alt_body = ch
                    break
            if alt_body is None:
                alt_body = alt_node
            else_paths = extract_paths_from_node(alt_body, src)

        results = []
        for (tp_lines, tp_term) in then_paths:
            results.append(([(f"assert({cond_text});", cond_line)] + tp_lines, tp_term))
        for (ep_lines, ep_term) in else_paths:
            neg = negate_cond(cond_text)
            results.append(([(f"assert({neg});", cond_line)] + ep_lines, ep_term))

        return results

    # ---- for 语句：只保留“进入循环体一次”的路径（无空体） ----
    if ntype == "for_statement":
        init_node = node.child_by_field_name("initializer")
        cond_node = node.child_by_field_name("condition")
        update_node = node.child_by_field_name("update")
        body_node = node.child_by_field_name("body")

        def strip_semis(s: str) -> str:
            s = (s or "").strip()
            while s.endswith(";"):
                s = s[:-1].strip()
            return s

        init_txt = strip_semis(text_of(init_node, src)) if init_node else ""
        cond_txt = text_of(cond_node, src).strip() if cond_node else ""
        upd_txt = strip_semis(text_of(update_node, src)) if update_node else ""

        header = f"for ({init_txt}; {cond_txt}; {upd_txt})".strip()
        header_line = get_line_no(node)

        body_paths = extract_paths_from_node(body_node, src) if body_node is not None else [([], False)]
        non_empty_bodies = [(l, t) for (l, t) in body_paths if has_nonempty_lines(l)]

        results = []
        for (bp_lines, bp_term) in non_empty_bodies:
            results.append((
                [(f"{header} {{", header_line)] + indent_block(bp_lines) + [("}", header_line)],
                bp_term
            ))

        if not results:
            return [([], False)]
        return results

    # ---- while 语句：只保留“进入循环体一次”的路径（无空体） ----
    if ntype == "while_statement":
        cond_node = node.child_by_field_name("condition")
        body_node = node.child_by_field_name("body")

        cond_text = text_of(cond_node, src).strip() if cond_node is not None else "/*cond*/"
        header = f"while ({cond_text})"
        header_line = get_line_no(node)

        body_paths = extract_paths_from_node(body_node, src) if body_node is not None else [([], False)]
        non_empty_bodies = [(l, t) for (l, t) in body_paths if has_nonempty_lines(l)]

        results = []
        for (bp_lines, bp_term) in non_empty_bodies:
            results.append((
                [(f"{header} {{", header_line)] + indent_block(bp_lines) + [("}", header_line)],
                bp_term
            ))

        if not results:
            return [([], False)]
        return results

    # ---------- RawSpan：直接用 byte slice ----------
    if ntype == "raw_span_statement":
        txt = src[node.start_byte:node.end_byte].decode(errors="ignore")
        txt = normalize_stmt_text(txt)
        if not txt:
            return []
        return [(txt, get_line_no(node))]

    # ---- 其他语句：break / 表达式 / 声明 等 ----
    txt = normalize_stmt_text(text_of(node, src))
    if not txt:
        return [([], False)]

    line_no = get_line_no(node)
    return [([(txt, line_no)], False)]


def extract_paths_from_seq(stmt_nodes, src: bytes):
    """
    顺序组合多个语句节点的所有路径。
    返回 List[(lines, terminated)]
    关键：terminated=True 的路径不会再拼接后续语句（return 终止语义）。
    """
    paths = [([], False)]
    for stmt in stmt_nodes:
        subpaths = extract_paths_from_node(stmt, src)  # List[(lines, term)]
        new_paths = []
        for (p_lines, p_term) in paths:
            if p_term:
                new_paths.append((p_lines, True))
                continue
            for (sp_lines, sp_term) in subpaths:
                new_paths.append((p_lines + sp_lines, sp_term))
        paths = new_paths
    return paths


# ============================================================
# Trace 匹配相关（保留你原逻辑）
# ============================================================

def load_trace_linenos(trace_file):
    """
    从 trace 文件中解析所有出现的整数，作为“可能的源码行号”。
    """
    linenos = set()
    with open(trace_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            for m in re.findall(r"\d+", line):
                try:
                    linenos.add(int(m))
                except ValueError:
                    pass
    return linenos


def score_path_against_trace(path, trace_linenos):
    """
    path: List[(code, line_no)]
    返回 (overlap_count, path_line_count, lines_set)
    """
    lines = {ln for (_, ln) in path if ln is not None}
    if not lines:
        return 0, 0, set()
    overlap = len(lines & trace_linenos)
    return overlap, len(lines), lines


def select_paths_by_trace(paths, trace_linenos):
    """
    paths: List[List[(code, line_no)]]  (这里用于“全枚举模式”)
    """
    scored = []
    for i, p in enumerate(paths):
        overlap, total, lines = score_path_against_trace(p, trace_linenos)
        if overlap == 0:
            continue
        scored.append((i, overlap, total, p, lines))

    if not scored:
        return [], None

    max_overlap = max(s[1] for s in scored)
    candidates = [s for s in scored if s[1] == max_overlap]

    min_total = min(s[2] for s in candidates)
    best = [s for s in candidates if s[2] == min_total]

    best_paths = [p for (_, _, _, p, _) in best]
    info = [(idx, overlap, total, lines) for (idx, overlap, total, p, lines) in best]
    return best_paths, info


# ============================================================
# Trace-guided 单路径截断（支持：return 终止 + 宏分支选择）
# ============================================================


def collect_subtree_lines(node):
    """
    返回 node 覆盖的所有源码行号集合（1-based，闭区间）。
    关键修复：不要只收集 start 行，否则跨行语句会漏命中 trace 行。
    """
    if node is None:
        return set()
    start = node.start_point[0] + 1
    end = node.end_point[0] + 1
    if end < start:
        end = start
    return set(range(start, end + 1))


def build_trace_guided_path(node, src: bytes, trace_linenos, force_full=False):
    """
    根据 trace_linenos，从 node 子树中只构造一条“最相关路径”。
    返回 List[(code, line_no)]。

    force_full=True：前缀区间，即使与 trace 没交集也要构造（默认偏向 then）。
    """
    if node is None:
        return []

    ntype = node.type

    # ---------- 容器：语句块 / 顶层 / preproc_group ----------
    if ntype in ("compound_statement", "translation_unit", "preproc_group", "preproc_else"):
        stmts = [c for c in node.children if c.is_named]
        if not stmts:
            return []

        last_idx = -1
        for i, s in enumerate(stmts):
            s_lines = collect_subtree_lines(s)
            if s_lines & trace_linenos:
                last_idx = i

        if last_idx == -1:
            if not force_full:
                return []
            last_idx = len(stmts) - 1

        path = []
        terminated = False

        for i, s in enumerate(stmts[: last_idx + 1]):
            if terminated:
                break

            sub = build_trace_guided_path(
                s, src, trace_linenos,
                force_full=(i < last_idx)
            )
            path.extend(sub)

            # ✅ 修复：只有“trace 实际走到的 return”才终止
            # 否则像 if(early_guard){return;} 这种会错误截断后续路径
            for code, ln in sub:
                if code.strip().startswith("return") and (ln in trace_linenos):
                    terminated = True
                    break

        return path

    # ---------- 预处理分支：#if/#ifdef/#ifndef ----------
    if ntype in ("preproc_if", "preproc_ifdef", "preproc_ifndef"):
        cond_text = _preproc_cond_text(node, src)
        cond_line = get_line_no(node)

        then_group, else_group = _get_preproc_then_else_groups(node)

        if force_full:
            chosen = then_group if then_group is not None else else_group
            chosen_tag = f"/*#if {cond_text}*/"
        else:
            then_score = len(collect_subtree_lines(then_group) & trace_linenos) if then_group else 0
            else_score = len(collect_subtree_lines(else_group) & trace_linenos) if else_group else 0

            if then_score == 0 and else_score == 0:
                chosen = then_group if then_group is not None else else_group
                chosen_tag = f"/*#if {cond_text}*/"
            elif then_score >= else_score:
                chosen = then_group
                chosen_tag = f"/*#if {cond_text}*/"
            else:
                chosen = else_group
                chosen_tag = f"/*#if !({cond_text})*/"

        body_path = build_trace_guided_path(chosen, src, trace_linenos, force_full=force_full) if chosen else []

        if not body_path and not force_full:
            return []

        return [(chosen_tag, cond_line)] + body_path + [("/*#endif*/", cond_line)]

    # ---------- return：终止 ----------
    if ntype == "return_statement":
        txt = normalize_stmt_text(text_of(node, src))
        if not txt:
            return []
        return [(txt, get_line_no(node))]

    # ---------- if 语句 ----------
    if ntype == "if_statement":
        cond_node = node.child_by_field_name("condition")
        cons_node = node.child_by_field_name("consequence")
        alt_node = node.child_by_field_name("alternative")

        raw_cond = text_of(cond_node, src).strip()
        cond_text = strip_outer_parens(raw_cond)
        cond_line = get_line_no(cond_node)

        # 解出 else body
        alt_body = None
        if alt_node is not None:
            for ch in alt_node.children:
                if ch.is_named:
                    alt_body = ch
                    break
            if alt_body is None:
                alt_body = alt_node

        if force_full:
            chosen_body = cons_node if cons_node is not None else alt_body
            chosen_is_then = True
        else:
            cons_score = len(collect_subtree_lines(cons_node) & trace_linenos) if cons_node else 0
            alt_score = len(collect_subtree_lines(alt_body) & trace_linenos) if alt_body else 0

            if cons_score == 0 and alt_score == 0:
                chosen_body = cons_node if cons_node is not None else alt_body
                chosen_is_then = True
            elif cons_score >= alt_score:
                chosen_body = cons_node
                chosen_is_then = True
            else:
                chosen_body = alt_body
                chosen_is_then = False

        path = []
        if chosen_is_then:
            path.append((f"assert({cond_text});", cond_line))
        else:
            path.append((f"assert({negate_cond(cond_text)});", cond_line))

        if chosen_body is not None:
            body_path = build_trace_guided_path(chosen_body, src, trace_linenos, force_full=force_full)
            path.extend(body_path)
        return path

    # ---------- for：进入一次 ----------
    if ntype == "for_statement":
        init_node = node.child_by_field_name("initializer")
        cond_node = node.child_by_field_name("condition")
        update_node = node.child_by_field_name("update")
        body_node = node.child_by_field_name("body")

        def strip_semis(s: str) -> str:
            s = (s or "").strip()
            while s.endswith(";"):
                s = s[:-1].strip()
            return s

        init_txt = strip_semis(text_of(init_node, src)) if init_node else ""
        cond_txt = text_of(cond_node, src).strip() if cond_node else ""
        upd_txt = strip_semis(text_of(update_node, src)) if update_node else ""

        header = f"for ({init_txt}; {cond_txt}; {upd_txt})".strip()
        header_line = get_line_no(node)

        body_path = build_trace_guided_path(body_node, src, trace_linenos, force_full=force_full) if body_node else []

        if not body_path and not force_full:
            return []

        return [(f"{header} {{", header_line)] + indent_block(body_path) + [("}", header_line)]

    # ---------- while：进入一次 ----------
    if ntype == "while_statement":
        cond_node = node.child_by_field_name("condition")
        body_node = node.child_by_field_name("body")

        cond_text = text_of(cond_node, src).strip() if cond_node is not None else "/*cond*/"
        header = f"while ({cond_text})"
        header_line = get_line_no(node)

        body_path = build_trace_guided_path(body_node, src, trace_linenos, force_full=force_full) if body_node else []

        if not body_path and not force_full:
            return []

        return [(f"{header} {{", header_line)] + indent_block(body_path) + [("}", header_line)]

    # ---------- 函数定义：包壳子 ----------
    if ntype == "function_definition":
        body = node.child_by_field_name("body")
        if body is None:
            return []

        header_txt = src[node.start_byte:body.start_byte].decode().rstrip()
        header_line = get_line_no(node)
        end_line = body.end_point[0] + 1

        body_path = build_trace_guided_path(body, src, trace_linenos, force_full=False)

        wrapped = []
        wrapped.append((header_txt + " {", header_line))
        wrapped += indent_block(body_path)
        wrapped.append(("}", end_line))
        return wrapped

    # ---------- 其他语句 ----------
    txt = normalize_stmt_text(text_of(node, src))
    if not txt:
        return []
    return [(txt, get_line_no(node))]


def extract_single_path_from_function(func_node, src: bytes, trace_linenos):
    """
    从函数定义中提取一条 trace 引导的截断路径。
    """
    return build_trace_guided_path(func_node, src, trace_linenos, force_full=False)


# ============================================================
# main
# ============================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_paths_ast_final.py <c-source-file> [trace-file]")
        print("       python extract_paths_ast_final.py <c-source-file> --rewrite-if <if_line>")
        sys.exit(1)

    c_file = sys.argv[1]

    # rewrite-if 模式
    if len(sys.argv) >= 4 and sys.argv[2] == "--rewrite-if":
        try:
            if_line = int(sys.argv[3])
        except ValueError:
            print(f"Invalid line number: {sys.argv[3]}")
            sys.exit(1)

        with open(c_file, "rb") as f:
            src = f.read()

        try:
            new_src = rewrite_if_to_assert_false_branch(src, if_line)
        except RuntimeError as e:
            print(f"[ERROR] {e}")
            sys.exit(1)

        sys.stdout.write(new_src.decode("utf-8"))
        return

    trace_file = sys.argv[2] if len(sys.argv) >= 3 else None

    with open(c_file, "rb") as f:
        src = f.read()

    tree = parser.parse(src)
    root = tree.root_node

    # 找第一个函数（通常是 main）
    func_nodes = [c for c in root.children if c.type == "function_definition"]
    if not func_nodes:
        print("No function_definition found in the C file.")
        sys.exit(1)

    func = func_nodes[0]

    # ---------- 无 trace：全枚举 ----------
    if trace_file is None:
        all_paths = extract_paths_from_node(func, src)  # List[(lines, term)]

        # 去重（按 code 内容去重）
        unique_paths = []
        seen = set()
        for (lines, term) in all_paths:
            key = tuple(code for (code, _) in lines)
            if key not in seen:
                seen.add(key)
                unique_paths.append((lines, term))

        print("=== Structured Assert Paths (AST-based, return terminates, preproc expanded, no empty loops) ===")
        if not unique_paths:
            print("（没有路径）")
            return

        for i, (lines, term) in enumerate(unique_paths, 1):
            print(f"\n--- Path {i} ---")
            for code, ln in lines:
                if ln is not None:
                    print(f"{code}    // line {ln}")
                else:
                    print(code)
            if term:
                print("/* [terminated by return] */")
        return

    # ---------- 有 trace：构造单条截断路径 ----------
    trace_linenos = load_trace_linenos(trace_file)
    if not trace_linenos:
        print(f"[WARN] Trace file '{trace_file}' 中未解析到任何行号，回退为全枚举输出所有路径。")

        all_paths = extract_paths_from_node(func, src)
        unique_paths = []
        seen = set()
        for (lines, term) in all_paths:
            key = tuple(code for (code, _) in lines)
            if key not in seen:
                seen.add(key)
                unique_paths.append((lines, term))

        for i, (lines, term) in enumerate(unique_paths, 1):
            print(f"\n--- Path {i} ---")
            for code, ln in lines:
                if ln is not None:
                    print(f"{code}    // line {ln}")
                else:
                    print(code)
            if term:
                print("/* [terminated by return] */")
        return

    single_path = extract_single_path_from_function(func, src, trace_linenos)

    print("=== Trace-guided Single Truncated Path (return terminates, preproc supported) ===")
    print(f"Trace 行号集合: {sorted(trace_linenos)}")

    if not single_path:
        print("（该函数内未构造出与 trace 相关的路径）")
        return

    for code, ln in single_path:
        if ln is not None:
            print(f"{code}    // line {ln}")
        else:
            print(code)


if __name__ == "__main__":
    main()
