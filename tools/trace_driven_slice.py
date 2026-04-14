#!/usr/bin/env python3
import argparse
import json
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if REPO_ROOT.as_posix() not in sys.path:
    sys.path.insert(0, REPO_ROOT.as_posix())

from pyTracer.SeedTracer import SeedTracer
from tree_sitter_languages import get_language, get_parser


PARSER = get_parser("c")
C_LANGUAGE = get_language("c")


def _same_source_file(lhs: str, rhs: str) -> bool:
    if not lhs or not rhs:
        return False
    return lhs == rhs or Path(lhs).name == Path(rhs).name


@dataclass
class TraceDrivenSummary:
    seed_name: str
    target_file: str
    target_line: int
    target_hit: bool = False
    trace_complete: bool = True
    call_path: list[str] = field(default_factory=list)
    function_locations: dict[str, dict[str, list[int]]] = field(default_factory=dict)


class TraceDrivenSummaryBuilder:
    def __init__(self, seed_name: str, target_file: str, target_line: int, window: int = 20, max_events: int = 50000):
        self.seed_name = seed_name
        self.target_file = target_file
        self.target_line = int(target_line)
        self.window = max(1, int(window))
        self.max_events = max(1, int(max_events))

        self._events = 0
        self._stack: list[str] = []
        self._target_hit = False
        self._trace_complete = True
        self._recent_locations: deque[tuple[str, int, Optional[str]]] = deque(maxlen=self.window * 16)
        self._post_target_events_remaining = 0
        self._relevant_functions: set[str] = set()
        self._call_path: list[str] = []
        self._function_locations: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
        self._last_location_by_func: dict[str, tuple[str, int]] = {}

    def _record_function_location(self, func_name: Optional[str], file_name: str, line_no: int) -> None:
        if not func_name or not file_name or line_no <= 0:
            return
        self._function_locations[func_name][file_name].add(line_no)

    def _record_location(self, file_name: str, line_no: int, func_name: Optional[str]) -> None:
        if not file_name or line_no <= 0:
            return
        self._recent_locations.append((file_name, line_no, func_name))
        if func_name:
            self._last_location_by_func[func_name] = (file_name, line_no)
        if self._target_hit and func_name in self._relevant_functions:
            self._record_function_location(func_name, file_name, line_no)

    def _record_target_hit(self) -> None:
        if self._target_hit:
            return
        self._target_hit = True
        self._call_path = list(self._stack)
        self._relevant_functions.update(self._call_path)
        self._post_target_events_remaining = self.window
        for file_name, line_no, func_name in self._recent_locations:
            if func_name in self._relevant_functions:
                self._record_function_location(func_name, file_name, line_no)

    def consume_event(self, event: dict) -> bool:
        self._events += 1
        if self._events > self.max_events:
            self._trace_complete = False
            return False

        event_type = event.get("event")
        if event_type == "F":
            func_name = event.get("name") or ""
            if self._stack:
                caller = self._stack[-1]
                caller_loc = self._last_location_by_func.get(caller)
                if caller_loc is not None:
                    self._record_location(caller_loc[0], caller_loc[1], caller)
            self._stack.append(func_name)
            return True

        if event_type == "R":
            func_name = event.get("name") or ""
            while self._stack:
                popped = self._stack.pop()
                if popped == func_name:
                    break
            return not (self._target_hit and self._post_target_events_remaining <= 0)

        if event_type != "B":
            return True

        file_name = event.get("name") or ""
        begin = int(event.get("begin", 0) or 0)
        end = int(event.get("end", 0) or 0)
        current_func = self._stack[-1] if self._stack else None
        for line_no in range(begin, end + 1):
            self._record_location(file_name, line_no, current_func)

        if _same_source_file(file_name, self.target_file) and begin <= self.target_line <= end:
            self._record_target_hit()

        if self._target_hit:
            self._post_target_events_remaining -= 1
            if self._post_target_events_remaining <= 0:
                return False
        return True

    def build(self, trace_complete: bool = True) -> TraceDrivenSummary:
        return TraceDrivenSummary(
            seed_name=self.seed_name,
            target_file=self.target_file,
            target_line=self.target_line,
            target_hit=self._target_hit,
            trace_complete=bool(trace_complete and self._trace_complete),
            call_path=list(self._call_path),
            function_locations={
                func_name: {file_name: sorted(lines) for file_name, lines in file_map.items()}
                for func_name, file_map in self._function_locations.items()
            },
        )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a trace-driven multi-function source slice from the tracer stream.")
    parser.add_argument("--trace-bin", required=True, help="Path to the *_trace binary")
    parser.add_argument("--trace-args", required=True, help="Trace binary args, use @@ as seed placeholder")
    parser.add_argument("--seed", required=True, help="Seed path")
    parser.add_argument("--static-json", required=False, default="", help="Optional legacy static/static.json path")
    parser.add_argument("--source-root", required=True, help="Project source root")
    parser.add_argument("--target-loc", required=True, help="Target location like parser.c:10513")
    parser.add_argument("--window", type=int, default=20, help="Post-target trace window size")
    parser.add_argument("--radius", type=int, default=1, help="Source context radius around dynamic lines")
    parser.add_argument("--max-events", type=int, default=50000, help="Stop trace after this many events")
    parser.add_argument("--branch-cover", choices=["auto", "true", "false"], default="auto",
                        help="Render target branch like AutoBug: true => assert(!(cond)), false => assert(cond)")
    parser.add_argument("--out", required=True, help="Output file for the rendered slice")
    return parser.parse_args()


def _load_static_index(static_json: Path) -> dict[str, dict]:
    payload = json.loads(static_json.read_text(encoding="utf-8"))
    index: dict[str, dict] = {}
    for item in payload.get("functions", []):
        name = item.get("name")
        if not name or name in index:
            continue
        index[name] = item
    return index


def _get_text(source_bytes: bytes, node) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _find_identifier(node, source_bytes: bytes) -> Optional[str]:
    if node is None:
        return None
    if node.type == "identifier":
        return _get_text(source_bytes, node)
    for child in getattr(node, "children", []) or []:
        found = _find_identifier(child, source_bytes)
        if found:
            return found
    return None


def _iter_function_definitions(root):
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            yield node
        children = list(getattr(node, "children", []) or [])
        stack.extend(reversed(children))


def _function_metadata_by_name(source_file: Path, function_name: str) -> Optional[dict]:
    try:
        source_bytes = source_file.read_bytes()
    except OSError:
        return None
    tree = PARSER.parse(source_bytes)
    for node in _iter_function_definitions(tree.root_node):
        declarator = node.child_by_field_name("declarator")
        identifier = _find_identifier(declarator, source_bytes)
        if identifier != function_name:
            continue
        return {
            "name": function_name,
            "file_name": source_file.as_posix(),
            "lineStart": int(node.start_point[0]) + 1,
            "lineEnd": int(node.end_point[0]) + 1,
        }
    return None


def _find_enclosing_function_metadata(source_file: Path, line_no: int) -> Optional[dict]:
    try:
        source_bytes = source_file.read_bytes()
    except OSError:
        return None
    tree = PARSER.parse(source_bytes)
    target_row = max(0, int(line_no) - 1)
    best_node = None
    for node in _iter_function_definitions(tree.root_node):
        if node.start_point[0] <= target_row <= node.end_point[0]:
            if best_node is None or (
                node.start_point[0] >= best_node.start_point[0]
                and node.end_point[0] <= best_node.end_point[0]
            ):
                best_node = node
    if best_node is None:
        return None
    declarator = best_node.child_by_field_name("declarator")
    identifier = _find_identifier(declarator, source_bytes) or source_file.stem
    return {
        "name": identifier,
        "file_name": source_file.as_posix(),
        "lineStart": int(best_node.start_point[0]) + 1,
        "lineEnd": int(best_node.end_point[0]) + 1,
    }


def _build_function_index(summary: TraceDrivenSummary, source_root: Path) -> dict[str, dict]:
    index: dict[str, dict] = {}
    target_source = _find_source_file(source_root, summary.target_file)
    target_meta = _find_enclosing_function_metadata(target_source, summary.target_line) if target_source else None
    if target_meta:
        index[str(target_meta["name"])] = target_meta

    for func_name in summary.call_path:
        if func_name in index:
            continue
        file_candidates = list((summary.function_locations.get(func_name) or {}).keys())
        for file_name in file_candidates:
            source_file = _find_source_file(source_root, file_name)
            if source_file is None:
                continue
            meta = _function_metadata_by_name(source_file, func_name)
            if meta:
                index[func_name] = meta
                break
        if func_name in index:
            continue
        if target_meta and str(target_meta.get("name")) == func_name:
            index[func_name] = target_meta
    return index


def _find_source_file(source_root: Path, relative_name: str) -> Optional[Path]:
    candidates = [
        source_root / relative_name,
        source_root / "src" / relative_name,
        source_root / "src_bear" / relative_name,
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _render_function_excerpt(
    source_lines: list[str],
    start_line: int,
    end_line: int,
    interesting_lines: set[int],
    *,
    radius: int,
    elide_ranges: Optional[list[tuple[int, int]]] = None,
) -> str:
    start = max(1, int(start_line))
    end = min(len(source_lines), int(end_line))
    if start > end:
        return ""

    keep: set[int] = set()
    elide_ranges = elide_ranges or []
    signature_end = min(end, start + 2)
    for line_no in range(start, signature_end + 1):
        keep.add(line_no)
    for line_no in interesting_lines:
        if line_no < start or line_no > end:
            continue
        lo = max(start, line_no - radius)
        hi = min(end, line_no + radius)
        for current in range(lo, hi + 1):
            keep.add(current)
    if not keep:
        return ""

    rendered: list[str] = []
    skipped = False
    elided = False
    for line_no in range(start, end + 1):
        in_elide = any(lo <= line_no <= hi for lo, hi in elide_ranges)
        if in_elide:
            if not elided:
                rendered.append("    /* ... branch body elided ... */")
                elided = True
            skipped = False
            continue
        elided = False
        if line_no in keep:
            if skipped:
                rendered.append("    /* ... */")
                skipped = False
            rendered.append(source_lines[line_no - 1].rstrip("\n"))
        else:
            skipped = True
    return "\n".join(rendered).rstrip() + "\n"


def _extract_condition_from_if(source_lines: list[str], line_no: int) -> Optional[str]:
    text = source_lines[line_no - 1].strip()
    if not text.startswith("if"):
        return None
    joined = []
    balance = 0
    seen_open = False
    for idx in range(line_no - 1, min(len(source_lines), line_no + 6)):
        line = source_lines[idx].strip()
        joined.append(line)
        for ch in line:
            if ch == "(":
                balance += 1
                seen_open = True
            elif ch == ")":
                balance -= 1
                if seen_open and balance == 0:
                    break
        if seen_open and balance == 0:
            break
    joined_text = " ".join(joined)
    start = joined_text.find("(")
    if start < 0:
        return None
    balance = 0
    end = -1
    for idx in range(start, len(joined_text)):
        ch = joined_text[idx]
        if ch == "(":
            balance += 1
        elif ch == ")":
            balance -= 1
            if balance == 0:
                end = idx
                break
    if end < 0:
        return None
    return joined_text[start + 1:end].strip() or None


def _extract_switch_expr(source_lines: list[str], start_line: int, end_line: int, target_line: int) -> Optional[str]:
    for idx in range(target_line - 1, start_line - 2, -1):
        text = source_lines[idx].strip()
        if "switch" not in text:
            continue
        begin = text.find("(")
        end = text.rfind(")")
        if begin >= 0 and end > begin:
            return text[begin + 1:end].strip() or None
    return None


def _find_if_body_range(source_lines: list[str], target_line: int, end_line: int) -> Optional[tuple[int, int]]:
    idx = target_line - 1
    if idx < 0 or idx >= len(source_lines):
        return None
    line = source_lines[idx]
    if "if" not in line:
        return None

    cond_closed = False
    balance = 0
    body_line = None
    for cur in range(idx, min(len(source_lines), idx + 8)):
        text = source_lines[cur]
        for ch in text:
            if ch == "(":
                balance += 1
            elif ch == ")":
                balance -= 1
                if balance <= 0:
                    cond_closed = True
        if cond_closed:
            tail = text[text.rfind(")") + 1:] if ")" in text else text
            if "{" in tail:
                body_line = cur + 1
                break
            if cur + 1 < len(source_lines):
                probe = cur + 1
                while probe < len(source_lines):
                    stripped = source_lines[probe].strip()
                    if not stripped:
                        probe += 1
                        continue
                    body_line = probe + 1
                    break
                break
    if body_line is None or body_line > end_line:
        return None

    stripped = source_lines[body_line - 1].strip()
    if stripped.startswith("{") or "{" in stripped:
        if body_line == target_line and "{" in line:
            body_line = min(end_line, body_line + 1)
        brace_depth = 0
        seen_open = False
        for cur in range(body_line - 1, min(len(source_lines), end_line)):
            text = source_lines[cur]
            for ch in text:
                if ch == "{":
                    brace_depth += 1
                    seen_open = True
                elif ch == "}":
                    brace_depth -= 1
                    if seen_open and brace_depth == 0:
                        return (body_line, cur + 1)
        return (body_line, min(end_line, body_line + 6))

    return (body_line, body_line)


def _find_case_body_range(source_lines: list[str], target_line: int, end_line: int) -> Optional[tuple[int, int]]:
    start = target_line + 1
    if start > end_line:
        return None
    for cur in range(start, min(len(source_lines), end_line + 1)):
        stripped = source_lines[cur - 1].strip()
        if stripped.startswith("case ") or stripped.startswith("default:") or stripped.startswith("}"):
            return (start, cur - 1) if cur - 1 >= start else None
    return (start, end_line) if start <= end_line else None


def _build_target_replacement(
    source_lines: list[str],
    start_line: int,
    end_line: int,
    target_file: str,
    target_line: int,
    branch_cover: str,
) -> tuple[Optional[list[str]], Optional[str], Optional[tuple[int, int]]]:
    if target_line < start_line or target_line > end_line:
        return None, None, None
    raw = source_lines[target_line - 1].rstrip("\n")
    stripped = raw.strip()
    negate = (branch_cover == "true")
    if branch_cover in {"true", "false"}:
        if stripped.startswith("if"):
            cond = _extract_condition_from_if(source_lines, target_line)
            if cond:
                expr = f"!({cond})" if negate else cond
                return [f"    assert({expr});    /* BRANCH LOCATION */"], "branch", _find_if_body_range(source_lines, target_line, end_line)
        if stripped.startswith("case "):
            case_value = stripped[len("case "):].split(":", 1)[0].strip()
            switch_expr = _extract_switch_expr(source_lines, start_line, end_line, target_line)
            if case_value and switch_expr:
                expr = f"{switch_expr} == {case_value}"
                return [f"    assert({expr});    /* BRANCH LOCATION */"], "switch-case", _find_case_body_range(source_lines, target_line, end_line)
    return [f"    /* TRACE LOCATION: {Path(target_file).name}:{target_line} */", raw], "trace", None


def _collect_file_includes(source_file: Path) -> list[str]:
    includes: list[str] = []
    try:
        lines = source_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return includes
    for line in lines[:200]:
        stripped = line.strip()
        if stripped.startswith("#include"):
            includes.append(stripped)
    return includes


def _render_trace_driven_slice(summary: TraceDrivenSummary, function_index: dict[str, dict], source_root: Path, radius: int, branch_cover: str) -> str:
    header = [
        "/* TRACE-DRIVEN MULTI-FUNCTION SLICE */",
        f"/* seed: {summary.seed_name} */",
        f"/* target: {summary.target_file}:{summary.target_line} */",
        f"/* target_hit: {int(summary.target_hit)} trace_complete: {int(summary.trace_complete)} */",
        f"/* call_path: {' -> '.join(summary.call_path) if summary.call_path else '(empty)'} */",
        "",
    ]
    chunks = ["\n".join(header)]
    include_pool: list[str] = []
    include_seen: set[str] = set()
    focus_include_files: list[Path] = []
    target_focus_files: set[str] = set()

    for func_name in summary.call_path[-2:]:
        meta = function_index.get(func_name)
        if not meta:
            continue
        file_name = meta.get("file_name") or ""
        if not file_name or file_name in target_focus_files:
            continue
        source_file = _find_source_file(source_root, file_name)
        if source_file is None:
            continue
        target_focus_files.add(file_name)
        focus_include_files.append(source_file)

    for index, func_name in enumerate(summary.call_path, start=1):
        meta = function_index.get(func_name)
        if not meta:
            continue
        file_name = meta.get("file_name") or ""
        if not file_name:
            continue
        source_file = _find_source_file(source_root, file_name)
        if source_file is None:
            continue
        try:
            source_lines = source_file.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
        except OSError:
            continue
        elide_ranges: list[tuple[int, int]] = []

        interesting_lines = set()
        callsite_line: Optional[int] = None
        for dynamic_file, lines in (summary.function_locations.get(func_name) or {}).items():
            if _same_source_file(dynamic_file, file_name):
                interesting_lines.update(int(line) for line in lines)
        next_func = summary.call_path[index] if index < len(summary.call_path) else None
        if next_func:
            start = int(meta.get("lineStart", 1) or 1)
            end = int(meta.get("lineEnd", 1) or 1)
            needle = f"{next_func}("
            for line_no in range(max(1, start), min(len(source_lines), end) + 1):
                if needle in source_lines[line_no - 1]:
                    interesting_lines.add(line_no)
                    interesting_lines.add(min(end, line_no + 1))
                    callsite_line = line_no
                    break
        if _same_source_file(file_name, summary.target_file) and meta.get("lineStart", 0) <= summary.target_line <= meta.get("lineEnd", 0):
            interesting_lines.add(summary.target_line)
            replacement, _, elide_range = _build_target_replacement(
                source_lines,
                int(meta.get("lineStart", 1) or 1),
                int(meta.get("lineEnd", 1) or 1),
                summary.target_file,
                summary.target_line,
                branch_cover,
            )
            if replacement:
                source_lines = list(source_lines)
                source_lines[summary.target_line - 1] = replacement[0] + "\n"
                for extra_idx, extra_line in enumerate(replacement[1:], start=1):
                    insert_pos = min(len(source_lines), summary.target_line - 1 + extra_idx)
                    source_lines.insert(insert_pos, extra_line + "\n")
                    interesting_lines.add(summary.target_line + extra_idx)
                if elide_range:
                    delta = len(replacement) - 1
                    elide_ranges.append((elide_range[0] + delta, elide_range[1] + delta))
                    func_end = int(meta.get("lineEnd", 1) or 1)
                    tail_start = elide_range[1] + delta + 1
                    if tail_start <= func_end:
                        elide_ranges.append((tail_start, func_end))
        elif callsite_line is not None:
            func_end = int(meta.get("lineEnd", 1) or 1)
            if callsite_line + 1 <= func_end:
                elide_ranges.append((callsite_line + 1, func_end))

        excerpt = _render_function_excerpt(
            source_lines,
            int(meta.get("lineStart", 1) or 1),
            int(meta.get("lineEnd", 1) or 1),
            interesting_lines,
            radius=radius,
            elide_ranges=elide_ranges,
        )
        if not excerpt.strip():
            continue
        chunks.append(
            "\n".join(
                [
                    f"/* TRACE PATH STEP {index}/{len(summary.call_path)} */",
                    f"/* function: {func_name} */",
                    f"/* file: {file_name}:{meta.get('lineStart', 0)}-{meta.get('lineEnd', 0)} */",
                    excerpt.rstrip(),
                    "",
                ]
            )
        )

    for source_file in focus_include_files:
        for inc in _collect_file_includes(source_file):
            if inc in include_seen:
                continue
            # Keep only small, model-useful context: local headers and libxml public/private headers.
            if not (
                inc.startswith('#include "')
                or "<libxml/" in inc
                or '"private/' in inc
            ):
                continue
            include_seen.add(inc)
            include_pool.append(inc)
            if len(include_pool) >= 12:
                break
        if len(include_pool) >= 12:
            break

    if include_pool:
        include_block = ["/* CONTEXT: relevant includes */", *include_pool, ""]
        chunks.insert(1, "\n".join(include_block))

    return "\n".join(chunks).rstrip() + "\n"


def build_trace_driven_slice(
    *,
    trace_bin: str,
    trace_args: str,
    seed_path: str,
    static_json: str,
    source_root: str,
    target_file: str,
    target_line: int,
    window: int = 20,
    radius: int = 1,
    max_events: int = 50000,
    branch_cover: str = "auto",
) -> tuple[TraceDrivenSummary, str]:
    tracer = SeedTracer(trace_bin, trace_args)
    builder = TraceDrivenSummaryBuilder(
        seed_name=Path(seed_path).name,
        target_file=target_file,
        target_line=target_line,
        window=window,
        max_events=max_events,
    )

    def handle_line(line: str) -> bool:
        event = tracer.parse_trace_line(line)
        if event is None:
            return True
        return builder.consume_event(event)

    retcode, stopped_early = tracer.trace_seed_stream(seed_path, 30.0, handle_line)
    summary = builder.build(trace_complete=(retcode == 0 or stopped_early))
    function_index: dict[str, dict] = {}
    if static_json:
        static_path = Path(static_json)
        if static_path.exists():
            function_index.update(_load_static_index(static_path))
    if not function_index:
        function_index.update(_build_function_index(summary, Path(source_root)))
    rendered = _render_trace_driven_slice(summary, function_index, Path(source_root), radius, branch_cover)
    return summary, rendered


def main() -> int:
    args = _parse_args()
    target_file, target_line_text = args.target_loc.rsplit(":", 1)
    target_line = int(target_line_text)
    summary, rendered = build_trace_driven_slice(
        trace_bin=args.trace_bin,
        trace_args=args.trace_args,
        seed_path=args.seed,
        static_json=args.static_json,
        source_root=args.source_root,
        target_file=target_file,
        target_line=target_line,
        window=args.window,
        radius=args.radius,
        max_events=args.max_events,
        branch_cover=args.branch_cover,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")

    print(json.dumps({
        "target_hit": summary.target_hit,
        "trace_complete": summary.trace_complete,
        "call_path_len": len(summary.call_path),
        "call_path": summary.call_path,
        "function_count_with_locations": len(summary.function_locations),
        "out": out_path.as_posix(),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
