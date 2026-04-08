from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any


@dataclass
class InputAdapterSpec:
    payload_offset: int = 0
    prefix_constraints: list[dict[str, Any]] = field(default_factory=list)
    delivery: str = "unknown"
    payload_kind: str = "unknown"
    evidence: list[str] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return (
            self.payload_offset > 0
            or bool(self.prefix_constraints)
            or self.delivery != "unknown"
            or self.payload_kind != "unknown"
        )


_PARSE_CALL_RE = re.compile(
    r"\b(?:[A-Za-z_]\w*Parse(?:With\w+)?|yyparse|xmlRead[A-Za-z_]\w*|json_load[sb]?|jq_parse)\s*"
    r"\(\s*(?:\([^)]*\)\s*)?(?P<var>[A-Za-z_]\w*)\s*\+\s*(?P<offset>\d+)",
    re.IGNORECASE,
)
_DIRECT_OFFSET_RE = re.compile(
    r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\([^;]*\);\s*.*?\b[A-Za-z_]\w+\s*\(\s*(?P=var)\s*\+\s*(?P<offset>\d+)",
    re.DOTALL,
)
_PREFIX_CHAR_RE = re.compile(
    r"(?P<var>[A-Za-z_]\w*)\s*\[\s*(?P<index>\d+)\s*\]\s*(?:==|!=)\s*'(?P<char>[^'])'"
)


def infer_input_adapter_from_harness(harness_code: str | None, exec_args: list[str] | None = None) -> InputAdapterSpec:
    spec = InputAdapterSpec()
    if not harness_code:
        return spec

    joined = harness_code
    lowered = joined.lower()

    if "@@" in " ".join(exec_args or []):
        spec.delivery = "file_placeholder"
        spec.evidence.append("seed delivered through @@ placeholder")
    elif re.search(r"\b(getchar|getc|fgetc)\s*\(", joined):
        spec.delivery = "stdin"
        spec.evidence.append("seed consumed from stdin character stream")
    elif "stdin" in lowered:
        spec.delivery = "stdin"
        spec.evidence.append("seed consumed from stdin")
    elif "argv[1]" in joined or "argc" in joined:
        spec.delivery = "argv_file"
        spec.evidence.append("seed delivered through argv/file path")
    elif "LLVMFuzzerTestOneInput" in joined:
        spec.delivery = "in_memory_buffer"
        spec.evidence.append("libFuzzer-style in-memory input")

    if any(token in lowered for token in ("json", "cjson_parse", "json_load", "parse_json")):
        spec.payload_kind = "json_text"
    elif any(token in lowered for token in ("xmlread", "xmlparse", "yyparse", "lexer", "token")):
        spec.payload_kind = "textual_parser_input"

    for matcher in (_PARSE_CALL_RE, _DIRECT_OFFSET_RE):
        match = matcher.search(joined)
        if match:
            spec.payload_offset = int(match.group("offset"))
            spec.evidence.append(
                f"parser consumes payload from {match.group('var')} + {spec.payload_offset}"
            )
            break

    if spec.delivery != "stdin":
        prefix_map: dict[int, set[str]] = {}
        for match in _PREFIX_CHAR_RE.finditer(joined):
            idx = int(match.group("index"))
            if spec.payload_offset and idx >= spec.payload_offset:
                continue
            prefix_map.setdefault(idx, set()).add(match.group("char"))

        for idx in sorted(prefix_map):
            allowed = sorted(prefix_map[idx])
            spec.prefix_constraints.append({"offset": idx, "allowed": allowed})
            spec.evidence.append(f"prefix byte {idx} constrained to {allowed}")

    return spec


def apply_input_adapter(data: bytes, spec: InputAdapterSpec | None) -> bytes:
    if not spec or spec.payload_offset <= 0:
        return data
    if len(data) <= spec.payload_offset:
        return b""
    return data[spec.payload_offset:]


def remap_field_offsets(fields: list[dict[str, Any]], spec: InputAdapterSpec | None) -> list[dict[str, Any]]:
    if not spec or spec.payload_offset <= 0:
        return fields
    shifted: list[dict[str, Any]] = []
    for field in fields:
        item = dict(field)
        for key in ("offset", "end", "value_offset", "value_end"):
            value = item.get(key)
            if isinstance(value, int):
                item[key] = value + spec.payload_offset
        shifted.append(item)
    return shifted


def summarize_input_adapter(spec: InputAdapterSpec | None) -> list[str]:
    if not spec or not spec.active:
        return []

    lines = [f"payload_offset={spec.payload_offset}"]
    if spec.delivery != "unknown":
        lines.append(f"delivery={spec.delivery}")
    if spec.payload_kind != "unknown":
        lines.append(f"payload_kind={spec.payload_kind}")
    if spec.prefix_constraints:
        rendered = ", ".join(
            f"byte[{item['offset']}] in {{{'/'.join(item['allowed'])}}}"
            for item in spec.prefix_constraints
        )
        lines.append(f"prefix_constraints={rendered}")
    return lines


def build_seed_invocation(
    program_path: str,
    exec_args: list[str] | None,
    seed_path: str | Path,
    spec: InputAdapterSpec | None = None,
) -> tuple[list[str], bytes | None]:
    args = list(exec_args or [])
    seed_path_str = str(seed_path)
    cmd = [program_path]

    if "@@" in args:
        cmd.extend(arg.replace("@@", seed_path_str) for arg in args)
        return cmd, None

    if spec and spec.delivery == "stdin":
        cmd.extend(args)
        return cmd, Path(seed_path).read_bytes()

    if spec and spec.delivery == "argv_file" and not args:
        cmd.append(seed_path_str)
        return cmd, None

    cmd.extend(arg.replace("@@", seed_path_str) for arg in args)
    return cmd, None
