from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import ujson


_QUOTED_RE = re.compile(r'"([^"\\]|\\.)*"|\'([^\'\\]|\\.)*\'')
_NUMBER_RE = re.compile(r"\b(?:0x[0-9A-Fa-f]+|\d+(?:\.\d+)?)\b")
_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_KEY_VALUE_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*([^\s#;]+)")


def build_generic_text_semantic_fields(seed_path: str | Path, out_path: str | Path | None = None) -> dict[str, Any]:
    seed_path = Path(seed_path)
    data = seed_path.read_bytes()
    text = data.decode("utf-8", errors="replace")
    fields: list[dict[str, Any]] = []
    line_start = 0

    for line_no, line in enumerate(text.splitlines(keepends=True), start=1):
        line_end = line_start + len(line)
        stripped = line.strip()
        if stripped:
            fields.append(
                {
                    "name": f"line[{line_no}]",
                    "kind": "line",
                    "offset": line_start,
                    "size": len(line),
                    "end": line_end,
                    "value": line.rstrip("\r\n"),
                    "path": f"/line[{line_no}]",
                    "reliable": True,
                }
            )

        for match in _KEY_VALUE_RE.finditer(line):
            key_start, key_end = match.span(1)
            value_start, value_end = match.span(2)
            fields.append(
                {
                    "name": f"line[{line_no}].{match.group(1)}",
                    "kind": "key_value",
                    "offset": line_start + key_start,
                    "size": value_end - key_start,
                    "end": line_start + value_end,
                    "value": match.group(2),
                    "value_offset": line_start + value_start,
                    "value_end": line_start + value_end,
                    "path": f"/line[{line_no}]/{match.group(1)}",
                    "reliable": True,
                }
            )

        for regex, kind in ((_QUOTED_RE, "quoted_string"), (_NUMBER_RE, "number"), (_IDENT_RE, "token")):
            for idx, match in enumerate(regex.finditer(line), start=1):
                start, end = match.span()
                fields.append(
                    {
                        "name": f"line[{line_no}].{kind}[{idx}]",
                        "kind": kind,
                        "offset": line_start + start,
                        "size": end - start,
                        "end": line_start + end,
                        "value": match.group(0),
                        "path": f"/line[{line_no}]/{kind}[{idx}]",
                        "reliable": True,
                    }
                )

        line_start = line_end

    result = {
        "format": "generic_text",
        "parser": "line_tokenizer",
        "well_formed": True,
        "file_path": seed_path.name,
        "fields": fields,
    }
    if out_path is not None:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(ujson.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
