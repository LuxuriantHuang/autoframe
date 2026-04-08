from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import ujson

from input_adapter import InputAdapterSpec, apply_input_adapter, remap_field_offsets, summarize_input_adapter


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _skip_ws(data: bytes, idx: int) -> int:
    while idx < len(data) and chr(data[idx]).isspace():
        idx += 1
    return idx


def _parse_string(data: bytes, idx: int) -> tuple[str, int, bool]:
    quote = data[idx]
    idx += 1
    start = idx
    escaped = False
    while idx < len(data):
        byte = data[idx]
        if escaped:
            escaped = False
        elif byte == 92:
            escaped = True
        elif byte == quote:
            return _decode(data[start:idx]), idx + 1, True
        idx += 1
    return _decode(data[start:idx]), idx, False


def _parse_literal(data: bytes, idx: int) -> tuple[str, int]:
    start = idx
    while idx < len(data) and chr(data[idx]) not in ",]} \t\r\n":
        idx += 1
    return _decode(data[start:idx]), idx


def fallback_parse_json_bytes(data: bytes) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    stack: list[dict[str, Any]] = []
    idx = 0
    pending_key: str | None = None
    well_formed = True

    def current_path() -> str:
        if not stack:
            return "$"
        return stack[-1]["path"]

    while idx < len(data):
        idx = _skip_ws(data, idx)
        if idx >= len(data):
            break
        byte = data[idx]
        char = chr(byte)

        if char == "{":
            path = stack[-1]["pending_path"] if stack and stack[-1].get("pending_path") else current_path()
            if not stack:
                path = "$"
            stack.append({"type": "object", "path": path, "expect": "key_or_end", "index": 0, "pending_path": None})
            fields.append(
                {
                    "name": path,
                    "kind": "object",
                    "offset": idx,
                    "size": 1,
                    "end": idx + 1,
                    "value": "{",
                    "path": path,
                    "reliable": True,
                }
            )
            idx += 1
            continue

        if char == "[":
            path = stack[-1]["pending_path"] if stack and stack[-1].get("pending_path") else current_path()
            if not stack:
                path = "$"
            stack.append({"type": "array", "path": path, "expect": "value_or_end", "index": 0, "pending_path": None})
            fields.append(
                {
                    "name": path,
                    "kind": "array",
                    "offset": idx,
                    "size": 1,
                    "end": idx + 1,
                    "value": "[",
                    "path": path,
                    "reliable": True,
                }
            )
            idx += 1
            continue

        if char in "}]":
            if stack:
                stack.pop()
            else:
                well_formed = False
            idx += 1
            pending_key = None
            continue

        if char == ",":
            if stack:
                top = stack[-1]
                top["expect"] = "key" if top["type"] == "object" else "value"
                top["pending_path"] = None
            pending_key = None
            idx += 1
            continue

        if char == ":":
            if stack and stack[-1]["type"] == "object":
                stack[-1]["expect"] = "value"
                if pending_key is not None:
                    stack[-1]["pending_path"] = f'{stack[-1]["path"]}.{pending_key}' if stack[-1]["path"] != "$" else f"$.{pending_key}"
            idx += 1
            continue

        if char in ('"', "'"):
            start = idx
            value, idx, closed = _parse_string(data, idx)
            reliable = closed
            top = stack[-1] if stack else None
            if top and top["type"] == "object" and top.get("expect") in {"key", "key_or_end"}:
                pending_key = value
                path = f'{top["path"]}.{value}' if top["path"] != "$" else f"$.{value}"
                kind = "object_key"
                top["expect"] = "colon"
                editable = "name"
            else:
                if top and top["type"] == "array":
                    path = f'{top["path"]}[{top["index"]}]'
                    top["index"] += 1
                elif top and top.get("pending_path"):
                    path = top["pending_path"]
                else:
                    path = current_path()
                kind = "string"
                editable = "value"
            fields.append(
                {
                    "name": path,
                    "kind": kind,
                    "offset": start,
                    "size": idx - start,
                    "end": idx,
                    "value": value,
                    "value_offset": start + 1,
                    "value_end": max(start + 1, idx - 1 if closed else idx),
                    "path": path,
                    "reliable": reliable,
                    "editable": editable,
                }
            )
            if not closed:
                well_formed = False
            if top and kind != "object_key" and top.get("pending_path"):
                top["pending_path"] = None
            continue

        start = idx
        value, idx = _parse_literal(data, idx)
        if not value:
            idx += 1
            well_formed = False
            continue
        top = stack[-1] if stack else None
        if top and top["type"] == "array":
            path = f'{top["path"]}[{top["index"]}]'
            top["index"] += 1
        elif top and top.get("pending_path"):
            path = top["pending_path"]
            top["pending_path"] = None
        else:
            path = current_path()
        kind = "literal"
        if value in {"true", "false"}:
            kind = "boolean"
        elif value == "null":
            kind = "null"
        else:
            try:
                float(value)
                kind = "number"
            except ValueError:
                reliable = False
                well_formed = False
            else:
                reliable = True
        fields.append(
            {
                "name": path,
                "kind": kind,
                "offset": start,
                "size": idx - start,
                "end": idx,
                "value": value,
                "path": path,
                "reliable": locals().get("reliable", True),
                "editable": "value",
            }
        )

    return {
        "format": "json",
        "parser": "fallback_json_tokenizer",
        "well_formed": well_formed,
        "fields": fields,
    }


def _flatten_json(value: Any, path: str, out: list[dict[str, Any]]) -> None:
    if isinstance(value, dict):
        out.append({"path": path, "kind": "object", "value": "{...}", "priority": "container"})
        for key, item in value.items():
            child_path = f"{path}.{key}" if path != "$" else f"$.{key}"
            out.append({"path": child_path, "kind": "object_key", "value": key, "priority": "key"})
            _flatten_json(item, child_path, out)
        return
    if isinstance(value, list):
        out.append({"path": path, "kind": "array", "value": "[...]", "priority": "container"})
        for idx, item in enumerate(value):
            _flatten_json(item, f"{path}[{idx}]", out)
        return
    kind = "null" if value is None else "boolean" if isinstance(value, bool) else "number" if isinstance(value, (int, float)) else "string"
    out.append({"path": path, "kind": kind, "value": str(value), "priority": "value"})


def _enrich_fields_with_json_paths(text: str, fields: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    try:
        parsed = json.loads(text)
    except Exception:
        return fields, False

    enriched_nodes: list[dict[str, Any]] = []
    _flatten_json(parsed, "$", enriched_nodes)
    index: dict[tuple[str, str], list[str]] = {}
    for node in enriched_nodes:
        index.setdefault((node["kind"], node["value"]), []).append(node["path"])

    for field in fields:
        key = (field["kind"], field["value"])
        if key not in index or not index[key]:
            continue
        field["json_path"] = index[key].pop(0)
        field["path"] = field["json_path"]
        if field["kind"] == "object_key":
            field["name"] = field["json_path"]
            field["semantic_role"] = "key"
        elif field["kind"] in {"string", "number", "boolean", "null"}:
            field["semantic_role"] = "value"
        elif field["kind"] in {"object", "array"}:
            field["semantic_role"] = "container"
    return fields, True


def build_json_semantic_fields(
    seed_path: str | Path,
    out_path: str | Path | None = None,
    adapter_spec: InputAdapterSpec | None = None,
) -> dict[str, Any]:
    seed_path = Path(seed_path)
    raw_data = seed_path.read_bytes()
    payload_data = apply_input_adapter(raw_data, adapter_spec)
    text = payload_data.decode("utf-8", errors="replace")
    result = fallback_parse_json_bytes(payload_data)
    result["fields"], result["used_json_recovery"] = _enrich_fields_with_json_paths(text, result["fields"])
    result["fields"] = remap_field_offsets(result["fields"], adapter_spec)
    result["file_path"] = seed_path.name
    if adapter_spec and adapter_spec.active:
        result["input_adapter"] = {
            "payload_offset": adapter_spec.payload_offset,
            "prefix_constraints": adapter_spec.prefix_constraints,
            "delivery": adapter_spec.delivery,
            "payload_kind": adapter_spec.payload_kind,
            "summary": summarize_input_adapter(adapter_spec),
        }
        result["payload_preview"] = text[:200]

    if out_path is not None:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(ujson.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
