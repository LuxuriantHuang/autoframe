from __future__ import annotations

import re
from collections import deque
from pathlib import Path
from typing import Any

import ujson

try:
    from tree_sitter_languages import get_parser
except Exception:  # pragma: no cover - optional dependency
    get_parser = None


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER_RE = re.compile(r"\b(?:0x[0-9A-Fa-f]+|\d+(?:\.\d+)?)\b")


def _line_starts(data: bytes) -> list[int]:
    starts = [0]
    for idx, byte in enumerate(data):
        if byte == 10:
            starts.append(idx + 1)
    return starts


def _point_to_offset(line_starts: list[int], point) -> int:
    row, col = point
    if row >= len(line_starts):
        return line_starts[-1]
    return line_starts[row] + col


def _fallback_lex_code(text: str, language: str) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    idx = 0
    while idx < len(text):
        if text.startswith("//", idx):
            end = text.find("\n", idx)
            end = len(text) if end == -1 else end
            fields.append({"name": f"comment[{idx}]", "kind": "line_comment", "offset": idx, "size": end - idx, "end": end, "value": text[idx:end], "path": f"/comment[{idx}]", "reliable": True})
            idx = end
            continue
        if text.startswith("/*", idx):
            end = text.find("*/", idx + 2)
            reliable = end != -1
            end = len(text) if end == -1 else end + 2
            fields.append({"name": f"comment[{idx}]", "kind": "block_comment", "offset": idx, "size": end - idx, "end": end, "value": text[idx:end], "path": f"/comment[{idx}]", "reliable": reliable})
            idx = end
            continue
        if language == "javascript" and text[idx] == "`":
            end = idx + 1
            escaped = False
            while end < len(text):
                if escaped:
                    escaped = False
                elif text[end] == "\\":
                    escaped = True
                elif text[end] == "`":
                    end += 1
                    break
                end += 1
            fields.append({"name": f"template[{idx}]", "kind": "string_literal", "offset": idx, "size": end - idx, "end": end, "value": text[idx:end], "path": f"/string[{idx}]", "reliable": end <= len(text)})
            idx = end
            continue
        if text[idx] in "\"'":
            quote = text[idx]
            end = idx + 1
            escaped = False
            while end < len(text):
                if escaped:
                    escaped = False
                elif text[end] == "\\":
                    escaped = True
                elif text[end] == quote:
                    end += 1
                    break
                end += 1
            fields.append({"name": f"string[{idx}]", "kind": "string_literal", "offset": idx, "size": end - idx, "end": end, "value": text[idx:end], "path": f"/string[{idx}]", "reliable": end <= len(text)})
            idx = end
            continue
        if text[idx] == "#" and (idx == 0 or text[idx - 1] == "\n"):
            end = text.find("\n", idx)
            end = len(text) if end == -1 else end
            fields.append({"name": f"preproc[{idx}]", "kind": "preprocessor", "offset": idx, "size": end - idx, "end": end, "value": text[idx:end], "path": f"/preprocessor[{idx}]", "reliable": True})
            idx = end
            continue
        ident = _IDENT_RE.match(text, idx)
        if ident:
            start, end = ident.span()
            fields.append({"name": ident.group(0), "kind": "identifier", "offset": start, "size": end - start, "end": end, "value": ident.group(0), "path": f"/identifier[{start}]", "reliable": True})
            idx = end
            continue
        number = _NUMBER_RE.match(text, idx)
        if number:
            start, end = number.span()
            fields.append({"name": number.group(0), "kind": "number_literal", "offset": start, "size": end - start, "end": end, "value": number.group(0), "path": f"/number[{start}]", "reliable": True})
            idx = end
            continue
        idx += 1
    return fields


def _language_node_types(language: str) -> dict[str, str]:
    if language == "c":
        return {
            "function_definition": "function_definition",
            "call_expression": "call_expression",
            "string_literal": "string_literal",
            "preproc_include": "preprocessor",
            "identifier": "identifier",
        }
    return {
        "function_declaration": "function_definition",
        "function": "function_definition",
        "call_expression": "call_expression",
        "string": "string_literal",
        "template_string": "string_literal",
        "identifier": "identifier",
        "member_expression": "member_expression",
        "import_statement": "import_statement",
    }


def _text_for_node(data: bytes, line_starts: list[int], node) -> tuple[int, int, str]:
    start = _point_to_offset(line_starts, node.start_point)
    end = _point_to_offset(line_starts, node.end_point)
    return start, end, data[start:end].decode("utf-8", errors="replace")


def _collect_named_children(node, wanted_type: str):
    return [child for child in node.children if child.type == wanted_type]


def _extract_specialized_fields(node, data: bytes, line_starts: list[int], language: str) -> list[dict[str, Any]]:
    extra: list[dict[str, Any]] = []
    if language == "c" and node.type == "function_definition":
        declarators = _collect_named_children(node, "function_declarator")
        for declarator in declarators:
            identifiers = _collect_named_children(declarator, "identifier")
            if not identifiers:
                continue
            ident = identifiers[0]
            start, end, snippet = _text_for_node(data, line_starts, ident)
            extra.append(
                {
                    "name": snippet,
                    "kind": "function_name",
                    "offset": start,
                    "size": end - start,
                    "end": end,
                    "value": snippet,
                    "path": f"/ast/function_name[{start}]",
                    "node_type": ident.type,
                    "reliable": True,
                }
            )
    elif language == "c" and node.type == "call_expression":
        identifiers = _collect_named_children(node, "identifier")
        if identifiers:
            ident = identifiers[0]
            start, end, snippet = _text_for_node(data, line_starts, ident)
            extra.append(
                {
                    "name": snippet,
                    "kind": "callee",
                    "offset": start,
                    "size": end - start,
                    "end": end,
                    "value": snippet,
                    "path": f"/ast/callee[{start}]",
                    "node_type": ident.type,
                    "reliable": True,
                }
            )
    elif language == "c" and node.type == "preproc_include":
        path_nodes = [child for child in node.children if child.type in {"system_lib_string", "string_literal"}]
        for path_node in path_nodes:
            start, end, snippet = _text_for_node(data, line_starts, path_node)
            extra.append(
                {
                    "name": snippet,
                    "kind": "include_path",
                    "offset": start,
                    "size": end - start,
                    "end": end,
                    "value": snippet,
                    "path": f"/ast/include_path[{start}]",
                    "node_type": path_node.type,
                    "reliable": True,
                }
            )
    elif language == "javascript" and node.type in {"function_declaration", "function"}:
        identifiers = _collect_named_children(node, "identifier")
        if identifiers:
            ident = identifiers[0]
            start, end, snippet = _text_for_node(data, line_starts, ident)
            extra.append(
                {
                    "name": snippet,
                    "kind": "function_name",
                    "offset": start,
                    "size": end - start,
                    "end": end,
                    "value": snippet,
                    "path": f"/ast/function_name[{start}]",
                    "node_type": ident.type,
                    "reliable": True,
                }
            )
    elif language == "javascript" and node.type == "call_expression":
        callee = node.child_by_field_name("function")
        if callee is not None:
            start, end, snippet = _text_for_node(data, line_starts, callee)
            extra.append(
                {
                    "name": snippet,
                    "kind": "callee",
                    "offset": start,
                    "size": end - start,
                    "end": end,
                    "value": snippet,
                    "path": f"/ast/callee[{start}]",
                    "node_type": callee.type,
                    "reliable": True,
                }
            )
    elif language == "javascript" and node.type == "member_expression":
        property_node = node.child_by_field_name("property")
        if property_node is not None:
            start, end, snippet = _text_for_node(data, line_starts, property_node)
            extra.append(
                {
                    "name": snippet,
                    "kind": "property_name",
                    "offset": start,
                    "size": end - start,
                    "end": end,
                    "value": snippet,
                    "path": f"/ast/property_name[{start}]",
                    "node_type": property_node.type,
                    "reliable": True,
                }
            )
    elif language == "javascript" and node.type == "import_statement":
        for child in node.children:
            if child.type in {"string", "string_fragment"}:
                start, end, snippet = _text_for_node(data, line_starts, child)
                extra.append(
                    {
                        "name": snippet,
                        "kind": "import_path",
                        "offset": start,
                        "size": end - start,
                        "end": end,
                        "value": snippet,
                        "path": f"/ast/import_path[{start}]",
                        "node_type": child.type,
                        "reliable": True,
                    }
                )
    return extra


def _collect_tree_sitter_fields(data: bytes, language: str) -> list[dict[str, Any]]:
    if get_parser is None:
        return []
    try:
        parser = get_parser(language)
        tree = parser.parse(data)
    except Exception:
        return []

    line_starts = _line_starts(data)
    fields: list[dict[str, Any]] = []
    type_map = _language_node_types(language)
    seen: set[tuple[str, int, int]] = set()

    def walk(node) -> None:
        mapped_kind = type_map.get(node.type)
        if mapped_kind:
            start = _point_to_offset(line_starts, node.start_point)
            end = _point_to_offset(line_starts, node.end_point)
            snippet = data[start:end].decode("utf-8", errors="replace")
            key = (mapped_kind, start, end)
            if key not in seen:
                seen.add(key)
                fields.append(
                    {
                        "name": f"{node.type}[{start}]",
                        "kind": mapped_kind,
                        "offset": start,
                        "size": end - start,
                        "end": end,
                        "value": snippet,
                        "path": f"/ast/{node.type}[{start}]",
                        "node_type": node.type,
                        "reliable": True,
                    }
                )
        for field in _extract_specialized_fields(node, data, line_starts, language):
            key = (field["kind"], field["offset"], field["end"])
            if key not in seen:
                seen.add(key)
                fields.append(field)
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return fields


def build_code_semantic_fields(
    seed_path: str | Path,
    *,
    language: str,
    out_path: str | Path | None = None,
) -> dict[str, Any]:
    seed_path = Path(seed_path)
    data = seed_path.read_bytes()
    text = data.decode("utf-8", errors="replace")
    fields = _fallback_lex_code(text, language)
    ast_fields = _collect_tree_sitter_fields(data, language)
    fields.extend(ast_fields)
    result = {
        "format": language,
        "parser": "fallback_lexer+tree_sitter",
        "well_formed": True,
        "used_tree_sitter": bool(ast_fields),
        "file_path": seed_path.name,
        "fields": fields,
    }
    if out_path is not None:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(ujson.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
