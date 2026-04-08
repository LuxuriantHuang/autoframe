from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import ujson

try:
    from lxml import etree
except Exception:  # pragma: no cover - optional dependency
    etree = None


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _is_name_char(byte: int) -> bool:
    return (
        48 <= byte <= 57
        or 65 <= byte <= 90
        or 97 <= byte <= 122
        or byte in b"_:.-"
    )


def _skip_ws(data: bytes, idx: int) -> int:
    while idx < len(data) and data[idx] in b" \t\r\n":
        idx += 1
    return idx


def _read_name(data: bytes, idx: int) -> tuple[str, int]:
    start = idx
    while idx < len(data) and _is_name_char(data[idx]):
        idx += 1
    return _decode(data[start:idx]), idx


def _find_tag_end(data: bytes, idx: int) -> tuple[int, bool]:
    in_quote: int | None = None
    while idx < len(data):
        byte = data[idx]
        if in_quote is not None:
            if byte == in_quote:
                in_quote = None
            idx += 1
            continue
        if byte in (34, 39):
            in_quote = byte
        elif byte == 62:
            return idx + 1, True
        idx += 1
    return len(data), False


def _find_doctype_end(data: bytes, idx: int) -> tuple[int, bool]:
    bracket_depth = 0
    in_quote: int | None = None
    while idx < len(data):
        byte = data[idx]
        if in_quote is not None:
            if byte == in_quote:
                in_quote = None
            idx += 1
            continue
        if byte in (34, 39):
            in_quote = byte
        elif byte == 91:
            bracket_depth += 1
        elif byte == 93 and bracket_depth > 0:
            bracket_depth -= 1
        elif byte == 62 and bracket_depth == 0:
            return idx + 1, True
        idx += 1
    return len(data), False


def _path_for(stack: list[str], name: str) -> str:
    return "/" + "/".join(stack + [name]) if stack or name else "/"


@dataclass(slots=True)
class _XmlToken:
    kind: str
    start: int
    end: int
    name: str = ""
    value: str = ""
    path: str = ""
    reliable: bool = True
    value_start: int | None = None
    value_end: int | None = None


def _parse_attributes(data: bytes, idx: int, end: int, base_path: str) -> list[_XmlToken]:
    attrs: list[_XmlToken] = []
    while idx < end:
        idx = _skip_ws(data, idx)
        if idx >= end or data[idx] in b"/>?":
            break
        name_start = idx
        attr_name, idx = _read_name(data, idx)
        if not attr_name:
            idx += 1
            continue
        idx = _skip_ws(data, idx)
        attr_end = idx
        value = ""
        value_start = None
        value_end = None
        reliable = True
        if idx < end and data[idx] == 61:
            idx += 1
            idx = _skip_ws(data, idx)
            if idx < end and data[idx] in (34, 39):
                quote = data[idx]
                idx += 1
                value_start = idx
                while idx < end and data[idx] != quote:
                    idx += 1
                value_end = idx
                value = _decode(data[value_start:value_end])
                if idx < end and data[idx] == quote:
                    idx += 1
                else:
                    reliable = False
                attr_end = idx
            else:
                value_start = idx
                while idx < end and data[idx] not in b" \t\r\n/>":
                    idx += 1
                value_end = idx
                value = _decode(data[value_start:value_end])
                attr_end = idx
                reliable = False
        attrs.append(
            _XmlToken(
                kind="attribute",
                start=name_start,
                end=attr_end,
                name=attr_name,
                value=value,
                path=f"{base_path}/@{attr_name}",
                reliable=reliable,
                value_start=value_start,
                value_end=value_end,
            )
        )
    return attrs


def _tokens_to_fields(tokens: list[_XmlToken]) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    counters: defaultdict[str, int] = defaultdict(int)
    for token in tokens:
        counters[token.kind] += 1
        fallback_name = token.name or f"{token.kind}_{counters[token.kind]}"
        field = {
            "name": fallback_name,
            "kind": token.kind,
            "offset": token.start,
            "size": max(0, token.end - token.start),
            "end": token.end,
            "value": token.value,
            "path": token.path,
            "reliable": token.reliable,
        }
        if token.kind == "element_name":
            field["name"] = token.path.strip("/").split("/")[-1] or token.name
        elif token.kind == "attribute":
            base = token.path.rsplit("/@", 1)[0].strip("/")
            prefix = base.split("/")[-1] if base else "root"
            field["name"] = f"{prefix}.@{token.name}"
        elif token.kind == "xml_decl_attr":
            field["name"] = f"xml_decl.{token.name}"
        elif token.kind == "doctype":
            field["name"] = "doctype"
        elif token.kind == "text":
            field["name"] = token.path.strip("/") or fallback_name
        if token.value_start is not None:
            field["value_offset"] = token.value_start
        if token.value_end is not None:
            field["value_end"] = token.value_end
        fields.append(field)
    return fields


def fallback_parse_xml_bytes(data: bytes) -> dict[str, Any]:
    tokens: list[_XmlToken] = []
    stack: list[str] = []
    idx = 0
    well_formed = True

    while idx < len(data):
        if data[idx] != 60:
            next_tag = data.find(b"<", idx)
            if next_tag == -1:
                next_tag = len(data)
            if data[idx:next_tag].strip():
                path = "/" + "/".join(stack) + "/text()" if stack else "/text()"
                tokens.append(
                    _XmlToken(
                        kind="text",
                        start=idx,
                        end=next_tag,
                        value=_decode(data[idx:next_tag]),
                        path=path,
                    )
                )
            idx = next_tag
            continue

        if data.startswith(b"<!--", idx):
            end = data.find(b"-->", idx + 4)
            reliable = end != -1
            end = len(data) if end == -1 else end + 3
            tokens.append(
                _XmlToken(
                    kind="comment",
                    start=idx,
                    end=end,
                    value=_decode(data[idx + 4:end - (3 if reliable else 0)]),
                    path="/" + "/".join(stack) + "/comment()" if stack else "/comment()",
                    reliable=reliable,
                )
            )
            well_formed &= reliable
            idx = end
            continue

        if data.startswith(b"<![CDATA[", idx):
            end = data.find(b"]]>", idx + 9)
            reliable = end != -1
            end = len(data) if end == -1 else end + 3
            tokens.append(
                _XmlToken(
                    kind="cdata",
                    start=idx,
                    end=end,
                    value=_decode(data[idx + 9:end - (3 if reliable else 0)]),
                    path="/" + "/".join(stack) + "/cdata()" if stack else "/cdata()",
                    reliable=reliable,
                )
            )
            well_formed &= reliable
            idx = end
            continue

        if data.startswith(b"<!DOCTYPE", idx):
            end, reliable = _find_doctype_end(data, idx + 9)
            tokens.append(
                _XmlToken(
                    kind="doctype",
                    start=idx,
                    end=end,
                    name="doctype",
                    value=_decode(data[idx:end]),
                    path="/!DOCTYPE",
                    reliable=reliable,
                )
            )
            well_formed &= reliable
            idx = end
            continue

        if data.startswith(b"<?", idx):
            end = data.find(b"?>", idx + 2)
            reliable = end != -1
            end = len(data) if end == -1 else end + 2
            inner = data[idx + 2:end - (2 if reliable else 0)]
            inner_idx = _skip_ws(inner, 0)
            target, inner_idx = _read_name(inner, inner_idx)
            path = f"/{target or 'pi'}"
            tokens.append(
                _XmlToken(
                    kind="xml_decl" if target == "xml" else "pi",
                    start=idx,
                    end=end,
                    name=target,
                    path=path,
                    reliable=reliable,
                )
            )
            if target == "xml":
                for attr in _parse_attributes(inner, inner_idx, len(inner), path):
                    attr.kind = "xml_decl_attr"
                    attr.start += idx + 2
                    attr.end += idx + 2
                    if attr.value_start is not None:
                        attr.value_start += idx + 2
                    if attr.value_end is not None:
                        attr.value_end += idx + 2
                    tokens.append(attr)
            well_formed &= reliable
            idx = end
            continue

        if data.startswith(b"</", idx):
            end, reliable = _find_tag_end(data, idx + 2)
            name_idx = _skip_ws(data, idx + 2)
            tag_name, _ = _read_name(data, name_idx)
            if tag_name:
                for pos in range(len(stack) - 1, -1, -1):
                    if stack[pos] == tag_name:
                        del stack[pos:]
                        break
            else:
                reliable = False
            well_formed &= reliable
            idx = end
            continue

        end, reliable = _find_tag_end(data, idx + 1)
        cursor = _skip_ws(data, idx + 1)
        tag_name, cursor = _read_name(data, cursor)
        if not tag_name:
            idx = end
            well_formed = False
            continue
        path = _path_for(stack, tag_name)
        tokens.append(
            _XmlToken(
                kind="element_name",
                start=idx + 1,
                end=idx + 1 + len(tag_name),
                name=tag_name,
                value=tag_name,
                path=path,
                reliable=reliable,
                value_start=idx + 1,
                value_end=idx + 1 + len(tag_name),
            )
        )
        tokens.extend(_parse_attributes(data, cursor, end - 1, path))
        probe = end - 2
        while probe > idx and data[probe] in b" \t\r\n":
            probe -= 1
        self_closing = probe > idx and data[probe] == 47
        if not self_closing:
            stack.append(tag_name)
        idx = end
        well_formed &= reliable

    return {
        "format": "xml",
        "parser": "fallback_tokenizer",
        "well_formed": well_formed,
        "fields": _tokens_to_fields(tokens),
    }


def _build_lxml_path_index(root) -> dict[tuple[str, str], deque[str]]:
    mapping: dict[tuple[str, str], deque[str]] = defaultdict(deque)
    tree = root.getroottree()
    for element in root.iter():
        if not isinstance(element.tag, str):
            continue
        path = tree.getpath(element)
        local_name = etree.QName(element.tag).localname
        mapping[("element_name", local_name)].append(path)
        for attr_name in element.attrib:
            local_attr = etree.QName(attr_name).localname if attr_name.startswith("{") else attr_name
            mapping[("attribute", local_attr)].append(f"{path}/@{local_attr}")
    return mapping


def _enrich_fields_with_lxml(data: bytes, fields: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    if etree is None:
        return fields, False
    try:
        parser = etree.XMLParser(recover=True, resolve_entities=False, huge_tree=True)
        root = etree.fromstring(data, parser=parser)
        if root is None:
            return fields, False
    except Exception:
        return fields, False

    path_index = _build_lxml_path_index(root)
    for field in fields:
        key_name = ""
        if field["kind"] == "element_name":
            key_name = field["name"].split("/")[-1]
        elif field["kind"] == "attribute":
            key_name = field["name"].split(".@", 1)[-1]
        if not key_name:
            continue
        candidates = path_index.get((field["kind"], key_name))
        if not candidates:
            continue
        lxml_path = candidates.popleft()
        field["lxml_path"] = lxml_path
        field["path"] = lxml_path
    return fields, True


def build_xml_semantic_fields(seed_path: str | Path, out_path: str | Path | None = None) -> dict[str, Any]:
    seed_path = Path(seed_path)
    with open(seed_path, "rb") as handle:
        data = handle.read()

    result = fallback_parse_xml_bytes(data)
    result["fields"], result["used_lxml_recovery"] = _enrich_fields_with_lxml(data, result["fields"])
    result["file_path"] = seed_path.name

    if out_path is not None:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as handle:
            ujson.dump(result, handle, ensure_ascii=False, indent=2)

    return result
