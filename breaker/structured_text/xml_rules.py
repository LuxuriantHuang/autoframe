from __future__ import annotations

import re

from breaker.models import MutationCandidate


_START_TAG_RE = re.compile(r"<([A-Za-z_][\w:.-]*)(?:\s[^>]*)?>")
_ENTITY_REF_RE = re.compile(r"&([A-Za-z_][\w.-]*)(?!;)")
_CHARREF_RE = re.compile(r"&#(x?[0-9A-Fa-f]*)(?!;)")
_NS_PREFIX_RE = re.compile(r"<(?P<prefix>[A-Za-z_][\w.-]*):(?P<name>[A-Za-z_][\w.-]*)")
_TAG_TOKEN_RE = re.compile(r"</?([A-Za-z_][\w:.-]*)[^>]*?>")


def build_xml_rule_candidates(seed_text: str, *, action: str, diagnostics_family: str) -> list[MutationCandidate]:
    builders = {
        "end_tag_mismatch": _fix_end_tag_mismatch,
        "attribute_quote_break": _fix_attribute_quote_break,
        "entity_corruption": _fix_entity_corruption,
        "charref_corruption": _fix_charref_corruption,
        "namespace_rebinding": _fix_namespace_rebinding,
        "doctype_truncation": _fix_doctype_truncation,
        "comment_cdata_truncation": _fix_comment_cdata_truncation,
        "extra_content_wrap": _wrap_extra_content,
        "general_xml_repair": _general_xml_repair,
    }
    builder = builders.get(action, _general_xml_repair)
    return [
        MutationCandidate(text=text, action=action, rationale=reason, diagnostics_family=diagnostics_family)
        for text, reason in builder(seed_text)
    ]


def _fix_end_tag_mismatch(text: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    stack: list[str] = []
    for match in _TAG_TOKEN_RE.finditer(text):
        token = match.group(0)
        tag_name = match.group(1)
        if token.startswith("</"):
            if stack and stack[-1] != tag_name:
                fixed = text[: match.start()] + f"</{stack[-1]}>" + text[match.end():]
                candidates.append((fixed, "rewrite mismatched closing tag to match nearest unmatched opener"))
                break
            if stack:
                stack.pop()
            continue
        if token.endswith("/>") or token.startswith("<?") or token.startswith("<!"):
            continue
        stack.append(tag_name)

    starts = [m.group(1) for m in _START_TAG_RE.finditer(text) if not text[m.start():].startswith("<?") and not text[m.start():].startswith("<!")]
    if starts and not text.rstrip().endswith(f"</{starts[0]}>"):
        candidates.append((text.rstrip() + f"</{starts[0]}>", "append a closing tag for the first root element"))
    return candidates or _general_xml_repair(text)


def _fix_attribute_quote_break(text: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    attr_match = re.search(r"(\s+[A-Za-z_:][\w:.-]*=)([^\"'\s>][^\s>]*)", text)
    if attr_match:
        fixed = text[: attr_match.start(2)] + f"\"{attr_match.group(2).rstrip('>')}\"" + text[attr_match.end(2):]
        candidates.append((fixed, "wrap bare attribute value with double quotes"))
    if text.count('"') % 2 == 1:
        candidates.append((text + "\"", "rebalance dangling double quote"))
    if text.count("'") % 2 == 1:
        candidates.append((text + "'", "rebalance dangling single quote"))
    return candidates or _general_xml_repair(text)


def _fix_entity_corruption(text: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    if "&bogus;" in text:
        candidates.append((text.replace("&bogus;", "&amp;", 1), "replace unknown entity with built-in &amp;"))
    if _ENTITY_REF_RE.search(text):
        candidates.append((_ENTITY_REF_RE.sub(r"&\1;", text, count=1), "restore missing semicolon on entity reference"))
    if "&" in text and "&amp;" not in text:
        candidates.append((text.replace("&", "&amp;", 1), "escape first raw ampersand"))
    return candidates or _general_xml_repair(text)


def _fix_charref_corruption(text: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    if _CHARREF_RE.search(text):
        candidates.append((_CHARREF_RE.sub(r"&#\1;", text, count=1), "restore numeric character reference terminator"))
    if "&#x;" in text:
        candidates.append((text.replace("&#x;", "&#x41;", 1), "replace empty hex charref with valid code point"))
    if "&#;" in text:
        candidates.append((text.replace("&#;", "&#65;", 1), "replace empty decimal charref with valid code point"))
    return candidates or _general_xml_repair(text)


def _fix_namespace_rebinding(text: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    ns_match = _NS_PREFIX_RE.search(text)
    if ns_match:
        prefix = ns_match.group("prefix")
        root_match = _START_TAG_RE.search(text)
        if root_match and f"xmlns:{prefix}=" not in root_match.group(0):
            injected = root_match.group(0)[:-1] + f' xmlns:{prefix}="urn:{prefix}">' 
            fixed = text[: root_match.start()] + injected + text[root_match.end():]
            candidates.append((fixed, "bind missing namespace prefix on root element"))
    if 'xmlns:xml=' in text:
        candidates.append((text.replace('xmlns:xml=', 'xmlns:ns=', 1), "avoid forbidden rebinding of reserved xml prefix"))
    return candidates or _general_xml_repair(text)


def _fix_doctype_truncation(text: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    if "<!DOCTYPE" in text and ">" not in text[text.index("<!DOCTYPE"):]:
        candidates.append((text + ">", "close truncated doctype declaration"))
    if "<!DOCTYPE" in text and "]>" not in text and "[" in text:
        candidates.append((text + "]>", "close internal subset and doctype"))
    if "<!DOCTYPE" in text:
        candidates.append((re.sub(r"<!DOCTYPE[^>]*>", "", text, count=1, flags=re.DOTALL).strip(), "remove malformed doctype entirely"))
    return candidates or _general_xml_repair(text)


def _fix_comment_cdata_truncation(text: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    if "<!--" in text and "-->" not in text:
        candidates.append((text + "-->", "close unterminated comment"))
    if "<![CDATA[" in text and "]]>" not in text:
        candidates.append((text + "]]>", "close unterminated CDATA section"))
    return candidates or _general_xml_repair(text)


def _wrap_extra_content(text: str) -> list[tuple[str, str]]:
    stripped = text.strip()
    return [
        (f"<wrapper>{stripped}</wrapper>", "wrap multiple top-level fragments in one root element"),
    ]


def _general_xml_repair(text: str) -> list[tuple[str, str]]:
    stripped = text.strip()
    if not stripped:
        return [("<root/>", "replace empty input with minimal XML root")]
    if not stripped.startswith("<"):
        return [(f"<root>{stripped}</root>", "wrap raw text in a root element")]
    return [(stripped, "preserve baseline text as fallback candidate")]
