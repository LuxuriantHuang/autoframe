from __future__ import annotations

import re

from breaker.models import DiagnosticResult


_DIAGNOSTIC_PATTERNS: list[tuple[str, tuple[re.Pattern[str], ...]]] = [
    (
        "tag_mismatch",
        (
            re.compile(r"opening and ending tag mismatch", re.IGNORECASE),
            re.compile(r"premature end of data in tag", re.IGNORECASE),
        ),
    ),
    (
        "attr_construct_error",
        (
            re.compile(r"attributes construct error", re.IGNORECASE),
            re.compile(r"error parsing attribute name", re.IGNORECASE),
            re.compile(r"attvalue: ['\"] expected", re.IGNORECASE),
            re.compile(r"specification mandates value for attribute", re.IGNORECASE),
        ),
    ),
    (
        "entity_undefined",
        (
            re.compile(r"entity ['`\"]?.+?['`\"]? not defined", re.IGNORECASE),
            re.compile(r"entity ref: expecting ';'", re.IGNORECASE),
        ),
    ),
    (
        "invalid_charref",
        (
            re.compile(r"charref: invalid", re.IGNORECASE),
            re.compile(r"xmlparsecharref: invalid", re.IGNORECASE),
            re.compile(r"invalid xml character", re.IGNORECASE),
        ),
    ),
    (
        "namespace_error",
        (
            re.compile(r"namespace error", re.IGNORECASE),
            re.compile(r"namespace prefix .* is not defined", re.IGNORECASE),
            re.compile(r"reuse of the xmlns namespace name is forbidden", re.IGNORECASE),
        ),
    ),
    (
        "doctype_error",
        (
            re.compile(r"doctype", re.IGNORECASE),
            re.compile(r"content error in the internal subset", re.IGNORECASE),
            re.compile(r"start tag expected, '<' not found", re.IGNORECASE),
        ),
    ),
    (
        "unterminated_cdata",
        (
            re.compile(r"cdata section not finished", re.IGNORECASE),
            re.compile(r"sequence '\]\]>' not found", re.IGNORECASE),
        ),
    ),
    (
        "unterminated_comment",
        (
            re.compile(r"comment not terminated", re.IGNORECASE),
            re.compile(r"double hyphen within comment", re.IGNORECASE),
        ),
    ),
    (
        "extra_content",
        (
            re.compile(r"extra content at the end of the document", re.IGNORECASE),
        ),
    ),
    (
        "multiple_roots",
        (
            re.compile(r"start tag expected, '<' not found", re.IGNORECASE),
            re.compile(r"extra content at the end of the document", re.IGNORECASE),
        ),
    ),
]


def normalize_xmllint_stderr(stderr_text: str) -> DiagnosticResult:
    text = (stderr_text or "").strip()
    lowered = text.lower()
    if not lowered:
        return DiagnosticResult(family="no_error", message="", raw_stderr=text)

    for family, patterns in _DIAGNOSTIC_PATTERNS:
        for pattern in patterns:
            if pattern.search(text):
                if family == "multiple_roots" and "extra content at the end of the document" not in lowered:
                    continue
                return DiagnosticResult(family=family, message=_first_relevant_line(text), raw_stderr=text)

    if "parser error" in lowered or "error:" in lowered:
        return DiagnosticResult(
            family="unknown_parse_error",
            message=_first_relevant_line(text),
            raw_stderr=text,
        )
    return DiagnosticResult(family="unknown_parse_error", message=_first_relevant_line(text), raw_stderr=text)


def _first_relevant_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""
