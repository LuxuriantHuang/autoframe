from __future__ import annotations

from breaker.models import MutationCandidate
from breaker.structured_text.xml_rules import build_xml_rule_candidates


_FAMILY_TO_ACTIONS: dict[str, list[str]] = {
    "no_error": ["general_xml_repair"],
    "tag_mismatch": ["end_tag_mismatch"],
    "attr_construct_error": ["attribute_quote_break"],
    "entity_undefined": ["entity_corruption"],
    "invalid_charref": ["charref_corruption"],
    "namespace_error": ["namespace_rebinding"],
    "doctype_error": ["doctype_truncation"],
    "unterminated_cdata": ["comment_cdata_truncation"],
    "unterminated_comment": ["comment_cdata_truncation"],
    "extra_content": ["extra_content_wrap"],
    "multiple_roots": ["extra_content_wrap"],
    "unknown_parse_error": ["general_xml_repair"],
}


def choose_structured_text_candidates(seed_text: str, diagnostics_family: str, max_candidates: int = 6) -> list[MutationCandidate]:
    actions = _FAMILY_TO_ACTIONS.get(diagnostics_family, ["general_xml_repair"])
    candidates: list[MutationCandidate] = []
    for action in actions:
        candidates.extend(build_xml_rule_candidates(seed_text, action=action, diagnostics_family=diagnostics_family))

    deduped: list[MutationCandidate] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate.text in seen:
            continue
        seen.add(candidate.text)
        deduped.append(candidate)
        if len(deduped) >= max_candidates:
            break
    return deduped
