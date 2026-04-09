from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class XmlGrammarCandidate:
    text: str
    strategy: str
    note: str = ""


_XML_DECL_RE = re.compile(r"<\?xml[^>]*\?>", re.IGNORECASE)
_DOCTYPE_RE = re.compile(r"<!DOCTYPE.*?>", re.IGNORECASE | re.DOTALL)
_INTERNAL_SUBSET_RE = re.compile(r"<!DOCTYPE\s+[^[]+\[(.*?)\]>", re.IGNORECASE | re.DOTALL)
_ROOT_RE = re.compile(r"<([A-Za-z_][\w:\-\.]*)([^>]*)>", re.DOTALL)
_PI_RE = re.compile(r"<\?(?!xml\b)[^>]+\?>", re.IGNORECASE)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_CDATA_RE = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)
_CHILD_ELEMENT_RE = re.compile(r"<([A-Za-z_][\w:\-\.]*)[^>]*>.*?</\1>", re.DOTALL)
_ATTR_RE = re.compile(r"\s+([^\s=]+)=(\"[^\"]*\"|'[^']*')")


def is_libxml_project(project: str) -> bool:
    return project in {"libxml", "xmllint"}


def build_libxml_grammar_candidates(
    *,
    constraints: str,
    summary: str,
    roadblock_code: str,
    preferred_seed_text: str | None = None,
    donor_seed_texts: list[str] | None = None,
    fields: dict[str, Any] | None = None,
    max_candidates: int = 8,
) -> list[XmlGrammarCandidate]:
    donor_seed_texts = [text for text in (donor_seed_texts or []) if text]
    hints = _collect_hints(constraints, summary, roadblock_code, fields)
    return _build_candidates_from_hints(hints, preferred_seed_text, donor_seed_texts, max_candidates=max_candidates)


def build_libxml_llm_mutation_spec_messages(
    *,
    constraints: str,
    summary: str,
    roadblock_code: str,
    preferred_seed_text: str | None = None,
    donor_seed_texts: list[str] | None = None,
    fields: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    hints = _collect_hints(constraints, summary, roadblock_code, fields)
    components = ", ".join(_component_catalog().keys())
    operations = ", ".join(_supported_operations())
    donor_preview = "\n---\n".join(_trim_for_prompt(text) for text in (donor_seed_texts or [])[:2]) or "(none)"
    return [
        {
            "role": "system",
            "content": (
                "You are planning XML grammar-aware mutations for libxml/xmllint.\n"
                "Return JSON only.\n"
                "Choose from the provided XML components and operations.\n"
                "Prioritize parser-survivable, structurally plausible inputs over random damage."
            ),
        },
        {
            "role": "user",
            "content": (
                "Produce one JSON object with keys:\n"
                "components: string[]\n"
                "operations: [{\"op\": string, ...optional params...}]\n"
                "reason: string\n\n"
                f"Available components: {components}\n"
                f"Available operations: {operations}\n"
                f"Hint baseline: {sorted(key for key, value in hints.items() if isinstance(value, bool) and value)}\n\n"
                f"<constraints>\n{constraints}\n</constraints>\n"
                f"<summary>\n{summary}\n</summary>\n"
                f"<roadblock_code>\n{_trim_for_prompt(roadblock_code, 1600)}\n</roadblock_code>\n"
                f"<preferred_seed>\n{_trim_for_prompt(preferred_seed_text)}\n</preferred_seed>\n"
                f"<donor_seeds>\n{donor_preview}\n</donor_seeds>\n"
            ),
        },
    ]


def build_libxml_llm_component_scoring_messages(
    *,
    constraints: str,
    summary: str,
    roadblock_code: str,
    preferred_seed_text: str | None = None,
    donor_seed_texts: list[str] | None = None,
    fields: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    hints = _collect_hints(constraints, summary, roadblock_code, fields)
    catalog = _component_catalog()
    component_lines = "\n".join(f"- {name}: {desc}" for name, desc in catalog.items())
    donor_preview = "\n---\n".join(_trim_for_prompt(text) for text in (donor_seed_texts or [])[:2]) or "(none)"
    return [
        {
            "role": "system",
            "content": (
                "You are ranking XML grammar components for coverage-oriented mutation planning.\n"
                "Return JSON only. Score components by relevance to the roadblock and parser survivability."
            ),
        },
        {
            "role": "user",
            "content": (
                "Produce one JSON object with key components, where components is a list of objects:\n"
                "[{\"name\": string, \"score\": number, \"reason\": string}]\n"
                "Use scores in [0,1]. Keep the list concise and sorted from high to low.\n\n"
                f"Available components:\n{component_lines}\n\n"
                f"Hint baseline: {sorted(key for key, value in hints.items() if isinstance(value, bool) and value)}\n\n"
                f"<constraints>\n{constraints}\n</constraints>\n"
                f"<summary>\n{summary}\n</summary>\n"
                f"<roadblock_code>\n{_trim_for_prompt(roadblock_code, 1600)}\n</roadblock_code>\n"
                f"<preferred_seed>\n{_trim_for_prompt(preferred_seed_text)}\n</preferred_seed>\n"
                f"<donor_seeds>\n{donor_preview}\n</donor_seeds>\n"
            ),
        },
    ]


def apply_llm_mutation_spec(
    *,
    constraints: str,
    summary: str,
    roadblock_code: str,
    spec: dict[str, Any],
    preferred_seed_text: str | None = None,
    donor_seed_texts: list[str] | None = None,
    fields: dict[str, Any] | None = None,
    max_candidates: int = 6,
) -> list[XmlGrammarCandidate]:
    donor_seed_texts = [text for text in (donor_seed_texts or []) if text]
    hints = _collect_hints(constraints, summary, roadblock_code, fields)
    _merge_selected_components_into_hints(hints, spec.get("components"))
    seed_texts = [text for text in [preferred_seed_text, *donor_seed_texts] if text] or _skeleton_slot_fill(hints, None)
    candidates: list[XmlGrammarCandidate] = []
    seen: set[str] = set()

    for text in seed_texts[:3]:
        current = text
        for op in spec.get("operations", []) or []:
            current = _apply_operation(current, op, hints)
        normalized = _normalize_text(current)
        if normalized and normalized not in seen:
            seen.add(normalized)
            candidates.append(XmlGrammarCandidate(normalized, "llm_mutation_spec", note=str(spec.get("reason", ""))))
        if len(candidates) >= max_candidates:
            return candidates[:max_candidates]

    for candidate in _build_candidates_from_hints(hints, preferred_seed_text, donor_seed_texts, max_candidates=max_candidates):
        if candidate.text in seen:
            continue
        seen.add(candidate.text)
        candidates.append(XmlGrammarCandidate(candidate.text, "llm_mutation_spec_fallback", note=str(spec.get("reason", ""))))
        if len(candidates) >= max_candidates:
            break
    return candidates[:max_candidates]


def build_candidates_from_component_scores(
    *,
    constraints: str,
    summary: str,
    roadblock_code: str,
    scoring_result: dict[str, Any],
    preferred_seed_text: str | None = None,
    donor_seed_texts: list[str] | None = None,
    fields: dict[str, Any] | None = None,
    max_candidates: int = 6,
) -> list[XmlGrammarCandidate]:
    donor_seed_texts = [text for text in (donor_seed_texts or []) if text]
    hints = _collect_hints(constraints, summary, roadblock_code, fields)
    _merge_selected_components_into_hints(hints, _extract_ranked_component_names(scoring_result))
    candidates = _build_candidates_from_hints(hints, preferred_seed_text, donor_seed_texts, max_candidates=max_candidates)
    return [
        XmlGrammarCandidate(candidate.text, "llm_component_scoring", note=str(scoring_result.get("reason", "")))
        for candidate in candidates
    ]


def _build_candidates_from_hints(
    hints: dict[str, Any],
    preferred_seed_text: str | None,
    donor_seed_texts: list[str],
    *,
    max_candidates: int,
) -> list[XmlGrammarCandidate]:
    candidates: list[XmlGrammarCandidate] = []
    seen: set[str] = set()

    def add(text: str, strategy: str, note: str = "") -> None:
        normalized = _normalize_text(text)
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        candidates.append(XmlGrammarCandidate(text=normalized, strategy=strategy, note=note))

    for text in _skeleton_slot_fill(hints, preferred_seed_text):
        add(text, "skeleton_slot_fill")
        if len(candidates) >= max_candidates:
            return candidates[:max_candidates]

    for text in _fragment_splicing(preferred_seed_text, donor_seed_texts, hints):
        add(text, "fragment_splicing")
        if len(candidates) >= max_candidates:
            return candidates[:max_candidates]

    for text in _constraint_guided_mutation(preferred_seed_text, donor_seed_texts, hints):
        add(text, "constraint_guided_mutation")
        if len(candidates) >= max_candidates:
            return candidates[:max_candidates]

    return candidates[:max_candidates]


def _collect_hints(
    constraints: str,
    summary: str,
    roadblock_code: str,
    fields: dict[str, Any] | None,
) -> dict[str, Any]:
    joined = "\n".join(part for part in (constraints, summary, roadblock_code) if part).lower()
    field_names = _extract_field_names(fields)
    return {
        "want_doctype": any(token in joined for token in ("doctype", "entity", "dtd", "catalog")),
        "want_entity": any(token in joined for token in ("entity", "entit", "catalog")),
        "want_attlist": any(token in joined for token in ("attlist", "xml:id", "id attribute")),
        "want_namespace": any(token in joined for token in ("namespace", "xmlns", "prefix", "uri")),
        "want_comment": "comment" in joined,
        "want_processing_instruction": any(token in joined for token in ("xml-model", "processing instruction", "catalog")),
        "want_non_ascii": any(token in joined for token in ("unicode", "utf", "char", "namechar", "ncname")),
        "want_recoverable_damage": any(token in joined for token in ("recover", "fallback", "error path", "malformed")),
        "want_cdata": any(token in joined for token in ("cdata", "raw text", "escaped text")),
        "want_charref": any(token in joined for token in ("charref", "character reference", "entity reference", "numeric reference")),
        "want_external_id": any(token in joined for token in ("system", "public", "external subset", "external id", "catalog")),
        "want_notation": any(token in joined for token in ("notation", "unparsed entity")),
        "want_default_attr": any(token in joined for token in ("default attribute", "#fixed", "#required", "#implied")),
        "want_mixed_content": any(token in joined for token in ("mixed", "text node", "tail text", "content model")),
        "want_stylesheet_pi": any(token in joined for token in ("xml-stylesheet", "stylesheet")),
        "want_catalog_pi": any(token in joined for token in ("xml-model", "oasis-xml-catalog", "catalog pi")),
        "want_duplicate_attr": any(token in joined for token in ("duplicate attr", "duplicate attribute")),
        "want_prefix_variation": any(token in joined for token in ("prefix", "qname", "qualified name", "xmlns")),
        "want_entity_ref": any(token in joined for token in ("entity reference", "&", "charref")),
        "want_comment_sandwich": any(token in joined for token in ("comment", "misc", "prolog")),
        "field_names": field_names,
    }


def _extract_field_names(fields: dict[str, Any] | None) -> list[str]:
    names: list[str] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in {"name", "field_name", "attribute", "tag", "element_name"} and isinstance(value, str):
                    stripped = value.strip()
                    if stripped and stripped not in names:
                        names.append(stripped)
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(fields)
    return names[:8]


def _skeleton_slot_fill(hints: dict[str, Any], preferred_seed_text: str | None) -> list[str]:
    root_name = _pick_root_name(preferred_seed_text, hints)
    attr_name = _pick_attr_name(hints)
    child_name = _pick_child_name(hints)
    attr_value = "alpha" if not hints["want_non_ascii"] else "alpha\u0100"
    ns_attr = _namespace_attrs(hints)
    comments = _comment_block(hints)
    pis = _processing_instruction_block(hints)
    internal_subset_parts: list[str] = []
    if hints["want_entity"]:
        internal_subset_parts.append('<!ENTITY customEntity "grammar-guided">')
    if hints["want_attlist"]:
        internal_subset_parts.append(f'<!ATTLIST {root_name} {attr_name} ID #IMPLIED>')
    if hints["want_default_attr"]:
        internal_subset_parts.append(f'<!ATTLIST {root_name} mode CDATA #FIXED "guided">')
    if hints["want_notation"]:
        internal_subset_parts.append('<!NOTATION gif SYSTEM "image/gif">')
        internal_subset_parts.append(f'<!ENTITY logo SYSTEM "logo.gif" NDATA gif>')
    doctype = ""
    if hints["want_doctype"] or internal_subset_parts:
        if internal_subset_parts:
            doctype = _build_doctype(root_name, hints, internal_subset_parts)
        else:
            doctype = _build_doctype(root_name, hints, [])
    text_body = _text_payload(hints)
    attr_fragment = f' {attr_name}="{attr_value}"'
    mixed_body = _mixed_content_body(child_name, text_body, hints)
    root_open = f"<{_prefixed_name(root_name, hints)}{ns_attr}{attr_fragment}>"
    root_close = f"</{_prefixed_name(root_name, hints)}>"
    base = (
        f"<?xml version='1.0' encoding='UTF-8'?>\n"
        f"{comments}{pis}{doctype}\n"
        f"{root_open}{mixed_body}{root_close}"
    )
    variants = [base]
    if hints["want_recoverable_damage"]:
        variants.append(base.replace("</child>", "", 1))
    if hints["want_namespace"]:
        variants.append(
            f"<?xml version='1.0' encoding='UTF-8'?>\n"
            f"{doctype}\n"
            f"<ns:{root_name} xmlns:ns=\"http://example.com/ns\"{attr_fragment}><ns:{child_name}>{text_body}</ns:{child_name}></ns:{root_name}>"
        )
    if hints["want_cdata"]:
        variants.append(
            f"<?xml version='1.0' encoding='UTF-8'?>\n"
            f"{comments}{doctype}\n"
            f"{root_open}<![CDATA[<raw>&content]]><{child_name}>{_charref_payload(hints)}</{child_name}>{root_close}"
        )
    if hints["want_external_id"]:
        variants.append(
            f"<?xml version='1.0' encoding='UTF-8'?>\n"
            f"<!DOCTYPE {root_name} SYSTEM \"guided.dtd\">\n"
            f"{root_open}<empty/>{root_close}"
        )
    if hints["want_mixed_content"]:
        variants.append(
            f"<?xml version='1.0' encoding='UTF-8'?>\n"
            f"{doctype}\n"
            f"{root_open}lead<{child_name} flag=\"1\"/>tail{root_close}"
        )
    return variants


def _fragment_splicing(
    preferred_seed_text: str | None,
    donor_seed_texts: list[str],
    hints: dict[str, Any],
) -> list[str]:
    base = preferred_seed_text or _skeleton_slot_fill(hints, None)[0]
    variants: list[str] = []
    donor_doctype = _first_fragment(donor_seed_texts, _DOCTYPE_RE)
    donor_decl = _first_fragment(donor_seed_texts, _XML_DECL_RE)
    donor_subset = _first_internal_subset(donor_seed_texts)
    donor_root_attr = _first_root_attrs(donor_seed_texts)
    donor_pi = _first_fragment(donor_seed_texts, _PI_RE)
    donor_comment = _first_fragment(donor_seed_texts, _COMMENT_RE)
    donor_cdata = _first_fragment(donor_seed_texts, _CDATA_RE)
    donor_child = _first_child_fragment(donor_seed_texts)

    if donor_decl and not _XML_DECL_RE.search(base):
        variants.append(f"{donor_decl}\n{base}")
    if donor_doctype and "<!DOCTYPE" not in base:
        insert_at = _xml_decl_end(base)
        variants.append(base[:insert_at] + donor_doctype + "\n" + base[insert_at:])
    if donor_subset and "<!DOCTYPE" in base and "[" not in base:
        variants.append(re.sub(r"<!DOCTYPE\s+([^\s>]+)>", rf"<!DOCTYPE \1 [\n{donor_subset}\n]>", base, count=1))
    if donor_root_attr:
        variants.append(_merge_root_attrs(base, donor_root_attr))
    if donor_pi and donor_pi not in base:
        insert_at = _xml_decl_end(base)
        variants.append(base[:insert_at] + donor_pi + "\n" + base[insert_at:])
    if donor_comment and donor_comment not in base:
        insert_at = _xml_decl_end(base)
        variants.append(base[:insert_at] + donor_comment + "\n" + base[insert_at:])
    if donor_cdata and "<![CDATA[" not in base:
        variants.append(_inject_before_first_closing_tag(base, donor_cdata))
    if donor_child:
        variants.append(_replace_first_child(base, donor_child))
    return variants


def _constraint_guided_mutation(
    preferred_seed_text: str | None,
    donor_seed_texts: list[str],
    hints: dict[str, Any],
) -> list[str]:
    seed_texts = [text for text in [preferred_seed_text, *donor_seed_texts] if text]
    if not seed_texts:
        seed_texts = _skeleton_slot_fill(hints, None)
    variants: list[str] = []
    for text in seed_texts[:4]:
        current = text
        if hints["want_attlist"] and "xml:id" not in current:
            current = _inject_root_attr(current, ' xml:id="guidedId"')
        if hints["want_namespace"] and "xmlns" not in current:
            current = _inject_root_attr(current, ' xmlns:guided="http://example.com/guided"')
        if hints["want_entity"] and "&customEntity;" not in current:
            current = _ensure_internal_subset(current, '<!ENTITY customEntity "guided-entity">')
            current = current.replace("</", "&customEntity;</", 1)
        if hints["want_processing_instruction"] and "<?xml-model" not in current:
            insert_at = _xml_decl_end(current)
            current = current[:insert_at] + '<?xml-model href="guided.rng"?>\n' + current[insert_at:]
        if hints["want_stylesheet_pi"] and "<?xml-stylesheet" not in current:
            insert_at = _xml_decl_end(current)
            current = current[:insert_at] + '<?xml-stylesheet type="text/xsl" href="guided.xsl"?>\n' + current[insert_at:]
        if hints["want_catalog_pi"] and "<?oasis-xml-catalog" not in current:
            insert_at = _xml_decl_end(current)
            current = current[:insert_at] + '<?oasis-xml-catalog catalog="catalog.xml"?>\n' + current[insert_at:]
        if hints["want_default_attr"] and "#FIXED" not in current:
            root_name = _pick_root_name(current, hints)
            current = _ensure_internal_subset(current, f'<!ATTLIST {root_name} mode CDATA #FIXED "guided">')
        if hints["want_notation"] and "NOTATION" not in current:
            current = _ensure_internal_subset(current, '<!NOTATION gif SYSTEM "image/gif">')
            current = _ensure_internal_subset(current, '<!ENTITY logo SYSTEM "logo.gif" NDATA gif>')
        if hints["want_external_id"] and "<!DOCTYPE" not in current:
            root_name = _pick_root_name(current, hints)
            insert_at = _xml_decl_end(current)
            current = current[:insert_at] + f'<!DOCTYPE {root_name} SYSTEM "guided.dtd">\n' + current[insert_at:]
        if hints["want_cdata"] and "<![CDATA[" not in current:
            current = _inject_before_first_closing_tag(current, "<![CDATA[guided<xml>&payload]]>")
        if hints["want_charref"] and "&#x" not in current:
            current = _replace_text_token(current, "guidedId", "guided&#x41;&#x100;Id")
            current = _replace_text_token(current, ">content<", f">{_charref_payload(hints)}<")
        if hints["want_mixed_content"]:
            current = _ensure_mixed_content(current)
        if hints["want_duplicate_attr"]:
            current = _duplicate_first_attr(current)
        if hints["want_prefix_variation"] and "xmlns:guided" not in current:
            current = _inject_root_attr(current, ' xmlns:guided="http://example.com/pfx"')
            current = _prefix_root_and_child(current, "guided")
        if hints["want_entity_ref"] and "&customEntity;" not in current:
            current = _ensure_internal_subset(current, '<!ENTITY customEntity "guided-entity">')
            current = _replace_text_token(current, ">content<", ">&customEntity;<")
        if hints["want_non_ascii"] and "\u0100" not in current:
            current = current.replace("guidedId", "guided\u0100Id")
        if hints["want_comment_sandwich"] and "<!--" not in current:
            current = f"<!-- pre-root -->\n{current}\n<!-- post-root -->"
        if hints["want_recoverable_damage"] and current.count("=") > 0:
            current = current.replace('"', "", 1)
        variants.append(current)
    return variants


def _pick_root_name(preferred_seed_text: str | None, hints: dict[str, Any]) -> str:
    if preferred_seed_text:
        match = _ROOT_RE.search(preferred_seed_text)
        if match:
            return match.group(1).split(":")[-1]
    for name in hints["field_names"]:
        cleaned = re.sub(r"[^A-Za-z0-9_\-:]", "", name)
        if cleaned and cleaned[0].isalpha():
            return cleaned
    return "root"


def _pick_attr_name(hints: dict[str, Any]) -> str:
    for name in hints["field_names"]:
        cleaned = re.sub(r"[^A-Za-z0-9_\-:]", "", name)
        if cleaned and cleaned[0].isalpha():
            return cleaned
    return "xml:id" if hints["want_attlist"] else "id"


def _pick_child_name(hints: dict[str, Any]) -> str:
    for name in hints["field_names"]:
        cleaned = re.sub(r"[^A-Za-z0-9_\-:]", "", name)
        if cleaned and cleaned[0].isalpha() and cleaned not in {"xml:id", "id"}:
            return cleaned.split(":")[-1]
    return "child"


def _normalize_text(text: str | None) -> str:
    if not text:
        return ""
    text = text.replace("\r\n", "\n").strip()
    return text + ("\n" if text else "")


def _first_fragment(seed_texts: list[str], pattern: re.Pattern[str]) -> str | None:
    for text in seed_texts:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def _first_internal_subset(seed_texts: list[str]) -> str | None:
    for text in seed_texts:
        match = _INTERNAL_SUBSET_RE.search(text)
        if match:
            return match.group(1).strip()
    return None


def _first_root_attrs(seed_texts: list[str]) -> str | None:
    for text in seed_texts:
        match = _ROOT_RE.search(text)
        if match and match.group(2).strip():
            return match.group(2)
    return None


def _first_child_fragment(seed_texts: list[str]) -> str | None:
    for text in seed_texts:
        matches = _CHILD_ELEMENT_RE.findall(text)
        if matches:
            match = _CHILD_ELEMENT_RE.search(text)
            if match:
                return match.group(0)
    return None


def _xml_decl_end(text: str) -> int:
    match = _XML_DECL_RE.search(text)
    if not match:
        return 0
    return match.end() + (1 if match.end() < len(text) and text[match.end():match.end() + 1] != "\n" else 0)


def _merge_root_attrs(text: str, donor_attrs: str) -> str:
    match = _ROOT_RE.search(text)
    if not match:
        return text
    merged_attrs = match.group(2)
    for attr in re.findall(r"\s+[^\s=]+=(?:\"[^\"]*\"|'[^']*')", donor_attrs):
        attr_name = attr.strip().split("=", 1)[0]
        if re.search(rf"\b{re.escape(attr_name)}=", merged_attrs):
            continue
        merged_attrs += attr
    return text[:match.start()] + f"<{match.group(1)}{merged_attrs}>" + text[match.end():]


def _inject_root_attr(text: str, attr_fragment: str) -> str:
    match = _ROOT_RE.search(text)
    if not match:
        return text
    return text[:match.start()] + f"<{match.group(1)}{match.group(2)}{attr_fragment}>" + text[match.end():]


def _ensure_internal_subset(text: str, fragment: str) -> str:
    if "<!DOCTYPE" not in text:
        root_name = _pick_root_name(text, {"field_names": []})
        insert_at = _xml_decl_end(text)
        return text[:insert_at] + f"<!DOCTYPE {root_name} [\n  {fragment}\n]>\n" + text[insert_at:]
    if "[" in text:
        return re.sub(r"\[(.*?)\]", lambda m: "[\n" + m.group(1).strip() + f"\n  {fragment}\n]", text, count=1, flags=re.DOTALL)
    return re.sub(r"<!DOCTYPE\s+([^\s>]+)>", rf"<!DOCTYPE \1 [\n  {fragment}\n]>", text, count=1)


def _build_doctype(root_name: str, hints: dict[str, Any], internal_subset_parts: list[str]) -> str:
    external_id = ' SYSTEM "guided.dtd"' if hints["want_external_id"] else ""
    if internal_subset_parts:
        return f"<!DOCTYPE {root_name}{external_id} [\n  " + "\n  ".join(internal_subset_parts) + "\n]>"
    return f"<!DOCTYPE {root_name}{external_id}>"


def _namespace_attrs(hints: dict[str, Any]) -> str:
    attrs = ""
    if hints["want_namespace"]:
        attrs += ' xmlns="http://example.com/ns"'
    if hints["want_prefix_variation"]:
        attrs += ' xmlns:alt="http://example.com/alt"'
    return attrs


def _comment_block(hints: dict[str, Any]) -> str:
    if hints["want_comment_sandwich"]:
        return "<!-- before-prolog -->\n<!-- before-root -->\n"
    if hints["want_comment"]:
        return "<!-- grammar-guided -->\n"
    return ""


def _processing_instruction_block(hints: dict[str, Any]) -> str:
    parts: list[str] = []
    if hints["want_processing_instruction"]:
        parts.append('<?xml-model href="example.rng"?>')
    if hints["want_stylesheet_pi"]:
        parts.append('<?xml-stylesheet type="text/xsl" href="guided.xsl"?>')
    if hints["want_catalog_pi"]:
        parts.append('<?oasis-xml-catalog catalog="catalog.xml"?>')
    return ("\n".join(parts) + "\n") if parts else ""


def _text_payload(hints: dict[str, Any]) -> str:
    if hints["want_cdata"]:
        return "<![CDATA[guided<xml>&payload]]>"
    if hints["want_entity_ref"] or hints["want_entity"]:
        return "&customEntity;"
    if hints["want_charref"]:
        return _charref_payload(hints)
    if hints["want_non_ascii"]:
        return "content\u0100"
    return "content"


def _charref_payload(hints: dict[str, Any]) -> str:
    return "&#x41;&#65;&#x100;" if hints["want_non_ascii"] else "&#x41;&#65;"


def _mixed_content_body(child_name: str, text_body: str, hints: dict[str, Any]) -> str:
    if hints["want_mixed_content"]:
        return f"lead<{child_name}>{text_body}</{child_name}>tail"
    return f"<{child_name}>{text_body}</{child_name}>"


def _prefixed_name(name: str, hints: dict[str, Any]) -> str:
    if hints["want_prefix_variation"] or hints["want_namespace"]:
        return f"alt:{name}" if hints["want_prefix_variation"] else name
    return name


def _inject_before_first_closing_tag(text: str, fragment: str) -> str:
    return re.sub(r"</([A-Za-z_][\w:\-\.]*)>", fragment + r"</\1>", text, count=1)


def _replace_first_child(text: str, new_child: str) -> str:
    return _CHILD_ELEMENT_RE.sub(new_child, text, count=1)


def _replace_text_token(text: str, old: str, new: str) -> str:
    if old in text:
        return text.replace(old, new, 1)
    return text


def _ensure_mixed_content(text: str) -> str:
    if re.search(r">[^<]+<[^/][^>]*>.*?</[^>]+>[^<]+</", text, re.DOTALL):
        return text
    return re.sub(
        r"<([A-Za-z_][\w:\-\.]*)[^>]*>(.*?)</\1>",
        lambda m: m.group(0) if "<" in m.group(2) and ">" in m.group(2) else f"<{m.group(1)}>lead<child/>tail</{m.group(1)}>",
        text,
        count=1,
        flags=re.DOTALL,
    )


def _duplicate_first_attr(text: str) -> str:
    match = _ROOT_RE.search(text)
    if not match:
        return text
    attr_match = _ATTR_RE.search(match.group(2))
    if not attr_match:
        return _inject_root_attr(text, ' duplicate="1" duplicate="2"')
    duplicated = f' {attr_match.group(1)}={attr_match.group(2)}'
    return text[:match.start()] + f"<{match.group(1)}{match.group(2)}{duplicated}>" + text[match.end():]


def _prefix_root_and_child(text: str, prefix: str) -> str:
    match = _ROOT_RE.search(text)
    if not match:
        return text
    root_name = match.group(1)
    bare_root = root_name.split(":")[-1]
    updated = text[:match.start()] + f"<{prefix}:{bare_root}{match.group(2)}>" + text[match.end():]
    updated = re.sub(rf"</{re.escape(root_name)}>", f"</{prefix}:{bare_root}>", updated, count=1)
    return re.sub(r"<child(\b|>)", rf"<{prefix}:child\1", updated, count=1).replace(f"</child>", f"</{prefix}:child>", 1)


def _component_catalog() -> dict[str, str]:
    return {
        "xml_decl": "XML declaration with version/encoding/standalone",
        "doctype": "DOCTYPE with optional internal or external subset",
        "entity": "general entity declaration and use",
        "attlist": "ATTLIST, xml:id, ID-like attributes",
        "namespace": "xmlns bindings and prefixed names",
        "processing_instruction": "xml-model or other PI in prolog/body",
        "stylesheet_pi": "xml-stylesheet PI",
        "catalog_pi": "oasis-xml-catalog PI",
        "comment": "comments around prolog or root",
        "cdata": "CDATA sections",
        "charref": "numeric character references",
        "external_id": "SYSTEM/PUBLIC external doctype",
        "notation": "NOTATION and unparsed entity",
        "default_attr": "ATTLIST defaults and #FIXED",
        "mixed_content": "text-element-text mixed content",
        "duplicate_attr": "duplicate attribute for recover path",
        "prefix_variation": "QName/prefix variation on root and child",
        "entity_ref": "entity references in text",
        "recoverable_damage": "light malformed damage that recover may accept",
        "non_ascii": "non-ASCII names or values",
    }


def _supported_operations() -> list[str]:
    return [
        "ensure_doctype",
        "ensure_external_doctype",
        "ensure_entity",
        "ensure_attlist",
        "inject_root_attr",
        "ensure_namespace",
        "ensure_processing_instruction",
        "ensure_stylesheet_pi",
        "ensure_catalog_pi",
        "wrap_cdata",
        "inject_charref_text",
        "ensure_mixed_content",
        "ensure_notation",
        "duplicate_first_attr",
        "prefix_root_and_child",
        "add_comment_sandwich",
        "apply_recoverable_damage",
    ]


def _trim_for_prompt(text: str | None, limit: int = 900) -> str:
    normalized = _normalize_text(text)
    if not normalized:
        return "(none)"
    if len(normalized) <= limit:
        return normalized
    return normalized[:limit] + "\n...[truncated]..."


def _component_to_hint_map() -> dict[str, str]:
    return {
        "doctype": "want_doctype",
        "entity": "want_entity",
        "attlist": "want_attlist",
        "namespace": "want_namespace",
        "comment": "want_comment",
        "processing_instruction": "want_processing_instruction",
        "stylesheet_pi": "want_stylesheet_pi",
        "catalog_pi": "want_catalog_pi",
        "cdata": "want_cdata",
        "charref": "want_charref",
        "external_id": "want_external_id",
        "notation": "want_notation",
        "default_attr": "want_default_attr",
        "mixed_content": "want_mixed_content",
        "duplicate_attr": "want_duplicate_attr",
        "prefix_variation": "want_prefix_variation",
        "entity_ref": "want_entity_ref",
        "recoverable_damage": "want_recoverable_damage",
        "non_ascii": "want_non_ascii",
    }


def _merge_selected_components_into_hints(hints: dict[str, Any], components: Any) -> None:
    if not components:
        return
    mapping = _component_to_hint_map()
    names: list[str] = []
    if isinstance(components, list):
        for item in components:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                names.append(item["name"])
    for name in names:
        hint_key = mapping.get(name)
        if hint_key:
            hints[hint_key] = True


def _extract_ranked_component_names(scoring_result: dict[str, Any]) -> list[str]:
    ranked: list[tuple[float, str]] = []
    for item in scoring_result.get("components", []) or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        score = item.get("score", 0.0)
        if not isinstance(name, str):
            continue
        try:
            numeric_score = float(score)
        except (TypeError, ValueError):
            numeric_score = 0.0
        ranked.append((numeric_score, name))
    ranked.sort(reverse=True)
    return [name for score, name in ranked if score > 0.0][:8]


def _apply_operation(text: str, op: Any, hints: dict[str, Any]) -> str:
    if not isinstance(op, dict):
        return text
    name = op.get("op")
    if not isinstance(name, str):
        return text
    current = text
    if name == "ensure_doctype":
        root_name = _pick_root_name(current, hints)
        current = _ensure_internal_subset(current, f'<!ATTLIST {root_name} xml:id ID #IMPLIED>') if "<!DOCTYPE" not in current else current
    elif name == "ensure_external_doctype":
        root_name = _pick_root_name(current, hints)
        insert_at = _xml_decl_end(current)
        if "<!DOCTYPE" not in current:
            current = current[:insert_at] + f'<!DOCTYPE {root_name} SYSTEM "{op.get("system", "guided.dtd")}">\n' + current[insert_at:]
    elif name == "ensure_entity":
        value = str(op.get("value", "guided-entity"))
        current = _ensure_internal_subset(current, f'<!ENTITY customEntity "{value}">')
        current = _replace_text_token(current, ">content<", ">&customEntity;<")
    elif name == "ensure_attlist":
        root_name = _pick_root_name(current, hints)
        attr_name = str(op.get("attr", "xml:id"))
        attr_kind = str(op.get("kind", "ID"))
        current = _ensure_internal_subset(current, f'<!ATTLIST {root_name} {attr_name} {attr_kind} #IMPLIED>')
    elif name == "inject_root_attr":
        attr_name = str(op.get("name", "xml:id"))
        attr_value = str(op.get("value", "guidedId"))
        current = _inject_root_attr(current, f' {attr_name}="{attr_value}"')
    elif name == "ensure_namespace":
        prefix = str(op.get("prefix", "guided"))
        current = _inject_root_attr(current, f' xmlns:{prefix}="http://example.com/{prefix}"')
    elif name == "ensure_processing_instruction":
        target = str(op.get("target", "xml-model"))
        payload = str(op.get("payload", 'href="guided.rng"'))
        insert_at = _xml_decl_end(current)
        current = current[:insert_at] + f"<?{target} {payload}?>\n" + current[insert_at:]
    elif name == "ensure_stylesheet_pi":
        insert_at = _xml_decl_end(current)
        current = current[:insert_at] + '<?xml-stylesheet type="text/xsl" href="guided.xsl"?>\n' + current[insert_at:]
    elif name == "ensure_catalog_pi":
        insert_at = _xml_decl_end(current)
        current = current[:insert_at] + '<?oasis-xml-catalog catalog="catalog.xml"?>\n' + current[insert_at:]
    elif name == "wrap_cdata":
        payload = str(op.get("payload", "guided<xml>&payload"))
        current = _inject_before_first_closing_tag(current, f"<![CDATA[{payload}]]>")
    elif name == "inject_charref_text":
        current = _replace_text_token(current, ">content<", f">{_charref_payload(hints)}<")
    elif name == "ensure_mixed_content":
        current = _ensure_mixed_content(current)
    elif name == "ensure_notation":
        current = _ensure_internal_subset(current, '<!NOTATION gif SYSTEM "image/gif">')
        current = _ensure_internal_subset(current, '<!ENTITY logo SYSTEM "logo.gif" NDATA gif>')
    elif name == "duplicate_first_attr":
        current = _duplicate_first_attr(current)
    elif name == "prefix_root_and_child":
        current = _prefix_root_and_child(current, str(op.get("prefix", "guided")))
    elif name == "add_comment_sandwich":
        current = f"<!-- pre-root -->\n{current}\n<!-- post-root -->"
    elif name == "apply_recoverable_damage":
        if current.count('"') > 0:
            current = current.replace('"', "", 1)
    return current
