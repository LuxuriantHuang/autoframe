from breaker.structured_text.xml_rules import build_xml_rule_candidates


def _texts(candidates):
    return [item.text for item in candidates]


def test_end_tag_mismatch_rule_repairs_closing_tag():
    candidates = build_xml_rule_candidates("<root><a></b></root>", action="end_tag_mismatch", diagnostics_family="tag_mismatch")
    assert any("</a>" in text for text in _texts(candidates))


def test_attribute_quote_break_rule_adds_quotes():
    candidates = build_xml_rule_candidates("<root a=test></root>", action="attribute_quote_break", diagnostics_family="attr_construct_error")
    assert any('a="test"' in text for text in _texts(candidates))


def test_entity_corruption_rule_restores_entity():
    candidates = build_xml_rule_candidates("<root>&bogus</root>", action="entity_corruption", diagnostics_family="entity_undefined")
    assert any("&bogus;" in text or "&amp;" in text for text in _texts(candidates))


def test_comment_cdata_rule_closes_unterminated_comment():
    candidates = build_xml_rule_candidates("<root><!-- broken</root>", action="comment_cdata_truncation", diagnostics_family="unterminated_comment")
    assert any("-->" in text for text in _texts(candidates))
