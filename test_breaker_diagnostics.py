from breaker.diagnostics import normalize_xmllint_stderr


def test_normalize_tag_mismatch():
    result = normalize_xmllint_stderr("parser error : Opening and ending tag mismatch: a line 1 and b\n")
    assert result.family == "tag_mismatch"


def test_normalize_attr_construct_error():
    result = normalize_xmllint_stderr("attributes construct error\n")
    assert result.family == "attr_construct_error"


def test_normalize_entity_undefined():
    result = normalize_xmllint_stderr("Entity 'bogus' not defined\n")
    assert result.family == "entity_undefined"


def test_normalize_unknown_parse_error():
    result = normalize_xmllint_stderr("parser error : something odd happened\n")
    assert result.family == "unknown_parse_error"


def test_normalize_no_error_for_empty_stderr():
    result = normalize_xmllint_stderr("")
    assert result.family == "no_error"
