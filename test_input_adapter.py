from input_adapter import infer_input_adapter_from_harness
from semantic_fields.json_provider import build_json_semantic_fields


_CJSON_HARNESS = """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;
    if (data[0] != 'b') return 0;
    if (data[1] != 'f') return 0;
    cJSON_ParseWithLength((const char *)data + 2, size - 2);
    return 0;
}
"""


def test_infer_input_adapter_from_afl_style_harness():
    spec = infer_input_adapter_from_harness(_CJSON_HARNESS, ["target_bin", "@@"])

    assert spec.payload_offset == 2
    assert spec.delivery == "file_placeholder"
    assert spec.payload_kind == "json_text"
    assert spec.prefix_constraints == [
        {"offset": 0, "allowed": ["b"]},
        {"offset": 1, "allowed": ["f"]},
    ]


def test_json_semantic_fields_use_payload_view_and_remap_offsets(tmp_path):
    seed_path = tmp_path / "seed.bin"
    seed_path.write_bytes(b'bf{"key":1}')

    spec = infer_input_adapter_from_harness(_CJSON_HARNESS, ["target_bin", "@@"])
    result = build_json_semantic_fields(seed_path, adapter_spec=spec)

    assert result["input_adapter"]["payload_offset"] == 2
    assert result["fields"][0]["offset"] == 2
    key_field = next(field for field in result["fields"] if field["kind"] == "object_key")
    assert key_field["path"] == "$.key"
    assert key_field["offset"] == 3
