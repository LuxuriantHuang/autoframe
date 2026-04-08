from pathlib import Path

from input_adapter import infer_input_adapter_from_harness
from semantic_fields.json_provider import build_json_semantic_fields


def test_infer_input_adapter_from_afl_style_harness():
    harness_code = Path("/home/lab420/Desktop/af/benchmarks/cjson/src/fuzzing/afl.c").read_text(encoding="utf-8")

    spec = infer_input_adapter_from_harness(harness_code, ["target_bin", "@@"])

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

    harness_code = Path("/home/lab420/Desktop/af/benchmarks/cjson/src/fuzzing/afl.c").read_text(encoding="utf-8")
    spec = infer_input_adapter_from_harness(harness_code, ["target_bin", "@@"])
    result = build_json_semantic_fields(seed_path, adapter_spec=spec)

    assert result["input_adapter"]["payload_offset"] == 2
    assert result["fields"][0]["offset"] == 2
    key_field = next(field for field in result["fields"] if field["kind"] == "object_key")
    assert key_field["path"] == "$.key"
    assert key_field["offset"] == 3
