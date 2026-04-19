from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import ujson

from config import ROOT_DIR
from input_adapter import infer_input_adapter_from_harness

JSON_PROJECTS = {"cjson", "jansson", "jq"}
C_PROJECTS = {"cflow"}
JS_PROJECTS = {"mujs"}
GENERIC_TEXT_PROJECTS = {"sqlite", "calc"}


def has_semantic_field_provider(project: str) -> bool:
    if project == "libxml" or project in JSON_PROJECTS or project in C_PROJECTS or project in JS_PROJECTS or project in GENERIC_TEXT_PROJECTS:
        return True
    parse_script = ROOT_DIR / "kaitai" / project / "parse.py"
    return parse_script.exists()


def build_semantic_fields(
    *,
    project: str,
    seed_path: str | Path,
    isi_json_path: str | Path,
    out_path: str | Path,
    harness_code: str | None = None,
) -> dict[str, Any] | None:
    if project == "libxml":
        from .xml_provider import build_xml_semantic_fields

        return build_xml_semantic_fields(seed_path, out_path=out_path)
    if project in JSON_PROJECTS:
        from .json_provider import build_json_semantic_fields

        adapter_spec = infer_input_adapter_from_harness(harness_code)
        return build_json_semantic_fields(seed_path, out_path=out_path, adapter_spec=adapter_spec)
    if project in C_PROJECTS:
        from .code_provider import build_code_semantic_fields

        return build_code_semantic_fields(seed_path, language="c", out_path=out_path)
    if project in JS_PROJECTS:
        from .code_provider import build_code_semantic_fields

        return build_code_semantic_fields(seed_path, language="javascript", out_path=out_path)
    if project in GENERIC_TEXT_PROJECTS:
        from .generic_text_provider import build_generic_text_semantic_fields

        return build_generic_text_semantic_fields(seed_path, out_path=out_path)

    parse_script = ROOT_DIR / "kaitai" / project / "parse.py"
    if not parse_script.exists():
        return None

    cmd = [
        "python",
        parse_script.as_posix(),
        Path(seed_path).as_posix(),
        Path(isi_json_path).as_posix(),
        "--out",
        Path(out_path).as_posix(),
    ]
    subprocess.run(cmd, stderr=subprocess.DEVNULL, check=False)

    if not Path(out_path).exists():
        return None

    with open(out_path, "r", encoding="utf-8") as handle:
        return ujson.load(handle)
