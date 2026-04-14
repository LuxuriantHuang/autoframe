from collections import defaultdict
from pathlib import Path

import main


def _base_eval(**overrides):
    params = dict(
        exec_ok=True,
        parse_family_hit=False,
        new_edges=0,
        target_file_hit=False,
        target_line_window_hit=False,
        coverage_gain_class="seed_generated",
        cost_metrics={},
        rejection_reason=None,
        stderr_text="",
        stderr_cluster="",
        stderr_novel=False,
        parser_depth_score=0,
        closest_hit_line_distance=None,
        deepest_call_chain_hit_index=-1,
        frontier_advance=False,
    )
    params.update(overrides)
    return main.SeedEvalResult(**params)


def test_classify_input_target_marks_cjson_as_structured(monkeypatch):
    monkeypatch.setattr(main, "PROJECT", "demo")
    monkeypatch.setattr(
        main,
        "cached_format_info",
        {"format_name": "cjson_payload", "format_description": "cjson parser input"},
    )

    assert main.classify_input_target(harness_code="parse_json(buf)") == "structured_text_parser"
    assert main.should_force_direct_llm_generation(harness_code="parse_json(buf)")


def test_code_like_text_does_not_force_structured_text_mode(monkeypatch):
    monkeypatch.setattr(main, "PROJECT", "demo")
    monkeypatch.setattr(
        main,
        "cached_format_info",
        {"format_name": "javascript_source", "format_description": "source text input"},
    )

    assert main.classify_input_target(harness_code="parseJavascript(source)") == "code_like_text"
    assert not main.should_force_direct_llm_generation(harness_code="parseJavascript(source)")


def test_infer_input_generation_mode_prefers_text_for_structured_xml_wrappers(monkeypatch):
    monkeypatch.setattr(main, "PROJECT", "xmllint")
    monkeypatch.setattr(
        main,
        "cached_format_info",
        {"format_name": "xml", "format_description": "xml parser input"},
    )

    harness_code = """
    int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        return xmlReadMemory((const char *)data, (int)size, NULL, NULL, 0) == NULL;
    }
    """

    assert main.classify_input_target(harness_code=harness_code) == "structured_text_parser"
    assert main.infer_input_generation_mode("xml parser branch context", harness_code) == "text_direct"


def test_apply_target_class_route_policy_only_for_structured_text():
    base_route = {
        "allow_direct_generation": False,
        "prefer_batch_mutation": True,
        "prefer_input_mutation": True,
        "prefer_state_guided": True,
    }
    base_ab = {
        "path_ab_enabled": True,
        "path_a_enabled": True,
        "path_b_enabled": True,
        "auto_enabled": True,
        "reason": "baseline",
    }

    structured = main.apply_target_class_route_policy(
        "structured_text_parser",
        generation_mode="binary_script",
        route_preferences=base_route,
        path_ab_policy=base_ab,
    )
    assert structured["generation_mode"] == "text_direct"
    assert structured["prefer_direct_text_generation"] is True
    assert structured["route_preferences"]["prefer_state_guided"] is False
    assert structured["path_ab_policy"]["path_ab_enabled"] is False

    code_like = main.apply_target_class_route_policy(
        "code_like_text",
        generation_mode="text_direct",
        route_preferences=base_route,
        path_ab_policy=base_ab,
    )
    assert code_like["generation_mode"] == "text_direct"
    assert code_like["route_preferences"]["prefer_state_guided"] is True
    assert code_like["path_ab_policy"]["path_ab_enabled"] is True


def test_normalize_parser_stderr_detects_xml_mismatch():
    stderr_text = "Opening and ending tag mismatch: foo line 1 and bar\nrecovering"

    assert main.normalize_parser_stderr(stderr_text) == "xml_mismatched_tag"
    assert main.score_parser_depth(stderr_text) >= 2


def test_structured_text_progress_requires_real_signal(monkeypatch):
    monkeypatch.setattr(main, "_seed_eval_target_class", lambda target_context=None: "structured_text_parser")

    assert not main._seed_eval_indicates_local_progress(_base_eval(exec_ok=True))
    assert main._seed_eval_indicates_local_progress(_base_eval(exec_ok=True, stderr_novel=True))
    assert main._seed_eval_indicates_local_progress(_base_eval(exec_ok=True, parser_depth_score=2))
    assert main._seed_eval_indicates_local_progress(_base_eval(exec_ok=True, frontier_advance=True))


def test_code_like_progress_accepts_file_or_parser_hits(monkeypatch):
    monkeypatch.setattr(main, "_seed_eval_target_class", lambda target_context=None: "code_like_text")

    assert not main._seed_eval_indicates_local_progress(_base_eval(exec_ok=True))
    assert main._seed_eval_indicates_local_progress(_base_eval(exec_ok=True, target_file_hit=True))
    assert main._seed_eval_indicates_local_progress(_base_eval(exec_ok=True, parse_family_hit=True))
    assert main._seed_eval_indicates_local_progress(_base_eval(exec_ok=True, frontier_advance=True))


def test_evaluate_seed_uses_runtime_and_coverage_feedback(monkeypatch, tmp_path):
    seed_path = tmp_path / "seed.xml"
    seed_path.write_text("<a></b>", encoding="utf-8")

    monkeypatch.setattr(main, "COV_TARGET_PATH", "/bin/true")
    monkeypatch.setattr(main, "PROJECT", "xmllint")
    monkeypatch.setattr(
        main,
        "cached_format_info",
        {"format_name": "xml", "format_description": "xml parser"},
    )
    monkeypatch.setattr(main, "_execute_seed_and_capture", lambda seed_path, harness_code=None: (True, "Opening and ending tag mismatch at line 1"))
    monkeypatch.setattr(main, "_build_seed_profdata", lambda seed_path: Path("/tmp/fake.profdata"))
    monkeypatch.setattr(main, "_call_chain_file_candidates", lambda call_chain: ["parser.c"])

    def fake_cov_show(file_name, profdata_path):
        if file_name == "target.c":
            return "  42|  3| hit line\n"
        if file_name == "parser.c":
            return "  10|  1| parser hit\n"
        return ""

    monkeypatch.setattr(main, "_llvm_cov_show_file", fake_cov_show)
    monkeypatch.setattr(main, "_seed_stderr_cluster_history", defaultdict(set))

    result = main.evaluate_seed(
        str(seed_path),
        {
            "roadblock": {"filename": "target.c", "line": 42, "function": "parse_target"},
            "call_chain": ["parse_target"],
            "harness_code": "xmlReadMemory(buf, len, NULL, NULL, 0)",
        },
    )

    assert result.exec_ok is True
    assert result.parse_family_hit is True
    assert result.target_file_hit is True
    assert result.target_line_window_hit is True
    assert result.stderr_cluster == "xml_mismatched_tag"
    assert result.stderr_novel is True
    assert result.coverage_gain_class == "target_line_window_hit"


def test_compute_new_coverage_features_tracks_incremental_branch_hits(monkeypatch):
    monkeypatch.setattr(main, "_seed_coverage_feature_history", defaultdict(set))
    profdata_path = Path("/tmp/fake.profdata")
    target_context = {"roadblock": {"filename": "target.c", "line": 10, "function": "parse_target"}}

    monkeypatch.setattr(
        main,
        "_export_one_sided_branch_features",
        lambda profdata: {
            ("a.c", 10, "true"),
            ("b.c", 20, "false"),
        },
    )
    assert main._compute_new_coverage_features(profdata_path, target_context) == 2
    assert main._compute_new_coverage_features(profdata_path, target_context) == 0

    monkeypatch.setattr(
        main,
        "_export_one_sided_branch_features",
        lambda profdata: {
            ("a.c", 10, "true"),
            ("b.c", 20, "false"),
            ("c.c", 30, "true"),
        },
    )
    assert main._compute_new_coverage_features(profdata_path, target_context) == 1


def test_evaluate_seed_reports_new_edges_from_coverage_export(monkeypatch, tmp_path):
    seed_path = tmp_path / "seed.json"
    seed_path.write_text('{"a":1}', encoding="utf-8")

    monkeypatch.setattr(main, "COV_TARGET_PATH", "/bin/true")
    monkeypatch.setattr(main, "PROJECT", "demo")
    monkeypatch.setattr(
        main,
        "cached_format_info",
        {"format_name": "source", "format_description": "code-like text input"},
    )
    monkeypatch.setattr(main, "_execute_seed_and_capture", lambda seed_path, harness_code=None: (True, ""))
    monkeypatch.setattr(main, "_build_seed_profdata", lambda seed_path: Path("/tmp/fake.profdata"))
    monkeypatch.setattr(main, "_call_chain_file_candidates", lambda call_chain: [])
    monkeypatch.setattr(main, "_llvm_cov_show_file", lambda file_name, profdata_path: "")
    monkeypatch.setattr(main, "_compute_new_coverage_features", lambda profdata_path, target_context: 3)
    monkeypatch.setattr(main, "_seed_stderr_cluster_history", defaultdict(set))

    result = main.evaluate_seed(
        str(seed_path),
        {
            "roadblock": {"filename": "target.c", "line": 99, "function": "target"},
            "call_chain": [],
            "harness_code": "parseSource(buf)",
        },
    )

    assert result.new_edges == 3
    assert result.coverage_gain_class == "new_edges"


def test_mark_frontier_advance_when_closest_hit_moves_forward(monkeypatch):
    monkeypatch.setattr(main, "_seed_frontier_history", defaultdict(dict))
    target_context = {"roadblock": {"filename": "target.c", "line": 100, "function": "parse_target"}}

    advanced1 = main._mark_frontier_advance(
        target_context=target_context,
        closest_hit_line_distance=30,
        deepest_call_chain_hit_index=0,
        parser_depth_score=1,
    )
    advanced2 = main._mark_frontier_advance(
        target_context=target_context,
        closest_hit_line_distance=12,
        deepest_call_chain_hit_index=0,
        parser_depth_score=1,
    )
    advanced3 = main._mark_frontier_advance(
        target_context=target_context,
        closest_hit_line_distance=15,
        deepest_call_chain_hit_index=0,
        parser_depth_score=1,
    )

    assert advanced1 is True
    assert advanced2 is True
    assert advanced3 is False


def test_evaluate_seed_marks_frontier_advance_when_target_distance_improves(monkeypatch, tmp_path):
    seed_path = tmp_path / "seed.xml"
    seed_path.write_text("<a></b>", encoding="utf-8")

    monkeypatch.setattr(main, "COV_TARGET_PATH", "/bin/true")
    monkeypatch.setattr(main, "PROJECT", "xmllint")
    monkeypatch.setattr(main, "cached_format_info", {"format_name": "xml", "format_description": "xml parser"})
    monkeypatch.setattr(main, "_execute_seed_and_capture", lambda seed_path, harness_code=None: (True, ""))
    monkeypatch.setattr(main, "_build_seed_profdata", lambda seed_path: Path("/tmp/fake.profdata"))
    monkeypatch.setattr(main, "_compute_new_coverage_features", lambda profdata_path, target_context: 0)
    monkeypatch.setattr(main, "_seed_stderr_cluster_history", defaultdict(set))
    monkeypatch.setattr(main, "_seed_frontier_history", defaultdict(dict))
    monkeypatch.setattr(main, "_call_chain_file_candidates", lambda call_chain: ["pre.c", "target.c"])

    reports = {
        "target.c": "  88|  1| pre-hit\n",
        "pre.c": "  10|  1| parser hit\n",
    }
    monkeypatch.setattr(main, "_llvm_cov_show_file", lambda file_name, profdata_path: reports.get(file_name, ""))

    target_context = {
        "roadblock": {"filename": "target.c", "line": 140, "function": "parse_target"},
        "call_chain": ["pre", "target"],
        "harness_code": "xmlReadMemory(buf, len, NULL, NULL, 0)",
    }

    first = main.evaluate_seed(str(seed_path), target_context)
    assert first.frontier_advance is True
    assert first.closest_hit_line_distance == 52
    assert first.coverage_gain_class == "target_file_hit"

    reports["target.c"] = "  95|  1| deeper hit\n"
    second = main.evaluate_seed(str(seed_path), target_context)
    assert second.frontier_advance is True
    assert second.closest_hit_line_distance == 45
    assert second.coverage_gain_class == "target_file_hit"
