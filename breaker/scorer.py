from __future__ import annotations

from breaker.models import ExecResult


def score_exec_result(candidate: ExecResult, baseline: ExecResult | None = None) -> tuple[float, dict[str, float]]:
    breakdown: dict[str, float] = {}
    score = 0.0

    if candidate.exec_ok:
        breakdown["exec_ok"] = 1.0
        score += 1.0
    if not candidate.timed_out:
        breakdown["not_timeout"] = 0.5
        score += 0.5
    if candidate.target_file_hit:
        breakdown["target_file_hit"] = 2.0
        score += 2.0
    if candidate.target_line_window_hit:
        breakdown["target_line_window_hit"] = 3.0
        score += 3.0
    if candidate.return_code == 0:
        breakdown["return_code_zero"] = 2.0
        score += 2.0
    elif candidate.return_code != -1:
        breakdown["process_returned"] = 0.5
        score += 0.5

    if candidate.diagnostics_family == "no_error":
        breakdown["no_error"] = 2.0
        score += 2.0
    elif candidate.diagnostics_family not in {"", "unknown_parse_error"}:
        breakdown["recognized_diagnostics"] = 1.0
        score += 1.0

    if baseline is not None:
        if baseline.diagnostics_family != candidate.diagnostics_family:
            breakdown["diagnostic_shift"] = 1.0
            score += 1.0
        if baseline.return_code != 0 and candidate.return_code == 0:
            breakdown["exit_improved"] = 1.5
            score += 1.5
        if baseline.target_line_window_hit is False and candidate.target_line_window_hit:
            breakdown["new_line_window_hit"] = 1.0
            score += 1.0
        if baseline.target_file_hit is False and candidate.target_file_hit:
            breakdown["new_file_hit"] = 0.5
            score += 0.5
        if candidate.runtime_ms < baseline.runtime_ms:
            breakdown["faster_runtime"] = 0.25
            score += 0.25

    return score, breakdown
