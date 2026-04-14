from __future__ import annotations

import tempfile
from pathlib import Path

from breaker.bottleneck import choose_structured_text_candidates
from breaker.executor import execute_target
from breaker.models import BreakerConfig, BreakerLoopResult, MutationCandidate, ScoredCandidate
from breaker.scorer import score_exec_result


def run_breaker_loop(cfg: BreakerConfig) -> BreakerLoopResult:
    baseline = execute_target(
        seed_path=cfg.seed_path,
        target_command=cfg.target_command,
        target_hint=cfg.target_hint,
        timeout_sec=cfg.timeout_sec,
        harness_code=cfg.harness_code,
    )

    seed_text = cfg.seed_path.read_text(encoding="utf-8", errors="replace")
    candidates = choose_structured_text_candidates(
        seed_text,
        diagnostics_family=baseline.diagnostics_family,
        max_candidates=cfg.max_candidates,
    )

    attempted: list[ScoredCandidate] = []
    best: ScoredCandidate | None = None
    temp_root = Path(tempfile.mkdtemp(prefix="breaker-loop-", dir=os_fspath_or_none(cfg.output_dir)))
    for index, candidate in enumerate(candidates):
        candidate_path = temp_root / f"candidate_{index:02d}.xml"
        candidate_path.write_text(candidate.text, encoding="utf-8")
        exec_result = execute_target(
            seed_path=candidate_path,
            target_command=cfg.target_command,
            target_hint=cfg.target_hint,
            timeout_sec=cfg.timeout_sec,
            harness_code=cfg.harness_code,
        )
        score, breakdown = score_exec_result(exec_result, baseline)
        scored = ScoredCandidate(
            candidate=candidate,
            seed_path=candidate_path,
            exec_result=exec_result,
            score=score,
            score_breakdown=breakdown,
        )
        attempted.append(scored)
        if best is None or scored.score > best.score:
            best = scored

    return BreakerLoopResult(
        baseline=baseline,
        best=best,
        attempted=attempted,
        feedback_summary=_build_feedback_summary(baseline, best, attempted),
    )


def _build_feedback_summary(baseline, best, attempted: list[ScoredCandidate]) -> str:
    lines = [
        f"baseline_family={baseline.diagnostics_family}",
        f"baseline_rc={baseline.return_code}",
        f"candidates={len(attempted)}",
    ]
    if best is not None:
        lines.extend(
            [
                f"best_action={best.candidate.action}",
                f"best_family={best.exec_result.diagnostics_family}",
                f"best_rc={best.exec_result.return_code}",
                f"best_score={best.score:.2f}",
                f"target_file_hit={best.exec_result.target_file_hit}",
                f"target_line_window_hit={best.exec_result.target_line_window_hit}",
            ]
        )
    return " | ".join(lines)


def os_fspath_or_none(path: Path | None) -> str | None:
    if path is None:
        return None
    path.mkdir(parents=True, exist_ok=True)
    return str(path)

