from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class TargetHint:
    file_path: str | None = None
    line: int | None = None
    window: int = 12


@dataclass(frozen=True)
class BreakerConfig:
    seed_path: Path
    target_command: str
    target_hint: TargetHint = field(default_factory=TargetHint)
    max_candidates: int = 6
    timeout_sec: int = 10
    project: str | None = None
    output_dir: Path | None = None
    harness_code: str | None = None
    format_info: dict[str, Any] | None = None


@dataclass(frozen=True)
class DiagnosticResult:
    family: str
    message: str
    raw_stderr: str


@dataclass(frozen=True)
class ExecResult:
    exec_ok: bool
    return_code: int
    runtime_ms: float
    stderr_text: str
    stdout_text: str
    target_file_hit: bool
    target_line_window_hit: bool
    diagnostics_family: str
    coverage_report: str = ""
    timed_out: bool = False


@dataclass(frozen=True)
class MutationCandidate:
    text: str
    action: str
    rationale: str = ""
    diagnostics_family: str = ""


@dataclass(frozen=True)
class ScoredCandidate:
    candidate: MutationCandidate
    seed_path: Path
    exec_result: ExecResult
    score: float
    score_breakdown: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class BreakerLoopResult:
    baseline: ExecResult
    best: ScoredCandidate | None
    attempted: list[ScoredCandidate] = field(default_factory=list)
    feedback_summary: str = ""

