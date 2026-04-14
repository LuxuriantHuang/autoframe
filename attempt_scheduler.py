from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SchedulerCandidate:
    path_name: str
    candidate_key: str
    target_key: str
    prepared_context_ref: str
    score: float
    payload: dict[str, Any] = field(default_factory=dict)
    cooldown_until: float = 0.0
    failure_count: int = 0
    selection_count: int = 0


@dataclass
class SchedulerResult:
    attempted: bool
    success: bool
    mode: str
    coverage_breakthrough: bool = False


class AttemptScheduler:
    def __init__(self, path_name: str, state_path: Path):
        self.path_name = path_name
        self.state_path = state_path
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.interesting_scores: dict[str, float] = {}
        self.failure_counts: dict[str, int] = {}
        self.cooldown_until: dict[str, float] = {}
        self.selection_counts: dict[str, int] = {}
        self.last_selected_key: str | None = None
        self._load()

    def _load(self) -> None:
        if not self.state_path.exists():
            return
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return
        self.interesting_scores = {
            str(key): float(value) for key, value in (payload.get("interesting_scores") or {}).items()
        }
        self.failure_counts = {
            str(key): int(value) for key, value in (payload.get("failure_counts") or {}).items()
        }
        self.cooldown_until = {
            str(key): float(value) for key, value in (payload.get("cooldown_until") or {}).items()
        }
        self.selection_counts = {
            str(key): int(value) for key, value in (payload.get("selection_counts") or {}).items()
        }
        self.last_selected_key = str(payload.get("last_selected_key") or "") or None

    def _save(self) -> None:
        payload = {
            "updated_at": time.time(),
            "path_name": self.path_name,
            "interesting_scores": self.interesting_scores,
            "failure_counts": self.failure_counts,
            "cooldown_until": self.cooldown_until,
            "selection_counts": self.selection_counts,
            "last_selected_key": self.last_selected_key or "",
        }
        self.state_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def sync_candidates(self, candidates: list[SchedulerCandidate]) -> list[SchedulerCandidate]:
        active_keys = {candidate.candidate_key for candidate in candidates}
        for candidate in candidates:
            self.interesting_scores.setdefault(candidate.candidate_key, 0.0)
            self.failure_counts.setdefault(candidate.candidate_key, 0)
            self.selection_counts.setdefault(candidate.candidate_key, 0)
            candidate.score += float(self.interesting_scores.get(candidate.candidate_key, 0.0))
            candidate.cooldown_until = float(self.cooldown_until.get(candidate.candidate_key, 0.0))
            candidate.failure_count = int(self.failure_counts.get(candidate.candidate_key, 0))
            candidate.selection_count = int(self.selection_counts.get(candidate.candidate_key, 0))

        for mapping in (
            self.interesting_scores,
            self.failure_counts,
            self.cooldown_until,
            self.selection_counts,
        ):
            for stale_key in list(mapping.keys()):
                if stale_key not in active_keys:
                    mapping.pop(stale_key, None)

        if self.last_selected_key and self.last_selected_key not in active_keys:
            self.last_selected_key = None
        self._save()
        return candidates

    def select_candidate(self, candidates: list[SchedulerCandidate]) -> SchedulerCandidate | None:
        if not candidates:
            return None
        now = time.time()
        eligible = [candidate for candidate in candidates if now >= candidate.cooldown_until]
        pool = eligible if eligible else candidates
        if self.last_selected_key and len(pool) > 1:
            non_repeated = [candidate for candidate in pool if candidate.candidate_key != self.last_selected_key]
            if non_repeated:
                pool = non_repeated

        best_rank = max(
            (candidate.score, -candidate.failure_count, -candidate.selection_count)
            for candidate in pool
        )
        best_candidates = [
            candidate for candidate in pool
            if (candidate.score, -candidate.failure_count, -candidate.selection_count) == best_rank
        ]
        selected = random.choice(best_candidates)
        self.selection_counts[selected.candidate_key] = int(self.selection_counts.get(selected.candidate_key, 0)) + 1
        self.last_selected_key = selected.candidate_key
        selected.selection_count = self.selection_counts[selected.candidate_key]
        self._save()
        return selected

    def record_result(self, candidate: SchedulerCandidate, result: SchedulerResult) -> None:
        key = candidate.candidate_key
        now = time.time()
        score = float(self.interesting_scores.get(key, 0.0))
        failures = int(self.failure_counts.get(key, 0))

        if result.coverage_breakthrough:
            score -= 3.0
            failures = 0
            self.cooldown_until[key] = now + 600.0
        elif result.success:
            score -= 2.0
            failures = 0
            self.cooldown_until[key] = now + 300.0
        elif result.attempted:
            failures += 1
            score -= 1.5
            self.cooldown_until[key] = now + self._cooldown_seconds(failures)
        else:
            failures += 1
            score -= 2.5
            self.cooldown_until[key] = now + self._cooldown_seconds(failures + 1)

        self.interesting_scores[key] = score
        self.failure_counts[key] = failures
        self._save()

    @staticmethod
    def _cooldown_seconds(failure_count: int) -> float:
        failure_count = max(1, int(failure_count))
        return float(min(1800, 60 * (2 ** (failure_count - 1))))
