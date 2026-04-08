import hashlib
import json
import logging
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from config import LOGGER_NAME

logger = logging.getLogger(LOGGER_NAME + __name__)


def _same_source_file(lhs: str, rhs: str) -> bool:
    if not lhs or not rhs:
        return False
    return lhs == rhs or Path(lhs).name == Path(rhs).name


@dataclass
class DynamicTraceSummary:
    seed_name: str
    target_file: str
    target_line: int
    trace_complete: bool
    target_hit: bool
    functions_seen: list[str] = field(default_factory=list)
    call_path: list[str] = field(default_factory=list)
    dynamic_call_edges: dict[str, list[str]] = field(default_factory=dict)
    executed_locations: dict[str, list[int]] = field(default_factory=dict)
    branch_window: dict[str, list[int]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict) -> "DynamicTraceSummary":
        return cls(**payload)


class TraceSummaryBuilder:
    def __init__(
        self,
        seed_name: str,
        target_file: str,
        target_line: int,
        window: int = 20,
        max_events: int = 50000,
    ) -> None:
        self.seed_name = seed_name
        self.target_file = target_file
        self.target_line = int(target_line)
        self.window = max(1, int(window))
        self.max_events = max(1, int(max_events))

        self._events = 0
        self._target_hit = False
        self._trace_complete = True
        self._stack: list[str] = []
        self._functions_seen: list[str] = []
        self._functions_seen_set: set[str] = set()
        self._call_path: list[str] = []
        self._dynamic_call_edges: dict[str, set[str]] = defaultdict(set)
        self._executed_locations: dict[str, set[int]] = defaultdict(set)
        self._branch_window: dict[str, set[int]] = defaultdict(set)
        self._recent_locations: deque[tuple[str, int, Optional[str]]] = deque(maxlen=self.window)
        self._post_target_events_remaining = 0
        self._relevant_functions: set[str] = set()

    def _mark_incomplete(self) -> None:
        self._trace_complete = False

    def _remember_function(self, func_name: str) -> None:
        if func_name and func_name not in self._functions_seen_set:
            self._functions_seen.append(func_name)
            self._functions_seen_set.add(func_name)

    def _record_location(self, file_name: str, line_no: int, func_name: Optional[str]) -> None:
        if not file_name or line_no <= 0:
            return
        self._recent_locations.append((file_name, line_no, func_name))

        if self._target_hit:
            if func_name and func_name in self._relevant_functions:
                self._executed_locations[file_name].add(line_no)
            if _same_source_file(file_name, self.target_file) and abs(line_no - self.target_line) <= self.window:
                self._branch_window[file_name].add(line_no)
            return

        if _same_source_file(file_name, self.target_file) and abs(line_no - self.target_line) <= self.window:
            self._branch_window[file_name].add(line_no)

    def _record_target_hit(self) -> None:
        if self._target_hit:
            return
        self._target_hit = True
        self._call_path = list(self._stack)
        self._relevant_functions.update(self._call_path)
        self._post_target_events_remaining = self.window
        for file_name, line_no, func_name in self._recent_locations:
            if func_name and func_name in self._relevant_functions:
                self._executed_locations[file_name].add(line_no)
            if _same_source_file(file_name, self.target_file) and abs(line_no - self.target_line) <= self.window:
                self._branch_window[file_name].add(line_no)

    def consume_event(self, event: dict) -> bool:
        self._events += 1
        if self._events > self.max_events:
            self._mark_incomplete()
            return False

        event_type = event.get("event")
        if event_type == "F":
            func_name = event.get("name") or ""
            if self._stack:
                self._dynamic_call_edges[self._stack[-1]].add(func_name)
            self._stack.append(func_name)
            self._remember_function(func_name)
            return True

        if event_type == "R":
            func_name = event.get("name") or ""
            while self._stack:
                popped = self._stack.pop()
                if popped == func_name:
                    break
            return not (self._target_hit and self._post_target_events_remaining <= 0)

        if event_type != "B":
            return True

        file_name = event.get("name") or ""
        begin = int(event.get("begin", 0) or 0)
        end = int(event.get("end", 0) or 0)
        current_func = self._stack[-1] if self._stack else None
        for line_no in range(begin, end + 1):
            self._record_location(file_name, line_no, current_func)

        if _same_source_file(file_name, self.target_file) and begin <= self.target_line <= end:
            self._record_target_hit()

        if self._target_hit:
            self._post_target_events_remaining -= 1
            if self._post_target_events_remaining <= 0:
                return False
        return True

    def build(self, trace_complete: bool = True) -> DynamicTraceSummary:
        completed = bool(trace_complete and self._trace_complete)
        return DynamicTraceSummary(
            seed_name=self.seed_name,
            target_file=self.target_file,
            target_line=self.target_line,
            trace_complete=completed,
            target_hit=self._target_hit,
            functions_seen=list(self._functions_seen),
            call_path=list(self._call_path),
            dynamic_call_edges={key: sorted(values) for key, values in self._dynamic_call_edges.items()},
            executed_locations={key: sorted(values) for key, values in self._executed_locations.items()},
            branch_window={key: sorted(values) for key, values in self._branch_window.items()},
        )


class DynamicTraceCache:
    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def build_fingerprint(trace_binary: Path, source_root: Path, bitcode_path: Optional[Path] = None) -> str:
        hasher = hashlib.sha256()
        for candidate in (trace_binary, source_root, bitcode_path):
            if not candidate:
                continue
            path = Path(candidate)
            hasher.update(path.as_posix().encode("utf-8", errors="ignore"))
            try:
                stat = path.stat()
            except OSError:
                continue
            hasher.update(str(int(stat.st_mtime)).encode("ascii"))
            hasher.update(str(int(stat.st_size)).encode("ascii"))
        return hasher.hexdigest()[:16]

    def _cache_path(self, project: str, roadblock: str, seed_name: str, fingerprint: str) -> Path:
        key = f"{project}:{roadblock}:{seed_name}:{fingerprint}"
        digest = hashlib.sha256(key.encode("utf-8", errors="ignore")).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def load(self, project: str, roadblock: str, seed_name: str, fingerprint: str) -> Optional[DynamicTraceSummary]:
        cache_path = self._cache_path(project, roadblock, seed_name, fingerprint)
        if not cache_path.exists():
            return None
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            return DynamicTraceSummary.from_dict(payload)
        except Exception as exc:
            logger.warning("[DYN_TRACE] Failed to load cache %s: %s", cache_path, exc)
            return None

    def save(self, project: str, roadblock: str, seed_name: str, fingerprint: str, summary: DynamicTraceSummary) -> None:
        cache_path = self._cache_path(project, roadblock, seed_name, fingerprint)
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(summary.to_dict(), f, ensure_ascii=False, indent=2)
        except Exception as exc:
            logger.warning("[DYN_TRACE] Failed to save cache %s: %s", cache_path, exc)
