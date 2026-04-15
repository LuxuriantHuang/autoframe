from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=path.parent, encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
        tmp_name = handle.name
    Path(tmp_name).replace(path)


def read_json(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    if not path.exists():
        return dict(default or {})
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return dict(default or {})


def worker_state_path(runtime_root: Path, path_name: str, worker_id: str) -> Path:
    return runtime_root / "workers" / path_name / f"{worker_id}.json"


def trace_monitor_state_path(runtime_root: Path) -> Path:
    return runtime_root / "monitor" / "state.json"


def solver_tasks_path(runtime_root: Path) -> Path:
    return runtime_root / "tasks" / "roadblocks.json"


def solver_claims_dir(runtime_root: Path) -> Path:
    return runtime_root / "tasks" / "claims"


def solver_claim_path(runtime_root: Path, task_id: str) -> Path:
    digest = hashlib.sha1(task_id.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return solver_claims_dir(runtime_root) / f"{digest}.json"


def launcher_state_path(runtime_root: Path) -> Path:
    return runtime_root / "launcher" / "state.json"
