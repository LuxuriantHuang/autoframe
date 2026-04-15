from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

import config
from attempt_scheduler import SchedulerCandidate
from runner_bootstrap import bootstrap_project, build_runtime_objects, runtime_root
from runtime_protocol import (
    read_json,
    solver_claim_path,
    solver_tasks_path,
    worker_state_path,
    write_json_atomic,
)


PATH_BASE_SCORES = {
    "direct_generation": 20.0,
    "flag": 19.0,
    "taint_mutation": 18.0,
    "state_driven": 17.0,
    "field_mutation": 16.0,
    "xml_grammar": 15.0,
    "batch_mutation": 14.0,
}

PATH_ENABLE_FLAGS = {
    "direct_generation": "ENABLE_SIMPLIFIED_DIRECT_GENERATION_PATH",
    "flag": "ENABLE_SIMPLIFIED_FLAG_PATH",
    "taint_mutation": "ENABLE_SIMPLIFIED_TAINT_MUTATION_PATH",
    "state_driven": "ENABLE_SIMPLIFIED_STATE_DRIVEN_PATH",
    "field_mutation": "ENABLE_SIMPLIFIED_FIELD_MUTATION_PATH",
    "xml_grammar": "ENABLE_SIMPLIFIED_XML_GRAMMAR_PATH",
    "batch_mutation": "ENABLE_SIMPLIFIED_BATCH_MUTATION_PATH",
}

PATH_WORKER_ATTEMPT_LIMIT = 3
TASK_LEASE_SECONDS = 900.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one AutoFrame path program as a standalone worker")
    parser.add_argument("--path", default=None)
    parser.add_argument("--worker-id", default=None)
    parser.add_argument("--runtime-root", default=None)
    parser.add_argument("--output-dir", default="out")
    parser.add_argument("--project", default=None)
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--exec-args", default=None)
    return parser.parse_args()


def _path_enabled(path_name: str) -> bool:
    flag_name = PATH_ENABLE_FLAGS[path_name]
    enabled = bool(getattr(config, flag_name))
    if path_name == "state_driven":
        enabled = enabled and bool(config.ENABLE_STATE_DRIVEN_PATH_B)
    return enabled


def _build_scheduler(core, path_name: str):
    scheduler_runtime = Path(config.RUN_RUNTIME_PATH) / "scheduler"
    scheduler_runtime.mkdir(parents=True, exist_ok=True)
    if path_name == "direct_generation":
        return core.DirectGenerationScheduler(scheduler_runtime)
    return core.SimplifiedPathScheduler(path_name, scheduler_runtime, base_score=PATH_BASE_SCORES[path_name])


def _write_state(root: Path, path_name: str, payload: dict) -> None:
    worker_id = str(payload.get("worker_id") or f"pid_{os.getpid()}")
    write_json_atomic(worker_state_path(root, path_name, worker_id), payload)


def _read_solver_candidates(
    *,
    core,
    root: Path,
    path_name: str,
) -> tuple[list[dict], dict]:
    payload = read_json(
        solver_tasks_path(root),
        {
            "solver_window_open": False,
            "coverage": {},
            "tasks": [],
        },
    )
    if not payload.get("solver_window_open", False):
        return [], payload

    now = time.time()
    candidates = []
    for task in payload.get("tasks", []):
        if task.get("task_type") != "roadblock":
            continue
        if not task.get("eligible", False):
            continue
        roadblock = (task.get("payload") or {}).get("roadblock")
        if not isinstance(roadblock, dict):
            continue
        roadblock_key = str(roadblock.get("roadblock_key") or "").strip()
        if not roadblock_key:
            continue
        claim_payload = read_json(solver_claim_path(root, str(task.get("task_id") or roadblock_key)), {})
        lease_owner = str(claim_payload.get("lease_owner") or "")
        lease_expires_at = float(claim_payload.get("lease_expires_at") or 0.0)
        if lease_owner and lease_expires_at > now and lease_owner != f"{path_name}:{os.getpid()}":
            continue
        candidates.append(roadblock)
    return core.PlateauAttemptOrchestrator.prepare_roadblocks(candidates), payload


def _claim_candidate(root: Path, path_name: str, candidate: SchedulerCandidate) -> tuple[bool, str]:
    task_id = f"roadblock:{candidate.target_key}"
    owner = f"{path_name}:{os.getpid()}"
    claim_path = solver_claim_path(root, task_id)
    now = time.time()
    claim_payload = read_json(claim_path, {})
    lease_owner = str(claim_payload.get("lease_owner") or "")
    lease_expires_at = float(claim_payload.get("lease_expires_at") or 0.0)
    if lease_owner and lease_expires_at > now and lease_owner != owner:
        return False, owner
    write_json_atomic(
        claim_path,
        {
            "task_id": task_id,
            "target_key": candidate.target_key,
            "path_name": path_name,
            "candidate_key": candidate.candidate_key,
            "lease_owner": owner,
            "lease_acquired_at": now,
            "lease_expires_at": now + TASK_LEASE_SECONDS,
            "updated_at": now,
        },
    )
    return True, owner


def _finalize_candidate_claim(
    root: Path,
    path_name: str,
    candidate: SchedulerCandidate,
    *,
    owner: str,
    result_mode: str,
    attempted: bool,
    success: bool,
    coverage_breakthrough: bool,
) -> None:
    task_id = f"roadblock:{candidate.target_key}"
    claim_path = solver_claim_path(root, task_id)
    current = read_json(claim_path, {})
    if str(current.get("lease_owner") or "") not in {"", owner}:
        return
    now = time.time()
    write_json_atomic(
        claim_path,
        {
            "task_id": task_id,
            "target_key": candidate.target_key,
            "path_name": path_name,
            "candidate_key": candidate.candidate_key,
            "lease_owner": owner,
            "lease_expires_at": now,
            "completed_at": now,
            "result_mode": result_mode,
            "attempted": bool(attempted),
            "success": bool(success),
            "coverage_breakthrough": bool(coverage_breakthrough),
            "updated_at": now,
        },
    )


def run_path_program(path_name: str) -> None:
    args = parse_args()
    if args.path and args.path != path_name:
        raise ValueError(f"Path runner mismatch: expected {path_name}, got {args.path}")
    core = bootstrap_project(
        project=args.project,
        output_dir=args.output_dir,
        test_mode=args.test,
        exec_args=args.exec_args,
        logger_component=f"path-{path_name}",
        console_logging_mode="lifecycle",
    )
    if not _path_enabled(path_name):
        core.logger.info(f"[PATH:{path_name}] Path disabled, exiting")
        return

    tracer, llm_util, _ = build_runtime_objects(core)
    root = Path(args.runtime_root) if args.runtime_root else runtime_root()
    worker_id = str(args.worker_id or f"pid_{os.getpid()}")
    state_payload = {
        "path_name": path_name,
        "worker_id": worker_id,
        "started": True,
        "completed": False,
        "attempted": False,
        "coverage_breakthrough_seen": False,
        "mode": "",
        "input_mode": "",
        "last_target": "",
        "attempt_count": 0,
        "error": "",
        "updated_at": time.time(),
    }
    _write_state(root, path_name, state_payload)
    core.logger.info(f"[PATH:{path_name}] Worker started (worker_id={worker_id})")

    try:
        scheduler = _build_scheduler(core, path_name)
        attempts = 0
        while attempts < PATH_WORKER_ATTEMPT_LIMIT:
            task_roadblocks, task_payload = _read_solver_candidates(core=core, root=root, path_name=path_name)
            if not task_roadblocks:
                state_payload["completed"] = True
                state_payload["error"] = "no_eligible_candidates"
                break

            roadblocks = task_roadblocks
            stuck_time = float((task_payload.get("coverage") or {}).get("stuck_time") or 0.0)
            state_payload["input_mode"] = "solver_tasks"

            context = core.PlateauAttemptContext(
                tracer=tracer,
                llm_util=llm_util,
                stuck_time=stuck_time,
                roadblocks=roadblocks,
                last_scan_time=0,
                read_files=set(),
            )
            candidate: SchedulerCandidate | None = scheduler.select_candidate(context)
            if candidate is None:
                state_payload["completed"] = True
                state_payload["error"] = "no_eligible_candidates"
                break

            state_payload["last_target"] = candidate.target_key
            state_payload["attempt_count"] = attempts + 1
            _write_state(root, path_name, {**state_payload, "updated_at": time.time()})

            claim_acquired, claim_owner = _claim_candidate(root, path_name, candidate)
            if not claim_acquired:
                state_payload["error"] = "task_claim_conflict"
                state_payload["updated_at"] = time.time()
                attempts += 1
                continue

            result = scheduler.execute(candidate, context)
            scheduler.record_result(candidate, result)
            _finalize_candidate_claim(
                root,
                path_name,
                candidate,
                owner=claim_owner,
                result_mode=result.mode,
                attempted=result.attempted,
                success=result.success,
                coverage_breakthrough=result.coverage_breakthrough,
            )

            attempts += 1
            state_payload["attempted"] = state_payload["attempted"] or bool(result.attempted)
            state_payload["mode"] = result.mode
            state_payload["coverage_breakthrough_seen"] = bool(result.coverage_breakthrough)
            state_payload["updated_at"] = time.time()

            if result.coverage_breakthrough:
                state_payload["completed"] = True
                break
            if not result.attempted:
                state_payload["completed"] = True
                state_payload["error"] = result.mode
                break

        if not state_payload["completed"]:
            state_payload["completed"] = True
            if not state_payload["coverage_breakthrough_seen"]:
                state_payload["error"] = state_payload["error"] or "attempt_limit_reached"
    except KeyboardInterrupt:
        state_payload["completed"] = True
        state_payload["error"] = "keyboard_interrupt"
        raise
    except Exception as exc:
        state_payload["completed"] = True
        state_payload["error"] = str(exc)
        core.logger.critical(f"[PATH:{path_name}] Path runner failed: {exc}", exc_info=True)
    finally:
        _write_state(root, path_name, {**state_payload, "updated_at": time.time()})
        core.logger.info(
            f"[PATH:{path_name}] Worker completed "
            f"(attempted={state_payload['attempted']}, "
            f"coverage_breakthrough_seen={state_payload['coverage_breakthrough_seen']}, "
            f"error={state_payload['error'] or 'none'})"
        )
        tracer.shutdown_background_workers(wait=False)
