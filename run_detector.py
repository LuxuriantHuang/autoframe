from __future__ import annotations

import argparse
import time
from typing import Any

import config
from runner_bootstrap import bootstrap_project, build_runtime_objects, runtime_root
from runtime_protocol import (
    read_json,
    solver_tasks_path,
    trace_monitor_state_path,
    write_json_atomic,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detector/trace producer for AutoFrame multi-process mode")
    parser.add_argument("--project", default=None)
    parser.add_argument("-o", "--output-dir", dest="output_dir", default="out")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--exec-args", dest="exec_args", default=None)
    return parser.parse_args()


def _write_trace_monitor_state(runtime_root_path, payload):
    write_json_atomic(trace_monitor_state_path(runtime_root_path), payload)

def _write_solver_tasks(runtime_root_path, payload):
    write_json_atomic(solver_tasks_path(runtime_root_path), payload)


def _build_trace_monitor_state(
    *,
    stuck_time: float,
    edges_found: int,
    prepared_roadblocks: list[dict[str, Any]],
    trace_ret: bool | None,
    trace_error: str,
    source: str,
) -> dict[str, Any]:
    return {
        "updated_at": time.time(),
        "source": source,
        "solver_window": {
            "open": bool(stuck_time >= config.THRESHOLD_TIME),
            "threshold_seconds": int(config.THRESHOLD_TIME),
        },
        "coverage": {
            "edges_found": int(edges_found),
            "stuck_time": float(stuck_time),
            "last_growth_time": time.time() - float(stuck_time),
        },
        "trace": {
            "attempted": trace_ret is not None,
            "success": bool(trace_ret) if trace_ret is not None else False,
            "error": trace_error,
            "roadblock_count": len(prepared_roadblocks),
        },
        "roadblocks": prepared_roadblocks,
    }


def _build_solver_tasks(
    *,
    stuck_time: float,
    edges_found: int,
    prepared_roadblocks: list[dict[str, Any]],
) -> dict[str, Any]:
    is_solver_window = stuck_time >= config.THRESHOLD_TIME
    now = time.time()
    tasks = []
    for index, roadblock in enumerate(prepared_roadblocks):
        roadblock_key = str(roadblock.get("roadblock_key") or "").strip()
        if not roadblock_key:
            continue
        tasks.append(
            {
                "task_id": f"roadblock:{roadblock_key}",
                "task_type": "roadblock",
                "status": "pending",
                "lease_owner": "",
                "lease_expires_at": 0.0,
                "created_at": now,
                "updated_at": now,
                "priority": index,
                "eligible": bool(is_solver_window),
                "target_key": roadblock_key,
                "coverage": {
                    "edges_found": int(edges_found),
                    "stuck_time": float(stuck_time),
                    "last_growth_time": now - float(stuck_time),
                },
                "payload": {
                    "roadblock": roadblock,
                },
            }
        )
    return {
        "updated_at": now,
        "schema_version": 1,
        "producer": "trace-monitor",
        "solver_window": {
            "open": bool(is_solver_window),
            "threshold_seconds": int(config.THRESHOLD_TIME),
        },
        "coverage": {
            "edges_found": int(edges_found),
            "stuck_time": float(stuck_time),
            "last_growth_time": now - float(stuck_time),
        },
        "solver_window_open": bool(is_solver_window),
        "task_count": len(tasks),
        "tasks": tasks,
    }


def _extract_prepared_roadblocks(core, tracer, read_files, last_scan_time):
    ret, next_scan_time, error_info, roadblocks = tracer.get_trace(read_files, last_scan_time)
    tracer.kick_autobug_prime_async()
    if "没有新的seed" in error_info and not roadblocks:
        roadblocks = tracer.get_current_one_sided_branches()
    elif not ret:
        roadblocks = []
    prepared = core.PlateauAttemptOrchestrator.prepare_roadblocks(roadblocks)
    return ret, next_scan_time, error_info, prepared


def main():
    args = parse_args()
    core = bootstrap_project(
        project=args.project,
        output_dir=args.output_dir,
        test_mode=args.test,
        exec_args=args.exec_args,
        logger_component="detector",
        console_logging_mode="lifecycle",
    )
    tracer, _, _ = build_runtime_objects(core)
    root = runtime_root()
    read_files = set()
    last_scan_time = 0

    core.logger.info("[DETECTOR] Detector loop started")
    try:
        while True:
            if not args.test:
                try:
                    core.check_fuzzer_alive()
                except core.FuzzerProcessDiedError as exc:
                    core.logger.critical(f"[{core.LogOp.FUZZER}] {exc}")
                    break

            tracer.poll_autobug_seed_queue()
            stuck_time = tracer.check_coverage_growth()
            tracer.kick_autobug_prime_async()
            stats = tracer._read_fuzzer_stats_summary()
            edges_found = int(stats.get("edges_found") or tracer.last_coverage or 0)
            trace_ret, last_scan_time, trace_error, prepared_roadblocks = _extract_prepared_roadblocks(
                core,
                tracer,
                read_files,
                last_scan_time,
            )
            trace_source = "solver_window_open" if stuck_time >= config.THRESHOLD_TIME else "coverage_poll"
            if not trace_ret and trace_error and "没有新的seed" not in trace_error:
                core.logger.warning(f"[DETECTOR] Coverage trace extraction failed: {trace_error}")

            monitor_payload = _build_trace_monitor_state(
                stuck_time=stuck_time,
                edges_found=edges_found,
                prepared_roadblocks=prepared_roadblocks,
                trace_ret=trace_ret,
                trace_error=trace_error,
                source=trace_source,
            )
            _write_trace_monitor_state(root, monitor_payload)
            _write_solver_tasks(
                root,
                _build_solver_tasks(
                    stuck_time=stuck_time,
                    edges_found=edges_found,
                    prepared_roadblocks=prepared_roadblocks,
                ),
            )

            time.sleep(config.CHECK_INTERVAL)
    except KeyboardInterrupt:
        core.logger.info("[DETECTOR] Keyboard interrupt detected")
    finally:
        tracer.shutdown_background_workers(wait=False)
        core.logger.info("[DETECTOR] Detector terminated")


if __name__ == "__main__":
    main()
