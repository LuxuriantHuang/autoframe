from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

import config
from runner_bootstrap import bootstrap_project, runtime_root
from runtime_protocol import launcher_state_path, write_json_atomic

NORMAL_EXIT_RESTART_DELAY_SECONDS = 15.0
MONITOR_NORMAL_EXIT_RESTART_DELAY_SECONDS = 5.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Launcher/manager for AutoFrame worker mode")
    parser.add_argument("--project", default=None)
    parser.add_argument("-o", "--output-dir", dest="output_dir", default="out")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--exec-args", dest="exec_args", default=None)
    return parser.parse_args()


def _enabled_paths() -> list[str]:
    paths = []
    if config.ENABLE_SIMPLIFIED_DIRECT_GENERATION_PATH:
        paths.append("direct_generation")
    if config.ENABLE_SIMPLIFIED_FLAG_PATH:
        paths.append("flag")
    if config.ENABLE_SIMPLIFIED_TAINT_MUTATION_PATH:
        paths.append("taint_mutation")
    if config.ENABLE_SIMPLIFIED_STATE_DRIVEN_PATH and config.ENABLE_STATE_DRIVEN_PATH_B:
        paths.append("state_driven")
    if config.ENABLE_SIMPLIFIED_FIELD_MUTATION_PATH:
        paths.append("field_mutation")
    if config.ENABLE_SIMPLIFIED_XML_GRAMMAR_PATH:
        paths.append("xml_grammar")
    if config.ENABLE_SIMPLIFIED_BATCH_MUTATION_PATH:
        paths.append("batch_mutation")
    return paths


def _base_cmd(script_name: str, args: argparse.Namespace) -> list[str]:
    script_path = Path(__file__).resolve().parent / script_name
    cmd = [sys.executable, os.fspath(script_path), "--output-dir", args.output_dir]
    if args.project:
        cmd.extend(["--project", args.project])
    if args.test:
        cmd.append("--test")
    if args.exec_args is not None:
        cmd.extend(["--exec-args", args.exec_args])
    return cmd


def _spawn_trace_monitor(args: argparse.Namespace) -> subprocess.Popen:
    return subprocess.Popen(_base_cmd("run_trace_monitor.py", args))


def _spawn_worker(path_name: str, args: argparse.Namespace, root: Path, slot: int) -> subprocess.Popen:
    cmd = _base_cmd("run_solver_worker.py", args)
    cmd.extend([
        "--runtime-root",
        os.fspath(root),
        "--path",
        path_name,
        "--worker-id",
        f"{path_name}_{slot}",
    ])
    return subprocess.Popen(cmd)


def _write_launcher_state(root: Path, payload: dict) -> None:
    write_json_atomic(launcher_state_path(root), payload)


def _maybe_restart_process(
    *,
    proc: subprocess.Popen,
    kind: str,
    name: str,
    normal_exit_restart_at: float | None,
    restart_delay_seconds: float,
    spawn_fn,
    logger,
) -> tuple[subprocess.Popen, float | None]:
    returncode = proc.poll()
    if returncode is None:
        return proc, None

    now = time.time()
    if returncode == 0:
        if normal_exit_restart_at is None:
            restart_at = now + restart_delay_seconds
            logger.info(
                f"[LAUNCHER] {kind} `{name}` exited normally with code 0; "
                f"retrying in {restart_delay_seconds:.0f}s"
            )
            return proc, restart_at
        if now < normal_exit_restart_at:
            return proc, normal_exit_restart_at
        logger.info(f"[LAUNCHER] Restarting {kind} `{name}` after normal exit cooldown")
        return spawn_fn(), None

    logger.warning(f"[LAUNCHER] {kind} `{name}` exited with code {returncode}; restarting immediately")
    return spawn_fn(), None


def main():
    args = parse_args()
    core = bootstrap_project(
        project=args.project,
        output_dir=args.output_dir,
        test_mode=args.test,
        exec_args=args.exec_args,
        logger_component="launcher",
        console_logging_mode="launcher",
    )
    root = runtime_root()
    enabled_paths = _enabled_paths()
    core.logger.info(
        f"[LAUNCHER] Starting trace monitor and solver workers for: "
        f"{', '.join(enabled_paths) if enabled_paths else '(none)'}"
    )

    monitor = _spawn_trace_monitor(args)
    monitor_restart_at: float | None = None
    workers: dict[str, subprocess.Popen] = {
        path_name: _spawn_worker(path_name, args, root, 0)
        for path_name in enabled_paths
    }
    worker_restart_at: dict[str, float | None] = {path_name: None for path_name in enabled_paths}

    try:
        while True:
            monitor, monitor_restart_at = _maybe_restart_process(
                proc=monitor,
                kind="Trace monitor",
                name="trace-monitor",
                normal_exit_restart_at=monitor_restart_at,
                restart_delay_seconds=MONITOR_NORMAL_EXIT_RESTART_DELAY_SECONDS,
                spawn_fn=lambda: _spawn_trace_monitor(args),
                logger=core.logger,
            )

            for path_name, proc in list(workers.items()):
                workers[path_name], worker_restart_at[path_name] = _maybe_restart_process(
                    proc=proc,
                    kind="Worker",
                    name=path_name,
                    normal_exit_restart_at=worker_restart_at.get(path_name),
                    restart_delay_seconds=NORMAL_EXIT_RESTART_DELAY_SECONDS,
                    spawn_fn=lambda path_name=path_name: _spawn_worker(path_name, args, root, 0),
                    logger=core.logger,
                )

            _write_launcher_state(
                root,
                {
                    "updated_at": time.time(),
                    "mode": "worker_orchestrator",
                    "monitor": {
                        "pid": monitor.pid,
                        "alive": monitor.poll() is None,
                        "restart_at": monitor_restart_at or 0.0,
                    },
                    "workers": {
                        path_name: {
                            "pid": proc.pid,
                            "alive": proc.poll() is None,
                            "restart_at": worker_restart_at.get(path_name) or 0.0,
                        }
                        for path_name, proc in workers.items()
                    },
                },
            )
            time.sleep(2)
    except KeyboardInterrupt:
        core.logger.info("[LAUNCHER] Keyboard interrupt detected")
    finally:
        for proc in workers.values():
            if proc.poll() is None:
                proc.terminate()
        if monitor.poll() is None:
            monitor.terminate()
        _write_launcher_state(
            root,
            {
                "updated_at": time.time(),
                "mode": "worker_orchestrator",
                "monitor": {
                    "pid": monitor.pid,
                    "alive": False,
                    "restart_at": 0.0,
                },
                "workers": {
                    path_name: {
                        "pid": proc.pid,
                        "alive": False,
                        "restart_at": 0.0,
                    }
                    for path_name, proc in workers.items()
                },
            },
        )
        core.logger.info("[LAUNCHER] Launcher terminated")


if __name__ == "__main__":
    main()
