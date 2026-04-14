from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
import time
from pathlib import Path

import config
from breaker.diagnostics import normalize_xmllint_stderr
from breaker.models import ExecResult, TargetHint
from input_adapter import build_seed_invocation, infer_input_adapter_from_harness


def execute_target(
    *,
    seed_path: str | Path,
    target_command: str,
    target_hint: TargetHint | None = None,
    timeout_sec: int = 10,
    harness_code: str | None = None,
) -> ExecResult:
    seed_path = Path(seed_path)
    target_hint = target_hint or TargetHint()
    argv = shlex.split(target_command)
    if not argv:
        raise ValueError("target_command must not be empty")

    program_path = argv[0]
    exec_args = argv[1:]
    input_adapter = infer_input_adapter_from_harness(harness_code, exec_args)
    cmd, stdin_bytes = build_seed_invocation(program_path, exec_args, seed_path, input_adapter)

    env = os.environ.copy()
    profile_dir = Path(tempfile.mkdtemp(prefix="breaker-prof-"))
    profile_raw = profile_dir / "target.profraw"
    env["LLVM_PROFILE_FILE"] = os.fspath(profile_raw)

    started = time.perf_counter()
    try:
        completed = subprocess.run(
            cmd,
            input=stdin_bytes,
            capture_output=True,
            timeout=timeout_sec,
            env=env,
            check=False,
        )
        runtime_ms = (time.perf_counter() - started) * 1000.0
        stdout_text = _decode_stream(completed.stdout)
        stderr_text = _decode_stream(completed.stderr)
        coverage_report, target_file_hit, target_line_window_hit = _collect_coverage_feedback(
            executable=program_path,
            profile_raw=profile_raw,
            target_hint=target_hint,
        )
        diagnostic = normalize_xmllint_stderr(stderr_text)
        return ExecResult(
            exec_ok=True,
            return_code=completed.returncode,
            runtime_ms=runtime_ms,
            stderr_text=stderr_text,
            stdout_text=stdout_text,
            target_file_hit=target_file_hit,
            target_line_window_hit=target_line_window_hit,
            diagnostics_family=diagnostic.family,
            coverage_report=coverage_report,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        runtime_ms = (time.perf_counter() - started) * 1000.0
        stderr_text = _decode_stream(exc.stderr)
        stdout_text = _decode_stream(exc.stdout)
        diagnostic = normalize_xmllint_stderr(stderr_text)
        return ExecResult(
            exec_ok=False,
            return_code=-9,
            runtime_ms=runtime_ms,
            stderr_text=stderr_text,
            stdout_text=stdout_text,
            target_file_hit=False,
            target_line_window_hit=False,
            diagnostics_family=diagnostic.family,
            coverage_report="",
            timed_out=True,
        )
    except OSError as exc:
        return ExecResult(
            exec_ok=False,
            return_code=-1,
            runtime_ms=0.0,
            stderr_text=str(exc),
            stdout_text="",
            target_file_hit=False,
            target_line_window_hit=False,
            diagnostics_family="unknown_parse_error",
            coverage_report="",
            timed_out=False,
        )


def _decode_stream(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    return data.decode("utf-8", errors="replace")


def _collect_coverage_feedback(
    *,
    executable: str,
    profile_raw: Path,
    target_hint: TargetHint,
) -> tuple[str, bool, bool]:
    if not target_hint.file_path or not profile_raw.exists() or profile_raw.stat().st_size == 0:
        return "", False, False

    profdata = profile_raw.with_suffix(".profdata")
    try:
        merge_proc = subprocess.run(
            [config.LLVM_PROFDATA_BIN, "merge", "-sparse", os.fspath(profile_raw), "-o", os.fspath(profdata)],
            capture_output=True,
            check=False,
            timeout=10,
        )
        if merge_proc.returncode != 0 or not profdata.exists():
            return "", False, False

        source_path = _resolve_target_source(target_hint.file_path)
        if source_path is None:
            return "", False, False

        cov_proc = subprocess.run(
            [
                config.LLVM_COV_BIN,
                "show",
                executable,
                f"-instr-profile={profdata}",
                os.fspath(source_path),
            ],
            capture_output=True,
            check=False,
            timeout=10,
        )
        report = _decode_stream(cov_proc.stdout)
        target_file_hit, target_line_window_hit = _scan_llvm_cov_report(
            report_text=report,
            target_line=target_hint.line,
            window=target_hint.window,
        )
        return report, target_file_hit, target_line_window_hit
    except (subprocess.SubprocessError, OSError):
        return "", False, False


def _resolve_target_source(file_path: str) -> Path | None:
    resolved = config.resolve_source_path(file_path)
    if resolved and resolved.exists():
        return resolved
    candidate = Path(file_path)
    if candidate.exists():
        return candidate
    project_candidate = config.SRC_PATH / file_path
    if project_candidate.exists():
        return project_candidate
    return None


def _scan_llvm_cov_report(report_text: str, target_line: int | None, window: int) -> tuple[bool, bool]:
    any_hit = False
    line_hit = False
    for line in report_text.splitlines():
        parts = line.split("|", 2)
        if len(parts) < 3:
            continue
        try:
            source_line = int(parts[0].strip())
        except ValueError:
            continue
        count_token = parts[1].strip().lower()
        if count_token in {"0", "0.0", ""}:
            continue
        any_hit = True
        if target_line is not None and abs(source_line - target_line) <= window:
            line_hit = True
    return any_hit, line_hit

