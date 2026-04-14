from __future__ import annotations

import argparse
import json
import shlex
from pathlib import Path

import config
from CoverageTracer import get_harness_code
from LLM.format_detector import InputFormatDetector
from breaker.loop import run_breaker_loop
from breaker.models import BreakerConfig, TargetHint


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the minimal real-feedback breaker for xmllint/libxml.")
    parser.add_argument("seed_path", help="Path to the XML seed file")
    parser.add_argument("--project", default="xmllint", help="Project name for config/static resolution")
    parser.add_argument("--output-dir", default="out", help="Output dir name used by config.set_project")
    parser.add_argument(
        "--target-command",
        default=None,
        help="Command template to run, use @@ for seed path. Default: '<llvmcov target> --recover @@'",
    )
    parser.add_argument("--target-file", default=None, help="Source file hint for target hit scoring")
    parser.add_argument("--target-line", type=int, default=None, help="Source line hint for target hit scoring")
    parser.add_argument("--window", type=int, default=12, help="Source line hit window")
    parser.add_argument("--max-candidates", type=int, default=6, help="Maximum rule-generated candidates")
    parser.add_argument("--timeout-sec", type=int, default=10, help="Per-execution timeout")
    args = parser.parse_args()

    config.set_project(args.project, args.output_dir)
    harness_code = get_harness_code()
    format_info = InputFormatDetector.get_cached_format(args.project)

    target_command = args.target_command
    if not target_command:
        target_command = shlex.join([str(config.COV_TARGET_PATH), "--recover", "@@"])

    result = run_breaker_loop(
        BreakerConfig(
            seed_path=Path(args.seed_path),
            target_command=target_command,
            target_hint=TargetHint(file_path=args.target_file, line=args.target_line, window=args.window),
            max_candidates=args.max_candidates,
            timeout_sec=args.timeout_sec,
            project=args.project,
            output_dir=config.RUN_RUNTIME_PATH / "breaker",
            harness_code=harness_code,
            format_info=format_info,
        )
    )

    payload = {
        "baseline": {
            "return_code": result.baseline.return_code,
            "diagnostics_family": result.baseline.diagnostics_family,
            "target_file_hit": result.baseline.target_file_hit,
            "target_line_window_hit": result.baseline.target_line_window_hit,
        },
        "best": None
        if result.best is None
        else {
            "seed_path": str(result.best.seed_path),
            "action": result.best.candidate.action,
            "score": result.best.score,
            "score_breakdown": result.best.score_breakdown,
            "return_code": result.best.exec_result.return_code,
            "diagnostics_family": result.best.exec_result.diagnostics_family,
            "target_file_hit": result.best.exec_result.target_file_hit,
            "target_line_window_hit": result.best.exec_result.target_line_window_hit,
        },
        "feedback_summary": result.feedback_summary,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

