#!/usr/bin/env python3
import argparse
import json
import shlex
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def parse_args():
    parser = argparse.ArgumentParser(description="Validate roadblock seed selection quality with offline A/B comparison.")
    parser.add_argument("--project", default="libxml")
    parser.add_argument("--output", default="out_5")
    parser.add_argument("--limit", type=int, default=30, help="Maximum number of roadblocks with >=2 candidates to evaluate.")
    parser.add_argument(
        "--report",
        default=None,
        help="Optional report path. Defaults to <OUTPUT_PATH>/logs/seed_selection_validation.json",
    )
    parser.add_argument(
        "--allow-trace-build",
        action="store_true",
        help="Allow rebuilding missing dynamic summaries instead of using cache-only validation.",
    )
    return parser.parse_args()


def export_roadblocks(config_module) -> list[dict]:
    profdata_path = config_module.STATIC_PATH / "main.profdata"
    cmd = [
        config_module.LLVM_COV_BIN,
        "export",
        str(config_module.COV_TARGET_PATH),
        "-format=text",
        f"-instr-profile={profdata_path}",
        "--json-only-one-sided-branches",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    payload = json.loads(result.stdout)

    # llvm-cov currently emits one synthetic files[0] bucket ("all_files")
    # and stores the real file path on each branch item.
    branches: list[dict] = []
    for file_entry in payload.get("data", [{}])[0].get("files", []):
        for branch in file_entry.get("one_sided_branches", []):
            item = branch.copy()
            item.pop("false_count", None)
            item.pop("true_count", None)
            item.pop("col", None)
            if item not in branches:
                branches.append(item)
    return branches


def roadblock_identity(roadblock: dict) -> tuple:
    if roadblock.get("group_type") == "switch":
        return (
            roadblock.get("filename"),
            "switch",
            int(roadblock.get("switch_statement_line", 0) or 0),
            int(roadblock.get("line", 0) or 0),
            int(roadblock.get("case_body_line", 0) or 0),
            int(roadblock.get("group_index", 0) or 0),
            str(roadblock.get("case_label", "") or "").strip(),
            roadblock.get("status"),
        )
    return (
        roadblock.get("filename"),
        "branch",
        int(roadblock.get("line", 0) or 0),
        str(roadblock.get("code", "") or "").strip(),
        roadblock.get("status"),
    )


def build_profdata_roadblock_index(config_module) -> dict[tuple, list[str]]:
    index: dict[tuple, list[str]] = {}
    prof_dir = config_module.STATIC_PATH / "prof"
    for profdata in sorted(prof_dir.glob("*.profdata")):
        seed_name = profdata.name[:-len(".profdata")]
        cmd = [
            config_module.LLVM_COV_BIN,
            "export",
            str(config_module.COV_TARGET_PATH),
            "-format=text",
            f"-instr-profile={profdata}",
            "--json-only-one-sided-branches",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        payload = json.loads(result.stdout)
        seen: set[tuple] = set()
        for file_entry in payload.get("data", [{}])[0].get("files", []):
            for branch in file_entry.get("one_sided_branches", []):
                rb_key = roadblock_identity(branch)
                if rb_key in seen:
                    continue
                seen.add(rb_key)
                index.setdefault(rb_key, []).append(seed_name)
    return index


def resolve_seed_path(config_module, seed_name: str) -> Path | None:
    direct = config_module.SEED_PATH / seed_name
    if direct.is_file():
        return direct

    seed_prefix = seed_name.split(",")[0]
    output_glob = sorted(config_module.PROJECT_HOME.glob("out_*"))
    for out_dir in output_glob:
        queue_dir = out_dir / "default" / "queue"
        if not queue_dir.is_dir():
            continue
        matches = sorted(queue_dir.glob(f"{seed_prefix}*"))
        if matches:
            return matches[0]
    return None


def build_validation_report(project: str, output: str, limit: int, report_path: Path | None, allow_trace_build: bool):
    import config

    config.set_project(project, output)

    from CoverageTracer import CoverageTracer
    from dynamic_trace_summary import DynamicTraceCache

    tracer = CoverageTracer(
        str(config.INPUT_PATH),
        str(config.OUTPUT_PATH),
        shlex.split(config.EXEC_ARGS),
        str(config.AFL_TARGET_PATH),
        str(config.TRACE_TARGET_PATH),
        config.bbs,
        config.funcs,
    )
    tracer.prof_dir = config.STATIC_PATH / "prof"
    tracer.dynamic_trace_cache = DynamicTraceCache(config.STATIC_PATH / "dynamic_trace_cache")

    fingerprint = tracer._dynamic_trace_fingerprint()

    def load_summary(cache_seed_name: str, seed_path: Path, roadblock: dict):
        roadblock_key = f"{roadblock.get('filename', '')}:{roadblock.get('line', 0)}"
        cached = tracer.dynamic_trace_cache.load(config.PROJECT, roadblock_key, cache_seed_name, fingerprint)
        if cached is not None or not allow_trace_build:
            return cached
        return tracer._load_or_build_dynamic_summary(seed_path, roadblock)

    comparisons: list[dict] = []
    if not allow_trace_build:
        grouped_cache: dict[tuple[str, int], list[dict]] = {}
        for cache_file in sorted((config.STATIC_PATH / "dynamic_trace_cache").glob("*.json")):
            with open(cache_file, "r", encoding="utf-8") as f:
                payload = json.load(f)
            key = (
                payload.get("target_file", ""),
                int(payload.get("target_line", 0) or 0),
            )
            grouped_cache.setdefault(key, []).append(payload)

        for (target_file, target_line), cached_entries in grouped_cache.items():
            roadblock = {"filename": target_file, "line": target_line}
            scored_candidates = []
            for entry in cached_entries:
                cache_seed_name = entry.get("seed_name")
                if not cache_seed_name:
                    continue
                seed_path = resolve_seed_path(config, cache_seed_name)
                if seed_path is None:
                    continue
                summary = load_summary(cache_seed_name, seed_path, roadblock)
                if summary is None:
                    continue
                score, metrics = tracer._seed_locality_score(seed_path, summary, roadblock)
                scored_candidates.append({
                    "cache_seed_name": cache_seed_name,
                    "seed_path": seed_path,
                    "summary": summary,
                    "score": score,
                    "metrics": metrics,
                })

            if len(scored_candidates) < 2:
                continue

            old_ranked = sorted(
                [item["seed_path"] for item in scored_candidates],
                key=lambda path: (path.stat().st_size, path.stat().st_ctime_ns, path.name),
            )
            new_ranked = sorted(scored_candidates, key=lambda item: item["score"], reverse=True)

            def summarize(seed_path: Path) -> dict:
                cache_seed_name = next(
                    item["cache_seed_name"]
                    for item in scored_candidates
                    if item["seed_path"] == seed_path
                )
                summary = load_summary(cache_seed_name, seed_path, roadblock)
                score, metrics = tracer._seed_locality_score(seed_path, summary, roadblock)
                result = dict(metrics)
                result["seed"] = seed_path.name
                result["cache_seed_name"] = cache_seed_name
                result["score"] = list(score[:-1])
                return result

            comparisons.append({
                "roadblock": {
                    "filename": roadblock.get("filename"),
                    "line": roadblock.get("line"),
                    "code": "",
                },
                "candidate_count": len(scored_candidates),
                "scored_candidate_count": len(scored_candidates),
                "old_top1": summarize(old_ranked[0]),
                "new_top1": summarize(new_ranked[0]["seed_path"]),
                "old_top3": [summarize(path) for path in old_ranked[:3]],
                "new_top3": [summarize(item["seed_path"]) for item in new_ranked[:3]],
            })
            if len(comparisons) >= limit:
                break
    else:
        roadblocks = export_roadblocks(config)
        profdata_index = build_profdata_roadblock_index(config)
        for roadblock in roadblocks:
            seed_names = profdata_index.get(roadblock_identity(roadblock), [])
            unique_seed_names = list(dict.fromkeys(seed_names))
            if len(unique_seed_names) < 2:
                continue

            seed_entries = [
                {"cache_seed_name": name, "seed_path": path}
                for name in unique_seed_names
                if (path := resolve_seed_path(config, name)) is not None
            ]
            if len(seed_entries) < 2:
                continue

            scored_candidates = []
            for entry in seed_entries:
                seed_path = entry["seed_path"]
                cache_seed_name = entry["cache_seed_name"]
                summary = load_summary(cache_seed_name, seed_path, roadblock)
                if summary is None:
                    continue
                score, metrics = tracer._seed_locality_score(seed_path, summary, roadblock)
                scored_candidates.append({
                    "cache_seed_name": cache_seed_name,
                    "seed_path": seed_path,
                    "summary": summary,
                    "score": score,
                    "metrics": metrics,
                })
            if len(scored_candidates) < 2:
                continue

            old_ranked = sorted(
                [item["seed_path"] for item in scored_candidates],
                key=lambda path: (path.stat().st_size, path.stat().st_ctime_ns, path.name),
            )
            new_ranked = sorted(scored_candidates, key=lambda item: item["score"], reverse=True)

            def summarize(seed_path: Path) -> dict:
                cache_seed_name = next(
                    item["cache_seed_name"]
                    for item in scored_candidates
                    if item["seed_path"] == seed_path
                )
                summary = load_summary(cache_seed_name, seed_path, roadblock)
                score, metrics = tracer._seed_locality_score(seed_path, summary, roadblock)
                result = dict(metrics)
                result["seed"] = seed_path.name
                result["cache_seed_name"] = cache_seed_name
                result["score"] = list(score[:-1])
                return result

            comparisons.append({
                "roadblock": {
                    "filename": roadblock.get("filename"),
                    "line": roadblock.get("line"),
                    "code": roadblock.get("code", ""),
                },
                "candidate_count": len(seed_entries),
                "scored_candidate_count": len(scored_candidates),
                "old_top1": summarize(old_ranked[0]),
                "new_top1": summarize(new_ranked[0]["seed_path"]),
                "old_top3": [summarize(path) for path in old_ranked[:3]],
                "new_top3": [summarize(item["seed_path"]) for item in new_ranked[:3]],
            })
            if len(comparisons) >= limit:
                break

    def avg(field: str, rows: list[dict], top_key: str) -> float:
        values = [row[top_key][field] for row in rows]
        return round(sum(values) / len(values), 3) if values else 0.0

    def count_better(field: str, rows: list[dict], *, lower_is_better: bool = False) -> int:
        total = 0
        for row in rows:
            old_value = row["old_top1"][field]
            new_value = row["new_top1"][field]
            if (new_value < old_value) if lower_is_better else (new_value > old_value):
                total += 1
        return total

    def count_any(top_key: str, field: str, rows: list[dict]) -> int:
        total = 0
        for row in rows:
            if any(item[field] for item in row[top_key]):
                total += 1
        return total

    summary = {
        "project": project,
        "output": output,
        "roadblocks_evaluated": len(comparisons),
        "cache_only": not allow_trace_build,
        "top1_avg_branch_window_lines": {
            "old": avg("branch_window_lines", comparisons, "old_top1"),
            "new": avg("branch_window_lines", comparisons, "new_top1"),
        },
        "top1_avg_executed_near_target": {
            "old": avg("executed_near_target", comparisons, "old_top1"),
            "new": avg("executed_near_target", comparisons, "new_top1"),
        },
        "top1_avg_min_branch_distance": {
            "old": avg("min_branch_distance", comparisons, "old_top1"),
            "new": avg("min_branch_distance", comparisons, "new_top1"),
        },
        "top1_better_counts": {
            "branch_exact": count_better("branch_exact", comparisons),
            "branch_window_lines": count_better("branch_window_lines", comparisons),
            "executed_near_target": count_better("executed_near_target", comparisons),
            "min_branch_distance": count_better("min_branch_distance", comparisons, lower_is_better=True),
        },
        "top3_any_branch_exact": {
            "old": count_any("old_top3", "branch_exact", comparisons),
            "new": count_any("new_top3", "branch_exact", comparisons),
        },
        "top3_any_target_hit": {
            "old": count_any("old_top3", "target_hit", comparisons),
            "new": count_any("new_top3", "target_hit", comparisons),
        },
    }

    report = {
        "summary": summary,
        "comparisons": comparisons,
    }

    if report_path is None:
        report_path = config.OUTPUT_PATH / "logs" / "seed_selection_validation.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report_path, report


def main():
    args = parse_args()
    report_path = Path(args.report).resolve() if args.report else None
    final_report_path, report = build_validation_report(
        args.project,
        args.output,
        args.limit,
        report_path,
        args.allow_trace_build,
    )
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    print(f"report={final_report_path}")


if __name__ == "__main__":
    main()
