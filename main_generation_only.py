import argparse
import json
import logging
import os
import random
import shlex
import sys
import threading
import time

import ujson

import config
import main as core
from CoverageTracer import CoverageTracer
from LLM.LLMUtil import LLMUtil


ROADBLOCK_REFRESH_INTERVAL = core.CHECK_INTERVAL
PLATEAU_MONITOR_INTERVAL = core.CHECK_INTERVAL


class GenerationOnlyCoordinator:
    def __init__(self, tracer: CoverageTracer, llm_util: LLMUtil, last_scan_time, read_files):
        self.tracer = tracer
        self.llm_util = llm_util
        self.last_scan_time = last_scan_time
        self.read_files = read_files
        self.stop_event = threading.Event()
        self.pool_lock = threading.Lock()
        self.solve_lock = threading.Lock()
        self.scheduler_state_lock = threading.RLock()
        self.roadblock_pool = []
        self.pool_cursor = 0
        self.last_refresh_time = 0.0
        self.last_solve_check_time = 0.0
        self.iteration_count = 0
        self.scheduler_state_path = config.RUN_RUNTIME_PATH / "generation_only_scheduler.json"
        self.interesting_scores: dict[str, float] = {}
        self.failure_counts: dict[str, int] = {}
        self.cooldown_until: dict[str, float] = {}
        self.selection_counts: dict[str, int] = {}
        self.last_selected_key: str | None = None
        self.initial_refresh_started = threading.Event()
        self.initial_refresh_done = threading.Event()
        self.refresh_in_progress = threading.Event()
        self._logged_waiting_for_initial_refresh = False
        self._logged_plateau_without_pool = False
        self.pending_plateau = threading.Event()
        self.pending_plateau_since = 0.0
        self._reward_feed_offset = 0
        self._load_scheduler_state()
        self._consume_reward_feed()

    def _load_scheduler_state(self) -> None:
        if not self.scheduler_state_path.exists():
            return
        try:
            payload = json.loads(self.scheduler_state_path.read_text(encoding="utf-8"))
        except Exception as exc:
            core.logger.warning(
                f"[{core.LogOp.ROADBLOCK}] Failed to load scheduler state {self.scheduler_state_path}: {exc}"
            )
            return
        with self.scheduler_state_lock:
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

    def _save_scheduler_state(self) -> None:
        with self.scheduler_state_lock:
            payload = {
                "updated_at": time.time(),
                "interesting_scores": dict(self.interesting_scores),
                "failure_counts": dict(self.failure_counts),
                "cooldown_until": dict(self.cooldown_until),
                "selection_counts": dict(self.selection_counts),
                "last_selected_key": self.last_selected_key or "",
            }
        try:
            self.scheduler_state_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            core.logger.warning(
                f"[{core.LogOp.ROADBLOCK}] Failed to save scheduler state {self.scheduler_state_path}: {exc}"
            )

    def _consume_reward_feed(self) -> None:
        """Read reward records from reward_feed.jsonl and merge into interesting_scores."""
        reward_path = config.REWARD_FEED_PATH
        if not reward_path.exists():
            return
        rewards_applied = 0
        try:
            with open(reward_path, "r", encoding="utf-8") as f:
                # Seek to last consumed offset
                with self.scheduler_state_lock:
                    reward_feed_offset = self._reward_feed_offset
                if reward_feed_offset > 0:
                    f.seek(reward_feed_offset)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    rb_key = record.get("roadblock_key")
                    reward = float(record.get("reward", 0))
                    if rb_key and reward != 0:
                        with self.scheduler_state_lock:
                            current = float(self.interesting_scores.get(rb_key, 0.0))
                            self.interesting_scores[rb_key] = current + reward
                        rewards_applied += 1
                with self.scheduler_state_lock:
                    self._reward_feed_offset = f.tell()
        except FileNotFoundError:
            return
        except Exception as exc:
            core.logger.warning(
                f"[{core.LogOp.ROADBLOCK}] Failed to consume reward feed: {exc}"
            )
            return
        if rewards_applied:
            core.logger.info(
                f"[{core.LogOp.ROADBLOCK}] Consumed {rewards_applied} reward(s) from feed, "
                f"updated interesting_scores"
            )
            self._save_scheduler_state()

    def _sync_scheduler_state(self, prepared_roadblocks) -> None:
        with self.scheduler_state_lock:
            active_keys = set()
            for rb in prepared_roadblocks:
                key = rb.get("roadblock_key") or core.get_roadblock_key(rb)
                active_keys.add(key)
                self.interesting_scores.setdefault(key, 0.0)
                self.failure_counts.setdefault(key, 0)
                self.selection_counts.setdefault(key, 0)

            stale_score_keys = set(self.interesting_scores) - active_keys
            stale_failure_keys = set(self.failure_counts) - active_keys
            stale_cooldown_keys = set(self.cooldown_until) - active_keys
            stale_selection_keys = set(self.selection_counts) - active_keys

            for key in stale_score_keys:
                self.interesting_scores.pop(key, None)
            for key in stale_failure_keys:
                self.failure_counts.pop(key, None)
            for key in stale_cooldown_keys:
                self.cooldown_until.pop(key, None)
            for key in stale_selection_keys:
                self.selection_counts.pop(key, None)

            if self.last_selected_key and self.last_selected_key not in active_keys:
                self.last_selected_key = None
        self._save_scheduler_state()

    def _cooldown_seconds_for_failures(self, failure_count: int) -> float:
        failure_count = max(1, int(failure_count))
        return float(min(1800, 60 * (2 ** (failure_count - 1))))

    def record_attempt_result(
        self,
        roadblock: dict,
        *,
        attempted: bool,
        mode: str,
        coverage_breakthrough: bool,
    ) -> None:
        roadblock_key = roadblock.get("roadblock_key") or core.get_roadblock_key(roadblock)
        now = time.time()
        with self.scheduler_state_lock:
            score = float(self.interesting_scores.get(roadblock_key, 0.0))
            failures = int(self.failure_counts.get(roadblock_key, 0))

            if coverage_breakthrough:
                score -= 3.0
                failures = 0
                self.cooldown_until[roadblock_key] = now + 600.0
            elif attempted:
                score -= 1.5
                failures += 1
                self.cooldown_until[roadblock_key] = now + self._cooldown_seconds_for_failures(failures)
            else:
                score -= 2.5
                failures += 1
                self.cooldown_until[roadblock_key] = now + self._cooldown_seconds_for_failures(failures + 1)

            self.interesting_scores[roadblock_key] = score
            self.failure_counts[roadblock_key] = failures
        self._save_scheduler_state()
        core.logger.info(
            f"[{core.LogOp.ROADBLOCK}] Scheduler updated for {roadblock_key}: "
            f"score={score:.1f}, failures={failures}, cooldown_until={self.cooldown_until.get(roadblock_key, 0):.0f}, mode={mode}"
        )

    def prepare_roadblocks(self, roadblocks):
        prepared_roadblocks = []
        for rb in roadblocks:
            rb["roadblock_id"] = rb.get("roadblock_id") or core.get_rb_id(rb)
            rb["roadblock_key"] = rb.get("roadblock_key") or core.get_roadblock_key(rb)
            if not rb.get("function"):
                func_meta = self.tracer._find_function_for_location(
                    rb.get("filename", ""), int(rb.get("line", 0) or 0)
                )
                if func_meta and func_meta.get("name"):
                    rb["function"] = func_meta.get("name")
                else:
                    rb["function"] = ""
            prepared_roadblocks.append(rb)
        return prepared_roadblocks

    def refresh_roadblock_pool(self) -> bool:
        if not self.initial_refresh_started.is_set():
            self.initial_refresh_started.set()
            core.logger.info(
                f"[{core.LogOp.ROADBLOCK}] Starting initial generation-only roadblock refresh"
            )
        self.refresh_in_progress.set()
        try:
            ret, new_last_scan_time, error_info, roadblocks = self.tracer.get_trace(
                self.read_files, self.last_scan_time
            )
            self.tracer.kick_autobug_prime_async()
            if "没有新的seed" in error_info and not roadblocks:
                core.logger.info(f"[{core.LogOp.ROADBLOCK}] {error_info}")
                roadblocks = self.tracer.get_current_one_sided_branches()
            elif not ret:
                core.logger.critical(
                    f"[{core.LogOp.ROADBLOCK}] Coverage trace extraction failed: {error_info}"
                )
                core.logger.critical("Cannot proceed without valid trace data")
                self.stop_event.set()
                raise RuntimeError(error_info)

            prepared_roadblocks = self.prepare_roadblocks(roadblocks)
            with self.pool_lock:
                self.last_scan_time = new_last_scan_time
                self.roadblock_pool = prepared_roadblocks
                self.pool_cursor = 0
                self._sync_scheduler_state(prepared_roadblocks)

            core.logger.info(
                f"[{core.LogOp.ROADBLOCK}] Refreshed generation-only roadblock pool: "
                f"{len(prepared_roadblocks)} candidate(s)"
            )
            self.initial_refresh_done.set()
            if self.pending_plateau.is_set():
                core.logger.info(
                    f"[{core.LogOp.ROADBLOCK}] Roadblock refresh completed while plateau is pending; "
                    f"scheduling immediate plateau handling"
                )
                self.last_solve_check_time = 0.0
            return bool(prepared_roadblocks)
        finally:
            self.refresh_in_progress.clear()

    def get_next_roadblock(self):
        with self.pool_lock:
            if not self.roadblock_pool:
                return None
            with self.scheduler_state_lock:
                now = time.time()
                eligible = []
                for rb in self.roadblock_pool:
                    key = rb.get("roadblock_key") or core.get_roadblock_key(rb)
                    if now < float(self.cooldown_until.get(key, 0.0)):
                        continue
                    eligible.append(rb)

                candidates = eligible if eligible else list(self.roadblock_pool)
                if self.last_selected_key and len(candidates) > 1:
                    non_repeated = [
                        rb for rb in candidates
                        if (rb.get("roadblock_key") or core.get_roadblock_key(rb)) != self.last_selected_key
                    ]
                    if non_repeated:
                        candidates = non_repeated

                def candidate_rank(rb):
                    key = rb.get("roadblock_key") or core.get_roadblock_key(rb)
                    return (
                        float(self.interesting_scores.get(key, 0.0)),
                        -int(self.failure_counts.get(key, 0)),
                        -int(self.selection_counts.get(key, 0)),
                    )

                best_rank = max(candidate_rank(rb) for rb in candidates)
                best_candidates = [rb for rb in candidates if candidate_rank(rb) == best_rank]
                roadblock = random.choice(best_candidates)
                roadblock_key = roadblock.get("roadblock_key") or core.get_roadblock_key(roadblock)
                self.selection_counts[roadblock_key] = int(self.selection_counts.get(roadblock_key, 0)) + 1
                self.last_selected_key = roadblock_key
            self._save_scheduler_state()
            core.logger.info(
                f"[{core.LogOp.ROADBLOCK}] Scheduler selected {roadblock_key} "
                f"(score={self.interesting_scores.get(roadblock_key, 0.0):.1f}, "
                f"failures={self.failure_counts.get(roadblock_key, 0)}, "
                f"selected={self.selection_counts.get(roadblock_key, 0)})"
            )
            return roadblock

    def monitor_roadblock_pool(self, every_n_seconds=ROADBLOCK_REFRESH_INTERVAL):
        while not self.stop_event.is_set():
            self.tracer.poll_autobug_seed_queue()
            self.tracer.kick_autobug_prime_async()
            cur_time = time.time()
            if cur_time - self.last_refresh_time >= every_n_seconds:
                try:
                    self.refresh_roadblock_pool()
                except Exception:
                    core.logger.critical(
                        "[{core.LogOp.ROADBLOCK}] Roadblock pool refresh failed",
                        exc_info=True,
                    )
                    self.stop_event.set()
                    return
                self.last_refresh_time = cur_time
            time.sleep(1)

    def monitor_coverage_plateau(self, every_n_seconds=PLATEAU_MONITOR_INTERVAL):
        while not self.stop_event.is_set():
            self.tracer.poll_autobug_seed_queue()
            self.tracer.kick_autobug_prime_async()
            self._consume_reward_feed()
            cur_time = time.time()
            if cur_time - self.last_solve_check_time < every_n_seconds:
                time.sleep(1)
                continue

            self.last_solve_check_time = cur_time
            if not self.initial_refresh_done.is_set() and not self._logged_waiting_for_initial_refresh:
                core.logger.info(
                    f"[{core.LogOp.ROADBLOCK}] Coverage monitor is active while initial roadblock refresh runs in background"
                )
                self._logged_waiting_for_initial_refresh = True
            stuck_time = self.tracer.check_coverage_growth()
            if stuck_time < core.THRESHOLD_TIME:
                continue

            if not self.solve_lock.acquire(blocking=False):
                continue

            try:
                roadblock = self.get_next_roadblock()
                if roadblock is None:
                    self.pending_plateau.set()
                    if self.pending_plateau_since <= 0.0:
                        self.pending_plateau_since = stuck_time
                    if self.initial_refresh_done.is_set() or not self._logged_plateau_without_pool:
                        status = "not ready yet" if not self.initial_refresh_done.is_set() else "empty"
                        core.logger.info(
                            f"[{core.LogOp.ROADBLOCK}] Plateau detected but roadblock pool is {status}"
                        )
                        if not self.initial_refresh_done.is_set():
                            self._logged_plateau_without_pool = True
                    continue
                self._logged_plateau_without_pool = False
                self.pending_plateau.clear()
                self.pending_plateau_since = 0.0

                core.logger.info(
                    f"[{core.LogOp.ROADBLOCK}] Plateau detected "
                    f"(stuck_time={stuck_time}s >= {core.THRESHOLD_TIME}s), "
                    f"attempting one generation-only roadblock"
                )
                attempted, mode, _, _ = handle_roadblock_generation_only(
                    roadblock, self.tracer, self.llm_util
                )
                self.iteration_count += 1

                stuck_time = self.tracer.check_coverage_growth()
                coverage_breakthrough = stuck_time < core.THRESHOLD_TIME
                self.record_attempt_result(
                    roadblock,
                    attempted=attempted,
                    mode=mode,
                    coverage_breakthrough=coverage_breakthrough,
                )
                if coverage_breakthrough:
                    core.reset_roadblock_outcomes()
                    core.logger.info(
                        f"[{core.LogOp.ROADBLOCK}] Coverage breakthrough detected after "
                        f"generation-only attempt (stuck_time={stuck_time}s < {core.THRESHOLD_TIME}s)"
                    )

                core.logger.info(
                    f"[{core.LogOp.ROADBLOCK}] Generation-only iteration {self.iteration_count} "
                    f"finished for {roadblock.get('roadblock_key')} "
                    f"(attempted={attempted}, mode={mode})"
                )
            except Exception:
                core.logger.critical(
                    "[{core.LogOp.ROADBLOCK}] Plateau monitor failed during generation-only attempt",
                    exc_info=True,
                )
                self.stop_event.set()
                return
            finally:
                self.solve_lock.release()


def apply_generation_only_overrides() -> None:
    overrides = {
        "ENABLE_SIMPLIFIED_FLAG_PATH": False,
        "ENABLE_SIMPLIFIED_TAINT_MUTATION_PATH": False,
        "ENABLE_SIMPLIFIED_STATE_DRIVEN_PATH": False,
        "ENABLE_SIMPLIFIED_FIELD_MUTATION_PATH": False,
        "ENABLE_SIMPLIFIED_BATCH_MUTATION_PATH": False,
        "ENABLE_SIMPLIFIED_XML_GRAMMAR_PATH": False,
        "ENABLE_SIMPLIFIED_XML_GRAMMAR_LLM_SPEC": False,
        "ENABLE_SIMPLIFIED_XML_GRAMMAR_LLM_SCORING": False,
        "ENABLE_SIMPLIFIED_DIRECT_GENERATION_PATH": True,
        "ENABLE_STATE_INFERENCE_PHASE_2": False,
        "ENABLE_STATE_INFERENCE_PHASE_3": False,
        "ENABLE_STATE_DRIVEN_PATH_B": False,
    }
    for name, value in overrides.items():
        setattr(config, name, value)
        setattr(core, name, value)


def bootstrap_from_cli(argv: list[str] | None = None) -> argparse.Namespace:
    argv = list(sys.argv[1:] if argv is None else argv)
    exec_args_override = None
    if "--" in argv:
        separator_index = argv.index("--")
        cli_argv = argv[:separator_index]
        exec_args_override = argv[separator_index + 1:]
    else:
        cli_argv = argv

    parser = argparse.ArgumentParser(description="AutoFrame Generation-Only Fuzzing")
    parser.add_argument("project", nargs="?", default=None,
                        help="要运行的 project 名称 (默认使用 config.py 中的 PROJECT)")
    parser.add_argument("-o", "--output-dir", dest="output_dir", default="out",
                        help="输出目录名 (默认: out)")
    parser.add_argument("--test", action="store_true",
                        help="启用测试模式 (设置 config.test=True)")
    parser.add_argument(
        "--exec-args",
        dest="exec_args",
        default=None,
        help="显式指定 EXEC_ARGS 字符串；若同时提供 `-- ...`，以后者为准",
    )
    args = parser.parse_args(cli_argv)

    config.test = args.test
    if exec_args_override is not None:
        config.EXEC_ARGS = shlex.join(exec_args_override)
    elif args.exec_args is not None:
        config.EXEC_ARGS = args.exec_args

    core.EXEC_ARGS = config.EXEC_ARGS
    core.THRESHOLD_TIME = config.THRESHOLD_TIME
    core.THRESHOLD_COV_DELTA = config.THRESHOLD_COV_DELTA

    if args.project or args.output_dir != "out":
        from config import set_project, PROJECT as DEFAULT_PROJECT

        project_name = args.project if args.project else DEFAULT_PROJECT
        set_project(project_name, args.output_dir)

        core.PROJECT = config.PROJECT
        core.OUTPUT_DIR_NAME = config.OUTPUT_DIR_NAME
        core.PROJECT_HOME = config.PROJECT_HOME
        core.STATIC_PATH = config.STATIC_PATH
        core.PLOT_PATH = config.PLOT_PATH
        core.SEED_PATH = config.SEED_PATH
        core.INPUT_PATH = config.INPUT_PATH
        core.OUTPUT_PATH = config.OUTPUT_PATH
        core.LLM_QUEUE_PATH = config.LLM_QUEUE_PATH
        core.MUT_QUEUE_PATH = config.MUT_QUEUE_PATH
        core.SYMBOLIC_QUEUE_PATH = config.SYMBOLIC_QUEUE_PATH
        core.AFL_TARGET_PATH = config.AFL_TARGET_PATH
        core.TRACE_TARGET_PATH = config.TRACE_TARGET_PATH
        core.SRC_PATH = config.SRC_PATH
        core.SRC_BEAR_PATH = config.SRC_BEAR_PATH
        core.TSEED_ISI_PATH = config.TSEED_ISI_PATH
        core.TSEED_ISI_JSON_PATH = config.TSEED_ISI_JSON_PATH
        core.RESULT_JSON_PATH = config.RESULT_JSON_PATH
        core.RELEVANT_FIELD_JSON_PATH = config.RELEVANT_FIELD_JSON_PATH
        core.BATCH_MUTATE_SCRIPT_PATH = config.BATCH_MUTATE_SCRIPT_PATH
        core.MUT_TMP_PATH = config.MUT_TMP_PATH
        core.LLM_TMP_PATH = config.LLM_TMP_PATH
        core.bbs = config.bbs
        core.funcs = config.funcs
        core.bcfile_path = config.bcfile_path
        core.slice_out = config.slice_out
        core.IPL_TARGET_PATH = config.IPL_TARGET_PATH
        core.FLAGREC_BITCODE = config.FLAGREC_BITCODE
        core.FLAGREC_CACHE = config.FLAGREC_CACHE

    apply_generation_only_overrides()
    config.ensure_runtime_layout()
    core._logger_initialized = False
    core.setup_logger()

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return args


def handle_roadblock_generation_only(roadblock, tracer: CoverageTracer, llm_util: LLMUtil):
    try:
        core.check_fuzzer_alive()
    except core.FuzzerProcessDiedError as e:
        core.logger.critical(f"[{core.LogOp.FUZZER}] {e}")
        core.logger.critical(
            "[{core.LogOp.FUZZER}] Fuzzer died before generation-only roadblock processing, aborting..."
        )
        raise

    roadblock_key = roadblock.get("roadblock_key") or core.get_roadblock_key(roadblock)
    roadblock_id = roadblock.get("roadblock_id") or core.get_rb_id(roadblock)
    core.logger.info(
        f"[{core.LogOp.ROADBLOCK}] Generation-only processing roadblock "
        f"{roadblock_id} (key: {roadblock_key})"
    )
    core.mark_roadblock_attempted(
        roadblock_key, roadblock, stage="handle_roadblock_generation_only"
    )

    seeds = tracer.get_rb_seed(roadblock)
    rb_file = roadblock["filename"]
    rb_line = roadblock["line"]
    slice_line = rb_line
    if roadblock.get("group_type", None) == "switch":
        switch_line = core.get_switch_statement_line(roadblock)
        if switch_line:
            slice_line = switch_line

    rb_fname = roadblock.get("function") or ""
    if not rb_fname:
        func_meta = tracer._find_function_for_location(rb_file, rb_line)
        if func_meta and func_meta.get("name"):
            rb_fname = str(func_meta.get("name"))

    if not rb_fname:
        core.logger.warning(
            f"[{core.LogOp.ROADBLOCK}] Generation-only mode: no function name found "
            f"for {roadblock_key}"
        )
        return False, "NO_FUNCTION_NAME", -1, roadblock_id

    call_chains = core.get_call_chain(rb_fname.split(".")[0])
    using_fallback_slice = False
    if call_chains is None or len(call_chains) == 0:
        code_slice = core.ensure_cached_single_function_slice(
            roadblock,
            llm_util,
        )
        if not code_slice or "No matching instruction found" in code_slice or len(code_slice) <= 50:
            core.logger.error(
                f"[{core.LogOp.ROADBLOCK}] Generation-only mode: failed to extract fallback code slice"
            )
            return False, "CODE_SLICE_FAILED", -1, roadblock_id
        using_fallback_slice = True
        call_chains = [[rb_fname.split(".")[0]]]
    else:
        call_chains = sorted(
            call_chains,
            key=core._score_input_driven_call_chain,
            reverse=True,
        )

    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"
    bcode = roadblock["code"]

    for call_chain in call_chains:
        if not using_fallback_slice:
            if len(call_chain) < core.DEPTH_THRESHOLD:
                continue
            code_slice = core.get_function_slice(
                call_chain,
                slice_line,
                roadblock["status"],
                llm_util,
                original_target_line=rb_line,
                target_file=roadblock.get("filename"),
            )
            if "No matching instruction found" in code_slice:
                return False, "SLICE_FAILED", -1, roadblock_id

        try:
            core.check_fuzzer_alive()
        except core.FuzzerProcessDiedError as e:
            core.logger.critical(f"[{core.LogOp.FUZZER}] {e}")
            core.logger.critical(
                "[{core.LogOp.FUZZER}] Fuzzer died before generation-only constraint analysis, aborting..."
            )
            raise

        core.logger.info(
            f"[{core.LogOp.ROADBLOCK}] Generation-only mode: starting constraint analysis"
        )
        res = None
        constraint_messages = core.build_constraints_messages(roadblock, code_slice)
        times = 0
        while times < core.MAX_TIME:
            resp = llm_util.get_response(constraint_messages)
            match = core.extract_json_with_fallback(resp, pattern_json)
            if not match:
                core.append_llm_retry_feedback(
                    constraint_messages,
                    resp,
                    "请只返回一个 JSON object，并完整包含 analise_branch_v2 需要的所有字段。"
                )
                times += 1
                continue
            try:
                res = json.loads(match.group(1).strip())
            except json.JSONDecodeError as exc:
                core.append_llm_retry_feedback(
                    constraint_messages,
                    resp,
                    f"JSON 解析失败：{exc}。请只返回一个合法的 JSON object，并完整包含 analise_branch_v2 需要的所有字段。"
                )
                times += 1
                continue
            analysis_error = core.validate_analysis_result_v2(res)
            if analysis_error:
                core.append_llm_retry_feedback(
                    constraint_messages,
                    resp,
                    f"返回结构不符合要求：{analysis_error}。请只返回一个 JSON object，并完整包含 analise_branch_v2 需要的所有字段。"
                )
                res = None
                times += 1
                continue
            break

        if res is None:
            return False, "CONSTRAINT_ANALYSIS_FAILED", -1, roadblock_id

        constraints = res["global_merged_constraints_in_natural_language"]
        summary = res["reasoning_summary"]
        ranked_seed_names = tracer.select_seed_names_for_roadblock(
            roadblock,
            seed_names=seeds,
            max_seeds=max(1, min(8, len(seeds))),
        )
        seed = ranked_seed_names[0] if ranked_seed_names else None
        harness_for_mode = core.get_harness_code()
        generation_mode = core.infer_input_generation_mode(code_slice, harness_for_mode)

        attempt_ctx = core.SimplifiedAttemptContext(
            roadblock=roadblock,
            roadblock_id=roadblock_id,
            roadblock_key=roadblock_key,
            tracer=tracer,
            llm_util=llm_util,
            call_chain=call_chain,
            code_slice=code_slice,
            constraints=constraints,
            summary=summary,
            bcode=bcode,
            seed=seed,
            orig=None,
            fields=None,
            relevant_info=None,
            harness_for_mode=harness_for_mode,
            state_hints=[],
            generation_mode=generation_mode,
        )

        plan = core.plan_direct_generation(
            llm_util=llm_util,
            code_slice=code_slice,
            constraints=constraints,
            summary=summary,
            target_branch=bcode,
            fields=None,
            state_hints=[],
            harness_code=harness_for_mode,
            preferred_seed=seed,
            inferred_mode=generation_mode,
        )
        generation_result = core.execute_direct_generation_plan(
            attempt_ctx,
            plan,
            queue_dir=config.get_named_queue_dir(core.DIRECT_GENERATION_FUZZER),
            skip_seed_gate=True,
            defer_effectiveness_to_outer_check=True,
            log_prefix="Generation-only Path C",
        )
        path_attempted = generation_result.attempted
        if path_attempted:
            # Register seed origin for reward feedback
            if hasattr(generation_result, 'candidate_path') and generation_result.candidate_path:
                seed_name = os.path.basename(generation_result.candidate_path)
                tracer.register_generated_seed(seed_name, roadblock_key, queue_name="LLM")
            core.logger.info(
                f"[{core.LogOp.ROADBLOCK}] Generation-only direct generation produced candidate output"
            )
        else:
            core.logger.info(
                f"[{core.LogOp.ROADBLOCK}] Generation-only direct generation produced no candidate output"
            )
        return path_attempted, "ATTEMPTED_DIRECT_GENERATION_ONLY", -1, roadblock_id

    return False, "NO_ROADBLOCKS_REMAIN", -1, roadblock_id


def main_generation_only() -> None:
    core.input_dir = os.fspath(core.INPUT_PATH)
    core.output_dir = os.fspath(core.OUTPUT_PATH)
    core.fuzzing_args = core.parse_exec_args(core.EXEC_ARGS)
    core.target_prog = core.AFL_TARGET_PATH
    core.trace_prog = None

    core.logger.info("=" * 60)
    core.logger.info("AUTOFUZZER GENERATION-ONLY SESSION INITIALIZATION")
    core.logger.info("=" * 60)
    core.logger.info(f"LLM model: {core.MODEL}")
    core.logger.info(f"Input directory: {core.input_dir}")
    core.logger.info(f"Output directory: {core.output_dir}")
    core.logger.info(f"Fuzzing arguments: {' '.join(core.fuzzing_args)}")
    core.logger.info(f"Target program: {core.target_prog}")
    core.logger.info(f"Coverage threshold: {core.THRESHOLD_TIME}s stagnation")
    core.logger.info(f"Coverage delta threshold: {core.THRESHOLD_COV_DELTA} edges")
    core.logger.info("Generation-only mode: direct generation only; taint/flag/state/field/batch/xml paths disabled")
    core.init_attempted_roadblock_store()

    core.fuzzer = core.FuzzerRunner(
        core.input_dir, core.output_dir, core.target_prog, core.fuzzing_args
    )
    fuzzer_pid = core.fuzzer.load_fuzzer_pid()
    if fuzzer_pid is not None:
        core.logger.info(f"[{core.LogOp.FUZZER}] Fuzzer PID (from fuzzer_stats): {fuzzer_pid}")
    else:
        core.logger.warning(f"[{core.LogOp.FUZZER}] Could not read fuzzer PID from fuzzer_stats")
    core.logger.info("=" * 60)

    time.sleep(1)
    try:
        tracer = CoverageTracer(
            core.input_dir,
            core.output_dir,
            core.fuzzing_args,
            core.target_prog,
            core.TRACE_TARGET_PATH,
            core.bbs,
            core.funcs,
            input_adapter_spec=core.get_input_adapter_spec(),
        )
        llm_util = LLMUtil(core.MODEL, core.API_KEY, core.BASE_URL)
        core.cached_format_info = core.ensure_cached_format_info(llm_util)
        coordinator = GenerationOnlyCoordinator(
            tracer=tracer,
            llm_util=llm_util,
            last_scan_time=0,
            read_files=set(),
        )
        core.logger.info(
            f"[{core.LogOp.ROADBLOCK}] Starting generation-only coverage monitor and background roadblock refresh"
        )
        tracker_thread = threading.Thread(
            target=coordinator.monitor_roadblock_pool,
            name="gen-roadblock-tracker",
            daemon=True,
        )
        plateau_thread = threading.Thread(
            target=coordinator.monitor_coverage_plateau,
            name="gen-plateau-monitor",
            daemon=True,
        )
        tracker_thread.start()
        plateau_thread.start()
        while True:
            try:
                core.check_fuzzer_alive()
            except core.FuzzerProcessDiedError as e:
                core.logger.critical(f"[{core.LogOp.FUZZER}] {e}")
                core.logger.critical("[{core.LogOp.FUZZER}] Fuzzer died, initiating graceful shutdown...")
                raise

            removed_count = core.update_pass_roadblock()
            if removed_count > 0:
                core.logger.info(
                    f"[{core.LogOp.ROADBLOCK}] Main loop: Iterative update removed "
                    f"{removed_count} expired roadblock(s)"
                )
            if coordinator.stop_event.is_set():
                raise RuntimeError("Generation-only coordinator stopped unexpectedly")
            time.sleep(core.CHECK_INTERVAL)
    except KeyboardInterrupt:
        core.logger.info("Keyboard interrupt detected (Ctrl+C)")
        core.logger.info("Initiating graceful shutdown...")
    except Exception as e:
        core.logger.critical(f"Unexpected error in main loop: {str(e)}", exc_info=True)
        core.logger.critical("Attempting graceful shutdown...")
    finally:
        if "coordinator" in locals():
            coordinator.stop_event.set()
        if "tracer" in locals():
            tracer.shutdown_background_workers(wait=False)
        core.logger.info("=" * 60)
        core.logger.info("INFERENCE STATISTICS")
        core.logger.info("=" * 60)
        core.logger.info(
            f"Indirect inference attempts: {core.inference_stats['indirect_attempts']}"
        )
        core.logger.info(
            f"Indirect inference successes: {core.inference_stats['indirect_successes']}"
        )
        if core.inference_stats["indirect_attempts"] > 0:
            success_rate = (
                core.inference_stats["indirect_successes"]
                / core.inference_stats["indirect_attempts"]
                * 100
            )
            core.logger.info(f"Indirect inference success rate: {success_rate:.1f}%")
        core.logger.info("=" * 60)
        core.logger.info("Session terminated")


if __name__ == "__main__":
    bootstrap_from_cli()
    main_generation_only()
