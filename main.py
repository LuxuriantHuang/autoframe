import argparse
import hashlib
import itertools
import json
import logging
import os
import random
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from re import Match
from typing import Any, Optional, Dict

from CoverageTracer import (
    CoverageTracer,
    _rank_call_chains_with_dynamic_context,
    _canonicalize_roadblock_status,
    analyze_low_value_guard_roadblock,
    format_call_chain,
    get_call_chain,
    get_function_slice,
    get_harness_code,
)
from attempt_scheduler import AttemptScheduler, SchedulerCandidate, SchedulerResult
from DSE_util import DSEUtil
from Excep.ScriptExtractError import ScriptExtractError
from Excep.ScriptNotFoundError import ScriptNotFoundError
from Excep.SeedNotFoundError import SeedNotFoundError
from FuzzerRunner import FuzzerRunner
from LLM.LLMUtil import LLMUtil, extract_function_block, extract_generator, run_generator, run_mutate_script
from LLM.flag_var_detector import run_flagrec_analysis, filter_relevant_flags, load_cached_flagrec_results, \
    save_flagrec_results
from LLM.format_detector import InputFormatDetector, get_format_detector
from LLM.flag_solver import solve_with_flags, extract_script_from_flag_result
from LLM.state_machine_analyzer import StateMachineInference
from input_adapter import (
    apply_input_adapter,
    build_seed_invocation,
    infer_input_adapter_from_harness,
    summarize_input_adapter,
)
from semantic_fields import build_semantic_fields, has_semantic_field_provider
from state_driven_mapper import StateDrivenMapper
from xml_grammar_mutator import (
    apply_llm_mutation_spec,
    build_candidates_from_component_scores,
    build_libxml_grammar_candidates,
    build_libxml_llm_component_scoring_messages,
    build_libxml_llm_mutation_spec_messages,
    is_libxml_project,
)
import config
from config import *
from find_seed_root import find_seed_root


# Flag to track if logger has been initialized
_logger_initialized = False
_logger_component_name = None
_console_logging_mode = "full"
NO_COVERAGE_GUIDED_RETRY_LIMIT = 1
SEED_COVERAGE_DIAG_TIMEOUT = int(config.SEED_COVERAGE_DIAG_TIMEOUT)
ROADBLOCK_STAGE_BUDGET = 3
ROADBLOCK_FAMILY_COOLDOWN_THRESHOLD = 3
ROADBLOCK_PER_FILE_STAGE_LIMIT = 1
ROADBLOCK_PER_FUNCTION_STAGE_LIMIT = 1
ROADBLOCK_SLICE_PROBE_BUDGET = 6
TAINT_EXTRACTION_FAILURE_THRESHOLD = 3
SEED_GATE_DEFAULT_MAX_MULTIPLIER = 4.0
SEED_GATE_DEFAULT_P95_MULTIPLIER = 2.0
SEED_IMPORT_CORPUS_SAMPLE_LIMIT = 48
SEED_IMPORT_MAX_BYTES = 8192
SEED_IMPORT_MIN_SCORE_FOR_BREAKTHROUGH = 0.30

DIRECT_GENERATION_FUZZER = "LLM"
FLAG_FUZZER = "flag"
SUBSPACE_BOOTSTRAP_FUZZER = "subspace_bootstrap"
XML_GRAMMAR_FUZZER = "xml_grammar"
TAINT_MUTATION_FUZZER = "taint_mutation"
FIELD_MUTATION_FUZZER = "field_mutation"
STATE_DRIVEN_FUZZER = "state_driven"
BATCH_MUTATION_FUZZER = "batch_mutation"


@dataclass
class ControlSurfaceProfile:
    argv_fixed: list[str]
    env_fixed: dict[str, str] = field(default_factory=dict)
    input_channels: list[str] = field(default_factory=list)
    mutable_surfaces: list[str] = field(default_factory=list)
    forbidden_surfaces: list[str] = field(default_factory=list)
    runtime_command_context: str = ""
    adapter_delivery: str = "unknown"


@dataclass
class SeedGateResult:
    decision: str
    accepted: bool
    reason: str
    audit_path: Optional[str] = None
    duplicate_of: Optional[str] = None


@dataclass
class SeedEvalResult:
    exec_ok: bool
    parse_family_hit: bool
    new_edges: int
    target_file_hit: bool
    target_line_window_hit: bool
    coverage_gain_class: str
    cost_metrics: dict[str, Any] = field(default_factory=dict)
    rejection_reason: Optional[str] = None
    stderr_text: str = ""
    stderr_cluster: str = ""
    stderr_novel: bool = False
    parser_depth_score: int = 0
    closest_hit_line_distance: int | None = None
    deepest_call_chain_hit_index: int = -1
    frontier_advance: bool = False


@dataclass
class DirectTextSeedResult:
    success: bool
    attempt_made: bool
    candidate_path: Optional[str] = None
    gate_result: Optional[SeedGateResult] = None
    eval_result: Optional[SeedEvalResult] = None
    response_text: Optional[str] = None
    failure_reason: Optional[str] = None


@dataclass
class DirectGenerationPlan:
    generation_mode: str
    strategy: str
    reason: str
    inferred_mode: str
    planner_result: Optional[dict[str, Any]] = None


@dataclass
class DirectGenerationExecutionResult:
    attempted: bool
    success: bool
    mode: str
    seed_id: int = -1
    candidate_path: Optional[str] = None
    failure_reason: Optional[str] = None
    gate_result: Optional[SeedGateResult] = None
    eval_result: Optional[SeedEvalResult] = None


@dataclass
class SimplifiedAttemptContext:
    roadblock: dict[str, Any]
    roadblock_id: int | str
    roadblock_key: str
    tracer: CoverageTracer
    llm_util: LLMUtil
    call_chain: list[str]
    code_slice: str
    constraints: str
    summary: str
    bcode: str
    seed: Optional[str]
    orig: Optional[str]
    fields: Optional[dict[str, Any]]
    relevant_info: Optional[dict[str, Any]]
    harness_for_mode: str | None
    state_hints: list[Any]
    generation_mode: str


def setup_logger():
    global _logger_initialized
    # Skip if already initialized to prevent creating multiple log files
    if _logger_initialized:
        return
    _logger_initialized = True

    logger = logging.getLogger()

    # Clear any existing handlers to avoid duplicates
    logger.handlers.clear()

    logger.setLevel(LOGGING_LEVEL)

    config.ensure_runtime_layout()
    formatter = logging.Formatter(LOGGING_FORMAT)

    if _logger_component_name:
        log_file_name = f"{config.sanitize_fs_component(str(_logger_component_name))}.log"
    else:
        log_file_name = config.LOGGER_FILE_NAME

    handler = logging.FileHandler(Path(config.LOG_PATH) / log_file_name)
    handler.setLevel(LOGGING_LEVEL)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(LOGGING_LEVEL)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(_ConsoleLogFilter(_console_logging_mode))
    logger.addHandler(console_handler)


class _ConsoleLogFilter(logging.Filter):
    def __init__(self, mode: str):
        super().__init__()
        self.mode = mode or "full"

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.WARNING:
            return True

        if self.mode == "full":
            return True

        message = record.getMessage()
        lowered = message.lower()

        if self.mode == "launcher":
            return "[LAUNCHER]" in message

        if self.mode == "lifecycle":
            lifecycle_tokens = (
                "started",
                "starting",
                "completed",
                "finished",
                "terminated",
                "exiting",
                "keyboard interrupt",
                "disabled, exiting",
            )
            return any(token in lowered for token in lifecycle_tokens)

        return True


def setup_llm_logger():
    """Setup a separate logger for LLM interactions."""
    llm_logger = logging.getLogger(LLM_LOGGER_NAME)
    llm_logger.setLevel(LOGGING_LEVEL)
    llm_logger.propagate = False

    # Clear any existing handlers to avoid duplicates
    llm_logger.handlers.clear()

    config.ensure_runtime_layout()
    formatter = logging.Formatter(LLM_LOGGING_FORMAT)

    # File handler for LLM logs
    if _logger_component_name:
        llm_log_file_name = f"{config.sanitize_fs_component(str(_logger_component_name))}-llm.log"
    else:
        llm_log_file_name = config.LLM_LOG_FILE_NAME

    llm_file_handler = logging.FileHandler(Path(config.LLM_LOG_PATH) / llm_log_file_name)
    llm_file_handler.setLevel(LOGGING_LEVEL)
    llm_file_handler.setFormatter(formatter)
    llm_logger.addHandler(llm_file_handler)

    return llm_logger


# Initialize LLM logger
llm_logger = None
_cached_input_adapter = None


def get_llm_logger():
    """Get or create the LLM logger instance."""
    global llm_logger
    if llm_logger is None:
        llm_logger = setup_llm_logger()
    return llm_logger


def get_input_adapter_spec(harness_code: str | None = None):
    global _cached_input_adapter
    if harness_code is None:
        harness_code = get_harness_code() or ""
    cache_key = harness_code
    if _cached_input_adapter is not None and _cached_input_adapter[0] == cache_key:
        return _cached_input_adapter[1]
    spec = infer_input_adapter_from_harness(harness_code, EXEC_ARGS)
    if spec.delivery == "unknown" and PROJECT == "cxxfilt":
        spec.delivery = "stdin"
        spec.payload_kind = spec.payload_kind if spec.payload_kind != "unknown" else "textual_parser_input"
        spec.evidence.append("project-level fallback: cxxfilt seeds are replayed through stdin")
    _cached_input_adapter = (cache_key, spec)
    return spec


def read_seed_payload_view(path: Path, harness_code: str | None = None) -> bytes:
    try:
        raw = path.read_bytes()
    except Exception:
        return b""
    return apply_input_adapter(raw, get_input_adapter_spec(harness_code))


def build_seed_execution(
    program_path: str | os.PathLike[str],
    seed_path: str | os.PathLike[str],
    *,
    exec_args: list[str] | None = None,
    harness_code: str | None = None,
) -> tuple[list[str], bytes | None]:
    spec = get_input_adapter_spec(harness_code)
    return build_seed_invocation(
        os.fspath(program_path),
        exec_args if exec_args is not None else fuzzing_args,
        os.fspath(seed_path),
        spec,
    )


# Logging helper constants for consistent message formatting
class LogOp:
    """Operation logging prefixes for structured log messages"""
    EXTRACT = "EXTRACT"
    MUTATE = "MUTATE"
    TEST = "TEST"
    ROADBLOCK = "ROADBLOCK"
    LLM = "LLM"
    FUZZER = "FUZZER"


ANALYSE_BRANCH_PROMPT_KEY_V2 = 'analise_branch_v2'
JUDGE_CONFLICT_PROMPT_KEY_V2 = 'judge_conflict_v2'

ANALYSE_BRANCH_V2_REQUIRED_KEYS = {
    'global_merged_constraints_in_natural_language',
    'reasoning_summary',
    'non_input_constraints',
    'breakthrough_assessment',
}

BREAKTHROUGH_ASSESSMENT_REQUIRED_KEYS = {
    'is_key_bottleneck',
    'worth_breaking_first',
    'can_be_broken_by_input_alone',
    'primary_blocker_type',
    'recommended_action',
}

JUDGE_CONFLICT_V2_REQUIRED_KEYS = {
    'decision',
    'reason',
    'should_generate_input',
    'should_try_state_guided_workflow',
    'should_deprioritize_roadblock',
    'summary',
    'input_drivenness_score',
    'state_dependency_score',
    'evidence_sufficiency_score',
    'expected_depth_score',
    'value_of_breaking_score',
    'recommended_next_steps',
}

PROMPT_SEMANTIC_FIELDS_SAMPLE_LIMIT = 64
PROMPT_SEMANTIC_FIELD_VALUE_LIMIT = 160
PROMPT_MAX_MESSAGE_CHARS_SOFT = 240000


def validate_analysis_result_v2(result: dict[str, Any]) -> Optional[str]:
    if not isinstance(result, dict):
        return f"analysis result must be a JSON object, got {type(result).__name__}"

    missing = ANALYSE_BRANCH_V2_REQUIRED_KEYS - set(result.keys())
    if missing:
        return f"missing top-level keys: {sorted(missing)}"

    if not isinstance(result.get('non_input_constraints'), list):
        return "non_input_constraints must be a list"

    assessment = result.get('breakthrough_assessment')
    if not isinstance(assessment, dict):
        return "breakthrough_assessment must be an object"

    missing_assessment = BREAKTHROUGH_ASSESSMENT_REQUIRED_KEYS - set(assessment.keys())
    if missing_assessment:
        return f"missing breakthrough_assessment keys: {sorted(missing_assessment)}"

    return None


def validate_decision_result_v2(result: dict[str, Any]) -> Optional[str]:
    if not isinstance(result, dict):
        return f"decision result must be a JSON object, got {type(result).__name__}"

    missing = JUDGE_CONFLICT_V2_REQUIRED_KEYS - set(result.keys())
    if missing:
        return f"missing decision keys: {sorted(missing)}"
    for key in (
        'input_drivenness_score',
        'state_dependency_score',
        'evidence_sufficiency_score',
        'expected_depth_score',
        'value_of_breaking_score',
    ):
        value = result.get(key)
        if not isinstance(value, (int, float)):
            return f"{key} must be a number"
    if not isinstance(result.get('recommended_next_steps'), list):
        return "recommended_next_steps must be a list"
    return None


def _truncate_prompt_text(text: str, max_chars: int) -> str:
    if text is None:
        return ""
    if len(text) <= max_chars:
        return text
    if max_chars <= 32:
        return text[:max_chars]
    head = max_chars // 2
    tail = max_chars - head - 21
    return text[:head] + "\n... [truncated] ...\n" + text[-tail:]


def _estimate_messages_chars(messages: list[dict[str, str]]) -> int:
    total = 0
    for message in messages:
        total += len(message.get('role', ''))
        total += len(message.get('content', '') or '')
    return total




def _sanitize_semantic_field_value(value: Any, max_chars: int = PROMPT_SEMANTIC_FIELD_VALUE_LIMIT) -> Any:
    if isinstance(value, str):
        return _truncate_prompt_text(value, max_chars)
    if isinstance(value, list):
        return [_sanitize_semantic_field_value(item, max_chars) for item in value[:8]]
    if isinstance(value, dict):
        compact: dict[str, Any] = {}
        for key, item in list(value.items())[:12]:
            compact[key] = _sanitize_semantic_field_value(item, max_chars)
        return compact
    return value




def validate_generic_object_result(result: Any, context: str) -> Optional[str]:
    if not isinstance(result, dict):
        return f"{context} must be a JSON object, got {type(result).__name__}"
    return None


def validate_mutator_rule_result(result: Any) -> Optional[str]:
    if not isinstance(result, dict):
        return f"mutator rule must be a JSON object, got {type(result).__name__}"
    edits = result.get('edits')
    if edits is None:
        return "missing required key: edits"
    if not isinstance(edits, list):
        return "edits must be a list"
    return None




def _collect_text_fragments(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        fragments: list[str] = []
        for item in value.values():
            fragments.extend(_collect_text_fragments(item))
        return fragments
    if isinstance(value, (list, tuple, set)):
        fragments: list[str] = []
        for item in value:
            fragments.extend(_collect_text_fragments(item))
        return fragments
    return []


def append_llm_retry_feedback(messages: list[dict[str, str]], resp: str, feedback: str):
    messages.append({'role': 'assistant', 'content': resp})
    messages.append({'role': 'user', 'content': feedback})


def _file_md5(path: str) -> str | None:
    try:
        digest = hashlib.md5()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _read_seed_prefix_bytes(path: str, limit: int = SEED_IMPORT_MAX_BYTES) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""


def _byte_ngram_set(data: bytes, n: int = 3, cap: int = 512) -> set[bytes]:
    if not data:
        return set()
    if len(data) < n:
        return {data}
    grams: set[bytes] = set()
    step = max(1, len(data) // cap)
    for idx in range(0, len(data) - n + 1, step):
        grams.add(data[idx: idx + n])
        if len(grams) >= cap:
            break
    return grams


def _text_token_set(data: bytes, cap: int = 128) -> set[str]:
    if not data:
        return set()
    printable = sum(1 for byte in data if 32 <= byte <= 126 or byte in {9, 10, 13})
    if printable / max(len(data), 1) < 0.85:
        return set()
    text = data.decode("utf-8", errors="ignore").lower()
    tokens = re.findall(r"[a-z0-9_:\-]{2,32}", text)
    if not tokens:
        return set()
    return set(tokens[:cap])


def _jaccard_similarity(left: set, right: set) -> float:
    if not left or not right:
        return 0.0
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def _recent_default_queue_paths(limit: int = SEED_IMPORT_CORPUS_SAMPLE_LIMIT) -> list[Path]:
    queue_root = Path(output_dir) if output_dir else Path(config.OUTPUT_PATH)
    queue_dir = queue_root / "default" / "queue"
    if not queue_dir.exists() or not queue_dir.is_dir():
        return []
    entries = [path for path in queue_dir.iterdir() if path.is_file()]
    entries.sort(
        key=lambda path: (
            1 if "+cov" in path.name else 0,
            int(path.stat().st_mtime_ns),
            int(path.stat().st_size),
            path.name,
        ),
        reverse=True,
    )
    return entries[:limit]




def _iter_seed_candidate_dirs() -> list[Path]:
    dirs: list[Path] = []
    for candidate in (globals().get("LLM_QUEUE_PATH"), globals().get("MUT_QUEUE_PATH"), globals().get("SYMBOLIC_QUEUE_PATH")):
        if candidate:
            dirs.append(Path(candidate))
    if output_dir:
        dirs.append(Path(output_dir) / "default" / "queue")

    unique_dirs: list[Path] = []
    seen: set[str] = set()
    for directory in dirs:
        key = os.fspath(directory)
        if key in seen:
            continue
        seen.add(key)
        unique_dirs.append(directory)
    return unique_dirs


def find_duplicate_seed_path(seed_path: str) -> str | None:
    try:
        seed_size = os.path.getsize(seed_path)
    except OSError:
        return None

    new_digest: str | None = None
    seed_realpath = os.path.realpath(seed_path)
    for directory in _iter_seed_candidate_dirs():
        if not directory.exists() or not directory.is_dir():
            continue
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.is_file():
                continue
            entry_path = os.fspath(entry)
            if os.path.realpath(entry_path) == seed_realpath:
                continue
            try:
                if entry.stat().st_size != seed_size:
                    continue
            except OSError:
                continue
            if new_digest is None:
                new_digest = _file_md5(seed_path)
                if new_digest is None:
                    return None
            entry_digest = _file_md5(entry_path)
            if entry_digest and entry_digest == new_digest:
                return entry_path
    return None


def regenerate_duplicate_seed_script(llm_util: LLMUtil, script: str, duplicate_path: str) -> str | None:
    improved_resp = llm_util.improve_script(
        script,
        f"<duplicate_output>\nGenerated seed matches existing input: {duplicate_path}\n</duplicate_output>",
        (
            "The generated input is byte-identical to an existing seed. Keep the same target constraints, "
            "but produce a different concrete input that is not identical to previous seeds."
        ),
    )
    if not improved_resp:
        return None
    return extract_generator(improved_resp)


def detect_fixed_runtime_config_dependency(
    non_input_constraints: list | None,
    breakthrough_assessment: dict | None,
) -> tuple[bool, list[str]]:
    """Detect dependencies on fixed runtime/build configuration outside fuzzable input bytes."""
    text_fragments = _collect_text_fragments(non_input_constraints) + _collect_text_fragments(breakthrough_assessment)
    if not text_fragments:
        return False, []

    text_blob = "\n".join(text_fragments).lower()
    pattern_groups = {
        "command_line_args": [
            r"\bcommand[\s-]*line\b",
            r"\bcmdline\b",
            r"\bargv\b",
            r"\bargc\b",
            r"\barg\[\d+\]\b",
            r"\boption(?:s)?\b",
            r"\bflag(?:s)?\b",
            r"\bruntime arguments?\b",
            r"\bcli arguments?\b",
            r"\bcommand[\s-]*line options?\b",
            r"\bcommand[\s-]*line flags?\b",
        ],
        "compile_or_build_options": [
            r"\bcompile[\s-]*(?:time|option|options|flag|flags)\b",
            r"\bcompiler[\s-]*(?:option|options|flag|flags)\b",
            r"\bbuild[\s-]*(?:option|options|flag|flags)\b",
            r"\bbuild[\s-]*configuration\b",
            r"\bbuild[\s-]*variant\b",
            r"\bpreprocessor\b",
            r"\bmacro\b",
            r"\bifdef\b",
            r"\bifndef\b",
            r"\bdefine[d]?\b",
            r"\bfeature[\s-]*flag\b",
            r"\bcflags\b",
            r"\bcppflags\b",
            r"\bldflags\b",
        ],
        "environment_configuration": [
            r"\benvironment variables?\b",
            r"\benv var(?:iable)?s?\b",
            r"\bgetenv\b",
            r"\bputenv\b",
            r"\bsetenv\b",
            r"\bunsetenv\b",
            r"\bprocess environment\b",
        ],
        "external_runtime_configuration": [
            r"\bworking directory\b",
            r"\bcwd\b",
            r"\bcurrent directory\b",
            r"\bconfig(?:uration)? file\b",
            r"\bexternal config(?:uration)?\b",
            r"\blaunch options?\b",
            r"\bstartup options?\b",
        ],
    }

    matched_groups: list[str] = []
    for label, patterns in pattern_groups.items():
        if any(re.search(pattern, text_blob, re.IGNORECASE) for pattern in patterns):
            matched_groups.append(label)

    return bool(matched_groups), matched_groups


def _has_input_driven_state_signal(text_blob: str) -> bool:
    patterns = [
        r"\binput[\s-]*(?:driven|controlled|dependent|derived)\b",
        r"\bcontrolled by input\b",
        r"\bderived from input\b",
        r"\breachable via input\b",
        r"\bset by .*input\b",
        r"\binput .*state\b",
        r"\bstate .*input\b",
        r"\bparser state\b",
        r"\bfield-driven state\b",
    ]
    return any(re.search(pattern, text_blob, re.IGNORECASE) for pattern in patterns)




def build_non_input_rejection_decision(matched_groups: list[str]) -> dict[str, Any]:
    scope_text = ", ".join(matched_groups) if matched_groups else "non-input constraints"
    return {
        "decision": "proceed_but_not_input_driven",
        "reason": "non_input_dominated",
        "should_generate_input": True,
        "should_try_state_guided_workflow": True,
        "should_deprioritize_roadblock": False,
        "summary": (
            f"The roadblock is influenced by {scope_text}. This suggests we should keep non-input and state-guided "
            f"exploration open, but it does not prove the roadblock is impossible or unworthy."
        ),
        "input_drivenness_score": 0.4,
        "state_dependency_score": 0.75,
        "evidence_sufficiency_score": 0.8,
        "expected_depth_score": 0.85,
        "value_of_breaking_score": 0.55,
        "recommended_next_steps": ["prefer_state_guided", "prefer_batch_mutation", "allow_direct_generation"],
    }






def relax_conflict_gate_decision(decision_result: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(decision_result)
    reason = str(normalized.get('reason') or '')
    decision = str(normalized.get('decision') or '')
    recommended_steps = list(normalized.get('recommended_next_steps') or [])

    if reason == 'constraint_conflict':
        return normalized

    if decision == 'reject':
        normalized['decision'] = 'proceed'
    normalized['should_generate_input'] = True
    normalized['should_deprioritize_roadblock'] = False

    if reason == 'non_input_dominated':
        normalized['should_try_state_guided_workflow'] = True
        for step in ('prefer_state_guided', 'prefer_batch_mutation', 'allow_direct_generation'):
            if step not in recommended_steps:
                recommended_steps.append(step)
    elif reason in {'low_value_bottleneck', 'insufficient_evidence'}:
        if 'allow_direct_generation' not in recommended_steps:
            recommended_steps.append('allow_direct_generation')

    normalized['recommended_next_steps'] = recommended_steps
    return normalized


def _clamp_score(value: Any, default: float = 0.5) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, numeric))




def summarize_breakthrough_probe(assessment: dict[str, Any] | None) -> dict[str, Any]:
    assessment = assessment or {}
    is_key = bool(assessment.get('is_key_bottleneck'))
    worth_breaking = bool(assessment.get('worth_breaking_first'))
    input_only = bool(assessment.get('can_be_broken_by_input_alone'))
    blocker_type = str(assessment.get('primary_blocker_type') or '').strip().lower()
    recommended_action = str(assessment.get('recommended_action') or '').strip().lower()

    keep_actions = {
        'continue_breakthrough',
        'try_input_mutation',
        'try_state_guided',
        'try_hybrid',
        'prioritize_breakthrough',
        'keep_exploring',
    }
    skip_actions = {'change_target', 'defer_roadblock', 'skip'}
    likely_possible = input_only or blocker_type in {'input', 'format', 'program_state', 'stateful_input'}
    should_continue = (
        is_key
        or worth_breaking
        or likely_possible
        or recommended_action in keep_actions
    ) and recommended_action not in skip_actions

    confidence = 0.35
    if should_continue:
        confidence = 0.55
        if is_key:
            confidence += 0.15
        if worth_breaking:
            confidence += 0.15
        if input_only:
            confidence += 0.1
    elif recommended_action in skip_actions:
        confidence = 0.2

    return {
        'should_continue': should_continue,
        'confidence': round(max(0.0, min(1.0, confidence)), 2),
        'is_key_bottleneck': is_key,
        'worth_breaking_first': worth_breaking,
        'can_be_broken_by_input_alone': input_only,
        'primary_blocker_type': blocker_type,
        'recommended_action': recommended_action,
    }


def _probe_slice_line_for_roadblock(roadblock: dict[str, Any]) -> int | None:
    if roadblock.get("group_type") == "switch":
        switch_line = get_switch_statement_line(roadblock)
        if switch_line:
            return switch_line
        case_body_line = roadblock.get('case_body_line')
        if isinstance(case_body_line, int):
            return case_body_line
    rb_line = roadblock.get('line')
    return rb_line if isinstance(rb_line, int) else None


def _direct_generation_slice_cache_path(roadblock: dict[str, Any]) -> Path:
    roadblock_key = roadblock.get('roadblock_key') or get_roadblock_key(roadblock)
    digest = hashlib.sha1(str(roadblock_key).encode("utf-8", errors="ignore")).hexdigest()[:10]
    stem = sanitize_fs_component(
        f"{Path(str(roadblock.get('filename', 'unknown'))).name}_{roadblock.get('line', 0)}_{digest}"
    )
    return config.get_direct_generation_slice_path(stem)


def ensure_cached_single_function_slice(
    roadblock: dict[str, Any],
    llm_util: LLMUtil,
    *,
    dynamic_context: Optional[dict[str, Any]] = None,
) -> str | None:
    cached_slice = roadblock.get('cached_single_function_slice')
    if cached_slice and isinstance(cached_slice, str):
        return cached_slice
    disk_cache_path = _direct_generation_slice_cache_path(roadblock)
    if disk_cache_path.exists():
        disk_cached_slice = disk_cache_path.read_text(encoding="utf-8", errors="ignore").strip()
        if disk_cached_slice:
            roadblock['cached_single_function_slice'] = disk_cached_slice
            roadblock['cached_single_function_call_chain'] = roadblock.get('cached_single_function_call_chain') or []
            return disk_cached_slice

    rb_fname = roadblock.get('function') or get_function_name(roadblock)[0] or ""
    if not rb_fname:
        return None

    slice_line = _probe_slice_line_for_roadblock(roadblock)
    fallback_chain = [rb_fname.split('.')[0]]
    code_slice = get_function_slice(
        fallback_chain,
        slice_line,
        roadblock.get('status'),
        llm_util,
        dynamic_context=dynamic_context,
        original_target_line=roadblock.get('line'),
        target_file=roadblock.get('filename'),
    )
    if not code_slice or "No matching instruction found" in code_slice or len(code_slice) <= 50:
        return None

    roadblock['cached_single_function_slice'] = code_slice
    roadblock['cached_single_function_call_chain'] = fallback_chain
    disk_cache_path.parent.mkdir(parents=True, exist_ok=True)
    disk_cache_path.write_text(code_slice, encoding="utf-8")
    return code_slice


def probe_breakthrough_opportunity_from_slice(
    roadblock: dict[str, Any],
    llm_util: LLMUtil,
    *,
    dynamic_context: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    cached_probe = roadblock.get('slice_probe_result')
    if isinstance(cached_probe, dict) and cached_probe.get('available') is not None:
        return cached_probe

    rb_fname = roadblock.get('function') or get_function_name(roadblock)[0] or ""
    if not rb_fname:
        return {
            'available': False,
            'should_continue': False,
            'reason': 'missing_function_name',
        }

    code_slice = ensure_cached_single_function_slice(
        roadblock,
        llm_util,
        dynamic_context=dynamic_context,
    )
    if not code_slice:
        result = {
            'available': False,
            'should_continue': False,
            'reason': 'slice_unavailable',
        }
        roadblock['slice_probe_result'] = result
        return result

    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"
    constraint_messages = build_constraints_messages(roadblock, code_slice)
    for _ in range(MAX_TIME):
        resp = llm_util.get_response(constraint_messages)
        match = extract_json_with_fallback(resp, pattern_json)
        if not match:
            append_llm_retry_feedback(
                constraint_messages,
                resp,
                "请只返回一个 JSON object，并完整包含 analise_branch_v2 需要的所有字段。"
            )
            continue
        try:
            res = json.loads(match.group(1).strip())
        except json.JSONDecodeError as exc:
            append_llm_retry_feedback(
                constraint_messages,
                resp,
                f"JSON 解析失败：{exc}。请只返回一个合法的 JSON object，并完整包含 analise_branch_v2 需要的所有字段。"
            )
            continue
        analysis_error = validate_analysis_result_v2(res)
        if analysis_error:
            append_llm_retry_feedback(
                constraint_messages,
                resp,
                f"返回结构不符合要求：{analysis_error}。请只返回一个 JSON object，并完整包含 analise_branch_v2 需要的所有字段。"
            )
            continue

        assessment = res.get('breakthrough_assessment') or {}
        summary = summarize_breakthrough_probe(assessment)
        result = {
            'available': True,
            'should_continue': summary['should_continue'],
            'confidence': summary['confidence'],
            'analysis': res,
            'assessment': assessment,
            'assessment_summary': summary,
            'reasoning_summary': res.get('reasoning_summary', ''),
            'code_slice': code_slice,
            'used_single_function_slice': True,
        }
        roadblock['slice_probe_result'] = result
        return result

    result = {
        'available': False,
        'should_continue': False,
        'reason': 'analysis_failed',
    }
    roadblock['slice_probe_result'] = result
    return result









# Roadblocks that have already produced a validated local hit or have been
# finalized for the current session. Do not select them again.
resolved_roadblocks = set()
attempted_roadblocks = set()
attempted_roadblocks_path: Optional[Path] = None

# Dictionary to track failed roadblocks with metadata (no retry within session)
# Format: {roadblock_key: {'roadblock': roadblock_dict, 'timestamp': float, 'mode': str}}
pass_roadblock = {}
# Dictionary to track failed roadblock keys with timestamps (for quick lookup/logging)
# Format: {roadblock_key: float(timestamp)}
# Key format: "filename:line:status" (e.g., "src/cmscnvrt.c:1523:true")
pass_roadblock_id = {}
roadblock_local_hits: dict[str, dict[str, Any]] = {}

# Recent roadblock outcomes used to decide when to start zero-covered exploration
# earlier than full roadblock exhaustion.
recent_roadblock_outcomes = deque(maxlen=5)


def get_roadblock_key(roadblock):
    """
    生成瓶颈的唯一标识符（基于位置信息，不依赖 ID）

    Args:
        roadblock: 瓶颈字典

    Returns:
        str: 唯一标识符，格式 "filename:line:status"
    """
    filename = roadblock.get('filename', '')
    line = roadblock.get('line', 0)
    status = _canonicalize_roadblock_status(roadblock)
    group_type = roadblock.get('group_type')
    side = str(roadblock.get('side', '') or '').strip()

    if status in {"only_true", "only_false"}:
        status_fragment = status
    elif side:
        status_fragment = f"{status}:{side}"
    else:
        status_fragment = str(status)

    file_short = filename.split('/')[-1] if filename else 'unknown'
    if group_type == "switch":
        switch_line = int(roadblock.get('switch_statement_line', 0) or 0)
        case_body_line = int(roadblock.get('case_body_line', 0) or 0)
        group_index = int(roadblock.get('group_index', 0) or 0)
        case_label = str(roadblock.get('case_label', '') or '').strip()
        return (
            f"{file_short}:switch:{switch_line}:{line}:{case_body_line}:"
            f"{group_index}:{case_label}:{status_fragment}"
        )
    code = str(roadblock.get('code', '') or '').strip()
    return f"{file_short}:branch:{line}:{code}:{status_fragment}"


def init_attempted_roadblock_store() -> None:
    global attempted_roadblocks_path, attempted_roadblocks

    attempted_roadblocks.clear()
    if not output_dir:
        attempted_roadblocks_path = None
        return

    attempted_roadblocks_path = Path(output_dir) / "runtime" / "attempted_roadblocks.jsonl"
    attempted_roadblocks_path.parent.mkdir(parents=True, exist_ok=True)
    if not attempted_roadblocks_path.exists():
        return

    loaded = 0
    for line in attempted_roadblocks_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = str(payload.get("roadblock_key") or "").strip()
        if not key:
            continue
        attempted_roadblocks.add(key)
        loaded += 1

    logger.info(
        f"[{LogOp.ROADBLOCK}] Loaded {loaded} attempted roadblock record(s) from "
        f"{attempted_roadblocks_path}"
    )


def mark_roadblock_attempted(roadblock_key: str, roadblock: Optional[dict] = None, stage: str = "handle") -> None:
    global attempted_roadblocks, attempted_roadblocks_path

    if not roadblock_key or roadblock_key in attempted_roadblocks:
        return

    attempted_roadblocks.add(roadblock_key)
    if attempted_roadblocks_path is None:
        return

    record = {
        "roadblock_key": roadblock_key,
        "timestamp": time.time(),
        "stage": stage,
        "roadblock_id": (roadblock or {}).get("roadblock_id"),
        "filename": (roadblock or {}).get("filename"),
        "line": (roadblock or {}).get("line"),
        "status": (roadblock or {}).get("status"),
    }
    with attempted_roadblocks_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

# Statistics for indirect inference tracking
inference_stats = {
    'indirect_attempts': 0,  # Number of times indirect inference was used
    'indirect_successes': 0,  # Number of successful indirect inference resolutions
}

# ========== NEW: Global format detection variables ==========
# Global format detector instance (initialized once per session)
format_detector: Optional[InputFormatDetector] = None
# Cached format info for current project
cached_format_info: Optional[Dict[str, Any]] = None
# The project name associated with cached_format_info
cached_format_project: Optional[str] = None
cached_control_surface_profile: Optional[ControlSurfaceProfile] = None
cached_control_surface_project: Optional[str] = None
unreachable_roadblocks: dict[str, dict[str, Any]] = {}
roadblock_scope_failures = defaultdict(int)
taint_extraction_failures = 0
_seed_gate_size_policy_cache: dict[str, dict[str, float]] = {}
_roadblock_call_chain_summary_cache: dict[str, dict[str, Any]] = {}


# ========== End format detection variables ==========


def _tokenize_exec_args() -> list[str]:
    return [arg for arg in EXEC_ARGS.split(sep=" ") if arg]


def build_control_surface_profile(project: str | None = None) -> ControlSurfaceProfile:
    project = project or PROJECT
    harness_code = get_harness_code() or ""
    adapter_spec = get_input_adapter_spec(harness_code)
    argv_fixed = _tokenize_exec_args()
    runtime_context = build_runtime_command_context()
    input_channels: list[str] = []
    if adapter_spec.delivery == "stdin":
        input_channels.append("stdin")
    elif adapter_spec.delivery == "argv":
        input_channels.append("argv_value")
    else:
        input_channels.append("file_content")

    mutable_surfaces = ["seed_bytes"]
    if adapter_spec.delivery == "file":
        mutable_surfaces.append("seed_filename")
    mutable_surfaces.append("queue_mix")

    forbidden_surfaces = ["env", "filesystem_layout", "network", "build_flags"]
    if "@@" not in argv_fixed or project == "libxml":
        forbidden_surfaces.append("argv")
    if project == "libxml":
        forbidden_surfaces.extend(["aux_file", "argv"])
        mutable_surfaces = ["seed_bytes"]

    env_fixed: dict[str, str] = {}
    for key in ("TARGET_BRANCH", "BRANCH_FIELD_EXPORT", "FIELD_CONFIG_FILE"):
        if key in os.environ:
            env_fixed[key] = os.environ[key]

    return ControlSurfaceProfile(
        argv_fixed=argv_fixed,
        env_fixed=env_fixed,
        input_channels=input_channels,
        mutable_surfaces=list(dict.fromkeys(mutable_surfaces)),
        forbidden_surfaces=list(dict.fromkeys(forbidden_surfaces)),
        runtime_command_context=runtime_context,
        adapter_delivery=adapter_spec.delivery,
    )


def ensure_control_surface_profile() -> ControlSurfaceProfile:
    global cached_control_surface_profile, cached_control_surface_project
    if cached_control_surface_project == PROJECT and cached_control_surface_profile is not None:
        return cached_control_surface_profile
    cached_control_surface_profile = build_control_surface_profile(PROJECT)
    cached_control_surface_project = PROJECT
    logger.info(
        f"[CONTROL] Profile initialized for {PROJECT}: argv_fixed={cached_control_surface_profile.argv_fixed}, "
        f"input_channels={cached_control_surface_profile.input_channels}, "
        f"mutable={cached_control_surface_profile.mutable_surfaces}, "
        f"forbidden={cached_control_surface_profile.forbidden_surfaces}"
    )
    return cached_control_surface_profile


def _normalize_input_subspace_info(format_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    info = dict(format_info or {})
    info.setdefault("format_name", "")
    info.setdefault("entry_mode", "")
    info.setdefault("reachable_families", [])
    info.setdefault("blocked_families", [])
    info.setdefault("known_mode_requirements", {})
    info.setdefault("seed_constraints", {})
    info.setdefault("format_description", "")
    info.setdefault("key_fields", [])
    info.setdefault("common_constraints", [])
    return info


def ensure_cached_format_info(llm_util: LLMUtil) -> Optional[Dict[str, Any]]:
    """Ensure input format detection runs at most once per project per process."""
    global format_detector, cached_format_info, cached_format_project

    if cached_format_project == PROJECT and cached_format_info is not None:
        return _normalize_input_subspace_info(cached_format_info)

    if format_detector is None:
        logger.info("[FORMAT_DETECT] Initializing format detector")
        format_detector = get_format_detector(llm_util)

    control_surface_profile = ensure_control_surface_profile()
    cached_info = InputFormatDetector.get_cached_format(PROJECT)
    if cached_info is not None:
        cached_format_info = _normalize_input_subspace_info(cached_info)
        cached_format_project = PROJECT
        logger.info(f"[FORMAT_DETECT] Reusing cached format for {PROJECT}: {cached_info.get('format_name', 'unknown')}")
        return cached_format_info

    cached_format_info = format_detector.detect_format(
        PROJECT,
        detection_context={
            "runtime_command_context": control_surface_profile.runtime_command_context,
            "argv_fixed": control_surface_profile.argv_fixed,
            "input_channels": control_surface_profile.input_channels,
            "mutable_surfaces": control_surface_profile.mutable_surfaces,
            "forbidden_surfaces": control_surface_profile.forbidden_surfaces,
        },
    )
    cached_format_info = _normalize_input_subspace_info(cached_format_info)
    cached_format_project = PROJECT if cached_format_info is not None else None

    if cached_format_info:
        logger.info(
            f"[FORMAT_DETECT] Format detected: {cached_format_info.get('format_name', 'unknown')} "
            f"(entry_mode={cached_format_info.get('entry_mode', 'unknown')}, "
            f"reachable_families={cached_format_info.get('reachable_families', [])}, "
            f"blocked_families={cached_format_info.get('blocked_families', [])})"
        )
    else:
        logger.warning("[FORMAT_DETECT] Format detection failed, continuing without format hints")

    return cached_format_info


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()






def _call_chain_summary_for_function(function_name: str) -> dict[str, Any]:
    normalized_name = (function_name or "").split(".")[0]
    if not normalized_name:
        return {
            "chain_count": 0,
            "family_scores": {},
            "preferred_family": "unknown",
            "harness_reachable": False,
            "best_chain": [],
            "file_markers": [],
            "function_markers": [],
        }

    cached = _roadblock_call_chain_summary_cache.get(normalized_name)
    if cached is not None:
        return cached

    call_chains = get_call_chain(normalized_name) or []
    family_scores = Counter()
    file_markers: set[str] = set()
    function_markers: set[str] = set()
    harness_reachable = False
    best_chain = None
    best_score = None

    for chain in call_chains:
        score = _score_input_driven_call_chain(chain)
        if best_score is None or score > best_score:
            best_chain = chain
            best_score = score

        for node in chain:
            func_name = (_chain_node_name(node) or "").strip()
            func_lower = _normalize_text(func_name)
            function_markers.add(func_name)
            meta = _lookup_func_meta_by_name(func_name)
            file_name = (meta.get("file_name", "") if meta else "") or ""
            file_lower = _normalize_text(Path(file_name).name if file_name else "")
            if file_name:
                file_markers.add(Path(file_name).name)

            if func_lower in {"main", "llvmfuzzertestoneinput"}:
                harness_reachable = True
            if "xpath" in func_lower or "xpath" in file_lower:
                family_scores["api.xpath"] += 4
            if any(token in func_lower for token in ("xmlschema", "relaxng", "validate")) or any(
                token in file_lower for token in ("xmlschemas", "relaxng")
            ):
                family_scores["schema.validation"] += 4
            if func_lower.startswith("htmlparse") or "htmlparser" in file_lower:
                family_scores["parser.html"] += 3
            if any(token in func_lower for token in ("xmlparse", "xmlload", "xmlread", "xmlctxt", "parse")):
                family_scores["parser.xml"] += 2
            if file_lower in {"parser.c", "encoding.c", "uri.c", "xmlio.c", "parserinternals.c"}:
                family_scores["parser.xml"] += 2
            if file_lower == "valid.c":
                family_scores["schema.validation"] += 3

    preferred_family = "unknown"
    if family_scores:
        preferred_family, _ = max(
            family_scores.items(),
            key=lambda item: (item[1], 1 if item[0].startswith("parser.") else 0),
        )

    summary = {
        "chain_count": len(call_chains),
        "family_scores": dict(family_scores),
        "preferred_family": preferred_family,
        "harness_reachable": harness_reachable,
        "best_chain": [_chain_node_name(node) for node in (best_chain or []) if _chain_node_name(node)],
        "file_markers": sorted(file_markers),
        "function_markers": sorted(function_markers),
    }
    _roadblock_call_chain_summary_cache[normalized_name] = summary
    return summary


def _roadblock_failure_scope_key(roadblock: dict[str, Any], family: str) -> str:
    filename = Path(str(roadblock.get("filename") or "")).name or "unknown"
    function_name = str(roadblock.get("function") or get_function_name(roadblock)[0] or "")
    summary = _call_chain_summary_for_function(function_name)
    best_chain = summary.get("best_chain") or []
    anchor = best_chain[1] if len(best_chain) > 1 else (best_chain[0] if best_chain else function_name or filename)
    anchor = _normalize_text(anchor) or "unknown"
    return f"{family}:{filename}:{anchor}"




def screen_roadblocks_with_llm(
    roadblocks: list[dict[str, Any]],
    llm_util: LLMUtil,
    *,
    budget: int | None = None,
) -> list[dict[str, Any]]:
    if budget is not None and budget <= 0:
        return roadblocks

    screened = 0
    for rb in roadblocks:
        if budget is not None and screened >= budget:
            break
        if rb.get('slice_probe_result') is not None:
            continue

        probe_result = probe_breakthrough_opportunity_from_slice(rb, llm_util)
        rb['slice_probe_result'] = probe_result
        screened += 1
        if not probe_result.get('available'):
            logger.info(
                f"[{LogOp.ROADBLOCK}] Slice probe unavailable for {rb.get('roadblock_key')} "
                f"(reason={probe_result.get('reason', 'unknown')})"
            )
            rb['reachability_decision'] = 'llm_screen_inconclusive'
            rb['reachability_reason'] = probe_result.get('reason', 'slice_probe_unavailable')
            rb['frontier_distance'] = 3
            rb['triage_tier'] = 'Tier B'
            rb['evidence_strength'] = max(float(rb.get('evidence_strength', 0.2) or 0.2), 0.25)
            continue

        summary = probe_result.get('assessment_summary') or {}
        confidence = float(probe_result.get('confidence', 0.0) or 0.0)
        should_continue = bool(probe_result.get('should_continue'))
        logger.info(
            f"[{LogOp.ROADBLOCK}] Slice probe for {rb.get('roadblock_key')}: "
            f"should_continue={should_continue}, "
            f"confidence={confidence:.2f}, "
            f"action={summary.get('recommended_action', 'unknown')}, "
            f"reasoning={probe_result.get('reasoning_summary', '')}"
        )

        if should_continue and confidence >= 0.75:
            rb['reachability_decision'] = 'llm_screen_selected'
            rb['reachability_reason'] = 'slice_probe_high_confidence'
            rb['frontier_distance'] = 0
            rb['triage_tier'] = 'Tier A'
            rb['evidence_strength'] = max(float(rb.get('evidence_strength', 0.35) or 0.35), confidence)
            rb['slice_probe_promoted'] = True
        elif should_continue:
            rb['reachability_decision'] = 'llm_screen_selected'
            rb['reachability_reason'] = 'slice_probe_positive'
            rb['frontier_distance'] = 1
            rb['triage_tier'] = 'Tier B'
            rb['evidence_strength'] = max(float(rb.get('evidence_strength', 0.35) or 0.35), confidence)
            rb['slice_probe_promoted'] = True
        else:
            rb['reachability_decision'] = 'llm_screen_rejected'
            rb['reachability_reason'] = 'slice_probe_low_opportunity'
            rb['frontier_distance'] = 5
            rb['triage_tier'] = 'Tier C'
            rb['evidence_strength'] = min(float(rb.get('evidence_strength', 0.35) or 0.35), 0.2)
            continue

    return roadblocks


def rank_roadblocks_with_frontier_distance(roadblocks) -> list:
    decision_order = {
        "llm_screen_selected": 0,
        "llm_screen_inconclusive": 1,
        "llm_screen_rejected": 2,
        "reachable": 0,
        "reachable_but_weak_signal": 1,
        "slice_probe_promoted": 1,
        "unreachable_due_to_control_surface": 2,
        "cooled_down": 3,
    }

    def sort_key(rb):
        return (
            decision_order.get(rb.get("reachability_decision", "reachable"), 3),
            int(rb.get("frontier_distance", 0)),
            _roadblock_low_leverage_penalty(rb),
            0 if rb.get("triage_tier") == "Tier A" else 1,
            rb.get("roadblock_id") if isinstance(rb.get("roadblock_id"), int) else (1 << 30),
        )

    return sorted(
        roadblocks,
        key=sort_key,
    )


def _roadblock_source_file_key(roadblock: dict[str, Any]) -> str:
    filename = roadblock.get("filename") or ""
    return Path(filename).name if filename else ""


def _roadblock_function_key(roadblock: dict[str, Any]) -> str:
    return str(roadblock.get("function") or "")


def _roadblock_low_leverage_penalty(roadblock: dict[str, Any]) -> int:
    filename = _normalize_text(_roadblock_source_file_key(roadblock))
    function_name = _normalize_text(_roadblock_function_key(roadblock))
    code = " ".join(str(roadblock.get("code") or "").split())
    guard_filter = roadblock.get("guard_filter")
    if not isinstance(guard_filter, dict):
        guard_filter = analyze_low_value_guard_roadblock(roadblock)
        roadblock["guard_filter"] = guard_filter

    if guard_filter.get("should_skip"):
        return 6

    if not code:
        return 0

    is_alias_compare = "!strcmp(" in code or "strcmp(" in code
    is_immediate_return = "return(" in code or "return (" in code
    returns_encoding_enum = "XML_CHAR_ENCODING_" in code

    if filename == "encoding.c" and function_name == "xmlparsecharencoding":
        if is_alias_compare:
            return 4
        if "alias != NULL" in code:
            return 1

    if is_alias_compare and is_immediate_return:
        return 2
    return 0


def select_stage_roadblocks(roadblocks, budget: int) -> list:
    if budget <= 0 or not roadblocks:
        return []

    selected = []
    deferred = []
    file_counts = defaultdict(int)
    function_counts = defaultdict(int)

    for rb in roadblocks:
        file_key = _roadblock_source_file_key(rb)
        function_key = _roadblock_function_key(rb)
        low_leverage_penalty = _roadblock_low_leverage_penalty(rb)

        file_limit = ROADBLOCK_PER_FILE_STAGE_LIMIT if low_leverage_penalty >= 2 else max(ROADBLOCK_PER_FILE_STAGE_LIMIT, 2)
        function_limit = ROADBLOCK_PER_FUNCTION_STAGE_LIMIT if low_leverage_penalty >= 2 else max(ROADBLOCK_PER_FUNCTION_STAGE_LIMIT, 2)

        file_saturated = bool(file_key) and file_counts[file_key] >= file_limit
        function_saturated = bool(function_key) and function_counts[function_key] >= function_limit
        if file_saturated or function_saturated:
            deferred.append(rb)
            continue

        selected.append(rb)
        if file_key:
            file_counts[file_key] += 1
        if function_key:
            function_counts[function_key] += 1
        if len(selected) >= budget:
            return selected

    for rb in deferred:
        selected.append(rb)
        if len(selected) >= budget:
            break

    return selected






@dataclass
class PlateauAttemptContext:
    tracer: CoverageTracer
    llm_util: LLMUtil
    stuck_time: float
    roadblocks: list[dict]
    last_scan_time: int
    read_files: set


@dataclass
class PathEpochState:
    path_name: str
    started: bool = False
    completed: bool = False
    completion_reason: str = ""
    coverage_breakthrough_seen: bool = False
    attempt_count: int = 0
    last_candidate_key: str | None = None


class PlateauPathScheduler:
    def __init__(self, path_name: str, runtime_dir: Path):
        self.path_name = path_name
        self.scheduler = AttemptScheduler(path_name, runtime_dir / f"{path_name}.json")

    def refresh_candidates(self, context: PlateauAttemptContext) -> list[SchedulerCandidate]:
        raise NotImplementedError

    def execute(self, candidate: SchedulerCandidate, context: PlateauAttemptContext) -> SchedulerResult:
        raise NotImplementedError

    def select_candidate(self, context: PlateauAttemptContext) -> SchedulerCandidate | None:
        candidates = self.scheduler.sync_candidates(self.refresh_candidates(context))
        return self.scheduler.select_candidate(candidates)

    def record_result(self, candidate: SchedulerCandidate, result: SchedulerResult) -> None:
        self.scheduler.record_result(candidate, result)


class DirectGenerationScheduler(PlateauPathScheduler):
    def __init__(self, runtime_dir: Path):
        super().__init__("direct_generation", runtime_dir)

    def refresh_candidates(self, context: PlateauAttemptContext) -> list[SchedulerCandidate]:
        candidates: list[SchedulerCandidate] = []
        for roadblock in context.roadblocks:
            roadblock_key = roadblock.get('roadblock_key') or get_roadblock_key(roadblock)
            if roadblock_key in resolved_roadblocks or roadblock_key in pass_roadblock_id:
                continue
            candidates.append(
                SchedulerCandidate(
                    path_name=self.path_name,
                    candidate_key=roadblock_key,
                    target_key=roadblock_key,
                    prepared_context_ref=roadblock_key,
                    score=20.0,
                    payload={"roadblock": roadblock},
                )
            )
        return candidates

    def execute(self, candidate: SchedulerCandidate, context: PlateauAttemptContext) -> SchedulerResult:
        roadblock = candidate.payload["roadblock"]
        attempted, mode, _, _ = handle_roadblock_direct_generation_only(roadblock, context.tracer, context.llm_util)
        stuck_time = context.tracer.check_coverage_growth()
        return SchedulerResult(
            attempted=attempted,
            success=attempted,
            mode=mode,
            coverage_breakthrough=stuck_time < THRESHOLD_TIME,
        )


class SimplifiedPathScheduler(PlateauPathScheduler):
    def __init__(self, path_name: str, runtime_dir: Path, *, base_score: float):
        super().__init__(path_name, runtime_dir)
        self.base_score = base_score

    def refresh_candidates(self, context: PlateauAttemptContext) -> list[SchedulerCandidate]:
        candidates: list[SchedulerCandidate] = []
        for roadblock in context.roadblocks:
            roadblock_key = roadblock.get('roadblock_key') or get_roadblock_key(roadblock)
            if roadblock_key in resolved_roadblocks or roadblock_key in pass_roadblock_id:
                continue
            candidates.append(
                SchedulerCandidate(
                    path_name=self.path_name,
                    candidate_key=f"{self.path_name}:{roadblock_key}",
                    target_key=roadblock_key,
                    prepared_context_ref=roadblock_key,
                    score=self.base_score,
                    payload={"roadblock": roadblock},
                )
            )
        return candidates

    def execute(self, candidate: SchedulerCandidate, context: PlateauAttemptContext) -> SchedulerResult:
        roadblock = candidate.payload["roadblock"]
        attempted, mode, _, _ = handle_roadblock_simplified(
            roadblock,
            context.tracer,
            context.llm_util,
            selected_paths={self.path_name},
            mark_attempted=False,
        )
        stuck_time = context.tracer.check_coverage_growth()
        return SchedulerResult(
            attempted=attempted,
            success=attempted,
            mode=mode,
            coverage_breakthrough=stuck_time < THRESHOLD_TIME,
        )


class PlateauAttemptOrchestrator:
    def __init__(self, tracer: CoverageTracer, llm_util: LLMUtil):
        self.tracer = tracer
        self.llm_util = llm_util
        self.runtime_dir = Path(output_dir) / "runtime" / "scheduler"
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.schedulers: list[PlateauPathScheduler] = []
        self.active_epoch_id = 0
        self.epoch_active = False
        self.path_epoch_states: dict[str, PathEpochState] = {}
        if ENABLE_SIMPLIFIED_DIRECT_GENERATION_PATH:
            self.schedulers.append(DirectGenerationScheduler(self.runtime_dir))
        if ENABLE_SIMPLIFIED_FLAG_PATH:
            self.schedulers.append(SimplifiedPathScheduler("flag", self.runtime_dir, base_score=19.0))
        if ENABLE_SIMPLIFIED_TAINT_MUTATION_PATH:
            self.schedulers.append(SimplifiedPathScheduler("taint_mutation", self.runtime_dir, base_score=18.0))
        if ENABLE_SIMPLIFIED_STATE_DRIVEN_PATH and ENABLE_STATE_DRIVEN_PATH_B:
            self.schedulers.append(SimplifiedPathScheduler("state_driven", self.runtime_dir, base_score=17.0))
        if ENABLE_SIMPLIFIED_FIELD_MUTATION_PATH:
            self.schedulers.append(SimplifiedPathScheduler("field_mutation", self.runtime_dir, base_score=16.0))
        if ENABLE_SIMPLIFIED_XML_GRAMMAR_PATH:
            self.schedulers.append(SimplifiedPathScheduler("xml_grammar", self.runtime_dir, base_score=15.0))
        if ENABLE_SIMPLIFIED_BATCH_MUTATION_PATH:
            self.schedulers.append(SimplifiedPathScheduler("batch_mutation", self.runtime_dir, base_score=14.0))
        self._reset_epoch_states()

    def _reset_epoch_states(self) -> None:
        self.path_epoch_states = {
            scheduler.path_name: PathEpochState(path_name=scheduler.path_name)
            for scheduler in self.schedulers
        }

    def has_active_epoch(self) -> bool:
        return self.epoch_active

    def start_new_epoch(self, stuck_time: float) -> None:
        self.active_epoch_id += 1
        self.epoch_active = True
        self._reset_epoch_states()
        logger.info(
            f"[{LogOp.ROADBLOCK}] Starting plateau epoch {self.active_epoch_id} "
            f"(stuck_time={stuck_time:.1f}s, paths={len(self.schedulers)})"
        )

    def close_epoch(self, reason: str) -> None:
        if not self.epoch_active:
            return
        logger.info(
            f"[{LogOp.ROADBLOCK}] Plateau epoch {self.active_epoch_id} finished: {reason}"
        )
        for state in self.path_epoch_states.values():
            logger.info(
                f"[{LogOp.ROADBLOCK}] Epoch {self.active_epoch_id} path `{state.path_name}` "
                f"summary: completed={state.completed}, attempts={state.attempt_count}, "
                f"coverage_breakthrough_seen={state.coverage_breakthrough_seen}, "
                f"last_candidate={state.last_candidate_key or 'N/A'}, "
                f"reason={state.completion_reason or 'pending'}"
            )
        self.epoch_active = False
        self._reset_epoch_states()

    @staticmethod
    def prepare_roadblocks(roadblocks: list[dict]) -> list[dict]:
        prepared_roadblocks = []
        for rb in roadblocks:
            rb['roadblock_id'] = rb.get('roadblock_id') or get_rb_id(rb)
            rb['roadblock_key'] = rb.get('roadblock_key') or get_roadblock_key(rb)
            rb['function'] = rb.get('function') or get_function_name(rb)[0]
            prepared_roadblocks.append(rb)
        return prepared_roadblocks

    def run_cycle(self, last_scan_time, read_files, stuck_time):
        if not self.epoch_active:
            self.start_new_epoch(stuck_time)

        # 检查是否启用停滞后trace模块
        # 如果禁用，直接使用现有的一side分支数据，不运行完整trace
        if not config.ENABLE_STAGNATION_TRACE:
            logger.info(f"[{LogOp.ROADBLOCK}] Stagnation trace disabled, using existing one-sided branches")
            roadblocks = self.tracer.get_current_one_sided_branches()
            ret = bool(roadblocks)
            error_info = "Trace disabled by config" if not ret else "Using cached branches"
        else:
            ret, last_scan_time, error_info, roadblocks = self.tracer.get_trace(read_files, last_scan_time)

        self.tracer.kick_autobug_prime_async()
        if not ret:
            if "没有新的seed" in error_info:
                logger.info(f"[{LogOp.ROADBLOCK}] {error_info}")
                logger.info(f"[{LogOp.ROADBLOCK}] Reusing current one-sided branches for epoch {self.active_epoch_id}")
                roadblocks = self.tracer.get_current_one_sided_branches()
            else:
                logger.critical(f"[{LogOp.ROADBLOCK}] Coverage trace extraction failed: {error_info}")
                logger.critical("Cannot proceed without valid trace data")
                sys.exit(1)

        if not roadblocks:
            logger.info(f"[{LogOp.ROADBLOCK}] No roadblocks available for epoch {self.active_epoch_id}")
            self.close_epoch("no_roadblocks")
            return False, last_scan_time, read_files

        prepared_roadblocks = self.prepare_roadblocks(roadblocks)

        # Pick one roadblock for this cycle via scheduler scoring
        context = PlateauAttemptContext(
            tracer=self.tracer,
            llm_util=self.llm_util,
            stuck_time=stuck_time,
            roadblocks=prepared_roadblocks,
            last_scan_time=last_scan_time,
            read_files=read_files,
        )
        # Use the first scheduler to pick a roadblock (all schedulers see the same candidates)
        picker = self.schedulers[0] if self.schedulers else None
        if picker is None:
            self.close_epoch("no_schedulers")
            return False, last_scan_time, read_files
        picked = picker.select_candidate(context)
        if picked is None:
            logger.info(f"[{LogOp.ROADBLOCK}] Epoch {self.active_epoch_id} no eligible roadblock candidate")
            self.close_epoch("no_eligible_candidates")
            return False, last_scan_time, read_files
        roadblock = picked.payload["roadblock"]
        roadblock_key = picked.target_key
        logger.info(
            f"[{LogOp.ROADBLOCK}] Epoch {self.active_epoch_id} selected roadblock {roadblock_key} "
            f"(score={picked.score:.1f}, failures={picked.failure_count})"
        )

        # LLM router decides which paths to try for this specific roadblock
        attempted, mode, _, roadblock_id = handle_roadblock_simplified(
            roadblock,
            self.tracer,
            self.llm_util,
            selected_paths=None,  # None → triggers LLM path router
            mark_attempted=False,
        )

        any_success = attempted
        stuck_time_after = self.tracer.check_coverage_growth()
        coverage_breakthrough = stuck_time_after < THRESHOLD_TIME

        if coverage_breakthrough:
            reset_roadblock_outcomes()
            logger.info(
                f"[{LogOp.ROADBLOCK}] Epoch {self.active_epoch_id} coverage breakthrough "
                f"after router-planned attempt (mode={mode})"
            )
            self.close_epoch(f"coverage_breakthrough:{mode}")
        else:
            logger.info(
                f"[{LogOp.ROADBLOCK}] Epoch {self.active_epoch_id} router-planned attempt "
                f"finished without breakthrough (mode={mode}, attempted={attempted})"
            )

        return any_success, last_scan_time, read_files


def update_pass_roadblock():
    """
    Iterative update mechanism for pass_roadblock lists.
    Failed roadblocks are retained for the current session and are not retried.
    RESOLVED roadblocks are also kept permanently for the session.

    Returns:
        int: Always 0 because failed roadblocks are no longer released for retry
    """
    global pass_roadblock_id, resolved_roadblocks

    logger.debug(
        f"[{LogOp.ROADBLOCK}] Iterative update: failed roadblocks stay skipped for this session, "
        f"current failed: {len(pass_roadblock_id)}, resolved: {len(resolved_roadblocks)}")
    return 0


def mark_roadblock_resolved(roadblock_key, mode):
    """
    记录瓶颈局部命中，但默认不做永久封锁。

    Args:
        roadblock_key: 瓶颈的唯一标识符
        mode: 命中模式 (FLAG, MUT_TAINT, LLM, etc.)
    """
    global pass_roadblock, pass_roadblock_id, unreachable_roadblocks, roadblock_local_hits, resolved_roadblocks

    roadblock_local_hits[roadblock_key] = {
        "timestamp": time.time(),
        "mode": mode,
    }
    resolved_roadblocks.add(roadblock_key)
    pass_roadblock[roadblock_key] = {
        "roadblock": pass_roadblock.get(roadblock_key, {}).get("roadblock"),
        "timestamp": time.time(),
        "mode": f"ATTEMPTED_LOCAL_HIT:{mode}",
    }
    pass_roadblock_id[roadblock_key] = time.time()
    unreachable_roadblocks.pop(roadblock_key, None)

    logger.info(
        f"[{LogOp.ROADBLOCK}] Roadblock {roadblock_key} recorded as LOCALLY_HIT "
        f"(mode: {mode}, skip for the rest of this session)"
    )


def mark_roadblock_failed(roadblock_key, mode, roadblock):
    """
    标记瓶颈为失败（当前 session 内不再重试）

    Args:
        roadblock_key: 瓶颈的唯一标识符
        mode: 失败时的模式
        roadblock: 瓶颈字典
    """
    global pass_roadblock, pass_roadblock_id, roadblock_scope_failures, unreachable_roadblocks

    # 添加到失败列表
    pass_roadblock[roadblock_key] = {
        'roadblock': roadblock,
        'timestamp': time.time(),
        'mode': mode
    }
    pass_roadblock_id[roadblock_key] = time.time()
    subspace_info = (roadblock or {}).get("subspace_info", {})
    family = subspace_info.get("subspace_family", "unknown")
    failure_scope_key = subspace_info.get("failure_scope_key") or _roadblock_failure_scope_key(roadblock or {}, family)
    if family and family != "unknown":
        roadblock_scope_failures[failure_scope_key] += 1
    if mode == "UNREACHABLE_CONTROL_SURFACE":
        unreachable_roadblocks[roadblock_key] = {
            "roadblock": roadblock,
            "mode": mode,
            "timestamp": time.time(),
        }

    logger.debug(f"[{LogOp.ROADBLOCK}] Roadblock {roadblock_key} marked as FAILED (mode: {mode}, skip for this session)")


def get_state_hints(roadblock: dict, code_slice: str, project: str) -> list:
    """
    从代码切片中识别状态变量，并返回输入映射提示。

    这是Phase 1轻量级实现，使用硬编码的领域知识来识别常见状态变量。

    Args:
        roadblock: roadblock信息字典
        code_slice: 代码切片
        project: 项目名称（如"lcms"）

    Returns:
        list: 状态提示字符串列表，每个提示说明如何通过修改输入来设置状态
    """
    hints = []

    # 只处理已定义的领域知识
    if project == "lcms":
        # lcms的ICC Profile状态变量映射
        code_lower = code_slice.lower()

        # 检测ColorSpace相关状态
        colorspace_indicators = ['colorspace', 'color_space', 'colorsig', 'pt_rgb', 'pt_lab',
                                 'pt_xyz', 'pt_gray', 'pt_cmyk', 'lcmscolorspace']
        if any(indicator in code_lower for indicator in colorspace_indicators):
            hints.append(
                "[STATE] 检测到ColorSpace相关状态变量。"
                "ICC Profile偏移16-19存储颜色空间签名（4字节，big-endian）："
                "RGB=0x52474220, LAB=0x4C414220, CMYK=0x434D594B, XYZ=0x58595A20, GRAY=0x47524159"
            )

        # 检测DeviceClass相关状态
        devclass_indicators = ['deviceclass', 'device_class', 'devclass', 'cmsgetdeviceclass',
                               'cmsigdisplayclass', 'mntr', 'prtr', 'scnr', 'link', 'abst']
        if any(indicator in code_lower for indicator in devclass_indicators):
            hints.append(
                "[STATE] 检测到DeviceClass相关状态变量。"
                "ICC Profile偏移12-15存储设备类别签名（4字节，big-endian）："
                "Display(mntr)=0x6D6E7472, Printer(prtr)=0x70727472, Scanner(scnr)=0x73636E72"
            )

        # 检测PCS相关状态
        pcs_indicators = ['pcs', 'profileconnection', 'connection_space', 'cmsgetpcs']
        if any(indicator in code_lower for indicator in pcs_indicators):
            hints.append(
                "[STATE] 检测到PCS(Profile Connection Space)相关状态变量。"
                "ICC Profile偏移20-23存储PCS签名（4字节，big-endian）："
                "XYZ=0x58595A20, Lab=0x4C616220"
            )

        # 检测RenderingIntent相关状态
        intent_indicators = ['renderingintent', 'rendering_intent', 'intent', 'perceptual',
                             'relative', 'saturation', 'absolute']
        if any(indicator in code_lower for indicator in intent_indicators):
            hints.append(
                "[STATE] 检测到RenderingIntent相关状态变量。"
                "ICC Profile偏移64-67存储渲染意图（4字节，big-endian）："
                "0=Perceptual(感知), 1=Relative(相对色度), 2=Saturation(饱和), 3=Absolute(绝对色度)"
            )

        # 检测profile结构体字段（通用模式）
        if 'profile->' in code_slice or 'hprofile' in code_lower:
            # 提取具体的profile字段名
            import re
            profile_fields = re.findall(r'profile->(\w+)', code_slice)
            if profile_fields:
                unique_fields = list(set(profile_fields))
                hints.append(
                    f"[STATE] 检测到profile结构体字段访问: {', '.join(unique_fields[:5])}。"
                    f"这些字段通常从ICC Profile header解析得到，可通过修改对应偏移的字节来控制。"
                )

    # 可以在这里添加其他项目的状态变量映射
    # elif project == "libpng":
    #     ...

    if hints:
        logger.info(f"[STATE] 识别到{len(hints)}个状态变量提示")
        for hint in hints:
            logger.debug(f"[STATE] {hint}")

    return hints


def _extract_call_chain_function_names(call_chain) -> list[str]:
    names = []
    for node in call_chain or []:
        if isinstance(node, dict):
            func_name = node.get("function") or node.get("name")
        else:
            func_name = str(node)
        if func_name and func_name not in names:
            names.append(func_name)
    return names


def _chain_node_name(node) -> str:
    if isinstance(node, dict):
        return node.get("function") or node.get("name") or ""
    return str(node) if node is not None else ""


def _get_function_meta(func_name: str) -> Optional[dict]:
    return next((item for item in funcs if item.get("name") == func_name), None)


def _lookup_func_meta_by_name(func_name: str) -> dict | None:
    """Look up function metadata from the global funcs list by name."""
    for func in funcs:
        if func.get('name') == func_name:
            return func
    return None


def reset_roadblock_outcomes():
    """Clear recent roadblock history after a coverage breakthrough."""
    recent_roadblock_outcomes.clear()


def _build_parser_free_text_fields(seed_name: str, harness_code: str | None = None) -> dict[str, Any] | None:
    """Build semantic fields from parser free-text seed by tokenizing lines."""
    seed_path = config.find_seed_path(seed_name)
    if seed_path is None or not seed_path.exists():
        return None

    payload = read_seed_payload_view(seed_path, harness_code)
    if not payload:
        try:
            payload = seed_path.read_bytes()
        except OSError:
            return None

    text = payload.decode("utf-8", errors="replace")
    if not text:
        return None

    quoted_re = re.compile(r'"([^"\\]|\\.)*"|\'([^\'\\]|\\.)*\'')
    number_re = re.compile(r"\b(?:0x[0-9A-Fa-f]+|\d+(?:\.\d+)?)\b")
    ident_re = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
    key_value_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*([^\s#;,)\]}]+)")

    fields: list[dict[str, Any]] = []
    line_start = 0
    for line_no, line in enumerate(text.splitlines(keepends=True), start=1):
        line_end = line_start + len(line)
        stripped = line.rstrip("\r\n")
        if stripped:
            fields.append({
                "name": f"line[{line_no}]",
                "kind": "line",
                "offset": line_start,
                "size": len(stripped),
                "end": line_start + len(stripped),
                "value": stripped[:PROMPT_SEMANTIC_FIELD_VALUE_LIMIT],
                "path": f"/line[{line_no}]",
                "reliable": False,
            })

        for match in key_value_re.finditer(line):
            key_start, _ = match.span(1)
            value_start, value_end = match.span(2)
            fields.append({
                "name": f"line[{line_no}].{match.group(1)}",
                "kind": "key_value",
                "offset": line_start + key_start,
                "size": value_end - key_start,
                "end": line_start + value_end,
                "value": match.group(2)[:PROMPT_SEMANTIC_FIELD_VALUE_LIMIT],
                "value_offset": line_start + value_start,
                "value_end": line_start + value_end,
                "path": f"/line[{line_no}]/{match.group(1)}",
                "reliable": False,
            })

        for regex, kind in ((quoted_re, "quoted_string"), (number_re, "number"), (ident_re, "token")):
            for idx, match in enumerate(regex.finditer(line), start=1):
                start, end = match.span()
                fields.append({
                    "name": f"line[{line_no}].{kind}[{idx}]",
                    "kind": kind,
                    "offset": line_start + start,
                    "size": end - start,
                    "end": line_start + end,
                    "value": match.group(0)[:PROMPT_SEMANTIC_FIELD_VALUE_LIMIT],
                    "path": f"/line[{line_no}]/{kind}[{idx}]",
                    "reliable": False,
                })

        line_start = line_end

    return {
        "format": "parser_free_text",
        "parser": "line_tokenizer_fallback",
        "well_formed": True,
        "file_path": seed_path.name,
        "fields": fields,
    }


def _normalize_text_mutation_fields(fields, seed_name: str | None = None, harness_code: str | None = None):
    """Normalize text mutation fields, building from seed if needed."""
    if fields:
        return fields
    if seed_name:
        return _build_parser_free_text_fields(seed_name, harness_code=harness_code)
    return None


def _looks_textual_semantic_input(fields=None, harness_code: str | None = None) -> bool:
    """Check if the input appears to be textual/semantic based on fields and harness."""
    text_keywords = {"xml", "json", "yaml", "toml", "ini", "csv", "sql", "javascript", "text", "source"}
    if cached_format_info:
        format_name = str(cached_format_info.get("format_name", "")).lower()
        format_desc = str(cached_format_info.get("format_description", "")).lower()
        if any(keyword in format_name or keyword in format_desc for keyword in text_keywords):
            return True
    if isinstance(fields, dict):
        field_items = fields.get("fields", [])
    else:
        field_items = fields or []
    text_kinds = {
        "element_name", "attribute", "xml_decl_attr", "text", "cdata", "comment",
        "string", "object_key", "quoted_string", "line", "key_value", "identifier",
        "function_name", "callee", "property_name", "include_path", "import_path",
        "preprocessor", "string_literal",
    }
    for item in field_items[:32]:
        kind = str(item.get("kind", "")).lower()
        if kind in text_kinds:
            return True
    if harness_code:
        lowered = (harness_code or "").lower()
        return any(token in lowered for token in ("parse", "xml", "json", "yaml", "read", "decode"))
    return False


def summarize_semantic_fields(fields, max_fields: int = 12) -> str:
    """Summarize semantic fields for prompt inclusion."""
    if not fields:
        return "(none)"
    if isinstance(fields, dict):
        field_items = fields.get("fields", [])
    else:
        field_items = fields
    lines: list[str] = []
    for item in field_items[:max_fields]:
        name = item.get("name", "?")
        kind = item.get("kind", "?")
        path = item.get("path") or item.get("json_path") or item.get("lxml_path") or ""
        offset = item.get("offset")
        size = item.get("size")
        role = item.get("semantic_role") or item.get("editable") or ""
        reliable = item.get("reliable", True)
        line_parts = [f"- {name}"]
        if kind != "?":
            line_parts.append(f"kind={kind}")
        if path:
            line_parts.append(f"path={path}")
        if offset is not None:
            line_parts.append(f"offset={offset}")
        if size is not None:
            line_parts.append(f"size={size}")
        if role:
            line_parts.append(f"role={role}")
        if not reliable:
            line_parts.append("unreliable")
        lines.append(" ".join(line_parts))
    if len(field_items) > max_fields:
        lines.append(f"... ({len(field_items) - max_fields} more fields omitted)")
    return "\n".join(lines)


def _describe_seed_delivery() -> str:
    """Describe how the seed is delivered to the target."""
    exec_args = [arg for arg in EXEC_ARGS.split(sep=" ") if arg]
    if "@@" in exec_args:
        return (
            "seed_delivery: file_content_via_placeholder\n"
            "important:\n"
            "- The generated input becomes the contents of the seed file substituted into `@@`.\n"
            "- Do not invent extra target argv options unless they already appear in target_args_template.\n"
            "- If a branch is only reachable by changing target argv flags that are not present in target_args_template, "
            "treat that branch as runtime-argument-driven rather than seed-content-driven.\n"
            "- Prefer paths that consume/parses the seed file contents over generic help, usage, version, or option-parser paths."
        )
    spec = get_input_adapter_spec()
    if spec.delivery == "stdin":
        return "seed_delivery: stdin"
    return f"seed_delivery: argv_positional (args={exec_args})"


def build_input_container_profile(
    generation_mode: str,
    *,
    fields=None,
    harness_code: str | None = None,
    preferred_seed: str | None = None,
) -> str:
    """Build a profile description of the input container for LLM prompts."""
    payload_format = "unknown"
    if cached_format_info:
        payload_format = cached_format_info.get("format_name") or payload_format
    is_textual = _looks_textual_semantic_input(fields=fields, harness_code=harness_code)
    layered = generation_mode != "text_direct" and is_textual
    wrapper_signals: list[str] = []
    joined = (harness_code or "").lower()
    if "@@" in EXEC_ARGS:
        wrapper_signals.append("seed arrives through file-content placeholder @@")
    if any(token in joined for token in ("argv", "argc", "getopt", "option", "usage")):
        wrapper_signals.append("harness also contains argv/option handling")
    if any(token in joined for token in ("json", "cjson", "parse", "token", "lexer", "xml", "yyparse")):
        wrapper_signals.append("harness shows parser-like payload consumption")
    adapter_spec = get_input_adapter_spec(harness_code)
    if adapter_spec.active:
        wrapper_signals.extend(
            f"auto adapter inferred: {line}" for line in summarize_input_adapter(adapter_spec)
        )

    field_summary = summarize_semantic_fields(fields)
    profile_lines = [
        f"outer_delivery={_describe_seed_delivery().splitlines()[0]}",
        f"payload_format_hint={payload_format}",
        f"payload_textual={is_textual}",
        f"likely_layered_wrapper={layered}",
    ]
    if wrapper_signals:
        profile_lines.append("wrapper_signals:")
        profile_lines.extend(f"- {signal}" for signal in wrapper_signals)
    profile_lines.append("editing_policy:")
    if layered:
        profile_lines.extend([
            "- Treat the seed as an outer wrapper/container carrying an inner payload.",
            "- Preserve stable wrapper framing unless constraints clearly target the wrapper itself.",
            "- Prefer edits inside semantic payload spans and values over rewriting the whole file.",
        ])
    else:
        profile_lines.extend([
            "- Treat the seed as a mostly single-layer payload.",
            "- Prefer semantic-field edits before whole-file rewrites.",
        ])
    profile_lines.append("semantic_field_summary:")
    profile_lines.append(field_summary)
    if preferred_seed:
        profile_lines.append(f"preferred_seed={preferred_seed}")
    return "\n".join(profile_lines)


def collect_input_examples_context(
    generation_mode: str,
    preferred_seed: str | None = None,
    max_examples: int = 2,
    max_text_chars: int = 1200,
    max_binary_bytes: int = 64,
) -> str:
    """Collect example inputs from existing seeds for LLM context."""
    candidate_paths: list[Path] = []
    seen_paths: set[str] = set()
    output_root = Path(output_dir) if output_dir else Path(config.OUTPUT_PATH)

    def add_candidate(path: Path | None) -> None:
        if not path or not path.exists() or not path.is_file():
            return
        path_str = os.fspath(path)
        if path_str in seen_paths:
            return
        seen_paths.add(path_str)
        candidate_paths.append(path)

    if preferred_seed:
        add_candidate(output_root / "default" / "queue" / preferred_seed)

    for queue_name in ("default", "LLM", "mut"):
        queue_path = output_root / queue_name / "queue"
        if not queue_path.exists():
            continue
        for path in sorted(p for p in queue_path.iterdir() if p.is_file() and not p.name.startswith(".")):
            add_candidate(path)
            if len(candidate_paths) >= max_examples:
                break
        if len(candidate_paths) >= max_examples:
            break

    if not candidate_paths:
        return ""

    harness_code = get_harness_code()
    adapter_spec = get_input_adapter_spec(harness_code)
    textual_preview = _looks_textual_semantic_input(harness_code=harness_code)
    sections: list[str] = []
    for index, path in enumerate(candidate_paths[:max_examples], start=1):
        try:
            raw_data = path.read_bytes()
            data = apply_input_adapter(raw_data, adapter_spec)
        except Exception:
            continue

        if generation_mode == "text_direct" or textual_preview:
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                preview = data[:max_binary_bytes].hex()
                sections.append(
                    f"<example_input index=\"{index}\" path=\"{path.name}\" size=\"{len(data)}\">\n"
                    f"hex_preview={preview}\n"
                    f"</example_input>"
                )
                continue
            preview = text[:max_text_chars]
            sections.append(
                f"<example_input index=\"{index}\" path=\"{path.name}\">\n"
                f"{preview}\n"
                f"</example_input>"
            )
        else:
            preview = data[:max_binary_bytes].hex()
            sections.append(
                f"<example_input index=\"{index}\" path=\"{path.name}\" size=\"{len(data)}\">\n"
                f"hex_preview={preview}\n"
                f"</example_input>"
            )

    if not sections:
        return ""

    guidance = (
        "Use these examples as same-family payload references. Preserve the same overall input type and mutate or simplify"
        " around them toward the target constraints; do not change the delivery channel."
    )
    if adapter_spec.active:
        guidance += f" Payload-view adapter detected: {'; '.join(summarize_input_adapter(adapter_spec))}."
    return "<input_examples>\n" + guidance + "\n" + "\n".join(sections) + "\n</input_examples>\n"


def build_semantic_fields_prompt_section(
    fields,
    max_fields: int = PROMPT_SEMANTIC_FIELDS_SAMPLE_LIMIT,
) -> str:
    """Build a prompt section describing semantic fields for mutation."""
    if not fields:
        return ""

    if isinstance(fields, dict):
        field_items = fields.get("fields", [])
        parser_name = fields.get("parser")
        format_name = fields.get("format") or fields.get("format_name")
    else:
        field_items = fields
        parser_name = None
        format_name = None

    sample_fields: list[dict[str, Any]] = []
    preferred_keys = (
        "name", "kind", "path", "json_path", "lxml_path", "offset", "size", "end",
        "value_offset", "value_end", "semantic_role", "editable", "reliable", "value"
    )
    for item in field_items[:max_fields]:
        if not isinstance(item, dict):
            continue
        compact_item: dict[str, Any] = {}
        for key in preferred_keys:
            if key in item and item[key] is not None:
                compact_item[key] = item[key]
        if compact_item:
            sample_fields.append(compact_item)

    metadata = [f"field_count={len(field_items)}"]
    if parser_name:
        metadata.append(f"parser={parser_name}")
    if format_name:
        metadata.append(f"format={format_name}")

    sections = [
        "<semantic_fields_summary>",
        ", ".join(metadata),
        summarize_semantic_fields(fields, max_fields=min(20, max_fields)),
        "</semantic_fields_summary>",
    ]

    if sample_fields:
        import json as json_mod
        sample_payload = {
            "sample_count": len(sample_fields),
            "omitted_count": max(0, len(field_items) - len(sample_fields)),
            "fields": sample_fields,
        }
        sections.extend([
            "<semantic_fields_sample>",
            json_mod.dumps(sample_payload, ensure_ascii=False, indent=2),
            "</semantic_fields_sample>",
        ])

    return "\n".join(sections)


def validate_generation_result(result: Any) -> Optional[str]:
    """Validate the structure of a generation result from LLM."""
    if not isinstance(result, dict):
        return f"generation result must be a JSON object, got {type(result).__name__}"
    if 'generation_script' not in result:
        return "missing required key: generation_script"
    if not isinstance(result.get('generation_script'), str):
        return "generation_script must be a string"
    return None


def _normalize_direct_generation_mode(planner_mode: str | None, inferred_mode: str) -> str:
    """Normalize the generation mode from planner or inference."""
    if planner_mode == "text_direct":
        return "text_direct"
    if planner_mode == "generate_script":
        return "generate_script"
    return "text_direct" if inferred_mode == "text_direct" else "generate_script"


def _append_direct_generation_plan_message(messages: list[dict], plan: DirectGenerationPlan) -> list[dict]:
    """Append plan information to generation messages."""
    result = list(messages)
    result.append({
        "role": "user",
        "content": (
            f"<generation_plan>\n"
            f"mode={plan.generation_mode}\n"
            f"strategy={plan.strategy}\n"
            f"reason={plan.reason}\n"
            f"</generation_plan>\n"
            f"Please follow the above plan for seed generation."
        ),
    })
    return result


def extract_direct_text_payload(response_text: str) -> str | None:
    """
    Extract direct text seed content from an LLM response.

    This function tries multiple strategies to extract the actual seed text
    from LLM responses, including:
    1. Tagged format: <generated_input>...</generated_input>
    2. Fenced code blocks: ```text ... ```, ```xml ... ```, etc.
    3. JSON format: {"generated_input": "..."}
    4. Quoted strings: "..." or '...'

    Returns the extracted text payload or None if extraction fails.
    """
    if not response_text:
        return None

    raw = response_text.strip()
    if not raw:
        return None

    # Try tagged format first
    tagged_match = re.search(
        r"<generated_input>\s*(.*?)\s*</generated_input>",
        raw,
        re.DOTALL | re.IGNORECASE,
    )
    if tagged_match:
        payload = tagged_match.group(1)
        return payload.strip("\n")

    # Try fenced code blocks
    fenced_match = re.search(
        r"```(?:text|xml|html|sql|json|txt|yaml|toml|c)?\s*(.*?)```",
        raw,
        re.DOTALL | re.IGNORECASE,
    )
    if fenced_match:
        payload = fenced_match.group(1)
        return payload.strip("\n")

    # Try JSON format
    json_match = _extract_first_valid_json_segment(raw)
    if json_match is not None:
        try:
            payload_obj = json.loads(json_match)
            if isinstance(payload_obj, dict):
                for key in ('generated_input', 'text_input', 'seed_content', 'content'):
                    value = payload_obj.get(key)
                    if isinstance(value, str) and value.strip():
                        return value
            elif isinstance(payload_obj, str) and payload_obj.strip():
                return payload_obj
        except Exception:
            pass

    # Try quoted strings
    if (
        (raw.startswith('"') and raw.endswith('"'))
        or (raw.startswith("'") and raw.endswith("'"))
    ):
        try:
            decoded = json.loads(raw if raw.startswith('"') else json.dumps(raw[1:-1]))
            if isinstance(decoded, str) and decoded.strip():
                return decoded
        except Exception:
            pass

    # Fallback: return the raw response
    return raw


def write_direct_text_seed_and_test(
    llm_util: LLMUtil,
    generation_messages: list[dict[str, str]],
    seed_path: str,
    *,
    roadblock: Optional[dict[str, Any]] = None,
    call_chain=None,
    max_attempts: int = 3,
    missing_payload_feedback: str | None = None,
    empty_payload_feedback: str | None = None,
    no_progress_feedback: str | None = None,
    require_local_progress: bool = False,
    skip_seed_gate: bool = False,
) -> DirectTextSeedResult:
    """
    Generate a direct text seed using LLM and test it.

    This function handles the complete workflow of:
    1. Getting LLM response
    2. Extracting text payload
    3. Writing to seed file
    4. Running seed gate evaluation
    5. Optionally requiring local progress

    Returns a DirectTextSeedResult with the outcome.
    """
    try:
        check_fuzzer_alive()
    except FuzzerProcessDiedError as e:
        logger.critical(f"[{LogOp.FUZZER}] {e}")
        logger.critical("[{LogOp.FUZZER}] Fuzzer died before direct-text seed generation, aborting...")
        raise

    missing_payload_feedback = (
        missing_payload_feedback
        or "未提取到可写入 seed 文件的文本内容。请只返回 <generated_input>...</generated_input> 包裹的 seed 文本。"
    )
    empty_payload_feedback = (
        empty_payload_feedback
        or "生成的 seed 为空文件。请直接返回非空的 <generated_input>...</generated_input> 文本内容。"
    )

    for attempt in range(max_attempts):
        resp = llm_util.get_response(generation_messages)
        generated_text = extract_direct_text_payload(resp)
        if not generated_text:
            if attempt < max_attempts - 1:
                append_llm_retry_feedback(generation_messages, resp, missing_payload_feedback)
            continue

        Path(seed_path).parent.mkdir(parents=True, exist_ok=True)
        with open(seed_path, 'w', encoding='utf-8') as f:
            f.write(generated_text)

        try:
            file_size = os.path.getsize(seed_path)
        except OSError:
            file_size = 0
        if file_size <= 0:
            if attempt < max_attempts - 1:
                append_llm_retry_feedback(generation_messages, resp, empty_payload_feedback)
            continue

        if skip_seed_gate:
            return DirectTextSeedResult(
                success=True,
                attempt_made=True,
                candidate_path=seed_path,
                gate_result=None,
                eval_result=None,
                response_text=resp,
            )

        gate_result, eval_result = gate_seed(seed_path, roadblock=roadblock, call_chain=call_chain)
        candidate_path = gate_result.audit_path or seed_path
        if not require_local_progress:
            return DirectTextSeedResult(
                success=True,
                attempt_made=True,
                candidate_path=candidate_path,
                gate_result=gate_result,
                eval_result=eval_result,
                response_text=resp,
            )

        local_progress = gate_result.accepted and _seed_eval_indicates_local_progress(eval_result)
        if local_progress:
            return DirectTextSeedResult(
                success=True,
                attempt_made=True,
                candidate_path=candidate_path,
                gate_result=gate_result,
                eval_result=eval_result,
                response_text=resp,
            )

        if attempt < max_attempts - 1 and no_progress_feedback:
            append_llm_retry_feedback(generation_messages, resp, no_progress_feedback)
            continue

        return DirectTextSeedResult(
            success=False,
            attempt_made=True,
            candidate_path=candidate_path,
            gate_result=gate_result,
            eval_result=eval_result,
            response_text=resp,
            failure_reason="NO_LOCAL_PROGRESS",
        )

    return DirectTextSeedResult(
        success=False,
        attempt_made=False,
        candidate_path=None,
        gate_result=None,
        eval_result=None,
        response_text=None,
        failure_reason="TEXT_GENERATION_FAILED",
    )


def _seed_id_from_path(path: str | None) -> int:
    """Extract seed ID from a file path."""
    if not path:
        return -1
    match = re.search(r'id:(\d+)', Path(path).name)
    return int(match.group(1)) if match else -1


def plan_direct_generation(
    *,
    llm_util: LLMUtil,
    code_slice: str,
    constraints,
    summary: str,
    target_branch: str,
    fields=None,
    state_hints=None,
    harness_code: str | None = None,
    preferred_seed: str | None = None,
    inferred_mode: str,
    max_retries: int = 3,
) -> DirectGenerationPlan:
    """
    Plan the direct generation approach using LLM.

    Returns a DirectGenerationPlan with the chosen generation mode and strategy.
    """
    constraint_text = constraints if isinstance(constraints, str) else json.dumps(constraints, ensure_ascii=False)
    planner_messages = [
        {
            "role": "system",
            "content": (
                "You are a fuzz seed generation planner. "
                "Choose exactly one generation_mode: text_direct or generate_script. "
                "Use text_direct only when the final answer should be raw seed text written directly into the seed file. "
                "Use generate_script when the model should output a Python script that writes the seed."
            ),
        },
        {
            "role": "user",
            "content": (
                f"<project>{PROJECT}</project>\n"
                f"<inferred_mode>{inferred_mode}</inferred_mode>\n"
                f"<target_branch>{target_branch}</target_branch>\n"
                f"<preferred_seed>{preferred_seed or '(none)'}</preferred_seed>\n"
                f"<has_fields>{bool(fields)}</has_fields>\n"
                f"<has_state_hints>{bool(state_hints)}</has_state_hints>\n"
                f"<harness_present>{bool(harness_code)}</harness_present>\n"
                f"<summary>{summary[:1200]}</summary>\n"
                f"<constraints>{constraint_text[:1800]}</constraints>\n"
                f"<code_slice>{code_slice[:3000]}</code_slice>\n"
                "Return one JSON object with keys: generation_mode, strategy, reason."
            ),
        },
    ]
    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"
    planner_result = None
    for attempt in range(max_retries):
        resp = llm_util.get_response(planner_messages)
        match = extract_json_with_fallback(resp, pattern_json)
        if not match:
            if attempt < max_retries - 1:
                append_llm_retry_feedback(
                    planner_messages,
                    resp,
                    "请只返回一个 JSON object，并且必须包含 generation_mode、strategy、reason。",
                )
            continue
        try:
            planner_result = json.loads(match.group(1).strip())
        except json.JSONDecodeError as exc:
            if attempt < max_retries - 1:
                append_llm_retry_feedback(
                    planner_messages,
                    resp,
                    f"JSON 解析失败：{exc}。请只返回一个合法的 JSON object。",
                )
            continue
        if not isinstance(planner_result, dict):
            planner_result = None
            continue
        break

    generation_mode = _normalize_direct_generation_mode(
        planner_result.get("generation_mode") if isinstance(planner_result, dict) else None,
        inferred_mode,
    )
    return DirectGenerationPlan(
        generation_mode=generation_mode,
        strategy=str((planner_result or {}).get("strategy") or generation_mode),
        reason=str((planner_result or {}).get("reason") or f"fallback_to_{generation_mode}"),
        inferred_mode=inferred_mode,
        planner_result=planner_result,
    )


def _log_full_prompt_messages(tag: str, messages: list[dict[str, str]]):
    """Log full prompt messages for debugging."""
    if not messages:
        logger.warning(f"[{LogOp.LLM}] {tag} messages are empty")
        return
    rendered_parts = []
    for index, message in enumerate(messages, start=1):
        role = message.get('role', 'unknown')
        content = message.get('content', '') or ''
        rendered_parts.append(
            f"===== MESSAGE {index} role={role} chars={len(content)} =====\n{content}"
        )
    rendered = "\n\n".join(rendered_parts)
    logger.info(
        f"[{LogOp.LLM}] {tag} full messages ({_estimate_messages_chars(messages)} chars)\n"
        f"{rendered}"
    )


def execute_direct_generation_plan(
    ctx: SimplifiedAttemptContext,
    plan: DirectGenerationPlan,
    *,
    queue_dir: str | Path | None = None,
    skip_seed_gate: bool = False,
    defer_effectiveness_to_outer_check: bool = False,
    log_prefix: str = "Path C",
) -> DirectGenerationExecutionResult:
    """
    Execute a direct generation plan by calling LLM and testing the result.

    Returns a DirectGenerationExecutionResult with the outcome.
    """
    llm_target_path = Path(queue_dir) if queue_dir is not None else config.get_named_queue_dir(DIRECT_GENERATION_FUZZER)
    llm_target_path.mkdir(parents=True, exist_ok=True)
    seed_id = len(os.listdir(llm_target_path))

    if plan.generation_mode == "text_direct":
        generation_messages = _append_direct_generation_plan_message(
            build_direct_text_generation_messages(
                ctx.code_slice,
                ctx.constraints,
                ctx.summary,
                fields=ctx.fields,
                target_branch=ctx.bcode,
                state_hints=ctx.state_hints,
                harness_code=ctx.harness_for_mode,
                preferred_seed=ctx.seed,
            ),
            plan,
        )
        _log_full_prompt_messages(f"{log_prefix} direct_generation text prompt", generation_messages)
        seed_path = os.fspath(config.next_queue_seed_path(llm_target_path, roadblock_id=ctx.roadblock_id))
        text_result = write_direct_text_seed_and_test(
            ctx.llm_util,
            generation_messages,
            seed_path,
            roadblock=ctx.roadblock,
            call_chain=ctx.call_chain,
            max_attempts=MAX_TIME,
            no_progress_feedback="该文本输入没有带来新的覆盖。请继续生成更短、更直接、更贴近目标分支状态的文本输入。",
            require_local_progress=not defer_effectiveness_to_outer_check and not skip_seed_gate,
            skip_seed_gate=skip_seed_gate,
        )
        return DirectGenerationExecutionResult(
            attempted=text_result.attempt_made,
            success=text_result.attempt_made if defer_effectiveness_to_outer_check else text_result.success,
            mode="text_direct",
            seed_id=_seed_id_from_path(text_result.candidate_path or seed_path),
            candidate_path=text_result.candidate_path or seed_path,
            failure_reason=text_result.failure_reason,
            gate_result=text_result.gate_result,
            eval_result=text_result.eval_result,
        )

    generation_messages = _append_direct_generation_plan_message(
        build_generate_script_messages(
            ctx.code_slice,
            ctx.constraints,
            ctx.summary,
            fields=ctx.fields,
            target_branch=ctx.bcode,
            state_hints=ctx.state_hints,
            harness_code=ctx.harness_for_mode,
            preferred_seed=ctx.seed,
        ),
        plan,
    )
    _log_full_prompt_messages(f"{log_prefix} direct_generation script prompt", generation_messages)
    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"
    times = 0
    while times < MAX_TIME:
        resp = ctx.llm_util.get_response(generation_messages)
        match = extract_json_with_fallback(resp, pattern_json)
        if not match:
            append_llm_retry_feedback(
                generation_messages,
                resp,
                "返回内容中没有可解析的 JSON。请只返回一个 JSON object，并且必须包含字符串字段 generation_script。",
            )
            times += 1
            continue
        try:
            res = json.loads(match.group(1).strip())
        except json.JSONDecodeError as exc:
            append_llm_retry_feedback(
                generation_messages,
                resp,
                f"JSON 解析失败：{exc}。请只返回一个合法的 JSON object，并包含字符串字段 generation_script。",
            )
            times += 1
            continue
        schema_error = validate_generation_result(res)
        if schema_error:
            append_llm_retry_feedback(
                generation_messages,
                resp,
                f"返回结构不符合要求：{schema_error}。请只返回一个 JSON object，并且 generation_script 必须是 Python 脚本字符串。",
            )
            times += 1
            continue
        script = res.get("generation_script")
        if not script:
            return DirectGenerationExecutionResult(
                attempted=False,
                success=False,
                mode="generate_script",
                failure_reason="EMPTY_SCRIPT",
            )
        solved, _, dest_file = extract_and_test(
            ctx.llm_util,
            script,
            ctx.roadblock_id,
            seed_id,
            ctx.tracer,
            fuzzer,
            roadblock=ctx.roadblock,
            call_chain=ctx.call_chain,
            code_slice=ctx.code_slice,
            queue_dir=llm_target_path,
        )
        attempted = solved or bool(dest_file)
        return DirectGenerationExecutionResult(
            attempted=attempted,
            success=attempted if defer_effectiveness_to_outer_check else solved,
            mode="generate_script",
            seed_id=_seed_id_from_path(dest_file),
            candidate_path=dest_file,
        )
    return DirectGenerationExecutionResult(
        attempted=False,
        success=False,
        mode="generate_script",
        failure_reason="GENERATION_RETRIES_EXHAUSTED",
    )


def build_input_type_contract(generation_mode: str) -> str:
    """
    Build a contract description for the expected input type.

    This helps the LLM understand what kind of input to generate.
    """
    if generation_mode == "text_direct":
        return (
            "Expected input type: direct text payload only.\n"
            "- You must generate only the program's consumed fuzz input payload itself.\n"
            "- Do not generate command-line arguments, shell commands, environment settings, wrappers, or prose.\n"
            "- The output must be seed file/stdin content in the same family as the provided examples."
        )
    return (
        "Expected input type: binary or structured non-text payload.\n"
        "- Return a Python generation script that writes the payload bytes to the provided output path.\n"
        "- Do not switch to argv-style payloads or plain explanatory text.\n"
        "- If examples are provided, preserve their payload family and mutate around them.\n"
        "- If the harness indicates an outer wrapper plus an inner textual payload (for example command/wrapper + JSON/XML/script body), "
        "preserve the wrapper framing and mutate only the payload portion unless the constraints clearly target the wrapper."
    )


def build_parser_rich_generation_bias(
    generation_mode: str,
    *,
    preferred_seed: str | None = None,
    harness_code: str | None = None,
) -> str:
    """
    Build parser-rich generation bias from existing seeds.

    Analyzes preferred seed to identify parser control surfaces and
    provides guidance for preserving them in generated inputs.
    """
    seed_path = config.find_seed_path(preferred_seed) if preferred_seed else None
    payload = read_seed_payload_view(seed_path, harness_code) if seed_path else b""
    if not payload and seed_path and seed_path.exists():
        payload = _read_seed_prefix_bytes(os.fspath(seed_path))
    if not payload:
        return ""

    printable_ratio = (
        sum(1 for byte in payload if 32 <= byte <= 126 or byte in {9, 10, 13}) / max(len(payload), 1)
    )
    if generation_mode == "binary_script" and printable_ratio < 0.80:
        return ""

    text = payload.decode("utf-8", errors="ignore")
    if not text:
        return ""

    rich_features: list[str] = []
    feature_checks = [
        ("xml_declaration", "<?xml" in text),
        ("doctype_or_schema_block", "<!DOCTYPE" in text or "<!ELEMENT" in text or "<!ATTLIST" in text),
        ("processing_instruction", "<?" in text and "?>" in text and "<?xml" not in text.strip()),
        ("comment_block", "<!--" in text and "-->" in text),
        ("namespace_binding", "xmlns:" in text or "xmlns=" in text),
        ("typed_attribute_or_id_like_field", " ID " in text or " id=" in text.lower()),
        ("entity_or_escape_usage", "&" in text and ";" in text),
        ("nested_tag_structure", text.count("<") >= 6 and text.count(">") >= 6),
    ]
    for feature_name, enabled in feature_checks:
        if enabled:
            rich_features.append(feature_name)

    if not rich_features:
        return ""

    lines = [
        "<parser_rich_seed_bias>",
        "Goal: prefer parser-rich same-family seeds that combine multiple control surfaces instead of flat minimal payloads.",
        "Keep the payload in the same family as the preferred/example seeds, but preserve or recombine parser control surfaces that often create new parser states.",
        "Prefer preserving multiple independent control surfaces together when they already exist in examples, instead of collapsing to a single plain element/document.",
        "Observed rich features in preferred/example seed:",
    ]
    lines.extend(f"- {feature}" for feature in rich_features)
    lines.extend([
        "Generation policy:",
        "- Keep at least 2 parser control surfaces when feasible for the format.",
        "- Prefer declaration/header + metadata/annotation + structured body combinations over flat single-node payloads.",
        "- Prefer small but state-rich payloads, not long filler text.",
        "- If mutating an example, preserve the structural skeleton and change only a few semantically meaningful parts.",
        "</parser_rich_seed_bias>",
    ])
    return "\n".join(lines) + "\n"


def _score_input_driven_call_chain(chain) -> tuple[int, int, int]:
    """
    Score a call chain for input-driven fuzzing suitability.

    Returns a tuple (cli_penalty, parser_bonus, length) where:
    - Lower cli_penalty is better (avoid CLI/help chains)
    - Higher parser_bonus is better (prefer parser/decoder style chains)
    - Higher length is better (deeper chains)

    This scoring helps prioritize chains that are more likely to be
    input-driven rather than argument-driven.
    """
    cli_penalty = 0
    parser_bonus = 0
    harness_bonus = 0
    cli_tokens = (
        "argp", "getopt", "help", "usage", "version", "fmtstream", "option",
    )
    parser_tokens = (
        "LLVMFuzzerTestOneInput".lower(), "parse", "parser", "lex", "lexer", "read", "load", "decode", "source",
    )

    for node in chain:
        func_name = (_chain_node_name(node) or "").lower()
        func_meta = _lookup_func_meta_by_name(_chain_node_name(node) or "")
        file_name = (func_meta.get("file_name", "") if func_meta else "").lower()

        if any(token in func_name for token in cli_tokens) or any(token in file_name for token in ("argp", "getopt")):
            cli_penalty += 1
        if any(token in func_name for token in parser_tokens):
            parser_bonus += 1
        if func_name in {"main", "llvmfuzzertestoneinput"}:
            harness_bonus += 1

    # Higher score is better:
    # 1. Avoid generic CLI/help chains when seed contents are file-driven.
    # 2. Prefer parser/decoder style chains.
    # 3. Prefer chains anchored at harness entry points.
    # 4. Use length only as a final tie-breaker.
    return (-cli_penalty, parser_bonus + harness_bonus, len(chain))


def _compute_percentile(values: list[int], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    pos = max(0.0, min(1.0, q)) * (len(ordered) - 1)
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    weight = pos - low
    return ordered[low] * (1 - weight) + ordered[high] * weight


def _build_seed_gate_size_policy(queue_dir: Path) -> dict[str, float]:
    cache_key = os.fspath(queue_dir)
    cached = _seed_gate_size_policy_cache.get(cache_key)
    if cached is not None:
        return cached

    sizes: list[int] = []
    if queue_dir.exists():
        for entry in queue_dir.iterdir():
            if not entry.is_file():
                continue
            try:
                sizes.append(entry.stat().st_size)
            except OSError:
                continue

    if not sizes:
        policy = {"p95": 1_048_576.0, "hard_max": 4_194_304.0, "max_seen": 0.0}
    else:
        p95 = max(1.0, _compute_percentile(sizes, 0.95))
        max_seen = max(sizes)
        hard_max = max(
            p95 * SEED_GATE_DEFAULT_P95_MULTIPLIER,
            max_seen * SEED_GATE_DEFAULT_MAX_MULTIPLIER,
            4096.0,
        )
        policy = {"p95": p95, "hard_max": hard_max, "max_seen": float(max_seen)}
    _seed_gate_size_policy_cache[cache_key] = policy
    return policy


def _get_seed_gate_policy() -> dict[str, float]:
    queue_dir = Path(output_dir) / "default" / "queue" if output_dir else SEED_PATH
    return _build_seed_gate_size_policy(queue_dir)


def _get_seed_gate_reject_dir() -> Path:
    reject_dir = RUN_RUNTIME_PATH / "seed_gate_rejected"
    reject_dir.mkdir(parents=True, exist_ok=True)
    return reject_dir


def _audit_rejected_seed(seed_path: str, reason: str) -> str | None:
    path = Path(seed_path)
    if not path.exists():
        return None
    target_dir = _get_seed_gate_reject_dir() / reason.lower()
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{int(time.time() * 1000)}_{path.name}"
    try:
        shutil.move(os.fspath(path), os.fspath(target))
        return os.fspath(target)
    except Exception as exc:
        logger.warning(f"[SEED_GATE] Failed to move rejected seed {seed_path}: {exc}")
        return None


def _llvm_cov_report_has_hits(report_text: str, target_line: int | None = None, window: int = 12) -> tuple[bool, bool]:
    any_hit = False
    target_hit = False
    if not report_text:
        return any_hit, target_hit
    pattern = re.compile(r"^\s*(\d+)\|\s*([0-9][0-9A-Za-z\.\-]*)\|", re.MULTILINE)
    for match in pattern.finditer(report_text):
        line_no = int(match.group(1))
        count_token = match.group(2).strip().lower()
        if count_token in {"0", "0.0"}:
            continue
        any_hit = True
        if target_line is not None and abs(line_no - target_line) <= window:
            target_hit = True
            break
    return any_hit, target_hit


def _call_chain_file_candidates(call_chain) -> list[str]:
    candidates: list[str] = []
    for func_name in _extract_call_chain_function_names(call_chain):
        meta = _get_function_meta(func_name)
        if not meta:
            continue
        file_name = meta.get("file_name")
        if file_name and file_name not in candidates:
            candidates.append(file_name)
    return candidates


_seed_stderr_cluster_history: dict[str, set[str]] = defaultdict(set)
_seed_coverage_feature_history: dict[str, set[tuple[str, int, str]]] = defaultdict(set)
_seed_frontier_history: dict[str, dict[str, int | None]] = defaultdict(dict)
_disabled_seed_coverage_diag_targets: set[str] = set()


def _string_contains_any(text: str, keywords: tuple[str, ...] | list[str] | set[str]) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in keywords)


def _looks_textual_semantic_input(fields=None, harness_code: str | None = None) -> bool:
    """Check if the input looks like textual semantic input (code, text, structured formats)."""
    format_name = str((cached_format_info or {}).get("format_name", "")).lower()
    format_desc = str((cached_format_info or {}).get("format_description", "")).lower()
    harness_joined = (harness_code or "").lower()
    project_name = str(PROJECT).lower()
    combined = " ".join((format_name, format_desc, harness_joined, project_name))

    # Check for textual/semantic input indicators
    textual_keywords = (
        "text", "string", "code", "script", "source", "parse", "parser",
        "javascript", "python", "json", "xml", "yaml", "html", "css",
        "sql", "regex", "markdown", "latex",
    )
    binary_keywords = (
        "binary", "compressed", "encrypted", "image", "audio", "video",
        "zip", "gzip", "tar", "archive", "executable", "bytecode",
    )

    # Check for binary indicators
    if _string_contains_any(combined, binary_keywords):
        return False

    # Check for textual indicators
    if _string_contains_any(combined, textual_keywords):
        return True

    # Check for structured formats
    structured_keywords = (
        "xml", "json", "cjson", "yaml", "toml", "ini", "csv", "plist",
        "config", "doctype", "entity", "namespace", "lexer", "yyparse",
    )
    if _string_contains_any(combined, structured_keywords):
        return True

    # Check if fields suggest textual input
    if fields:
        for field in fields:
            field_name = str(field.get("name", "")).lower()
            field_type = str(field.get("type", "")).lower()
            if _string_contains_any(field_name + " " + field_type, textual_keywords):
                return True

    # Default to False (binary/unknown)
    return False


def classify_input_target(fields=None, harness_code: str | None = None) -> str:
    format_name = str((cached_format_info or {}).get("format_name", "")).lower()
    format_desc = str((cached_format_info or {}).get("format_description", "")).lower()
    harness_joined = (harness_code or "").lower()
    project_name = str(PROJECT).lower()
    combined = " ".join((format_name, format_desc, harness_joined, project_name))

    structured_keywords = (
        "xml", "json", "cjson", "yaml", "toml", "ini", "csv", "plist",
        "config", "doctype", "entity", "namespace", "lexer", "yyparse",
    )
    if _string_contains_any(combined, structured_keywords):
        return "structured_text_parser"

    if _looks_textual_semantic_input(fields=fields, harness_code=harness_code):
        return "code_like_text"

    return "binary_or_other"


def _seed_eval_target_class(target_context: Optional[dict[str, Any]] = None) -> str:
    target_context = target_context or {}
    harness_code = target_context.get("harness_code") or get_harness_code()
    fields = target_context.get("fields")
    return classify_input_target(fields=fields, harness_code=harness_code)


def normalize_parser_stderr(stderr_text: str) -> str:
    lowered = (stderr_text or "").lower()
    if not lowered.strip():
        return ""

    cluster_rules = [
        ("xml_mismatched_tag", ("opening and ending tag mismatch", "mismatch")),
        ("xml_attr_error", ("attribute", "construct error")),
        ("xml_entity_error", ("entity", "not defined")),
        ("xml_namespace_error", ("namespace",)),
        ("xml_doctype_error", ("doctype",)),
        ("json_unterminated_string", ("unterminated string",)),
        ("json_invalid_escape", ("invalid escape",)),
        ("json_unexpected_token", ("unexpected", "token")),
        ("json_invalid_number", ("invalid number",)),
        ("json_duplicate_key", ("duplicate", "key")),
        ("syntax_error", ("syntax error",)),
        ("parse_error", ("parse error",)),
    ]
    for cluster_name, keywords in cluster_rules:
        if all(keyword in lowered for keyword in keywords):
            return cluster_name

    if "error" in lowered:
        return "generic_error"
    return "unknown"


def score_parser_depth(stderr_text: str) -> int:
    lowered = (stderr_text or "").lower()
    if not lowered.strip():
        return 0

    score = 0
    if _string_contains_any(lowered, ("line ", "column ", "byte ", "offset ")):
        score += 1
    if _string_contains_any(lowered, ("tag", "attribute", "entity", "namespace", "doctype", "token", "escape")):
        score += 1
    if _string_contains_any(lowered, ("recover", "internal subset", "processing instruction", "duplicate key")):
        score += 1
    return score


def _seed_history_key(target_context: Optional[dict[str, Any]]) -> str:
    target_context = target_context or {}
    roadblock = target_context.get("roadblock") or {}
    filename = roadblock.get("filename", "")
    line = roadblock.get("line", "")
    function_name = roadblock.get("function", "")
    return f"{PROJECT}:{filename}:{line}:{function_name}"


def _mark_stderr_cluster_seen(cluster: str, target_context: Optional[dict[str, Any]]) -> bool:
    if not cluster:
        return False
    history_key = _seed_history_key(target_context)
    seen = _seed_stderr_cluster_history[history_key]
    if cluster in seen:
        return False
    seen.add(cluster)
    return True


def _mark_frontier_advance(
    *,
    target_context: Optional[dict[str, Any]],
    closest_hit_line_distance: int | None,
    deepest_call_chain_hit_index: int,
    parser_depth_score: int,
) -> bool:
    history_key = _seed_history_key(target_context)
    prev = _seed_frontier_history.get(history_key, {})
    advanced = False

    prev_distance = prev.get("closest_hit_line_distance")
    if closest_hit_line_distance is not None and (
        prev_distance is None or closest_hit_line_distance < prev_distance
    ):
        advanced = True

    prev_chain_index_value = prev.get("deepest_call_chain_hit_index")
    prev_chain_index = -1 if prev_chain_index_value is None else int(prev_chain_index_value)
    if deepest_call_chain_hit_index > prev_chain_index:
        advanced = True

    prev_parser_depth_value = prev.get("parser_depth_score")
    prev_parser_depth = 0 if prev_parser_depth_value is None else int(prev_parser_depth_value)
    if parser_depth_score > prev_parser_depth:
        advanced = True

    updated = dict(prev)
    if closest_hit_line_distance is not None:
        updated["closest_hit_line_distance"] = (
            closest_hit_line_distance
            if prev_distance is None
            else min(int(prev_distance), closest_hit_line_distance)
        )
    updated["deepest_call_chain_hit_index"] = max(prev_chain_index, deepest_call_chain_hit_index)
    updated["parser_depth_score"] = max(prev_parser_depth, parser_depth_score)
    _seed_frontier_history[history_key] = updated
    return advanced


def _execute_seed_and_capture(seed_path: str, harness_code: str | None = None) -> tuple[bool, str]:
    program_path = trace_prog or target_prog
    if not program_path:
        return False, ""

    try:
        cmd, stdin_data = build_seed_execution(program_path, seed_path, harness_code=harness_code)
    except Exception as exc:
        logger.warning(f"[{LogOp.TEST}] Failed to build seed execution command for {seed_path}: {exc}")
        return False, ""

    try:
        result = subprocess.run(
            cmd,
            input=stdin_data,
            stdin=subprocess.DEVNULL if stdin_data is None else None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stderr_text = ""
        if exc.stderr:
            stderr_text = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else str(exc.stderr)
        return False, stderr_text or "timeout"
    except Exception as exc:
        logger.warning(f"[{LogOp.TEST}] Seed execution failed for {seed_path}: {exc}")
        return False, str(exc)

    stderr_data = result.stderr or b""
    if isinstance(stderr_data, bytes):
        stderr_text = stderr_data.decode("utf-8", errors="replace")
    else:
        stderr_text = str(stderr_data)
    return result.returncode == 0, stderr_text


def _classify_seed_gain(
    *,
    exec_ok: bool,
    target_line_window_hit: bool,
    target_file_hit: bool,
    parse_family_hit: bool,
    new_edges: int,
    stderr_novel: bool,
    parser_depth_score: int,
    frontier_advance: bool,
) -> str:
    if not exec_ok:
        return "execution_failed"
    if target_line_window_hit:
        return "target_line_window_hit"
    if target_file_hit:
        return "target_file_hit"
    if frontier_advance:
        return "frontier_advance"
    if new_edges > 0:
        return "new_edges"
    if stderr_novel:
        return "diagnostic_novelty"
    if parse_family_hit:
        return "parser_family_hit"
    if parser_depth_score > 0:
        return "parser_progress"
    return "seed_generated"


def evaluate_seed(seed_path: str, target_context: Optional[dict[str, Any]] = None) -> SeedEvalResult:
    target_context = target_context or {}
    try:
        file_size = os.path.getsize(seed_path)
    except OSError:
        return SeedEvalResult(
            exec_ok=False,
            parse_family_hit=False,
            new_edges=0,
            target_file_hit=False,
            target_line_window_hit=False,
            coverage_gain_class="missing_seed",
            cost_metrics={},
            rejection_reason="SEED_UNPARSEABLE",
        )

    harness_code = target_context.get("harness_code") or get_harness_code()
    exec_ok, stderr_text = _execute_seed_and_capture(seed_path, harness_code=harness_code)
    stderr_cluster = normalize_parser_stderr(stderr_text)
    stderr_novel = _mark_stderr_cluster_seen(stderr_cluster, target_context)
    parser_depth_score = score_parser_depth(stderr_text)

    roadblock = target_context.get("roadblock") or {}
    call_chain = target_context.get("call_chain")

    target_file_hit = False
    target_line_window_hit = False
    parse_family_hit = False
    new_edges = 0
    closest_hit_line_distance = None
    deepest_call_chain_hit_index = -1
    frontier_advance = False
    coverage_gain_class = "seed_generated"

    frontier_advance = _mark_frontier_advance(
        target_context=target_context,
        closest_hit_line_distance=None,
        deepest_call_chain_hit_index=deepest_call_chain_hit_index,
        parser_depth_score=parser_depth_score,
    )

    target_class = _seed_eval_target_class(target_context)
    if target_class == "structured_text_parser" and not parse_family_hit and stderr_cluster not in {"", "unknown"}:
        parse_family_hit = True

    coverage_gain_class = _classify_seed_gain(
        exec_ok=exec_ok,
        target_line_window_hit=target_line_window_hit,
        target_file_hit=target_file_hit,
        parse_family_hit=parse_family_hit,
        new_edges=new_edges,
        stderr_novel=stderr_novel,
        parser_depth_score=parser_depth_score,
        frontier_advance=frontier_advance,
    )

    return SeedEvalResult(
        exec_ok=exec_ok,
        parse_family_hit=parse_family_hit,
        new_edges=new_edges,
        target_file_hit=target_file_hit,
        target_line_window_hit=target_line_window_hit,
        coverage_gain_class=coverage_gain_class,
        cost_metrics={"file_size": file_size},
        rejection_reason=None if exec_ok else "SEED_EXECUTION_FAILED",
        stderr_text=stderr_text[:1000],
        stderr_cluster=stderr_cluster,
        stderr_novel=stderr_novel,
        parser_depth_score=parser_depth_score,
        closest_hit_line_distance=closest_hit_line_distance,
        deepest_call_chain_hit_index=deepest_call_chain_hit_index,
        frontier_advance=frontier_advance,
    )


def gate_seed(
    seed_path: str,
    roadblock: Optional[dict[str, Any]] = None,
    call_chain=None,
) -> tuple[SeedGateResult, SeedEvalResult]:
    if not os.path.exists(seed_path):
        eval_result = SeedEvalResult(False, False, 0, False, False, "missing_seed", {}, "SEED_UNPARSEABLE")
        return SeedGateResult("reject_unparseable", False, "seed_not_found"), eval_result

    file_size = os.path.getsize(seed_path)
    if file_size <= 0:
        audit_path = _audit_rejected_seed(seed_path, "reject_unparseable")
        eval_result = SeedEvalResult(False, False, 0, False, False, "empty_seed", {"file_size": file_size}, "SEED_UNPARSEABLE")
        return SeedGateResult("reject_unparseable", False, "empty_seed", audit_path=audit_path), eval_result

    duplicate_path = find_duplicate_seed_path(seed_path)
    if duplicate_path:
        if not config.SEED_GATE_DISABLE_REJECT:
            audit_path = _audit_rejected_seed(seed_path, "reject_duplicate")
            eval_result = SeedEvalResult(False, False, 0, False, False, "duplicate_seed", {"file_size": file_size}, "SEED_DUPLICATE")
            return SeedGateResult("reject_duplicate", False, "duplicate_seed", audit_path=audit_path, duplicate_of=duplicate_path), eval_result
        logger.info(
            f"[SEED_GATE] Reject disabled; accepting duplicate seed {seed_path} "
            f"(matched existing seed {duplicate_path})"
        )

    size_policy = _get_seed_gate_policy()
    if file_size > size_policy["hard_max"]:
        if not config.SEED_GATE_DISABLE_REJECT:
            audit_path = _audit_rejected_seed(seed_path, "reject_too_large")
            eval_result = SeedEvalResult(False, False, 0, False, False, "size_rejected", {"file_size": file_size, **size_policy}, "SEED_TOO_LARGE")
            return SeedGateResult("reject_too_large", False, "seed_exceeds_hard_limit", audit_path=audit_path), eval_result
        logger.info(
            f"[SEED_GATE] Reject disabled; accepting oversized seed {seed_path} "
            f"(size={file_size}, hard_max={int(size_policy['hard_max'])})"
        )

    eval_result = evaluate_seed(seed_path, {"roadblock": roadblock or {}, "call_chain": call_chain})
    return SeedGateResult("accept", True, "seed_generated"), eval_result




def _seed_eval_indicates_local_progress(eval_result: SeedEvalResult) -> bool:
    if not eval_result.exec_ok:
        return False

    target_class = _seed_eval_target_class()
    if target_class == "structured_text_parser":
        return any((
            eval_result.target_line_window_hit,
            eval_result.target_file_hit and eval_result.parse_family_hit,
            eval_result.new_edges > 0,
            eval_result.frontier_advance,
            eval_result.stderr_novel,
            eval_result.parser_depth_score >= 2,
        ))

    return any((
        eval_result.target_line_window_hit,
        eval_result.target_file_hit,
        eval_result.new_edges > 0,
        eval_result.frontier_advance,
        eval_result.parse_family_hit,
    ))

def extract_and_test(
    llm_util: LLMUtil,
    script,
    roadblock_id,
    seed_id,
    tracer: CoverageTracer,
    fuzzer: FuzzerRunner,
    roadblock: Optional[dict] = None,
    call_chain=None,
    code_slice: Optional[str] = None,
    no_coverage_retry_budget: int = NO_COVERAGE_GUIDED_RETRY_LIMIT,
    duplicate_retry_budget: int = 2,
    queue_dir: str | Path | None = None,
    path_prefix: str | None = None,
):
    global input_dir, output_dir, fuzzing_args, target_prog, trace_prog

    # Check fuzzer alive before seed generation
    try:
        check_fuzzer_alive()
    except FuzzerProcessDiedError as e:
        logger.critical(f"[{LogOp.FUZZER}] {e}")
        logger.critical("[{LogOp.FUZZER}] Fuzzer died before extract_and_test, aborting...")
        raise

    logger.info(f"[{LogOp.EXTRACT}] Extracting Python script from LLM response")
    script = extract_generator(script)
    logger.info(f"[{LogOp.EXTRACT}] Executing generated Python script")
    stdout, stderr, new_seed_path = run_generator(
        script,
        roadblock_id if roadblock_id else 999999,
        seed_id,
        output_dir,
        path_prefix=path_prefix,
        queue_dir=queue_dir,
    )
    err_times = 0
    while stderr and "Connected to: <socket.socket" not in stderr:
        if err_times >= 3:
            logger.error(f"[{LogOp.EXTRACT}] Script execution failed after {err_times} attempts")
            return False, script, None
        logger.warning(f"[{LogOp.EXTRACT}] Script execution attempt {err_times + 1} failed, attempting fix")
        fix_resp = llm_util.fix_chat(script, stderr)
        if "Error fixing seed" in fix_resp:
            err_times += 1
            continue
        fixed_generator_script = extract_generator(fix_resp)
        stdout, stderr, new_seed_path = run_generator(
            fixed_generator_script,
            roadblock_id if roadblock_id else 999999,
            seed_id,
            output_dir,
            path_prefix=path_prefix,
            queue_dir=queue_dir,
        )
        script = fixed_generator_script
        err_times += 1

    if not os.path.exists(new_seed_path):
        logger.error(f"[{LogOp.EXTRACT}] Script execution failed - output file not generated: {new_seed_path}")
        logger.error(f"[{LogOp.EXTRACT}] Script length: {len(script)} chars")
        logger.error(f"[{LogOp.EXTRACT}] stdout: {stdout}")
        logger.error(f"[{LogOp.EXTRACT}] stderr: {stderr}", exc_info=True)
        return False, script, None

    # Check if the generated file is empty (0 bytes)
    file_size = os.path.getsize(new_seed_path)
    empty_file_times = 0
    while file_size == 0:
        if empty_file_times >= 3:
            logger.error(f"[{LogOp.EXTRACT}] Generated file is empty after {empty_file_times} attempts")
            return False, script, None
        logger.warning(
            f"[{LogOp.EXTRACT}] Generated file is empty (0 bytes), attempt {empty_file_times + 1}, attempting fix")
        empty_fix_resp = llm_util.empty_file_solve(script, stdout, stderr)
        if "Error fixing empty file" in empty_fix_resp:
            empty_file_times += 1
            continue
        fixed_generator_script = extract_generator(empty_fix_resp)
        stdout, stderr, new_seed_path = run_generator(
            fixed_generator_script,
            roadblock_id if roadblock_id else 999999,
            seed_id,
            output_dir,
            path_prefix=path_prefix,
            queue_dir=queue_dir,
        )
        script = fixed_generator_script
        empty_file_times += 1
        if not os.path.exists(new_seed_path):
            logger.error(f"[{LogOp.EXTRACT}] Fix attempt failed - output file not generated: {new_seed_path}")
            continue
        file_size = os.path.getsize(new_seed_path)
        if file_size > 0:
            logger.info(f"[{LogOp.EXTRACT}] Empty file fixed - new file size: {file_size} bytes")

    logger.info(f"[{LogOp.EXTRACT}] Seed already added to queue: {new_seed_path}")
    gate_result, eval_result = gate_seed(new_seed_path, roadblock=roadblock, call_chain=call_chain)
    logger.info(
        f"[SEED_GATE] decision={gate_result.decision} accepted={gate_result.accepted} "
        f"reason={gate_result.reason} audit_path={gate_result.audit_path or '(none)'}"
    )
    if gate_result.decision == "reject_duplicate" and duplicate_retry_budget > 0 and gate_result.duplicate_of:
        improved_script = regenerate_duplicate_seed_script(llm_util, script, gate_result.duplicate_of)
        if improved_script and improved_script.strip() != script.strip():
            logger.info(f"[{LogOp.EXTRACT}] Retrying generator because output duplicated an existing seed")
            improved_script_block = f"```python\n{improved_script}\n```"
            return extract_and_test(
                llm_util,
                improved_script_block,
                roadblock_id,
                seed_id + 1,
                tracer,
                fuzzer,
                roadblock=roadblock,
                call_chain=call_chain,
                code_slice=code_slice,
                no_coverage_retry_budget=no_coverage_retry_budget,
                duplicate_retry_budget=duplicate_retry_budget - 1,
                queue_dir=queue_dir,
                path_prefix=path_prefix,
            )
    if not gate_result.accepted:
        logger.info(
            f"[{LogOp.TEST}] Seed generated and queued for later coverage check despite gate rejection: "
            f"{eval_result.rejection_reason or gate_result.reason}"
        )
        return True, script, gate_result.audit_path or new_seed_path

    logger.info(
        f"[{LogOp.TEST}] Seed generated and accepted "
        f"(exec_ok={eval_result.exec_ok}, file_size={eval_result.cost_metrics.get('file_size')})"
    )
    return True, script, new_seed_path


def mutate_and_test(
    llm_util: LLMUtil,
    script,
    seed_id,
    orig,
    fuzzer: FuzzerRunner,
    tracer: CoverageTracer,
    roadblock: Optional[dict] = None,
    call_chain=None,
    path_prefix: str | None = None,
    queue_dir: str | Path | None = None,
):
    global input_dir, output_dir, fuzzing_args, target_prog, trace_prog

    # Check fuzzer alive before mutation testing
    try:
        check_fuzzer_alive()
    except FuzzerProcessDiedError as e:
        logger.critical(f"[{LogOp.FUZZER}] {e}")
        logger.critical("[{LogOp.FUZZER}] Fuzzer died before mutate_and_test, aborting...")
        raise

    stdout, stderr, new_seed_path = run_mutate_script(
        script,
        seed_id,
        orig,
        output_dir,
        path_prefix=path_prefix,
        queue_dir=queue_dir,
    )
    err_times = 0
    while stderr and "Connected to: <socket.socket" not in stderr:
        if err_times >= 3:
            logger.error(f"[{LogOp.MUTATE}] Mutation script execution failed after {err_times} attempts")
            return False, script, None
        logger.warning(f"[{LogOp.MUTATE}] Mutation script execution attempt {err_times + 1} failed, attempting fix")
        fix_resp = llm_util.fix_chat(script, stderr)
        if "Error fixing seed" in fix_resp:
            err_times += 1
            continue
        fixed_generator_script = extract_generator(fix_resp)
        stdout, stderr, new_seed_path = run_mutate_script(
            fixed_generator_script,
            seed_id,
            orig,
            output_dir,
            path_prefix=path_prefix,
            queue_dir=queue_dir,
        )
        script = fixed_generator_script
        err_times += 1

    if not os.path.exists(new_seed_path):
        logger.error(f"[{LogOp.MUTATE}] Mutation script execution failed - output file not generated: {new_seed_path}")
        logger.error(f"[{LogOp.MUTATE}] Script length: {len(script)} chars")
        logger.error(f"[{LogOp.MUTATE}] stdout: {stdout}")
        logger.error(f"[{LogOp.MUTATE}] stderr: {stderr}", exc_info=True)
        return False, script, None

    logger.info(f"[{LogOp.MUTATE}] Mutated seed already added to queue: {new_seed_path}")
    gate_result, eval_result = gate_seed(new_seed_path, roadblock=roadblock, call_chain=call_chain)
    logger.info(
        f"[SEED_GATE] decision={gate_result.decision} accepted={gate_result.accepted} "
        f"reason={gate_result.reason} audit_path={gate_result.audit_path or '(none)'}"
    )
    if not gate_result.accepted:
        logger.info(
            f"[{LogOp.TEST}] Mutated seed generated for later coverage check despite gate rejection: "
            f"{eval_result.rejection_reason or gate_result.reason}"
        )
        return True, script, gate_result.audit_path or new_seed_path
    logger.info(
        f"[{LogOp.TEST}] Mutated seed generated and accepted "
        f"(exec_ok={eval_result.exec_ok}, file_size={eval_result.cost_metrics.get('file_size')})"
    )
    return True, script, new_seed_path




def mutate_suggest_with_taint(code_slice, constraints, field, byte_range, llm_util: LLMUtil, pattern_json):
    """
    Generate mutation suggestions using LLM with old prompt (for use with taint analysis data).

    Args:
        code_slice: Code slice string
        constraints: Constraints in natural language
        field: Relevant field string from taint analysis
        byte_range: Byte range from taint analysis
        llm_util: LLM utility instance
        pattern_json: JSON pattern regex

    Returns:
        Dictionary with 'passable' and 'input_modifications' keys
    """
    # LLM interaction logging
    llm_log = get_llm_logger()
    llm_log.info(f"[LLM_INTERACTION] mutate_suggest_with_taint called")
    llm_log.debug(f"[LLM_INTERACTION] code_slice_preview: {str(code_slice)[:200] if code_slice else 'None'}...")
    llm_log.debug(
        f"[LLM_INTERACTION] constraints_count: {len(constraints) if isinstance(constraints, list) else 'N/A'}")
    llm_log.debug(f"[LLM_INTERACTION] field: {field[:100] if field else 'None'}...")

    container_context = build_input_container_profile(
        "binary_script",
        fields=field if isinstance(field, dict) else None,
        harness_code=get_harness_code() or "",
    )
    user_content = prompts['prompt']['mutate_suggest']['user_prompt'].format(
        code_slice=code_slice,
        constraints=constraints,
        relevant_fields=field,
        byte_range=byte_range,
    )
    user_content += (
        "\n<input_container_profile>\n"
        f"{container_context}\n"
        "</input_container_profile>\n"
    )
    messages = [
        {'role': 'system', 'content': prompts['prompt']['mutate_suggest']['sys_prompt']},
        {'role': 'user', 'content': user_content}
    ]

    max_retries = 3
    retry_count = 0

    while retry_count < max_retries:
        try:
            resp = llm_util.get_response(messages)
            llm_log.info(f"[LLM_INTERACTION] mutate_suggest_with_taint response length: {len(resp) if resp else 0}")

            # Handle empty string (cannot determine)
            if not resp.strip():
                logger.info(
                    f"[{LogOp.LLM}] mutate_suggest_with_taint: LLM returned empty string - cannot determine mutations")
                llm_log.warning(f"[LLM_INTERACTION] mutate_suggest_with_taint returned empty response")
                return {'passable': False, 'input_modifications': []}

            try:
                data = ujson.loads(resp)
                logger.debug(f"[{LogOp.LLM}] mutate_suggest_with_taint: Detected format type: {type(data).__name__}")

                # Support new format: array
                if isinstance(data, list):
                    logger.info(
                        f"[{LogOp.LLM}] mutate_suggest_with_taint: Parsed {len(data)} field(s) from array format")
                    llm_log.info(f"[LLM_INTERACTION] mutate_suggest_with_taint parsed {len(data)} fields")

                    if not data:
                        logger.info(
                            f"[{LogOp.LLM}] mutate_suggest_with_taint: Empty array - no modifications suggested")
                        llm_log.warning(f"[LLM_INTERACTION] mutate_suggest_with_taint returned empty array")
                        return {'passable': False, 'input_modifications': []}

                    # Convert new array format to structure expected by downstream
                    input_modifications = []
                    for item in data:
                        converted = {
                            'input_field': item.get('field_name', ''),
                            'byte_range': {
                                'start': item.get('offset', 0),
                                'end': item.get('offset', 0) + item.get('size', 0)
                            },
                            'constraints': [
                                f"encoding={item.get('encoding')}, value={item.get('new_value')}: {item.get('reason', '')}"
                            ],
                            '_new_format': item  # Preserve original for get_mutate_script
                        }
                        input_modifications.append(converted)

                    logger.debug(
                        f"[{LogOp.LLM}] mutate_suggest_with_taint: Converted data structure: {json.dumps(input_modifications, indent=2)}")
                    llm_log.info(
                        f"[LLM_INTERACTION] mutate_suggest_with_taint result: passable=True, modifications={len(input_modifications)}")
                    return {'passable': True, 'input_modifications': input_modifications}

                # Old format: dict with passable - NO LONGER SUPPORTED
                elif isinstance(data, dict):
                    retry_count += 1
                    logger.warning(
                        f"[{LogOp.LLM}] mutate_suggest_with_taint: Old format detected (attempt {retry_count}/{max_retries}). Got keys: {list(data.keys())}")
                    llm_log.warning(f"[LLM_INTERACTION] mutate_suggest_with_taint old format detected")
                    if retry_count < max_retries:
                        append_llm_retry_feedback(
                            messages,
                            resp,
                            "请不要返回 object。请只返回 JSON 数组，每个元素描述一个字段修改建议。"
                        )
                        continue
                    return {'passable': False, 'input_modifications': []}

                else:
                    retry_count += 1
                    logger.warning(
                        f"[{LogOp.LLM}] mutate_suggest_with_taint: Unexpected format type: {type(data).__name__} (attempt {retry_count}/{max_retries})")
                    llm_log.warning(
                        f"[LLM_INTERACTION] mutate_suggest_with_taint unexpected format: {type(data).__name__}")
                    if retry_count < max_retries:
                        append_llm_retry_feedback(
                            messages,
                            resp,
                            f"返回类型错误：{type(data).__name__}。请只返回 JSON 数组。"
                        )
                        continue
                    return {'passable': False, 'input_modifications': []}

            except (ValueError, ujson.JSONDecodeError) as e:
                retry_count += 1
                if retry_count < max_retries:
                    logger.debug(
                        f"[{LogOp.LLM}] mutate_suggest_with_taint: JSON parse error (retry {retry_count}/{max_retries}): {str(e)}")
                    llm_log.error(
                        f"[LLM_INTERACTION] mutate_suggest_with_taint JSON parse error, retry {retry_count}/{max_retries}: {str(e)}")
                    messages.append({'role': 'assistant', 'content': resp})
                    messages.append({
                        'role': 'user',
                        'content': f'解析失败，请返回JSON数组。错误: {str(e)}'
                    })
                else:
                    logger.error(
                        f"[{LogOp.LLM}] mutate_suggest_with_taint: JSON parse failed after {max_retries} retries: {str(e)}")
                    llm_log.error(
                        f"[LLM_INTERACTION] mutate_suggest_with_taint JSON parse failed after {max_retries} retries: {str(e)}")
                    return {'passable': False, 'input_modifications': []}

        except Exception as e:
            retry_count += 1
            if retry_count >= max_retries:
                logger.error(f"[{LogOp.LLM}] mutate_suggest_with_taint: Failed after {max_retries} retries: {str(e)}")
                llm_log.error(
                    f"[LLM_INTERACTION] mutate_suggest_with_taint failed after {max_retries} retries: {str(e)}")
                return {'passable': False, 'input_modifications': []}

    llm_log.error(f"[LLM_INTERACTION] mutate_suggest_with_taint failed, returning no modifications")
    return {'passable': False, 'input_modifications': []}


def get_mutate_script(input_modifications, llm_util: LLMUtil, *, fields=None, harness_code=None, preferred_seed=None):
    # LLM interaction logging
    llm_log = get_llm_logger()
    llm_log.info(f"[LLM_INTERACTION] get_mutate_script called")
    llm_log.debug(f"[LLM_INTERACTION] input_modifications_count: {len(input_modifications)}")

    # Build enhanced input_modifications with concrete values for mutate_script_gen LLM
    enhanced_mods = []
    for item in input_modifications:
        if '_new_format' in item:
            new_fmt = item['_new_format']
            # Create detailed constraint from concrete values (two-step approach)
            constraint_desc = (
                f"Set bytes at offset {new_fmt.get('offset')} "
                f"(size={new_fmt.get('size')}, encoding={new_fmt.get('encoding')}) "
                f"to value {new_fmt.get('new_value')}. "
                f"Reason: {new_fmt.get('reason', '')}"
            )
            enhanced_mods.append({
                'input_field': item['input_field'],
                'byte_range': item['byte_range'],
                'constraints': [constraint_desc],
                '_concrete_value': new_fmt.get('new_value'),
                '_encoding': new_fmt.get('encoding'),
                '_kind': new_fmt.get('kind'),
                '_path': new_fmt.get('path') or new_fmt.get('json_path') or new_fmt.get('lxml_path'),
                '_editable': new_fmt.get('editable'),
                '_semantic_role': new_fmt.get('semantic_role'),
                '_reliable': new_fmt.get('reliable', True),
            })
        else:
            # Fallback for items without new format (should not happen with new code)
            enhanced_mods.append(item)

    logger.debug(f"[{LogOp.LLM}] Enhanced modifications: {json.dumps(enhanced_mods, indent=2)}")

    generation_mode = "text_direct" if _looks_textual_semantic_input(
        fields=fields,
        harness_code=harness_code or get_harness_code() or "",
    ) else "binary_script"
    container_context = build_input_container_profile(
        generation_mode,
        fields=fields,
        harness_code=harness_code or get_harness_code() or "",
        preferred_seed=preferred_seed,
    )
    system_prompt = (
        get_formatted_prompt('mutate_script_gen')
        + "\n\n### Layered Input Editing Guidance\n"
        + "- If the seed contains an outer wrapper and an inner textual payload, preserve the wrapper and patch only the payload span when possible.\n"
        + "- Prefer semantic-field span replacement using provided offsets/value offsets over broad whole-file rewrites.\n"
        + "- If a modification targets a textual field, it is acceptable to decode to text, patch the relevant span, and re-encode, as long as unrelated bytes remain stable.\n"
        + "- If the seed is textual, preserve parser-visible structure such as delimiters, quotes, separators, and balanced nesting whenever possible.\n"
    )
    user_content = prompts['prompt']['mutate_script_gen']['user_prompt'].format(
        input_modifications=json.dumps(enhanced_mods, indent=2, ensure_ascii=False)
    )
    user_content += (
        "\n<input_container_profile>\n"
        f"{container_context}\n"
        "</input_container_profile>\n"
    )
    user_content += collect_input_examples_context(generation_mode, preferred_seed=preferred_seed, max_examples=1)
    messages = [
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': user_content}
    ]

    resp = llm_util.get_response(messages)
    llm_log.info(f"[LLM_INTERACTION] get_mutate_script response length: {len(resp) if resp else 0}")

    match = re.search(r"```python(.*?)```", resp, re.DOTALL | re.IGNORECASE)

    if match:
        logger.info(f"[{LogOp.LLM}] Successfully extracted Python script ({len(match.group(1))} chars)")
        llm_log.info(f"[LLM_INTERACTION] get_mutate_script result: script_length={len(match.group(1))}")
        return match.group(1)
    else:
        logger.error(f"[{LogOp.LLM}] Failed to extract Python code block from LLM response")
        llm_log.error(f"[LLM_INTERACTION] get_mutate_script failed to extract Python code block")
        return None


def get_text_mutation_plan(
    code_slice,
    constraints,
    target_branch,
    llm_util: LLMUtil,
    *,
    fields=None,
    harness_code=None,
    preferred_seed=None,
):
    llm_log = get_llm_logger()
    llm_log.info("[LLM_INTERACTION] get_text_mutation_plan called")

    effective_fields = _normalize_text_mutation_fields(fields, seed_name=preferred_seed, harness_code=harness_code)
    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"
    container_context = build_input_container_profile(
        "text_direct",
        fields=effective_fields,
        harness_code=harness_code or get_harness_code() or "",
        preferred_seed=preferred_seed,
    )
    user_content = prompts['prompt']['text_mutation_plan_gen']['user_prompt'].format(
        code_slice=code_slice,
        constraints=constraints,
        target_branch=target_branch,
        semantic_fields=build_semantic_fields_prompt_section(effective_fields) if effective_fields else "(none)",
        input_container_profile=container_context,
        input_examples=collect_input_examples_context("text_direct", preferred_seed=preferred_seed, max_examples=1) or "(none)",
    )
    messages = [
        {'role': 'system', 'content': get_formatted_prompt('text_mutation_plan_gen')},
        {'role': 'user', 'content': user_content},
    ]

    for _ in range(3):
        resp = llm_util.get_response(messages)
        match = extract_json_with_fallback(resp, pattern_json)
        if not match:
            append_llm_retry_feedback(messages, resp, "请只返回 JSON 数组，每个元素描述一个文本变异计划项。")
            continue
        try:
            data = json.loads(match.group(1).strip())
        except json.JSONDecodeError as exc:
            append_llm_retry_feedback(messages, resp, f"JSON 解析失败：{exc}。请只返回合法 JSON 数组。")
            continue
        if not isinstance(data, list):
            append_llm_retry_feedback(messages, resp, "返回类型错误。请只返回 JSON 数组。")
            continue

        normalized: list[dict[str, Any]] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            mutation = str(item.get("mutation", "")).strip()
            if mutation not in {
                "replace", "append_suffix", "prepend_prefix", "wrap",
                "delete", "duplicate", "insert_before", "insert_after",
            }:
                continue
            if not any(k in item for k in ("field_name", "path", "offset")):
                continue
            normalized.append({
                "mutation": mutation,
                "value": "" if item.get("value") is None else str(item.get("value")),
                "reason": str(item.get("reason", "")).strip(),
                "field_name": str(item.get("field_name", "")).strip() or None,
                "path": str(item.get("path", "")).strip() or None,
                "offset": item.get("offset"),
                "size": item.get("size"),
                "occurrence": item.get("occurrence", 1),
                "aggressiveness": str(item.get("aggressiveness", "conservative")).strip() or "conservative",
            })
        if normalized:
            llm_log.info(f"[LLM_INTERACTION] get_text_mutation_plan result: items={len(normalized)}")
            return normalized, effective_fields
        append_llm_retry_feedback(
            messages,
            resp,
            "没有提取到有效计划。请输出包含 mutation/value/reason 和定位信息的 JSON 数组。"
        )
    return [], effective_fields


def _resolve_text_mutation_span(plan_item: dict[str, Any], text_fields) -> tuple[int, int] | None:
    offset = plan_item.get("offset")
    size = plan_item.get("size")
    if isinstance(offset, int) and isinstance(size, int):
        return offset, max(offset, offset + max(0, size))

    field_items = text_fields.get("fields", []) if isinstance(text_fields, dict) else []
    try:
        occurrence = max(1, int(plan_item.get("occurrence", 1)))
    except Exception:
        occurrence = 1

    candidates = []
    for item in field_items:
        if plan_item.get("path") and item.get("path") == plan_item["path"]:
            candidates.append(item)
        elif plan_item.get("field_name") and item.get("name") == plan_item["field_name"]:
            candidates.append(item)
    if len(candidates) < occurrence:
        return None

    chosen = candidates[occurrence - 1]
    start = chosen.get("value_offset", chosen.get("offset"))
    end = chosen.get("value_end", chosen.get("end"))
    if not isinstance(start, int) or not isinstance(end, int):
        return None
    return start, end


def _apply_single_text_mutation(text: str, span: tuple[int, int], plan_item: dict[str, Any]) -> str | None:
    start, end = span
    if start < 0 or end < start or end > len(text):
        return None

    mutation = plan_item["mutation"]
    value = plan_item.get("value", "")
    selected = text[start:end]

    if mutation == "replace":
        return text[:start] + value + text[end:]
    if mutation == "append_suffix":
        return text[:end] + value + text[end:]
    if mutation == "prepend_prefix":
        return text[:start] + value + text[start:]
    if mutation == "wrap":
        return text[:start] + value + selected + value + text[end:]
    if mutation == "delete":
        return text[:start] + text[end:]
    if mutation == "duplicate":
        return text[:end] + (value if value else "") + selected + text[end:]
    if mutation == "insert_before":
        return text[:start] + value + text[start:]
    if mutation == "insert_after":
        return text[:end] + value + text[end:]
    return None


def execute_text_mutation_plan(
    plan_items,
    seed_name: str,
    *,
    text_fields=None,
    harness_code: str | None = None,
    max_outputs: int = 8,
) -> list[str]:
    seed_path = config.find_seed_path(seed_name)
    if seed_path is None or not seed_path.exists():
        return []

    try:
        original_text = seed_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    effective_fields = _normalize_text_mutation_fields(text_fields, seed_name=seed_name, harness_code=harness_code)
    out_dir = Path(config.MUT_QUEUE_PATH)
    out_dir.mkdir(parents=True, exist_ok=True)

    match = re.search(r'id:(\d+)', seed_name)
    orig_id = int(match.group(1)) if match else 0
    seen_payloads = {original_text}
    written_paths: list[str] = []

    aggressiveness_rank = {
        "conservative": 0,
        "balanced": 1,
        "aggressive": 2,
    }

    resolved_items: list[dict[str, Any]] = []
    for item in plan_items:
        span = _resolve_text_mutation_span(item, effective_fields)
        if span is None:
            continue
        resolved_items.append({
            "plan": item,
            "span": span,
            "start": span[0],
            "end": span[1],
            "aggressiveness_rank": aggressiveness_rank.get(
                str(item.get("aggressiveness", "conservative")).lower(),
                1,
            ),
        })

    resolved_items.sort(
        key=lambda item: (
            item["aggressiveness_rank"],
            item["start"],
            item["end"],
            str(item["plan"].get("field_name") or item["plan"].get("path") or ""),
        )
    )

    def spans_conflict(left: dict[str, Any], right: dict[str, Any]) -> bool:
        return not (left["end"] <= right["start"] or right["end"] <= left["start"])

    def apply_combo(combo: tuple[dict[str, Any], ...]) -> str | None:
        mutated_text = original_text
        for item in sorted(combo, key=lambda entry: entry["start"], reverse=True):
            mutated_text = _apply_single_text_mutation(mutated_text, item["span"], item["plan"])
            if mutated_text is None:
                return None
        return mutated_text

    combo_candidates: list[tuple[dict[str, Any], ...]] = []
    combo_candidates.extend((item,) for item in resolved_items)

    for combo_size in (2, 3):
        for combo in itertools.combinations(resolved_items, combo_size):
            if any(spans_conflict(left, right) for left, right in itertools.combinations(combo, 2)):
                continue
            max_rank = max(item["aggressiveness_rank"] for item in combo)
            if combo_size == 3 and max_rank >= aggressiveness_rank["aggressive"]:
                continue
            combo_candidates.append(combo)

    combo_candidates.sort(
        key=lambda combo: (
            len(combo),
            max(item["aggressiveness_rank"] for item in combo),
            sum(item["start"] for item in combo),
        )
    )

    next_id = len([p for p in out_dir.iterdir() if p.is_file() and not p.name.startswith(".")])
    for combo in combo_candidates:
        if len(written_paths) >= max_outputs:
            break
        mutated_text = apply_combo(combo)
        if mutated_text is None or not mutated_text or mutated_text in seen_payloads:
            continue
        seen_payloads.add(mutated_text)
        out_path = out_dir / f"id:{next_id:06},src:{orig_id:06}"
        out_path.write_text(mutated_text, encoding="utf-8")
        written_paths.append(out_path.as_posix())
        next_id += 1

    return written_paths


def try_text_mutation(
    code_slice,
    constraints,
    target_branch,
    llm_util: LLMUtil,
    *,
    seed_name: str | None,
    fields=None,
    harness_code=None,
    roadblock=None,
    call_chain=None,
):
    if not seed_name:
        return False, None

    plan_items, effective_fields = get_text_mutation_plan(
        code_slice,
        constraints,
        target_branch,
        llm_util,
        fields=fields,
        harness_code=harness_code,
        preferred_seed=seed_name,
    )
    if not plan_items:
        return False, None

    candidate_paths = execute_text_mutation_plan(
        plan_items,
        seed_name,
        text_fields=effective_fields,
        harness_code=harness_code,
    )
    if not candidate_paths:
        return False, None

    for candidate_path in candidate_paths:
        gate_result, eval_result = gate_seed(candidate_path, roadblock=roadblock, call_chain=call_chain)
        logger.info(
            f"[SEED_GATE] Path T text mutation decision={gate_result.decision} accepted={gate_result.accepted} "
            f"reason={gate_result.reason}"
        )
        if gate_result.accepted and _seed_eval_indicates_local_progress(eval_result):
            return True, candidate_path

    return False, candidate_paths[0]


def mutate_suggest_without_taint(code_slice, fields, target_branch, llm_util: LLMUtil, pattern_json):
    llm_log = get_llm_logger()
    # 基础 system prompt
    sys_prompt = prompts['prompt']['mutate_suggest_without_taint']['sys_prompt']

    # 根据库名动态添加领域特定规则
    domain_rules = ""
    if '_domain_rules' in prompts['prompt']:
        domain_rules_config = prompts['prompt']['_domain_rules']
        if PROJECT in domain_rules_config:
            lib_rules = domain_rules_config[PROJECT]
            if 'structure' in lib_rules:
                domain_rules = "\n\n" + lib_rules['structure']
                logger.info(f"[{LogOp.LLM}] Added structure rules for {PROJECT}")

    # ========== NEW: Add input format info to system prompt ==========
    format_addition = ""
    if cached_format_info:
        format_addition = f"\n\n### 已检测到的输入格式信息\n{InputFormatDetector.format_info_to_prompt_section(cached_format_info)}"
        logger.info(f"[{LogOp.LLM}] Added format info to mutate_suggest_without_taint prompt")
    # ========== End format info addition ==========

    container_context = build_input_container_profile(
        "binary_script",
        fields=fields,
        harness_code=get_harness_code() or "",
    )
    user_content = prompts['prompt']['mutate_suggest_without_taint']['user_prompt'].format(
        code_slice=code_slice,
        fields=fields,
        target_branch=target_branch,
    )
    user_content += (
        "\n<input_container_profile>\n"
        f"{container_context}\n"
        "</input_container_profile>\n"
    )
    user_content += collect_input_examples_context("binary_script", max_examples=1)
    messages = [
        {'role': 'system', 'content': sys_prompt + domain_rules + format_addition},
        {'role': 'user', 'content': user_content}
        # constraints=constraints,
        # relevant_fields=field,
        # byte_range=byte_range)}
    ]

    max_retries = 3
    retry_count = 0

    while retry_count < max_retries:
        try:
            resp = llm_util.get_response(messages)

            # Handle empty string (cannot determine)
            if not resp.strip():
                logger.info(f"[{LogOp.LLM}] Mutate suggest: LLM returned empty string - cannot determine mutations")
                return {'passable': False, 'input_modifications': [], 'confidence': None, 'inference_types': []}

            try:
                data = ujson.loads(resp)
                logger.debug(f"[{LogOp.LLM}] Mutate suggest: Detected format type: {type(data).__name__}")

                # Only support new format: array
                if isinstance(data, list):
                    logger.info(f"[{LogOp.LLM}] Mutate suggest: Parsed {len(data)} field(s) from array format")

                    if not data:
                        logger.info(f"[{LogOp.LLM}] Mutate suggest: Empty array - no modifications suggested")
                        return {'passable': False, 'input_modifications': [], 'confidence': None, 'inference_types': []}

                    # Convert new array format to structure expected by downstream
                    # Also extract confidence and inference_type for strategy decisions
                    input_modifications = []
                    confidence_levels = {'high': 3, 'medium': 2, 'low': 1}
                    min_confidence_score = float('inf')
                    inference_types = set()

                    for item in data:
                        # Extract confidence and inference_type
                        item_confidence = item.get('confidence', 'medium')
                        item_inference_type = item.get('inference_type', 'direct')

                        # Track minimum confidence (weakest link)
                        if item_confidence in confidence_levels:
                            min_confidence_score = min(min_confidence_score, confidence_levels[item_confidence])

                        # Collect all inference types
                        inference_types.add(item_inference_type)

                        converted = {
                            'input_field': item.get('field_name', ''),
                            'byte_range': {
                                'start': item.get('offset', 0),
                                'end': item.get('offset', 0) + item.get('size', 0)
                            },
                            'constraints': [
                                f"encoding={item.get('encoding')}, value={item.get('new_value')}: {item.get('reason', '')}"
                            ],
                            '_new_format': item,  # Preserve original for get_mutate_script
                            '_confidence': item_confidence,
                            '_inference_type': item_inference_type
                        }
                        input_modifications.append(converted)

                    # Convert score back to confidence level
                    confidence_reverse = {3: 'high', 2: 'medium', 1: 'low'}
                    overall_confidence = confidence_reverse.get(min_confidence_score,
                                                                'medium') if min_confidence_score != float(
                        'inf') else 'medium'

                    logger.info(
                        f"[{LogOp.LLM}] Mutate suggest: Overall confidence={overall_confidence}, inference_types={list(inference_types)}")
                    logger.debug(
                        f"[{LogOp.LLM}] Mutate suggest: Converted data structure: {json.dumps(input_modifications, indent=2)}")

                    return {
                        'passable': True,
                        'input_modifications': input_modifications,
                        'confidence': overall_confidence,
                        'inference_types': list(inference_types)
                    }

                # Old format: dict with passable - NO LONGER SUPPORTED
                elif isinstance(data, dict):
                    retry_count += 1
                    logger.warning(
                        f"[{LogOp.LLM}] Mutate suggest: Old format detected (attempt {retry_count}/{max_retries}). Got keys: {list(data.keys())}")
                    if retry_count < max_retries:
                        append_llm_retry_feedback(
                            messages,
                            resp,
                            "请不要返回 object。请只返回 JSON 数组，每个元素描述一个字段修改建议。"
                        )
                        continue
                    return {'passable': False, 'input_modifications': [], 'confidence': None, 'inference_types': []}

                else:
                    retry_count += 1
                    logger.warning(
                        f"[{LogOp.LLM}] Mutate suggest: Unexpected format type: {type(data).__name__} (attempt {retry_count}/{max_retries})")
                    if retry_count < max_retries:
                        append_llm_retry_feedback(
                            messages,
                            resp,
                            f"返回类型错误：{type(data).__name__}。请只返回 JSON 数组。"
                        )
                        continue
                    return {'passable': False, 'input_modifications': [], 'confidence': None, 'inference_types': []}

            except (ValueError, ujson.JSONDecodeError) as e:
                retry_count += 1
                if retry_count < max_retries:
                    logger.debug(
                        f"[{LogOp.LLM}] Mutate suggest: JSON parse error (retry {retry_count}/{max_retries}): {str(e)}")
                    messages.append({'role': 'assistant', 'content': resp})
                    messages.append({
                        'role': 'user',
                        'content': f'JSON parse failed, please return JSON array. Error: {str(e)}'
                    })
                else:
                    logger.error(
                        f"[{LogOp.LLM}] Mutate suggest: JSON parse failed after {max_retries} retries: {str(e)}")
                    return {'passable': False, 'input_modifications': [], 'confidence': None, 'inference_types': []}

        except Exception as e:
            retry_count += 1
            if retry_count >= max_retries:
                logger.error(f"[{LogOp.LLM}] Mutate suggest: Failed after {max_retries} retries: {str(e)}")
                return {'passable': False, 'input_modifications': [], 'confidence': None, 'inference_types': []}

    return {'passable': False, 'input_modifications': [], 'confidence': None, 'inference_types': []}




class JSONMatch:
    def __init__(self, text: str):
        self._text = text
        self._span = (0, len(text))

    def group(self, num=0):
        return self._text

    def span(self, num=0):
        return self._span

    def start(self):
        return 0

    def end(self):
        return len(self._text)


def _extract_first_valid_json_segment(text: str) -> str | None:
    decoder = json.JSONDecoder()
    for idx, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            _, end = decoder.raw_decode(text, idx)
            return text[idx:end]
        except json.JSONDecodeError:
            continue
    return None


def extract_json_with_fallback(resp: str, pattern_json: str) -> Match[str] | None:
    """
    Extract JSON from LLM response with fallback logic.

    Args:
        resp: LLM response string
        pattern_json: JSON pattern regex to match

    Returns:
        Match object if found, None otherwise

    Logic:
        1. First try to match pattern_json (e.g., ```json...```)
        2. If regex fails, try to parse entire response as JSON
        3. If that also fails, return None
    """
    # Step 1: Try fenced JSON first, but validate the extracted payload before returning it.
    match = re.search(pattern_json, resp, re.DOTALL | re.IGNORECASE)
    if match:
        json_text = _extract_first_valid_json_segment(match.group(1).strip())
        if json_text is not None:
            logger.debug(f"[{LogOp.LLM}] JSON extracted via regex pattern match")
            return JSONMatch(json_text)
        logger.debug(f"[{LogOp.LLM}] Regex matched fenced block, but payload was not valid JSON")

    # Step 2: Try the full response, including JSON embedded in plain text.
    trimmed_resp = resp.strip()
    json_text = _extract_first_valid_json_segment(trimmed_resp)
    if json_text is not None:
        logger.debug(f"[{LogOp.LLM}] JSON extracted via direct parse (full response is valid JSON)")
        return JSONMatch(json_text)

    # Step 3: Not valid JSON, return None
    logger.debug(f"[{LogOp.LLM}] Response is not valid JSON and no pattern match found")
    return None


def build_generate_script_messages(code_slice: str | Any, constraints, input_profile,
                                   fields=None, target_branch=None, state_hints=None, harness_code=None,
                                   preferred_seed=None) -> list[dict[str, str]]:
    # 动态构建可选部分，避免空标签
    optional_sections = ""
    generation_mode = "binary_script"

    # ========== NEW: Add input format section ==========
    if cached_format_info:
        format_section = InputFormatDetector.format_info_to_prompt_section(cached_format_info)
        optional_sections += f"<input_format>\n{format_section}\n</input_format>\n"
    optional_sections += (
        "<input_container_profile>\n"
        f"{build_input_container_profile(generation_mode, fields=fields, harness_code=harness_code, preferred_seed=preferred_seed)}\n"
        "</input_container_profile>\n"
    )
    # ========== End input format section ==========

    if fields:
        optional_sections += build_semantic_fields_prompt_section(fields)
    if target_branch:
        optional_sections += f"<target_branch>\n{target_branch}\n</target_branch>\n"
    if state_hints:
        # 将state_hints列表转换为格式化的字符串
        hints_text = "\n".join([f"  - {hint}" for hint in state_hints])
        optional_sections += f"<state_hints>\n{hints_text}\n</state_hints>\n"
    optional_sections += f"<expected_input_type>\n{build_input_type_contract(generation_mode)}\n</expected_input_type>\n"
    optional_sections += build_parser_rich_generation_bias(
        generation_mode,
        preferred_seed=preferred_seed,
        harness_code=harness_code,
    )
    optional_sections += collect_input_examples_context(generation_mode, preferred_seed=preferred_seed)

    # ========== NEW: Build entry_functions section (for fallback slice mode) ==========
    entry_functions_section = ""
    if harness_code:
        entry_functions_section = f"<entry_functions>\n{harness_code}\n</entry_functions>\n"
    # ========== End entry_functions section ==========

    # 构建基础 user prompt 内容
    user_content = prompts['prompt']['generate_script']['user_prompt'].format(
        entry_functions=entry_functions_section,
        codes=code_slice,
        lib=PROJECT,
        runtime_command_context=build_runtime_command_context(),
        constraint_detail=constraints,
        input_profile=input_profile,
        optional_sections=optional_sections,
    )

    # 添加领域特定规则（不依赖 fields，只要项目有配置就使用）
    sys_prompt = get_formatted_prompt('generate_script')
    if '_domain_rules' in prompts['prompt']:
        domain_rules_config = prompts['prompt']['_domain_rules']
        if PROJECT in domain_rules_config:
            lib_rules = domain_rules_config[PROJECT]
            # 将结构规则合并到 sys_prompt 中（避免重复）
            if 'structure' in lib_rules:
                # 检查 sys_prompt 中是否已包含结构规则，避免重复
                if 'structure' not in sys_prompt.lower() or 'file format' not in sys_prompt.lower():
                    sys_prompt += "\n\n### 文件格式结构信息\n" + lib_rules['structure']
                    logger.info(f"[{LogOp.LLM}] Added structure rules for {PROJECT} in generate_script")

    messages = [
        {'role': 'system', 'content': sys_prompt},
        {'role': 'user', 'content': user_content}
    ]
    prompt_chars = _estimate_messages_chars(messages)
    if prompt_chars > PROMPT_MAX_MESSAGE_CHARS_SOFT:
        logger.warning(
            f"[{LogOp.LLM}] Large generate_script prompt detected: {prompt_chars} chars "
            f"(soft limit {PROMPT_MAX_MESSAGE_CHARS_SOFT})"
        )
    return messages


def build_direct_text_generation_messages(code_slice: str | Any, constraints, input_profile,
                                          fields=None, target_branch=None, state_hints=None,
                                          harness_code=None, preferred_seed=None) -> list[dict[str, str]]:
    optional_sections = ""
    generation_mode = "text_direct"

    if cached_format_info:
        format_section = InputFormatDetector.format_info_to_prompt_section(cached_format_info)
        optional_sections += f"<input_format>\n{format_section}\n</input_format>\n"
    optional_sections += (
        "<input_container_profile>\n"
        f"{build_input_container_profile(generation_mode, fields=fields, harness_code=harness_code, preferred_seed=preferred_seed)}\n"
        "</input_container_profile>\n"
    )
    if fields:
        optional_sections += build_semantic_fields_prompt_section(fields)
    if target_branch:
        optional_sections += f"<target_branch>\n{target_branch}\n</target_branch>\n"
    if state_hints:
        hints_text = "\n".join([f"  - {hint}" for hint in state_hints])
        optional_sections += f"<state_hints>\n{hints_text}\n</state_hints>\n"
    optional_sections += f"<expected_input_type>\n{build_input_type_contract(generation_mode)}\n</expected_input_type>\n"
    optional_sections += build_parser_rich_generation_bias(
        generation_mode,
        preferred_seed=preferred_seed,
        harness_code=harness_code,
    )
    optional_sections += collect_input_examples_context(generation_mode, preferred_seed=preferred_seed)

    entry_functions_section = ""
    if harness_code:
        entry_functions_section = f"<entry_functions>\n{harness_code}\n</entry_functions>\n"

    user_content = prompts['prompt']['generate_text_input_direct']['user_prompt'].format(
        entry_functions=entry_functions_section,
        codes=code_slice,
        lib=PROJECT,
        runtime_command_context=build_runtime_command_context(),
        constraint_detail=constraints,
        input_profile=input_profile,
        optional_sections=optional_sections,
    )

    messages = [
        {'role': 'system', 'content': get_formatted_prompt('generate_text_input_direct')},
        {'role': 'user', 'content': user_content},
    ]
    prompt_chars = _estimate_messages_chars(messages)
    if prompt_chars > PROMPT_MAX_MESSAGE_CHARS_SOFT:
        logger.warning(
            f"[{LogOp.LLM}] Large generate_text_input_direct prompt detected: {prompt_chars} chars "
            f"(soft limit {PROMPT_MAX_MESSAGE_CHARS_SOFT})"
        )
    return messages




def build_constraints_messages(rb_info, code_slice: str | Any) -> list[dict[str, str]]:
    # LLM interaction logging
    return [
        {'role': 'system', 'content': prompts['prompt'][ANALYSE_BRANCH_PROMPT_KEY_V2]['sys_prompt']},
        {'role': 'user',
         'content': prompts['prompt'][ANALYSE_BRANCH_PROMPT_KEY_V2]['user_prompt'].format(codes=code_slice,
                                                                                           rb_info=rb_info,
                                                                                           lib=PROJECT,
                                                                                           runtime_command_context=build_runtime_command_context())}
    ]




def get_rb_id(roadblock):
    _, rb_fid = get_function_name(roadblock)
    roadblock_id = None
    for bb in bbs:
        if rb_fid == bb['function'] and bb['lineEnd'] >= roadblock['line'] >= bb['lineStart']:
            roadblock_id = bb['id']
            break
        elif (rb_fid == bb['function'] and roadblock.get("group_type", None) == "switch"
                and bb['lineEnd'] >= roadblock['case_body_line']>= bb['lineStart']): # 后面也要用这个case_body_line吗？考虑一下
            roadblock_id = bb['id']
            break
    return roadblock_id


def get_function_name(roadblock):
    rb_file = roadblock['filename']
    rb_line = roadblock['line']
    for func in funcs:
        if "file_name" not in func:
            continue
        if func["file_name"].split("/")[-1] == rb_file.split("/")[-1]:
            if func['lineEnd'] >= rb_line >= func['lineStart']:
                return func['name'], func["id"]
    return "", ""


def get_switch_statement_line(roadblock):
    """
    对于 switch case 类型的 roadblock，查找对应的 switch 语句行号。

    通过查找源文件中 case 之前最近的 switch 语句来确定。

    Args:
        roadblock: 包含 filename, line, 等信息的字典

    Returns:
        switch 语句的行号，如果找不到则返回 None
    """
    # 如果 roadblock 中已经包含 switch_statement 字段，尝试从中提取行号
    # 当前导出的 switch_statement 字段只包含语句内容，不包含行号
    # 所以我们需要通过查找源文件来确定

    rb_file = roadblock['filename']
    rb_line = roadblock['line']

    source_path = config.resolve_source_path(rb_file)

    if not source_path:
        logger.debug(f"[SWITCH] Source file not found for {rb_file}")
        return None

    try:
        # 读取源文件，查找 case 之前最近的 switch 语句
        with open(source_path, 'r') as f:
            lines = f.readlines()

        # 从 case 行向上查找 switch 语句
        # 通常 switch 语句在 case 之前不远
        for i in range(rb_line - 2, max(0, rb_line - 51), -1):  # 向上查找最多 50 行
            line = lines[i].strip()
            if line.startswith('switch') and '(' in line:
                logger.debug(f"[SWITCH] Found switch statement at line {i + 1} for case at line {rb_line}")
                return i + 1  # 返回 1-based 行号

    except Exception as e:
        logger.warning(f"[SWITCH] Error reading source file {source_path}: {e}")

    return None






def _build_seed_payload_preview(
    seed_name: str,
    *,
    harness_code: str | None = None,
    max_text_chars: int = 1200,
    max_binary_bytes: int = 96,
) -> str:
    seed_path = config.find_seed_path(seed_name)
    if seed_path is None or not seed_path.exists():
        return "<seed_preview>\nmissing_seed\n</seed_preview>"

    payload = read_seed_payload_view(seed_path, harness_code)
    if not payload:
        try:
            payload = seed_path.read_bytes()
        except OSError:
            return f"<seed_preview path=\"{seed_path.name}\">\nread_failed\n</seed_preview>"

    preview_lines = [
        f"path={seed_path.name}",
        f"payload_size={len(payload)}",
    ]
    text_ratio = (
        sum(1 for byte in payload if 32 <= byte <= 126 or byte in {9, 10, 13}) / max(len(payload), 1)
    )
    if text_ratio >= 0.80:
        preview_lines.append("payload_kind=text")
        preview_lines.append(payload.decode("utf-8", errors="replace")[:max_text_chars])
    else:
        preview_lines.append("payload_kind=binary")
        preview_lines.append(f"hex_preview={payload[:max_binary_bytes].hex()}")

    return "<seed_preview>\n" + "\n".join(preview_lines) + "\n</seed_preview>"


def _seed_payload_looks_textual(seed_name: str, *, harness_code: str | None = None) -> bool:
    seed_path = config.find_seed_path(seed_name)
    if seed_path is None or not seed_path.exists():
        return False

    payload = read_seed_payload_view(seed_path, harness_code)
    if not payload:
        try:
            payload = seed_path.read_bytes()
        except OSError:
            return False
    if not payload:
        return False

    printable = sum(1 for byte in payload if 32 <= byte <= 126 or byte in {9, 10, 13})
    return (printable / max(len(payload), 1)) >= 0.80


def get_seed_targeted_mutation_script(
    *,
    code_slice: str,
    constraints,
    target_branch: str,
    llm_util: LLMUtil,
    seed_name: str,
    fields=None,
    relevant_info=None,
    harness_code: str | None = None,
    max_retries: int = 3,
) -> str | None:
    llm_log = get_llm_logger()
    llm_log.info("[LLM_INTERACTION] get_seed_targeted_mutation_script called")

    generation_mode = "text_direct" if _looks_textual_semantic_input(
        fields=fields,
        harness_code=harness_code or get_harness_code() or "",
    ) else "binary_script"
    container_context = build_input_container_profile(
        generation_mode,
        fields=fields,
        harness_code=harness_code or get_harness_code() or "",
        preferred_seed=seed_name,
    )
    semantic_fields_section = build_semantic_fields_prompt_section(fields) if fields else ""
    relevant_info_section = ""
    if relevant_info:
        try:
            relevant_info_section = (
                "<taint_context>\n"
                + json.dumps(relevant_info, ensure_ascii=False, default=str)[:2000]
                + "\n</taint_context>\n"
            )
        except Exception:
            relevant_info_section = ""

    messages = [
        {
            "role": "system",
            "content": (
                "你是一位 seed 定向变异脚本生成专家。给定一个具体 reachable seed、目标分支约束、"
                "以及可选的字段/污点上下文，输出一个最小修改的 Python 变异脚本。\n"
                "要求：\n"
                "- 最终只输出一个 ```python``` 代码块，不要解释。\n"
                "- 脚本必须接受两个参数：sys.argv[1] 是原始 seed 路径，sys.argv[2] 是输出 seed 路径。\n"
                "- 脚本必须读取原始 seed，做尽量局部、最小、同家族的修改，再写出新 seed。\n"
                "- 如果输入是文本或带外层 wrapper 的文本载荷，优先保留整体骨架，只修改关键字段/片段。\n"
                "- 如果输入是二进制，优先做定点、短范围修改，不要把文件整体重写成无关格式。\n"
                "- 除非约束明确要求整体重建，否则禁止把整个文件替换成全新内容；优先保留大部分原始字节/文本。\n"
                "- 保持文件基本可解析；如果需要长度、校验、分隔符、配对结构，请同步维护。\n"
                "- 不要打印调试信息，不要依赖外部文件或额外环境。"
            ),
        },
        {
            "role": "user",
            "content": (
                f"<lib_under_fuzzing>\n{PROJECT}\n</lib_under_fuzzing>\n"
                f"<runtime_command_context>\n{build_runtime_command_context()}\n</runtime_command_context>\n"
                f"<target_branch>\n{target_branch}\n</target_branch>\n"
                f"<constraints>\n{constraints}\n</constraints>\n"
                f"<code_slice>\n{code_slice}\n</code_slice>\n"
                f"<input_container_profile>\n{container_context}\n</input_container_profile>\n"
                f"{semantic_fields_section}"
                f"{relevant_info_section}"
                f"{_build_seed_payload_preview(seed_name, harness_code=harness_code)}\n"
                f"{collect_input_examples_context(generation_mode, preferred_seed=seed_name, max_examples=1)}"
            ),
        },
    ]

    for attempt in range(max_retries):
        resp = llm_util.get_response(messages)
        try:
            script = extract_generator(resp)
        except ScriptNotFoundError:
            script = None
        if script:
            llm_log.info(
                f"[LLM_INTERACTION] get_seed_targeted_mutation_script result: script_length={len(script)}"
            )
            return script
        if attempt < max_retries - 1:
            append_llm_retry_feedback(
                messages,
                resp,
                "请只返回一个可运行的 ```python``` 代码块，并严格使用 sys.argv[1] 读取原 seed、"
                "使用 sys.argv[2] 写出新 seed。",
            )
    llm_log.error("[LLM_INTERACTION] get_seed_targeted_mutation_script failed after retries")
    return None



def process_relevant_fields_for_simplified_path(
    seed: str,
    *,
    roadblock_id: int | str,
    rb_file: str,
    rb_line: int,
    enable_semantic_parsing: bool = True,
) -> tuple[Optional[dict[str, Any]], Optional[str], Optional[dict[str, Any]]]:
    global taint_extraction_failures

    taint_dir = config.get_taint_artifact_dir(seed, roadblock_id)
    semantic_dir = config.get_semantic_fields_artifact_dir(seed, roadblock_id)
    taint_dir.mkdir(parents=True, exist_ok=True)
    semantic_dir.mkdir(parents=True, exist_ok=True)
    tseed_isi_path = taint_dir / "tseed.isi"
    tseed_isi_json_path = taint_dir / "tseed.isi.json"
    result_json_path = semantic_dir / "result.json"
    relevant_field_json_path = taint_dir / "relevant_field.json"
    seed_path = config.find_seed_path(seed)
    if seed_path is None:
        return None, None, None

    root_seed_path = find_seed_root(seed_path.parent.as_posix(), seed_path.name, OUTPUT_PATH.as_posix())
    resolved_seed_path = Path(root_seed_path) if root_seed_path else seed_path
    if not resolved_seed_path.exists():
        return None, None, None

    shutil.copy2(resolved_seed_path, tseed_isi_path)
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = os.path.expanduser(
        "~/Desktop/autoframe/ipl-modeling/install/lib") + ':' + os.environ.get('LD_LIBRARY_PATH', '')
    env['DFSAN_OPTIONS'] = "warn_unimplemented=0"
    env['TARGET_BRANCH'] = f'{os.path.basename(rb_file)}:{rb_line}'

    if taint_extraction_failures >= TAINT_EXTRACTION_FAILURE_THRESHOLD:
        logger.warning(
            f"[{LogOp.ROADBLOCK}] Taint extraction disabled for this session after "
            f"{taint_extraction_failures} consecutive failures"
        )
        return None, None, None

    cmd_extract = [IPL_TARGET_PATH, tseed_isi_path]
    subprocess.run(cmd_extract, env=env, stderr=subprocess.DEVNULL)

    isi_json_path = tseed_isi_json_path
    if not os.path.exists(isi_json_path):
        taint_extraction_failures += 1
        return None, None, None
    taint_extraction_failures = 0

    fields = None
    if enable_semantic_parsing:
        fields = build_semantic_fields(
            project=PROJECT,
            seed_path=resolved_seed_path,
            isi_json_path=isi_json_path,
            out_path=result_json_path,
            harness_code=get_harness_code(),
        )
        if fields and 'error' in fields:
            fields = None

    env['BRANCH_FIELD_EXPORT'] = relevant_field_json_path.as_posix()
    if fields and os.path.exists(result_json_path):
        env['FIELD_CONFIG_FILE'] = result_json_path.as_posix()

    subprocess.run(cmd_extract, env=env, stderr=subprocess.DEVNULL)
    if not os.path.exists(relevant_field_json_path):
        taint_extraction_failures += 1
        return None, None, None
    taint_extraction_failures = 0

    with open(relevant_field_json_path, 'r') as f:
        rel_json = ujson.load(f)
    return rel_json['branches'][0], resolved_seed_path.name, fields


def attempt_simplified_flag_path(
    ctx: SimplifiedAttemptContext,
    relevant_flags: list[dict[str, Any]],
    constant_groups: dict[str, Any],
) -> bool:
    global fuzzer, output_dir

    if not (ENABLE_SIMPLIFIED_FLAG_PATH and relevant_flags):
        return False

    try:
        flag_reachable, flag_result = solve_with_flags(
            ctx.code_slice,
            ctx.roadblock,
            ctx.constraints,
            relevant_flags,
            constant_groups,
            ctx.llm_util,
            prompts
        )
        if not (flag_reachable and flag_result):
            return False
        script = extract_script_from_flag_result(flag_result)
        if not script:
            return False
        llm_target_path = config.get_named_queue_dir(FLAG_FUZZER)
        os.makedirs(llm_target_path, exist_ok=True)
        seed_id = len(os.listdir(llm_target_path))
        solved, _, dest_file = extract_and_test(
            ctx.llm_util,
            script,
            ctx.roadblock_id,
            seed_id,
            ctx.tracer,
            fuzzer,
            roadblock=ctx.roadblock,
            call_chain=ctx.call_chain,
            code_slice=ctx.code_slice,
            queue_dir=llm_target_path,
            path_prefix="flag",
        )
        return solved or bool(dest_file)
    except Exception as e:
        logger.error(f"[{LogOp.ROADBLOCK}] Flag-based solving error: {e}", exc_info=True)
        return False


def attempt_simplified_taint_mutation_path(ctx: SimplifiedAttemptContext, pattern_json: str) -> bool:
    global fuzzer, output_dir

    if not (ENABLE_SIMPLIFIED_TAINT_MUTATION_PATH and ctx.seed and ctx.relevant_info and ctx.relevant_info.get('ranges')):
        return False

    try:
        mut_target_path = config.get_named_queue_dir(TAINT_MUTATION_FUZZER)
        os.makedirs(mut_target_path, exist_ok=True)
        seed_id = len(os.listdir(mut_target_path))
        field = ctx.relevant_info['fields']
        byte_range = [dict(item) for item in ctx.relevant_info['ranges']]
        if byte_range:
            byte_range[0]['end'] = str(int(byte_range[0]['end']) - 1)
        suggestions = mutate_suggest_with_taint(
            ctx.code_slice, ctx.constraints, field if field else "", byte_range, ctx.llm_util, pattern_json
        )
        if not suggestions['passable']:
            return False
        script = get_mutate_script(
            suggestions['input_modifications'],
            ctx.llm_util,
            fields=ctx.fields,
            harness_code=ctx.harness_for_mode,
            preferred_seed=ctx.seed,
        )
        if not script:
            return False
        solved, _, dest_file = mutate_and_test(
            ctx.llm_util,
            script,
            seed_id,
            ctx.seed,
            fuzzer,
            ctx.tracer,
            roadblock=ctx.roadblock,
            call_chain=ctx.call_chain,
            path_prefix="taint_mutation",
            queue_dir=mut_target_path,
        )
        return solved or bool(dest_file)
    except Exception as e:
        logger.error(f"[{LogOp.ROADBLOCK}] Simplified Path A error: {e}", exc_info=True)
        return False


def attempt_simplified_state_driven_path(ctx: SimplifiedAttemptContext) -> bool:
    global fuzzer, output_dir

    if not (ENABLE_SIMPLIFIED_STATE_DRIVEN_PATH and ENABLE_STATE_DRIVEN_PATH_B and ctx.seed is not None):
        return False

    try:
        mut_target_path = config.get_named_queue_dir(STATE_DRIVEN_FUZZER)
        os.makedirs(mut_target_path, exist_ok=True)
        seed_id = len(os.listdir(mut_target_path))
        state_mapper = StateDrivenMapper(ctx.llm_util)
        sample_seed_path = Path(output_dir) / 'default' / 'queue' / ctx.seed
        taint_info = {'branches': [ctx.relevant_info]} if ctx.relevant_info and ctx.relevant_info.get('ranges') else None
        known_format_info = {'format_info': cached_format_info} if cached_format_info else None
        mapping_result = state_mapper.analyze(
            code_slice=ctx.code_slice,
            roadblock=ctx.roadblock,
            sample_seed_path=sample_seed_path,
            taint_info=taint_info,
            known_format_info=known_format_info
        )
        if not (mapping_result and mapping_result.get('state_mappings')):
            return False
        script = state_mapper.generate_mutation_script(
            mappings=mapping_result,
            constraints=ctx.constraints,
            output_path=MUT_TMP_PATH / f"state_{ctx.roadblock_id}"
        )
        if not script:
            return False
        script = extract_generator(script)
        solved, _, dest_file = mutate_and_test(
            ctx.llm_util,
            script,
            seed_id,
            ctx.orig if ctx.orig else ctx.seed,
            fuzzer,
            ctx.tracer,
            roadblock=ctx.roadblock,
            call_chain=ctx.call_chain,
            path_prefix="state_driven",
            queue_dir=mut_target_path,
        )
        return solved or bool(dest_file)
    except Exception as e:
        logger.warning(f"[{LogOp.ROADBLOCK}] Simplified Path B state-driven error: {e}", exc_info=True)
        return False


def attempt_simplified_field_mutation_path(ctx: SimplifiedAttemptContext, pattern_json: str) -> bool:
    global fuzzer, output_dir

    if not (ENABLE_SIMPLIFIED_FIELD_MUTATION_PATH and ctx.seed is not None and ctx.fields is not None):
        return False

    try:
        mut_target_path = config.get_named_queue_dir(FIELD_MUTATION_FUZZER)
        os.makedirs(mut_target_path, exist_ok=True)
        seed_id = len(os.listdir(mut_target_path))
        suggestions = mutate_suggest_without_taint(
            ctx.code_slice,
            ctx.fields,
            ctx.bcode,
            ctx.llm_util,
            pattern_json
        )
        if not suggestions['passable']:
            return False
        script = get_mutate_script(
            suggestions['input_modifications'],
            ctx.llm_util,
            fields=ctx.fields,
            harness_code=ctx.harness_for_mode,
            preferred_seed=ctx.seed,
        )
        if not script:
            return False
        solved, _, dest_file = mutate_and_test(
            ctx.llm_util,
            script,
            seed_id,
            ctx.orig if ctx.orig else ctx.seed,
            fuzzer,
            ctx.tracer,
            roadblock=ctx.roadblock,
            call_chain=ctx.call_chain,
            path_prefix="field_mutation",
            queue_dir=mut_target_path,
        )
        return solved or bool(dest_file)
    except Exception as e:
        logger.error(f"[{LogOp.ROADBLOCK}] Simplified Path B fallback error: {e}", exc_info=True)
        return False




def _load_text_seed_for_xml(seed_name: str | None) -> str | None:
    if not seed_name:
        return None
    seed_path = config.find_seed_path(seed_name)
    if seed_path is None or not seed_path.exists():
        return None
    try:
        return seed_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def _collect_libxml_donor_texts(preferred_seed: str | None, limit: int = 4) -> list[str]:
    donors: list[str] = []
    seen: set[str] = set()
    for seed_name in [preferred_seed]:
        text = _load_text_seed_for_xml(seed_name)
        if text and text not in seen:
            seen.add(text)
            donors.append(text)

    queue_dirs = [
        Path(output_dir) / "default" / "queue",
        Path(output_dir) / "LLM" / "queue",
    ]
    for queue_dir in queue_dirs:
        if len(donors) >= limit:
            break
        if not queue_dir.exists():
            continue
        for seed_path in sorted(queue_dir.iterdir(), reverse=True):
            if len(donors) >= limit:
                break
            if not seed_path.is_file():
                continue
            try:
                text = seed_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if not text or text in seen:
                continue
            seen.add(text)
            donors.append(text)
    return donors


def _call_llm_json_object(
    llm_util: LLMUtil,
    messages: list[dict[str, str]],
    context: str,
    max_retries: int = 3,
) -> dict[str, Any] | None:
    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"
    resp = ""
    for attempt in range(max_retries):
        try:
            resp = llm_util.get_response(messages)
            match = extract_json_with_fallback(resp, pattern_json)
            if not match:
                logger.warning(f"[{LogOp.LLM}] {context}: JSON pattern not found (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    append_llm_retry_feedback(messages, resp, "请只返回一个 JSON object，不要输出额外解释。")
                continue
            result = json.loads(match.group(1).strip())
            schema_error = validate_generic_object_result(result, context)
            if schema_error:
                logger.warning(
                    f"[{LogOp.LLM}] {context}: invalid schema (attempt {attempt + 1}/{max_retries}): {schema_error}"
                )
                if attempt < max_retries - 1:
                    append_llm_retry_feedback(
                        messages,
                        resp,
                        f"返回结构不符合要求：{schema_error}。请只返回一个 JSON object。",
                    )
                continue
            return result
        except json.JSONDecodeError as exc:
            logger.warning(f"[{LogOp.LLM}] {context}: JSON decode error (attempt {attempt + 1}/{max_retries}): {exc}")
            if attempt < max_retries - 1:
                append_llm_retry_feedback(messages, resp, f"JSON 解析失败：{exc}。请只返回一个 JSON object。")
        except Exception as exc:
            logger.error(f"[{LogOp.LLM}] {context}: unexpected error: {exc}", exc_info=True)
            break
    return None


def attempt_simplified_xml_grammar_path(ctx: SimplifiedAttemptContext) -> bool:
    global output_dir

    if not ENABLE_SIMPLIFIED_XML_GRAMMAR_PATH:
        return False
    if not is_libxml_project(PROJECT):
        return False
    if ctx.generation_mode != "text_direct":
        return False

    try:
        preferred_seed_text = _load_text_seed_for_xml(ctx.seed)
        donor_seed_texts = _collect_libxml_donor_texts(ctx.seed)
        candidates = build_libxml_grammar_candidates(
            constraints=ctx.constraints,
            summary=ctx.summary,
            roadblock_code=ctx.bcode,
            preferred_seed_text=preferred_seed_text,
            donor_seed_texts=donor_seed_texts,
            fields=ctx.fields,
            max_candidates=6,
        )
        if ENABLE_SIMPLIFIED_XML_GRAMMAR_LLM_SPEC:
            spec_messages = build_libxml_llm_mutation_spec_messages(
                constraints=ctx.constraints,
                summary=ctx.summary,
                roadblock_code=ctx.bcode,
                preferred_seed_text=preferred_seed_text,
                donor_seed_texts=donor_seed_texts,
                fields=ctx.fields,
            )
            spec_result = _call_llm_json_object(ctx.llm_util, spec_messages, "xml grammar llm spec")
            if spec_result:
                candidates.extend(
                    apply_llm_mutation_spec(
                        constraints=ctx.constraints,
                        summary=ctx.summary,
                        roadblock_code=ctx.bcode,
                        spec=spec_result,
                        preferred_seed_text=preferred_seed_text,
                        donor_seed_texts=donor_seed_texts,
                        fields=ctx.fields,
                        max_candidates=4,
                    )
                )
        if ENABLE_SIMPLIFIED_XML_GRAMMAR_LLM_SCORING:
            scoring_messages = build_libxml_llm_component_scoring_messages(
                constraints=ctx.constraints,
                summary=ctx.summary,
                roadblock_code=ctx.bcode,
                preferred_seed_text=preferred_seed_text,
                donor_seed_texts=donor_seed_texts,
                fields=ctx.fields,
            )
            scoring_result = _call_llm_json_object(ctx.llm_util, scoring_messages, "xml grammar llm scoring")
            if scoring_result:
                candidates.extend(
                    build_candidates_from_component_scores(
                        constraints=ctx.constraints,
                        summary=ctx.summary,
                        roadblock_code=ctx.bcode,
                        scoring_result=scoring_result,
                        preferred_seed_text=preferred_seed_text,
                        donor_seed_texts=donor_seed_texts,
                        fields=ctx.fields,
                        max_candidates=4,
                    )
                )
        dedup_candidates = []
        seen_texts: set[str] = set()
        for candidate in candidates:
            if not candidate.text or candidate.text in seen_texts:
                continue
            seen_texts.add(candidate.text)
            dedup_candidates.append(candidate)
        candidates = dedup_candidates[:10]
        if not candidates:
            return False

        llm_target_path = config.get_named_queue_dir(XML_GRAMMAR_FUZZER)
        attempted = False
        accepted = False
        for candidate in candidates:
            seed_path = os.fspath(config.next_queue_seed_path(llm_target_path, roadblock_id=ctx.roadblock_id))
            Path(seed_path).write_text(candidate.text, encoding="utf-8")
            attempted = True
            gate_result, eval_result = gate_seed(seed_path, roadblock=ctx.roadblock, call_chain=ctx.call_chain)
            logger.info(
                f"[{LogOp.ROADBLOCK}] Simplified XML grammar path strategy={candidate.strategy} "
                f"decision={gate_result.decision} accepted={gate_result.accepted} reason={gate_result.reason}"
            )
            if gate_result.accepted:
                accepted = True
        return attempted and accepted
    except Exception as e:
        logger.error(f"[{LogOp.ROADBLOCK}] Simplified XML grammar path error: {e}", exc_info=True)
        return False


def attempt_simplified_batch_mutation_path(ctx: SimplifiedAttemptContext) -> bool:
    global output_dir

    if not ENABLE_SIMPLIFIED_BATCH_MUTATION_PATH:
        return False

    logger.info(f"[{LogOp.ROADBLOCK}] Simplified Path D: trying reachable-seed targeted mutation")
    try:
        available_seeds = ctx.tracer.get_rb_seed(ctx.roadblock)
        ranked_seed_names = ctx.tracer.select_seed_names_for_roadblock(
            ctx.roadblock,
            seed_names=available_seeds,
            max_seeds=max(1, min(4, len(available_seeds))),
        )
        candidate_seed_names: list[str] = []
        for seed_name in [ctx.seed, *ranked_seed_names]:
            if seed_name and seed_name not in candidate_seed_names:
                candidate_seed_names.append(seed_name)
        if not candidate_seed_names:
            return False

        mut_target_path = config.get_named_queue_dir(BATCH_MUTATION_FUZZER)
        Path(mut_target_path).mkdir(parents=True, exist_ok=True)

        for seed_name in candidate_seed_names:
            seed_fields = ctx.fields if seed_name == ctx.seed else _normalize_text_mutation_fields(
                None,
                seed_name=seed_name,
                harness_code=ctx.harness_for_mode,
            )
            seed_relevant_info = ctx.relevant_info if seed_name == ctx.seed else None
            if _seed_payload_looks_textual(seed_name, harness_code=ctx.harness_for_mode):
                text_success, text_candidate = try_text_mutation(
                    ctx.code_slice,
                    ctx.constraints,
                    ctx.bcode,
                    ctx.llm_util,
                    seed_name=seed_name,
                    fields=seed_fields,
                    harness_code=ctx.harness_for_mode,
                    roadblock=ctx.roadblock,
                    call_chain=ctx.call_chain,
                )
                if text_success or text_candidate:
                    logger.info(
                        f"[{LogOp.ROADBLOCK}] Simplified Path D generated a text mutation candidate from reachable seed {seed_name}"
                    )
                    return True

            script = get_seed_targeted_mutation_script(
                code_slice=ctx.code_slice,
                constraints=ctx.constraints,
                target_branch=ctx.bcode,
                llm_util=ctx.llm_util,
                seed_name=seed_name,
                fields=seed_fields,
                relevant_info=seed_relevant_info,
                harness_code=ctx.harness_for_mode,
            )
            if not script:
                logger.info(
                    f"[{LogOp.ROADBLOCK}] Simplified Path D could not synthesize a targeted script for seed {seed_name}"
                )
                continue

            seed_id = len(os.listdir(mut_target_path))
            solved, _, dest_file = mutate_and_test(
                ctx.llm_util,
                script,
                seed_id,
                ctx.orig if seed_name == ctx.seed and ctx.orig else seed_name,
                fuzzer,
                ctx.tracer,
                roadblock=ctx.roadblock,
                call_chain=ctx.call_chain,
                path_prefix="batch_mutation",
                queue_dir=mut_target_path,
            )
            if solved or dest_file:
                logger.info(
                    f"[{LogOp.ROADBLOCK}] Simplified Path D generated a candidate seed from reachable seed {seed_name}"
                )
                return True
            logger.info(
                f"[{LogOp.ROADBLOCK}] Simplified Path D produced no candidate output for reachable seed {seed_name}"
            )
        return False
    except Exception as e:
        logger.warning(f"[{LogOp.ROADBLOCK}] Simplified Path D error: {e}", exc_info=True)
        return False


def run_direct_generation(
    ctx: SimplifiedAttemptContext,
    *,
    skip_seed_gate: bool = False,
    log_prefix: str = "Direct generation",
) -> bool:
    global fuzzer, output_dir

    if not ENABLE_SIMPLIFIED_DIRECT_GENERATION_PATH:
        return False

    logger.info(f"[{LogOp.ROADBLOCK}] {log_prefix}: trying direct generation")
    try:
        plan = plan_direct_generation(
            llm_util=ctx.llm_util,
            code_slice=ctx.code_slice,
            constraints=ctx.constraints,
            summary=ctx.summary,
            target_branch=ctx.bcode,
            fields=ctx.fields,
            state_hints=ctx.state_hints,
            harness_code=ctx.harness_for_mode,
            preferred_seed=ctx.seed,
            inferred_mode=ctx.generation_mode,
        )
        result = execute_direct_generation_plan(
            ctx,
            plan,
            queue_dir=config.get_named_queue_dir(DIRECT_GENERATION_FUZZER),
            skip_seed_gate=skip_seed_gate,
            defer_effectiveness_to_outer_check=True,
            log_prefix=log_prefix,
        )
        if result.attempted and result.gate_result:
            logger.info(
                f"[SEED_GATE] {log_prefix} {result.mode} decision={result.gate_result.decision} "
                f"accepted={result.gate_result.accepted} reason={result.gate_result.reason}"
            )
        return result.attempted
    except Exception as e:
        logger.error(f"[{LogOp.ROADBLOCK}] {log_prefix} error: {e}", exc_info=True)
        return False


def _filter_and_reorder_path_attempts_by_names(
    path_attempts: list[tuple[str, bool, Any]],
    ordered_names: list[str],
) -> list[tuple[str, bool, Any]]:
    attempt_map = {path_name: attempt for path_name, *rest in path_attempts for attempt in [(path_name, *rest)]}
    selected: list[tuple[str, bool, Any]] = []
    seen: set[str] = set()

    for path_name in ordered_names:
        if path_name in attempt_map and path_name not in seen:
            selected.append(attempt_map[path_name])
            seen.add(path_name)

    return selected


def plan_simplified_path_selection(
    *,
    llm_util: LLMUtil,
    roadblock: dict[str, Any],
    code_slice: str,
    constraints,
    summary: str,
    target_class: str,
    generation_mode: str,
    available_paths: list[str],
    enabled_paths: list[str],
    seed_available: bool,
    has_fields: bool,
    has_taint_ranges: bool,
    has_state_hints: bool,
    has_relevant_flags: bool,
) -> list[str]:
    if len(enabled_paths) <= 1:
        return enabled_paths

    path_capabilities = {
        "flag": "Best when relevant compile/runtime flag variables clearly gate the target branch.",
        "taint_mutation": "Best when a reachable seed exists and taint ranges identify input bytes that influence the branch.",
        "state_driven": "Best when the branch depends on parser/program state transitions and a reachable seed exists.",
        "field_mutation": "Best when semantic fields are available and structured inputs can be edited at field level.",
        "xml_grammar": "Best for libxml-style structured text parsing when direct text generation is appropriate.",
        "batch_mutation": "Best as a fallback targeted mutation path over reachable seeds when other stronger signals are weak.",
        "direct_generation": "Best when seed mutation signals are weak or when generating a fresh input is more promising than editing.",
    }
    available_info = []
    for path_name in available_paths:
        available_info.append({
            "path_name": path_name,
            "enabled": path_name in enabled_paths,
            "capability": path_capabilities.get(path_name, ""),
        })

    user_content = (
        f"<project>{PROJECT}</project>\n"
        f"<target_class>{target_class}</target_class>\n"
        f"<generation_mode>{generation_mode}</generation_mode>\n"
        f"<roadblock>{json.dumps(roadblock, ensure_ascii=False, default=str)[:1600]}</roadblock>\n"
        f"<summary>{summary[:1200]}</summary>\n"
        f"<constraints>{json.dumps(constraints, ensure_ascii=False)[:1800] if not isinstance(constraints, str) else constraints[:1800]}</constraints>\n"
        f"<code_slice>{code_slice[:3000]}</code_slice>\n"
        f"<signals>\n"
        f"seed_available={seed_available}\n"
        f"has_fields={has_fields}\n"
        f"has_taint_ranges={has_taint_ranges}\n"
        f"has_state_hints={has_state_hints}\n"
        f"has_relevant_flags={has_relevant_flags}\n"
        f"</signals>\n"
        f"<path_options>{json.dumps(available_info, ensure_ascii=False)}</path_options>\n"
        "Choose only the enabled paths that are actually worth trying for this roadblock.\n"
        "Return one JSON object with keys: selected_paths, primary_path, reason.\n"
        "selected_paths must be an array of distinct enabled path names, sorted from most suitable to least suitable.\n"
        "Do not include paths whose prerequisites are clearly missing or whose fit is weak."
    )
    messages = [
        {
            "role": "system",
            "content": (
                "You are a path routing planner for an input-generation pipeline. "
                "Given one target roadblock, current evidence, and candidate path capabilities, "
                "select only the enabled paths that are actually worth trying, and rank those selected paths. "
                "Prefer paths whose prerequisites are already satisfied, and omit weak fits. "
                "Do not invent path names. Output JSON only."
            ),
        },
        {"role": "user", "content": user_content},
    ]

    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"
    for attempt in range(3):
        resp = llm_util.get_response(messages)
        match = extract_json_with_fallback(resp, pattern_json)
        if not match:
            if attempt < 2:
                append_llm_retry_feedback(
                    messages,
                    resp,
                    "请只返回一个 JSON object，并包含 selected_paths、primary_path、reason。",
                )
            continue
        try:
            result = json.loads(match.group(1).strip())
        except json.JSONDecodeError as exc:
            if attempt < 2:
                append_llm_retry_feedback(
                    messages,
                    resp,
                    f"JSON 解析失败：{exc}。请只返回一个合法的 JSON object。",
                )
            continue
        if not isinstance(result, dict):
            continue
        selected_paths = result.get("selected_paths")
        if not isinstance(selected_paths, list):
            continue
        normalized = []
        seen = set()
        for item in selected_paths:
            path_name = str(item).strip()
            if path_name in enabled_paths and path_name not in seen:
                normalized.append(path_name)
                seen.add(path_name)
        if normalized:
            logger.info(
                f"[{LogOp.ROADBLOCK}] LLM path router selected paths={normalized} "
                f"primary={result.get('primary_path') or normalized[0]}"
            )
            return normalized
        logger.info(
            f"[{LogOp.ROADBLOCK}] LLM path router rejected all paths for this roadblock "
            f"(reason={result.get('reason') or 'none'})"
        )
        return []

    return enabled_paths


def handle_roadblock_simplified(
    roadblock,
    tracer: CoverageTracer,
    llm_util: LLMUtil,
    *,
    selected_paths: set[str] | None = None,
    mark_attempted: bool = True,
):
    global inference_stats, attempted_roadblocks
    global fuzzer, input_dir, output_dir, fuzzing_args, target_prog, trace_prog

    try:
        check_fuzzer_alive()
    except FuzzerProcessDiedError as e:
        logger.critical(f"[{LogOp.FUZZER}] {e}")
        logger.critical("[{LogOp.FUZZER}] Fuzzer died before simplified roadblock processing, aborting...")
        raise

    roadblock_key = roadblock.get('roadblock_key') or get_roadblock_key(roadblock)
    roadblock_id = roadblock.get('roadblock_id') or get_rb_id(roadblock)
    logger.info(f"[{LogOp.ROADBLOCK}] Simplified processing roadblock {roadblock_id} (key: {roadblock_key})")
    if mark_attempted:
        mark_roadblock_attempted(roadblock_key, roadblock, stage="handle_roadblock_simplified")

    seeds = tracer.get_rb_seed(roadblock)
    rb_file = roadblock['filename']
    rb_line = roadblock['line']
    slice_line = rb_line
    if roadblock.get('group_type', None) == 'switch':
        switch_line = get_switch_statement_line(roadblock)
        if switch_line:
            slice_line = switch_line

    dynamic_context = tracer.build_dynamic_context_for_roadblock(roadblock, seed_names=seeds)

    rb_fname = None
    bcode = roadblock['code']
    for func in funcs:
        if "file_name" not in func:
            continue
        if func["file_name"].split("/")[-1] == rb_file.split("/")[-1]:
            if func['lineEnd'] >= rb_line >= func['lineStart']:
                rb_fname = func["name"]
                break
    if not rb_fname:
        logger.warning(f"[{LogOp.ROADBLOCK}] Simplified mode: no function name found for {roadblock_key}")
        return False, "NO_FUNCTION_NAME", -1, roadblock_id

    call_chains = get_call_chain(rb_fname.split('.')[0])
    using_fallback_slice = False

    if call_chains is None or len(call_chains) == 0:
        code_slice = ensure_cached_single_function_slice(
            roadblock,
            llm_util,
            dynamic_context=dynamic_context,
        )
        if not code_slice or "No matching instruction found" in code_slice or len(code_slice) <= 50:
            logger.error(f"[{LogOp.ROADBLOCK}] Simplified mode: failed to extract fallback code slice")
            return False, "CODE_SLICE_FAILED", -1, roadblock_id
        using_fallback_slice = True
        call_chains = [[rb_fname.split('.')[0]]]
    else:
        call_chains = _rank_call_chains_with_dynamic_context(
            call_chains,
            dynamic_context,
            fallback_scorer=_score_input_driven_call_chain,
        )

    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"

    for call_chain in call_chains:
        if using_fallback_slice:
            pass
        else:
            if len(call_chain) < DEPTH_THRESHOLD:
                continue
            code_slice = get_function_slice(
                call_chain,
                slice_line,
                roadblock['status'],
                llm_util,
                dynamic_context=dynamic_context,
                original_target_line=rb_line,
            )
            if "No matching instruction found" in code_slice:
                return False, "SLICE_FAILED", -1, roadblock_id

        try:
            check_fuzzer_alive()
        except FuzzerProcessDiedError as e:
            logger.critical(f"[{LogOp.FUZZER}] {e}")
            logger.critical("[{LogOp.FUZZER}] Fuzzer died before simplified constraint analysis, aborting...")
            raise

        logger.info(f"[{LogOp.ROADBLOCK}] Simplified mode: starting constraint analysis")
        res = None
        constraint_messages = build_constraints_messages(roadblock, code_slice)
        times = 0
        while times < MAX_TIME:
            resp = llm_util.get_response(constraint_messages)
            match = extract_json_with_fallback(resp, pattern_json)
            if not match:
                append_llm_retry_feedback(
                    constraint_messages,
                    resp,
                    "请只返回一个 JSON object，并完整包含 analise_branch_v2 需要的所有字段。"
                )
                times += 1
                continue
            try:
                res = json.loads(match.group(1).strip())
            except json.JSONDecodeError as exc:
                append_llm_retry_feedback(
                    constraint_messages,
                    resp,
                    f"JSON 解析失败：{exc}。请只返回一个合法的 JSON object，并完整包含 analise_branch_v2 需要的所有字段。"
                )
                times += 1
                continue
            analysis_error = validate_analysis_result_v2(res)
            if analysis_error:
                append_llm_retry_feedback(
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

        constraints = res['global_merged_constraints_in_natural_language']
        summary = res['reasoning_summary']

        logger.info("checking for flag variables at target branch")
        flagrec_result = None
        if FLAGREC_CACHE.exists():
            flagrec_result = load_cached_flagrec_results(FLAGREC_CACHE)
        if flagrec_result is None and FLAGREC_BITCODE.exists():
            try:
                flagrec_output_dir = config.get_flagrec_output_dir()
                flagrec_output_dir.mkdir(parents=True, exist_ok=True)
                flagrec_result = run_flagrec_analysis(
                    str(FLAGREC_BITCODE),
                    str(PROJECT_HOME),
                    str(flagrec_output_dir)
                )
                save_flagrec_results(flagrec_result, FLAGREC_CACHE)
            except Exception as e:
                logger.error(f"[{LogOp.ROADBLOCK}] Flagrec analysis failed: {e}", exc_info=True)

        has_flags = False
        relevant_flags = []
        constant_groups = {}
        if flagrec_result:
            has_flags, relevant_flags, constant_groups = filter_relevant_flags(flagrec_result, roadblock)

        state_hints = []
        if ENABLE_STATE_INFERENCE_PHASE_3:
            try:
                state_inference = StateMachineInference(llm_util)
                target_branch_str = f"{rb_file.split('/')[-1]}:{rb_line}: {bcode}"
                state_hints = state_inference.get_state_hints_with_multi_stage(
                    code_slice, target_branch_str, PROJECT, call_chain
                )
            except Exception:
                state_hints = []
        if not state_hints and ENABLE_STATE_INFERENCE_PHASE_2:
            try:
                state_inference = StateMachineInference(llm_util)
                target_branch_str = f"{rb_file.split('/')[-1]}:{rb_line}: {bcode}"
                state_hints = state_inference.get_state_hints_for_prompt(code_slice, target_branch_str, PROJECT)
            except Exception:
                state_hints = []
        if not state_hints:
            state_hints = get_state_hints(roadblock, code_slice, PROJECT)

        ranked_seed_names = tracer.select_seed_names_for_roadblock(
            roadblock,
            seed_names=seeds,
            max_seeds=max(1, min(8, len(seeds))),
        )
        seed = ranked_seed_names[0] if ranked_seed_names else None
        relevant_info = None
        orig = None
        fields = None
        if ranked_seed_names:
            enable_semantic = PROJECT in ENABLE_FIELD_PARSING or has_semantic_field_provider(PROJECT)
            for candidate_seed in ranked_seed_names:
                seed = candidate_seed
                relevant_info, orig, fields = process_relevant_fields_for_simplified_path(
                    seed,
                    roadblock_id=roadblock_id,
                    rb_file=rb_file,
                    rb_line=rb_line,
                    enable_semantic_parsing=enable_semantic,
                )
                if orig is not None:
                    break

        harness_for_mode = get_harness_code()
        generation_mode = "text_direct" if _looks_textual_semantic_input(
            fields=fields,
            harness_code=harness_for_mode,
        ) else "binary_script"
        target_class = classify_input_target(fields=fields, harness_code=harness_for_mode)
        attempt_ctx = SimplifiedAttemptContext(
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
            orig=orig,
            fields=fields,
            relevant_info=relevant_info,
            harness_for_mode=harness_for_mode,
            state_hints=state_hints,
            generation_mode=generation_mode,
        )

        if target_class == "structured_text_parser":
            path_attempts = [
                ("xml_grammar", ENABLE_SIMPLIFIED_XML_GRAMMAR_PATH, lambda: attempt_simplified_xml_grammar_path(attempt_ctx)),
                ("field_mutation", ENABLE_SIMPLIFIED_FIELD_MUTATION_PATH, lambda: attempt_simplified_field_mutation_path(attempt_ctx, pattern_json)),
                ("direct_generation", ENABLE_SIMPLIFIED_DIRECT_GENERATION_PATH, lambda: run_direct_generation(attempt_ctx, log_prefix="Simplified Path C")),
                ("batch_mutation", ENABLE_SIMPLIFIED_BATCH_MUTATION_PATH, lambda: attempt_simplified_batch_mutation_path(attempt_ctx)),
                ("taint_mutation", ENABLE_SIMPLIFIED_TAINT_MUTATION_PATH, lambda: attempt_simplified_taint_mutation_path(attempt_ctx, pattern_json)),
            ]
        else:
            path_attempts = [
                ("flag", ENABLE_SIMPLIFIED_FLAG_PATH, lambda: attempt_simplified_flag_path(attempt_ctx, relevant_flags, constant_groups)),
                ("taint_mutation", ENABLE_SIMPLIFIED_TAINT_MUTATION_PATH, lambda: attempt_simplified_taint_mutation_path(attempt_ctx, pattern_json)),
                ("state_driven", ENABLE_SIMPLIFIED_STATE_DRIVEN_PATH and ENABLE_STATE_DRIVEN_PATH_B, lambda: attempt_simplified_state_driven_path(attempt_ctx)),
                ("field_mutation", ENABLE_SIMPLIFIED_FIELD_MUTATION_PATH, lambda: attempt_simplified_field_mutation_path(attempt_ctx, pattern_json)),
                ("xml_grammar", ENABLE_SIMPLIFIED_XML_GRAMMAR_PATH, lambda: attempt_simplified_xml_grammar_path(attempt_ctx)),
                ("batch_mutation", ENABLE_SIMPLIFIED_BATCH_MUTATION_PATH, lambda: attempt_simplified_batch_mutation_path(attempt_ctx)),
                ("direct_generation", ENABLE_SIMPLIFIED_DIRECT_GENERATION_PATH, lambda: run_direct_generation(attempt_ctx, log_prefix="Simplified Path C")),
            ]

        if selected_paths is None:
            enabled_path_names = [path_name for path_name, enabled, _ in path_attempts if enabled]
            planned_paths = plan_simplified_path_selection(
                llm_util=llm_util,
                roadblock=roadblock,
                code_slice=code_slice,
                constraints=constraints,
                summary=summary,
                target_class=target_class,
                generation_mode=generation_mode,
                available_paths=[path_name for path_name, _, _ in path_attempts],
                enabled_paths=enabled_path_names,
                seed_available=seed is not None,
                has_fields=fields is not None,
                has_taint_ranges=bool(relevant_info and relevant_info.get('ranges')),
                has_state_hints=bool(state_hints),
                has_relevant_flags=bool(relevant_flags),
            )
            if not planned_paths:
                logger.info(f"[{LogOp.ROADBLOCK}] LLM path router decided no simplified path is worth trying")
                return False, "LLM_ROUTER_REJECTED_ALL_PATHS", -1, roadblock_id
            path_attempts = _filter_and_reorder_path_attempts_by_names(path_attempts, planned_paths)

        attempt_made = False
        for path_name, enabled, path_runner in path_attempts:
            if selected_paths is not None and path_name not in selected_paths:
                continue
            if not enabled:
                logger.info(f"[{LogOp.ROADBLOCK}] Simplified path `{path_name}` disabled by config")
                continue
            path_attempted = path_runner()
            if path_attempted:
                logger.info(f"[{LogOp.ROADBLOCK}] Simplified path `{path_name}` produced candidate output")
            else:
                logger.info(f"[{LogOp.ROADBLOCK}] Simplified path `{path_name}` produced no candidate output")
            attempt_made = attempt_made or path_attempted

        return attempt_made, "ATTEMPTED_ALL_PATHS", -1, roadblock_id

    return False, "NO_ROADBLOCKS_REMAIN", -1, roadblock_id


def handle_roadblock_direct_generation_only(roadblock, tracer: CoverageTracer, llm_util: LLMUtil):
    global attempted_roadblocks

    try:
        check_fuzzer_alive()
    except FuzzerProcessDiedError as e:
        logger.critical(f"[{LogOp.FUZZER}] {e}")
        logger.critical("[{LogOp.FUZZER}] Fuzzer died before direct-generation-only roadblock processing, aborting...")
        raise

    roadblock_key = roadblock.get('roadblock_key') or get_roadblock_key(roadblock)
    roadblock_id = roadblock.get('roadblock_id') or get_rb_id(roadblock)
    if roadblock_key in attempted_roadblocks:
        logger.info(f"[{LogOp.ROADBLOCK}] Direct-generation scheduler skipping attempted roadblock: {roadblock_key}")
        return False, "ALREADY_ATTEMPTED", -1, roadblock_id

    logger.info(f"[{LogOp.ROADBLOCK}] Direct-generation scheduler processing {roadblock_id} (key: {roadblock_key})")
    mark_roadblock_attempted(roadblock_key, roadblock, stage="handle_roadblock_direct_generation_only")

    seeds = tracer.get_rb_seed(roadblock)
    rb_file = roadblock['filename']
    rb_line = roadblock['line']
    slice_line = rb_line
    if roadblock.get('group_type', None) == 'switch':
        switch_line = get_switch_statement_line(roadblock)
        if switch_line:
            slice_line = switch_line

    rb_fname = roadblock.get('function') or ""
    if not rb_fname:
        func_meta = tracer._find_function_for_location(rb_file, rb_line)
        if func_meta and func_meta.get('name'):
            rb_fname = str(func_meta.get('name'))
    if not rb_fname:
        mark_roadblock_failed(roadblock_key, "NO_FUNCTION_NAME", roadblock)
        return False, "NO_FUNCTION_NAME", -1, roadblock_id

    call_chains = get_call_chain(rb_fname.split('.')[0])
    using_fallback_slice = False
    if call_chains is None or len(call_chains) == 0:
        code_slice = ensure_cached_single_function_slice(roadblock, llm_util)
        if not code_slice or "No matching instruction found" in code_slice or len(code_slice) <= 50:
            mark_roadblock_failed(roadblock_key, "CODE_SLICE_FAILED", roadblock)
            return False, "CODE_SLICE_FAILED", -1, roadblock_id
        using_fallback_slice = True
        call_chains = [[rb_fname.split('.')[0]]]
    else:
        call_chains = sorted(call_chains, key=_score_input_driven_call_chain, reverse=True)

    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"
    bcode = roadblock['code']

    for call_chain in call_chains:
        if not using_fallback_slice:
            if len(call_chain) < DEPTH_THRESHOLD:
                continue
            code_slice = get_function_slice(
                call_chain,
                slice_line,
                roadblock['status'],
                llm_util,
                original_target_line=rb_line,
                target_file=roadblock.get('filename'),
            )
            if "No matching instruction found" in code_slice:
                mark_roadblock_failed(roadblock_key, "SLICE_FAILED", roadblock)
                return False, "SLICE_FAILED", -1, roadblock_id

        constraint_messages = build_constraints_messages(roadblock, code_slice)
        res = None
        retries = 0
        while retries < MAX_TIME:
            resp = llm_util.get_response(constraint_messages)
            match = extract_json_with_fallback(resp, pattern_json)
            if not match:
                append_llm_retry_feedback(
                    constraint_messages,
                    resp,
                    "请只返回一个 JSON object，并完整包含 analise_branch_v2 需要的所有字段。",
                )
                retries += 1
                continue
            try:
                res = json.loads(match.group(1).strip())
            except json.JSONDecodeError as exc:
                append_llm_retry_feedback(
                    constraint_messages,
                    resp,
                    f"JSON 解析失败：{exc}。请只返回一个合法的 JSON object，并完整包含 analise_branch_v2 需要的所有字段。",
                )
                retries += 1
                continue
            analysis_error = validate_analysis_result_v2(res)
            if analysis_error:
                append_llm_retry_feedback(
                    constraint_messages,
                    resp,
                    f"返回结构不符合要求：{analysis_error}。请只返回一个 JSON object，并完整包含 analise_branch_v2 需要的所有字段。",
                )
                res = None
                retries += 1
                continue
            break

        if res is None:
            mark_roadblock_failed(roadblock_key, "CONSTRAINT_ANALYSIS_FAILED", roadblock)
            return False, "CONSTRAINT_ANALYSIS_FAILED", -1, roadblock_id

        constraints = res["global_merged_constraints_in_natural_language"]
        summary = res["reasoning_summary"]
        ranked_seed_names = tracer.select_seed_names_for_roadblock(
            roadblock,
            seed_names=seeds,
            max_seeds=max(1, min(8, len(seeds))),
        )
        seed = ranked_seed_names[0] if ranked_seed_names else None
        harness_for_mode = get_harness_code()
        generation_mode = "text_direct" if _looks_textual_semantic_input(
            fields=None,
            harness_code=harness_for_mode,
        ) else "binary_script"

        attempt_ctx = SimplifiedAttemptContext(
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

        path_attempted = run_direct_generation(attempt_ctx, log_prefix="Direct-generation scheduler")
        if path_attempted:
            logger.info(f"[{LogOp.ROADBLOCK}] Direct-generation scheduler produced candidate output")
            return True, "ATTEMPTED_DIRECT_GENERATION_ONLY", -1, roadblock_id

    mark_roadblock_failed(roadblock_key, "DIRECT_GENERATION_FAILED", roadblock)
    return False, "DIRECT_GENERATION_FAILED", -1, roadblock_id


def resolve_coverage_stuck(orchestrator: PlateauAttemptOrchestrator, tracer: CoverageTracer, last_scan_time, read_files, stuck_time):
    global cached_format_info
    cached_format_info = ensure_cached_format_info(orchestrator.llm_util)
    return orchestrator.run_cycle(last_scan_time, read_files, stuck_time)


class FuzzerProcessDiedError(Exception):
    """Exception raised when the fuzzer process is no longer running."""
    pass


def check_fuzzer_alive():
    """
    Check if the fuzzer process is still alive.
    Uses FuzzerRunner's check_alive() method to determine status.
    Raises FuzzerProcessDiedError if the fuzzer is not running.
    Skips check when config.test is True (test mode).
    """
    # Skip fuzzer process check in test mode.
    # Use config.test instead of the imported module-level `test` snapshot,
    # so runner_bootstrap(test_mode=True) is honored consistently.
    if config.test:
        return

    if fuzzer is None:
        raise FuzzerProcessDiedError("Fuzzer not initialized")

    if not fuzzer.check_alive():
        if fuzzer.is_alive_from_stats():
            # Fuzzer was started externally and is still alive
            return

        logger.error(f"[{LogOp.FUZZER}] Fuzzer process is no longer alive")
        raise FuzzerProcessDiedError("Fuzzer process died")


def parse_exec_args(exec_args_value: str) -> list[str]:
    """Parse EXEC_ARGS into argv tokens."""
    if not exec_args_value:
        return []
    return shlex.split(exec_args_value)


def read_cmdline_file() -> list[str]:
    """Read command line args from xxx/out_x/default/cmdline file.

    The file format:
    - First line: target program (ignored, we use AFL_TARGET_PATH from config)
    - Remaining lines: command line arguments

    Returns:
        list of command line args, empty if file doesn't exist or on error
    """
    cmdline_path = PROJECT_HOME / OUTPUT_DIR_NAME / "default" / "cmdline"

    if not cmdline_path.exists():
        return []

    try:
        with open(cmdline_path, "r") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]

        if not lines:
            return []

        # Skip first line (target program), return the rest as args
        args = lines[1:] if len(lines) > 1 else []
        return args
    except Exception as e:
        logger.warning(f"Failed to read cmdline file {cmdline_path}: {e}")
        return []


# 全局变量用于信号处理
_shutdown_requested = False


def cleanup_child_processes():
    """清理所有相关的子进程"""
    # 查找并清理所有相关的子进程
    # 包括: calc.autotrace 以及 autobug 相关的进程
    try:
        # 使用pgrep查找相关进程
        result = subprocess.run(
            ["pgrep", "-f", "calc.autotrace|autobug"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            pids = result.stdout.strip().split('\n')
            pids = [int(pid) for pid in pids if pid]
            cleaned = 0
            for pid in pids:
                try:
                    # 检查是否是我们进程的子进程
                    pgrp = os.getpgid(pid)
                    current_pgrp = os.getpgrp()
                    if pgrp == current_pgrp or True:  # 清理所有相关进程
                        try:
                            pgid = os.getpgid(pid)
                            os.killpg(pgid, signal.SIGTERM)
                            cleaned += 1
                        except (ProcessLookupError, OSError):
                            try:
                                os.kill(pid, signal.SIGTERM)
                                cleaned += 1
                            except (ProcessLookupError, OSError):
                                pass
                except (ProcessLookupError, OSError):
                    pass
            if cleaned > 0:
                logger.info(f"Cleaned up {cleaned} child process(es)")
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        # pgrep不可用或超时，使用ps命令
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                cleaned = 0
                for line in result.stdout.split('\n'):
                    if 'calc.autotrace' in line or 'autobug' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                pid = int(parts[1])
                                os.kill(pid, signal.SIGTERM)
                                cleaned += 1
                            except (ValueError, ProcessLookupError, OSError):
                                pass
                if cleaned > 0:
                    logger.info(f"Cleaned up {cleaned} child process(es)")
        except (subprocess.TimeoutExpired, ValueError):
            logger.debug("Could not cleanup child processes via ps command")


def signal_handler(signum, frame):
    """处理SIGINT和SIGTERM信号，确保清理所有子进程"""
    global _shutdown_requested
    if _shutdown_requested:
        # 如果已经请求过关闭，直接退出
        logger.critical("Force exit after repeated interrupt signal")
        sys.exit(1)

    _shutdown_requested = True
    logger.warning("=" * 60)
    logger.warning(f"Received signal {signum}, initiating graceful shutdown...")
    logger.warning("=" * 60)

    # 清理所有相关的子进程
    cleanup_child_processes()


def main():
    global fuzzer, input_dir, output_dir, fuzzing_args, target_prog, trace_prog

    # 注册信号处理器，确保KeyboardInterrupt时正确清理子进程
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    logger.info("Signal handlers registered for SIGINT and SIGTERM")

    read_files = set()
    last_scan_time = 0
    input_dir = os.fspath(INPUT_PATH)
    output_dir = os.fspath(OUTPUT_PATH)

    # Try to read args from cmdline file first
    cmdline_args = read_cmdline_file()
    if cmdline_args:
        fuzzing_args = cmdline_args
    else:
        # Fall back to config EXEC_ARGS
        fuzzing_args = parse_exec_args(EXEC_ARGS)

    # Target program always from config
    target_prog = AFL_TARGET_PATH
    trace_prog = TRACE_TARGET_PATH

    # Initialize configuration logging
    logger.info("=" * 60)
    logger.info("AUTOFUZZER SESSION INITIALIZATION")
    logger.info("=" * 60)
    logger.info(f"LLM model: {MODEL}")
    logger.info(f"Input directory: {input_dir}")
    logger.info(f"Output directory: {output_dir}")
    logger.info(f"Fuzzing arguments: {' '.join(fuzzing_args)}")
    logger.info(f"Target program: {target_prog}")
    logger.info(f"Trace program: {trace_prog}")
    logger.info(f"Coverage threshold: {THRESHOLD_TIME}s stagnation")
    logger.info(f"Coverage delta threshold: {THRESHOLD_COV_DELTA} edges")
    init_attempted_roadblock_store()

    fuzzer = FuzzerRunner(input_dir, output_dir, target_prog, fuzzing_args)

    # Load and cache fuzzer PID from fuzzer_stats
    fuzzer_pid = fuzzer.load_fuzzer_pid()
    if fuzzer_pid is not None:
        logger.info(f"[{LogOp.FUZZER}] Fuzzer PID (from fuzzer_stats): {fuzzer_pid}")
    else:
        logger.warning(f"[{LogOp.FUZZER}] Could not read fuzzer PID from fuzzer_stats")
    logger.info("=" * 60)

    time.sleep(1)
    try:
        tracer = CoverageTracer(
            input_dir,
            output_dir,
            fuzzing_args,
            target_prog,
            trace_prog,
            bbs,
            funcs,
            input_adapter_spec=get_input_adapter_spec(),
        )
        llm_util = LLMUtil(MODEL, API_KEY, BASE_URL)
        cached_format_info = ensure_cached_format_info(llm_util)
        orchestrator = PlateauAttemptOrchestrator(tracer, llm_util)
        logger.info(
            f"[{LogOp.ROADBLOCK}] Coverage monitor is active; trace extraction starts on plateau, "
            f"while AutoBug branch-cache priming may continue asynchronously in the background"
        )
        iteration_count = 0
        stop_event = threading.Event()

        # Thread 1: seed_monitor — continuous get-branch collection (like hyllfuzz)
        def seed_monitor_loop():
            while not stop_event.is_set():
                try:
                    check_fuzzer_alive()
                except FuzzerProcessDiedError as e:
                    logger.critical(f"[{LogOp.FUZZER}] seed_monitor: {e}")
                    stop_event.set()
                    return
                try:
                    tracer.poll_autobug_seed_queue()
                    tracer.kick_autobug_prime_async()
                except Exception as exc:
                    logger.warning(f"[{LogOp.ROADBLOCK}] seed_monitor error: {exc}", exc_info=True)
                stop_event.wait(AUTOBUG_SCAN_INTERVAL)

        seed_monitor = threading.Thread(target=seed_monitor_loop, name="seed_monitor", daemon=True)
        seed_monitor.start()
        logger.info(f"[{LogOp.ROADBLOCK}] seed_monitor thread started (interval={AUTOBUG_SCAN_INTERVAL}s)")

        # Thread 2: plateau_monitor — stuck detection + path attempts (like hyllfuzz)
        try:
            while not stop_event.is_set():
                try:
                    check_fuzzer_alive()
                except FuzzerProcessDiedError as e:
                    logger.critical(f"[{LogOp.FUZZER}] {e}")
                    logger.critical("[{LogOp.FUZZER}] Fuzzer died, initiating graceful shutdown...")
                    break

                stuck_time = tracer.check_coverage_growth()
                epoch_active = orchestrator.has_active_epoch()
                if not epoch_active and stuck_time < THRESHOLD_TIME:
                    logger.info(
                        f"[{LogOp.ROADBLOCK}] Coverage monitor waiting for plateau "
                        f"(stuck_time={stuck_time:.1f}s, threshold={THRESHOLD_TIME}s)"
                    )
                    stop_event.wait(CHECK_INTERVAL)
                    continue
                if epoch_active and stuck_time < THRESHOLD_TIME:
                    logger.info(
                        f"[{LogOp.ROADBLOCK}] Continuing active plateau epoch despite recent coverage growth "
                        f"(stuck_time={stuck_time:.1f}s < {THRESHOLD_TIME}s)"
                    )

                removed_count = update_pass_roadblock()
                if removed_count > 0:
                    logger.info(
                        f"[{LogOp.ROADBLOCK}] Main loop: Iterative update removed {removed_count} expired roadblock(s)")

                success, last_scan_time, read_files = resolve_coverage_stuck(
                    orchestrator, tracer, last_scan_time, read_files, stuck_time
                )
                iteration_count += 1
                logger.info(f"[{LogOp.ROADBLOCK}] Main loop iteration {iteration_count} completed")
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt detected (Ctrl+C)")
            logger.info("Initiating graceful shutdown...")
        except Exception as e:
            logger.critical(f"Unexpected error in main loop: {str(e)}", exc_info=True)
            logger.critical("Attempting graceful shutdown...")
        finally:
            stop_event.set()
            seed_monitor.join(timeout=5)
    finally:
        if "tracer" in locals():
            tracer.shutdown_background_workers(wait=False)
        logger.info("Saving coverage state to static.json")
        with open(STATIC_PATH / "static.json", 'w') as f:
            ujson.dump({"basic_blocks": bbs, "functions": funcs}, f)

        # Log inference statistics
        logger.info("=" * 60)
        logger.info("INFERENCE STATISTICS")
        logger.info("=" * 60)
        logger.info(f"Indirect inference attempts: {inference_stats['indirect_attempts']}")
        logger.info(f"Indirect inference successes: {inference_stats['indirect_successes']}")
        if inference_stats['indirect_attempts'] > 0:
            success_rate = inference_stats['indirect_successes'] / inference_stats['indirect_attempts'] * 100
            logger.info(f"Indirect inference success rate: {success_rate:.1f}%")
        logger.info("=" * 60)

        logger.info("Session terminated")


logger = logging.getLogger(LOGGER_NAME + __name__)
fuzzer = None
input_dir = None
output_dir = None
fuzzing_args = None
target_prog = None
trace_prog = None

if __name__ == '__main__':
    argv = sys.argv[1:]
    exec_args_override = None
    if "--" in argv:
        separator_index = argv.index("--")
        cli_argv = argv[:separator_index]
        exec_args_override = argv[separator_index + 1:]
    else:
        cli_argv = argv

    # 命令行参数解析
    parser = argparse.ArgumentParser(description="AutoFrame Fuzzing")
    parser.add_argument("project", nargs="?", default=None,
                        help="要运行的project名称 (默认使用config.py中的PROJECT)")
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

    # 设置 config.test: 有 --test 时为 True，否则为 False
    import config

    config.test = args.test
    if exec_args_override is not None:
        config.EXEC_ARGS = shlex.join(exec_args_override)
    elif args.exec_args is not None:
        config.EXEC_ARGS = args.exec_args

    global EXEC_ARGS
    EXEC_ARGS = config.EXEC_ARGS

    # 统一复用 config.py 中计算好的阈值，避免出现双份配置漂移。
    global THRESHOLD_TIME, THRESHOLD_COV_DELTA
    THRESHOLD_TIME = config.THRESHOLD_TIME
    THRESHOLD_COV_DELTA = config.THRESHOLD_COV_DELTA

    # 如果指定了project或输出目录，更新config并重新导入变量
    if args.project or args.output_dir != "out":
        from config import set_project, PROJECT as DEFAULT_PROJECT

        project_name = args.project if args.project else DEFAULT_PROJECT
        set_project(project_name, args.output_dir)

        # 直接从 config 模块重新导入更新后的变量（不使用 reload）
        import config

        # 更新当前模块的全局变量
        PROJECT = config.PROJECT
        OUTPUT_DIR_NAME = config.OUTPUT_DIR_NAME
        PROJECT_HOME = config.PROJECT_HOME
        STATIC_PATH = config.STATIC_PATH
        PLOT_PATH = config.PLOT_PATH
        SEED_PATH = config.SEED_PATH
        INPUT_PATH = config.INPUT_PATH
        OUTPUT_PATH = config.OUTPUT_PATH
        LLM_QUEUE_PATH = config.LLM_QUEUE_PATH
        MUT_QUEUE_PATH = config.MUT_QUEUE_PATH
        SYMBOLIC_QUEUE_PATH = config.SYMBOLIC_QUEUE_PATH
        AFL_TARGET_PATH = config.AFL_TARGET_PATH
        TRACE_TARGET_PATH = config.TRACE_TARGET_PATH
        SRC_PATH = config.SRC_PATH
        SRC_BEAR_PATH = config.SRC_BEAR_PATH
        TSEED_ISI_PATH = config.TSEED_ISI_PATH
        TSEED_ISI_JSON_PATH = config.TSEED_ISI_JSON_PATH
        RESULT_JSON_PATH = config.RESULT_JSON_PATH
        RELEVANT_FIELD_JSON_PATH = config.RELEVANT_FIELD_JSON_PATH
        BATCH_MUTATE_SCRIPT_PATH = config.BATCH_MUTATE_SCRIPT_PATH
        MUT_TMP_PATH = config.MUT_TMP_PATH
        LLM_TMP_PATH = config.LLM_TMP_PATH
        # 需要使用 global 声明来更新模块级别的 bbs, funcs 和项目特定路径变量
        global bbs, funcs, bcfile_path, slice_out, IPL_TARGET_PATH, FLAGREC_BITCODE, FLAGREC_CACHE
        bbs = config.bbs
        funcs = config.funcs
        bcfile_path = config.bcfile_path
        slice_out = config.slice_out
        IPL_TARGET_PATH = config.IPL_TARGET_PATH
        FLAGREC_BITCODE = config.FLAGREC_BITCODE
        FLAGREC_CACHE = config.FLAGREC_CACHE

    config.ensure_runtime_layout()
    _logger_initialized = False
    setup_logger()

    # Suppress verbose logs from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    main()
