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
import subprocess
import sys
import tempfile
import time

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from re import Match
from typing import Any, Optional, Dict

from CoverageTracer import (
    CoverageTracer,
    _rank_call_chains_with_dynamic_context,
    analyze_low_value_guard_roadblock,
    format_call_chain,
    get_call_chain,
    get_function_slice,
    get_harness_code,
)
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
import config
from config import *
from find_seed_root import find_seed_root


# Flag to track if logger has been initialized
_logger_initialized = False
NO_COVERAGE_GUIDED_RETRY_LIMIT = 1
LLVM_PROFDATA_BIN = os.fspath(Path(config.LLVM_PROFDATA_BIN))
LLVM_COV_BIN = os.fspath(Path(config.LLVM_COV_BIN))
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

    handler = logging.FileHandler(Path(config.LOG_PATH) / config.LOGGER_FILE_NAME)
    handler.setLevel(LOGGING_LEVEL)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(LOGGING_LEVEL)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


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
    llm_file_handler = logging.FileHandler(Path(config.LLM_LOG_PATH) / config.LLM_LOG_FILE_NAME)
    llm_file_handler.setLevel(LOGGING_LEVEL)
    llm_file_handler.setFormatter(formatter)
    llm_logger.addHandler(llm_file_handler)

    # Console handler for LLM logs (optional, can be disabled)
    llm_console_handler = logging.StreamHandler()
    llm_console_handler.setLevel(LOGGING_LEVEL)
    llm_console_handler.setFormatter(formatter)
    llm_logger.addHandler(llm_console_handler)

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


def _log_full_prompt_messages(tag: str, messages: list[dict[str, str]]):
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


def validate_generation_result(result: Any) -> Optional[str]:
    if not isinstance(result, dict):
        return f"generation result must be a JSON object, got {type(result).__name__}"
    if 'generation_script' not in result:
        return "missing required key: generation_script"
    if not isinstance(result.get('generation_script'), str):
        return "generation_script must be a string"
    return None


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


def map_decision_reason_to_failure(reason: str) -> str:
    mapping = {
        'constraint_conflict': 'CONSTRAINTS_CONFLICT',
        'non_input_dominated': 'NON_INPUT_DOMINATED',
        'low_value_bottleneck': 'LOW_VALUE_BOTTLENECK',
        'insufficient_evidence': 'ROADBLOCK_INSUFFICIENT_INFO',
    }
    return mapping.get(reason, 'ROADBLOCK_DECISION_REJECTED')


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


def estimate_afl_import_score(seed_path: str) -> dict[str, Any]:
    seed_data = _read_seed_prefix_bytes(seed_path)
    if not seed_data:
        return {
            "score": 0.0,
            "closest_seed": None,
            "closest_similarity": 1.0,
            "byte_similarity": 1.0,
            "text_similarity": 1.0,
        }

    candidate_realpath = os.path.realpath(seed_path)
    seed_bytes = _byte_ngram_set(seed_data)
    seed_tokens = _text_token_set(seed_data)
    best_similarity = 0.0
    best_byte_similarity = 0.0
    best_text_similarity = 0.0
    best_name: str | None = None

    for corpus_path in _recent_default_queue_paths():
        if os.path.realpath(os.fspath(corpus_path)) == candidate_realpath:
            continue
        corpus_data = _read_seed_prefix_bytes(os.fspath(corpus_path))
        if not corpus_data:
            continue
        byte_similarity = _jaccard_similarity(seed_bytes, _byte_ngram_set(corpus_data))
        text_similarity = _jaccard_similarity(seed_tokens, _text_token_set(corpus_data))
        similarity = max(byte_similarity, text_similarity)
        if similarity > best_similarity:
            best_similarity = similarity
            best_byte_similarity = byte_similarity
            best_text_similarity = text_similarity
            best_name = corpus_path.name

    score = max(0.0, min(1.0, 1.0 - best_similarity))
    return {
        "score": round(score, 4),
        "closest_seed": best_name,
        "closest_similarity": round(best_similarity, 4),
        "byte_similarity": round(best_byte_similarity, 4),
        "text_similarity": round(best_text_similarity, 4),
    }


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


def detect_non_input_blocker_dependency(
    non_input_constraints: list | None,
    breakthrough_assessment: dict | None,
) -> tuple[bool, list[str]]:
    """
    Detect roadblocks whose main blocker is outside the fuzzable input space.

    Exception: if the blocker is program state but the state is explicitly described as
    input-driven / reachable by crafted input, keep the roadblock.
    """
    assessment = breakthrough_assessment or {}
    if assessment.get("can_be_broken_by_input_alone") is True:
        return False, []

    text_fragments = _collect_text_fragments(non_input_constraints) + _collect_text_fragments(assessment)
    text_blob = "\n".join(text_fragments).lower()
    matched_groups: list[str] = []

    fixed_runtime_only, fixed_runtime_groups = detect_fixed_runtime_config_dependency(non_input_constraints, assessment)
    if fixed_runtime_only:
        matched_groups.extend(fixed_runtime_groups)

    primary_blocker_type = str(assessment.get("primary_blocker_type") or "").strip().lower()
    if primary_blocker_type in {"environment", "resource", "external_dependency", "call_order", "unknown"}:
        matched_groups.append(f"primary_blocker_type:{primary_blocker_type}")
    elif primary_blocker_type == "program_state" and not _has_input_driven_state_signal(text_blob):
        matched_groups.append("primary_blocker_type:program_state_non_input_driven")

    recommended_action = str(assessment.get("recommended_action") or "").strip().lower()
    if recommended_action in {"change_target", "defer_roadblock"} and not matched_groups:
        matched_groups.append(f"recommended_action:{recommended_action}")

    return bool(matched_groups), matched_groups


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


def build_fixed_runtime_rejection_decision(matched_groups: list[str]) -> dict[str, Any]:
    return build_non_input_rejection_decision(matched_groups)


def build_pre_judge_bypass_decision() -> dict[str, Any]:
    return {
        "decision": "proceed",
        "reason": "pre_judge_disabled",
        "should_generate_input": True,
        "should_try_state_guided_workflow": False,
        "should_deprioritize_roadblock": False,
        "summary": (
            "The v2 pre-judgment switch is disabled in config, so this roadblock bypasses "
            "judge_conflict_v2 and proceeds with the default downstream exploration flow."
        ),
        "input_drivenness_score": 0.7,
        "state_dependency_score": 0.45,
        "evidence_sufficiency_score": 0.5,
        "expected_depth_score": 0.5,
        "value_of_breaking_score": 0.7,
        "recommended_next_steps": ["prefer_input_mutation", "allow_direct_generation"],
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


def normalize_decision_result_v2(result: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(result)
    normalized['input_drivenness_score'] = _clamp_score(result.get('input_drivenness_score'), 0.5)
    normalized['state_dependency_score'] = _clamp_score(result.get('state_dependency_score'), 0.5)
    normalized['evidence_sufficiency_score'] = _clamp_score(result.get('evidence_sufficiency_score'), 0.4)
    normalized['expected_depth_score'] = _clamp_score(result.get('expected_depth_score'), 0.5)
    normalized['value_of_breaking_score'] = _clamp_score(result.get('value_of_breaking_score'), 0.5)
    if not isinstance(normalized.get('recommended_next_steps'), list):
        normalized['recommended_next_steps'] = []
    return normalized


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


def ensure_cached_single_function_slice(
    roadblock: dict[str, Any],
    llm_util: LLMUtil,
    *,
    dynamic_context: Optional[dict[str, Any]] = None,
) -> str | None:
    cached_slice = roadblock.get('cached_single_function_slice')
    if cached_slice and isinstance(cached_slice, str):
        return cached_slice

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
    )
    if not code_slice or "No matching instruction found" in code_slice or len(code_slice) <= 50:
        return None

    roadblock['cached_single_function_slice'] = code_slice
    roadblock['cached_single_function_call_chain'] = fallback_chain
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


def merge_breakthrough_probe_with_conflict_decision(
    decision_result: dict[str, Any],
    slice_probe_result: dict[str, Any] | None,
) -> dict[str, Any]:
    if not slice_probe_result or not slice_probe_result.get('available'):
        return relax_conflict_gate_decision(decision_result)

    normalized = dict(decision_result)
    recommended_steps = list(normalized.get('recommended_next_steps') or [])
    probe_positive = bool(slice_probe_result.get('should_continue'))
    assessment_summary = slice_probe_result.get('assessment_summary') or {}
    probe_reason = (
        slice_probe_result.get('reasoning_summary')
        or assessment_summary.get('recommended_action')
        or 'slice_probe'
    )

    if probe_positive:
        normalized = relax_conflict_gate_decision(normalized)
        normalized['value_of_breaking_score'] = max(
            _clamp_score(normalized.get('value_of_breaking_score'), 0.5),
            float(assessment_summary.get('confidence', slice_probe_result.get('confidence', 0.55)) or 0.55),
        )
        if 'allow_direct_generation' not in recommended_steps:
            recommended_steps.append('allow_direct_generation')
        if assessment_summary.get('can_be_broken_by_input_alone') and 'prefer_input_mutation' not in recommended_steps:
            recommended_steps.append('prefer_input_mutation')
        elif 'prefer_state_guided' not in recommended_steps:
            recommended_steps.append('prefer_state_guided')
        normalized['summary'] = (
            f"{normalized.get('summary', '')}\n"
            f"Single-function slice probe indicates the roadblock is still worth trying: {probe_reason}"
        ).strip()
    elif str(normalized.get('reason') or '') != 'constraint_conflict':
        normalized['decision'] = 'reject'
        normalized['reason'] = 'slice_probe_low_opportunity'
        normalized['should_generate_input'] = False
        normalized['should_try_state_guided_workflow'] = False
        normalized['should_deprioritize_roadblock'] = True
        normalized['input_drivenness_score'] = 0.2
        normalized['state_dependency_score'] = 0.2
        normalized['value_of_breaking_score'] = 0.2
        normalized['summary'] = (
            "Single-function slice probe indicates this roadblock has low breakthrough value "
            f"or weak opportunity under the current workflow: {probe_reason}"
        )
        recommended_steps = ['deprioritize_roadblock']

    normalized['recommended_next_steps'] = recommended_steps
    return normalized


def derive_route_preferences(decision_result: dict[str, Any]) -> dict[str, bool | float]:
    input_score = _clamp_score(decision_result.get('input_drivenness_score'), 0.5)
    state_score = _clamp_score(decision_result.get('state_dependency_score'), 0.5)
    evidence_score = _clamp_score(decision_result.get('evidence_sufficiency_score'), 0.4)
    depth_score = _clamp_score(decision_result.get('expected_depth_score'), 0.5)
    value_score = _clamp_score(decision_result.get('value_of_breaking_score'), 0.5)
    decision = str(decision_result.get('decision') or '')

    return {
        'input_score': input_score,
        'state_score': state_score,
        'evidence_score': evidence_score,
        'depth_score': depth_score,
        'value_score': value_score,
        'prefer_input_mutation': input_score >= 0.55 and evidence_score >= 0.35,
        'prefer_state_guided': state_score >= 0.55 or bool(decision_result.get('should_try_state_guided_workflow')),
        'prefer_batch_mutation': input_score >= 0.35 and depth_score >= 0.55 and evidence_score >= 0.35,
        'allow_direct_generation': value_score >= 0.45 and (input_score >= 0.3 or evidence_score < 0.5),
        'hard_reject': decision == 'reject' and value_score < 0.35,
        'defer_for_more_evidence': decision == 'need_more_information' and value_score >= 0.4,
        'recommended_steps': list(decision_result.get('recommended_next_steps') or []),
        'collect_more_evidence': False,
    }


def apply_recommended_next_steps(decision_result: dict[str, Any], route_preferences: dict[str, Any]) -> dict[str, Any]:
    updated = dict(route_preferences)
    steps = list(decision_result.get('recommended_next_steps') or [])
    updated['recommended_steps'] = steps
    for step in steps:
        if step == 'prefer_input_mutation':
            updated['prefer_input_mutation'] = True
            updated['input_score'] = max(updated['input_score'], 0.6)
        elif step == 'prefer_state_guided':
            updated['prefer_state_guided'] = True
            updated['state_score'] = max(updated['state_score'], 0.6)
        elif step == 'prefer_batch_mutation':
            updated['prefer_batch_mutation'] = True
            updated['depth_score'] = max(updated['depth_score'], 0.6)
        elif step == 'allow_direct_generation':
            updated['allow_direct_generation'] = True
        elif step == 'collect_more_evidence':
            updated['collect_more_evidence'] = True
            updated['defer_for_more_evidence'] = True
        elif step == 'deprioritize_roadblock':
            updated['value_score'] = min(updated['value_score'], 0.35)
    return updated


def derive_path_ab_policy(
    project: str,
    route_preferences: dict[str, Any],
    seed: Optional[str],
    relevant_info: Optional[dict[str, Any]],
    cached_format_info: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Decide whether Path A/B should run while preserving existing whitelist behavior."""
    in_whitelist = project in ENABLE_FIELD_PARSING
    has_seed = seed is not None
    has_taint_ranges = bool(relevant_info and relevant_info.get('ranges'))
    has_input_signal = route_preferences.get('input_score', 0.0) >= 0.45
    has_state_signal = (
        route_preferences.get('prefer_state_guided', False)
        or route_preferences.get('state_score', 0.0) >= 0.5
    )
    has_evidence = route_preferences.get('evidence_score', 0.0) >= 0.35
    has_format_hint = bool(cached_format_info)

    auto_enable = (
        has_seed
        and has_evidence
        and (
            (route_preferences.get('prefer_input_mutation', False) and has_taint_ranges)
            or (has_state_signal and (has_taint_ranges or has_format_hint or has_input_signal))
        )
    )

    path_ab_enabled = in_whitelist or auto_enable
    path_a_enabled = path_ab_enabled and has_taint_ranges
    path_b_enabled = path_ab_enabled and has_seed

    if in_whitelist:
        reason = "whitelist field parsing enabled"
    elif auto_enable:
        reason = "auto-enabled by seed/evidence/input signals"
    else:
        reason = "insufficient seed/evidence/input signals"

    return {
        'enable_semantic_parsing': in_whitelist,
        'path_ab_enabled': path_ab_enabled,
        'path_a_enabled': path_a_enabled,
        'path_b_enabled': path_b_enabled,
        'auto_enabled': auto_enable and not in_whitelist,
        'reason': reason,
    }


def collect_additional_roadblock_evidence(
    roadblock: dict[str, Any],
    code_slice: str,
    project: str,
    *,
    llm_util=None,
    call_chains=None,
    selected_call_chain=None,
    slice_line=None,
    selected_seed: str | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    if code_slice:
        try:
            extra_state_hints = get_state_hints(roadblock, code_slice, project)
        except Exception:
            extra_state_hints = []
        if extra_state_hints:
            evidence['state_hints'] = extra_state_hints
    try:
        harness_code = get_harness_code()
    except Exception:
        harness_code = None
    if harness_code:
        evidence['harness_code'] = harness_code

    if llm_util and call_chains:
        alternate_slices = []
        for chain in call_chains:
            if selected_call_chain and chain == selected_call_chain:
                continue
            try:
                alt_slice = get_function_slice(chain, slice_line, roadblock.get('status'), llm_util)
            except Exception:
                continue
            if not alt_slice or "No matching instruction found" in alt_slice or alt_slice == code_slice:
                continue
            alternate_slices.append(alt_slice)
            if len(alternate_slices) >= 2:
                break
        if alternate_slices:
            evidence['alternate_slices'] = alternate_slices
            replacement_slice = max(alternate_slices, key=len)
            if len(replacement_slice) > len(code_slice):
                evidence['replacement_code_slice'] = replacement_slice

    if selected_seed and selected_call_chain:
        seed_path = config.find_seed_path(selected_seed)
        if seed_path and seed_path.exists():
            try:
                coverage_context = build_seed_coverage_diagnosis_context(str(seed_path), roadblock, selected_call_chain)
            except Exception:
                coverage_context = None
            if coverage_context:
                evidence['coverage_diagnosis_context'] = coverage_context

    evidence['evidence_boost'] = min(0.2, 0.05 * len([key for key in evidence.keys() if key != 'replacement_code_slice'])) if evidence else 0.0
    return evidence


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
    status = roadblock.get('status', True)
    group_type = roadblock.get('group_type')

    file_short = filename.split('/')[-1] if filename else 'unknown'
    if group_type == "switch":
        switch_line = int(roadblock.get('switch_statement_line', 0) or 0)
        case_body_line = int(roadblock.get('case_body_line', 0) or 0)
        group_index = int(roadblock.get('group_index', 0) or 0)
        case_label = str(roadblock.get('case_label', '') or '').strip()
        return (
            f"{file_short}:switch:{switch_line}:{line}:{case_body_line}:"
            f"{group_index}:{case_label}:{str(status)[:4]}"
        )
    code = str(roadblock.get('code', '') or '').strip()
    return f"{file_short}:branch:{line}:{code}:{str(status)[:4]}"


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


def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in text for keyword in keywords)


def _required_surfaces_for_family(family: str, activation: str) -> set[str]:
    if activation == "input_only":
        return set()
    if family == "parser.html":
        return {"argv"}
    if family in {"api.xpath", "schema.validation"}:
        return {"argv", "aux_file"}
    if activation in {"input_plus_mode", "state_or_runtime"}:
        return {"argv"}
    return set()


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


def build_default_reachability_profile(roadblock: dict[str, Any]) -> dict[str, Any]:
    """Treat every roadblock as directly reachable without subspace/frontier triage."""
    return {
        "subspace_info": {
            "subspace_family": "unknown",
            "subspace_mode": "default",
            "subspace_state": "unknown",
            "entry_markers": [],
            "activation_requirements": "unknown",
            "control_surface_profile": ensure_control_surface_profile(),
            "required_surfaces": [],
            "reachable_families": [],
            "blocked_families": [],
            "frontier_distance": 0,
            "call_chain_summary": {},
            "failure_scope_key": _roadblock_failure_scope_key(roadblock, "unknown"),
            "entry_signal_files": [],
            "entry_signal_functions": [],
        },
        "decision": "reachable",
        "reason": "subspace_triage_disabled",
        "frontier_distance": 0,
        "tier": "Tier A",
        "family_match": False,
        "evidence_strength": 0.35,
        "requires_extra_surface": False,
        "estimated_cost": 1,
        "last_failure_mode": pass_roadblock.get(roadblock.get("roadblock_key", ""), {}).get("mode"),
        "last_n_attempts": 0,
    }


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


def screen_selected_roadblocks(
    candidates: list[dict[str, Any]],
    llm_util: LLMUtil,
    *,
    budget: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    if budget <= 0 or not candidates:
        return [], [], [], []

    ranked_candidates = rank_roadblocks_with_frontier_distance(candidates)
    initial_tier_a = [rb for rb in ranked_candidates if rb.get('triage_tier') == 'Tier A']
    initial_tier_b = [rb for rb in ranked_candidates if rb.get('triage_tier') == 'Tier B']

    preselected: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for rb in select_stage_roadblocks(initial_tier_a, budget) + select_stage_roadblocks(initial_tier_b, budget):
        rb_key = rb.get('roadblock_key') or f"anon:{id(rb)}"
        if rb_key in seen_keys:
            continue
        seen_keys.add(rb_key)
        preselected.append(rb)

    if not preselected:
        return [], [], [], []

    screened_candidates = screen_roadblocks_with_llm(preselected, llm_util, budget=len(preselected))
    screened_candidates = rank_roadblocks_with_frontier_distance(screened_candidates)

    tier_a = [rb for rb in screened_candidates if rb.get('triage_tier') == 'Tier A']
    tier_b = [rb for rb in screened_candidates if rb.get('triage_tier') == 'Tier B']
    rejected = [rb for rb in screened_candidates if rb.get('triage_tier') == 'Tier C']
    deferred = [rb for rb in screened_candidates if rb.get('triage_tier') == 'Tier D']

    return (
        select_stage_roadblocks(tier_a, budget),
        select_stage_roadblocks(tier_b, budget),
        rejected,
        deferred,
    )


def record_roadblock_outcome(success: bool):
    """Track recent roadblock outcomes for mixed exploration timing."""
    recent_roadblock_outcomes.append(bool(success))


def reset_roadblock_outcomes():
    """Clear recent roadblock history after a coverage breakthrough."""
    recent_roadblock_outcomes.clear()


def get_recent_roadblock_failure_rate() -> float:
    """Return the failure ratio of recent roadblock attempts."""
    if not recent_roadblock_outcomes:
        return 0.0
    failures = sum(1 for success in recent_roadblock_outcomes if not success)
    return failures / len(recent_roadblock_outcomes)


def should_enter_early_zero_branch_stage(stuck_time: float, roadblock_count: int, skipped_failed: int) -> bool:
    """
    Start zero-covered exploration before one-sided roadblocks are fully exhausted
    once the current roadblock workflow shows clear low-yield signals.
    """
    if not (ENABLE_ZERO_BRANCH_SECOND_STAGE and ENABLE_ZERO_COVERED_EXPLORATION):
        return False

    if roadblock_count <= 0:
        return True

    recent_failure_rate = get_recent_roadblock_failure_rate()
    enough_history = len(recent_roadblock_outcomes) >= recent_roadblock_outcomes.maxlen
    visible_candidates = roadblock_count + skipped_failed
    failed_ratio = skipped_failed / visible_candidates if visible_candidates > 0 else 0.0

    return (
        stuck_time >= THRESHOLD_TIME * 2
        and enough_history
        and recent_failure_rate >= 0.8
        and (roadblock_count <= 3 or failed_ratio >= 0.7)
    )


def should_prioritize_zero_branch_stage(stuck_time: float, roadblock_count: int, skipped_failed: int) -> bool:
    """
    Escalate zero-covered exploration to primary mode when the current stagnation is
    clearly deep, even if a few roadblocks are still technically available.
    """
    if roadblock_count <= 0:
        return True

    recent_failure_rate = get_recent_roadblock_failure_rate()
    enough_history = len(recent_roadblock_outcomes) >= recent_roadblock_outcomes.maxlen
    visible_candidates = roadblock_count + skipped_failed
    failed_ratio = skipped_failed / visible_candidates if visible_candidates > 0 else 0.0

    return (
        stuck_time >= THRESHOLD_TIME * 4
        and enough_history
        and recent_failure_rate >= 0.8
        and (roadblock_count <= 3 or failed_ratio >= 0.7)
    )


def run_zero_branch_stage(
    tracer: CoverageTracer,
    llm_util: LLMUtil,
    last_scan_time,
    read_files,
    attempt_limit: int,
    stage_reason: str,
):
    """Run zero-covered branch exploration and stop early on any breakthrough."""
    try:
        zero_branches = tracer.get_zero_branch_targets_from_llvm_cov()[:attempt_limit]
        logger.info(
            f"[{LogOp.ROADBLOCK}] ZERO_BRANCH_STAGE entered ({stage_reason}), "
            f"found {len(zero_branches)} zero-covered branches"
        )

        for zc_branch in zero_branches:
            ret, mode, id, target_id = handle_zero_covered_branch(zc_branch, tracer, llm_util)
            stuck_time = tracer.check_coverage_growth()

            if stuck_time < THRESHOLD_TIME:
                reset_roadblock_outcomes()
                logger.info(f"[{LogOp.ROADBLOCK}] Coverage breakthrough via zero-covered branch!")
                return True, True, last_scan_time, read_files
            if ret:
                logger.info(f"[{LogOp.ROADBLOCK}] Zero-covered branch resolved: {mode}")
                return True, False, last_scan_time, read_files
    except Exception as e:
        logger.error(f"[{LogOp.ROADBLOCK}] Error during zero-branch fallback: {e}", exc_info=True)

    return False, False, last_scan_time, read_files


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


def _build_seed_profdata(seed_path: str) -> Optional[Path]:
    diag_dir = RUN_TRACE_PATH / "coverage_diag"
    diag_dir.mkdir(parents=True, exist_ok=True)

    seed_tag = Path(seed_path).name.replace(":", "_").replace(",", "_")
    profraw_path = diag_dir / f"{seed_tag}.profraw"
    profdata_path = diag_dir / f"{seed_tag}.profdata"

    for artifact in (profraw_path, profdata_path):
        if artifact.exists():
            artifact.unlink()

    trace_cmd, stdin_data = build_seed_execution(COV_TARGET_PATH, seed_path)
    env = os.environ.copy()
    env["LLVM_PROFILE_FILE"] = os.fspath(profraw_path)

    try:
        subprocess.run(
            trace_cmd,
            input=stdin_data,
            stdin=subprocess.DEVNULL if stdin_data is None else None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=os.fspath(diag_dir),
            timeout=TIMEOUT,
            check=False,
        )
    except Exception as e:
        logger.warning(f"[{LogOp.TEST}] Failed to execute seed for coverage diagnosis: {e}")
        return None

    if not profraw_path.exists():
        logger.warning(f"[{LogOp.TEST}] Coverage diagnosis profraw not generated for seed: {seed_path}")
        return None

    merge_cmd = [
        LLVM_PROFDATA_BIN,
        "merge",
        "-sparse",
        "-o",
        os.fspath(profdata_path),
        os.fspath(profraw_path),
    ]
    result = subprocess.run(
        merge_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        cwd=os.fspath(diag_dir),
        check=False,
    )
    if result.returncode != 0 or not profdata_path.exists():
        logger.warning(
            f"[{LogOp.TEST}] Failed to merge profdata for coverage diagnosis: "
            f"{result.stderr[:300] if result.stderr else '(empty)'}"
        )
        return None

    return profdata_path


def _llvm_cov_show_file(file_name: str, profdata_path: Path) -> Optional[str]:
    cmd = [
        LLVM_COV_BIN,
        "show",
        os.fspath(COV_TARGET_PATH),
        "-format=text",
        f"-instr-profile={profdata_path.as_posix()}",
        file_name,
    ]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        cwd=os.fspath(profdata_path.parent),
        check=False,
    )
    if result.returncode != 0:
        logger.warning(
            f"[{LogOp.TEST}] llvm-cov show failed for {file_name}: "
            f"{result.stderr[:300] if result.stderr else '(empty)'}"
        )
        return None
    return result.stdout


def _extract_line_window(report_text: str, target_line: int, window: int = 12) -> str:
    lines = report_text.splitlines()
    if not lines:
        return ""
    start = max(0, target_line - window - 1)
    end = min(len(lines), target_line + window)
    return "\n".join(lines[start:end])


def build_seed_coverage_diagnosis_context(seed_path: str, roadblock: dict, call_chain) -> Optional[str]:
    profdata_path = _build_seed_profdata(seed_path)
    if not profdata_path:
        return None

    function_names = _extract_call_chain_function_names(call_chain)
    target_func = roadblock.get("function")
    if target_func and target_func not in function_names:
        function_names.append(target_func)

    file_cache = {}
    sections = [
        f"<seed_path>\n{seed_path}\n</seed_path>",
        f"<target_function>\n{target_func or 'unknown'}\n</target_function>",
        f"<target_location>\n{roadblock.get('filename', 'unknown')}:{roadblock.get('line', 0)}\n</target_location>",
        f"<call_chain>\n{' -> '.join(function_names) if function_names else 'N/A'}\n</call_chain>",
    ]

    for func_name in function_names:
        meta = _get_function_meta(func_name)
        if not meta or not meta.get("file_name"):
            continue
        file_name = meta["file_name"]
        if file_name not in file_cache:
            file_cache[file_name] = _llvm_cov_show_file(file_name, profdata_path)
        report_text = file_cache[file_name]
        if not report_text:
            continue
        block = extract_function_block(report_text, func_name)
        if block:
            sections.append(
                f"<function_coverage name=\"{func_name}\">\n{block[:5000]}\n</function_coverage>"
            )

    target_file = roadblock.get("filename")
    if target_file:
        if target_file not in file_cache:
            file_cache[target_file] = _llvm_cov_show_file(target_file, profdata_path)
        target_report = file_cache[target_file]
        if target_report:
            line_window = _extract_line_window(target_report, roadblock.get("line", 0))
            if line_window:
                sections.append(
                    f"<target_line_window>\n{line_window[:3000]}\n</target_line_window>"
                )

    return "\n".join(sections)


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


def evaluate_seed(seed_path: str, target_context: Optional[dict[str, Any]] = None) -> SeedEvalResult:
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

    return SeedEvalResult(
        exec_ok=True,
        parse_family_hit=False,
        new_edges=0,
        target_file_hit=False,
        target_line_window_hit=False,
        coverage_gain_class="seed_generated",
        cost_metrics={"file_size": file_size},
        rejection_reason=None,
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
        audit_path = _audit_rejected_seed(seed_path, "reject_duplicate")
        eval_result = SeedEvalResult(False, False, 0, False, False, "duplicate_seed", {"file_size": file_size}, "SEED_DUPLICATE")
        return SeedGateResult("reject_duplicate", False, "duplicate_seed", audit_path=audit_path, duplicate_of=duplicate_path), eval_result

    size_policy = _get_seed_gate_policy()
    if file_size > size_policy["hard_max"]:
        audit_path = _audit_rejected_seed(seed_path, "reject_too_large")
        eval_result = SeedEvalResult(False, False, 0, False, False, "size_rejected", {"file_size": file_size, **size_policy}, "SEED_TOO_LARGE")
        return SeedGateResult("reject_too_large", False, "seed_exceeds_hard_limit", audit_path=audit_path), eval_result

    eval_result = evaluate_seed(seed_path, {"roadblock": roadblock or {}, "call_chain": call_chain})
    return SeedGateResult("accept", True, "seed_generated"), eval_result


def diagnose_and_improve_no_coverage(
    llm_util: LLMUtil,
    generator_script: str,
    seed_path: str,
    roadblock: dict,
    call_chain,
    code_slice: str,
) -> Optional[str]:
    coverage_context = build_seed_coverage_diagnosis_context(seed_path, roadblock, call_chain)
    if not coverage_context:
        return None

    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"
    target_branch_code = roadblock.get("code") or roadblock.get("case_label") or ""
    diagnosis_messages = [
        {
            "role": "system",
            "content": prompts['prompt']['no_coverage_diagnosis']['sys_prompt'],
        },
        {
            "role": "user",
            "content": get_formatted_user_prompt(
                'no_coverage_diagnosis',
                roadblock_json=json.dumps(roadblock, ensure_ascii=False),
                target_branch_code=target_branch_code,
                code_slice=code_slice[:8000],
                generator_script=generator_script,
                coverage_context=coverage_context,
                runtime_command_context=build_runtime_command_context(),
            ),
        },
    ]

    diagnosis_resp = llm_util.get_response(diagnosis_messages)
    diagnosis_match = extract_json_with_fallback(diagnosis_resp, pattern_json)
    advice_text = diagnosis_resp.strip()
    if diagnosis_match:
        try:
            diagnosis = json.loads(diagnosis_match.group(1).strip())
            advice_lines = diagnosis.get("improvement_advice", [])
            if isinstance(advice_lines, list) and advice_lines:
                advice_text = "\n".join(f"- {line}" for line in advice_lines)
            summary = diagnosis.get("reason_summary")
            next_focus = diagnosis.get("next_focus")
            if summary:
                advice_text = f"{summary}\n{advice_text}"
            if next_focus:
                advice_text = f"{advice_text}\n下一步重点：{next_focus}"
            logger.info(
                f"[{LogOp.TEST}] No-coverage diagnosis status: "
                f"{diagnosis.get('coverage_status', 'unknown')}"
            )
        except Exception as e:
            logger.warning(f"[{LogOp.TEST}] Failed to parse no-coverage diagnosis JSON: {e}")

    improved_resp = llm_util.improve_script(generator_script, coverage_context, advice_text)
    try:
        return extract_generator(improved_resp)
    except ScriptNotFoundError:
        logger.warning(f"[{LogOp.TEST}] Improved generator response did not contain a Python code block")
        return None


def _seed_eval_indicates_local_progress(eval_result: SeedEvalResult) -> bool:
    return bool(eval_result.exec_ok)

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
    stdout, stderr, new_seed_path = run_generator(script, roadblock_id if roadblock_id else 999999, seed_id, output_dir)
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
        stdout, stderr, new_seed_path = run_generator(fixed_generator_script, roadblock_id if roadblock_id else 999999,
                                                      seed_id, output_dir)
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
        stdout, stderr, new_seed_path = run_generator(fixed_generator_script, roadblock_id if roadblock_id else 999999,
                                                      seed_id, output_dir)
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
            )
    if not gate_result.accepted:
        logger.info(
            f"[{LogOp.TEST}] Seed rejected before queue acceptance: "
            f"{eval_result.rejection_reason or gate_result.reason}"
        )
        return False, script, gate_result.audit_path or new_seed_path

    logger.info(
        f"[{LogOp.TEST}] Seed accepted after generation "
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
):
    global input_dir, output_dir, fuzzing_args, target_prog, trace_prog

    # Check fuzzer alive before mutation testing
    try:
        check_fuzzer_alive()
    except FuzzerProcessDiedError as e:
        logger.critical(f"[{LogOp.FUZZER}] {e}")
        logger.critical("[{LogOp.FUZZER}] Fuzzer died before mutate_and_test, aborting...")
        raise

    stdout, stderr, new_seed_path = run_mutate_script(script, seed_id, orig, output_dir)
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
        stdout, stderr, new_seed_path = run_mutate_script(fixed_generator_script, seed_id, orig, output_dir)
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
        return False, script, gate_result.audit_path or new_seed_path
    logger.info(
        f"[{LogOp.TEST}] Mutated seed accepted "
        f"(exec_ok={eval_result.exec_ok}, file_size={eval_result.cost_metrics.get('file_size')})"
    )
    return True, script, new_seed_path


def handle_subspace_bootstrap(target, tracer: CoverageTracer, llm_util: LLMUtil):
    global output_dir

    roadblock_key = target.get('roadblock_key') or get_roadblock_key(target)
    roadblock_id = target.get('roadblock_id')
    subspace_info = target.get("subspace_info") or {}
    family = subspace_info.get("subspace_family", "unknown")
    decision = target.get("reachability_decision")

    if decision != "reachable_but_weak_signal":
        logger.warning(
            f"[{LogOp.ROADBLOCK}] Bootstrap requested for non-bootstrap candidate "
            f"{roadblock_key} (decision={decision})"
        )
        return False, "BOOTSTRAP_SKIPPED", -1, roadblock_id

    if family not in {"parser.xml", "parser.html"}:
        logger.warning(
            f"[{LogOp.ROADBLOCK}] Bootstrap unsupported for family={family}, skipping roadblock {roadblock_key}"
        )
        mark_roadblock_failed(roadblock_key, "BOOTSTRAP_FAILED", target)
        return False, "BOOTSTRAP_FAILED", -1, roadblock_id

    logger.info(
        f"[{LogOp.ROADBLOCK}] Starting subspace bootstrap for {roadblock_key} "
        f"(family={family}, distance={target.get('frontier_distance')})"
    )

    target_desc = (
        "Generate the smallest possible HTML-like payload that causes the target to enter the HTML parsing family. "
        "Do not try to satisfy the deep branch; focus on switching parser family."
        if family == "parser.html"
        else "Generate the smallest possible XML payload that reliably enters the XML parser and progresses into parsing logic. "
             "Do not optimize for the deep branch; focus on entering the parser subspace."
    )
    constraints = (
        f"Bootstrap target family: {family}\n"
        f"{target_desc}\n"
        f"Target location: {target.get('filename', 'unknown')}:{target.get('line', 0)}\n"
        f"If a document wrapper is needed, keep it minimal and well-formed."
    )
    input_profile = (
        f"Subspace bootstrap only. Goal: enter {family}. "
        f"Current reachability reason: {target.get('reachability_reason', 'unknown')}."
    )
    code_slice = (
        f"/* bootstrap target */\n"
        f"file: {target.get('filename', 'unknown')}\n"
        f"function: {target.get('function', 'unknown')}\n"
        f"line: {target.get('line', 0)}\n"
        f"branch: {target.get('code', '')}\n"
    )
    harness_code = get_harness_code()
    generation_messages = build_direct_text_generation_messages(
        code_slice,
        constraints,
        input_profile,
        target_branch=target.get("code"),
        harness_code=harness_code,
    )

    llm_queue_path = Path(output_dir) / "LLM" / "queue"
    os.makedirs(llm_queue_path, exist_ok=True)
    seed_id = len(os.listdir(llm_queue_path))
    times = 0
    while times < MAX_TIME:
        resp = llm_util.get_response(generation_messages)
        generated_text = extract_direct_text_payload(resp)
        if not generated_text:
            append_llm_retry_feedback(
                generation_messages,
                resp,
                "未提取到可写入 seed 文件的文本内容。请只返回 <generated_input>...</generated_input> 包裹的最小 seed 文本。"
            )
            times += 1
            continue

        seed_path = os.path.join(llm_queue_path, f"id:{int(seed_id):06},bid:{int(roadblock_id or 999999):06}")
        with open(seed_path, 'w', encoding='utf-8') as f:
            f.write(generated_text)
        logger.info(f"[{LogOp.ROADBLOCK}] Bootstrap seed written to {seed_path}")

        gate_result, eval_result = gate_seed(seed_path, roadblock=target)
        logger.info(
            f"[SEED_GATE] decision={gate_result.decision} accepted={gate_result.accepted} "
            f"reason={gate_result.reason}"
        )
        local_progress = gate_result.accepted and _seed_eval_indicates_local_progress(eval_result)
        if local_progress:
            logger.info(
                f"[{LogOp.ROADBLOCK}] Subspace bootstrap produced local hit evidence for {roadblock_key} "
                f"(family={family})"
            )
            mark_roadblock_resolved(roadblock_key, "SUBSPACE_BOOTSTRAP")
            return True, "SUBSPACE_BOOTSTRAP", seed_id, roadblock_id

        append_llm_retry_feedback(
            generation_messages,
            resp,
            "该输入没有带来新的覆盖。请继续生成更小、更直接、更能进入目标 parser family 的输入。"
        )
        times += 1

    mark_roadblock_failed(roadblock_key, "BOOTSTRAP_FAILED", target)
    logger.info(f"[{LogOp.ROADBLOCK}] Subspace bootstrap failed for {roadblock_key}")
    return False, "BOOTSTRAP_FAILED", -1, roadblock_id


def handle_roadblock(roadblock, tracer: CoverageTracer, llm_util: LLMUtil):
    global pass_roadblock, inference_stats, attempted_roadblocks
    global fuzzer, input_dir, output_dir, fuzzing_args, target_prog, trace_prog

    # Check if fuzzer is still alive before starting roadblock processing
    try:
        check_fuzzer_alive()
    except FuzzerProcessDiedError as e:
        logger.critical(f"[{LogOp.FUZZER}] {e}")
        logger.critical("[{LogOp.FUZZER}] Fuzzer died before roadblock processing, aborting...")
        raise

    # 生成瓶颈的唯一标识符（基于位置信息）
    roadblock_key = roadblock.get('roadblock_key') or get_roadblock_key(roadblock)
    roadblock_id = roadblock.get('roadblock_id')  # 保留用于日志

    if roadblock_key in attempted_roadblocks:
        logger.info(f"[{LogOp.ROADBLOCK}] Skipping already-attempted roadblock: {roadblock_key}")
        return False, "ALREADY_ATTEMPTED", -1, roadblock_id

    if roadblock.get("reachability_decision") in {
        "unreachable_due_to_control_surface",
        "cooled_down",
        "llm_screen_rejected",
    }:
        logger.warning(
            f"[{LogOp.ROADBLOCK}] Roadblock {roadblock_key} blocked before handling: "
            f"{roadblock.get('reachability_decision')} ({roadblock.get('reachability_reason')})"
        )
        mark_roadblock_failed(roadblock_key, "UNREACHABLE_CONTROL_SURFACE", roadblock)
        return False, "UNREACHABLE_CONTROL_SURFACE", -1, roadblock_id

    if roadblock.get("reachability_decision") not in {
        None,
        "reachable",
        "reachable_but_weak_signal",
        "llm_screen_selected",
        "llm_screen_inconclusive",
    }:
        logger.warning(
            f"[{LogOp.ROADBLOCK}] Roadblock {roadblock_key} reached handle_roadblock despite "
            f"reachability_decision={roadblock.get('reachability_decision')}"
        )
        return False, "SUBSPACE_UNREACHED_SHOULD_NOT_HANDLE", -1, roadblock_id

    logger.info(f"[{LogOp.ROADBLOCK}] Processing roadblock {roadblock_id} (key: {roadblock_key})")
    mark_roadblock_attempted(roadblock_key, roadblock, stage="handle_roadblock")
    seeds = tracer.get_rb_seed(roadblock)
    rb_file = roadblock['filename']
    rb_line = roadblock['line']

    # 对于 switch case 类型的 roadblock，查找 switch 语句的行号
    slice_line = rb_line  # 默认使用 roadblock 的行号
    if roadblock.get('group_type', None) == 'switch':
        switch_line = get_switch_statement_line(roadblock)
        if switch_line:
            logger.info(
                f"[{LogOp.ROADBLOCK}] Switch case detected at line {rb_line}, using switch statement at line {switch_line} for slicing")
            slice_line = switch_line
        else:
            logger.warning(
                f"[{LogOp.ROADBLOCK}] Switch case at line {rb_line} but switch statement line not found, using case line for slicing")

    dynamic_context = tracer.build_dynamic_context_for_roadblock(roadblock, seed_names=seeds)
    if dynamic_context:
        logger.info(
            f"[{LogOp.ROADBLOCK}] Dynamic trace context ready: "
            f"{len(dynamic_context.get('preferred_call_paths', []))} path(s), "
            f"{len(dynamic_context.get('preferred_functions', []))} function(s)"
        )
    else:
        logger.info(f"[{LogOp.ROADBLOCK}] Dynamic trace context unavailable, using static slicing only")

    rb_fname = None
    rb_fid = None
    bcode = roadblock['code']
    for func in funcs:
        if "file_name" not in func:
            continue
        if func["file_name"].split("/")[-1] == rb_file.split("/")[-1]:
            if func['lineEnd'] >= rb_line >= func['lineStart']:
                rb_fname = func["name"]
                rb_fid = func["id"]
                break
    # roadblock_id = None
    # for bb in bbs:
    #     if rb_fid == bb['function'] and bb['lineEnd'] >= rb_line >= bb['lineStart']:
    #         roadblock_id = bb['id']
    #         break
    roadblock_id = roadblock['roadblock_id']
    if not rb_fname:
        logger.warning(f"[{LogOp.ROADBLOCK}] Roadblock {roadblock_id}: No function name found in call graph")
        logger.debug(f"[{LogOp.ROADBLOCK}] File: {rb_file}, Line: {rb_line}")
        mark_roadblock_failed(roadblock_key, "NO_FUNCTION_NAME", roadblock)
        return False, "This roadblock has no file name in call graph", -1, roadblock_id

    # ========== 调用链获取与代码切片（支持回退策略）==========
    # 策略1: 尝试获取完整调用链
    # 策略2: 如果失败，尝试单函数切片作为回退
    call_chains = get_call_chain(rb_fname.split('.')[0])

    # 记录是否使用了回退策略
    using_fallback_slice = False

    if call_chains is None or len(call_chains) == 0:
        logger.warning(f"[{LogOp.ROADBLOCK}] No valid call chain found for function {rb_fname}")
        logger.info(f"[{LogOp.ROADBLOCK}] ===== FALLBACK: Attempting single function slice =====")

        # 回退策略：尝试使用单函数切片
        # 构造单函数"调用链"
        fallback_chain = [rb_fname.split('.')[0]]

        # 尝试提取单函数代码
        logger.info(f"[{LogOp.ROADBLOCK}] Fallback: Extracting single function: {fallback_chain[0]}")
        code_slice = ensure_cached_single_function_slice(
            roadblock,
            llm_util,
            dynamic_context=dynamic_context,
        )

        if code_slice and "No matching instruction found" not in code_slice and len(code_slice) > 50:
            # 单函数切片成功
            logger.info(f"[{LogOp.ROADBLOCK}] ===== FALLBACK SUCCESS: Single function slice extracted ({len(code_slice)} chars) =====")
            logger.info(f"[{LogOp.ROADBLOCK}] Note: Using single function slice - input context may be limited")
            using_fallback_slice = True

            # 设置一个虚拟的 call_chain 用于后续处理（虽然只有一个函数）
            call_chains = [fallback_chain]
        else:
            # 单函数切片也失败
            logger.error(f"[{LogOp.ROADBLOCK}] ===== FALLBACK FAILED: Could not extract single function code =====")
            mark_roadblock_failed(roadblock_key, "CODE_SLICE_FAILED", roadblock)
            return False, "Failed to extract code (no call chain and fallback failed)", -1, roadblock_id
    else:
        logger.info(f"[{LogOp.ROADBLOCK}] Found {len(call_chains)} valid call chain(s) for {rb_fname}")
        call_chains = _rank_call_chains_with_dynamic_context(
            call_chains,
            dynamic_context,
            fallback_scorer=_score_input_driven_call_chain,
        )
        logger.debug(
            f"[{LogOp.ROADBLOCK}] Ranked call chains for {rb_fname}: "
            f"{[(format_call_chain(chain), _score_input_driven_call_chain(chain)) for chain in call_chains[:5]]}"
        )

    for call_chain in call_chains:
        logger.debug(f"[{LogOp.ROADBLOCK}] Executing call chain: {format_call_chain(call_chain)}")

        # 如果使用了回退策略（单函数切片），跳过深度检查和代码提取
        if using_fallback_slice:
            logger.debug(f"[{LogOp.ROADBLOCK}] Using fallback slice, skipping depth check and re-extraction")
            # code_slice 已经在回退时提取好了，直接使用
        else:
            # 正常路径：检查调用链深度
            if len(call_chain) < DEPTH_THRESHOLD:
                logger.debug(
                    f"[{LogOp.ROADBLOCK}] Call chain too shallow (depth={len(call_chain)}, threshold={DEPTH_THRESHOLD})")
                continue
            # 正常路径：提取代码切片
            logger.info(f"[{LogOp.ROADBLOCK}] Starting function slice extraction for {rb_file}:{rb_line}")
            code_slice = get_function_slice(
                call_chain,
                slice_line,
                roadblock['status'],
                llm_util,
                dynamic_context=dynamic_context,
                original_target_line=rb_line,
            )
            logger.info(f"[{LogOp.ROADBLOCK}] Function slice extraction completed, length: {len(code_slice)} chars")
            if "No matching instruction found" in code_slice:
                logger.error(f"[{LogOp.ROADBLOCK}] Slice failed - 'No matching instruction found' in result")
                mark_roadblock_failed(roadblock_key, "SLICE_FAILED", roadblock)
                return False, "No matching instruction found in exact bc", -1, roadblock_id

        pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"
        solved = False
        times = 0

        # Check fuzzer alive before LLM constraint analysis
        try:
            check_fuzzer_alive()
        except FuzzerProcessDiedError as e:
            logger.critical(f"[{LogOp.FUZZER}] {e}")
            logger.critical("[{LogOp.FUZZER}] Fuzzer died before constraint analysis, aborting...")
            raise

        logger.info(f"[{LogOp.ROADBLOCK}] Starting constraint analysis (code_slice preview: {code_slice[:100]}...)")
        res = None
        constraint_messages = build_constraints_messages(roadblock, code_slice)
        while times < MAX_TIME:
            logger.debug(f"[{LogOp.ROADBLOCK}] Constraint analysis attempt {times + 1}/{MAX_TIME}")
            resp = llm_util.get_response(constraint_messages)
            match = extract_json_with_fallback(resp, pattern_json)
            if not match:
                logger.debug(
                    f"[{LogOp.LLM}] JSON pattern not found in constraint analysis response, requesting regeneration")
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
                logger.warning(
                    f"[{LogOp.LLM}] Constraint analysis JSON parse failed: {exc}; requesting regeneration")
                append_llm_retry_feedback(
                    constraint_messages,
                    resp,
                    f"JSON 解析失败：{exc}。请只返回一个合法的 JSON object，并完整包含 analise_branch_v2 需要的所有字段。"
                )
                times += 1
                continue

            analysis_error = validate_analysis_result_v2(res)
            if analysis_error:
                logger.warning(
                    f"[{LogOp.LLM}] Invalid analise_branch_v2 schema: {analysis_error}; requesting regeneration")
                append_llm_retry_feedback(
                    constraint_messages,
                    resp,
                    f"返回结构不符合要求：{analysis_error}。请只返回一个 JSON object，并完整包含 analise_branch_v2 需要的所有字段。"
                )
                res = None
                times += 1
                continue
            break

        # Check if all attempts failed to get a valid response
        if res is None:
            logger.error(
                f"[{LogOp.ROADBLOCK}] Constraint analysis failed after {MAX_TIME} attempts - LLM consistently returned unsatisfiable or invalid response")
            mark_roadblock_failed(roadblock_key, "CONSTRAINT_ANALYSIS_FAILED", roadblock)
            return False, "Constraint analysis failed", -1, roadblock_id

        logger.info(f"[{LogOp.ROADBLOCK}] Starting conflict judgment")
        constraints = res['global_merged_constraints_in_natural_language']
        summary = res['reasoning_summary']
        non_input_constraints = res['non_input_constraints']
        assessment = res['breakthrough_assessment']
        non_input_dominated, matched_groups = detect_non_input_blocker_dependency(
            non_input_constraints,
            assessment,
        )
        if non_input_dominated:
            logger.info(
                f"[{LogOp.ROADBLOCK}] Roadblock {roadblock_id} is dominated by non-input blockers "
                f"({', '.join(matched_groups)}); rejecting because only input-driven breakthroughs are in scope"
            )
            decision_result = build_non_input_rejection_decision(matched_groups)
        elif not ENABLE_V2_PRE_JUDGE:
            logger.info(
                f"[{LogOp.ROADBLOCK}] V2 pre-judgment disabled by config "
                f"(ENABLE_V2_PRE_JUDGE=False), skipping judge_conflict_v2"
            )
            decision_result = build_pre_judge_bypass_decision()
        else:
            try:
                decision_result = judge_conflict(
                    constraints,
                    non_input_constraints,
                    assessment,
                    llm_util,
                    code_slice,
                    roadblock['status']
                )
            except ValueError as exc:
                logger.error(f"[{LogOp.ROADBLOCK}] judge_conflict_v2 failed: {exc}")
                mark_roadblock_failed(roadblock_key, "ROADBLOCK_DECISION_INVALID_SCHEMA", roadblock)
                return False, "roadblock decision invalid schema", -1, roadblock_id

        decision_result = normalize_decision_result_v2(decision_result)
        slice_probe_result = roadblock.get('slice_probe_result')
        decision_result = merge_breakthrough_probe_with_conflict_decision(decision_result, slice_probe_result)
        decision = decision_result['decision']
        reason = decision_result['reason']
        should_generate_input = decision_result['should_generate_input']
        should_try_state_guided = decision_result['should_try_state_guided_workflow']
        route_preferences = derive_route_preferences(decision_result)
        route_preferences = apply_recommended_next_steps(decision_result, route_preferences)
        supplemental_evidence = {}
        supplemental_state_hints = []
        supplemental_harness_code = None

        logger.info(
            f"[{LogOp.ROADBLOCK}] Decision result for roadblock {roadblock_id}: "
            f"decision={decision}, reason={reason}, "
            f"should_generate_input={should_generate_input}, "
            f"should_try_state_guided_workflow={should_try_state_guided}, "
            f"input_score={route_preferences['input_score']:.2f}, "
            f"state_score={route_preferences['state_score']:.2f}, "
            f"evidence_score={route_preferences['evidence_score']:.2f}, "
            f"depth_score={route_preferences['depth_score']:.2f}, "
            f"value_score={route_preferences['value_score']:.2f}"
        )
        if slice_probe_result and slice_probe_result.get('available'):
            logger.info(
                f"[{LogOp.ROADBLOCK}] Joint gate used slice probe for roadblock {roadblock_id}: "
                f"slice_should_continue={slice_probe_result.get('should_continue')}, "
                f"slice_confidence={slice_probe_result.get('confidence', 0.0):.2f}"
            )

        if route_preferences['hard_reject']:
            failure_reason = map_decision_reason_to_failure(reason)
            logger.error(f"[{LogOp.ROADBLOCK}] Roadblock {roadblock_id} rejected: {reason}")
            mark_roadblock_failed(roadblock_key, failure_reason, roadblock)
            return False, failure_reason.lower(), -1, roadblock_id

        if decision == "need_more_information":
            if route_preferences['defer_for_more_evidence']:
                supplemental_evidence = collect_additional_roadblock_evidence(roadblock, code_slice, PROJECT)
                supplemental_state_hints = supplemental_evidence.get('state_hints') or []
                supplemental_harness_code = supplemental_evidence.get('harness_code')
                if supplemental_evidence.get('evidence_boost'):
                    route_preferences['evidence_score'] = min(
                        1.0,
                        route_preferences['evidence_score'] + supplemental_evidence['evidence_boost'],
                    )
                if supplemental_harness_code:
                    route_preferences['allow_direct_generation'] = True
                logger.warning(
                    f"[{LogOp.ROADBLOCK}] Roadblock {roadblock_id} needs more information; "
                    f"continuing with low-confidence exploratory paths instead of immediate rejection"
                )
                if supplemental_evidence:
                    logger.info(
                        f"[{LogOp.ROADBLOCK}] Supplemental evidence collected: "
                        f"state_hints={len(supplemental_state_hints)}, "
                        f"harness_code={'yes' if supplemental_harness_code else 'no'}"
                    )
            else:
                logger.error(f"[{LogOp.ROADBLOCK}] Insufficient information for roadblock {roadblock_id}")
                mark_roadblock_failed(roadblock_key, "ROADBLOCK_INSUFFICIENT_INFO", roadblock)
                return False, "insufficient information", -1, roadblock_id

        state_guided_only = decision == "proceed_but_not_input_driven"
        if state_guided_only:
            logger.info(
                f"[{LogOp.ROADBLOCK}] Roadblock {roadblock_id} is worth exploring, but input generation is not the "
                f"primary strategy"
            )

        # ========== NEW: Flag variable detection ==========
        logger.info("checking for flag variables at target branch")

        # Try to load cached flagrec results
        flagrec_result = None
        if FLAGREC_CACHE.exists():
            logger.info(f"[{LogOp.ROADBLOCK}] Loading cached flagrec results from {FLAGREC_CACHE}")
            flagrec_result = load_cached_flagrec_results(FLAGREC_CACHE)
            if flagrec_result:
                logger.info(f"[{LogOp.ROADBLOCK}] Loaded {len(flagrec_result)} cached flagrec results")

        # If no cache, run flagrec (once per project analysis)
        if flagrec_result is None and FLAGREC_BITCODE.exists():
            try:
                FLAGREC_OUTPUT_DIR = config.get_flagrec_output_dir()
                FLAGREC_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
                logger.info(f"running flagrec analysis on {FLAGREC_BITCODE}")
                flagrec_result = run_flagrec_analysis(
                    str(FLAGREC_BITCODE),
                    str(PROJECT_HOME),
                    str(FLAGREC_OUTPUT_DIR)
                )
                # Cache results
                save_flagrec_results(flagrec_result, FLAGREC_CACHE)
            except Exception as e:
                logger.error(f"[{LogOp.ROADBLOCK}] Flagrec analysis failed: {e}", exc_info=True)

        # Filter relevant flags for this roadblock
        # Check fuzzer alive before flag analysis
        try:
            check_fuzzer_alive()
        except FuzzerProcessDiedError as e:
            logger.critical(f"[{LogOp.FUZZER}] {e}")
            logger.critical("[{LogOp.FUZZER}] Fuzzer died before flag analysis, aborting...")
            raise

        has_flags = False
        relevant_flags = []
        constant_groups = {}

        if flagrec_result:
            has_flags, relevant_flags, constant_groups = filter_relevant_flags(
                flagrec_result, roadblock
            )

        if has_flags and relevant_flags:
            logger.info(f"[{LogOp.ROADBLOCK}] Found {len(relevant_flags)} relevant flag variable(s)")
            for flag in relevant_flags:
                logger.info(f"[{LogOp.ROADBLOCK}]   - {flag['name']} (confidence: {flag.get('confidence', 0)})")

            # Try flag-based solving
            try:
                flag_reachable, flag_result = solve_with_flags(
                    code_slice,
                    roadblock,
                    constraints,
                    relevant_flags,
                    constant_groups,
                    llm_util,
                    prompts
                )

                if flag_reachable and flag_result:
                    logger.info("flag-based solving reachable, extracting script")

                    # Extract script from result
                    script = extract_script_from_flag_result(flag_result)
                    if script:
                        LLM_TARGET_PATH = Path(output_dir) / "LLM" / "queue"
                        os.makedirs(LLM_TARGET_PATH, exist_ok=True)
                        seed_id = len(os.listdir(LLM_TARGET_PATH))
                        logger.info("testing flag-based generation script")
                        solved, script, dest_file = extract_and_test(
                            llm_util, script, roadblock_id, seed_id, tracer, fuzzer
                        )
                        if solved:
                            logger.info(f"[{LogOp.ROADBLOCK}] Flag-based solution produced a locally validated seed for roadblock {roadblock_id}")
                            mark_roadblock_resolved(roadblock_key, "FLAG")
                            return True, "FLAG", seed_id, roadblock_id
                        else:
                            logger.info(f"[{LogOp.ROADBLOCK}] Flag-based script tested but coverage not achieved")
                            # Fall through to standard approaches
                    else:
                        logger.info(f"[{LogOp.ROADBLOCK}] No script extracted from flag-based solving")
                else:
                    logger.info(f"[{LogOp.ROADBLOCK}] Flag-based solving not reachable")
            except Exception as e:
                logger.error(f"[{LogOp.ROADBLOCK}] Flag-based solving error: {e}", exc_info=True)

        # If no flags or flag-based solving failed, try state variable hints
        # ========== State variable detection (Phase 1: Lightweight, Phase 2: LLM-assisted, Phase 3: Multi-stage) ==========
        logger.info(f"[{LogOp.ROADBLOCK}] Checking for state variables in code slice")

        state_hints = []

        # Try Phase 3 first if enabled (most comprehensive)
        if ENABLE_STATE_INFERENCE_PHASE_3:
            logger.info(f"[{LogOp.ROADBLOCK}] Using Phase 3 multi-stage progressive analysis")
            try:
                state_inference = StateMachineInference(llm_util)
                target_branch_str = f"{rb_file.split('/')[-1]}:{rb_line}: {bcode}"
                state_hints = state_inference.get_state_hints_with_multi_stage(
                    code_slice, target_branch_str, PROJECT, call_chain
                )
                if state_hints:
                    logger.info(f"[{LogOp.ROADBLOCK}] Phase 3: Found {len(state_hints)} multi-stage state hints")
                    for hint in state_hints:
                        logger.debug(f"[{LogOp.ROADBLOCK}] Multi-stage hint: {hint}")
                else:
                    logger.info(f"[{LogOp.ROADBLOCK}] Phase 3: No state hints from multi-stage analysis")
            except Exception as e:
                logger.error(f"[{LogOp.ROADBLOCK}] Phase 3 multi-stage analysis error: {e}, falling back to Phase 2/1")
                state_hints = []

        # If Phase 3 didn't produce results or isn't enabled, try Phase 2
        if not state_hints and ENABLE_STATE_INFERENCE_PHASE_2:
            logger.info(f"[{LogOp.ROADBLOCK}] Using Phase 2 LLM-assisted state inference")
            try:
                state_inference = StateMachineInference(llm_util)
                target_branch_str = f"{rb_file.split('/')[-1]}:{rb_line}: {bcode}"
                state_hints = state_inference.get_state_hints_for_prompt(code_slice, target_branch_str, PROJECT)
                if state_hints:
                    logger.info(f"[{LogOp.ROADBLOCK}] Phase 2: Found {len(state_hints)} LLM-inferred state hints")
                    for hint in state_hints:
                        logger.debug(f"[{LogOp.ROADBLOCK}] LLM-inferred hint: {hint}")
                else:
                    logger.info(
                        f"[{LogOp.ROADBLOCK}] Phase 2: No state variables inferred by LLM, falling back to Phase 1")
            except Exception as e:
                logger.error(f"[{LogOp.ROADBLOCK}] Phase 2 state inference error: {e}, falling back to Phase 1")

        # If Phase 2/3 didn't produce results, use Phase 1 (lightweight hardcoded mapping)
        if not state_hints:
            # Phase 1: Lightweight hardcoded mapping (default fallback)
            logger.info(f"[{LogOp.ROADBLOCK}] Using Phase 1 lightweight state detection")
            state_hints = get_state_hints(roadblock, code_slice, PROJECT)

        if supplemental_state_hints:
            merged_state_hints = []
            for hint in state_hints + supplemental_state_hints:
                if hint not in merged_state_hints:
                    merged_state_hints.append(hint)
            state_hints = merged_state_hints

        if state_hints:
            logger.info(f"[{LogOp.ROADBLOCK}] Found {len(state_hints)} state variable hint(s)")
            for hint in state_hints:
                logger.debug(f"[{LogOp.ROADBLOCK}] State hint: {hint}")
        else:
            logger.debug(f"[{LogOp.ROADBLOCK}] No state variables detected")

        # If no flags or flag-based solving failed, continue with standard flow
        logger.info(f"[{LogOp.ROADBLOCK}] Proceeding with standard taint analysis")

        # ========== End of flag detection and state hint section ==========

        def process_relevant_fields(seed, enable_semantic_parsing=True):
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
                logger.error(f"[{LogOp.ROADBLOCK}] Seed not found in current experiment queues: {seed}")
                return None, None, None

            root_seed_path = find_seed_root(seed_path.parent.as_posix(), seed_path.name, OUTPUT_PATH.as_posix())
            resolved_seed_path = Path(root_seed_path) if root_seed_path else seed_path
            if not resolved_seed_path.exists():
                logger.error(f"[{LogOp.ROADBLOCK}] Resolved seed path does not exist: {resolved_seed_path}")
                return None, None, None

            global output_dir
            shutil.copy2(resolved_seed_path, tseed_isi_path)

            # Build environment variables
            env = os.environ.copy()
            env['LD_LIBRARY_PATH'] = os.path.expanduser(
                "~/Desktop/autoframe/ipl-modeling/install/lib") + ':' + os.environ.get(
                'LD_LIBRARY_PATH', '')
            env['DFSAN_OPTIONS'] = "warn_unimplemented=0"
            env['TARGET_BRANCH'] = f'{os.path.basename(rb_file)}:{rb_line}'

            if taint_extraction_failures >= TAINT_EXTRACTION_FAILURE_THRESHOLD:
                logger.warning(
                    f"[{LogOp.ROADBLOCK}] Taint extraction disabled for this session after "
                    f"{taint_extraction_failures} consecutive failures"
                )
                return None, None, None

            # ========== Phase 1: Run cmd_extract to generate .isi.json ==========
            cmd_extract = [
                IPL_TARGET_PATH,
                tseed_isi_path
            ]
            subprocess.run(cmd_extract, env=env, stderr=subprocess.DEVNULL)

            # Check if .isi.json was generated
            isi_json_path = tseed_isi_json_path
            if not os.path.exists(isi_json_path):
                logger.error(f"cmd_extract failed to generate {isi_json_path}")
                taint_extraction_failures += 1
                return None, None, None
            taint_extraction_failures = 0

            fields = None  # 初始化 fields

            # ========== Phase 2: Run test.py with .isi.json to generate result.json (可选) ==========
            if enable_semantic_parsing:
                logger.info(f"[{LogOp.ROADBLOCK}] Running semantic field parsing (test.py)")
                fields = build_semantic_fields(
                    project=PROJECT,
                    seed_path=resolved_seed_path,
                    isi_json_path=isi_json_path,
                    out_path=result_json_path,
                    harness_code=get_harness_code(),
                )
                if fields:
                    logger.debug(
                        f"[{LogOp.ROADBLOCK}] Loaded result.json with {len(fields.get('fields', []))} fields")
                    if 'error' in fields:
                        logger.error(f"[{LogOp.ROADBLOCK}] semantic field provider reported error: {fields.get('error')}")
                        fields = None
                else:
                    logger.warning(
                        f"[{LogOp.ROADBLOCK}] semantic field parsing failed to generate result.json, continuing without semantic fields")
            else:
                logger.info(
                    f"[{LogOp.ROADBLOCK}] Skipping semantic field parsing (test.py), using taint-based ranges only")

            # ========== Phase 3: Run cmd_extract again for taint analysis ==========
            env['BRANCH_FIELD_EXPORT'] = relevant_field_json_path.as_posix()
            # 只有在有 result.json 时才设置 FIELD_CONFIG_FILE
            if fields and os.path.exists(result_json_path):
                env['FIELD_CONFIG_FILE'] = result_json_path.as_posix()

            subprocess.run(cmd_extract, env=env, stderr=subprocess.DEVNULL)
            if not os.path.exists(relevant_field_json_path):
                logger.error(f"[{LogOp.ROADBLOCK}] cmd_extract failed to generate relevant_field.json")
                taint_extraction_failures += 1
                return None, None, None
            taint_extraction_failures = 0
            with open(relevant_field_json_path, 'r') as f:
                rel_json = ujson.load(f)
            return rel_json['branches'][0], resolved_seed_path.name, fields

        ranked_seed_names = tracer.select_seed_names_for_roadblock(roadblock, seed_names=seeds, max_seeds=max(1, min(8, len(seeds))))
        seed = ranked_seed_names[0] if ranked_seed_names else None
        if ranked_seed_names:
            logger.info(f"[{LogOp.ROADBLOCK}] Ranked roadblock seeds: {ranked_seed_names[:5]}")

        relevant_info = None
        orig = None
        fields = None  # 初始化 fields
        if ranked_seed_names:
            # 语义字段解析仍保留白名单行为；Path A/B 的尝试资格由后续策略统一判定
            enable_semantic = PROJECT in ENABLE_FIELD_PARSING or has_semantic_field_provider(PROJECT)
            for candidate_seed in ranked_seed_names:
                seed = candidate_seed
                relevant_info, orig, fields = process_relevant_fields(seed, enable_semantic_parsing=enable_semantic)
                if orig is not None:
                    logger.info(f"[{LogOp.ROADBLOCK}] Selected best-ranked seed for downstream paths: {seed}")
                    break
            if route_preferences['defer_for_more_evidence']:
                richer_evidence = collect_additional_roadblock_evidence(
                    roadblock,
                    code_slice,
                    PROJECT,
                    llm_util=llm_util,
                    call_chains=call_chains,
                    selected_call_chain=call_chain,
                    slice_line=slice_line,
                    selected_seed=seed,
                )
                supplemental_evidence.update(richer_evidence)
                supplemental_state_hints = list(dict.fromkeys(supplemental_state_hints + (richer_evidence.get('state_hints') or [])))
                if richer_evidence.get('replacement_code_slice'):
                    code_slice = richer_evidence['replacement_code_slice']
                if richer_evidence.get('harness_code'):
                    supplemental_harness_code = richer_evidence['harness_code']
                    route_preferences['allow_direct_generation'] = True
                if richer_evidence.get('evidence_boost'):
                    route_preferences['evidence_score'] = min(
                        1.0,
                        route_preferences['evidence_score'] + richer_evidence['evidence_boost'],
                    )
                if richer_evidence.get('coverage_diagnosis_context'):
                    summary = (
                        f"{summary}\n\nSupplemental coverage diagnosis:\n"
                        f"{richer_evidence['coverage_diagnosis_context'][:1200]}"
                    )

        path_ab_policy = derive_path_ab_policy(
            PROJECT,
            route_preferences,
            seed,
            relevant_info,
            cached_format_info=cached_format_info,
        )
        harness_for_mode = supplemental_harness_code
        if not harness_for_mode:
            try:
                harness_for_mode = get_harness_code()
            except Exception:
                harness_for_mode = None
        generation_mode = infer_input_generation_mode(code_slice, harness_for_mode)
        prefer_direct_text_generation = generation_mode == "text_direct"
        text_direct_attempted = False
        force_direct_llm_generation = should_force_direct_llm_generation(
            fields=fields,
            harness_code=harness_for_mode,
        )

        if force_direct_llm_generation:
            generation_mode = "text_direct"
            prefer_direct_text_generation = True
            route_preferences['allow_direct_generation'] = True
            route_preferences['prefer_batch_mutation'] = False
            route_preferences['prefer_input_mutation'] = False
            route_preferences['prefer_state_guided'] = False
            path_ab_policy['path_ab_enabled'] = False
            path_ab_policy['path_a_enabled'] = False
            path_ab_policy['path_b_enabled'] = False
            path_ab_policy['auto_enabled'] = False
            path_ab_policy['reason'] = 'xml_force_direct_llm'
            logger.info(
                f"[{LogOp.ROADBLOCK}] XML/text target detected; keeping Path T-1, "
                f"skipping Path A/B/D, and falling through to direct generation"
            )

        def attempt_text_mutation(*, terminal_on_failure: bool):
            logger.info(f"[{LogOp.ROADBLOCK}] Path T-1: Trying lightweight text mutation before direct generation")
            solved, candidate_path = try_text_mutation(
                code_slice,
                constraints,
                bcode,
                llm_util,
                seed_name=seed,
                fields=fields,
                harness_code=harness_for_mode,
                roadblock=roadblock,
                call_chain=call_chain,
            )
            if solved:
                logger.info(
                    f"[{LogOp.ROADBLOCK}] Path T-1 produced a locally validated seed via lightweight text mutation"
                )
                seed_match = re.search(r'id:(\d+)', Path(candidate_path).name) if candidate_path else None
                mutated_seed_id = int(seed_match.group(1)) if seed_match else -1
                mark_roadblock_resolved(roadblock_key, "TEXT_MUTATION")
                return True, "TEXT_MUTATION", mutated_seed_id, roadblock_id

            if candidate_path:
                logger.info(
                    f"[{LogOp.ROADBLOCK}] Path T-1 produced candidate(s) but no local gain; "
                    f"continuing to direct text generation"
                )
            else:
                logger.info(f"[{LogOp.ROADBLOCK}] Path T-1 could not produce viable text mutation candidates")

            if terminal_on_failure:
                mark_roadblock_failed(roadblock_key, "NO_LOCAL_TARGET_HIT", roadblock)
                return False, "text mutation generated but local validation failed", -1, roadblock_id
            return None

        def attempt_direct_text_generation(*, terminal_on_failure: bool):
            nonlocal text_direct_attempted
            text_direct_attempted = True
            route_preferences['allow_direct_generation'] = True
            logger.info(f"[{LogOp.ROADBLOCK}] Path T0: Trying direct text generation before heavier paths")

            llm_target_path = Path(output_dir) / "LLM" / "queue"
            os.makedirs(llm_target_path, exist_ok=True)
            local_seed_id = len(os.listdir(llm_target_path))
            local_harness_code = supplemental_harness_code
            if not local_harness_code and using_fallback_slice:
                local_harness_code = get_harness_code()

            generation_messages = build_direct_text_generation_messages(
                code_slice,
                constraints,
                summary,
                fields=fields,
                target_branch=bcode,
                state_hints=state_hints,
                harness_code=local_harness_code,
                preferred_seed=seed,
            )
            _log_full_prompt_messages("Path T0 text_direct prompt", generation_messages)

            attempt = 0
            while attempt < MAX_TIME:
                resp = llm_util.get_response(generation_messages)
                generated_text = extract_direct_text_payload(resp)
                if not generated_text:
                    append_llm_retry_feedback(
                        generation_messages,
                        resp,
                        "未提取到可写入 seed 文件的文本内容。请只返回 <generated_input>...</generated_input> 包裹的 seed 文本。"
                    )
                    attempt += 1
                    continue

                seed_path = os.path.join(llm_target_path, f"id:{int(local_seed_id):06},bid:{int(roadblock_id):06}")
                with open(seed_path, 'w', encoding='utf-8') as f:
                    f.write(generated_text)
                logger.info(f"[{LogOp.ROADBLOCK}] Path T0: Text seed written to {seed_path}")
                gate_result, eval_result = gate_seed(seed_path, roadblock=roadblock, call_chain=call_chain)
                logger.info(
                    f"[SEED_GATE] Path T0 text decision={gate_result.decision} accepted={gate_result.accepted} "
                    f"reason={gate_result.reason}"
                )
                local_progress = gate_result.accepted and _seed_eval_indicates_local_progress(eval_result)
                if local_progress:
                    logger.info(
                        f"[{LogOp.ROADBLOCK}] Path T0 produced a locally validated seed via direct text generation"
                    )
                    mark_roadblock_resolved(roadblock_key, "LLM_TEXT")
                    return True, "LLM_TEXT", local_seed_id, roadblock_id

                append_llm_retry_feedback(
                    generation_messages,
                    resp,
                    "该文本输入没有带来新的覆盖。请继续生成更短、更直接、更贴近目标分支状态的文本输入。"
                )
                attempt += 1

            if terminal_on_failure:
                mark_roadblock_failed(roadblock_key, "NO_LOCAL_TARGET_HIT", roadblock)
                return False, "LLM text generated but local validation failed", local_seed_id, roadblock_id
            logger.info(
                f"[{LogOp.ROADBLOCK}] Path T0: Direct text generation exhausted without local gain; "
                f"continuing to heavier paths"
            )
            return None

        if prefer_direct_text_generation:
            mutation_result = attempt_text_mutation(terminal_on_failure=False)
            if mutation_result is not None:
                return mutation_result
            direct_result = attempt_direct_text_generation(terminal_on_failure=False)
            if direct_result is not None:
                return direct_result

        # ========== 路径 2 & 3: 污点分析和通用求解（级联尝试）==========
        # 新逻辑：
        # - 路径 A: 如果 relevant_info 存在且有 ranges，使用 mutate_suggest_with_taint（老的 prompt）
        # - 路径 B: 如果路径A失败或没有 ranges，尝试 mutate_suggest_without_taint
        # - 路径 C: 如果路径B也失败，尝试 generate_script（原来的路径3）
        # 一旦某个路径成功就退出

        if path_ab_policy['auto_enabled']:
            logger.info(
                f"[{LogOp.ROADBLOCK}] Project '{PROJECT}' not in ENABLE_FIELD_PARSING, "
                f"but Path A/B auto-enabled ({path_ab_policy['reason']})")
        elif not path_ab_policy['path_ab_enabled']:
            logger.info(
                f"[{LogOp.ROADBLOCK}] Project '{PROJECT}' not in ENABLE_FIELD_PARSING, "
                f"skipping Path A/B, using Path C directly ({path_ab_policy['reason']})")
        # 尝试路径 A: 有污点分析数据且有 ranges
        elif path_ab_policy['path_a_enabled'] and route_preferences['prefer_input_mutation']:
            logger.info(f"[{LogOp.ROADBLOCK}] Path A: Taint analysis with ranges - using mutate_suggest_with_taint")
            MUT_TARGET_PATH = Path(output_dir) / "mut" / "queue"
            os.makedirs(MUT_TARGET_PATH, exist_ok=True)
            seed_id = len(os.listdir(MUT_TARGET_PATH))
            orig = seed  # Use original seed for mutation
            field = relevant_info['fields']
            byte_range = relevant_info['ranges']
            byte_range[0]['end'] = str(int(byte_range[0]['end']) - 1)

            times = 0
            path_succeeded = False
            while times < MAX_TIME and not path_succeeded:
                try:
                    logger.debug(f"[{LogOp.ROADBLOCK}] Path A: Mutation attempt {times + 1}/{MAX_TIME}")
                    suggestions = mutate_suggest_with_taint(code_slice, constraints, field if field else "", byte_range,
                                                            llm_util,
                                                            pattern_json)
                    if not suggestions['passable']:
                        logger.debug(f"[{LogOp.ROADBLOCK}] Path A: Mutation unsatisfiable, will try other paths")
                        break  # 路径A失败，跳出并尝试路径B

                    logger.info(f"[{LogOp.ROADBLOCK}] Path A: Starting mutation script generation")
                    script = get_mutate_script(
                        suggestions['input_modifications'],
                        llm_util,
                        fields=fields,
                        harness_code=harness_for_mode,
                        preferred_seed=orig,
                    )
                    if not script:
                        logger.debug(f"[{LogOp.ROADBLOCK}] Path A: Script generation failed, retrying")
                        times += 1
                        continue

                    logger.info(f"[{LogOp.ROADBLOCK}] Path A: Starting mutation script testing")
                    solved, script, dest_file = mutate_and_test(
                        llm_util,
                        script,
                        seed_id,
                        orig,
                        fuzzer,
                        tracer,
                        roadblock=roadblock,
                        call_chain=call_chain,
                    )
                    if solved:
                        logger.info(
                            f"[{LogOp.ROADBLOCK}] Path A produced a locally validated seed via mutate_suggest_with_taint")
                        mark_roadblock_resolved(roadblock_key, "MUT_TAINT")
                        return True, "MUT_TAINT", seed_id, roadblock_id
                    else:
                        logger.debug(
                            f"[{LogOp.ROADBLOCK}] Path A: Tested but coverage not gained, will try other paths")
                        break  # 路径A未获得覆盖，跳出并尝试路径B
                except ScriptNotFoundError:
                    logger.debug(f"[{LogOp.ROADBLOCK}] Path A: ScriptNotFoundError, retrying")
                    times += 1
                except ScriptExtractError:
                    logger.debug(f"[{LogOp.ROADBLOCK}] Path A: ScriptExtractError, retrying")
                    times += 1
                except Exception as e:
                    logger.error(f"[{LogOp.ROADBLOCK}] Path A error: {str(e)}, will try other paths")
                    break

        # ========== Path B: 状态驱动语义增强 (替代原有 mutate_suggest_without_taint) ==========
        # 白名单项目保留原有语义增强能力；其他项目在有足够证据时允许自动尝试 parser-free Path B
        # 方法: 代码分析 + LLM 推断 + 格式规范
        if not path_ab_policy['path_b_enabled']:
            logger.info(
                f"[{LogOp.ROADBLOCK}] Path B: Skipped ({path_ab_policy['reason']})")
        else:
            logger.info(f"[{LogOp.ROADBLOCK}] Path B: State-driven semantic enhancement")

            MUT_TARGET_PATH = Path(output_dir) / "mut" / "queue"
            os.makedirs(MUT_TARGET_PATH, exist_ok=True)
            seed_id = len(os.listdir(MUT_TARGET_PATH))

            # ========== 尝试状态驱动映射 ==========
            state_mapper = None
            # 只有当 seed 存在时才能进行状态驱动映射分析
            if ENABLE_STATE_DRIVEN_PATH_B and seed is not None and route_preferences['prefer_state_guided']:
                try:
                    from state_driven_mapper import StateDrivenMapper
                    state_mapper = StateDrivenMapper(llm_util)

                    # 准备样本种子路径
                    sample_seed_path = Path(output_dir) / 'default' / 'queue' / seed

                    # 准备污点信息 (如果有)
                    taint_info = None
                    if relevant_info and relevant_info.get('ranges'):
                        taint_info = {'branches': [relevant_info]}

                    # 准备格式信息
                    known_format_info = {'format_info': cached_format_info} if cached_format_info else None

                    logger.info(f"[{LogOp.ROADBLOCK}] Path B: Running state-driven mapping analysis")

                    # 执行状态驱动映射分析
                    mapping_result = state_mapper.analyze(
                        code_slice=code_slice,
                        roadblock=roadblock,
                        sample_seed_path=sample_seed_path,
                        taint_info=taint_info,
                        known_format_info=known_format_info
                    )

                    if mapping_result and mapping_result.get('state_mappings'):
                        num_mappings = len(mapping_result['state_mappings'])
                        logger.info(f"[{LogOp.ROADBLOCK}] Path B: State-driven mapping found {num_mappings} fields")

                        # 记录映射摘要
                        for m in mapping_result['state_mappings'][:5]:
                            spec_marker = " [SPEC]" if m.get('from_spec') else ""
                            logger.debug(f"[{LogOp.ROADBLOCK}]   "
                                         f"offset {m['input_offset']}: {m['state_variable']}{spec_marker}")

                        # 生成变异脚本
                        script = state_mapper.generate_mutation_script(
                            mappings=mapping_result,
                            constraints=constraints,
                            output_path=MUT_TMP_PATH / f"state_{roadblock_id}"
                        )

                        if script:
                            # 提取并测试脚本
                            script = extract_generator(script)
                            logger.info(f"[{LogOp.ROADBLOCK}] Path B: Testing state-driven mutation")

                            try:
                                solved, script, dest_file = mutate_and_test(
                                    llm_util,
                                    script,
                                    seed_id,
                                    orig if orig else seed,
                                    fuzzer,
                                    tracer,
                                    roadblock=roadblock,
                                    call_chain=call_chain,
                                )

                                if solved:
                                    logger.info(
                                        f"[{LogOp.ROADBLOCK}] Path B produced a locally validated seed "
                                        f"via state-driven mapping"
                                    )
                                    mark_roadblock_resolved(roadblock_key, "STATE_DRIVEN")
                                    return True, "STATE_DRIVEN", seed_id, roadblock_id
                                else:
                                    logger.info(
                                        f"[{LogOp.ROADBLOCK}] Path B: State-driven tested but coverage not gained")
                            except (ScriptNotFoundError, ScriptExtractError) as e:
                                logger.warning(
                                    f"[{LogOp.ROADBLOCK}] Path B: State-driven script error: {e}, will try fallback")
                    else:
                        logger.info(f"[{LogOp.ROADBLOCK}] Path B: State-driven mapping produced no results")

                except Exception as e:
                    logger.warning(f"[{LogOp.ROADBLOCK}] Path B: State-driven mapping failed: {e}", exc_info=True)
                    # 继续回退逻辑

                # ========== 回退 1: 原有 Path B (Kaitai fields) ==========
                if fields is not None and (route_preferences['input_score'] >= 0.3 or route_preferences['evidence_score'] < 0.55):
                    logger.info(f"[{LogOp.ROADBLOCK}] Path B: Fallback to Kaitai-based Path B")

                    times = 0
                    path_succeeded = False
                    while times < MAX_TIME and not path_succeeded:
                        try:
                            logger.debug(
                                f"[{LogOp.ROADBLOCK}] Path B: Fallback mutation attempt {times + 1}/{MAX_TIME}")

                            suggestions = mutate_suggest_without_taint(code_slice, fields, bcode,
                                                                       llm_util,
                                                                       pattern_json)
                            if not suggestions['passable']:
                                logger.debug(
                                    f"[{LogOp.ROADBLOCK}] Path B: Fallback mutation unsatisfiable, will try path C")
                                break

                            # ========== 利用间接推理信息调整策略 ==========
                            confidence = suggestions.get('confidence', 'medium')
                            inference_types = suggestions.get('inference_types', [])

                            # 记录推理类型信息
                            has_indirect = any(it.startswith('indirect') for it in inference_types)
                            if has_indirect:
                                logger.info(
                                    f"[{LogOp.ROADBLOCK}] Path B: Fallback using indirect inference (types={inference_types}, confidence={confidence})")
                                # 更新统计信息
                                inference_stats['indirect_attempts'] += 1
                            else:
                                logger.info(
                                    f"[{LogOp.ROADBLOCK}] Path B: Fallback using direct evidence (confidence={confidence})")

                            # 根据 confidence 决定最大尝试次数
                            if confidence == 'low':
                                # 低置信度也继续保留探索空间，不再单次失败就切走
                                max_attempts_for_this = MAX_TIME
                                logger.info(
                                    f"[{LogOp.ROADBLOCK}] Path B: Fallback low confidence mode - keeping iterative exploration enabled")
                            elif confidence == 'medium':
                                # 中等置信度：正常尝试
                                max_attempts_for_this = MAX_TIME
                            else:  # high
                                # 高置信度：正常尝试
                                max_attempts_for_this = MAX_TIME

                            # 检查是否已超过该 confidence 级别的最大尝试次数
                            if times >= max_attempts_for_this:
                                logger.info(
                                    f"[{LogOp.ROADBLOCK}] Path B: Fallback reached max attempts ({max_attempts_for_this}) for confidence={confidence}, will try path C")
                                break
                            # ========== 间接推理策略调整结束 ==========

                            logger.info(f"[{LogOp.ROADBLOCK}] Path B: Fallback starting mutation script generation")
                            script = get_mutate_script(
                                suggestions['input_modifications'],
                                llm_util,
                                fields=fields,
                                harness_code=harness_for_mode,
                                preferred_seed=seed,
                            )
                            if not script:
                                logger.debug(f"[{LogOp.ROADBLOCK}] Path B: Fallback script generation failed, retrying")
                                times += 1
                                continue

                            logger.info(f"[{LogOp.ROADBLOCK}] Path B: Fallback starting mutation script testing")
                            solved, script, dest_file = mutate_and_test(
                                llm_util,
                                script,
                                seed_id,
                                orig if orig else seed,
                                fuzzer,
                                tracer,
                                roadblock=roadblock,
                                call_chain=call_chain,
                            )
                            if solved:
                                # 成功时更新统计
                                if has_indirect:
                                    inference_stats['indirect_successes'] += 1
                                    mode_suffix = "_INDIRECT"
                                    logger.info(
                                        f"[{LogOp.ROADBLOCK}] Path B fallback succeeded with INDIRECT inference (types={inference_types})")
                                else:
                                    mode_suffix = "_DIRECT"
                                    logger.info(f"[{LogOp.ROADBLOCK}] Path B fallback succeeded with DIRECT evidence")
                                logger.info(
                                    f"[{LogOp.ROADBLOCK}] Path B fallback produced a locally validated seed "
                                    f"via mutate_suggest_without_taint (confidence={confidence})")
                                return True, f"FALLBACK_B{mode_suffix}", seed_id, roadblock_id
                            else:
                                logger.debug(
                                    f"[{LogOp.ROADBLOCK}] Path B: Fallback tested but coverage not gained, will try path C")
                                break
                        except ScriptNotFoundError:
                            logger.debug(f"[{LogOp.ROADBLOCK}] Path B: Fallback ScriptNotFoundError, retrying")
                            times += 1
                        except ScriptExtractError:
                            logger.debug(f"[{LogOp.ROADBLOCK}] Path B: Fallback ScriptExtractError, retrying")
                            times += 1
                        except Exception as e:
                            logger.error(f"[{LogOp.ROADBLOCK}] Path B: Fallback error: {str(e)}, will try path C")
                            break

        # 如果到这里还没成功，继续到 Path C (原有逻辑)
        logger.info(f"[{LogOp.ROADBLOCK}] Path B exhausted, proceeding to path C")

        # 尝试路径 D: 批量变异（三步突破：branch_analysis -> mutator_rule_gen -> mutate_batch_script_gen）
        logger.info(f"[{LogOp.ROADBLOCK}] Path D: Trying batch mutation process (three-step breakthrough)")
        if PROJECT not in ENABLE_FIELD_PARSING:
            logger.info(
                f"[{LogOp.ROADBLOCK}] Path D: Project '{PROJECT}' has no structure-parsing enhancement; "
                f"continuing in parser-free mode")
        try:
            if not route_preferences['prefer_batch_mutation']:
                raise RuntimeError("batch mutation deprioritized by route scoring")
            # 获取target branch和status
            target_branch = bcode
            target_side = "true" if roadblock['status'] else "false"

            # 识别input_source（可复用Path A/B的数据）
            input_source = identify_input_source(code_slice)
            logger.info(f"[{LogOp.ROADBLOCK}] Path D: Identified input source: {input_source}")

            # Step 1: Branch Analysis
            logger.info(f"[{LogOp.ROADBLOCK}] Path D: Step 1 - Running branch_analysis")
            branch_analysis_result = run_branch_analysis(code_slice, target_branch, input_source, llm_util)
            if not branch_analysis_result or not branch_analysis_result.get('passable', False):
                logger.warning(
                    f"[{LogOp.ROADBLOCK}] Path D: Step 1 - Branch analysis failed or not passable, will try path C")
            else:
                logger.info(f"[{LogOp.ROADBLOCK}] Path D: Step 1 - Branch analysis completed, passable=True")
                logger.debug(
                    f"[{LogOp.ROADBLOCK}] Path D: Branch type: {branch_analysis_result.get('branch_type', 'unknown')}")

                # Step 2: Mutator Rule Generation
                logger.info(f"[{LogOp.ROADBLOCK}] Path D: Step 2 - Running mutator_rule_gen")
                mutator_rule = run_mutator_rule_gen(branch_analysis_result, target_side, llm_util)
                if not mutator_rule or not mutator_rule.get('edits'):
                    logger.warning(
                        f"[{LogOp.ROADBLOCK}] Path D: Step 2 - Mutator rule generation failed, will try path C")
                else:
                    logger.info(
                        f"[{LogOp.ROADBLOCK}] Path D: Step 2 - Mutator rule generated with {len(mutator_rule['edits'])} edit(s)")
                    logger.debug(f"[{LogOp.ROADBLOCK}] Path D: Min size: {mutator_rule.get('min_size', 0)}")

                    # Step 3: Batch Mutation Script Generation
                    logger.info(f"[{LogOp.ROADBLOCK}] Path D: Step 3 - Running mutate_batch_script_gen")
                    seed_dir = os.path.join(output_dir, 'default', 'queue')
                    branch_id = mutator_rule.get("branch_id") or "llm_mut"
                    branch_work_dir = config.get_branch_output_dir(branch_id)
                    batch_out_dir = config.get_branch_queue_dir(branch_id)
                    manifest_dir = branch_work_dir
                    filtered_seed_dir = config.get_batch_mutation_filtered_seed_dir(branch_id)
                    filtered_seed_dir, filtered_seed_count = create_batch_mutation_seed_dir(seed_dir, filtered_seed_dir)
                    logger.info(
                        f"[{LogOp.ROADBLOCK}] Path D: Filtered batch mutation inputs to "
                        f"{filtered_seed_count} id-prefixed files from default queue")
                    Path(batch_out_dir).mkdir(parents=True, exist_ok=True)
                    Path(manifest_dir).mkdir(parents=True, exist_ok=True)

                    batch_script = run_mutate_batch_script_gen(
                        mutator_rule,
                        filtered_seed_dir,
                        os.fspath(batch_out_dir),
                        os.fspath(manifest_dir),
                        llm_util,
                    )
                    if not batch_script:
                        shutil.rmtree(filtered_seed_dir, ignore_errors=True)
                        logger.warning(
                            f"[{LogOp.ROADBLOCK}] Path D: Step 3 - Batch script generation failed, will try path C")
                    else:
                        # 保存批量变异脚本到PROJECT目录下（固定名称，便于管理）
                        script_path = config.get_batch_mutation_script_path(branch_id)
                        script_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(script_path, 'w') as f:
                            f.write(batch_script)

                        logger.info(f"[{LogOp.ROADBLOCK}] Path D: Step 3 - Executing batch mutation script")
                        result = subprocess.run(
                            ['python3', os.fspath(script_path), filtered_seed_dir, os.fspath(batch_out_dir), os.fspath(manifest_dir)],
                            capture_output=True,
                            text=True,
                            timeout=300
                        )
                        shutil.rmtree(filtered_seed_dir, ignore_errors=True)

                        if result.returncode != 0:
                            logger.error(
                                f"[{LogOp.ROADBLOCK}] Path D: Step 3 - Script execution failed: {result.stderr}")
                        else:
                            logger.info(f"[{LogOp.ROADBLOCK}] Path D: Step 3 - Batch mutation completed")
                            logger.debug(
                                f"[{LogOp.ROADBLOCK}] Path D: Output: {result.stdout[:500] if result.stdout else ''}")

                            # Count and test generated files
                            if os.path.exists(batch_out_dir):
                                mutated_files = [f for f in os.listdir(batch_out_dir) if not f.startswith('.')]
                                logger.info(
                                    f"[{LogOp.ROADBLOCK}] Path D: Generated {len(mutated_files)} mutated seeds")

                                sampled_files = sorted(mutated_files)[: min(8, len(mutated_files))]
                                coverage_gained = False
                                test_seed_id = -1
                                accepted_sample_count = 0
                                for test_file in sampled_files:
                                    sample_path = os.path.join(batch_out_dir, test_file)
                                    gate_result, eval_result = gate_seed(sample_path, roadblock=roadblock, call_chain=call_chain)
                                    logger.info(
                                        f"[SEED_GATE] Path D sample={test_file} decision={gate_result.decision} "
                                        f"accepted={gate_result.accepted} reason={gate_result.reason}"
                                    )
                                    if not gate_result.accepted:
                                        continue
                                    accepted_sample_count += 1
                                    match = re.search(r'id:(\d+)', test_file)
                                    if match:
                                        test_seed_id = int(match.group(1))
                                        gained = _seed_eval_indicates_local_progress(eval_result)
                                        if gained:
                                            coverage_gained = True
                                            logger.info(
                                                f"[{LogOp.ROADBLOCK}] Path D: Sampled mutated seed produced local hit evidence: {test_file}")
                                            break

                                if accepted_sample_count == 0:
                                    logger.info(f"[{LogOp.ROADBLOCK}] Path D: No sampled mutated seeds passed SeedGate")

                                if coverage_gained:
                                    logger.info(
                                        f"[{LogOp.ROADBLOCK}] Path D produced a locally validated seed via batch mutation")
                                    mark_roadblock_resolved(roadblock_key, "BATCH_MUTATE")
                                    return True, "BATCH_MUTATE", test_seed_id, roadblock_id

        except subprocess.TimeoutExpired:
            logger.warning(f"[{LogOp.ROADBLOCK}] Path D: Script execution timeout, will try path C")
        except Exception as e:
            logger.warning(f"[{LogOp.ROADBLOCK}] Path D error: {str(e)}, will try path C")

        # 尝试路径 C: generate_script（原来的路径3）
        # 即使前面的判定更偏向 state-guided，只要 Path D 已经失败，仍允许用 Path C 做最后兜底。
        # Path D 和 Path C 的能力边界并不完全相同：批量定向变异失败，不代表直接生成一定无效。
        if state_guided_only or not should_generate_input:
            logger.warning(
                f"[{LogOp.ROADBLOCK}] State-guided workflow preferred for roadblock {roadblock_id}, "
                f"but Path D did not resolve it; falling back to direct generate_script"
            )

        if not route_preferences['allow_direct_generation']:
            logger.warning(
                f"[{LogOp.ROADBLOCK}] Direct generation deprioritized by route scoring for roadblock {roadblock_id}; "
                f"stopping after mutation/state-guided attempts"
            )
            mark_roadblock_failed(roadblock_key, "DIRECT_GENERATION_DEPRIORITIZED", roadblock)
            return False, "direct generation deprioritized", -1, roadblock_id

        logger.info(
            f"[{LogOp.ROADBLOCK}] Path C: Trying "
            f"{'direct text generation' if generation_mode == 'text_direct' else 'script generation'}")
        if generation_mode == "text_direct" and text_direct_attempted:
            logger.info(
                f"[{LogOp.ROADBLOCK}] Path C: Skipping duplicate direct text generation because Path T0 already exhausted"
            )
            mark_roadblock_failed(roadblock_key, "ALL_PATHS_FAILED", roadblock)
            return False, "", -1, roadblock_id
        LLM_TARGET_PATH = Path(output_dir) / "LLM" / "queue"
        os.makedirs(LLM_TARGET_PATH, exist_ok=True)
        seed_id = len(os.listdir(LLM_TARGET_PATH))
        # if test:
        #     pass_roadblock[roadblock_key] = {"roadblock": roadblock, "timestamp": time.time()}
        #     pass_roadblock_id[roadblock_key] = time.time()
        #     return False, "skip while test", -1, roadblock_id

        # 记录可用的补充信息
        if fields:
            logger.info(
                f"[{LogOp.ROADBLOCK}] Path C: Using semantic fields info ({len(fields.get('fields', []))} fields)")
        if bcode:
            logger.info(f"[{LogOp.ROADBLOCK}] Path C: Using target branch code")

        logger.info(f"[{LogOp.ROADBLOCK}] Path C: Starting Python script generation (max {MAX_TIME} attempts)")

        # ========== NEW: For fallback slice mode, get harness code ==========
        harness_code = supplemental_harness_code
        if harness_code:
            logger.info(f"[{LogOp.ROADBLOCK}] Path C: Reusing supplemental harness code ({len(harness_code)} chars)")
        elif using_fallback_slice:
            logger.info(f"[{LogOp.ROADBLOCK}] Fallback slice mode: Extracting harness code (main + LLVMFuzzerTestOneInput)")
            harness_code = get_harness_code()
            if harness_code:
                logger.info(f"[{LogOp.ROADBLOCK}] Harness code extracted: {len(harness_code)} chars")
            else:
                logger.warning(f"[{LogOp.ROADBLOCK}] Failed to extract harness code, proceeding without it")
        # ========== End harness code extraction ==========

        if generation_mode == "text_direct":
            generation_messages = build_direct_text_generation_messages(
                code_slice,
                constraints,
                summary,
                fields=fields,
                target_branch=bcode,
                state_hints=state_hints,
                harness_code=harness_code,
                preferred_seed=seed,
            )
        else:
            generation_messages = build_generate_script_messages(
                code_slice,
                constraints,
                summary,
                fields=fields,
                target_branch=bcode,
                state_hints=state_hints,
                harness_code=harness_code,
                preferred_seed=seed,
            )
        logger.info(
            f"[{LogOp.ROADBLOCK}] Final code_slice for Path C "
            f"(mode={generation_mode}, chars={len(code_slice) if code_slice else 0})\n"
            f"{code_slice or ''}"
        )
        _log_full_prompt_messages(f"Path C {generation_mode} prompt", generation_messages)
        times = 0
        while times < MAX_TIME:
            try:
                logger.debug(
                    f"[{LogOp.ROADBLOCK}] Path C: "
                    f"{'Text' if generation_mode == 'text_direct' else 'Script'} generation attempt "
                    f"{times + 1}/{MAX_TIME}")
                resp = llm_util.get_response(generation_messages)
                if generation_mode == "text_direct":
                    generated_text = extract_direct_text_payload(resp)
                    if not generated_text:
                        append_llm_retry_feedback(
                            generation_messages,
                            resp,
                            "未提取到可写入 seed 文件的文本内容。请只返回 <generated_input>...</generated_input> 包裹的 seed 文本。"
                        )
                        times += 1
                        continue

                    seed_path = os.path.join(LLM_TARGET_PATH, f"id:{int(seed_id):06},bid:{int(roadblock_id):06}")
                    with open(seed_path, 'w', encoding='utf-8') as f:
                        f.write(generated_text)
                    logger.info(f"[{LogOp.ROADBLOCK}] Path C: Text seed written to {seed_path}")
                    gate_result, eval_result = gate_seed(seed_path, roadblock=roadblock, call_chain=call_chain)
                    logger.info(
                        f"[SEED_GATE] Path C text decision={gate_result.decision} accepted={gate_result.accepted} "
                        f"reason={gate_result.reason}"
                    )
                    local_progress = gate_result.accepted and _seed_eval_indicates_local_progress(eval_result)
                    if local_progress:
                        logger.info(
                            f"[{LogOp.ROADBLOCK}] Path C produced a locally validated seed via direct text generation")
                        mark_roadblock_resolved(roadblock_key, "LLM_TEXT")
                        return True, "LLM_TEXT", seed_id, roadblock_id

                    fail_mode = eval_result.rejection_reason or "NO_NEW_EDGES"
                    mark_roadblock_failed(roadblock_key, fail_mode, roadblock)
                    logger.debug(f"[{LogOp.ROADBLOCK}] Path C: Generated text but local validation did not accept it")
                    return False, "LLM text generated but local validation failed", seed_id, roadblock_id

                match = extract_json_with_fallback(resp, pattern_json)
                if not match:
                    logger.debug(f"[{LogOp.LLM}] Path C: JSON pattern not found, requesting regeneration")
                    append_llm_retry_feedback(
                        generation_messages,
                        resp,
                        "返回内容中没有可解析的 JSON。请只返回一个 JSON object，并且必须包含字符串字段 generation_script。"
                    )
                    times += 1
                    continue
                try:
                    res = json.loads(match.group(1).strip())
                except json.JSONDecodeError as exc:
                    logger.warning(f"[{LogOp.LLM}] Path C: JSON parse failed: {exc}; requesting regeneration")
                    append_llm_retry_feedback(
                        generation_messages,
                        resp,
                        f"JSON 解析失败：{exc}。请只返回一个合法的 JSON object，并包含字符串字段 generation_script。"
                    )
                    times += 1
                    continue
                schema_error = validate_generation_result(res)
                if schema_error:
                    logger.warning(f"[{LogOp.LLM}] Path C: Invalid generation schema: {schema_error}; requesting regeneration")
                    append_llm_retry_feedback(
                        generation_messages,
                        resp,
                        f"返回结构不符合要求：{schema_error}。请只返回一个 JSON object，并且 generation_script 必须是 Python 脚本字符串。"
                    )
                    times += 1
                    continue
                res['library'] = PROJECT
                script = res['generation_script']
                if script:
                    logger.info(f"[{LogOp.ROADBLOCK}] Path C: Starting generated script testing")
                    solved, script, dest_file = extract_and_test(llm_util, script, roadblock_id, seed_id, tracer,
                                                                 fuzzer, roadblock=roadblock, call_chain=call_chain,
                                                                 code_slice=code_slice)
                    if solved:
                        logger.info(
                            f"[{LogOp.ROADBLOCK}] Path C produced a locally validated seed via generate_script")
                        mark_roadblock_resolved(roadblock_key, "LLM")
                        return True, "LLM", seed_id, roadblock_id
                    else:
                        mark_roadblock_failed(roadblock_key, "NO_LOCAL_TARGET_HIT", roadblock)
                        logger.debug(f"[{LogOp.ROADBLOCK}] Path C: Generated but local validation did not pass")
                        return False, "LLM generated but local validation failed", seed_id, roadblock_id
                else:
                    mark_roadblock_failed(roadblock_key, "PATH_C_NO_SCRIPT", roadblock)
                    return False, "", -1, roadblock_id
            except ScriptNotFoundError:
                logger.debug(f"[{LogOp.ROADBLOCK}] Path C: ScriptNotFoundError, retrying")
                times += 1
            except ScriptExtractError:
                logger.debug(f"[{LogOp.ROADBLOCK}] Path C: ScriptExtractError, retrying")
                times += 1
            except (KeyError, TypeError) as e:
                logger.debug(
                    f"[{LogOp.ROADBLOCK}] Path C: Response shape error {e} - retrying")
                times += 1

        mark_roadblock_failed(roadblock_key, "ALL_PATHS_FAILED", roadblock)
        return False, "", -1, roadblock_id

    mark_roadblock_failed(roadblock_key, "NO_ROADBLOCKS_REMAIN", roadblock)
    return False, "No roadblocks remain", -1, roadblock_id


# ============================================================
# 零覆盖分支处理辅助函数
# ============================================================

def is_text_input_library():
    """判断当前项目是否为文本输入型库"""
    return PROJECT in getattr(config, 'TEXT_INPUT_LIBS', [])


def infer_input_generation_mode(code_context: str = "", harness_code: str | None = None) -> str:
    """Infer whether the current seed should be generated as direct text or via a binary/script workflow."""
    context_parts = [PROJECT]
    if cached_format_info:
        for key in (
            'format_name',
            'format_description',
            'recommended_library',
            'structure_hints',
            'magic_bytes',
        ):
            value = cached_format_info.get(key)
            if value:
                context_parts.append(str(value))
        for key in ('key_fields', 'common_constraints'):
            value = cached_format_info.get(key)
            if value:
                context_parts.extend(str(item) for item in value)
    if code_context:
        context_parts.append(code_context)
    if harness_code:
        context_parts.append(harness_code)

    joined = "\n".join(context_parts).lower()

    text_format_keywords = (
        'xml', 'json', 'yaml', 'toml', 'ini', 'csv', 'sql', 'html', 'javascript',
        'source code', 'c source', 'text input', 'plain text', 'utf-8', 'ascii',
        'parser', 'yyparse', 'lex', 'token', 'document',
    )
    binary_format_keywords = (
        'magic bytes', 'png', 'jpeg', 'jpg', 'gif', 'bmp', 'wav', 'mp3', 'ogg',
        'zip', 'gzip', 'tar', 'elf', 'pe', 'mach-o', 'protobuf', 'pcap', 'pdf',
        'binary format', 'chunk', 'crc', 'checksum',
    )
    wrapper_binary_signals = (
        'llvmfuzzertestoneinput',
        'const uint8_t *data',
        'uint8_t *data',
        'data + ',
        'buf + ',
        'data[',
        'buf[',
        'size - ',
        'size < ',
    )

    if any(keyword in joined for keyword in binary_format_keywords):
        return "binary_script"

    if any(signal in joined for signal in wrapper_binary_signals) and any(
        keyword in joined for keyword in ('json', 'xml', 'text', 'parser', 'yyparse', 'token')
    ):
        return "binary_script"

    if any(keyword in joined for keyword in text_format_keywords):
        return "text_direct"

    if is_text_input_library() and not any(signal in joined for signal in wrapper_binary_signals):
        return "text_direct"

    return "binary_script"


def extract_direct_text_payload(response_text: str) -> str | None:
    """Extract direct text seed content from an LLM response."""
    if not response_text:
        return None

    raw = response_text.strip()
    if not raw:
        return None

    tagged_match = re.search(
        r"<generated_input>\s*(.*?)\s*</generated_input>",
        raw,
        re.DOTALL | re.IGNORECASE,
    )
    if tagged_match:
        payload = tagged_match.group(1)
        return payload.strip("\n")

    fenced_match = re.search(
        r"```(?:text|xml|html|sql|json|txt|yaml|toml|c)?\s*(.*?)```",
        raw,
        re.DOTALL | re.IGNORECASE,
    )
    if fenced_match:
        payload = fenced_match.group(1)
        return payload.strip("\n")

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

    return raw


def _looks_textual_semantic_input(fields=None, harness_code: str | None = None) -> bool:
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
        if str(item.get("kind", "")).lower() in text_kinds:
            return True
    if harness_code:
        joined = harness_code.lower()
        if any(keyword in joined for keyword in ("json", "xml", "yyparse", "javascript", "token", "parser")):
            return True
    return False


def should_force_direct_llm_generation(fields=None, harness_code: str | None = None) -> bool:
    if PROJECT == "xmllint":
        return True
    if not _looks_textual_semantic_input(fields=fields, harness_code=harness_code):
        return False
    if cached_format_info:
        format_name = str(cached_format_info.get("format_name", "")).lower()
        format_desc = str(cached_format_info.get("format_description", "")).lower()
        if "xml" in format_name or "xml" in format_desc:
            return True
    return False


def build_input_type_contract(generation_mode: str) -> str:
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


def collect_input_examples_context(
    generation_mode: str,
    preferred_seed: str | None = None,
    max_examples: int = 2,
    max_text_chars: int = 1200,
    max_binary_bytes: int = 64,
) -> str:
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


def summarize_semantic_fields(fields, max_fields: int = 12) -> str:
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
        parts = [f"name={name}", f"kind={kind}"]
        if path:
            parts.append(f"path={path}")
        if offset is not None and size is not None:
            parts.append(f"span=[{offset},{offset + size})")
        if role:
            parts.append(f"role={role}")
        parts.append(f"reliable={reliable}")
        lines.append("- " + ", ".join(parts))
    if len(field_items) > max_fields:
        lines.append(f"- ... ({len(field_items) - max_fields} more fields omitted)")
    return "\n".join(lines)


def build_semantic_fields_prompt_section(
    fields,
    max_fields: int = PROMPT_SEMANTIC_FIELDS_SAMPLE_LIMIT,
) -> str:
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
                compact_item[key] = _sanitize_semantic_field_value(item[key])
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
        sample_payload = {
            "sample_count": len(sample_fields),
            "omitted_count": max(0, len(field_items) - len(sample_fields)),
            "fields": sample_fields,
        }
        sections.extend([
            "<semantic_fields_sample>",
            json.dumps(sample_payload, ensure_ascii=False, separators=(",", ":")),
            "</semantic_fields_sample>",
        ])

    return "\n".join(sections) + "\n"


def _build_parser_free_text_fields(seed_name: str, harness_code: str | None = None) -> dict[str, Any] | None:
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
    if fields:
        return fields
    if seed_name:
        return _build_parser_free_text_fields(seed_name, harness_code=harness_code)
    return None


def build_input_container_profile(
    generation_mode: str,
    *,
    fields=None,
    harness_code: str | None = None,
    preferred_seed: str | None = None,
) -> str:
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


def build_parser_rich_generation_bias(
    generation_mode: str,
    *,
    preferred_seed: str | None = None,
    harness_code: str | None = None,
) -> str:
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


def extract_function_context(target, context_lines=30):
    """
    提取函数上下文（LLVM切片失败时的回退策略）：
    1. 函数签名在首位
    2. zero-branch 为中心的 ±30 行上下文
    3. 上下文的最前与最后边界为函数体本身的上下界
    """
    func = None
    for f in funcs:
        if f['name'] == target['function']:
            func = f
            break

    if not func:
        logger.error(f"[ZERO_COV] Function {target['function']} not found in static analysis")
        return None

    try:
        # 确定源文件路径
        if os.path.exists(SRC_BEAR_PATH / func['file_name']):
            src_file = SRC_BEAR_PATH / func['file_name']
        else:
            src_file = SRC_PATH / func['file_name']

        with open(src_file, 'r') as f:
            lines = f.readlines()

        # 构造结果：[函数签名] + [branch上下文]
        result = []

        # 1. 函数签名部分
        result.append(f"// === FUNCTION: {target['function']} ===\n")
        sig_end = min(func['lineStart'] + 5, len(lines) + 1)
        result.append(''.join(lines[func['lineStart']-1:sig_end]))
        result.append("\n// ... [middle code omitted]\n\n")

        # 2. zero-branch 为中心的 ±30 行（受函数体限制）
        branch_line = target['line']
        context_start = max(func['lineStart'], branch_line - context_lines)
        context_end = min(func['lineEnd'], branch_line + context_lines)

        result.append(f"// === BRANCH CONTEXT (line {branch_line}) ===\n")
        result.extend(lines[context_start-1:context_end])

        code_slice = ''.join(result)
        logger.info(f"[ZERO_COV] Extracted function context: {len(code_slice)} chars")
        logger.info(
            f"[ZERO_COV] Full extracted function context for {target['function']}:{branch_line}\n"
            f"{code_slice}"
        )
        return code_slice

    except Exception as e:
        logger.error(f"[ZERO_COV] Failed to extract function context: {e}")
        return None


def _lookup_func_meta_by_name(func_name: str) -> dict | None:
    for func in funcs:
        if func.get('name') == func_name:
            return func
    return None


def _describe_seed_delivery() -> str:
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
        return (
            "seed_delivery: stdin_stream\n"
            "important:\n"
            "- The generated seed is stored as a file by AFL, but replay/diagnosis must pipe that file's bytes to stdin.\n"
            "- Do not invent extra target argv options unless they already appear in target_args_template.\n"
            "- Prefer branches reached by parsing stdin token/content over generic help, usage, version, or option-parser paths."
        )
    if spec.delivery == "argv_file":
        return (
            "seed_delivery: argv_file_path\n"
            "important:\n"
            "- The generated seed is replayed by passing its file path to the target argv.\n"
            "- Do not invent extra target argv options unless they already appear in target_args_template."
        )
    return (
        "seed_delivery: direct_argv_or_stdin\n"
        "important:\n"
        "- Use the runtime command template to determine whether the seed affects file contents, argv payloads, or stdin.\n"
        "- Do not assume you can add extra target argv options unless they already appear in target_args_template."
    )


def _get_zero_cov_supporting_context(llm_util: LLMUtil) -> dict[str, str]:
    ensure_cached_format_info(llm_util)
    harness_code = get_harness_code() or ""
    format_section = ""
    if cached_format_info:
        format_section = InputFormatDetector.format_info_to_prompt_section(cached_format_info)
    return {
        "runtime_command_context": build_runtime_command_context(),
        "seed_delivery_context": _describe_seed_delivery(),
        "input_container_context": build_input_container_profile("binary_script", harness_code=harness_code),
        "format_context": format_section,
        "harness_code": harness_code,
    }


def _score_input_driven_call_chain(chain) -> tuple[int, int, int]:
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


def get_code_slice_with_fallback(target, tracer: CoverageTracer, llm_util: LLMUtil):
    """
    获取代码切片，带回退策略：
    1. 尝试标准 LLVM 切片
    2. 失败时使用函数上下文回退
    """
    # 策略 1: 尝试获取调用链并做 LLVM 切片
    call_chains = get_call_chain(target['function'])
    if call_chains:
        logger.info(f"[ZERO_COV] Found {len(call_chains)} call chains, attempting LLVM slice")
        # 使用 None 作为 only_side（零覆盖分支不关心方向）
        ranked_chains = sorted(call_chains, key=_score_input_driven_call_chain, reverse=True)
        best_chain = ranked_chains[0]
        logger.info(f"[ZERO_COV] Using best call chain: {format_call_chain(best_chain)}")
        logger.debug(
            f"[ZERO_COV] Best call chain score={_score_input_driven_call_chain(best_chain)}; "
            f"top_candidates={[format_call_chain(chain) for chain in ranked_chains[:3]]}"
        )
        code_slice = get_function_slice(best_chain, target['line'], None, llm_util)
        if code_slice and "No matching instruction found" not in code_slice:
            logger.info(f"[ZERO_COV] LLVM slice successful: {len(code_slice)} chars")
            return code_slice
        else:
            logger.warning(f"[ZERO_COV] LLVM slice failed or returned error")

    # 策略 2: 回退到函数上下文
    logger.info("[ZERO_COV] Falling back to function context extraction")
    code_slice = extract_function_context(target)
    if code_slice:
        return code_slice

    logger.error("[ZERO_COV] All slice strategies failed")
    return None


def analyze_reachability_constraints(target, code_slice, llm_util: LLMUtil):
    """
    分析到达零覆盖分支的可达性约束
    """
    logger.info(f"[ZERO_COV] Analyzing reachability constraints for {target['function']}:{target['line']}")

    # 构造 roadblock_info（复用现有格式）
    rb_info = {
        'filename': target['file'],
        'line': target['line'],
        'function': target['function'],
        'status': 'zero_covered',  # 特殊状态
    }

    # 添加代码信息
    if code_slice:
        rb_info['code'] = extract_branch_code_from_slice(code_slice, target['line'])

    # 使用专门的 analyze_zero_covered_branch prompt
    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"
    support_context = _get_zero_cov_supporting_context(llm_util)

    messages = [
        {'role': 'system',
         'content': prompts['prompt']['analyze_zero_covered_branch']['sys_prompt']},
        {'role': 'user',
         'content': get_formatted_user_prompt(
             'analyze_zero_covered_branch',
             filename=target['file'],
             line=target['line'],
             function=target['function'],
             code_slice=code_slice,
             runtime_command_context=support_context['runtime_command_context'],
             seed_delivery_context=support_context['seed_delivery_context'],
             format_context=support_context['format_context'] or "(unknown)",
             harness_code=support_context['harness_code'] or "(unavailable)",
         )}
    ]

    max_retries = 3
    for attempt in range(max_retries):
        try:
            resp = llm_util.get_response(messages)
            match = extract_json_with_fallback(resp, pattern_json)

            if not match:
                logger.warning(f"[ZERO_COV] No JSON found in LLM response (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    append_llm_retry_feedback(
                        messages,
                        resp,
                        "请只返回一个 JSON object，描述零覆盖分支的可达性约束。"
                    )
                continue

            constraints = json.loads(match.group(1).strip())
            schema_error = validate_generic_object_result(constraints, "zero-covered reachability analysis result")
            if schema_error:
                logger.warning(f"[ZERO_COV] Invalid reachability constraints schema: {schema_error}")
                if attempt < max_retries - 1:
                    append_llm_retry_feedback(
                        messages,
                        resp,
                        f"返回结构不符合要求：{schema_error}。请只返回一个 JSON object。"
                    )
                continue

            logger.info(f"[ZERO_COV] Reachability constraints analyzed: {len(constraints.get('path_prerequisites', []))} prerequisites")
            return constraints
        except Exception as e:
            logger.error(f"[ZERO_COV] Error analyzing reachability constraints (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                append_llm_retry_feedback(
                    messages,
                    resp if 'resp' in locals() else "",
                    f"上一次返回无法解析：{e}。请只返回一个合法的 JSON object。"
                )

    return None


def extract_branch_code_from_slice(code_slice, target_line):
    """从切片中提取目标分支的代码"""
    lines = code_slice.split('\n')
    for i, line in enumerate(lines):
        # 查找包含目标行号的代码
        if f"// === BRANCH CONTEXT (line {target_line}) ===" in line:
            # 找到了分支上下文，提取分支条件代码
            context_lines = []
            for j in range(i+1, min(i+10, len(lines))):
                if lines[j].strip() and not lines[j].strip().startswith('//'):
                    context_lines.append(lines[j])
                elif '//' in lines[j]:
                    break
            return '\n'.join(context_lines[:3])  # 返回前几行作为分支代码
    return "if (condition) { /* branch */ }"


def generate_input_for_zero_covered(target, constraints, llm_util: LLMUtil):
    """
    为零覆盖分支生成输入
    """
    if not constraints:
        logger.error("[ZERO_COV] No constraints available for input generation")
        return None, None

    generation_mode = infer_input_generation_mode(
        constraints.get('code_slice', ''),
        get_harness_code(),
    )
    if generation_mode == "text_direct":
        return generation_mode, generate_text_input_for_zero_covered(constraints, target, llm_util)
    return generation_mode, generate_binary_script_for_zero_covered(constraints, target, llm_util)


def generate_text_input_for_zero_covered(constraints, target, llm_util: LLMUtil):
    """
    为文本输入型库（mujs, sqlite等）生成文本内容。

    使用 LLM 直接生成满足约束的文本输入，而非 Python 脚本。
    """
    logger.info(f"[ZERO_COV] Generating text input for {PROJECT}")

    # 构造简化的 prompt 用于文本生成
    code_slice = constraints.get('code_slice', '')
    path_prerequisites = constraints.get('path_prerequisites', '')
    support_context = _get_zero_cov_supporting_context(llm_util)
    input_examples = collect_input_examples_context("text_direct")

    messages = [
        {'role': 'system', 'content': prompts['prompt']['zero_covered_text_input_generation']['sys_prompt']},
        {'role': 'user', 'content': get_formatted_user_prompt(
            'zero_covered_text_input_generation',
            project=PROJECT,
            function=target['function'],
            line=target['line'],
            path_prerequisites=path_prerequisites,
            code_slice=code_slice[:2000],
            runtime_command_context=support_context['runtime_command_context'],
            seed_delivery_context=support_context['seed_delivery_context'],
            format_context=support_context['format_context'] or "(unknown)",
            harness_code=support_context['harness_code'] or "(unavailable)",
            input_examples=input_examples or "(none)",
        )}
    ]

    try:
        resp = llm_util.get_response(messages)

        cleaned_resp = extract_direct_text_payload(resp)
        if cleaned_resp is None:
            logger.error("[ZERO_COV] Text generation returned no extractable payload")
            return None

        logger.info(f"[ZERO_COV] Generated text input (length: {len(cleaned_resp)})")
        return cleaned_resp

    except Exception as e:
        logger.error(f"[ZERO_COV] Text generation failed: {e}")
        return None


def generate_binary_script_for_zero_covered(constraints, target, llm_util: LLMUtil):
    """为二进制输入型库生成 Python 脚本"""
    logger.info(f"[ZERO_COV] Generating binary script for {PROJECT}")

    # 构造 roadblock_info
    rb_info = {
        'filename': target['file'],
        'line': target['line'],
        'function': target['function'],
        'status': 'zero_covered',
    }

    # 使用 generate_script prompt 生成脚本
    summary = "Generate input that reaches the target branch location"
    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"

    messages = build_generate_script_messages(
        constraints.get('code_slice', ''),
        constraints.get('path_prerequisites', ''),
        summary,
        target_branch=f"{target['function']}:{target['line']}",
        preferred_seed=None,
    )

    max_retries = 3
    for attempt in range(max_retries):
        resp = llm_util.get_response(messages)
        match = extract_json_with_fallback(resp, pattern_json)
        if not match:
            logger.warning(f"[ZERO_COV] Binary script generation returned no JSON (attempt {attempt + 1}/{max_retries})")
            if attempt < max_retries - 1:
                append_llm_retry_feedback(
                    messages,
                    resp,
                    "请只返回一个 JSON object，并且必须包含字符串字段 generation_script。"
                )
            continue
        try:
            res = json.loads(match.group(1).strip())
        except json.JSONDecodeError as exc:
            logger.warning(f"[ZERO_COV] Binary script generation JSON parse failed: {exc}")
            if attempt < max_retries - 1:
                append_llm_retry_feedback(
                    messages,
                    resp,
                    f"JSON 解析失败：{exc}。请只返回一个合法的 JSON object，并包含字符串字段 generation_script。"
                )
            continue
        schema_error = validate_generation_result(res)
        if schema_error:
            logger.warning(f"[ZERO_COV] Invalid binary script generation schema: {schema_error}")
            if attempt < max_retries - 1:
                append_llm_retry_feedback(
                    messages,
                    resp,
                    f"返回结构不符合要求：{schema_error}。请只返回一个 JSON object，并且 generation_script 必须是字符串。"
                )
            continue
        return res.get('generation_script', None)
    return None


def handle_zero_covered_branch(target, tracer: CoverageTracer, llm_util: LLMUtil):
    """
    处理零覆盖分支（两边都未执行）。

    完整实现流程：
    1. 获取代码切片（带回退策略）
    2. 分析可达性约束
    3. 生成输入（文本或脚本）
    4. 测试并入队
    """
    global pass_roadblock, inference_stats
    global fuzzer, input_dir, output_dir, fuzzing_args, target_prog, trace_prog

    logger.info(f"[{LogOp.ROADBLOCK}] Processing zero-covered branch: {target['file']}:{target['line']}")

    try:
        check_fuzzer_alive()
    except FuzzerProcessDiedError as e:
        logger.critical(f"[{LogOp.FUZZER}] {e}")
        logger.critical("[{LogOp.FUZZER}] Fuzzer died, aborting...")
        raise

    target_key = f"{target['file']}:{target['line']}:zero_covered"
    target_id = target['id']

    # 步骤 1: 获取代码切片（带回退策略）
    code_slice = get_code_slice_with_fallback(target, tracer, llm_util)
    if not code_slice:
        logger.error(f"[ZERO_COV] Failed to get code slice for {target['function']}:{target['line']}")
        mark_roadblock_failed(target_key, "SLICE_FAILED", target)
        return False, "Code slice extraction failed", -1, target_id

    # 步骤 2: 分析可达性约束
    constraints = analyze_reachability_constraints(target, code_slice, llm_util)
    if not constraints:
        logger.error(f"[ZERO_COV] Failed to analyze reachability constraints")
        mark_roadblock_failed(target_key, "CONSTRAINT_ANALYSIS_FAILED", target)
        return False, "Constraint analysis failed", -1, target_id

    # 步骤 3: 生成输入
    generation_mode, script_or_text = generate_input_for_zero_covered(target, constraints, llm_util)
    if not script_or_text:
        logger.error(f"[ZERO_COV] Failed to generate input")
        mark_roadblock_failed(target_key, "INPUT_GENERATION_FAILED", target)
        return False, "Input generation failed", -1, target_id

    # 步骤 4: 根据库类型处理
    LLM_TARGET_PATH = Path(output_dir) / "LLM" / "queue"
    os.makedirs(LLM_TARGET_PATH, exist_ok=True)
    seed_id = len(os.listdir(LLM_TARGET_PATH))

    try:
        if generation_mode == "text_direct":
            # 文本输入型库：直接写入文本文件
            seed_path = os.path.join(LLM_TARGET_PATH, f"id:{int(seed_id):06},src:zero_cov")
            with open(seed_path, 'w', encoding='utf-8') as f:
                f.write(script_or_text)
            logger.info(f"[ZERO_COV] Text seed written: {seed_path}")
        else:
            # 二进制输入型库：执行 Python 脚本
            from LLM.LLMUtil import run_generator
            script = script_or_text  # 已经是 Python 脚本
            stdout, stderr, new_seed_path = run_generator(script, target_id, seed_id, output_dir)

            if stderr and "Connected" not in stderr:
                logger.warning(f"[ZERO_COV] Script execution had errors, retrying...")
                # 简化处理，直接返回失败
                mark_roadblock_failed(target_key, "SCRIPT_EXECUTION_FAILED", target)
                return False, "Script execution failed", -1, target_id

            seed_path = new_seed_path

        gate_result, eval_result = gate_seed(seed_path, roadblock=target)
        logger.info(
            f"[SEED_GATE] ZERO_COV decision={gate_result.decision} accepted={gate_result.accepted} "
            f"reason={gate_result.reason}"
        )
        local_progress = gate_result.accepted and _seed_eval_indicates_local_progress(eval_result)
        logger.info(
            f"[ZERO_COV] Local seed evaluation: class={eval_result.coverage_gain_class}, "
            f"parse_family_hit={eval_result.parse_family_hit}, target_file_hit={eval_result.target_file_hit}, "
            f"target_line_window_hit={eval_result.target_line_window_hit}, new_edges={eval_result.new_edges}"
        )

        if local_progress:
            logger.info(f"[{LogOp.ROADBLOCK}] Zero-covered branch produced a locally validated seed")
            return True, "ZERO_COV", seed_id, target_id
        else:
            logger.info(f"[ZERO_COV] Seed generated but local validation did not accept it")
            mark_roadblock_failed(target_key, eval_result.rejection_reason or "NO_NEW_EDGES", target)
            return False, "No coverage gain", seed_id, target_id

    except Exception as e:
        logger.error(f"[ZERO_COV] Error during processing: {e}", exc_info=True)
        mark_roadblock_failed(target_key, "EXCEPTION", target)
        return False, f"Exception: {str(e)}", -1, target_id


def handle_uncalled_function(target, tracer: CoverageTracer, llm_util: LLMUtil):
    """
    处理未调用函数。

    策略：
    1. 分析调用该函数的条件
    2. 生成满足调用条件的输入
    3. 可能需要设置特定的状态或标志
    """
    global pass_roadblock
    global fuzzer, input_dir, output_dir, fuzzing_args, target_prog, trace_prog

    logger.info(f"[{LogOp.ROADBLOCK}] Processing uncalled function: {target['name']} in {target['file']}")

    try:
        check_fuzzer_alive()
    except FuzzerProcessDiedError as e:
        logger.critical(f"[{LogOp.FUZZER}] {e}")
        logger.critical("[{LogOp.FUZZER}] Fuzzer died, aborting...")
        raise

    target_key = f"{target['file']}:{target['name']}:uncalled_func"
    target_id = target['id']

    # TODO: 添加针对未调用函数的特定处理逻辑
    # 1. 查找所有调用该函数的位置
    # 2. 分析每个调用点的条件
    # 3. 生成满足调用条件的种子
    logger.warning(f"[{LogOp.ROADBLOCK}] Uncalled function handling not fully implemented yet")
    mark_roadblock_failed(target_key, "NOT_IMPLEMENTED", target)
    return False, "Uncalled function handling not implemented", -1, target_id


def handle_unexecuted_block(target, tracer: CoverageTracer, llm_util: LLMUtil):
    """
    处理未执行基本块。

    策略：
    1. 找到已执行的前驱块
    2. 分析从前驱到该块的分支条件
    3. 复用 handle_roadblock 的逻辑
    """
    global pass_roadblock
    global fuzzer, input_dir, output_dir, fuzzing_args, target_prog, trace_prog

    logger.info(f"[{LogOp.ROADBLOCK}] Processing unexecuted block: {target['function']}:{target['line']}")

    try:
        check_fuzzer_alive()
    except FuzzerProcessDiedError as e:
        logger.critical(f"[{LogOp.FUZZER}] {e}")
        logger.critical("[{LogOp.FUZZER}] Fuzzer died, aborting...")
        raise

    target_key = f"{target['file']}:{target['line']}:unexecuted_block"
    target_id = target['id']

    # 未执行基本块可以转换为 roadblock 格式处理
    # 构造一个虚拟的 roadblock 对象
    virtual_roadblock = {
        'id': target_id,
        'filename': target['file'],
        'line': target['line'],
        'function': target['function'],
        'type': 'unexecuted_block',
        'status': 'unknown'  # 未知方向，因为块未执行
    }

    logger.info(f"[{LogOp.ROADBLOCK}] Converting unexecuted block to virtual roadblock")

    # 调用 handle_roadblock 处理
    return handle_roadblock(virtual_roadblock, tracer, llm_util)


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


# def mutate_suggest(code_slice, constraints, field, byte_range, llm_util: LLMUtil, pattern_json):
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


def judge_conflict(
    constraints: list,
    non_input_constraints: list,
    breakthrough_assessment: dict,
    llm_util: LLMUtil,
    full_code_slice,
    status_now
):
    # LLM interaction logging
    llm_log = get_llm_logger()
    llm_log.info(f"[LLM_INTERACTION] judge_conflict called")
    llm_log.debug(f"[LLM_INTERACTION] constraints_count: {len(constraints)}")
    llm_log.debug(
        f"[LLM_INTERACTION] non_input_constraints_count: "
        f"{len(non_input_constraints) if isinstance(non_input_constraints, list) else 'N/A'}"
    )
    llm_log.debug(
        f"[LLM_INTERACTION] full_code_slice_preview: "
        f"{str(full_code_slice)[:200] if full_code_slice else 'None'}..."
    )
    llm_log.debug(f"[LLM_INTERACTION] status_now: {status_now}")

    # 基础 system prompt
    sys_prompt = prompts['prompt'][JUDGE_CONFLICT_PROMPT_KEY_V2]['sys_prompt']

    # 根据库名动态添加领域特定冲突检测规则
    domain_rules = ""
    if '_domain_rules' in prompts['prompt']:
        domain_rules_config = prompts['prompt']['_domain_rules']
        if PROJECT in domain_rules_config:
            lib_rules = domain_rules_config[PROJECT]
            if 'conflict_rules' in lib_rules:
                domain_rules = "\n\n" + lib_rules['conflict_rules']
                logger.info(f"[{LogOp.LLM}] Added conflict detection rules for {PROJECT}")

    messages = [
        {'role': 'system', 'content': sys_prompt + domain_rules},
        {'role': 'user',
         'content': prompts['prompt'][JUDGE_CONFLICT_PROMPT_KEY_V2]['user_prompt'].format(
             lib=PROJECT,
             runtime_command_context=build_runtime_command_context(),
             constraints=json.dumps(constraints, ensure_ascii=False, indent=2),
             non_input_constraints=json.dumps(non_input_constraints, ensure_ascii=False, indent=2),
             breakthrough_assessment=json.dumps(breakthrough_assessment, ensure_ascii=False, indent=2),
             rb_code=full_code_slice,
             status_now=status_now
         )}
    ]
    max_retries = 3
    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"

    for attempt in range(max_retries):
        resp = llm_util.get_response(messages)
        llm_log.info(f"[LLM_INTERACTION] judge_conflict raw response length: {len(resp) if resp else 0}")

        decision_result = None
        match = re.search(pattern_json, resp, re.DOTALL | re.IGNORECASE)
        try:
            if match:
                decision_result = json.loads(match.group(1).strip())
            else:
                decision_result = json.loads(resp.strip())
        except json.JSONDecodeError as exc:
            logger.warning(f"[{LogOp.LLM}] judge_conflict_v2 JSON parse failed: {exc}")

        if decision_result is not None:
            schema_error = validate_decision_result_v2(decision_result)
            if not schema_error:
                llm_log.info(
                    f"[LLM_INTERACTION] judge_conflict result: decision={decision_result['decision']}, "
                    f"reason={decision_result['reason']}"
                )
                return decision_result
            logger.warning(f"[{LogOp.LLM}] Invalid judge_conflict_v2 schema: {schema_error}")

        if attempt < max_retries - 1:
            messages.append({'role': 'assistant', 'content': resp})
            messages.append({
                'role': 'user',
                'content': prompts['prompt']['retry_json_required_fields']['user_prompt']
            })

    raise ValueError("judge_conflict_v2 failed to return a valid structured decision")


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


def get_generate_script(code_slice: str | Any, llm_util: LLMUtil, pattern_json: str, constraints, input_profile,
                        fields=None, target_branch=None, state_hints=None, harness_code=None,
                        preferred_seed=None) -> Match[str] | None:
    messages = build_generate_script_messages(
        code_slice,
        constraints,
        input_profile,
        fields=fields,
        target_branch=target_branch,
        state_hints=state_hints,
        harness_code=harness_code,
        preferred_seed=preferred_seed,
    )
    resp = llm_util.get_response(messages)

    return extract_json_with_fallback(resp, pattern_json)


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


def get_constraints_nl(rb_info, code_slice: str | Any, llm_util: LLMUtil, pattern_json, ) -> Match[
                                                                                                 str] | None:
    # LLM interaction logging
    llm_log = get_llm_logger()
    llm_log.info(f"[LLM_INTERACTION] get_constraints_nl called")
    llm_log.debug(f"[LLM_INTERACTION] roadblock_info: {rb_info}")
    llm_log.debug(f"[LLM_INTERACTION] code_slice_preview: {str(code_slice)[:200] if code_slice else 'None'}...")

    messages = build_constraints_messages(rb_info, code_slice)
    logger.debug(messages)
    resp = llm_util.get_response(messages)
    llm_log.info(f"[LLM_INTERACTION] get_constraints_nl response length: {len(resp) if resp else 0}")

    return extract_json_with_fallback(resp, pattern_json)


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
    # 但 llvm-cov export 的 switch_statement 字段只包含语句内容，不包含行号
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


def identify_input_source(code_slice: str) -> str:
    """
    Identify the fuzz input source from code slice.

    Args:
        code_slice: Code slice containing the fuzz harness

    Returns:
        Identified input source (e.g., 'data', 'buf->data')
    """
    input_source = None
    for line in code_slice.split('\n'):
        if 'LLVMFuzzerTestOneInput' in line:
            match = re.search(r'\((\w+\s*\*\s*\w+)', line)
            if match:
                input_source = match.group(1).strip() + '->data'
            break
        elif 'data' in line and '*' in line:
            # Try to identify data parameter
            match = re.search(r'const\s+uint8_t\s*\*\s*(\w+)', line)
            if match:
                input_source = match.group(1)
                break

    return input_source if input_source else "data"  # Default fallback


def run_branch_analysis(code_slice: str, target_branch: str, input_source: str, llm_util: LLMUtil):
    """
    Step 1: Analyze target branch to extract input dependencies and constraints.

    Args:
        code_slice: Code slice containing the target branch
        target_branch: The specific branch condition to analyze
        input_source: Fuzz input source (e.g., data/buf/input_stream)
        llm_util: LLM utility instance

    Returns:
        Dictionary with branch analysis result or None on failure
    """
    # LLM interaction logging
    llm_log = get_llm_logger()
    llm_log.info(f"[LLM_INTERACTION] run_branch_analysis called")
    llm_log.debug(f"[LLM_INTERACTION] code_slice_preview: {str(code_slice)[:200] if code_slice else 'None'}...")
    llm_log.debug(f"[LLM_INTERACTION] target_branch: {target_branch}")
    llm_log.debug(f"[LLM_INTERACTION] input_source: {input_source}")

    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"

    # ========== NEW: Add format context ==========
    format_context = ""
    if cached_format_info:
        format_context = f"\n\n<detected_input_format>\n{InputFormatDetector.format_info_to_prompt_section(cached_format_info)}\n</detected_input_format>"
        logger.info(f"[{LogOp.LLM}] Added format context to branch_analysis prompt")
    # ========== End format context ==========

    messages = [
        {'role': 'system', 'content': prompts['prompt']['branch_analysis']['sys_prompt'] + format_context},
        {'role': 'user',
         'content': prompts['prompt']['branch_analysis']['user_prompt'].format(
             code_slice=code_slice,
             target_branch=target_branch,
             input_source=input_source
         )}
    ]

    max_retries = 3
    for attempt in range(max_retries):
        try:
            resp = llm_util.get_response(messages)
            match = extract_json_with_fallback(resp, pattern_json)

            if match:
                result = json.loads(match.group(1).strip())
                schema_error = validate_generic_object_result(result, "branch_analysis result")
                if schema_error:
                    logger.warning(
                        f"[{LogOp.LLM}] Branch analysis invalid schema (attempt {attempt + 1}/{max_retries}): {schema_error}")
                    llm_log.warning(f"[LLM_INTERACTION] run_branch_analysis invalid schema: {schema_error}")
                    if attempt < max_retries - 1:
                        append_llm_retry_feedback(
                            messages,
                            resp,
                            f"返回结构不符合要求：{schema_error}。请只返回一个 JSON object。"
                        )
                    continue
                logger.debug(f"[{LogOp.LLM}] Branch analysis result: {json.dumps(result, indent=2)}")
                llm_log.info(f"[LLM_INTERACTION] run_branch_analysis result: passable={result.get('passable')}")
                return result
            else:
                # Fallback: try to parse entire response as JSON
                logger.debug(f"[{LogOp.LLM}] Branch analysis: No pattern match, trying direct JSON parse")
                try:
                    trimmed_resp = resp.strip()
                    result = json.loads(trimmed_resp)
                    schema_error = validate_generic_object_result(result, "branch_analysis result")
                    if schema_error:
                        logger.warning(
                            f"[{LogOp.LLM}] Branch analysis invalid direct-parse schema (attempt {attempt + 1}/{max_retries}): {schema_error}")
                        llm_log.warning(f"[LLM_INTERACTION] run_branch_analysis invalid direct schema: {schema_error}")
                        if attempt < max_retries - 1:
                            append_llm_retry_feedback(
                                messages,
                                resp,
                                f"返回结构不符合要求：{schema_error}。请只返回一个 JSON object。"
                            )
                        continue
                    logger.debug(
                        f"[{LogOp.LLM}] Branch analysis result (via direct parse): {json.dumps(result, indent=2)}")
                    llm_log.info(
                        f"[LLM_INTERACTION] run_branch_analysis result (direct parse): passable={result.get('passable')}")
                    return result
                except json.JSONDecodeError:
                    logger.warning(
                        f"[{LogOp.LLM}] Branch analysis: JSON pattern not found and direct parse failed (attempt {attempt + 1}/{max_retries})")
                    llm_log.warning(
                        f"[LLM_INTERACTION] run_branch_analysis JSON parse failed, attempt {attempt + 1}/{max_retries}")
                    if attempt < max_retries - 1:
                        messages.append({'role': 'assistant', 'content': resp})
                        messages.append({
                            'role': 'user',
                            'content': prompts['prompt']['retry_json_only']['user_prompt']
                        })

        except json.JSONDecodeError as e:
            logger.warning(
                f"[{LogOp.LLM}] Branch analysis: JSON parse error (attempt {attempt + 1}/{max_retries}): {str(e)}")
            llm_log.error(f"[LLM_INTERACTION] run_branch_analysis JSON decode error: {str(e)}")
            if attempt < max_retries - 1:
                messages.append({'role': 'assistant', 'content': resp})
                messages.append({
                    'role': 'user',
                    'content': get_formatted_user_prompt('retry_json_parse_failed', error=str(e))
                })
        except Exception as e:
            logger.error(f"[{LogOp.LLM}] Branch analysis error: {str(e)}")
            llm_log.error(f"[LLM_INTERACTION] run_branch_analysis error: {str(e)}")
            break

    llm_log.error(f"[LLM_INTERACTION] run_branch_analysis failed after {max_retries} attempts")
    return None


def run_mutator_rule_gen(branch_analysis: dict, target_side: str, llm_util: LLMUtil):
    """
    Step 2: Generate deterministic mutator rules from branch analysis.

    Args:
        branch_analysis: Output from run_branch_analysis
        target_side: Target branch direction (true or false)
        llm_util: LLM utility instance

    Returns:
        Dictionary with mutator rule or None on failure
    """
    # LLM interaction logging
    llm_log = get_llm_logger()
    llm_log.info(f"[LLM_INTERACTION] run_mutator_rule_gen called")
    llm_log.debug(f"[LLM_INTERACTION] target_side: {target_side}")
    llm_log.debug(
        f"[LLM_INTERACTION] branch_analysis_passable: {branch_analysis.get('passable') if branch_analysis else 'None'}")

    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"

    messages = [
        {'role': 'system', 'content': prompts['prompt']['mutator_rule_gen']['sys_prompt']},
        {'role': 'user',
         'content': prompts['prompt']['mutator_rule_gen']['user_prompt'].format(
             branch_analysis=json.dumps(branch_analysis, indent=2, ensure_ascii=False),
             target_side=target_side
         )}
    ]

    max_retries = 3
    for attempt in range(max_retries):
        try:
            resp = llm_util.get_response(messages)
            match = extract_json_with_fallback(resp, pattern_json)

            if match:
                result = json.loads(match.group(1).strip())
                schema_error = validate_mutator_rule_result(result)
                if schema_error:
                    logger.warning(
                        f"[{LogOp.LLM}] Mutator rule invalid schema (attempt {attempt + 1}/{max_retries}): {schema_error}")
                    llm_log.warning(f"[LLM_INTERACTION] run_mutator_rule_gen invalid schema: {schema_error}")
                    if attempt < max_retries - 1:
                        append_llm_retry_feedback(
                            messages,
                            resp,
                            f"返回结构不符合要求：{schema_error}。请只返回一个 JSON object，并包含列表字段 edits。"
                        )
                    continue
                logger.debug(f"[{LogOp.LLM}] Mutator rule result: {json.dumps(result, indent=2)}")
                llm_log.info(f"[LLM_INTERACTION] run_mutator_rule_gen result: edits={len(result.get('edits', []))}")
                return result
            else:
                # Fallback: try to parse entire response as JSON
                logger.debug(f"[{LogOp.LLM}] Mutator rule gen: No pattern match, trying direct JSON parse")
                try:
                    trimmed_resp = resp.strip()
                    result = json.loads(trimmed_resp)
                    schema_error = validate_mutator_rule_result(result)
                    if schema_error:
                        logger.warning(
                            f"[{LogOp.LLM}] Mutator rule invalid direct-parse schema (attempt {attempt + 1}/{max_retries}): {schema_error}")
                        llm_log.warning(f"[LLM_INTERACTION] run_mutator_rule_gen invalid direct schema: {schema_error}")
                        if attempt < max_retries - 1:
                            append_llm_retry_feedback(
                                messages,
                                resp,
                                f"返回结构不符合要求：{schema_error}。请只返回一个 JSON object，并包含列表字段 edits。"
                            )
                        continue
                    logger.debug(
                        f"[{LogOp.LLM}] Mutator rule result (via direct parse): {json.dumps(result, indent=2)}")
                    llm_log.info(
                        f"[LLM_INTERACTION] run_mutator_rule_gen result (direct parse): edits={len(result.get('edits', []))}")
                    return result
                except json.JSONDecodeError:
                    logger.warning(
                        f"[{LogOp.LLM}] Mutator rule gen: JSON pattern not found and direct parse failed (attempt {attempt + 1}/{max_retries})")
                    llm_log.warning(
                        f"[LLM_INTERACTION] run_mutator_rule_gen JSON parse failed, attempt {attempt + 1}/{max_retries}")
                    if attempt < max_retries - 1:
                        messages.append({'role': 'assistant', 'content': resp})
                        messages.append({
                            'role': 'user',
                            'content': prompts['prompt']['retry_json_only']['user_prompt']
                        })

        except json.JSONDecodeError as e:
            logger.warning(
                f"[{LogOp.LLM}] Mutator rule gen: JSON parse error (attempt {attempt + 1}/{max_retries}): {str(e)}")
            llm_log.error(f"[LLM_INTERACTION] run_mutator_rule_gen JSON decode error: {str(e)}")
            if attempt < max_retries - 1:
                messages.append({'role': 'assistant', 'content': resp})
                messages.append({
                    'role': 'user',
                    'content': get_formatted_user_prompt('retry_json_parse_failed', error=str(e))
                })
        except Exception as e:
            logger.error(f"[{LogOp.LLM}] Mutator rule gen error: {str(e)}")
            llm_log.error(f"[LLM_INTERACTION] run_mutator_rule_gen error: {str(e)}")
            break

    llm_log.error(f"[LLM_INTERACTION] run_mutator_rule_gen failed after {max_retries} attempts")
    return None


def run_mutate_batch_script_gen(mutator_rule: dict, seed_dir: str, out_dir: str, manifest_dir: str, llm_util: LLMUtil):
    """
    Step 3: Generate batch mutation script from mutator rules.

    Args:
        mutator_rule: Output from run_mutator_rule_gen
        seed_dir: Input seed directory path
        out_dir: Output queue directory path
        manifest_dir: Directory where manifest.csv should be written
        llm_util: LLM utility instance

    Returns:
        Python batch script string or None on failure
    """
    # LLM interaction logging
    llm_log = get_llm_logger()
    llm_log.info(f"[LLM_INTERACTION] run_mutate_batch_script_gen called")
    llm_log.debug(f"[LLM_INTERACTION] seed_dir: {seed_dir}")
    llm_log.debug(f"[LLM_INTERACTION] out_dir: {out_dir}")
    llm_log.debug(f"[LLM_INTERACTION] manifest_dir: {manifest_dir}")

    messages = [
        {'role': 'system', 'content': get_formatted_prompt('mutate_batch_script_gen')},
        {'role': 'user',
         'content': prompts['prompt']['mutate_batch_script_gen']['user_prompt'].format(
             rule=json.dumps(mutator_rule, indent=2, ensure_ascii=False),
             seed_dir=seed_dir,
             out_dir=out_dir,
             manifest_dir=manifest_dir
         )}
    ]

    max_retries = 3
    for attempt in range(max_retries):
        try:
            resp = llm_util.get_response(messages)
            match = re.search(r"```python(.*?)```", resp, re.DOTALL | re.IGNORECASE)

            if match:
                script = match.group(1).strip()
                logger.info(f"[{LogOp.LLM}] Batch script generated ({len(script)} chars)")
                llm_log.info(f"[LLM_INTERACTION] run_mutate_batch_script_gen result: script_length={len(script)}")
                return script
            else:
                logger.warning(
                    f"[{LogOp.LLM}] Batch script gen: Python code block not found (attempt {attempt + 1}/{max_retries})")
                llm_log.warning(
                    f"[LLM_INTERACTION] run_mutate_batch_script_gen code block not found, attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    messages.append({'role': 'assistant', 'content': resp})
                    messages.append({
                        'role': 'user',
                        'content': prompts['prompt']['retry_python_block']['user_prompt']
                    })

        except Exception as e:
            logger.error(f"[{LogOp.LLM}] Batch script gen error: {str(e)}")
            llm_log.error(f"[LLM_INTERACTION] run_mutate_batch_script_gen error: {str(e)}")
            if attempt < max_retries - 1:
                messages.append({'role': 'assistant', 'content': resp})
                messages.append({
                    'role': 'user',
                    'content': get_formatted_user_prompt('retry_python_script', error=str(e))
                })
            else:
                break

    llm_log.error(f"[LLM_INTERACTION] run_mutate_batch_script_gen failed after {max_retries} attempts")
    return None


def create_batch_mutation_seed_dir(seed_dir: str, target_dir: str | Path | None = None) -> tuple[str, int]:
    filtered_dir = Path(target_dir) if target_dir is not None else Path(tempfile.mkdtemp(prefix="batch_mutate_inputs_"))
    if filtered_dir.exists():
        shutil.rmtree(filtered_dir, ignore_errors=True)
    filtered_dir.mkdir(parents=True, exist_ok=True)
    selected_count = 0
    for seed_path in sorted(Path(seed_dir).iterdir()):
        if not seed_path.is_file() or not seed_path.name.startswith("id:"):
            continue
        os.symlink(seed_path, filtered_dir / seed_path.name)
        selected_count += 1
    return os.fspath(filtered_dir), selected_count


def resolve_coverage_stuck(tracer: CoverageTracer, last_scan_time, read_files, stuck_time):
    global pass_roadblock, pass_roadblock_id, attempted_roadblocks
    global fuzzer, input_dir, output_dir, fuzzing_args, target_prog, trace_prog

    # Iterative update: Remove expired roadblocks from pass_roadblock list
    update_pass_roadblock()

    ret, last_scan_time, error_info, roadblocks = tracer.get_trace(read_files, last_scan_time)
    if not ret:
        # 没有新 seed 时继续利用已有静态 roadblock 池，而不是直接等待。
        if "没有新的seed" in error_info:
            logger.info(f"[{LogOp.ROADBLOCK}] {error_info}")
            logger.info(f"[{LogOp.ROADBLOCK}] Reusing existing roadblocks and continuing exploration without waiting for new AFL seeds")
            roadblocks = tracer.get_roadblocks(STATIC_PATH)
            ret = True
        else:
            logger.critical(f"[{LogOp.ROADBLOCK}] Coverage trace extraction failed: {error_info}")
            logger.critical("Cannot proceed without valid trace data")
            sys.exit(1)

    dse_util = None
    llm_util = LLMUtil(MODEL, API_KEY, BASE_URL)

    # ========== NEW: Initialize format detection once per session ==========
    global cached_format_info
    cached_format_info = ensure_cached_format_info(llm_util)
    # ========== End format detection initialization ==========
    # tracer 可能花费较长时间；追踪完成后立即重新检查覆盖率，
    # 避免继续处理已经被 AFL 新种子突破的旧瓶颈。
    # stuck_time = tracer.check_coverage_growth()
    # if stuck_time < THRESHOLD_TIME:
    #     logger.info(
    #         f"[{LogOp.ROADBLOCK}] Coverage changed during trace extraction "
    #         f"(stuck_time={stuck_time}s < {THRESHOLD_TIME}s), skipping stale roadblocks"
    #     )
    #     return True, last_scan_time, read_files

    # logger.info(f"[{LogOp.ROADBLOCK}] ROADBLOCK_STAGE stuck_time={stuck_time:.1f}s")

    # 过滤瓶颈：
    # 1. 排除已解决的瓶颈 (resolved_roadblocks - 永久不再尝试)
    # 2. 排除未超时的失败瓶颈 (pass_roadblock_id - 可重试)
    filtered_roadblocks = []
    deprioritized_roadblocks = []
    skipped_resolved = 0
    skipped_failed = 0
    skipped_attempted = 0
    skipped_low_value = 0

    for rb in roadblocks:
        rb_key = get_roadblock_key(rb)

        # 检查是否已解决
        if rb_key in resolved_roadblocks:
            skipped_resolved += 1
            logger.debug(f"[{LogOp.ROADBLOCK}] Skipping resolved roadblock: {rb_key}")
            continue

        if rb_key in attempted_roadblocks:
            skipped_attempted += 1
            logger.debug(f"[{LogOp.ROADBLOCK}] Skipping attempted roadblock: {rb_key}")
            continue

        # 检查是否在失败列表中（本次 session 内不再重试）
        if rb_key in pass_roadblock_id:
            skipped_failed += 1
            logger.debug(f"[{LogOp.ROADBLOCK}] Skipping failed roadblock (already failed in this session): {rb_key}")
            continue

        # 可处理的瓶颈
        rb_id = get_rb_id(rb)
        rb_func = get_function_name(rb)[0]
        rb['roadblock_id'] = rb_id
        rb['roadblock_key'] = rb_key  # 添加 key 字段便于后续使用
        rb['function'] = rb_func
        # rb['guard_filter'] = analyze_low_value_guard_roadblock(rb)
        # if rb['guard_filter'].get('should_skip'):
        #     skipped_low_value += 1
        #     logger.info(
        #         f"[{LogOp.ROADBLOCK}] Skipping low-value guard roadblock: {rb_key} "
        #         f"({rb['guard_filter'].get('reason', 'guard-filtered')})"
        #     )
        #     continue
        # reachability = build_default_reachability_profile(rb)
        # subspace_info = reachability["subspace_info"]
        # rb['subspace_info'] = subspace_info
        # rb['reachability_decision'] = reachability['decision']
        # rb['reachability_reason'] = reachability['reason']
        # rb['frontier_distance'] = reachability['frontier_distance']
        # rb['triage_tier'] = reachability['tier']
        # rb['family_match'] = reachability['family_match']
        # rb['evidence_strength'] = reachability['evidence_strength']
        # rb['requires_extra_surface'] = reachability['requires_extra_surface']
        # rb['estimated_cost'] = reachability['estimated_cost']
        # rb['last_n_attempts'] = reachability['last_n_attempts']
        # rb['last_failure_mode'] = reachability['last_failure_mode']
        # rb['subspace_info']['frontier_distance'] = reachability['frontier_distance']
        filtered_roadblocks.append(rb)

    # filtered_roadblocks = rank_roadblocks_with_frontier_distance(filtered_roadblocks)
    # tier_a_candidates = [rb for rb in filtered_roadblocks if rb.get('triage_tier') == 'Tier A']
    # tier_b_candidates = [rb for rb in filtered_roadblocks if rb.get('triage_tier') == 'Tier B']
    # unreachable_candidates = [rb for rb in filtered_roadblocks if rb.get('triage_tier') == 'Tier C']
    # cooled_down_candidates = [rb for rb in filtered_roadblocks if rb.get('triage_tier') == 'Tier D']
    # for rb in unreachable_candidates:
    #     logger.info(
    #         f"[{LogOp.ROADBLOCK}] LLM-screen rejected roadblock {rb.get('roadblock_key')} "
    #         f"(family={rb.get('subspace_info', {}).get('subspace_family')}, "
    #         f"reason={rb.get('reachability_reason')})"
    #     )
    # for rb in cooled_down_candidates:
    #     logger.info(
    #         f"[{LogOp.ROADBLOCK}] LLM-screen deferred roadblock {rb.get('roadblock_key')} "
    #         f"(family={rb.get('subspace_info', {}).get('subspace_family')}, reason={rb.get('reachability_reason')})"
    #     )
    # logger.info(
    #     f"[{LogOp.ROADBLOCK}] Static screening summary: tier_a={len(tier_a_candidates)}, "
    #     f"tier_b={len(tier_b_candidates)}, rejected={len(unreachable_candidates)}, "
    #     f"deferred={len(cooled_down_candidates)}, attempted_skipped={skipped_attempted}, "
    #     f"low_value_guard_skipped={skipped_low_value}"
    # )
    roadblocks, bootstrap_candidates, rejected_by_probe, deferred_by_probe = screen_selected_roadblocks(
        filtered_roadblocks,
        llm_util,
        budget=ROADBLOCK_STAGE_BUDGET,
    )
    for rb in rejected_by_probe:
        logger.info(
            f"[{LogOp.ROADBLOCK}] Probe-screen rejected roadblock {rb.get('roadblock_key')} "
            f"(family={rb.get('subspace_info', {}).get('subspace_family')}, "
            f"reason={rb.get('reachability_reason')})"
        )
    for rb in deferred_by_probe:
        logger.info(
            f"[{LogOp.ROADBLOCK}] Probe-screen deferred roadblock {rb.get('roadblock_key')} "
            f"(family={rb.get('subspace_info', {}).get('subspace_family')}, "
            f"reason={rb.get('reachability_reason')})"
        )
    logger.info(
        f"[{LogOp.ROADBLOCK}] Probe screening summary: selected={len(roadblocks)}, "
        f"bootstrap={len(bootstrap_candidates)}, rejected={len(rejected_by_probe)}, "
        f"deferred={len(deferred_by_probe)}"
    )
    early_zero_stage = should_enter_early_zero_branch_stage(stuck_time, len(roadblocks), skipped_failed)
    prioritize_zero_stage = should_prioritize_zero_branch_stage(stuck_time, len(roadblocks), skipped_failed)

    if not roadblocks and skipped_failed > 0:
        logger.info(
            f"[{LogOp.ROADBLOCK}] All current roadblocks were filtered by failed/completed-session gating; "
            f"keeping fully attempted roadblocks skipped instead of reopening them"
        )

    if not roadblocks:
        if bootstrap_candidates:
            logger.info(
                f"[{LogOp.ROADBLOCK}] No Tier A candidates; attempting weak-signal candidates "
                f"({len(bootstrap_candidates)})"
            )
            for target in bootstrap_candidates:
                ret, mode, id, roadblock_id = handle_subspace_bootstrap(target, tracer, llm_util)
                if ret:
                    return True, last_scan_time, read_files
                record_roadblock_outcome(False)
        logger.info(
            f"[{LogOp.ROADBLOCK}] All roadblocks filtered "
            f"({skipped_resolved} resolved, {skipped_attempted} attempted, {skipped_failed} failed this session)"
        )
        attempted, coverage_breakthrough, last_scan_time, read_files = run_zero_branch_stage(
            tracer,
            llm_util,
            last_scan_time,
            read_files,
            MAX_ZERO_COVERED_ATTEMPTS,
            "no roadblocks available",
        )
        if attempted:
            return True, last_scan_time, read_files

        logger.info("[{LogOp.ROADBLOCK}] Waiting for new roadblocks to appear or coverage changes")
        return False, last_scan_time, read_files

    if prioritize_zero_stage:
        if prioritize_zero_stage:
            logger.info(
                f"[{LogOp.ROADBLOCK}] Prioritizing ZERO_BRANCH_STAGE "
                f"(stuck_time={stuck_time:.1f}s, recent_failure_rate={get_recent_roadblock_failure_rate():.2f}, "
                f"remaining_roadblocks={len(roadblocks)}, skipped_failed={skipped_failed})"
            )
        attempted, coverage_breakthrough, last_scan_time, read_files = run_zero_branch_stage(
            tracer,
            llm_util,
            last_scan_time,
            read_files,
            MAX_ZERO_COVERED_ATTEMPTS,
            "early promotion due to deep stagnation",
        )
        if attempted:
            return True, last_scan_time, read_files
        logger.info(f"[{LogOp.ROADBLOCK}] ZERO_BRANCH_STAGE had no breakthrough, falling back to remaining roadblocks")

    logger.info(
        f"[{LogOp.ROADBLOCK}] Processing {len(roadblocks)} roadblock(s) "
        f"({skipped_resolved} resolved, {skipped_attempted} attempted, {skipped_failed} failed this session)"
    )

    if bootstrap_candidates and (len(roadblocks) <= 1 or len(bootstrap_candidates) > len(roadblocks)):
        logger.info(
            f"[{LogOp.ROADBLOCK}] Attempting one bootstrap candidate before reachable roadblocks "
            f"(reachable={len(roadblocks)}, bootstrap={len(bootstrap_candidates)})"
        )
        ret, mode, id, roadblock_id = handle_subspace_bootstrap(bootstrap_candidates[0], tracer, llm_util)
        if ret:
            return True, last_scan_time, read_files
        record_roadblock_outcome(False)

    if early_zero_stage:
        logger.info(
            f"[{LogOp.ROADBLOCK}] Early ZERO_BRANCH_STAGE probe triggered "
            f"(stuck_time={stuck_time:.1f}s, recent_failure_rate={get_recent_roadblock_failure_rate():.2f}, "
            f"remaining_roadblocks={len(roadblocks)}, skipped_failed={skipped_failed})"
        )
        attempted, coverage_breakthrough, last_scan_time, read_files = run_zero_branch_stage(
            tracer,
            llm_util,
            last_scan_time,
            read_files,
            1,
            "early mixed exploration",
        )
        if coverage_breakthrough:
            return True, last_scan_time, read_files
        if attempted:
            logger.info(f"[{LogOp.ROADBLOCK}] Early zero-branch probe completed without breakthrough, returning to roadblocks")

    for roadblock in roadblocks:
        ret, mode, id, roadblock_id = handle_roadblock(roadblock, tracer, llm_util)
        # Check coverage after each roadblock attempt
        # If coverage has grown (stuck_time < threshold), stop trying and wait for next bottleneck
        stuck_time = tracer.check_coverage_growth()

        # Check if fuzzer process is still alive after coverage check
        try:
            check_fuzzer_alive()
        except FuzzerProcessDiedError as e:
            logger.critical(f"[{LogOp.FUZZER}] {e}")
            logger.critical("[{LogOp.FUZZER}] Fuzzer died during roadblock resolution, initiating graceful shutdown...")
            raise

        if stuck_time < THRESHOLD_TIME:
            reset_roadblock_outcomes()
            logger.info(
                f"[{LogOp.ROADBLOCK}] Coverage breakthrough detected after roadblock attempt (stuck_time={stuck_time}s < {THRESHOLD_TIME}s)")
            logger.info(f"[{LogOp.ROADBLOCK}] Stopping further attempts, waiting for next coverage bottleneck")
            return True, last_scan_time, read_files
        if ret:
            record_roadblock_outcome(True)
            logger.info(
                f"[{LogOp.ROADBLOCK}] Roadblock produced local hit evidence but no global breakthrough: {mode}. "
                f"Continuing to remaining roadblocks in this stage"
            )
        else:
            record_roadblock_outcome(False)
            logger.debug(f"[{LogOp.ROADBLOCK}] Roadblock resolution failed: {mode}")

    logger.info("[{LogOp.ROADBLOCK}] Waiting for new roadblocks to appear or coverage changes")
    return False, last_scan_time, read_files


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
    # Skip fuzzer process check in test mode
    if test:
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


def main():
    global fuzzer, input_dir, output_dir, fuzzing_args, target_prog, trace_prog
    read_files = set()
    last_scan_time = 0
    input_dir = os.fspath(INPUT_PATH)
    output_dir = os.fspath(OUTPUT_PATH)
    fuzzing_args = parse_exec_args(EXEC_ARGS)
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
        iteration_count = 0
        while True:
            # Check if fuzzer process is still alive
            try:
                check_fuzzer_alive()
            except FuzzerProcessDiedError as e:
                logger.critical(f"[{LogOp.FUZZER}] {e}")
                logger.critical("[{LogOp.FUZZER}] Fuzzer died, initiating graceful shutdown...")
                raise

            stuck_time = tracer.check_coverage_growth()
            if stuck_time < THRESHOLD_TIME:
                time.sleep(CHECK_INTERVAL)
                continue

            # Iterative update before processing roadblocks
            removed_count = update_pass_roadblock()
            if removed_count > 0:
                logger.info(
                    f"[{LogOp.ROADBLOCK}] Main loop: Iterative update removed {removed_count} expired roadblock(s)")

            success, last_scan_time, read_files = resolve_coverage_stuck(tracer, last_scan_time, read_files, stuck_time)
            iteration_count += 1
            logger.info(f"[{LogOp.ROADBLOCK}] Main loop iteration {iteration_count} completed")
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt detected (Ctrl+C)")
        logger.info("Initiating graceful shutdown...")
    except Exception as e:
        logger.critical(f"Unexpected error in main loop: {str(e)}", exc_info=True)
        logger.critical("Attempting graceful shutdown...")
    finally:
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
