import logging
import os
import re
import shlex
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

import ujson
import yaml
from dotenv import load_dotenv


class _SafeFormatDict(dict):
    """Preserve unknown placeholders during str.format_map."""

    def __missing__(self, key):
        return "{" + key + "}"


_SIMPLE_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _safe_prompt_substitute(template: str, values: dict) -> str:
    """Replace only simple {name} placeholders and leave all other braces intact."""

    def repl(match):
        key = match.group(1)
        if key in values:
            return str(values[key])
        return match.group(0)

    return _SIMPLE_PLACEHOLDER_RE.sub(repl, template)

# logger config
LOGGER_NAME = "AutomationFramework@"
LOGGING_LEVEL = logging.INFO
LOGGING_FORMAT = "%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s"

# LLM logger config (separate from main logger)
LLM_LOGGER_NAME = "LLMInteraction@"
LLM_LOGGING_FORMAT = "%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s"

ROOT_DIR = Path(os.getenv("AF_HOME", Path(__file__).resolve().parent)).resolve()
load_dotenv(ROOT_DIR / ".env")

test = os.getenv("AF_TEST_MODE", "1").lower() in {"1", "true", "yes", "on"}
DEFAULT_DELETE_OUT = True
HOUR = 3600
MAX_DURATION = 3 * HOUR
MAX_TIME = 3
# Fuzzing config
PWD = ROOT_DIR.as_posix()
TOOLS_PATH = ROOT_DIR / "tools"
LLVM_BIN_PATH = TOOLS_PATH / "bin"


def _resolve_existing_path(*candidates: Path) -> Path:
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _resolve_tool_path(env_var: str, candidates: list[Path], which_names: list[str]) -> str:
    override = os.getenv(env_var)
    if override:
        return os.fspath(Path(override).expanduser())

    for candidate in candidates:
        if candidate.exists():
            return os.fspath(candidate)

    for name in which_names:
        resolved = shutil.which(name)
        if resolved:
            return resolved

    return os.fspath(candidates[0]) if candidates else (which_names[0] if which_names else "")


AFL_PATH = Path(os.getenv("AF_AFL_PATH", ROOT_DIR / "AFLplusplus")).expanduser()
SHOWMAP_PATH = Path(
    _resolve_tool_path(
        "AF_SHOWMAP_BIN",
        [AFL_PATH / "afl-showmap"],
        ["afl-showmap"],
    )
)

SVF_SLICE_PATH = _resolve_existing_path(
    Path(os.getenv("AF_SVF_SLICE_PATH", "")).expanduser() if os.getenv("AF_SVF_SLICE_PATH") else ROOT_DIR / "tools" / "svf_slice",
    ROOT_DIR / "svf" / "build",
)

# Keep the old workflow for coverage tools:
# - prefer the in-repo llvm-project build for llvm-cov
# - prefer system llvm-profdata (older versions may be required by gclang traces)
LLVM_COV_BIN = _resolve_tool_path(
    "AF_LLVM_COV_BIN",
    [
        ROOT_DIR / "llvm-project" / "build" / "bin" / "llvm-cov",
        LLVM_BIN_PATH / "llvm-cov",
    ],
    ["llvm-cov-10", "llvm-cov", "llvm-cov-14"],
)
LLVM_PROFDATA_BIN = _resolve_tool_path(
    "AF_LLVM_PROFDATA_BIN",
    [],
    ["llvm-profdata-14", "llvm-profdata", "llvm-profdata-10", "llvm-profdata-11", "llvm-profdata-18"],
)
LLVM_OPT_BIN = _resolve_tool_path(
    "AF_LLVM_OPT_BIN",
    [LLVM_BIN_PATH / "opt"],
    ["opt"],
)
SLICE_PLUGIN_PATH = _resolve_existing_path(
    SVF_SLICE_PATH / "libBranchConditionSlicer.so",
    SVF_SLICE_PATH / "libBranchConditionSlicer_v2.so",
)
FUZZER_NAME = "default"
PROJECT = os.getenv("AF_PROJECT", "mujs")
OUTPUT_DIR_NAME = os.getenv("AF_OUTPUT_DIR", "out")  # 输出目录名，可通过命令行 -o 参数修改


def _sanitize_log_component(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return sanitized or "unknown"


def sanitize_fs_component(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", (value or "").strip())
    sanitized = sanitized.strip("._-")
    return sanitized or "unknown"


def _build_log_file_name(prefix: str, lib_name: str) -> str:
    now = time.localtime()
    date_part = time.strftime("%Y-%m-%d", now)
    time_part = time.strftime("%H_%M_%S", now)
    return f"{prefix}-{_sanitize_log_component(lib_name)}-{date_part}-{time_part}.log"


LOGGER_FILE_NAME = _build_log_file_name("autoframe", PROJECT)
LLM_LOG_FILE_NAME = _build_log_file_name("llm_interactions", PROJECT)

# Field parsing configuration
# 只有在此列表中的项目才会尝试执行字段解析
# 如果能映射污点但无法解出字段可以直接尝试变污点对应位置
ENABLE_FIELD_PARSING = ['libpng', 'lcms', "jhead", "libxml", "cjson", "jansson", "jq", "mujs", "cflow"]  # 结构化/文本格式支持语义字段解析

# coverage tracer config
# MAP_SIZE = 18
TEST_SEED_DELTA = 1
if test:
    THRESHOLD_TIME = 10
    THRESHOLD_COV_DELTA = 1  # 至少需要增加 1 个 edge 才算有效增长
else:
    THRESHOLD_TIME = 120  # 覆盖率无增长超过120s
    THRESHOLD_COV_DELTA = 1  # 至少需要增加 20 个 edge 才算有效增长

# 旧逻辑保留：
CHECK_INTERVAL = 10  # 每 10 秒检查一次
TIMEOUT = 30
AUTOBUG_PRIME_MAX_SEEDS_PER_ROUND = int(os.getenv("AF_AUTOBUG_PRIME_MAX_SEEDS_PER_ROUND", "32"))
PROJECT_HOME = ROOT_DIR / "benchmarks" / PROJECT
STATIC_PATH = Path(PROJECT_HOME) / "static"
OUTPUT_PATH = PROJECT_HOME / OUTPUT_DIR_NAME
RUN_ROOT = OUTPUT_PATH
RUN_LOG_PATH = OUTPUT_PATH / "logs"
LOG_PATH = RUN_LOG_PATH
LLM_LOG_PATH = RUN_LOG_PATH / "llm"
RUN_RUNTIME_PATH = OUTPUT_PATH / "runtime"
RUN_LLM_PATH = RUN_RUNTIME_PATH / "llm"
RUN_MUT_PATH = RUN_RUNTIME_PATH / "mut"
RUN_SLICE_PATH = RUN_RUNTIME_PATH / "slice"
RUN_TRACE_PATH = RUN_RUNTIME_PATH / "trace"
RUN_TAINT_PATH = RUN_RUNTIME_PATH / "taint"
RUN_SEMANTIC_FIELDS_PATH = RUN_RUNTIME_PATH / "semantic_fields"
RUN_SYMBOLIC_PATH = RUN_RUNTIME_PATH / "symbolic"
PLOT_PATH = Path(PROJECT_HOME) / OUTPUT_DIR_NAME / FUZZER_NAME / "plot_data"
SEED_PATH = Path(PROJECT_HOME) / OUTPUT_DIR_NAME / FUZZER_NAME / "queue"
FUZZER_STATS_PATH = Path(PROJECT_HOME) / OUTPUT_DIR_NAME / FUZZER_NAME / "fuzzer_stats"
DEPTH_THRESHOLD = 0

# ============================================================
# Input/Output Paths
# ============================================================
INPUT_PATH = PROJECT_HOME / "in"
LLM_QUEUE_PATH = OUTPUT_PATH / "LLM" / "queue"
MUT_QUEUE_PATH = OUTPUT_PATH / "mut" / "queue"
SYMBOLIC_QUEUE_PATH = OUTPUT_PATH / "symbolic" / "queue"

# ============================================================
# Target Binary Paths
# ============================================================
AFL_TARGET_PATH = PROJECT_HOME / "target" / "afl" / f"{PROJECT}_fuzz"
TRACE_TARGET_PATH = PROJECT_HOME / "target" / "trace" / f"{PROJECT}_trace"

# ============================================================
# Source Code Paths
# ============================================================
SRC_PATH = PROJECT_HOME / "src"
SRC_BEAR_PATH = PROJECT_HOME / "src_bear"
BUILD_PATH = PROJECT_HOME / "build"
BUILD_TMP_PATH = BUILD_PATH / "tmp"


def resolve_source_path(path_like) -> Path | None:
    """Resolve build-recorded file paths back to an existing source file."""
    if not path_like:
        return None

    raw_path = Path(path_like)
    candidate_strings: list[str] = []

    try:
        candidate_strings.append(raw_path.as_posix())
    except Exception:
        candidate_strings.append(str(path_like))

    # Some binaries embed paths from per-variant build directories rather than src/.
    build_variants = ("llvmcov", "fuzz", "cmplog", "trace", "ipl", "tmp")
    base_candidates = [
        BUILD_PATH.as_posix(),
        (PROJECT_HOME / "build").as_posix(),
    ]

    for candidate in list(candidate_strings):
        candidate_path = Path(candidate)
        if not candidate_path.is_absolute():
            candidate_strings.append((SRC_BEAR_PATH / candidate_path).as_posix())
            candidate_strings.append((SRC_PATH / candidate_path).as_posix())

        # Some projects keep generated sources as templates such as shell.c.in.
        if not candidate.endswith(".in"):
            candidate_strings.append(f"{candidate}.in")

        for build_base in base_candidates:
            for variant in build_variants:
                build_prefix = f"{build_base}/{variant}/"
                if build_prefix in candidate:
                    candidate_strings.append(candidate.replace(build_prefix, f"{SRC_PATH.as_posix()}/"))

        if "/src_bear/" not in candidate and candidate.startswith(f"{PROJECT_HOME.as_posix()}/"):
            rel = candidate.removeprefix(f"{PROJECT_HOME.as_posix()}/")
            candidate_strings.append((SRC_BEAR_PATH / rel).as_posix())

        if "/src/" not in candidate and candidate.startswith(f"{PROJECT_HOME.as_posix()}/"):
            rel = candidate.removeprefix(f"{PROJECT_HOME.as_posix()}/")
            candidate_strings.append((SRC_PATH / rel).as_posix())

        filename = Path(candidate).name
        if filename:
            candidate_strings.append((SRC_BEAR_PATH / filename).as_posix())
            candidate_strings.append((SRC_PATH / filename).as_posix())
            if not filename.endswith(".in"):
                candidate_strings.append((SRC_BEAR_PATH / f"{filename}.in").as_posix())
                candidate_strings.append((SRC_PATH / f"{filename}.in").as_posix())

    seen = set()
    for candidate in candidate_strings:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        resolved = Path(candidate)
        if resolved.exists():
            return resolved

    filename = Path(str(path_like)).name
    if filename:
        recursive_targets = [filename]
        if not filename.endswith(".in"):
            recursive_targets.append(f"{filename}.in")
        for source_root in (SRC_BEAR_PATH, SRC_PATH):
            if not source_root.exists():
                continue
            for target_name in recursive_targets:
                for match in source_root.rglob(target_name):
                    if match.exists():
                        return match

    return None

# ============================================================
# Processing Paths
# ============================================================
TSEED_ISI_PATH = RUN_TAINT_PATH / "tseed.isi"
TSEED_ISI_JSON_PATH = RUN_TAINT_PATH / "tseed.isi.json"
RESULT_JSON_PATH = RUN_SEMANTIC_FIELDS_PATH / "result.json"
RELEVANT_FIELD_JSON_PATH = RUN_SEMANTIC_FIELDS_PATH / "relevant_field.json"
BATCH_MUTATE_SCRIPT_PATH = RUN_MUT_PATH / "scripts" / "batch_mutate.py"
GENERATOR_SCRIPT_PATH = RUN_LLM_PATH / "scripts" / "generator.py"
MUTATOR_SCRIPT_PATH = RUN_MUT_PATH / "scripts" / "mutator.py"
def _load_static_data(static_path: Path):
    static_file = static_path / "static.json"
    if not static_file.exists():
        logging.getLogger(__name__).warning(
            "static.json not found at %s; using empty static metadata until a project dataset is mounted.",
            static_file,
        )
        return {}, [], [], []

    with open(static_file, 'r') as f:
        static_data = ujson.load(f)
    return (
        static_data,
        static_data.get("basic_blocks", []),
        static_data.get("functions", []),
        static_data.get("callsites", []),
    )


static, bbs, funcs, callsites = _load_static_data(STATIC_PATH)

def update_indirect_calls(static_func, new_edges):
    # 创建函数ID到函数对象的映射，避免遍历所有函数
    func_map = {f["id"]: f for f in static_func}

    for func_id, new_calls in new_edges.items():
        if func_id in func_map:
            func = func_map[func_id]
            # 只在需要时创建set，使用原地更新更高效
            existing_calls = set(func["calls"])
            existing_calls.update(new_calls)  # 原地合并
            func["calls"] = list(existing_calls)

EXEC_ARGS = ""

# llvm-cov config
COV_TARGET_PATH = PROJECT_HOME / "target" / "llvmcov" / "target"

# DSE config
DSE_SEEDS_NUM = 3
DSE_DOCKER_TMP_PATH = Path("/root/Project") / OUTPUT_DIR_NAME / "runtime" / "symbolic" / "tmp"
DSE_TMP_PATH = RUN_SYMBOLIC_PATH / "tmp"
DSE_TARGET_PATH = PROJECT_HOME / OUTPUT_DIR_NAME / "symbolic" / "queue"
DSE_PROGRAM = PROJECT_HOME / "target" / "symbolic" / "target_binary"

# LLM config
def _provider_env(provider: str, default_base_url: str) -> tuple[str, str]:
    """Return provider-specific base URL and API key, with AF_* kept as legacy overrides."""
    base_url = os.getenv(f"{provider}_BASE_URL", "") or default_base_url
    api_key = os.getenv(f"{provider}_API_KEY", "")
    return os.getenv("AF_BASE_URL", "") or base_url, os.getenv("AF_API_KEY", "") or api_key


model = os.getenv("AF_MODEL_PROVIDER", "qwen-max")
MODEL = os.getenv("AF_MODEL_NAME", "")
BASE_URL = ""
API_KEY = ""
PREFIX = ""
if "deepseek" in model:
    BASE_URL, API_KEY = _provider_env("DEEPSEEK", "https://api.deepseek.com/beta")
    PREFIX = "deepseek/"
    if not MODEL and model == "deepseek-chat":
        MODEL = "deepseek-chat"
    elif not MODEL and model == "deepseek-reasoner":
        MODEL = "deepseek-reasoner"
elif "qwen" in model:
    BASE_URL, API_KEY = _provider_env("DASHSCOPE", "https://dashscope.aliyuncs.com/compatible-mode/v1")
    if not MODEL and model == "qwen-max":
        MODEL = "qwen3-max"
    elif not MODEL and model == "qwen-long":
        MODEL = "qwen-long"
    elif not MODEL and model == "qwen-coder":
        MODEL = "qwen3-coder-plus"
    elif not MODEL and model == "qwen-plus":
        MODEL = "qwen3.5-plus"
elif "kimi" in model:
    MODEL = MODEL or "kimi-k2-0711-preview"
    BASE_URL, API_KEY = _provider_env("MOONSHOT", "https://api.moonshot.cn/v1")
elif "glm" in model:
    BASE_URL, API_KEY = _provider_env("BIGMODEL", "https://open.bigmodel.cn/api/paas/v4/")
    if not MODEL and (model == "glm5" or model == "glm-5"):
        MODEL = "glm-5"
    elif not MODEL and (model == "glm4.7" or model == "glm-4.7"):
        MODEL = "glm-4.7"

if not MODEL:
    MODEL = model

# LLM sampling config
LLM_TEMPERATURE = float(os.getenv("AF_LLM_TEMPERATURE", "0.5"))
LLM_TOP_P = float(os.getenv("AF_LLM_TOP_P", "1.0"))

# Thinking mode configuration
# Models that support thinking mode (extra_body={"thinking": {"type": "enabled"}})
# Add model names or patterns here to enable thinking for specific models
ENABLE_THINKING_MODELS = [
    # "glm-5",  # 智谱 GLM-5 模型支持 thinking
    # Add more models here, e.g.:
    "deepseek-reasoner",
    # "qwen3.5-plus", # default thinking open
    # "o1-preview",
    # "o1-mini",
]


def is_thinking_enabled(model_name: str, model_config: str = model) -> bool:
    """
    Check if thinking mode should be enabled for the current model.

    Args:
        model_name: The actual model name being used
        model_config: The model configuration name from config

    Returns:
        True if thinking mode should be enabled, False otherwise
    """
    for pattern in ENABLE_THINKING_MODELS:
        if pattern in model_name or pattern in model_config:
            return True
    return False



## LLM timeout and retry configuration
LLM_TIMEOUT = 300  # LLM API timeout in seconds (5 minutes)
LLM_MAX_RETRIES = 3  # Maximum retry attempts for LLM API calls
LLM_RETRY_DELAY = 5  # Delay between retries in seconds00  # LLM API timeout in minutes (3 minutes = 180 seconds)
LLM_TMP_PATH = RUN_LLM_PATH / "tmp"
# LLM_TARGET_PATH = PROJECT_HOME / "out" / "LLM" / "queue"
PROMPT_FILE_NAME = "prompt.yaml"
PROMPT_PATH = ROOT_DIR / "LLM" / PROMPT_FILE_NAME
if PROMPT_PATH.exists():
    with open(PROMPT_PATH) as f:
        prompts = yaml.safe_load(f)
else:
    logging.getLogger(__name__).warning("Prompt file not found at %s; using empty prompt registry.", PROMPT_PATH)
    prompts = {"prompt": {}}

bcfile_path = Path(PROJECT_HOME) / 'target' / 'trace' / f"{PROJECT}_trace.bc"
slice_out = os.fspath(RUN_SLICE_PATH / "slice.txt")
IPL_TARGET_PATH = PROJECT_HOME / "target" / "ipl" / f"{PROJECT}_ipl"
MUT_TMP_PATH = RUN_MUT_PATH / "tmp"

# Flagrec tool configuration
FLAGREC_BITCODE = bcfile_path  # Reuse existing trace bitcode
FLAGREC_CACHE = STATIC_PATH / "flagrec_cache.json"
FLAGREC_MIN_CONFIDENCE = 0.5


@dataclass(frozen=True)
class ExperimentPaths:
    run_root: Path
    log_dir: Path
    llm_log_dir: Path
    runtime_dir: Path
    llm_runtime_dir: Path
    mut_runtime_dir: Path
    slice_dir: Path
    trace_dir: Path
    taint_dir: Path
    semantic_fields_dir: Path
    symbolic_dir: Path
    default_queue: Path
    llm_queue: Path
    mut_queue: Path
    symbolic_queue: Path


def get_run_paths() -> ExperimentPaths:
    return ExperimentPaths(
        run_root=RUN_ROOT,
        log_dir=LOG_PATH,
        llm_log_dir=LLM_LOG_PATH,
        runtime_dir=RUN_RUNTIME_PATH,
        llm_runtime_dir=RUN_LLM_PATH,
        mut_runtime_dir=RUN_MUT_PATH,
        slice_dir=RUN_SLICE_PATH,
        trace_dir=RUN_TRACE_PATH,
        taint_dir=RUN_TAINT_PATH,
        semantic_fields_dir=RUN_SEMANTIC_FIELDS_PATH,
        symbolic_dir=RUN_SYMBOLIC_PATH,
        default_queue=SEED_PATH,
        llm_queue=LLM_QUEUE_PATH,
        mut_queue=MUT_QUEUE_PATH,
        symbolic_queue=SYMBOLIC_QUEUE_PATH,
    )


def ensure_runtime_layout() -> None:
    required_dirs = [
        OUTPUT_PATH,
        LOG_PATH,
        LLM_LOG_PATH,
        RUN_RUNTIME_PATH,
        RUN_LLM_PATH,
        RUN_LLM_PATH / "tmp",
        RUN_LLM_PATH / "scripts",
        RUN_MUT_PATH,
        RUN_MUT_PATH / "tmp",
        RUN_MUT_PATH / "scripts",
        RUN_SLICE_PATH,
        RUN_TRACE_PATH,
        RUN_TAINT_PATH,
        RUN_SEMANTIC_FIELDS_PATH,
        RUN_SYMBOLIC_PATH,
        RUN_SYMBOLIC_PATH / "tmp",
        LLM_QUEUE_PATH,
        MUT_QUEUE_PATH,
        SYMBOLIC_QUEUE_PATH,
    ]
    for path in required_dirs:
        Path(path).mkdir(parents=True, exist_ok=True)


def get_branch_dir_name(branch_id: str) -> str:
    return f"branch_{sanitize_fs_component(branch_id)}"


def get_branch_output_dir(branch_id: str) -> Path:
    return OUTPUT_PATH / get_branch_dir_name(branch_id)


def get_branch_queue_dir(branch_id: str) -> Path:
    return get_branch_output_dir(branch_id) / "queue"


def get_named_output_dir(name: str) -> Path:
    return OUTPUT_PATH / sanitize_fs_component(name)


def get_named_queue_dir(name: str) -> Path:
    return get_named_output_dir(name) / "queue"


def get_batch_mutation_dir(branch_id: str) -> Path:
    return get_branch_output_dir(branch_id) / "batch_mutation"


def get_batch_mutation_script_path(branch_id: str) -> Path:
    return get_batch_mutation_dir(branch_id) / "script.py"


def get_batch_mutation_filtered_seed_dir(branch_id: str) -> Path:
    return get_batch_mutation_dir(branch_id) / "filtered_seeds"


def build_queue_seed_name(
    seed_id: int,
    *,
    path_prefix: str | None = None,
    roadblock_id: int | str | None = None,
    src_id: int | str | None = None,
    aux_id: int | str | None = None,
    suffix: str = "",
) -> str:
    parts = [f"id:{int(seed_id):06}"]
    if path_prefix:
        parts.append(f"path:{sanitize_fs_component(path_prefix)}")
    if roadblock_id is not None:
        parts.append(f"bid:{int(roadblock_id):06}")
    if src_id is not None:
        parts.append(f"src:{int(src_id):06}")
    if aux_id is not None:
        parts.append(f"aux:{int(aux_id):02}")
    return ",".join(parts) + suffix


def next_queue_seed_path(
    queue_dir: str | Path,
    *,
    path_prefix: str | None = None,
    roadblock_id: int | str | None = None,
    src_id: int | str | None = None,
    aux_id: int | str | None = None,
    suffix: str = "",
) -> Path:
    queue_path = Path(queue_dir)
    queue_path.mkdir(parents=True, exist_ok=True)
    next_id = 0
    for entry in queue_path.iterdir():
        if not entry.is_file():
            continue
        match = re.match(r"id:(\d+)", entry.name)
        if not match:
            continue
        next_id = max(next_id, int(match.group(1)) + 1)

    while True:
        candidate = queue_path / build_queue_seed_name(
            next_id,
            path_prefix=path_prefix,
            roadblock_id=roadblock_id,
            src_id=src_id,
            aux_id=aux_id,
            suffix=suffix,
        )
        if not candidate.exists():
            return candidate
        next_id += 1


def iter_experiment_queue_dirs() -> list[Path]:
    queue_dirs = [SEED_PATH, LLM_QUEUE_PATH, MUT_QUEUE_PATH, SYMBOLIC_QUEUE_PATH]
    seen: set[str] = {os.fspath(path.resolve()) for path in queue_dirs if path.exists()}
    try:
        for entry in sorted(OUTPUT_PATH.iterdir()):
            if not entry.is_dir():
                continue
            queue_path = entry / "queue"
            if queue_path.is_dir():
                resolved = os.fspath(queue_path.resolve())
                if resolved not in seen:
                    queue_dirs.append(queue_path)
                    seen.add(resolved)
    except FileNotFoundError:
        pass
    return queue_dirs


def find_seed_path(seed_name: str) -> Path | None:
    candidate = Path(seed_name)
    if candidate.is_absolute() and candidate.exists():
        return candidate

    for queue_dir in iter_experiment_queue_dirs():
        queue_candidate = queue_dir / candidate.name
        if queue_candidate.exists():
            return queue_candidate
    return None


def get_slice_output_path(label: str | None = None) -> Path:
    suffix = sanitize_fs_component(label or "slice")
    return RUN_SLICE_PATH / f"{suffix}.txt"


def get_generator_script_path(bottleneck_id: int | str, seed_id: int | str) -> Path:
    return RUN_LLM_PATH / "scripts" / f"generator_bid_{int(bottleneck_id):06}_seed_{int(seed_id):06}.py"


def get_mutator_script_path(seed_id: int | str, orig_seed: str | None = None) -> Path:
    stem = f"mutator_seed_{int(seed_id):06}"
    if orig_seed:
        stem += f"_{sanitize_fs_component(Path(orig_seed).name)}"
    return RUN_MUT_PATH / "scripts" / f"{stem}.py"


def get_flagrec_output_dir() -> Path:
    return STATIC_PATH / "flagrec_output"


def get_taint_artifact_dir(seed_name: str, roadblock_id: int | str) -> Path:
    return RUN_TAINT_PATH / f"rb_{int(roadblock_id):06}_{sanitize_fs_component(seed_name)}"


def get_semantic_fields_artifact_dir(seed_name: str, roadblock_id: int | str) -> Path:
    return RUN_SEMANTIC_FIELDS_PATH / f"rb_{int(roadblock_id):06}_{sanitize_fs_component(seed_name)}"

# Failed roadblock bookkeeping
# Failed roadblocks are retained for the whole session and are not retried by
# the main workflow. This avoids re-scheduling the same failed bottleneck after
# the in-process guided retry flow has already been attempted.
PASS_ROADBLOCK_TIMEOUT = None

# State variable inference configuration
# Phase 1: Lightweight hardcoded mapping (always enabled)
# Phase 2: LLM-assisted state inference (experimental)
ENABLE_STATE_INFERENCE_PHASE_2 = True  # Set to True to enable LLM-assisted state inference

# Phase 3: Multi-stage progressive analysis configuration
ENABLE_STATE_INFERENCE_PHASE_3 = True  # Set to True to enable multi-stage analysis

# Extended slice configuration for Phase 3
MAX_SLICE_SIZE = 5000  # Maximum slice size in characters for extended analysis
EXTENDED_SLICE_CACHE_SIZE = 100  # Maximum number of cached slices
SETUP_FUNC_CACHE_SIZE = 200  # Maximum number of cached setup functions

# ============================================================
# 状态驱动映射配置 (Path B 增强)
# ============================================================

# 启用状态驱动映射作为 Path B
# 设为 False 时完全跳过 StateDrivenMapper，直接使用原有 Path B/C
ENABLE_STATE_DRIVEN_PATH_B = True

# Simplified roadblock breakthrough path toggles for ablation.
ENABLE_SIMPLIFIED_FLAG_PATH = True
ENABLE_SIMPLIFIED_TAINT_MUTATION_PATH = True
ENABLE_SIMPLIFIED_STATE_DRIVEN_PATH = True
ENABLE_SIMPLIFIED_FIELD_MUTATION_PATH = True
ENABLE_SIMPLIFIED_BATCH_MUTATION_PATH = True
ENABLE_SIMPLIFIED_XML_GRAMMAR_PATH = True
ENABLE_SIMPLIFIED_XML_GRAMMAR_LLM_SPEC = True
ENABLE_SIMPLIFIED_XML_GRAMMAR_LLM_SCORING = True
ENABLE_SIMPLIFIED_DIRECT_GENERATION_PATH = True

# v2 流程前置判断开关
# True: 执行 judge_conflict_v2 前置判断
# False: 跳过前置判断，直接按默认放行策略进入后续路径选择
ENABLE_V2_PRE_JUDGE = False

# 格式规范增强开关
# 对于有标准格式的项目 (如 lcms 的 ICC Profile)，使用已知偏移
ENABLE_FORMAT_SPEC_ENHANCEMENT = True

# 状态驱动映射超时 (秒)
# 防止 LLM 分析时间过长
STATE_DRIVEN_TIMEOUT = 30

# 映射结果缓存
# 缓存已学习的映射以避免重复分析
STATE_DRIVEN_CACHE_SIZE = 50
STATE_DRIVEN_CACHE_TTL = 1800  # 30分钟

# 调试选项
STATE_DRIVEN_DEBUG = False  # 输出详细的映射分析日志

# ============================================================
# 未覆盖代码探索配置 (Uncovered Code Exploration)
# ============================================================

# Zero-branch path has been removed from the active scheduler/main flow.
ENABLE_ZERO_BRANCH_SECOND_STAGE = False

# 启用开关：控制是否探索不同类型的未覆盖代码
ENABLE_ZERO_COVERED_EXPLORATION = False  # 零覆盖分支路径已停用
ENABLE_UNCALLED_FUNC_EXPLORATION = True  # 探索未调用函数
ENABLE_UNEXECUTED_BLOCK_EXPLORATION = True  # 探索未执行基本块

# 每轮最大尝试次数（防止陷入单一类型）
MAX_ZERO_COVERED_ATTEMPTS = 3  # 零覆盖分支每轮最多尝试3个
MAX_UNCALLED_ATTEMPTS = 2      # 未调用函数每轮最多尝试2个
MAX_UNEXECUTED_ATTEMPTS = 3    # 未执行基本块每轮最多尝试3个

# 优先级策略
EXPLORATION_STRATEGY = 'balanced'  # 'depth' (深层优先), 'breadth' (浅层优先), 'balanced' (综合)

# 该配置不再参与 zero-branch second-stage 触发，仅保留给其他实验性未覆盖探索逻辑
ONE_SIDED_EXHAUSTION_THRESHOLD = 0

# 输入类型分类：根据目标库的输入方式选择不同的生成策略
# 文本输入型库：LLM 直接生成文本内容，写入 seed 文件
TEXT_INPUT_LIBS = ['mujs', 'sqlite', 'libxml', 'cjson', 'jansson', 'cflow']
# 二进制输入型库：LLM 生成 Python 脚本，执行脚本产生二进制文件
BINARY_INPUT_LIBS = ['libpng', 'lcms', 'libtiff', 'libwebp', 'openssl']

# Helper functions to get formatted prompts with shared sections
def get_formatted_prompt(prompt_key: str, sys_prompt_key: str = 'sys_prompt', **kwargs):
    """
    Get a formatted prompt with shared sections pre-filled.

    Args:
        prompt_key: The key in prompts['prompt'] to access (e.g., 'generate_script')
        sys_prompt_key: The key within the prompt dict (default: 'sys_prompt')
        **kwargs: Additional format arguments

    Returns:
        The formatted prompt string with shared sections filled in
    """
    prompt = prompts['prompt'][prompt_key][sys_prompt_key]

    # Get shared sections from prompts['prompt']
    prompt_section = prompts.get('prompt', {})
    shared_sections = {
        'format_library_table': prompt_section.get('_format_library_mapping', ''),
        'structure_aware_mutation': prompt_section.get('_structure_aware_mutation', ''),
        'crc_checksum_rules': prompt_section.get('_crc_checksum_rules', ''),
        'learned_mappings': prompt_section.get('_learned_mappings', ''),
        'mapping_guidance': prompt_section.get('_mapping_guidance', ''),
    }

    # Merge with additional kwargs (additional kwargs can override shared sections if needed)
    shared_sections.update(kwargs)

    # Format the prompt while preserving unknown placeholders.
    try:
        return _safe_prompt_substitute(prompt, shared_sections)
    except Exception as e:
        logging.warning(f"Failed to format prompt {prompt_key}.{sys_prompt_key}: {e}")
        return prompt


def get_formatted_user_prompt(prompt_key: str, **kwargs):
    """
    Get a formatted user prompt with placeholders filled.

    Args:
        prompt_key: The key in prompts['prompt'] to access
        **kwargs: Format arguments (typically codes, lib, constraints, etc.)

    Returns:
        The formatted user prompt string
    """
    prompt = prompts['prompt'][prompt_key]['user_prompt']
    try:
        return _safe_prompt_substitute(prompt, kwargs)
    except Exception as e:
        logging.warning(f"Failed to format user prompt {prompt_key}: {e}")
        return prompt


def build_runtime_command_context(
    sample_seed_path: str = "/path/to/seed_input",
    generator_output_path: str = "<output_path>",
) -> str:
    """Build a reusable prompt section describing the actual runtime command."""
    exec_args = [arg for arg in EXEC_ARGS.split(sep=" ") if arg]

    def materialize_args(seed_path: str) -> list[str]:
        return [arg.replace("@@", seed_path) for arg in exec_args]

    def format_cmd(prog, args: list[str]) -> str:
        return shlex.join([os.fspath(prog), *args])

    target_args = materialize_args(sample_seed_path)

    lines = [
        "<runtime_command>",
        "important:",
        "- Distinguish the generator script argv from the target program argv.",
        "- `@@` is replaced with the generated seed path at runtime.",
        "- Only argv positions shown below are guaranteed runtime arguments.",
        f"seed_placeholder: @@",
        f"generator_command: {shlex.join(['python', os.fspath(GENERATOR_SCRIPT_PATH), generator_output_path])}",
        f"target_program: {os.fspath(AFL_TARGET_PATH)}",
        f"target_args_template: {' '.join(exec_args) if exec_args else '(none)'}",
        f"example_target_command: {format_cmd(AFL_TARGET_PATH, target_args)}",
        f"trace_program: {os.fspath(TRACE_TARGET_PATH)}",
        f"example_trace_command: {format_cmd(TRACE_TARGET_PATH, target_args)}",
        f"coverage_program: {os.fspath(COV_TARGET_PATH)}",
        f"example_coverage_command: {format_cmd(COV_TARGET_PATH, target_args)}",
        "</runtime_command>",
    ]
    return "\n".join(lines)


def set_project(project_name: str, output_dir_name: str = "out"):
    """运行时设置当前project，重新计算所有相关路径

    Args:
        project_name: project名称
        output_dir_name: 输出目录名，默认为"out"

    注意：此函数会修改 config 模块的全局变量，并更新所有通过 'from config import *' 导入的模块。
    """
    global PROJECT, OUTPUT_DIR_NAME, PROJECT_HOME, STATIC_PATH, PLOT_PATH, SEED_PATH, FUZZER_STATS_PATH
    global RUN_ROOT, RUN_LOG_PATH, RUN_RUNTIME_PATH, RUN_LLM_PATH, RUN_MUT_PATH
    global RUN_SLICE_PATH, RUN_TRACE_PATH, RUN_TAINT_PATH, RUN_SEMANTIC_FIELDS_PATH, RUN_SYMBOLIC_PATH
    global LLM_TMP_PATH, MUT_TMP_PATH, bcfile_path, COV_TARGET_PATH
    global IPL_TARGET_PATH, bbs, funcs, slice_out
    global DSE_TMP_PATH, DSE_TARGET_PATH, DSE_PROGRAM, DSE_DOCKER_TMP_PATH
    global FLAGREC_BITCODE, FLAGREC_CACHE
    global LOGGER_FILE_NAME, LLM_LOG_FILE_NAME
    # Input/Output Paths
    global INPUT_PATH, OUTPUT_PATH, LOG_PATH, LLM_LOG_PATH, LLM_QUEUE_PATH, MUT_QUEUE_PATH, SYMBOLIC_QUEUE_PATH
    # Target Binary Paths
    global AFL_TARGET_PATH, TRACE_TARGET_PATH
    # Source Code Paths
    global SRC_PATH, SRC_BEAR_PATH, BUILD_PATH, BUILD_TMP_PATH
    # Processing Paths
    global TSEED_ISI_PATH, TSEED_ISI_JSON_PATH, RESULT_JSON_PATH, RELEVANT_FIELD_JSON_PATH
    global BATCH_MUTATE_SCRIPT_PATH, GENERATOR_SCRIPT_PATH, MUTATOR_SCRIPT_PATH

    PROJECT = project_name
    OUTPUT_DIR_NAME = output_dir_name
    PROJECT_HOME = ROOT_DIR / "benchmarks" / PROJECT
    STATIC_PATH = Path(PROJECT_HOME) / "static"
    OUTPUT_PATH = PROJECT_HOME / OUTPUT_DIR_NAME
    RUN_ROOT = OUTPUT_PATH
    RUN_LOG_PATH = OUTPUT_PATH / "logs"
    LOG_PATH = RUN_LOG_PATH
    LLM_LOG_PATH = RUN_LOG_PATH / "llm"
    LOGGER_FILE_NAME = _build_log_file_name("autoframe", PROJECT)
    LLM_LOG_FILE_NAME = _build_log_file_name("llm_interactions", PROJECT)
    RUN_RUNTIME_PATH = OUTPUT_PATH / "runtime"
    RUN_LLM_PATH = RUN_RUNTIME_PATH / "llm"
    RUN_MUT_PATH = RUN_RUNTIME_PATH / "mut"
    RUN_SLICE_PATH = RUN_RUNTIME_PATH / "slice"
    RUN_TRACE_PATH = RUN_RUNTIME_PATH / "trace"
    RUN_TAINT_PATH = RUN_RUNTIME_PATH / "taint"
    RUN_SEMANTIC_FIELDS_PATH = RUN_RUNTIME_PATH / "semantic_fields"
    RUN_SYMBOLIC_PATH = RUN_RUNTIME_PATH / "symbolic"
    PLOT_PATH = Path(PROJECT_HOME) / OUTPUT_DIR_NAME / FUZZER_NAME / "plot_data"
    SEED_PATH = Path(PROJECT_HOME) / OUTPUT_DIR_NAME / FUZZER_NAME / "queue"
    FUZZER_STATS_PATH = Path(PROJECT_HOME) / OUTPUT_DIR_NAME / FUZZER_NAME / "fuzzer_stats"

    # Input/Output Paths
    INPUT_PATH = PROJECT_HOME / "in"
    LLM_QUEUE_PATH = OUTPUT_PATH / "LLM" / "queue"
    MUT_QUEUE_PATH = OUTPUT_PATH / "mut" / "queue"
    SYMBOLIC_QUEUE_PATH = OUTPUT_PATH / "symbolic" / "queue"

    # Target Binary Paths
    AFL_TARGET_PATH = PROJECT_HOME / "target" / "afl" / f"{PROJECT}_fuzz"
    TRACE_TARGET_PATH = PROJECT_HOME / "target" / "trace" / f"{PROJECT}_trace"
    COV_TARGET_PATH = PROJECT_HOME / "target" / "llvmcov" / "target"
    bcfile_path = Path(PROJECT_HOME) / 'target' / 'trace' / f"{PROJECT}_trace.bc"
    slice_out = os.fspath(RUN_SLICE_PATH / "slice.txt")
    IPL_TARGET_PATH = PROJECT_HOME / "target" / "ipl" / f"{PROJECT}_ipl"

    # Source Code Paths
    SRC_PATH = PROJECT_HOME / "src"
    SRC_BEAR_PATH = PROJECT_HOME / "src_bear"
    BUILD_PATH = PROJECT_HOME / "build"
    BUILD_TMP_PATH = BUILD_PATH / "tmp"

    # LLM & mutation paths
    LLM_TMP_PATH = RUN_LLM_PATH / "tmp"
    MUT_TMP_PATH = RUN_MUT_PATH / "tmp"

    # DSE paths
    DSE_DOCKER_TMP_PATH = Path("/root/Project") / OUTPUT_DIR_NAME / "runtime" / "symbolic" / "tmp"
    DSE_TMP_PATH = RUN_SYMBOLIC_PATH / "tmp"
    DSE_TARGET_PATH = PROJECT_HOME / OUTPUT_DIR_NAME / "symbolic" / "queue"
    DSE_PROGRAM = PROJECT_HOME / "target" / "symbolic" / "target_binary"

    # Processing Paths
    TSEED_ISI_PATH = RUN_TAINT_PATH / "tseed.isi"
    TSEED_ISI_JSON_PATH = RUN_TAINT_PATH / "tseed.isi.json"
    RESULT_JSON_PATH = RUN_SEMANTIC_FIELDS_PATH / "result.json"
    RELEVANT_FIELD_JSON_PATH = RUN_SEMANTIC_FIELDS_PATH / "relevant_field.json"
    BATCH_MUTATE_SCRIPT_PATH = RUN_MUT_PATH / "scripts" / "batch_mutate.py"
    GENERATOR_SCRIPT_PATH = RUN_LLM_PATH / "scripts" / "generator.py"
    MUTATOR_SCRIPT_PATH = RUN_MUT_PATH / "scripts" / "mutator.py"

    # Flagrec paths
    FLAGREC_BITCODE = bcfile_path
    FLAGREC_CACHE = STATIC_PATH / "flagrec_cache.json"

    # 重新加载静态分析数据
    global static, bbs, funcs, callsites
    static, bbs, funcs, callsites = _load_static_data(STATIC_PATH)

    # 更新所有已导入 config 的模块的全局变量
    import sys
    import logging
    logger = logging.getLogger(__name__)
    updated_modules = []
    skipped_modules = []
    for module_name, module in sys.modules.items():
        if module is None:
            continue
        # 跳过 config 模块本身
        if module_name == 'config':
            continue
        # 检查模块是否导入了 config（通过查看是否有 PROJECT_HOME 等变量）
        if hasattr(module, 'PROJECT_HOME'):
            try:
                module.PROJECT = PROJECT
                module.OUTPUT_DIR_NAME = OUTPUT_DIR_NAME
                module.PROJECT_HOME = PROJECT_HOME
                module.STATIC_PATH = STATIC_PATH
                module.RUN_ROOT = RUN_ROOT
                module.RUN_LOG_PATH = RUN_LOG_PATH
                module.RUN_RUNTIME_PATH = RUN_RUNTIME_PATH
                module.RUN_LLM_PATH = RUN_LLM_PATH
                module.RUN_MUT_PATH = RUN_MUT_PATH
                module.LOGGER_FILE_NAME = LOGGER_FILE_NAME
                module.LLM_LOG_FILE_NAME = LLM_LOG_FILE_NAME
                module.RUN_SLICE_PATH = RUN_SLICE_PATH
                module.RUN_TRACE_PATH = RUN_TRACE_PATH
                module.RUN_TAINT_PATH = RUN_TAINT_PATH
                module.RUN_SEMANTIC_FIELDS_PATH = RUN_SEMANTIC_FIELDS_PATH
                module.RUN_SYMBOLIC_PATH = RUN_SYMBOLIC_PATH
                module.PLOT_PATH = PLOT_PATH
                module.SEED_PATH = SEED_PATH
                module.FUZZER_STATS_PATH = FUZZER_STATS_PATH
                module.INPUT_PATH = INPUT_PATH
                module.OUTPUT_PATH = OUTPUT_PATH
                module.LOG_PATH = LOG_PATH
                module.LLM_LOG_PATH = LLM_LOG_PATH
                module.LLM_QUEUE_PATH = LLM_QUEUE_PATH
                module.MUT_QUEUE_PATH = MUT_QUEUE_PATH
                module.SYMBOLIC_QUEUE_PATH = SYMBOLIC_QUEUE_PATH
                module.AFL_TARGET_PATH = AFL_TARGET_PATH
                module.TRACE_TARGET_PATH = TRACE_TARGET_PATH
                module.COV_TARGET_PATH = COV_TARGET_PATH
                module.SRC_PATH = SRC_PATH
                module.SRC_BEAR_PATH = SRC_BEAR_PATH
                module.TSEED_ISI_PATH = TSEED_ISI_PATH
                module.TSEED_ISI_JSON_PATH = TSEED_ISI_JSON_PATH
                module.RESULT_JSON_PATH = RESULT_JSON_PATH
                module.RELEVANT_FIELD_JSON_PATH = RELEVANT_FIELD_JSON_PATH
                module.BATCH_MUTATE_SCRIPT_PATH = BATCH_MUTATE_SCRIPT_PATH
                module.GENERATOR_SCRIPT_PATH = GENERATOR_SCRIPT_PATH
                module.MUTATOR_SCRIPT_PATH = MUTATOR_SCRIPT_PATH
                module.MUT_TMP_PATH = MUT_TMP_PATH
                module.LLM_TMP_PATH = LLM_TMP_PATH
                module.DSE_TMP_PATH = DSE_TMP_PATH
                module.DSE_DOCKER_TMP_PATH = DSE_DOCKER_TMP_PATH
                module.DSE_TARGET_PATH = DSE_TARGET_PATH
                module.bbs = bbs
                module.funcs = funcs
                module.callsites = callsites
                # 更新项目特定的路径变量（如果在模块中存在）
                if hasattr(module, 'bcfile_path'):
                    module.bcfile_path = bcfile_path
                if hasattr(module, 'slice_out'):
                    module.slice_out = slice_out
                if hasattr(module, 'IPL_TARGET_PATH'):
                    module.IPL_TARGET_PATH = IPL_TARGET_PATH
                if hasattr(module, 'FLAGREC_BITCODE'):
                    module.FLAGREC_BITCODE = FLAGREC_BITCODE
                if hasattr(module, 'FLAGREC_CACHE'):
                    module.FLAGREC_CACHE = FLAGREC_CACHE
                updated_modules.append(module_name)
            except Exception as e:
                # 记录无法更新的模块错误
                logger.warning(f"Failed to update module {module_name}: {e}")
                skipped_modules.append((module_name, str(e)))
        else:
            # 记录没有 PROJECT_HOME 属性的模块
            if module_name and not module_name.startswith('_') and hasattr(module, '__file__') and module.__file__:
                # 只记录可能是项目相关的模块（跳过标准库）
                skipped_modules.append((module_name, "No PROJECT_HOME attribute"))

    logger.info(f"set_project: Updated {len(updated_modules)} modules: {updated_modules[:10]}")  # 只显示前10个
    if skipped_modules:
        logger.debug(f"set_project: Skipped {len(skipped_modules)} modules")
        for name, reason in skipped_modules[:5]:  # 只显示前5个
            logger.debug(f"  - {name}: {reason}")
