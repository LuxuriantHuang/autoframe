from __future__ import annotations

import logging
import shlex
from pathlib import Path

import config


def bootstrap_project(
    *,
    project: str | None = None,
    output_dir: str = "out",
    test_mode: bool = False,
    exec_args: str | None = None,
    logger_component: str | None = None,
    console_logging_mode: str = "full",
):
    import main as core

    config.test = bool(test_mode)
    if config.test:
        config.THRESHOLD_TIME = 10
        config.THRESHOLD_COV_DELTA = 1
    else:
        config.THRESHOLD_TIME = 120
        config.THRESHOLD_COV_DELTA = 1
    if exec_args is not None:
        config.EXEC_ARGS = exec_args
    core.EXEC_ARGS = config.EXEC_ARGS
    core.THRESHOLD_TIME = config.THRESHOLD_TIME
    core.THRESHOLD_COV_DELTA = config.THRESHOLD_COV_DELTA

    if project or output_dir != "out":
        project_name = project if project else config.PROJECT
        config.set_project(project_name, output_dir)

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

    config.ensure_runtime_layout()
    core._logger_initialized = False
    core._logger_component_name = logger_component
    core._console_logging_mode = console_logging_mode
    core.llm_logger = None
    core.setup_logger()
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    core.init_attempted_roadblock_store()
    return core


def build_runtime_objects(core):
    from CoverageTracer import CoverageTracer
    from FuzzerRunner import FuzzerRunner
    from LLM.LLMUtil import LLMUtil

    input_dir = core.os.fspath(config.INPUT_PATH)
    output_dir = core.os.fspath(config.OUTPUT_PATH)
    fuzzing_args = shlex.split(config.EXEC_ARGS) if config.EXEC_ARGS else []
    target_prog = config.AFL_TARGET_PATH
    trace_prog = config.TRACE_TARGET_PATH

    core.input_dir = input_dir
    core.output_dir = output_dir
    core.fuzzing_args = fuzzing_args
    core.target_prog = target_prog
    core.trace_prog = trace_prog

    fuzzer = FuzzerRunner(input_dir, output_dir, target_prog, fuzzing_args)
    fuzzer.load_fuzzer_pid()
    core.fuzzer = fuzzer

    tracer = CoverageTracer(
        input_dir,
        output_dir,
        fuzzing_args,
        target_prog,
        trace_prog,
        core.bbs,
        core.funcs,
        input_adapter_spec=core.get_input_adapter_spec(),
    )
    llm_util = LLMUtil(config.MODEL, config.API_KEY, config.BASE_URL)
    return tracer, llm_util, fuzzer


def runtime_root() -> Path:
    return config.RUN_RUNTIME_PATH
