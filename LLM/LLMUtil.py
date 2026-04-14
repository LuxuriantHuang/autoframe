import json
import logging
import os
import re
import shutil
import subprocess
import time
import inspect
from pathlib import Path
from openai import OpenAI
import httpx
import openai

import config
from Excep.ScriptExtractError import ScriptExtractError
from Excep.ScriptNotFoundError import ScriptNotFoundError
from config import LOGGER_NAME
from pyTracer.CodeHeat import CodeHeat
from .prompt_constructor import *

logger = logging.getLogger(LOGGER_NAME + __name__)

logger = logging.getLogger(LOGGER_NAME + __name__)


def get_llm_interaction_logger():
    return logging.getLogger(config.LLM_LOGGER_NAME)


def infer_llm_operation_name() -> str:
    for frame_info in inspect.stack()[2:]:
        module = inspect.getmodule(frame_info.frame)
        module_name = module.__name__ if module else ""
        if module_name == __name__ and frame_info.function == "get_response":
            continue
        if module_name.startswith("LLM.") or module_name in {"main", "main_v2", "__main__"}:
            return f"{module_name}.{frame_info.function}"
    return "unknown"


MAX_INPUT_CHARS_HARD = 258048
MAX_INPUT_CHARS_SOFT = 240000
TRUNCATION_NOTICE = "\n\n[truncated to fit model input length]\n\n"


def _estimate_messages_chars(messages) -> int:
    total = 0
    for message in messages or []:
        total += len(message.get("role", ""))
        total += len(message.get("content", "") or "")
    return total


def _shrink_messages_to_limit(messages, hard_limit: int = MAX_INPUT_CHARS_HARD):
    copied = [
        {key: value for key, value in message.items()}
        for message in (messages or [])
    ]
    total_chars = _estimate_messages_chars(copied)
    if total_chars <= hard_limit:
        return copied, False, total_chars

    for idx in range(len(copied) - 1, -1, -1):
        total_chars = _estimate_messages_chars(copied)
        if total_chars <= hard_limit:
            return copied, True, total_chars
        overflow = total_chars - hard_limit + len(TRUNCATION_NOTICE) + 256
        content = copied[idx].get("content")
        if not isinstance(content, str) or len(content) <= 0:
            continue
        keep = max(0, len(content) - overflow)
        if keep <= 0:
            copied[idx]["content"] = TRUNCATION_NOTICE
        else:
            copied[idx]["content"] = content[:keep] + TRUNCATION_NOTICE
        total_chars = _estimate_messages_chars(copied)
        if total_chars <= hard_limit:
            return copied, True, total_chars

    total_chars = _estimate_messages_chars(copied)
    return copied, total_chars < _estimate_messages_chars(messages), total_chars


def parse_llm_json_response(response: str):
    """Parse JSON from raw LLM output, tolerating fenced blocks and extra text."""
    response = (response or "").strip()
    if not response:
        raise json.JSONDecodeError("Empty response", response, 0)

    json_match = re.search(r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```", response, re.DOTALL | re.IGNORECASE)
    if json_match:
        response = json_match.group(1).strip()

    if response.startswith("{") or response.startswith("["):
        return json.loads(response)

    decoder = json.JSONDecoder()
    for start_idx, ch in enumerate(response):
        if ch not in "[{":
            continue
        try:
            obj, _ = decoder.raw_decode(response[start_idx:])
            return obj
        except json.JSONDecodeError:
            continue

    raise json.JSONDecodeError("No JSON object found in response", response, 0)


def get_message(user_prompt):
    return [{
        "role": "system",
        "content": get_sys_prompt()
    }, {
        "role": "user",
        "content": user_prompt
    }]


def message_with_prefix(user_prompt):
    chat_messages = get_message(user_prompt)

    if "deepseek" in config.model:
        chat_messages.append({
            'role': 'assistant',
            'content': get_prefix(),
            'prefix': True
        })
    elif "qwen" in config.model or "kimi" in config.model:
        chat_messages.append({
            'role': 'assistant',
            'content': get_prefix(),
            'partial': True
        })

    return chat_messages


def normalize_python_script(generator_text: str) -> str:
    """Accept either a fenced ```python block or raw Python source."""
    if not isinstance(generator_text, str):
        raise ScriptNotFoundError("生成文本不是有效的字符串脚本")

    text = generator_text.strip()
    if not text:
        raise ScriptNotFoundError("生成文本为空")

    code_match = re.search(r"```python\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if code_match:
        return code_match.group(1).strip()

    generic_match = re.search(r"```\s*(.*?)```", text, re.DOTALL)
    if generic_match:
        return generic_match.group(1).strip()

    return text


def extract_generator(generator_text):
    return normalize_python_script(generator_text)


def _make_generator_run_dir(bottleneck_id, seed_id) -> Path:
    run_dir = (
        Path(config.LLM_TMP_PATH)
        / "generator_artifacts"
        / f"bid_{int(bottleneck_id):06}_seed_{int(seed_id):06}_{time.time_ns()}"
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _move_generator_artifacts_to_queue(run_dir: Path, bottleneck_id: int, path_prefix: str | None = None) -> list[str]:
    llm_target_path = Path(config.LLM_QUEUE_PATH)
    llm_target_path.mkdir(parents=True, exist_ok=True)

    moved_paths = []
    artifact_index = 0
    for artifact_path in sorted(p for p in run_dir.rglob("*") if p.is_file()):
        suffix = artifact_path.suffix if artifact_path.suffix else ""
        dest_path = config.next_queue_seed_path(
            llm_target_path,
            path_prefix=path_prefix,
            roadblock_id=bottleneck_id,
            aux_id=artifact_index,
            suffix=suffix,
        )
        shutil.move(os.fspath(artifact_path), os.fspath(dest_path))
        moved_paths.append(os.fspath(dest_path))
        artifact_index += 1

    return moved_paths


def _next_queue_id(queue_path: Path, ignore_path: Path | None = None) -> int:
    max_id = -1
    ignored_path = ignore_path.resolve() if ignore_path is not None else None
    for entry in queue_path.iterdir():
        if ignored_path is not None and entry.resolve() == ignored_path:
            continue
        match = re.match(r"id:(\d+)", entry.name)
        if not match:
            continue
        max_id = max(max_id, int(match.group(1)))
    return max_id + 1


def _promote_directory_output_to_queue(output_path: Path, queue_path: Path) -> list[str]:
    if not output_path.exists() or not output_path.is_dir():
        return []

    moved_paths = []
    base_name = output_path.name
    metadata = base_name.split(",", 1)[1] if "," in base_name else ""
    next_id = _next_queue_id(queue_path, ignore_path=output_path)
    artifact_index = 0
    for artifact_path in sorted(p for p in output_path.rglob("*") if p.is_file()):
        suffix = artifact_path.suffix if artifact_path.suffix else ""
        if artifact_index == 0:
            dest_name = f"{base_name},aux:{artifact_index:02}{suffix}"
        elif metadata:
            dest_name = f"id:{next_id:06},{metadata},aux:{artifact_index:02}{suffix}"
            next_id += 1
        else:
            dest_name = f"id:{next_id:06},aux:{artifact_index:02}{suffix}"
            next_id += 1
        dest_path = queue_path / dest_name
        shutil.move(os.fspath(artifact_path), os.fspath(dest_path))
        moved_paths.append(os.fspath(dest_path))
        artifact_index += 1

    shutil.rmtree(output_path, ignore_errors=True)
    return moved_paths


def _make_mutator_run_dir(seed_id) -> Path:
    run_dir = (
        Path(config.MUT_TMP_PATH)
        / "mutator_artifacts"
        / f"seed_{int(seed_id):06}_{time.time_ns()}"
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _move_mutator_artifacts_to_queue(run_dir: Path, orig_id: int, path_prefix: str | None = None) -> list[str]:
    mut_target_path = Path(config.MUT_QUEUE_PATH)
    mut_target_path.mkdir(parents=True, exist_ok=True)

    moved_paths = []
    artifact_index = 0
    for artifact_path in sorted(p for p in run_dir.rglob("*") if p.is_file()):
        suffix = artifact_path.suffix if artifact_path.suffix else ""
        dest_path = config.next_queue_seed_path(
            mut_target_path,
            path_prefix=path_prefix,
            src_id=orig_id,
            aux_id=artifact_index,
            suffix=suffix,
        )
        shutil.move(os.fspath(artifact_path), os.fspath(dest_path))
        moved_paths.append(os.fspath(dest_path))
        artifact_index += 1

    return moved_paths


def run_generator(
    generator,
    bottleneck_id,
    seed_id,
    output_dir,
    path_prefix: str | None = None,
    queue_dir: str | Path | None = None,
):
    generator = normalize_python_script(generator)
    # 记录脚本内容（debug级别）
    logger.debug(f"[GENERATOR_SCRIPT] ===== Generator Script Content (attempt for seed_id={seed_id}) =====")
    logger.debug(f"[GENERATOR_SCRIPT] {generator}")
    logger.debug(f"[GENERATOR_SCRIPT] ===== End of Generator Script Content =====")

    # 将generator代码写入.py文件中
    file_path = config.get_generator_script_path(bottleneck_id, seed_id)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(generator)

    # 直接写入LLM/queue，跳过LLM_TMP_PATH
    LLM_TARGET_PATH = Path(queue_dir) if queue_dir is not None else Path(config.LLM_QUEUE_PATH)
    os.makedirs(LLM_TARGET_PATH, exist_ok=True)
    new_seed_path = os.fspath(
        config.next_queue_seed_path(
            LLM_TARGET_PATH,
            path_prefix=path_prefix,
            roadblock_id=bottleneck_id,
        )
    )
    run_dir = _make_generator_run_dir(bottleneck_id, seed_id)
    logger.info(f"生成脚本执行 - 目标文件: {new_seed_path}")
    logger.info(f"生成脚本执行 - 隔离目录: {run_dir}")
    # 使用 subprocess 运行文件并捕获输出
    try:
        # 运行命令，捕获标准输出和标准错误
        result = subprocess.run(
            ["python", os.fspath(file_path), new_seed_path],  # 执行的命令
            cwd=os.fspath(run_dir),
            text=True,  # 以文本形式返回输出
            capture_output=True,  # 捕获标准输出和标准错误
            encoding="utf-8",  # 显式指定编码为 UTF-8
            timeout=30  # 添加超时限制
        )

        artifact_paths = _move_generator_artifacts_to_queue(run_dir, bottleneck_id, path_prefix=path_prefix)
        if artifact_paths:
            logger.info(f"生成脚本执行 - 从隔离目录收集到 {len(artifact_paths)} 个附加种子")

        promoted_output_paths = _promote_directory_output_to_queue(Path(new_seed_path), LLM_TARGET_PATH)
        if promoted_output_paths:
            logger.warning(
                f"生成脚本将目标路径写成目录，已递归提取 {len(promoted_output_paths)} 个文件到 LLM queue"
            )

        # 检查文件是否生成
        if promoted_output_paths:
            new_seed_path = promoted_output_paths[0]
            file_size = os.path.getsize(new_seed_path)
            logger.info(f"目录式输出已展开，首个种子文件大小: {file_size} bytes")
        elif os.path.isfile(new_seed_path):
            file_size = os.path.getsize(new_seed_path)
            logger.info(f"生成脚本执行成功 - 文件大小: {file_size} bytes")
        elif artifact_paths:
            new_seed_path = artifact_paths[0]
            file_size = os.path.getsize(new_seed_path)
            logger.warning(
                f"生成脚本未写入指定输出路径，改用隔离目录中的首个附加种子: {new_seed_path}"
            )
            logger.info(f"附加种子文件大小: {file_size} bytes")
        else:
            logger.error(f"生成脚本执行失败 - 未生成文件: {new_seed_path}")

        # 记录执行结果（debug级别，无论成功还是失败）
        logger.debug(f"[GENERATOR_RESULT] Return code: {result.returncode}")
        if result.stdout:
            logger.debug(f"[GENERATOR_RESULT] stdout: {result.stdout[:1000]}")  # 扩展到1000字符
        else:
            logger.debug(f"[GENERATOR_RESULT] stdout: (empty)")
        if result.stderr:
            logger.debug(f"[GENERATOR_RESULT] stderr: {result.stderr[:1000]}")  # 扩展到1000字符
        else:
            logger.debug(f"[GENERATOR_RESULT] stderr: (empty)")

        # 如果失败，额外记录ERROR级别的信息
        if not os.path.exists(new_seed_path):
            logger.error(f"返回码: {result.returncode}")
            logger.error(f"stdout: {result.stdout[:500] if result.stdout else '(empty)'}")
            logger.error(f"stderr: {result.stderr[:500] if result.stderr else '(empty)'}")

        return result.stdout, result.stderr, new_seed_path
    except subprocess.TimeoutExpired:
        logger.error(f"生成脚本执行超时（30秒）")
        raise ScriptExtractError("生成脚本执行超时")
    except Exception as e:
        logger.error(f"运行generator代码的子线程异常: {e}")
        raise ScriptExtractError("运行generator代码的子线程异常")
    finally:
        if run_dir.exists():
            shutil.rmtree(run_dir, ignore_errors=True)


def run_mutate_script(
    script,
    seed_id,
    orig_seed,
    output_dir,
    path_prefix: str | None = None,
    queue_dir: str | Path | None = None,
):
    script = normalize_python_script(script)
    # 记录脚本内容（debug级别）
    logger.debug(f"[MUTATE_SCRIPT] ===== Mutate Script Content (attempt for seed_id={seed_id}) =====")
    logger.debug(f"[MUTATE_SCRIPT] {script}")
    logger.debug(f"[MUTATE_SCRIPT] ===== End of Mutate Script Content =====")

    file_path = config.get_mutator_script_path(seed_id, orig_seed)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(script)


    orig_id = re.search(r'id:(\d+)', orig_seed).group(1)
    orig_id = int(orig_id) if int(orig_id) else 0
    resolved_seed = config.find_seed_path(orig_seed)
    orig_seed_path = os.fspath(resolved_seed) if resolved_seed is not None else os.path.join(config.SEED_PATH, orig_seed)

    # 直接写入mut/queue，跳过MUT_TMP_PATH
    MUT_TARGET_PATH = Path(queue_dir) if queue_dir is not None else Path(config.MUT_QUEUE_PATH)
    os.makedirs(MUT_TARGET_PATH, exist_ok=True)
    new_seed_path = os.fspath(
        config.next_queue_seed_path(
            MUT_TARGET_PATH,
            path_prefix=path_prefix,
            src_id=orig_id,
        )
    )
    run_dir = _make_mutator_run_dir(seed_id)
    logger.info(f"变异脚本执行 - 原种子: {orig_seed_path}")
    logger.info(f"变异脚本执行 - 新种子: {new_seed_path}")
    logger.info(f"变异脚本执行 - 隔离目录: {run_dir}")
    try:
        # 运行命令，捕获标准输出和标准错误
        result = subprocess.run(
            ["python", os.fspath(file_path), orig_seed_path, new_seed_path],  # 执行的命令
            cwd=os.fspath(run_dir),
            text=True,  # 以文本形式返回输出
            capture_output=True,  # 捕获标准输出和标准错误
            encoding="utf-8",  # 显式指定编码为 UTF-8
            timeout=30  # 添加超时限制
        )

        artifact_paths = _move_mutator_artifacts_to_queue(run_dir, orig_id, path_prefix=path_prefix)
        if artifact_paths:
            logger.info(f"变异脚本执行 - 从隔离目录收集到 {len(artifact_paths)} 个附加种子")

        promoted_output_paths = _promote_directory_output_to_queue(Path(new_seed_path), Path(MUT_TARGET_PATH))
        if promoted_output_paths:
            logger.warning(
                f"变异脚本将目标路径写成目录，已递归提取 {len(promoted_output_paths)} 个文件到 mut queue"
            )

        # 检查文件是否生成
        if promoted_output_paths:
            new_seed_path = promoted_output_paths[0]
            file_size = os.path.getsize(new_seed_path)
            logger.info(f"目录式变异输出已展开，首个种子文件大小: {file_size} bytes")
        elif os.path.isfile(new_seed_path):
            file_size = os.path.getsize(new_seed_path)
            logger.info(f"变异脚本执行成功 - 生成文件大小: {file_size} bytes")
        elif artifact_paths:
            new_seed_path = artifact_paths[0]
            file_size = os.path.getsize(new_seed_path)
            logger.warning(
                f"变异脚本未写入指定输出路径，改用隔离目录中的首个附加种子: {new_seed_path}"
            )
            logger.info(f"附加种子文件大小: {file_size} bytes")
        else:
            logger.error(f"变异脚本执行失败 - 未生成文件: {new_seed_path}")

        # 记录执行结果（debug级别，无论成功还是失败）
        logger.debug(f"[MUTATE_RESULT] Return code: {result.returncode}")
        if result.stdout:
            logger.debug(f"[MUTATE_RESULT] stdout: {result.stdout[:1000]}")  # 扩展到1000字符
        else:
            logger.debug(f"[MUTATE_RESULT] stdout: (empty)")
        if result.stderr:
            logger.debug(f"[MUTATE_RESULT] stderr: {result.stderr[:1000]}")  # 扩展到1000字符
        else:
            logger.debug(f"[MUTATE_RESULT] stderr: (empty)")

        # 如果失败，额外记录ERROR级别的信息
        if not os.path.exists(new_seed_path):
            logger.error(f"返回码: {result.returncode}")
            logger.error(f"stdout: {result.stdout[:500] if result.stdout else '(empty)'}")
            logger.error(f"stderr: {result.stderr[:500] if result.stderr else '(empty)'}")

        return result.stdout, result.stderr, new_seed_path
    except subprocess.TimeoutExpired:
        logger.error(f"变异脚本执行超时（30秒）")
        raise ScriptExtractError("变异脚本执行超时")
    except Exception as e:
        logger.error(f"运行mutator代码的子线程异常: {e}")
        raise ScriptExtractError("运行mutator代码的子线程异常")
    finally:
        if run_dir.exists():
            shutil.rmtree(run_dir, ignore_errors=True)


def get_coverage_report_by_trace(execution_path, call_chain):
    function_coverage = ""
    code_heat = CodeHeat()
    code_heat.merge(execution_path, config.bbs)
    for fname in call_chain:
        f = next((item for item in config.funcs if item.get("name") == fname), None)
        filename = f['file_name'].split('/')[-1]
        start = f['lineStart']
        end = f['lineEnd']
        fid = f['id']
        with open(Path(config.PROJECT_HOME) / "src" / filename) as f:
            code = [line.rstrip('\n') for line in f.readlines()]
        file_heat = code_heat.code_heat[filename]
        # print(code)
        # print(file_heat)
        for key in file_heat:
            code[key - 1] += f'  // coverage: {file_heat[key]}'

        function_snippet_list = code[start - 1:end]
        function_snippet = '\n'.join(function_snippet_list)
        function_coverage += function_snippet
        function_coverage += '\n\n'
    return function_coverage


def extract_function_block(text: str, funcname: str) -> str | None:
    """
    从 llvm-cov show 的输出中提取指定函数的覆盖率文本块。

    参数:
        text (str): llvm-cov show 的完整输出
        funcname (str): 要提取的函数名，例如 "main"

    返回:
        str | None: 匹配到的函数覆盖率文本块；如果找不到返回 None
    """
    # 匹配形如 "funcname:\n ... （直到下一个函数名: 或文件结尾）"
    pattern = re.compile(rf"^[^\n]*{re.escape(funcname)}:\n(.*?)(?=\n[^\n:]+:[^\n:]*:|\Z)", re.S)
    match = pattern.search(text)
    if match:
        return match.group(0)
    return None


class LLMUtil:
    def __init__(self, model, key, base_url):
        self.model = model
        # Configure timeout for OpenAI client
        self.client = OpenAI(
            api_key=key,
            base_url=base_url,
            timeout=config.LLM_TIMEOUT
        )

    def get_response(self, messages, suffix=None, temp=None):
        """Get LLM response with timeout and retry logic."""
        from openai import APITimeoutError, APIError
        import httpx

        llm_log = get_llm_interaction_logger()
        if temp is None:
            temp = config.LLM_TEMPERATURE
        sanitized_messages, truncated, prompt_chars = _shrink_messages_to_limit(messages)
        if prompt_chars > MAX_INPUT_CHARS_SOFT:
            logger.warning(
                f"[LLM] Large prompt for {infer_llm_operation_name()}: {prompt_chars} chars "
                f"(soft limit {MAX_INPUT_CHARS_SOFT})"
            )
        if truncated:
            logger.warning(
                f"[LLM] Prompt exceeded hard limit and was truncated before request: {prompt_chars} chars"
            )
            llm_log.warning(
                f"[LLM_REQUEST] {infer_llm_operation_name()} prompt truncated to {prompt_chars} chars"
            )

        max_retries = config.LLM_MAX_RETRIES
        retry_delay = config.LLM_RETRY_DELAY

        for attempt in range(max_retries):
            try:
                # Check if thinking mode should be enabled for the current model
                extra_params = {}
                if config.is_thinking_enabled(self.model, config.model):
                    extra_params["extra_body"] = {"thinking": {"type": "enabled"}}
                    logger.info(f"[LLM] Thinking mode enabled for model: {self.model}")

                if suffix is None:
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=sanitized_messages,
                        temperature=temp,
                        top_p=config.LLM_TOP_P,
                        **extra_params
                    )
                else:
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=sanitized_messages,
                        stream=False,
                        temperature=temp,
                        top_p=config.LLM_TOP_P,
                        stop=[suffix],
                        **extra_params
                    )
                content = response.choices[0].message.content
                logger.debug(f"[LLM] API call succeeded on attempt {attempt + 1}/{max_retries}")
                operation_name = infer_llm_operation_name()
                llm_log.info(
                    f"[LLM_RESPONSE] {operation_name} attempt {attempt + 1}/{max_retries}\n{content}"
                )
                return content

            except APITimeoutError as e:
                logger.warning(f"[LLM] API timeout on attempt {attempt + 1}/{max_retries}: {e}")
                if attempt < max_retries - 1:
                    logger.info(f"[LLM] Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error(f"[LLM] All {max_retries} retry attempts exhausted for timeout")
                    raise
            except (APIError, httpx.HTTPStatusError) as e:
                logger.warning(f"[LLM] API error on attempt {attempt + 1}/{max_retries}: {e}")
                if attempt < max_retries - 1:
                    logger.info(f"[LLM] Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error(f"[LLM] All {max_retries} retry attempts exhausted for API error: {e}")
                    raise
            except Exception as e:
                logger.error(f"[LLM] Unexpected error on attempt {attempt + 1}/{max_retries}: {e}")
                if attempt < max_retries - 1:
                    logger.info(f"[LLM] Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error(f"[LLM] All {max_retries} retry attempts exhausted: {e}")
                    raise
        return None

    def first_chat(self, code_snippet, callee, bcode, status):
        """Initial generation chat using LLM.

        Args:
            code_snippet: The code snippet to analyze
            callee: The function name containing the roadblock
            bcode: The roadblock constraint code
            status: The current status ("only_true" or "only_false")

        Returns:
            Generated Python code
        """
        import config
        sys_prompt = config.prompts['prompt']['initial_generation']['sys_prompt']
        user_prompt = config.prompts['prompt']['initial_generation']['user_prompt'].format(
            code_snippet=code_snippet,
            callee=callee,
            bcode=bcode,
            status=status
        )

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_prompt}
        ]

        return self.get_response(messages)

    def fix_chat(self, generator, stderr):
        """Fix error in generated script using LLM.

        Args:
            generator: The generated Python code
            stderr: The error message from execution

        Returns:
            Fixed Python code (without prefix/suffix wrappers)
        """
        import config
        sys_prompt = config.prompts['prompt']['fix_error_script']['sys_prompt']
        user_prompt = config.prompts['prompt']['fix_error_script']['user_prompt'].format(
            generator=generator,
            stderr=stderr,
            runtime_command_context=config.build_runtime_command_context()
        )

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_prompt}
        ]

        resp = self.get_response(messages)
        return resp

    def empty_file_chat(self, generator, stdout, stderr):
        """Fix empty file issue in generated script using LLM.

        Args:
            generator: The generated Python code
            stdout: The stdout message from execution
            stderr: The stderr message from execution (if any)

        Returns:
            Fixed Python code (without prefix/suffix wrappers)
        """
        import config
        sys_prompt = config.prompts['prompt']['fix_empty_file']['sys_prompt']

        # Prepare stderr section for the prompt
        stderr_section = f"### 错误信息：\n```\n{stderr}\n```" if stderr else ""

        user_prompt = config.prompts['prompt']['fix_empty_file']['user_prompt'].format(
            generator=generator,
            stdout=stdout,
            stderr_section=stderr_section,
            runtime_command_context=config.build_runtime_command_context()
        )

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_prompt}
        ]

        resp = self.get_response(messages)
        return resp

    def no_cover_chat(self, generator, coverage, bottleneck_code, funcname):
        """Improve generator when coverage is not reached.

        Args:
            generator: The generated Python code
            coverage: The coverage report string
            bottleneck_code: The bottleneck code location
            funcname: The function name containing the bottleneck

        Returns:
            Improvement advice
        """
        import config
        sys_prompt = config.prompts['prompt']['improve_no_coverage']['sys_prompt']
        user_prompt = config.prompts['prompt']['improve_no_coverage']['user_prompt'].format(
            generator=generator,
            coverage=coverage,
            bottleneck_code=bottleneck_code,
            funcname=funcname
        )

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_prompt}
        ]

        return self.get_response(messages)

    def no_cover_chat_v2(self, generator, coverage, bottleneck_code, funcname):
        """Improve generator when coverage is not reached using the v2 prompt."""
        import config
        sys_prompt = config.prompts['prompt']['improve_no_coverage_v2']['sys_prompt']
        user_prompt = config.prompts['prompt']['improve_no_coverage_v2']['user_prompt'].format(
            generator=generator,
            coverage=coverage,
            bottleneck_code=bottleneck_code,
            funcname=funcname,
            runtime_command_context=config.build_runtime_command_context()
        )

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_prompt}
        ]

        return self.get_response(messages)

    def no_break_chat(self, generator, coverage, bottleneck_code, funcname):
        """Improve generator when breakthrough is needed.

        Args:
            generator: The generated Python code
            coverage: The coverage report string
            bottleneck_code: The bottleneck code location
            funcname: The function name containing the bottleneck

        Returns:
            Improvement advice
        """
        import config
        sys_prompt = config.prompts['prompt']['improve_breakthrough']['sys_prompt']
        user_prompt = config.prompts['prompt']['improve_breakthrough']['user_prompt'].format(
            generator=generator,
            coverage=coverage,
            bottleneck_code=bottleneck_code,
            funcname=funcname
        )

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_prompt}
        ]

        return self.get_response(messages)

    def no_break_chat_v2(self, generator, coverage, bottleneck_code, funcname):
        """Improve generator when breakthrough is needed using the v2 prompt."""
        import config
        sys_prompt = config.prompts['prompt']['improve_breakthrough_v2']['sys_prompt']
        user_prompt = config.prompts['prompt']['improve_breakthrough_v2']['user_prompt'].format(
            generator=generator,
            coverage=coverage,
            bottleneck_code=bottleneck_code,
            funcname=funcname,
            runtime_command_context=config.build_runtime_command_context()
        )

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_prompt}
        ]

        return self.get_response(messages)

    def improve_generator_chat(self, generator, coverage, message):
        """Improve generator with specific advice.

        Args:
            generator: The generated Python code
            coverage: The coverage report string
            message: The improvement advice string

        Returns:
            Improved Python code
        """
        import config
        sys_prompt = config.prompts['prompt']['improve_with_advice']['sys_prompt']
        user_prompt = config.prompts['prompt']['improve_with_advice']['user_prompt'].format(
            generator=generator,
            coverage=coverage,
            advice=message,
            runtime_command_context=config.build_runtime_command_context()
        )

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_prompt}
        ]

        return self.get_response(messages)

    def first_solve(self, code_snippet, callee, bcode, status):
        # 保存本次使用的代码等信息到一个指定路径文件

        # 第一次对话，得到初始生成器脚本
        try:
            resp = self.first_chat(code_snippet, callee, bcode, status)
        except Exception as e:
            logger.error(e)
            resp = f"Error generating seed: {str(e)}"
        return resp

    def fix_solve(self, generator, stderr):
        try:
            resp = self.fix_chat(generator, stderr)
        except Exception as e:
            logger.error(e)
            resp = f"Error fixing seed: {str(e)}"
        return resp

    def empty_file_solve(self, generator, stdout, stderr):
        try:
            resp = self.empty_file_chat(generator, stdout, stderr)
        except Exception as e:
            logger.error(e)
            resp = f"Error fixing empty file: {str(e)}"
        return resp

    def test_seed(self, tracer):
        """Legacy global-coverage fallback.

        Newer flows should prefer local single-seed evaluation in main.py.
        """
        last_cov = tracer.last_coverage
        time.sleep(10)  # 需要一点时间让fuzzer接收新种子与变异
        this_cov = tracer.get_edge_count()
        if (this_cov - last_cov) > config.TEST_SEED_DELTA:
            tracer.last_coverage = this_cov
            tracer.last_growth_time = time.time()
            logger.info(f"new seed brings {this_cov - last_cov} paths growth (legacy global signal)")
            return True
        return False

    def get_advice(self, rb_info: dict, coverage, generator):
        logger.info("getting advice")
        advice = self.no_break_chat(generator, coverage, rb_info['code'], rb_info['func_name'])
        return advice

    def get_advice_v2(self, rb_info: dict, coverage, generator):
        logger.info("getting advice with v2 prompt")
        advice = self.no_break_chat_v2(generator, coverage, rb_info['code'], rb_info['func_name'])
        return advice

    def improve_script(self, generator, coverage, advice):
        logger.info("improving script")
        try:
            resp = self.improve_generator_chat(generator, coverage, advice)
        except Exception as e:
            logger.error(e)
            resp = f"Error improve script: {str(e)}"
        return resp
