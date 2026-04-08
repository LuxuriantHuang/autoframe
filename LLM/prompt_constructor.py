"""
Prompt constructor module - provides interface functions for accessing prompts.

All prompts are loaded via config.py from the configured prompt source file.
This module provides backward-compatible interfaces for existing code.
"""

import re

from config import prompts


class _SafeFormatDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


_SIMPLE_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _safe_prompt_substitute(template: str, values: dict) -> str:
    def repl(match):
        key = match.group(1)
        if key in values:
            return str(values[key])
        return match.group(0)

    return _SIMPLE_PLACEHOLDER_RE.sub(repl, template)


def get_prompt(prompt_key: str, key_type: str = 'user_prompt', **kwargs):
    """Get a prompt by key with optional formatting.

    Args:
        prompt_key: The key in prompts['prompt'] to access (e.g., 'state_variable_extractor')
        key_type: The type of prompt ('sys_prompt', 'user_prompt', etc.)
        **kwargs: Optional format arguments for user_prompt

    Returns:
        The prompt string, formatted if kwargs provided for user_prompt
    """
    if prompt_key not in prompts['prompt']:
        raise KeyError(f"Prompt key '{prompt_key}' not found in prompts")

    if key_type not in prompts['prompt'][prompt_key]:
        raise KeyError(f"Prompt type '{key_type}' not found in '{prompt_key}'")

    prompt = prompts['prompt'][prompt_key][key_type]

    # Format user_prompt with kwargs if provided
    if key_type == 'user_prompt' and kwargs:
        try:
            return _safe_prompt_substitute(prompt, kwargs)
        except Exception as e:
            import logging
            logging.warning(f"Failed to format prompt {prompt_key}.{key_type}: {e}")
            return prompt

    return prompt


def get_sys_prompt():
    """Get the generic system prompt for initial generation."""
    return prompts['prompt']['_generic_sys_prompt']


def get_prefix():
    """Get the Python code block prefix."""
    return prompts['prompt']['_code_block_prefix']


def get_suffix():
    """Get the main block suffix for generated scripts."""
    return prompts['prompt']['_main_block_suffix']


def first_prompt(code_snippet, callee, bcode, status):
    """Get the initial generation prompt for first interaction.

    Args:
        code_snippet: The code snippet to analyze
        callee: The function name containing the roadblock
        bcode: The roadblock constraint code
        status: The current status ("only_true" or "only_false")

    Returns:
        Formatted prompt string
    """
    user_prompt = prompts['prompt']['initial_generation']['user_prompt']
    return user_prompt.format(
        code_snippet=code_snippet,
        callee=callee,
        bcode=bcode,
        status=status
    )


def fix_prompt(generator, stderr):
    """Get the prompt for fixing error in generated code.

    Args:
        generator: The generated Python code
        stderr: The error message from execution

    Returns:
        Formatted prompt string
    """
    user_prompt = prompts['prompt']['fix_error_script']['user_prompt']
    return user_prompt.format(
        generator=generator,
        stderr=stderr
    )


def coverage_prompt(coverage):
    """Get the prompt for coverage analysis.

    Args:
        coverage: The coverage report string

    Returns:
        Formatted prompt string
    """
    user_prompt = prompts['prompt']['coverage_analysis']['user_prompt']
    return user_prompt.format(coverage=coverage)


def both_no_cover_improve_prompt(generator, coverage, bottleneck_code, funcname):
    """Get the prompt for improving generator when coverage is not reached.

    Args:
        generator: The generated Python code
        coverage: The coverage report string
        bottleneck_code: The bottleneck code location
        funcname: The function name containing the bottleneck

    Returns:
        Formatted prompt string
    """
    user_prompt = prompts['prompt']['improve_no_coverage']['user_prompt']
    return user_prompt.format(
        generator=generator,
        coverage=coverage,
        bottleneck_code=bottleneck_code,
        funcname=funcname
    )


def breakthrough_improve_prompt(generator, coverage, bottleneck_code, funcname):
    """Get the prompt for improving generator when breakthrough is needed.

    Args:
        generator: The generated Python code
        coverage: The coverage report string
        bottleneck_code: The bottleneck code location
        funcname: The function name containing the bottleneck

    Returns:
        Formatted prompt string
    """
    user_prompt = prompts['prompt']['improve_breakthrough']['user_prompt']
    return user_prompt.format(
        generator=generator,
        coverage=coverage,
        bottleneck_code=bottleneck_code,
        funcname=funcname
    )


def improve_generator_with_advice_prompt(generator, coverage, advice):
    """Get the prompt for improving generator with specific advice.

    Args:
        generator: The generated Python code
        coverage: The coverage report string
        advice: The improvement advice string

    Returns:
        Formatted prompt string
    """
    user_prompt = prompts['prompt']['improve_with_advice']['user_prompt']
    return user_prompt.format(
        generator=generator,
        coverage=coverage,
        advice=advice
    )


def get_format_section() -> str:
    """Get the current project's format info as a prompt section.

    Returns:
        Formatted format info string, or empty string if not available
    """
    from LLM.format_detector import InputFormatDetector
    import config

    format_info = InputFormatDetector.get_cached_format(config.PROJECT)
    if format_info:
        return InputFormatDetector.format_info_to_prompt_section(format_info)
    return ""
