"""
Flag-based constraint solving using LLM.

This module provides functionality to solve branch constraints that involve
flag variables by leveraging LLM analysis of flag semantics and constraints.
"""

import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

# Add parent directory to path to import main module
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import LOGGER_NAME, get_formatted_prompt
from LLM.LLMUtil import normalize_python_script

logger = logging.getLogger(LOGGER_NAME + __name__)


def get_llm_logger():
    """Get the LLM logger instance from main module."""
    import sys
    # First try to get from __main__ (when running as main script)
    main_module = sys.modules.get('__main__')
    if main_module and hasattr(main_module, 'get_llm_logger'):
        return main_module.get_llm_logger()

    # Then try to get from 'main' module (when imported)
    main_mod = sys.modules.get('main')
    if main_mod and hasattr(main_mod, 'get_llm_logger'):
        return main_mod.get_llm_logger()

    # Fallback: create a simple logger if main module is not available
    llm_logger = logging.getLogger("LLMInteraction@flag_solver")
    if not llm_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s"))
        llm_logger.addHandler(handler)
        llm_logger.setLevel(logging.INFO)
    return llm_logger


def format_roadblock(roadblock: Dict[str, Any]) -> str:
    """
    Format roadblock info for prompt.

    Args:
        roadblock: Dict with roadblock info

    Returns:
        JSON string representation
    """
    return json.dumps({
        'file': roadblock.get('filename', ''),
        'line': roadblock.get('line', 0),
        'status': roadblock.get('status', ''),
        'code': roadblock.get('code', '')
    }, ensure_ascii=False, indent=2)


def solve_with_flags(code_slice: str, roadblock: Dict[str, Any], constraints: list,
                     flag_vars: list, constant_groups: dict, llm_util, prompts: dict) -> Tuple[bool, Any]:
    """
    Use LLM to generate solution based on flag variable constraints.

    Args:
        code_slice: Program code slice
        roadblock: Roadblock info dict
        constraints: Existing natural language constraints
        flag_vars: List of relevant flag variable dicts from flagrec
        constant_groups: Dict of constant group definitions
        llm_util: LLMUtil instance for LLM interaction
        prompts: Dict containing prompt templates

    Returns:
        Tuple of (reachable, result_dict):
            - reachable: bool, whether flag-based solving is possible
            - result_dict: Dict with generation script or None
    """
    # LLM interaction logging
    llm_log = get_llm_logger()
    llm_log.info(f"[LLM_INTERACTION] solve_with_flags called")
    llm_log.debug(f"[LLM_INTERACTION] flag_vars_count: {len(flag_vars)}")
    llm_log.debug(f"[LLM_INTERACTION] constraints_count: {len(constraints) if constraints else 0}")

    flag_vars_str = json.dumps(flag_vars, indent=2, ensure_ascii=False)
    groups_str = json.dumps(constant_groups, indent=2, ensure_ascii=False)

    messages = [
        {'role': 'system', 'content': get_formatted_prompt('flag_constraint_solve')},
        {'role': 'user',
         'content': prompts['prompt']['flag_constraint_solve']['user_prompt'].format(
             lib=roadblock.get('lib', ''),
             codes=code_slice,
             rb_info=format_roadblock(roadblock),
             constraints=constraints,
             flag_variables=flag_vars_str,
             constant_groups=groups_str
         )}
    ]

    logger.info("Calling LLM for flag-based constraint solving")
    resp = llm_util.get_response(messages)
    llm_log.info(f"[LLM_INTERACTION] solve_with_flags response length: {len(resp) if resp else 0}")

    # Parse JSON response
    pattern_json = r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```"
    match = re.search(pattern_json, resp, re.DOTALL | re.IGNORECASE)

    if not match:
        logger.error("Flag solve response missing JSON")
        llm_log.error(f"[LLM_INTERACTION] solve_with_flags failed: JSON not found in response")
        return False, None

    try:
        result = json.loads(match.group(1).strip())
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse flag solve JSON: {e}")
        llm_log.error(f"[LLM_INTERACTION] solve_with_flags JSON decode error: {e}")
        return False, None

    if not result.get('reachable', False):
        logger.info("Flag-based solving determined unreachable")
        llm_log.info(f"[LLM_INTERACTION] solve_with_flags result: not_reachable")
        return False, None

    logger.info("Flag-based solving determined reachable")
    llm_log.info(f"[LLM_INTERACTION] solve_with_flags result: reachable")
    return True, result


def extract_script_from_flag_result(result: Dict[str, Any]) -> str | None:
    """
    Extract generation script from flag-based solving result.

    Args:
        result: Dict from solve_with_flags

    Returns:
        Python script string, or None if not found
    """
    # Check if generation_script is directly in result
    if 'generation_script' in result:
        script = result['generation_script']
        if isinstance(script, str) and script.strip():
            return normalize_python_script(script)

    # Check if script is wrapped in code block
    if 'generation_script' in result:
        script_match = re.search(r"```python(.*?)```", str(result['generation_script']), re.DOTALL)
        if script_match:
            return script_match.group(1).strip()

    # Look for any script field
    for key in ['script', 'python_script', 'code']:
        if key in result:
            script = result[key]
            if isinstance(script, str) and script.strip():
                return normalize_python_script(script)

    return None


def get_flag_solve_summary(result: Dict[str, Any]) -> str:
    """
    Get a summary of the flag-based solving result.

    Args:
        result: Dict from solve_with_flags

    Returns:
        Summary string
    """
    if not result:
        return "No result"

    summary_parts = []

    if 'flag_analysis' in result:
        flags = result['flag_analysis']
        summary_parts.append(f"Flags analyzed: {len(flags)}")
        for flag in flags[:3]:  # Show first 3
            summary_parts.append(f"  - {flag.get('name', '?')}: {flag.get('target_value_name', '?')}")

    if 'input_strategy' in result:
        strategy = result['input_strategy']
        summary_parts.append(f"Strategy: {strategy.get('approach', 'unknown')}")

    if 'confidence' in result:
        summary_parts.append(f"Confidence: {result['confidence']:.2f}")

    return '\n'.join(summary_parts)
