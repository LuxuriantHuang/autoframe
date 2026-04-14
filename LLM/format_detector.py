"""
Input Format Detector - LLM-based input format detection for fuzzing targets.

This module provides functionality to detect the input format of a fuzzing target
by analyzing the entry function (LLVMFuzzerTestOneInput for libFuzzer targets,
or main for binary targets) and related code.
"""
import json
import logging
import re
import shlex
from pathlib import Path
from typing import Any, Dict, Optional

import config
from config import funcs, PROJECT_HOME, LOGGER_NAME, STATIC_PATH
from LLM.LLMUtil import LLMUtil, parse_llm_json_response
from LLM.prompt_constructor import get_prompt

logger = logging.getLogger(LOGGER_NAME + __name__)

# Global cache for detected format info (per project)
_input_format_cache: Dict[str, Dict[str, Any]] = {}
_FORMAT_CACHE_FILE = "input_format_cache.json"


class InputFormatDetector:
    """Detects input format of fuzzing targets using LLM."""

    def __init__(self, llm_util: LLMUtil):
        """Initialize the format detector.

        Args:
            llm_util: LLM utility instance for making API calls
        """
        self.llm_util = llm_util
        self._format_info: Optional[Dict[str, Any]] = None

    @staticmethod
    def _cache_file_path() -> Path:
        return STATIC_PATH / _FORMAT_CACHE_FILE

    @staticmethod
    def _read_disk_cache() -> Dict[str, Dict[str, Any]]:
        cache_file = InputFormatDetector._cache_file_path()
        if not cache_file.exists():
            return {}
        try:
            with open(cache_file, "r") as f:
                payload = json.load(f)
            if isinstance(payload, dict):
                return {
                    str(key): value
                    for key, value in payload.items()
                    if isinstance(value, dict)
                }
        except Exception as e:
            logger.warning(f"[FORMAT_DETECT] Failed to read disk cache from {cache_file}: {e}")
        return {}

    @staticmethod
    def _write_disk_cache(cache_payload: Dict[str, Dict[str, Any]]) -> None:
        cache_file = InputFormatDetector._cache_file_path()
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(cache_file, "w") as f:
                json.dump(cache_payload, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"[FORMAT_DETECT] Failed to write disk cache to {cache_file}: {e}")

    @staticmethod
    def _sync_memory_cache_from_disk(lib: str) -> Optional[Dict[str, Any]]:
        disk_cache = InputFormatDetector._read_disk_cache()
        cached = disk_cache.get(lib)
        if isinstance(cached, dict):
            _input_format_cache[lib] = cached
            logger.info(f"[FORMAT_DETECT] Using disk-cached format info for {lib}")
            return cached
        return None

    @staticmethod
    def _persist_cache(lib: str, format_info: Dict[str, Any]) -> None:
        _input_format_cache[lib] = format_info
        disk_cache = InputFormatDetector._read_disk_cache()
        disk_cache[lib] = format_info
        InputFormatDetector._write_disk_cache(disk_cache)

    def detect_format(self, lib: str = None, detection_context: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Detect the input format for the given library/project.

        This method:
        1. Extracts entry function content (LLVMFuzzerTestOneInput or main) from source
        2. Calls LLM to analyze and determine the input format
        3. Caches the result globally

        Args:
            lib: Library/project name (defaults to config.PROJECT)

        Returns:
            Dictionary containing format info, or None if detection fails
        """
        if lib is None:
            lib = config.PROJECT

        # Check in-memory cache first
        if lib in _input_format_cache:
            logger.info(f"[FORMAT_DETECT] Using cached format info for {lib}")
            self._format_info = _input_format_cache[lib]
            return self._format_info

        # Then try persistent cache under static/
        cached_from_disk = self._sync_memory_cache_from_disk(lib)
        if cached_from_disk is not None:
            self._format_info = cached_from_disk
            return self._format_info

        logger.info(f"[FORMAT_DETECT] Detecting input format for {lib}")

        # Step 1: Extract LLVMFuzzerTestOneInput function
        func_content = self._extract_entry_function()
        if not func_content:
            logger.error("[FORMAT_DETECT] Failed to extract entry function")
            return None

        # Step 2: Call LLM for format detection
        format_info = self._call_llm_for_format(func_content, lib, detection_context=detection_context)
        if format_info:
            format_info = self._augment_with_input_subspace_info(format_info, lib, detection_context=detection_context)
            # Cache the result in memory and under static/ for reuse across runs.
            self._persist_cache(lib, format_info)
            self._format_info = format_info
            logger.info(f"[FORMAT_DETECT] Detected format: {format_info.get('format_name', 'unknown')}")

        return format_info

    def _extract_entry_function(self) -> Optional[str]:
        """Extract entry function content from source files.

        First tries to find LLVMFuzzerTestOneInput for libFuzzer targets.
        If not found, falls back to main function for binary targets.

        Uses static.json to find function location, then reads source file.

        Returns:
            Function content as string, or None if not found
        """
        # First try to find LLVMFuzzerTestOneInput (for libFuzzer targets)
        # Then fall back to main function (for binary targets)
        entry_func = None
        entry_func_name = None

        for func in funcs:
            if func.get('name') == 'LLVMFuzzerTestOneInput':
                entry_func = func
                entry_func_name = 'LLVMFuzzerTestOneInput'
                break

        # If LLVMFuzzerTestOneInput not found, try main function
        if not entry_func:
            for func in funcs:
                if func.get('name') == 'main':
                    entry_func = func
                    entry_func_name = 'main'
                    break

        if not entry_func:
            logger.error("[FORMAT_DETECT] Neither LLVMFuzzerTestOneInput nor main found in static.json")
            return None

        logger.info(f"[FORMAT_DETECT] Using entry function: {entry_func_name}")

        file_name = entry_func.get('file_name', '')
        line_start = entry_func.get('lineStart', 0)
        line_end = entry_func.get('lineEnd', 0)

        if not file_name or line_start == 0:
            logger.error(f"[FORMAT_DETECT] Invalid function metadata: {entry_func}")
            return None

        # Construct source file path
        # file_name might be like "test-transform.c" or full path
        src_path = config.resolve_source_path(file_name)
        if not src_path:
            alt_paths = [
                PROJECT_HOME / 'src' / file_name,
                PROJECT_HOME / file_name.split('/')[-1],
            ]
            src_path = next((alt_path for alt_path in alt_paths if alt_path.exists()), None)

        if not src_path:
            logger.error(f"[FORMAT_DETECT] Source file not found: {file_name}")
            return None

        try:
            with open(src_path, 'r') as f:
                lines = f.readlines()

            # Extract function content (1-indexed in static.json)
            func_lines = lines[line_start - 1:line_end]
            func_content = ''.join(func_lines)

            logger.debug(f"[FORMAT_DETECT] Extracted {len(func_lines)} lines from {src_path}")
            return func_content

        except Exception as e:
            logger.error(f"[FORMAT_DETECT] Error reading source file: {e}")
            return None

    def _call_llm_for_format(
        self,
        func_content: str,
        lib: str,
        detection_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Call LLM to detect input format from function content.

        Args:
            func_content: The entry function content (LLVMFuzzerTestOneInput or main)
            lib: Library/project name

        Returns:
            Parsed format info dictionary, or None on failure
        """
        try:
            sys_prompt = get_prompt('input_format_detection', 'sys_prompt')
            user_prompt = get_prompt('input_format_detection', 'user_prompt')
        except KeyError:
            logger.error("[FORMAT_DETECT] Prompt 'input_format_detection' not found in prompt.yaml")
            return None

        if not sys_prompt or not user_prompt:
            logger.error("[FORMAT_DETECT] Empty prompt for input_format_detection")
            return None

        extra_sections: list[str] = []
        if detection_context:
            runtime_context = detection_context.get("runtime_command_context")
            if runtime_context:
                extra_sections.append(str(runtime_context))
            argv_fixed = detection_context.get("argv_fixed") or []
            if argv_fixed:
                extra_sections.append(f"<control_surface>\nargv_fixed: {shlex.join(argv_fixed)}\n</control_surface>")
            input_channels = detection_context.get("input_channels") or []
            mutable_surfaces = detection_context.get("mutable_surfaces") or []
            forbidden_surfaces = detection_context.get("forbidden_surfaces") or []
            extra_sections.append(
                "<input_subspace_expectation>\n"
                f"input_channels: {', '.join(input_channels) if input_channels else 'unknown'}\n"
                f"mutable_surfaces: {', '.join(mutable_surfaces) if mutable_surfaces else 'unknown'}\n"
                f"forbidden_surfaces: {', '.join(forbidden_surfaces) if forbidden_surfaces else 'unknown'}\n"
                "Please infer not only the file format, but also which parser/API families are reachable "
                "under the fixed runtime command and which ones are blocked by fixed argv or extra-file requirements.\n"
                "</input_subspace_expectation>"
            )

        user_content = user_prompt.format(
            code_slice=func_content,
            lib=lib
        )
        if extra_sections:
            user_content = f"{user_content}\n\n" + "\n\n".join(extra_sections)

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_content}
        ]

        try:
            response = self.llm_util.get_response(messages)
            result = parse_llm_json_response(response)

            logger.info(f"[FORMAT_DETECT] LLM detected format: {result.get('format_name', 'unknown')}")
            return result

        except json.JSONDecodeError as e:
            logger.error(f"[FORMAT_DETECT] Failed to parse LLM response as JSON: {e}")
            return None
        except Exception as e:
            logger.error(f"[FORMAT_DETECT] Error during LLM call: {e}")
            return None

    def _augment_with_input_subspace_info(
        self,
        format_info: Dict[str, Any],
        lib: str,
        detection_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        info = dict(format_info or {})
        detection_context = detection_context or {}
        argv_fixed = [str(arg) for arg in detection_context.get("argv_fixed") or []]
        entry_mode = " ".join(argv_fixed) if argv_fixed else str(config.EXEC_ARGS)
        info.setdefault("entry_mode", entry_mode)
        info.setdefault("reachable_families", [])
        info.setdefault("blocked_families", [])
        info.setdefault("known_mode_requirements", {})
        info.setdefault("seed_constraints", {})

        if lib == "libxml":
            has_html_mode = any(arg in {"--html", "--htmlout"} for arg in argv_fixed)
            info["entry_mode"] = f"xmllint {entry_mode}".strip()
            info["reachable_families"] = ["parser.html"] if has_html_mode else ["parser.xml"]
            blocked = ["api.xpath", "schema.validation", "catalog.runtime"]
            if not has_html_mode:
                blocked.append("parser.html")
            info["blocked_families"] = sorted(set(blocked))
            known_reqs = info.get("known_mode_requirements", {}) or {}
            known_reqs.update(
                {
                    "parser.html": ["argv:--html"],
                    "api.xpath": ["argv:--xpath"],
                    "schema.validation": ["argv:--schema/--relaxng/--schematron", "aux_file:schema"],
                    "catalog.runtime": ["env/catalog files"],
                }
            )
            info["known_mode_requirements"] = known_reqs
            seed_constraints = info.get("seed_constraints", {}) or {}
            seed_constraints.setdefault("recommended_size", "small")
            seed_constraints.setdefault("single_file", True)
            seed_constraints.setdefault("allow_external_refs", False)
            seed_constraints.setdefault("notes", "Prefer small single-file XML inputs that do not rely on external schema/catalog/CLI flags.")
            info["seed_constraints"] = seed_constraints

        return info

    def get_format_info(self) -> Optional[Dict[str, Any]]:
        """Get cached format info without re-detecting.

        Returns:
            Cached format info, or None if not detected yet
        """
        return self._format_info

    @staticmethod
    def get_cached_format(lib: str = None) -> Optional[Dict[str, Any]]:
        """Get globally cached format info for a library.

        Args:
            lib: Library name (defaults to config.PROJECT)

        Returns:
            Cached format info, or None if not cached
        """
        if lib is None:
            lib = config.PROJECT
        cached = _input_format_cache.get(lib)
        if cached is not None:
            return cached
        return InputFormatDetector._sync_memory_cache_from_disk(lib)

    @staticmethod
    def format_info_to_prompt_section(format_info: Dict[str, Any]) -> str:
        """Convert format info to a prompt section string.

        Args:
            format_info: Format info dictionary

        Returns:
            Formatted string for inclusion in prompts
        """
        if not format_info:
            return ""

        sections = []

        if 'format_name' in format_info:
            sections.append(f"**Input Format**: {format_info['format_name']}")

        if 'format_description' in format_info:
            sections.append(f"**Description**: {format_info['format_description']}")

        if 'key_fields' in format_info and format_info['key_fields']:
            fields_str = ', '.join(str(f) for f in format_info['key_fields'][:5])
            sections.append(f"**Key Fields**: {fields_str}")

        if 'magic_bytes' in format_info:
            sections.append(f"**Magic Bytes**: {format_info['magic_bytes']}")

        if 'recommended_library' in format_info:
            sections.append(f"**Recommended Python Library**: {format_info['recommended_library']}")

        if 'entry_mode' in format_info and format_info['entry_mode']:
            sections.append(f"**Entry Mode**: {format_info['entry_mode']}")

        if 'reachable_families' in format_info and format_info['reachable_families']:
            sections.append(f"**Reachable Families**: {', '.join(str(item) for item in format_info['reachable_families'])}")

        if 'blocked_families' in format_info and format_info['blocked_families']:
            sections.append(f"**Blocked Families**: {', '.join(str(item) for item in format_info['blocked_families'])}")

        if 'structure_hints' in format_info:
            sections.append(f"**Structure Hints**:\n{format_info['structure_hints']}")

        if 'common_constraints' in format_info and format_info['common_constraints']:
            constraints_str = ', '.join(str(c) for c in format_info['common_constraints'][:3])
            sections.append(f"**Common Constraints**: {constraints_str}")

        fmt = '\n'.join(sections)
        logger.debug(f"[FORMAT_DETECT] Format info: {fmt}")
        return fmt

    @staticmethod
    def clear_cache(lib: str = None):
        """Clear cached format info for a library.

        Args:
            lib: Library name (defaults to all if None)
        """
        global _input_format_cache
        disk_cache = InputFormatDetector._read_disk_cache()
        if lib is None:
            _input_format_cache.clear()
            disk_cache.clear()
        else:
            if lib in _input_format_cache:
                del _input_format_cache[lib]
            disk_cache.pop(lib, None)
        InputFormatDetector._write_disk_cache(disk_cache)


def get_format_detector(llm_util: LLMUtil) -> InputFormatDetector:
    """Factory function to create a format detector.

    Args:
        llm_util: LLM utility instance

    Returns:
        InputFormatDetector instance
    """
    return InputFormatDetector(llm_util)


def get_format_section() -> str:
    """Get the current project's format info as a prompt section.

    Returns:
        Formatted format info string, or empty string if not available
    """
    format_info = InputFormatDetector.get_cached_format(config.PROJECT)
    if format_info:
        return InputFormatDetector.format_info_to_prompt_section(format_info)
    return ""
