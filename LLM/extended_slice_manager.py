"""
Extended Slice Manager - Phase 3: Intelligently decide when to extend code slices

This module provides functionality for:
- Deciding when additional function slices are needed
- Inferring state setup functions from variable names
- Managing slice cache to optimize token usage

Classes:
    ExtendedSliceManager: Manages extended slice decisions and caching
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
from LLM.LLMUtil import LLMUtil, parse_llm_json_response
from LLM.prompt_constructor import get_prompt
from CoverageTracer import get_function_slice

logger = logging.getLogger(config.LOGGER_NAME + __name__)

# Configuration - use values from config.py
MAX_SLICE_SIZE = getattr(config, 'MAX_SLICE_SIZE', 5000)  # Maximum slice size in characters


class ExtendedSliceManager:
    """
    Manages extended slice analysis for Phase 3 state inference.

    This class handles:
    1. Known format specifications (Phase 1 hardcoded mappings)
    2. Slice cache to avoid redundant token usage
    3. Setup function inference from variable names
    """

    # Known format specifications for common libraries
    KNOWN_MAPPINGS = {
        'lcms': {
            'ColorSpace': {
                'offset': 16, 'size': 4, 'encoding': 'u32be',
                'setup_func': 'cmsOpenProfileFromMem',
                'possible_values': ['RGB', 'LAB', 'CMYK', 'XYZ', 'GRAY'],
                'signatures': {
                    'RGB': '0x52474220', 'LAB': '0x4C414220',
                    'CMYK': '0x434D594B', 'XYZ': '0x58595A20'
                }
            },
            'DeviceClass': {
                'offset': 12, 'size': 4, 'encoding': 'u32be',
                'setup_func': 'cmsOpenProfileFromMem',
                'possible_values': ['mntr', 'prtr', 'scnr', 'link', 'abst'],
                'signatures': {
                    'mntr': '0x6D6E7472', 'prtr': '0x70727472',
                    'scnr': '0x73636E72', 'abst': '0x61627374'
                }
            },
            'PCS': {
                'offset': 20, 'size': 4, 'encoding': 'u32be',
                'setup_func': 'cmsOpenProfileFromMem',
                'possible_values': ['XYZ', 'LAB'],
                'signatures': {
                    'XYZ': '0x58595A20', 'LAB': '0x4C616220'
                }
            },
            'RenderingIntent': {
                'offset': 64, 'size': 4, 'encoding': 'u32be',
                'setup_func': 'cmsOpenProfileFromMem',
                'possible_values': [0, 1, 2, 3],
                'value_names': ['perceptual', 'relative', 'saturation', 'absolute']
            },
        },
        'libpng': {
            'color_type': {
                'offset': 25, 'size': 1, 'encoding': 'u8',
                'setup_func': 'png_read_info',
                'possible_values': [0, 2, 3, 4, 6],
                'value_names': ['grayscale', 'truecolor', 'indexed', 'grayscale_alpha', 'truecolor_alpha']
            },
            'bit_depth': {
                'offset': 24, 'size': 1, 'encoding': 'u8',
                'setup_func': 'png_read_info',
                'possible_values': [1, 2, 4, 8, 16]
            },
            'width': {
                'offset': 16, 'size': 4, 'encoding': 'u32be',
                'setup_func': 'png_read_info'
            },
            'height': {
                'offset': 20, 'size': 4, 'encoding': 'u32be',
                'setup_func': 'png_read_info'
            },
        }
    }

    # Setup function name patterns for inference
    SETUP_FUNC_PATTERNS = {
        'ColorSpace': ['cmsOpenProfileFromMem', 'cmsReadTag', 'cmsReadICCintegrated'],
        'DeviceClass': ['cmsOpenProfileFromMem', 'cmsGetDeviceClass', 'cmsReadHeader'],
        'PCS': ['cmsOpenProfileFromMem', 'cmsGetPCS', 'cmsGetProfileICC'],
        'RenderingIntent': ['cmsOpenProfileFromMem', 'cmsGetHeader', 'cmsReadTag'],
        'color_type': ['png_read_info', 'png_get_IHDR', 'png_get_IHDR'],
        'bit_depth': ['png_read_info', 'png_get_IHDR', 'png_get_channels'],
    }

    def __init__(self, llm_util: LLMUtil, lib: str):
        """Initialize the extended slice manager.

        Args:
            llm_util: LLM utility instance
            lib: Library name (e.g., 'lcms', 'libpng')
        """
        self.llm_util = llm_util
        self.lib = lib
        self.slice_cache: Dict[str, str] = {}
        self.setup_func_cache: Dict[str, str] = {}

    def decide_extended_analysis(
        self,
        state_vars: List[Dict[str, Any]],
        code_slice: str
    ) -> Dict[str, Any]:
        """
        Decide which functions need extended slice analysis.

        Args:
            state_vars: List of state variables from Phase 2 analysis
            code_slice: Current code slice

        Returns:
            Dictionary containing:
                - funcs_to_slice: List of function names needing slices
                - enhanced_vars: Enhanced state variable info with known mappings
                - needs_extended: Boolean indicating if extended analysis is needed
        """
        logger.info(f"[EXT_SLICE] Deciding extended analysis for {len(state_vars)} state variables")

        funcs_to_slice = []
        enhanced_vars = []

        for var in state_vars:
            var_name = var.get('name', '')
            enhanced_var = var.copy()

            # Check for known mappings (Phase 1)
            if var_name in self.KNOWN_MAPPINGS.get(self.lib, {}):
                known = self.KNOWN_MAPPINGS[self.lib][var_name]
                enhanced_var['setup_info'] = known
                enhanced_var['confidence'] = 'high'
                enhanced_var['source'] = 'known_mapping'
                logger.debug(f"[EXT_SLICE] {var_name}: Using known mapping")
            else:
                # Try to infer setup function
                setup_func = self.infer_setup_function(var_name, code_slice)
                if setup_func:
                    enhanced_var['inferred_setup_func'] = setup_func
                    enhanced_var['confidence'] = 'medium'
                    enhanced_var['source'] = 'inferred'
                    if setup_func not in funcs_to_slice:
                        funcs_to_slice.append(setup_func)
                    logger.debug(f"[EXT_SLICE] {var_name}: Inferred setup func: {setup_func}")
                else:
                    enhanced_var['confidence'] = 'low'
                    enhanced_var['source'] = 'unknown'
                    logger.debug(f"[EXT_SLICE] {var_name}: No setup function found")

            enhanced_vars.append(enhanced_var)

        result = {
            'funcs_to_slice': funcs_to_slice,
            'enhanced_vars': enhanced_vars,
            'needs_extended': len(funcs_to_slice) > 0,
            'complete': all(v.get('confidence') == 'high' for v in enhanced_vars)
        }

        logger.info(f"[EXT_SLICE] Decision complete: {len(funcs_to_slice)} functions to slice, "
                   f"{'complete' if result['complete'] else 'needs extension'}")
        return result

    def infer_setup_function(
        self,
        state_var: str,
        code_slice: str
    ) -> Optional[str]:
        """
        Infer the setup function for a given state variable.

        Uses multiple strategies:
        1. Pattern matching on variable names
        2. LLM-based inference
        3. Cache lookup

        Args:
            state_var: State variable name (e.g., 'ColorSpace', 'profile->ColorSpace')
            code_slice: Code slice to analyze

        Returns:
            Inferred setup function name, or None if cannot be inferred
        """
        # Normalize variable name (remove profile-> prefix, etc.)
        normalized_var = state_var.replace('profile->', '').replace('->', '')
        normalized_var = normalized_var.replace('hProfile->', '')

        # Check cache first
        cache_key = f"{self.lib}:{normalized_var}"
        if cache_key in self.setup_func_cache:
            return self.setup_func_cache[cache_key]

        # Strategy 1: Pattern matching
        for var_pattern, func_patterns in self.SETUP_FUNC_PATTERNS.items():
            if var_pattern.lower() in normalized_var.lower():
                for func in func_patterns:
                    # Check if function name appears in code or is library-specific
                    if self.is_valid_function_for_lib(func):
                        logger.debug(f"[EXT_SLICE] Pattern match: {state_var} -> {func}")
                        self.setup_func_cache[cache_key] = func
                        return func

        # Strategy 2: LLM inference (only if pattern matching failed)
        return self.llm_infer_setup_function(state_var, code_slice)

    def llm_infer_setup_function(
        self,
        state_var: str,
        code_slice: str
    ) -> Optional[str]:
        """
        Use LLM to infer the setup function for a state variable.

        Args:
            state_var: State variable name
            code_slice: Code slice to analyze

        Returns:
            Inferred setup function name, or None
        """
        logger.debug(f"[EXT_SLICE] Using LLM to infer setup function for {state_var}")

        sys_prompt = get_prompt('setup_function_inference', 'sys_prompt')
        user_prompt = get_prompt(
            'setup_function_inference', 'user_prompt',
            state_var=state_var,
            code_slice=code_slice[:2000],  # Limit slice size
            lib=self.lib
        )

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_prompt}
        ]

        try:
            response = self.llm_util.get_response(messages)
            result = parse_llm_json_response(response)

            inferred_func = result.get('setup_function')
            if inferred_func:
                logger.info(f"[EXT_SLICE] LLM inferred: {state_var} -> {inferred_func}")
                # Cache the result
                cache_key = f"{self.lib}:{state_var}"
                self.setup_func_cache[cache_key] = inferred_func

            return inferred_func

        except json.JSONDecodeError as e:
            logger.error(f"[EXT_SLICE] Failed to parse LLM response: {e}")
            return None
        except Exception as e:
            logger.error(f"[EXT_SLICE] LLM inference error: {e}")
            return None

    def get_function_slices(
        self,
        func_names: List[str],
        call_chain: Optional[List[str]] = None
    ) -> Dict[str, str]:
        """
        Get code slices for specified functions.

        Args:
            func_names: List of function names
            call_chain: Optional call chain for context

        Returns:
            Dictionary mapping function names to their slices
        """
        slices = {}

        for func_name in func_names:
            # Check cache first
            if func_name in self.slice_cache:
                slices[func_name] = self.slice_cache[func_name]
                logger.debug(f"[EXT_SLICE] Using cached slice for {func_name}")
                continue

            # Get slice
            try:
                slice_text = get_function_slice(func_name, self.lib)
                # Truncate if too large
                if len(slice_text) > MAX_SLICE_SIZE:
                    logger.warning(f"[EXT_SLICE] Slice for {func_name} too large "
                                   f"({len(slice_text)} chars), truncating to {MAX_SLICE_SIZE}")
                    slice_text = self._truncate_slice(slice_text, MAX_SLICE_SIZE)

                slices[func_name] = slice_text
                self.slice_cache[func_name] = slice_text
                logger.info(f"[EXT_SLICE] Retrieved slice for {func_name}: {len(slice_text)} chars")

            except Exception as e:
                logger.error(f"[EXT_SLICE] Failed to get slice for {func_name}: {e}")
                slices[func_name] = ""

        return slices

    def _truncate_slice(self, slice_text: str, max_size: int) -> str:
        """Truncate slice to maximum size while preserving structure."""
        if len(slice_text) <= max_size:
            return slice_text

        # Try to truncate at a reasonable boundary
        truncated = slice_text[:max_size]

        # Find the last complete line
        last_newline = truncated.rfind('\n')
        if last_newline > max_size * 0.8:  # Keep at least 80% if we find a newline
            return truncated[:last_newline]

        return truncated

    def is_valid_function_for_lib(self, func_name: str) -> bool:
        """Check if a function name is valid for the current library."""
        if self.lib == 'lcms':
            return func_name.startswith('cms') or func_name.startswith('_cms')
        elif self.lib == 'libpng':
            return 'png' in func_name.lower()
        elif self.lib == 'libxml':
            return 'xml' in func_name.lower() or 'html' in func_name.lower()
        return True  # Default to accepting

    def get_known_mappings(self, state_var: str) -> Optional[Dict[str, Any]]:
        """
        Get known format mappings for a state variable.

        Args:
            state_var: State variable name

        Returns:
            Dictionary containing offset, size, setup_func, etc., or None
        """
        return self.KNOWN_MAPPINGS.get(self.lib, {}).get(state_var)

    def clear_cache(self):
        """Clear all caches to free memory."""
        self.slice_cache.clear()
        self.setup_func_cache.clear()
        logger.debug("[EXT_SLICE] Caches cleared")

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics for monitoring."""
        return {
            'slice_cache_size': len(self.slice_cache),
            'setup_func_cache_size': len(self.setup_func_cache),
            'total_cached_items': len(self.slice_cache) + len(self.setup_func_cache)
        }
