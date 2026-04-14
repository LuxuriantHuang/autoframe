"""
State Machine Analyzer - Phase 2/3: LLM-assisted State Variable Inference

This module provides classes for extracting and analyzing state variables
from code slices using LLM, establishing state-to-input mappings, and
analyzing state dependencies.

Classes:
    StateVariableExtractor: Extracts state variables from code using LLM
    StateToInputMapper: Infers state-to-input offset mappings
    StateDependencyAnalyzer: Analyzes dependencies between state variables
    StateMachineInference: Main entry point for state inference pipeline (Phase 2)
    MultiStageStateAnalyzer: Progressive analysis across Phase 1/2/3 (imported)
"""

import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add parent directory to path to import main module
sys.path.insert(0, str(Path(__file__).parent.parent))

import config
from LLM.LLMUtil import LLMUtil, parse_llm_json_response
from LLM.prompt_constructor import get_prompt

logger = logging.getLogger(config.LOGGER_NAME + __name__)

_INVALID_SLICE_MARKERS = (
    "No matching instruction found",
    "Source file not found",
    "source file not found",
    "failed to load source",
    "unable to load source",
    "无法加载",
)


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
    llm_logger = logging.getLogger("LLMInteraction@state_machine")
    if not llm_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s"))
        llm_logger.addHandler(handler)
        llm_logger.setLevel(logging.INFO)
    return llm_logger


class StateVariableExtractor:
    """Extracts state variables from code slices using LLM."""

    def __init__(self, llm_util: LLMUtil):
        """Initialize the state variable extractor.

        Args:
            llm_util: LLM utility instance for making API calls
        """
        self.llm_util = llm_util

    def extract(self, code_slice: str, target_branch: str, lib: str) -> Optional[Dict[str, Any]]:
        """Extract state variables from the given code slice.

        Args:
            code_slice: The code slice to analyze
            target_branch: The target branch statement
            lib: The library name (e.g., "lcms", "libpng")

        Returns:
            Dictionary containing extracted state variables, or None if extraction fails
        """
        # LLM interaction logging
        llm_log = get_llm_logger()
        llm_log.info(f"[LLM_INTERACTION] StateVariableExtractor.extract called for {lib}")
        llm_log.debug(f"[LLM_INTERACTION] code_slice_preview: {str(code_slice)[:200] if code_slice else 'None'}...")
        llm_log.debug(f"[LLM_INTERACTION] target_branch: {target_branch}")

        logger.info(f"[STATE_EXTRACTION] Extracting state variables for {lib}")

        sys_prompt = get_prompt('state_variable_extractor', 'sys_prompt')
        user_prompt = get_prompt('state_variable_extractor', 'user_prompt').format(
            code_slice=code_slice,
            target_branch=target_branch,
            lib=lib
        )

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_prompt}
        ]

        try:
            response = self.llm_util.get_response(messages)
            llm_log.info(f"[LLM_INTERACTION] StateVariableExtractor.extract response length: {len(response) if response else 0}")
            # Parse JSON response
            result = parse_llm_json_response(response)

            state_vars = result.get('state_variables', [])
            logger.info(f"[STATE_EXTRACTION] Found {len(state_vars)} state variables")
            llm_log.info(f"[LLM_INTERACTION] StateVariableExtractor.extract result: {len(state_vars)} state variables found")
            for var in state_vars:
                logger.debug(f"  - {var['name']} (confidence: {var.get('confidence', 'unknown')})")

            return result

        except json.JSONDecodeError as e:
            logger.error(f"[STATE_EXTRACTION] Failed to parse LLM response as JSON: {e}")
            llm_log.error(f"[LLM_INTERACTION] StateVariableExtractor.extract JSON decode error: {e}")
            return None
        except Exception as e:
            logger.error(f"[STATE_EXTRACTION] Error during state extraction: {e}")
            llm_log.error(f"[LLM_INTERACTION] StateVariableExtractor.extract error: {e}")
            return None


class StateToInputMapper:
    """Infers state-to-input offset mappings using LLM."""

    # Known format specifications for common libraries
    FORMAT_SPECS = {
        'lcms': {
            'ColorSpace': {'offset': 16, 'size': 4, 'encoding': 'u32be', 'type': 'signature'},
            'DeviceClass': {'offset': 12, 'size': 4, 'encoding': 'u32be', 'type': 'signature'},
            'PCS': {'offset': 20, 'size': 4, 'encoding': 'u32be', 'type': 'signature'},
            'RenderingIntent': {'offset': 64, 'size': 4, 'encoding': 'u32be', 'type': 'value'},
        },
        'libpng': {
            'color_type': {'offset': 25, 'size': 1, 'encoding': 'u8', 'type': 'value'},
            'bit_depth': {'offset': 24, 'size': 1, 'encoding': 'u8', 'type': 'value'},
            'width': {'offset': 16, 'size': 4, 'encoding': 'u32be', 'type': 'value'},
            'height': {'offset': 20, 'size': 4, 'encoding': 'u32be', 'type': 'value'},
        }
    }

    # Common state name patterns for different libraries
    STATE_PATTERNS = {
        'lcms': [
            r'profile\s*->\s*ColorSpace',
            r'profile\s*->\s*DevClass',
            r'profile\s*->\s*PCS',
            r'profile\s*->\s*RenderingIntent',
            r'hProfile\s*->\s*\w+',
            r'\w+\.ColorSpace',
            r'\w+\.DeviceClass',
        ],
        'libpng': [
            r'png_ptr\s*->\s*color_type',
            r'png_ptr\s*->\s*bit_depth',
            r'png_ptr\s*->\s*interlaced',
            r'info_ptr\s*->\s*\w+',
        ]
    }

    def __init__(self, llm_util: LLMUtil):
        """Initialize the state-to-input mapper.

        Args:
            llm_util: LLM utility instance for making API calls
        """
        self.llm_util = llm_util

    def map_state_to_input(
        self,
        state_variables: Dict[str, Any],
        code_slice: str,
        lib: str
    ) -> Optional[Dict[str, Any]]:
        """Map state variables to input offsets using LLM.

        Args:
            state_variables: Output from StateVariableExtractor
            code_slice: The code slice being analyzed
            lib: The library name

        Returns:
            Dictionary containing state-to-input mappings, or None if mapping fails
        """
        # LLM interaction logging
        llm_log = get_llm_logger()
        llm_log.info(f"[LLM_INTERACTION] StateToInputMapper.map_state_to_input called for {lib}")
        llm_log.debug(f"[LLM_INTERACTION] state_variables_count: {len(state_variables.get('state_variables', []))}")

        logger.info(f"[STATE_MAPPING] Mapping state variables to input for {lib}")

        # First check for known mappings in format specs
        known_mappings = self._check_known_mappings(state_variables, lib)

        # Use LLM to infer unknown mappings
        sys_prompt = get_prompt('state_to_input_mapper', 'sys_prompt')
        user_prompt = get_prompt('state_to_input_mapper', 'user_prompt').format(
            state_variables=json.dumps(state_variables, ensure_ascii=False, indent=2),
            code_slice=code_slice,
            lib=lib,
            file_format_context=self._get_format_context(lib)
        )

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_prompt}
        ]

        try:
            response = self.llm_util.get_response(messages)
            llm_log.info(f"[LLM_INTERACTION] StateToInputMapper.map_state_to_input response length: {len(response) if response else 0}")
            result = parse_llm_json_response(response)

            # Merge known mappings with LLM-inferred mappings
            mappings = result.get('mappings', [])

            # Add known mappings that weren't found by LLM
            for known in known_mappings:
                if not any(m['state_variable'] == known['state_variable'] for m in mappings):
                    known['inference_method'] = 'format_spec'
                    known['confidence'] = 'high'
                    mappings.append(known)

            result['mappings'] = mappings

            logger.info(f"[STATE_MAPPING] Generated {len(mappings)} mappings")
            llm_log.info(f"[LLM_INTERACTION] StateToInputMapper.map_state_to_input result: {len(mappings)} mappings")
            for m in mappings:
                logger.debug(f"  - {m['state_variable']} @ offset {m.get('input_offset', '?')} "
                           f"(confidence: {m.get('confidence', 'unknown')})")

            return result

        except json.JSONDecodeError as e:
            logger.error(f"[STATE_MAPPING] Failed to parse LLM response: {e}")
            llm_log.error(f"[LLM_INTERACTION] StateToInputMapper.map_state_to_input JSON decode error: {e}")
            return None
        except Exception as e:
            logger.error(f"[STATE_MAPPING] Error during mapping: {e}")
            llm_log.error(f"[LLM_INTERACTION] StateToInputMapper.map_state_to_input error: {e}")
            return None

    def _check_known_mappings(self, state_variables: Dict[str, Any], lib: str) -> List[Dict[str, Any]]:
        """Check format specifications for known state-to-input mappings.

        Args:
            state_variables: State variables from extractor
            lib: Library name

        Returns:
            List of known mappings found in format specs
        """
        known = []
        if lib not in self.FORMAT_SPECS:
            return known

        format_spec = self.FORMAT_SPECS[lib]
        state_vars = state_variables.get('state_variables', [])

        for state_var in state_vars:
            name = state_var.get('name', '')
            # Try to match state name to format spec keys
            for key, spec in format_spec.items():
                if key.lower() in name.lower() or name.lower() in key.lower():
                    # Determine target value if available
                    target_value = state_var.get('target_value', '')
                    byte_value = self._compute_byte_value(target_value, spec)

                    known.append({
                        'state_variable': name,
                        'input_offset': spec['offset'],
                        'size': spec['size'],
                        'encoding': spec['encoding'],
                        'endianness': 'big' if 'be' in spec['encoding'] else 'little',
                        'target_value': target_value,
                        'byte_value': byte_value,
                        'reasoning': f"Known {lib} format specification"
                    })

        return known

    def _compute_byte_value(self, target_value: str, spec: Dict[str, Any]) -> str:
        """Compute the byte representation of a target value.

        Args:
            target_value: Target value (could be enum name, hex, or decimal)
            spec: Format specification for this state

        Returns:
            Hex string representation of the byte value
        """
        # Known signature mappings
        signatures = {
            'RGB': '0x52474220',
            'LAB': '0x4C414220',
            'XYZ': '0x58595A20',
            'CMYK': '0x434D594B',
            'mntr': '0x6D6E7472',
            'prtr': '0x70727472',
            'scnr': '0x73636E72',
        }

        # Check if target is a known signature
        for sig, val in signatures.items():
            if sig.lower() in target_value.lower():
                return val

        # Try to parse as hex
        if target_value.startswith('0x') or target_value.startswith('0X'):
            return target_value

        # Try to parse as integer
        try:
            int_val = int(target_value)
            size = spec.get('size', 4)
            if spec['encoding'] == 'u32be':
                return f'0x{int_val:08x}'
            elif spec['encoding'] == 'u32le':
                return f'0x{int_val:08x}'
            elif spec['encoding'] == 'u16be':
                return f'0x{int_val:04x}'
            elif spec['encoding'] == 'u16le':
                return f'0x{int_val:04x}'
            elif spec['encoding'] == 'u8':
                return f'0x{int_val:02x}'
        except ValueError:
            pass

        # Return as-is if we can't compute
        return target_value

    def _get_format_context(self, lib: str) -> str:
        """Get format-specific context for the LLM.

        Args:
            lib: Library name

        Returns:
            Format context string
        """
        contexts = {
            'lcms': "ICC Profile format: 128-byte header with DeviceClass@12, ColorSpace@16, PCS@20",
            'libpng': "PNG format: 8-byte signature, IHDR chunk at offset 8",
            'libjpeg': "JPEG format: SOI marker (0xFFD8) followed by segments",
        }
        return contexts.get(lib, "Unknown format")


class StateDependencyAnalyzer:
    """Analyzes dependencies and constraints between state variables."""

    def __init__(self, llm_util: LLMUtil):
        """Initialize the state dependency analyzer.

        Args:
            llm_util: LLM utility instance for making API calls
        """
        self.llm_util = llm_util

    def analyze(
        self,
        state_variables: Dict[str, Any],
        mappings: Dict[str, Any],
        code_slice: str,
        target_branch: str
    ) -> Optional[Dict[str, Any]]:
        """Analyze dependencies between state variables.

        Args:
            state_variables: Output from StateVariableExtractor
            mappings: Output from StateToInputMapper
            code_slice: The code slice being analyzed
            target_branch: The target branch statement

        Returns:
            Dictionary containing dependency analysis, or None if analysis fails
        """
        # LLM interaction logging
        llm_log = get_llm_logger()
        llm_log.info(f"[LLM_INTERACTION] StateDependencyAnalyzer.analyze called")
        llm_log.debug(f"[LLM_INTERACTION] state_variables_count: {len(state_variables.get('state_variables', []))}")
        llm_log.debug(f"[LLM_INTERACTION] mappings_count: {len(mappings.get('mappings', [])) if mappings else 0}")

        logger.info("[STATE_DEPENDENCY] Analyzing state dependencies")

        sys_prompt = get_prompt('state_dependency_analyzer', 'sys_prompt')
        user_prompt = get_prompt('state_dependency_analyzer', 'user_prompt').format(
            state_variables=json.dumps(state_variables, ensure_ascii=False, indent=2),
            mappings=json.dumps(mappings, ensure_ascii=False, indent=2),
            code_slice=code_slice,
            target_branch=target_branch
        )

        messages = [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_prompt}
        ]

        try:
            response = self.llm_util.get_response(messages)
            llm_log.info(f"[LLM_INTERACTION] StateDependencyAnalyzer.analyze response length: {len(response) if response else 0}")
            result = parse_llm_json_response(response)

            conflicts = result.get('conflicts', [])
            if conflicts:
                logger.warning(f"[STATE_DEPENDENCY] Found {len(conflicts)} potential conflicts")
                llm_log.info(f"[LLM_INTERACTION] StateDependencyAnalyzer.analyze result: {len(conflicts)} conflicts found")
                for conflict in conflicts:
                    logger.debug(f"  - {conflict}")
            else:
                llm_log.info(f"[LLM_INTERACTION] StateDependencyAnalyzer.analyze result: no conflicts")

            return result

        except json.JSONDecodeError as e:
            logger.error(f"[STATE_DEPENDENCY] Failed to parse LLM response: {e}")
            llm_log.error(f"[LLM_INTERACTION] StateDependencyAnalyzer.analyze JSON decode error: {e}")
            return None
        except Exception as e:
            logger.error(f"[STATE_DEPENDENCY] Error during analysis: {e}")
            llm_log.error(f"[LLM_INTERACTION] StateDependencyAnalyzer.analyze error: {e}")
            return None


class StateMachineInference:
    """Main entry point for the state inference pipeline."""

    def __init__(self, llm_util: LLMUtil):
        """Initialize the state machine inference pipeline.

        Args:
            llm_util: LLM utility instance for making API calls
        """
        self.llm_util = llm_util
        self.extractor = StateVariableExtractor(llm_util)
        self.mapper = StateToInputMapper(llm_util)
        self.dependency_analyzer = StateDependencyAnalyzer(llm_util)

    @staticmethod
    def _is_valid_code_slice(code_slice: str) -> bool:
        if not code_slice or len(code_slice.strip()) < 32:
            return False
        return not any(marker in code_slice for marker in _INVALID_SLICE_MARKERS)

    def infer_state_machine(
        self,
        code_slice: str,
        target_branch: str,
        lib: str
    ) -> Optional[Dict[str, Any]]:
        """Run the full state inference pipeline.

        Args:
            code_slice: The code slice to analyze
            target_branch: The target branch statement
            lib: The library name

        Returns:
            Dictionary containing complete state analysis, or None if pipeline fails
        """
        logger.info(f"[STATE_INFERENCE] Starting state inference for {lib}")
        if not self._is_valid_code_slice(code_slice):
            logger.warning("[STATE_INFERENCE] Skipping state inference because code slice is invalid or unresolved")
            return None

        # Step 1: Extract state variables
        state_vars = self.extractor.extract(code_slice, target_branch, lib)
        if not state_vars:
            logger.warning("[STATE_INFERENCE] Failed to extract state variables")
            return None

        # Step 2: Map states to input offsets
        mappings = self.mapper.map_state_to_input(state_vars, code_slice, lib)
        if not mappings:
            logger.warning("[STATE_INFERENCE] Failed to map states to inputs")
            # Continue anyway with partial results

        # Step 3: Analyze dependencies
        dependencies = None
        if mappings:
            dependencies = self.dependency_analyzer.analyze(
                state_vars, mappings, code_slice, target_branch
            )

        # Compile final result
        result = {
            'state_variables': state_vars,
            'mappings': mappings,
            'dependencies': dependencies,
            'state_hints': self._generate_state_hints(state_vars, mappings)
        }

        logger.info("[STATE_INFERENCE] State inference complete")
        return result

    def _generate_state_hints(
        self,
        state_vars: Dict[str, Any],
        mappings: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Generate state hints for prompt integration.

        Args:
            state_vars: State variable extraction result
            mappings: State-to-input mapping result

        Returns:
            List of state hint strings
        """
        hints = []

        if not mappings:
            return hints

        for mapping in mappings.get('mappings', []):
            var_name = mapping.get('state_variable', 'unknown')
            offset = mapping.get('input_offset', '?')
            size = mapping.get('size', '?')
            encoding = mapping.get('encoding', '?')
            target = mapping.get('target_value', 'unknown')
            byte_val = mapping.get('byte_value', target)

            hint = (
                f"[STATE] {var_name}: input offset {offset}-{offset+size-1} "
                f"({size} bytes, {encoding}), target value {target} "
                f"(bytes: {byte_val})"
            )
            hints.append(hint)

        return hints

    def get_state_hints_for_prompt(self, code_slice: str, target_branch: str, lib: str) -> List[str]:
        """Convenience method to get state hints directly for prompt integration.

        Args:
            code_slice: The code slice to analyze
            target_branch: The target branch statement
            lib: The library name

        Returns:
            List of state hint strings for prompt
        """
        result = self.infer_state_machine(code_slice, target_branch, lib)
        if result:
            return result.get('state_hints', [])
        return []

    def infer_with_multi_stage(
        self,
        code_slice: str,
        target_branch: str,
        lib: str,
        call_chain: Optional[List[str]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Perform multi-stage progressive analysis (Phase 3).

        This method uses the MultiStageStateAnalyzer to progressively try
        different information sources from high-confidence hardcoded mappings
        to extended slice analysis.

        Args:
            code_slice: The code slice to analyze
            target_branch: The target branch statement
            lib: The library name
            call_chain: Optional call chain for context

        Returns:
            Dictionary containing complete state analysis, or None if analysis fails
        """
        # Lazy import to avoid circular dependency
        from LLM.multi_stage_analyzer import MultiStageStateAnalyzer

        logger.info(f"[STATE_INFERENCE] Using multi-stage progressive analysis for {lib}")
        if not self._is_valid_code_slice(code_slice):
            logger.warning("[STATE_INFERENCE] Skipping multi-stage inference because code slice is invalid or unresolved")
            return None

        # Create multi-stage analyzer for this library
        multi_stage_analyzer = MultiStageStateAnalyzer(self.llm_util, lib)

        # Perform progressive analysis
        result = multi_stage_analyzer.analyze_with_progressive_stages(
            code_slice, target_branch, call_chain
        )

        # Log statistics
        stats = multi_stage_analyzer.get_statistics()
        logger.info(f"[STATE_INFERENCE] Multi-stage stats: {json.dumps(stats, indent=2)}")

        return result

    def get_state_hints_with_multi_stage(
        self,
        code_slice: str,
        target_branch: str,
        lib: str,
        call_chain: Optional[List[str]] = None
    ) -> List[str]:
        """
        Get state hints using multi-stage progressive analysis.

        This is the recommended method for Phase 3 integration, as it
        automatically selects the best analysis strategy based on
        available information.

        Args:
            code_slice: The code slice to analyze
            target_branch: The target branch statement
            lib: The library name
            call_chain: Optional call chain for context

        Returns:
            List of state hint strings for prompt integration
        """
        result = self.infer_with_multi_stage(code_slice, target_branch, lib, call_chain)
        if result:
            hints = result.get('state_hints', [])
            logger.info(f"[STATE_INFERENCE] Generated {len(hints)} state hints using {result.get('stage_used', 'unknown')}")
            return hints
        return []
