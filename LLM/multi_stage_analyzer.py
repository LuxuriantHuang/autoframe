"""
Multi-Stage State Analyzer - Phase 3: Progressive State Analysis Pipeline

This module provides a multi-stage analyzer that progressively uses different
information sources to infer state variables and their mappings, from high-confidence
hardcoded mappings to LLM-based inference.

Classes:
    MultiStageStateAnalyzer: Coordinates progressive analysis across multiple stages
"""

import json
import logging
from typing import Any, Dict, List, Optional

import config
from LLM.LLMUtil import LLMUtil
from LLM.extended_slice_manager import ExtendedSliceManager
from LLM.state_machine_analyzer import StateMachineInference

logger = logging.getLogger(config.LOGGER_NAME + __name__)


class MultiStageStateAnalyzer:
    """
    Coordinates multi-stage progressive state analysis.

    This class implements a progressive analysis strategy:
    1. Stage 1: Try Phase 1 hardcoded mappings (high confidence, 0 tokens)
    2. Stage 2: Phase 2 slice analysis (medium confidence, ~2000 tokens)
    3. Stage 3: Extended slice analysis when needed (medium confidence, ~3000 tokens)

    The analyzer returns early if a stage produces a complete result.
    """

    def __init__(self, llm_util: LLMUtil, lib: str):
        """Initialize the multi-stage state analyzer.

        Args:
            llm_util: LLM utility instance
            lib: Library name (e.g., 'lcms', 'libpng')
        """
        self.llm_util = llm_util
        self.lib = lib
        self.extended_slice_manager = ExtendedSliceManager(llm_util, lib)
        self.phase2_analyzer = StateMachineInference(llm_util)

        # Statistics tracking
        self.stage1_hits = 0
        self.stage2_hits = 0
        self.stage3_hits = 0
        self.total_analyses = 0

    def analyze_with_progressive_stages(
        self,
        code_slice: str,
        target_branch: str,
        call_chain: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Perform progressive state analysis across multiple stages.

        The analysis proceeds in stages, returning early if a complete result is found:
        - Stage 1: Check for known hardcoded mappings (Phase 1)
        - Stage 2: Perform slice-based analysis (Phase 2)
        - Stage 3: Extended slice analysis if needed

        Args:
            code_slice: The code slice to analyze
            target_branch: The target branch statement
            call_chain: Optional call chain for context

        Returns:
            Dictionary containing:
                - state_variables: List of detected state variables
                - mappings: State-to-input mappings
                - dependencies: State dependency analysis
                - state_hints: Formatted hints for prompts
                - stage_used: Which stage produced the result
                - confidence: Overall confidence level
                - complete: Whether all states have high-confidence mappings
        """
        self.total_analyses += 1
        logger.info(f"[MULTI_STAGE] Starting progressive analysis for {self.lib}")

        result = {
            'state_variables': [],
            'mappings': None,
            'dependencies': None,
            'state_hints': [],
            'stage_used': 'none',
            'confidence': 'unknown',
            'complete': False
        }

        # Stage 1: Try Phase 1 hardcoded mappings
        stage1_result = self.stage1_known_mappings(code_slice, target_branch)
        if stage1_result['complete']:
            self.stage1_hits += 1
            logger.info("[MULTI_STAGE] Stage 1: Complete with known mappings")
            result.update(stage1_result)
            result['stage_used'] = 'stage1'
            return result

        # Stage 2: Phase 2 slice analysis
        logger.info("[MULTI_STAGE] Stage 1 incomplete, proceeding to Stage 2")
        stage2_result = self.stage2_slice_analysis(code_slice, target_branch)
        result.update(stage2_result)

        # Stage 3: Check if extended analysis is needed
        if self.needs_extended_analysis(result):
            logger.info("[MULTI_STAGE] Stage 2 incomplete, proceeding to Stage 3")
            stage3_result = self.stage3_extended_analysis(
                code_slice, target_branch, call_chain
            )
            result = self.merge_results(result, stage3_result)
            if result.get('complete'):
                self.stage3_hits += 1
                result['stage_used'] = 'stage3'
            else:
                result['stage_used'] = 'stage3_incomplete'
        else:
            self.stage2_hits += 1
            result['stage_used'] = 'stage2'

        logger.info(f"[MULTI_STAGE] Analysis complete using {result['stage_used']}, "
                   f"confidence: {result['confidence']}, complete: {result['complete']}")
        return result

    def stage1_known_mappings(
        self,
        code_slice: str,
        target_branch: str
    ) -> Dict[str, Any]:
        """
        Stage 1: Check for known hardcoded mappings (Phase 1).

        This stage checks if the target branch involves state variables that
        have known mappings in the ExtendedSliceManager.

        Args:
            code_slice: The code slice to analyze
            target_branch: The target branch statement

        Returns:
            Dictionary with analysis results
        """
        logger.debug("[MULTI_STAGE] Stage 1: Checking for known mappings")

        # Extract potential state variable names from the target branch
        state_var_names = self._extract_state_var_names(target_branch, code_slice)

        enhanced_vars = []
        complete = True
        all_mappings = []

        for var_name in state_var_names:
            known = self.extended_slice_manager.get_known_mappings(var_name)
            if known:
                enhanced_var = {
                    'name': var_name,
                    'setup_info': known,
                    'confidence': 'high',
                    'source': 'known_mapping'
                }
                enhanced_vars.append(enhanced_var)

                # Create mapping for this variable
                mapping = {
                    'state_variable': var_name,
                    'input_offset': known['offset'],
                    'size': known['size'],
                    'encoding': known['encoding'],
                    'endianness': 'big' if 'be' in known['encoding'] else 'little',
                    'inference_method': 'format_spec',
                    'confidence': 'high',
                    'reasoning': f"Known {self.lib} format specification"
                }

                # Add possible values if available
                if 'possible_values' in known:
                    mapping['possible_values'] = known['possible_values']
                if 'signatures' in known:
                    mapping['signatures'] = known['signatures']

                all_mappings.append(mapping)
            else:
                # At least one unknown variable, not complete
                complete = False

        if enhanced_vars:
            result = {
                'state_variables': enhanced_vars,
                'mappings': {'mappings': all_mappings},
                'dependencies': None,
                'state_hints': self._generate_hints_from_mappings(all_mappings),
                'confidence': 'high' if complete else 'medium',
                'complete': complete
            }
            logger.info(f"[MULTI_STAGE] Stage 1: Found {len(enhanced_vars)} known mappings, "
                       f"complete: {complete}")
            return result

        return {'complete': False, 'confidence': 'unknown'}

    def stage2_slice_analysis(
        self,
        code_slice: str,
        target_branch: str
    ) -> Dict[str, Any]:
        """
        Stage 2: Perform Phase 2 slice-based analysis.

        This stage uses the StateMachineInference to analyze the code slice
        and extract state variables using LLM.

        Args:
            code_slice: The code slice to analyze
            target_branch: The target branch statement

        Returns:
            Dictionary with analysis results
        """
        logger.debug("[MULTI_STAGE] Stage 2: Performing slice-based analysis")

        try:
            phase2_result = self.phase2_analyzer.infer_state_machine(
                code_slice, target_branch, self.lib
            )

            if phase2_result:
                # Determine confidence based on state variable extraction
                state_vars = phase2_result.get('state_variables', {}).get('state_variables', [])
                has_high_confidence = any(v.get('confidence') == 'high' for v in state_vars)

                return {
                    'state_variables': state_vars,
                    'mappings': phase2_result.get('mappings'),
                    'dependencies': phase2_result.get('dependencies'),
                    'state_hints': phase2_result.get('state_hints', []),
                    'confidence': 'medium' if has_high_confidence else 'low',
                    'complete': False  # Stage 2 rarely produces complete results
                }
        except Exception as e:
            logger.error(f"[MULTI_STAGE] Stage 2 analysis failed: {e}")

        return {'complete': False, 'confidence': 'low'}

    def stage3_extended_analysis(
        self,
        code_slice: str,
        target_branch: str,
        call_chain: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Stage 3: Extended slice analysis using setup function slices.

        This stage retrieves slices of state setup functions and combines
        them with the original slice for enhanced analysis.

        Args:
            code_slice: The original code slice
            target_branch: The target branch statement
            call_chain: Optional call chain for context

        Returns:
            Dictionary with enhanced analysis results
        """
        logger.debug("[MULTI_STAGE] Stage 3: Performing extended slice analysis")

        # Get current state variables from Stage 2
        # For now, we'll re-extract to determine what needs extension
        try:
            # First, get basic state extraction
            state_vars = self.phase2_analyzer.extractor.extract(code_slice, target_branch, self.lib)
            if not state_vars:
                return {'complete': False, 'confidence': 'unknown'}

            # Decide which functions need extended slicing
            extended_decision = self.extended_slice_manager.decide_extended_analysis(
                state_vars.get('state_variables', []), code_slice
            )

            if not extended_decision['needs_extended']:
                logger.info("[MULTI_STAGE] Stage 3: No extended analysis needed")
                return {
                    'state_variables': extended_decision['enhanced_vars'],
                    'complete': extended_decision['complete'],
                    'confidence': 'medium' if extended_decision['complete'] else 'low'
                }

            # Get extended slices
            func_names = extended_decision['funcs_to_slice']
            logger.info(f"[MULTI_STAGE] Stage 3: Fetching {len(func_names)} extended slices")
            extended_slices = self.extended_slice_manager.get_function_slices(func_names, call_chain)

            # Combine original slice with extended slices
            combined_context = self._combine_slices(code_slice, extended_slices)

            # Re-analyze with extended context
            enhanced_result = self.phase2_analyzer.infer_state_machine(
                combined_context, target_branch, self.lib
            )

            if enhanced_result:
                # Merge enhanced results with decision results
                enhanced_vars = extended_decision['enhanced_vars']
                for var in enhanced_vars:
                    # Add any new information from enhanced analysis
                    existing_vars = enhanced_result.get('state_variables', {}).get('state_variables', [])
                    for existing in existing_vars:
                        if existing.get('name') == var.get('name'):
                            # Merge information
                            if 'setup_info' not in var and 'input_offset' in existing:
                                var['input_offset'] = existing['input_offset']

                return {
                    'state_variables': enhanced_vars,
                    'mappings': enhanced_result.get('mappings'),
                    'dependencies': enhanced_result.get('dependencies'),
                    'state_hints': enhanced_result.get('state_hints', []),
                    'complete': extended_decision['complete'],
                    'confidence': 'medium' if extended_decision['complete'] else 'low'
                }

        except Exception as e:
            logger.error(f"[MULTI_STAGE] Stage 3 analysis failed: {e}")

        return {'complete': False, 'confidence': 'low'}

    def needs_extended_analysis(self, result: Dict[str, Any]) -> bool:
        """
        Determine if extended slice analysis is needed.

        Args:
            result: Current analysis result

        Returns:
            True if extended analysis is needed
        """
        # Need extended analysis if:
        # 1. Not complete
        # 2. Has at least some state variables (otherwise extended analysis won't help)
        # 3. Confidence is not already high

        if result.get('complete', False):
            return False

        state_vars = result.get('state_variables', [])
        if not state_vars:
            return False

        # Check if we have low/medium confidence variables that could benefit from extension
        for var in state_vars:
            if isinstance(var, dict):
                conf = var.get('confidence', 'low')
                if conf in ['low', 'medium']:
                    return True

        return False

    def merge_results(
        self,
        base_result: Dict[str, Any],
        new_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Merge analysis results from different stages.

        Args:
            base_result: Base result from earlier stage
            new_result: New result from later stage

        Returns:
            Merged result dictionary
        """
        merged = base_result.copy()

        # Merge state variables, avoiding duplicates
        base_vars = base_result.get('state_variables', [])
        new_vars = new_result.get('state_variables', [])

        # Create a map of existing variables
        var_map = {}
        for var in base_vars:
            if isinstance(var, dict) and 'name' in var:
                var_map[var['name']] = var

        # Add or update with new variables
        for var in new_vars:
            if isinstance(var, dict) and 'name' in var:
                if var['name'] in var_map:
                    # Merge info from new result
                    existing = var_map[var['name']]
                    for key, value in var.items():
                        if key not in existing or existing.get(key) is None:
                            existing[key] = value
                else:
                    var_map[var['name']] = var

        merged['state_variables'] = list(var_map.values())

        # Update other fields if new_result has them
        for key in ['mappings', 'dependencies', 'state_hints', 'complete', 'confidence']:
            if key in new_result and new_result[key] is not None:
                merged[key] = new_result[key]

        return merged

    def _extract_state_var_names(
        self,
        target_branch: str,
        code_slice: str
    ) -> List[str]:
        """
        Extract potential state variable names from target branch and code slice.

        Args:
            target_branch: The target branch statement
            code_slice: The code slice to analyze

        Returns:
            List of potential state variable names
        """
        # Known state variables for different libraries
        known_vars = {
            'lcms': ['ColorSpace', 'DeviceClass', 'PCS', 'RenderingIntent'],
            'libpng': ['color_type', 'bit_depth', 'width', 'height'],
            'libjpeg': ['color_space', 'components', 'precision']
        }

        var_names = []

        # Check if known variables are mentioned
        for var in known_vars.get(self.lib, []):
            if var.lower() in target_branch.lower() or var.lower() in code_slice.lower():
                var_names.append(var)

        # Also check for profile-> patterns common in lcms
        if self.lib == 'lcms':
            import re
            profile_patterns = re.findall(r'profile\s*->\s*(\w+)', code_slice)
            var_names.extend(profile_patterns)

        # Remove duplicates while preserving order
        seen = set()
        unique_vars = []
        for var in var_names:
            if var not in seen:
                seen.add(var)
                unique_vars.append(var)

        return unique_vars

    def _generate_hints_from_mappings(self, mappings: List[Dict[str, Any]]) -> List[str]:
        """
        Generate state hints from mappings.

        Args:
            mappings: List of state-to-input mappings

        Returns:
            List of formatted hint strings
        """
        hints = []
        for mapping in mappings:
            var_name = mapping.get('state_variable', 'unknown')
            offset = mapping.get('input_offset', '?')
            size = mapping.get('size', '?')
            encoding = mapping.get('encoding', '?')

            hint = (
                f"[STATE] {var_name}: input offset {offset}-{offset+size-1 if offset != '?' else '?'} "
                f"({size} bytes, {encoding})"
            )
            hints.append(hint)

        return hints

    def _combine_slices(
        self,
        original_slice: str,
        extended_slices: Dict[str, str]
    ) -> str:
        """
        Combine original slice with extended slices.

        Args:
            original_slice: The original code slice
            extended_slices: Dictionary of function names to their slices

        Returns:
            Combined code context
        """
        parts = [original_slice]

        for func_name, slice_text in extended_slices.items():
            if slice_text:
                parts.append(f"\n// Extended slice for {func_name}:\n{slice_text}")

        return "\n".join(parts)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about stage usage.

        Returns:
            Dictionary with statistics
        """
        return {
            'total_analyses': self.total_analyses,
            'stage1_hits': self.stage1_hits,
            'stage2_hits': self.stage2_hits,
            'stage3_hits': self.stage3_hits,
            'stage1_rate': self.stage1_hits / self.total_analyses if self.total_analyses > 0 else 0,
            'stage2_rate': self.stage2_hits / self.total_analyses if self.total_analyses > 0 else 0,
            'stage3_rate': self.stage3_hits / self.total_analyses if self.total_analyses > 0 else 0,
        }

    def reset_statistics(self):
        """Reset statistics counters."""
        self.stage1_hits = 0
        self.stage2_hits = 0
        self.stage3_hits = 0
        self.total_analyses = 0
