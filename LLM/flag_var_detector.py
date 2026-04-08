"""
Flag variable detection module using flagrec tool.

This module provides functionality to detect flag variables in C/C++ programs
that may affect branch conditions, using the flagrec static analysis tool.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Any

from config import LOGGER_NAME

logger = logging.getLogger(LOGGER_NAME + __name__)


def run_flagrec_analysis(bitcode_path: str, source_dir: str, output_dir: str,
                         min_confidence: float = 0.5) -> Dict[str, Any]:
    """
    Run flagrec as subprocess and return parsed results.

    Args:
        bitcode_path: Path to the LLVM bitcode file (.bc)
        source_dir: Path to the source code directory
        output_dir: Directory where flagrec will save results
        min_confidence: Minimum confidence score for flag variables (0.0-1.0)

    Returns:
        Dict containing flagrec results with 'flagVariables' and 'constantGroups'

    Raises:
        RuntimeError: If flagrec execution fails
    """
    flagrec_bin = "/home/lab420/Desktop/autoframe/flag_var/flagrec/build/flagrec"

    cmd = [
        flagrec_bin,
        "--bitcode", str(bitcode_path),
        "--source-dir", str(source_dir),
        "--out", str(output_dir),
        "--min-confidence", str(min_confidence)
    ]

    logger.info(f"Running flagrec: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300  # 5 minute timeout
    )

    if result.returncode != 0:
        raise RuntimeError(f"Flagrec failed: {result.stderr}")

    # Read and parse the JSON output
    flags_json_path = Path(output_dir) / "flags.json"
    if not flags_json_path.exists():
        raise RuntimeError(f"Flagrec output not found: {flags_json_path}")

    with open(flags_json_path, 'r') as f:
        flagrec_result = json.load(f)

    logger.info(f"Flagrec found {len(flagrec_result.get('flagVariables', []))} flag variables")
    return flagrec_result


def filter_relevant_flags(flagrec_result: Dict[str, Any], roadblock: Dict[str, Any],
                          line_tolerance: int = 10) -> Tuple[bool, List[Dict], Dict]:
    """
    Filter flag variables to those relevant to the target branch.

    Args:
        flagrec_result: Dict from flagrec flags.json output
        roadblock: Dict with roadblock info containing 'filename', 'line', 'code', 'status'
        line_tolerance: Maximum line distance to consider a flag relevant

    Returns:
        Tuple of (has_flags, relevant_flags, constant_groups):
            - has_flags: bool, whether relevant flags were found
            - relevant_flags: list of relevant FlagVariable dicts
            - constant_groups: dict mapping groupId -> ConstantGroup
    """
    all_flags = flagrec_result.get('flagVariables', [])

    # Build constant group lookup
    constant_groups = {}
    for group in flagrec_result.get('constantGroups', []):
        constant_groups[group['id']] = group

    relevant = []
    rb_file = Path(roadblock.get('filename', '')).name
    rb_line = roadblock.get('line', 0)

    logger.info(f"Filtering flags for {rb_file}:{rb_line} (tolerance: ±{line_tolerance} lines)")

    for flag in all_flags:
        flag_loc = flag.get('location', {})

        # Handle location as dict or string
        if isinstance(flag_loc, dict):
            flag_file = Path(flag_loc.get('file', '')).name
            flag_line = flag_loc.get('line', 0)
        else:
            # Handle string format "file.c:123"
            if ':' in str(flag_loc):
                parts = str(flag_loc).split(':')
                flag_file = parts[0]
                flag_line = int(parts[-1]) if len(parts) > 1 and parts[-1].isdigit() else 0
            else:
                continue

        # Skip if different file
        if flag_file != rb_file:
            continue

        # Check if flag has checks near roadblock line
        found = False
        for check in flag.get('checks', []):
            check_loc = check.get('location', {})
            if isinstance(check_loc, dict):
                check_line = check_loc.get('line', 0)
            else:
                if ':' in str(check_loc):
                    check_line = int(str(check_loc).split(':')[-1])
                else:
                    continue

            if abs(check_line - rb_line) <= line_tolerance:
                relevant.append(flag)
                found = True
                break

        if not found:
            # Also check assignments near roadblock
            for assign in flag.get('assignments', []):
                assign_loc = assign.get('location', {})
                if isinstance(assign_loc, dict):
                    assign_line = assign_loc.get('line', 0)
                else:
                    if ':' in str(assign_loc):
                        assign_line = int(str(assign_loc).split(':')[-1])
                    else:
                        continue

                if abs(assign_line - rb_line) <= line_tolerance:
                    relevant.append(flag)
                    break

    logger.info(f"Found {len(relevant)} relevant flag variables")
    for flag in relevant:
        logger.info(f"  - {flag.get('name', '<unnamed>')} (confidence: {flag.get('confidence', 0):.2f})")

    return len(relevant) > 0, relevant, constant_groups


def load_cached_flagrec_results(cache_file: Path) -> Dict[str, Any] | None:
    """
    Load cached flagrec analysis results.

    Args:
        cache_file: Path to the cached flagrec JSON file

    Returns:
        Dict of flagrec results, or None if cache doesn't exist/invalid
    """
    if not cache_file.exists():
        return None

    try:
        with open(cache_file, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Failed to load flagrec cache: {e}")
        return None


def save_flagrec_results(flagrec_result: Dict[str, Any], cache_file: Path) -> None:
    """
    Save flagrec analysis results to cache.

    Args:
        flagrec_result: Dict of flagrec results to cache
        cache_file: Path to save the cache file
    """
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_file, 'w') as f:
        json.dump(flagrec_result, f, indent=2)
    logger.info(f"Saved flagrec results to cache: {cache_file}")
