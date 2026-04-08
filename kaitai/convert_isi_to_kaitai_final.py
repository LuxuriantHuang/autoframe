#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def traverse_isi_tree(
    node: Dict[str, Any],
    path_prefix: str = "",
    base_offset: int = 0,
    fields: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Recursively traverse the ISI JSON tree and extract all nodes."""
    if fields is None:
        fields = []

    if not isinstance(node, dict):
        return fields

    for hash_id, content in node.items():
        if not isinstance(content, dict):
            continue

        start = content.get("start", 0)
        end = content.get("end", 0)
        has_child = "child" in content

        abs_start = base_offset + start
        abs_end = base_offset + end
        size = abs_end - abs_start

        field_name = path_prefix if path_prefix else hash_id

        # Add ALL nodes
        fields.append({
            "hash_id": hash_id,
            "name": field_name,
            "offset": abs_start,
            "size": size,
            "has_child": has_child,
        })

        # Recursively process children
        if has_child:
            child = content["child"]
            if isinstance(child, dict):
                for child_hash_id, child_content in child.items():
                    child_path = f"{field_name}.{child_hash_id}" if field_name else child_hash_id
                    traverse_isi_tree(
                        {child_hash_id: child_content},
                        child_path,
                        base_offset,
                        fields
                    )

    return fields


def build_mapping_by_range(
    isi_fields: List[Dict[str, Any]],
    kaitai_fields: List[Dict[str, Any]]
) -> Dict[str, str]:
    """Build a mapping from ISI hash_id to Kaitai field name."""
    mapping = {}

    for isi_field in isi_fields:
        isi_start = isi_field["offset"]
        isi_end = isi_start + isi_field["size"]

        # Find best matching Kaitai field
        best_match = None
        best_score = 0

        for kaitai_field in kaitai_fields:
            kaitai_start = kaitai_field["offset"]
            kaitai_end = kaitai_start + kaitai_field["size"]

            # Calculate overlap
            overlap_start = max(isi_start, kaitai_start)
            overlap_end = min(isi_end, kaitai_end)
            overlap = max(0, overlap_end - overlap_start)

            if overlap > 0:
                isi_size = isi_field["size"]
                kaitai_size = kaitai_field["size"]

                if isi_size == kaitai_size and isi_start == kaitai_start:
                    score = 100  # Perfect match
                elif isi_start == kaitai_start:
                    score = 80  # Same start
                else:
                    score = (overlap / isi_size) * 50  # Partial overlap

                if score > best_score:
                    best_score = score
                    best_match = kaitai_field["name"]

        if best_match and best_score >= 50:
            mapping[isi_field["hash_id"]] = best_match

    return mapping


def deduplicate_fields(fields: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicate fields (same offset) and keep the most specific one.
    Prefer larger fields over smaller ones at the same offset.
    """
    # Group by offset
    by_offset: Dict[int, List[Dict[str, Any]]] = {}
    for field in fields:
        offset = field["offset"]
        if offset not in by_offset:
            by_offset[offset] = []
        by_offset[offset].append(field)

    # For each offset, keep the largest field
    result = []
    for offset, field_list in by_offset.items():
        # Sort by size descending, then by name length ascending
        field_list.sort(key=lambda f: (-f["size"], len(f["name"])))
        result.append(field_list[0])  # Keep the largest

    return result


def convert_with_reference(
    isi_json_path: str,
    reference_json_path: str,
    deduplicate: bool = True
) -> Dict[str, Any]:
    """Convert ISI to Kaitai format using reference."""
    # Read ISI JSON
    with open(isi_json_path, 'r', encoding='utf-8') as f:
        isi_data = json.load(f)

    # Extract all ISI fields
    isi_fields = []
    if isinstance(isi_data, dict):
        for root_key, root_value in isi_data.items():
            if isinstance(root_value, dict):
                traverse_isi_tree(
                    {root_key: root_value},
                    path_prefix=root_key,
                    base_offset=0,
                    fields=isi_fields
                )

    # Read reference Kaitai output
    with open(reference_json_path, 'r', encoding='utf-8') as f:
        ref_data = json.load(f)
        kaitai_fields = ref_data.get("fields", [])

    # Build mapping
    hash_to_name = build_mapping_by_range(isi_fields, kaitai_fields)

    # Apply mapping and filter to leaf nodes
    result_fields = []
    for isi_field in isi_fields:
        if not isi_field["has_child"]:  # Only leaf nodes
            hash_id = isi_field["hash_id"]
            field_name = hash_to_name.get(hash_id, isi_field["name"])

            result_fields.append({
                "name": field_name,
                "offset": isi_field["offset"],
                "size": isi_field["size"],
            })

    # Deduplicate if requested
    if deduplicate:
        result_fields = deduplicate_fields(result_fields)

    # Sort by offset
    result_fields = sorted(result_fields, key=lambda x: (x["offset"], x["name"]))

    return {
        "file_path": isi_json_path,
        "fields": result_fields
    }


def generate_reference_for_file(binary_file: str, test_py_path: str) -> Optional[str]:
    """Generate Kaitai reference output for a binary file."""
    ref_output = Path(binary_file).with_suffix(".kaitai.json")

    cmd = [
        "python3",
        test_py_path,
        binary_file,
        "-o",
        str(ref_output)
    ]

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return str(ref_output)
    except subprocess.CalledProcessError as e:
        print(f"Error generating reference: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Convert ISI JSON to Kaitai format with field name mapping"
    )
    parser.add_argument("input", help="Input .isi.json file path")
    parser.add_argument("-o", "--output", default="kaitai_fields.json",
                       help="Output JSON path (default: kaitai_fields.json)")
    parser.add_argument("-r", "--reference",
                       help="Reference JSON from Kaitai parser")
    parser.add_argument("-b", "--binary",
                       help="Binary file to auto-generate reference from")
    parser.add_argument("-t", "--test-py",
                       default="/home/lab420/Desktop/autoframe/kaitai/test.py",
                       help="Path to test.py script")
    parser.add_argument("--keep-duplicates", action="store_true",
                       help="Keep duplicate fields at same offset (default: remove)")

    args = parser.parse_args()

    # Determine reference path
    reference_path = args.reference

    if args.binary and not reference_path:
        print(f"Generating Kaitai reference for {args.binary}...")
        reference_path = generate_reference_for_file(args.binary, args.test_py)
        if not reference_path:
            print("Failed to generate reference. Exiting.")
            return

    if not reference_path:
        print("Error: Either --reference or --binary must be provided")
        parser.print_help()
        return

    # Convert
    result = convert_with_reference(
        args.input,
        reference_path,
        deduplicate=not args.keep_duplicates
    )

    # Write output
    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    print(f"Converted {args.input} -> {args.output}")
    print(f"Extracted {len(result['fields'])} fields")
    print(f"Used reference: {reference_path}")
    if not args.keep_duplicates:
        print("Duplicates removed (kept largest field at each offset)")


if __name__ == "__main__":
    main()