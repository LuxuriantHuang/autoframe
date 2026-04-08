#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import traceback

from kaitaistruct import KaitaiStructError, EndOfStreamError

from png import Png  # noqa: F401


def _dbg_start_end(dbg_entry: Any) -> Optional[Tuple[int, int]]:
    """Extract (start,end) from Kaitai --read-pos _debug entry."""
    if not isinstance(dbg_entry, dict):
        return None
    s = dbg_entry.get("start")
    e = dbg_entry.get("end")
    if isinstance(s, int) and isinstance(e, int) and e >= s:
        return s, e
    return None


def _is_kaitai_obj(x: Any) -> bool:
    """Heuristic: Kaitai struct objects have _debug and _io."""
    return hasattr(x, "_debug") and hasattr(x, "_io")


def _generate_file_id(file_path: str) -> str:
    """Generate unique ID for file based on content hash."""
    try:
        with open(file_path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()[:12]
    except Exception:
        return hashlib.md5(file_path.encode()).hexdigest()[:12]


def collect_fields_robust(
    obj: Any,
    path_prefix: str = "",
    base_offset: int = 0,
    *,
    seen: Optional[Set[int]] = None,
    errors: Optional[List[Dict[str, Any]]] = None,
    depth: int = 0,
) -> List[Dict[str, Any]]:
    """
    Recursively collect fields with fault-tolerant parsing.
    Continues parsing even when individual fields fail.
    """
    if seen is None:
        seen = set()
    if errors is None:
        errors = []

    out: List[Dict[str, Any]] = []

    oid = id(obj)
    if oid in seen:
        return out
    seen.add(oid)

    dbg = getattr(obj, "_debug", None)
    if not isinstance(dbg, dict):
        return out

    parent_io = getattr(obj, "_io", None)

    for field_name, dbg_entry in dbg.items():
        if field_name in ("_io", "_root", "_parent"):
            continue

        full_name = field_name if path_prefix == "" else f"{path_prefix}.{field_name}"

        # Try to get field value with error handling
        val = None
        field_error = None
        try:
            val = getattr(obj, field_name)
        except Exception as e:
            # Field access failed, but continue parsing
            field_error = {
                "field": full_name,
                "error": f"{type(e).__name__}: {str(e)}",
                "depth": depth,
                "traceback": traceback.format_exc().split('\n')[:3]  # First 3 lines
            }
            errors.append(field_error)

        r = _dbg_start_end(dbg_entry)

        # Determine if this is a parent node
        is_parent_object = val is not None and _is_kaitai_obj(val)
        is_parent_list = isinstance(val, list) and val and _is_kaitai_obj(val[0])

        # Add field if it's a leaf node (even if it has an error)
        if r and not is_parent_object and not is_parent_list:
            rel_s, rel_e = r
            abs_s = base_offset + rel_s
            abs_e = base_offset + rel_e
            field_dict = {
                "name": full_name,
                "offset": int(abs_s),
                "size": int(abs_e - abs_s)
            }
            if field_error:
                field_dict["parse_error"] = field_error["error"]
            out.append(field_dict)

        # Recursively parse child objects (even if parent had issues)
        if val is not None:
            # Handle lists
            if isinstance(val, list):
                for i, item in enumerate(val):
                    if not _is_kaitai_obj(item):
                        continue
                    item_prefix = f"{full_name}[{i}]"

                    item_io = getattr(item, "_io", None)
                    if item_io is parent_io:
                        child_base = base_offset
                    else:
                        child_base = base_offset + (r[0] if r else 0)

                    try:
                        out.extend(collect_fields_robust(
                            item, item_prefix, child_base,
                            seen=seen, errors=errors, depth=depth + 1
                        ))
                    except Exception as e:
                        # Child parsing failed, record and continue
                        errors.append({
                            "field": item_prefix,
                            "error": f"{type(e).__name__}: {str(e)}",
                            "depth": depth + 1
                        })
                continue

            # Handle child objects
            if _is_kaitai_obj(val):
                child_io = getattr(val, "_io", None)
                if child_io is parent_io:
                    child_base = base_offset
                else:
                    child_base = base_offset + (r[0] if r else 0)

                try:
                    out.extend(collect_fields_robust(
                        val, full_name, child_base,
                        seen=seen, errors=errors, depth=depth + 1
                    ))
                except Exception as e:
                    # Child parsing failed, record and continue
                    errors.append({
                        "field": full_name,
                        "error": f"{type(e).__name__}: {str(e)}",
                        "depth": depth + 1
                    })

    return out


def build_output_with_metadata(
    file_path: str,
    parent_id: Optional[str] = None,
    generation: int = 0,
    mutation_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build output with metadata for fuzzing mutation tracking.

    Args:
        file_path: Path to the file to parse
        parent_id: ID of the parent file in mutation tree
        generation: Number of mutations from seed (0 = seed)
        mutation_info: Dictionary with mutation details (type, position, etc.)
    """
    file_id = _generate_file_id(file_path)
    errors: List[Dict[str, Any]] = []

    try:
        parsed = Png.from_file(file_path)
        fields = collect_fields_robust(
            parsed, path_prefix="", base_offset=0,
            errors=errors
        )

        # De-dup and sort by offset
        uniq = {}
        for f in fields:
            key = (f["name"], f["offset"], f["size"])
            uniq[key] = f
        fields = sorted(uniq.values(), key=lambda x: (x["offset"], x["name"]))

        is_valid = len(errors) == 0

        return {
            "file_path": file_path,
            "file_id": file_id,
            "metadata": {
                "parent_id": parent_id,
                "generation": generation,
                "mutation_info": mutation_info or {},
                "is_valid": is_valid,
                "parse_errors": errors
            },
            "fields": fields
        }

    except Exception as e:
        # Top-level parsing failed
        return {
            "file_path": file_path,
            "file_id": file_id,
            "metadata": {
                "parent_id": parent_id,
                "generation": generation,
                "mutation_info": mutation_info or {},
                "is_valid": False,
                "parse_errors": [{
                    "field": "<root>",
                    "error": f"{type(e).__name__}: {str(e)}",
                    "depth": 0,
                    "traceback": traceback.format_exc()
                }]
            },
            "fields": []
        }


class MutationTree:
    """Track mutation tree for fuzzing corpus."""

    def __init__(self, db_path: str = "mutation_tree.json"):
        self.db_path = db_path
        self.tree: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self):
        """Load existing mutation tree from disk."""
        if Path(self.db_path).exists():
            try:
                with open(self.db_path, 'r') as f:
                    self.tree = json.load(f)
            except Exception:
                self.tree = {}

    def _save(self):
        """Save mutation tree to disk."""
        with open(self.db_path, 'w') as f:
            json.dump(self.tree, f, ensure_ascii=False, indent=2)

    def add_node(self, result: Dict[str, Any]):
        """Add a node to the mutation tree."""
        file_id = result["file_id"]
        self.tree[file_id] = {
            "file_path": result["file_path"],
            "metadata": result["metadata"],
            "field_count": len(result["fields"]),
            "timestamp": None  # Could add timestamp if needed
        }
        self._save()

    def get_lineage(self, file_id: str) -> List[Dict[str, Any]]:
        """
        Get full lineage from seed to this file.
        Returns list of nodes from seed to target.
        """
        lineage = []
        current = file_id

        while current is not None:
            if current not in self.tree:
                break
            node = self.tree[current]
            lineage.append(node)
            current = node["metadata"].get("parent_id")

        lineage.reverse()  # Put seed first
        return lineage

    def get_seed_id(self, file_id: str) -> Optional[str]:
        """Get the root seed ID for a given file."""
        current = file_id
        while current is not None:
            if current not in self.tree:
                return current
            parent_id = self.tree[current]["metadata"].get("parent_id")
            if parent_id is None:
                return current
            current = parent_id
        return None


def main():
    ap = argparse.ArgumentParser(
        description="Robust Kaitai parser with mutation tree tracking for fuzzing"
    )
    ap.add_argument("input", help="input file path")
    ap.add_argument("-o", "--output", default="fields_robust.json",
                    help="output json path (default: fields_robust.json)")
    ap.add_argument("--parent-id", default=None,
                    help="parent file ID in mutation tree")
    ap.add_argument("--generation", type=int, default=0,
                    help="mutation generation (0 = seed file)")
    ap.add_argument("--mutation-type", default=None,
                    help="type of mutation applied (e.g., bit_flip, splice)")
    ap.add_argument("--mutation-position", type=int, default=None,
                    help="byte position of mutation")
    ap.add_argument("--update-tree", action="store_true",
                    help="update mutation tree database")

    args = ap.parse_args()

    # Build mutation info if provided
    mutation_info = None
    if args.mutation_type or args.mutation_position is not None:
        mutation_info = {
            "type": args.mutation_type or "unknown",
            "position": args.mutation_position
        }

    # Parse file
    result = build_output_with_metadata(
        args.input,
        parent_id=args.parent_id,
        generation=args.generation,
        mutation_info=mutation_info
    )

    # Write output
    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    print(f"Wrote -> {args.output}")

    # Update mutation tree if requested
    if args.update_tree:
        tree = MutationTree()
        tree.add_node(result)
        print(f"Updated mutation tree -> {tree.db_path}")

        # Show lineage
        lineage = tree.get_lineage(result["file_id"])
        print(f"Lineage (generation {len(lineage) - 1}):")
        for i, node in enumerate(lineage):
            gen = node["metadata"].get("generation", 0)
            path = node["file_path"]
            mut_type = node["metadata"].get("mutation_info", {}).get("type", "seed")
            print(f"  [{gen}] {path} ({mut_type})")


if __name__ == "__main__":
    main()
