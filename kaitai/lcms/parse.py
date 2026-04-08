#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Robust ICC/LCMS semantic parser + NESTFuzz-based reliability annotation (embedded into fields).

What you get:
- Output JSON schema matches your flat fields style:
    {
      "file_format": ".icc",
      "file_size": ...,
      "fields": [
        {"name":..., "offset":..., "size":..., "tag_id":..., "reliable": true/false?},
        ...
      ],
      "field_tag_base": 1,
      "byte_tag_base": 10000,
      "total_fields": ...
    }

Important behaviors:
1) Container field "tags" is NOT emitted at all (no "tags" node in fields).
2) Reliability is embedded into each field as boolean key "reliable".
   - Container fields are skipped (but we no longer output them anyway).
3) NESTFuzz "big leaf" (e.g., [149,EOF) as one leaf) is treated as UNPARSED_TAIL:
   - Big leaves are excluded from "evidence coverage"
   - The tail blob region is used to mark overlapped robust fields as unreliable
4) gap_tolerance=1 when coarsening leaf coverage (allow 1-byte holes).
5) size==0 fields are always unreliable.

Usage:
  python3 parse.py sample.icc nest.json --out out.json

Tuning (CLI):
  --gap 1            # default 1
  --min-run 2        # default 2
  --max-leaf-len 16  # default 16 (small leaves are evidence; larger leaves => blob candidates)
  --no-tail-unreliable   # disable tail-blob rule (not recommended)
"""

import argparse
import json
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


ICC_SIGNATURE = b"acsp"
ICC_HEADER_SIZE = 128


# ---------------------------
# Robust semantic field output
# ---------------------------

@dataclass
class Field:
    name: str
    offset: int
    size: int
    tag_id: int


class Tagger:
    def __init__(self, start: int = 1):
        self._next = start

    def new(self) -> int:
        tid = self._next
        self._next += 1
        return tid


def u32be(b: bytes, offset: int = 0) -> int:
    """Read big-endian 32-bit unsigned integer from bytes."""
    if offset + 4 > len(b):
        return 0
    return struct.unpack_from(">I", b, offset)[0]


def u16be(b: bytes, offset: int = 0) -> int:
    """Read big-endian 16-bit unsigned integer from bytes."""
    if offset + 2 > len(b):
        return 0
    return struct.unpack_from(">H", b, offset)[0]


def get_tag_name(tag_sig: int) -> str:
    """Convert tag signature integer to 4-character string."""
    try:
        return struct.pack(">I", tag_sig).decode("ASCII", errors="replace")
    except:
        return f"tag_{tag_sig}"


def parse_icc_fields(
    data: bytes,
    field_tag_base: int = 1,
    file_format: str = ".icc",
) -> Dict[str, Any]:
    """
    Produce flat fields list for ICC profile.
    DOES NOT include container field "tags".
    Adds semantic subfields for profile header and tag entries.
    """
    fields: List[Field] = []
    t = Tagger(field_tag_base)
    file_size = len(data)

    # Parse profile header (128 bytes fixed)
    off = 0

    # Basic header fields
    fields.append(Field("profile_size", off, 4, t.new()))
    off += 4

    fields.append(Field("cmm_type", off, 4, t.new()))
    off += 4

    fields.append(Field("version", off, 4, t.new()))
    # Parse version subfields if enough data
    if off + 4 <= file_size:
        fields.append(Field("version.major", off, 1, t.new()))
        fields.append(Field("version.minor_and_bugfix", off + 1, 1, t.new()))
        fields.append(Field("version.reserved", off + 2, 2, t.new()))
    off += 4

    fields.append(Field("profile_class", off, 4, t.new()))
    off += 4

    fields.append(Field("color_space", off, 4, t.new()))
    off += 4

    fields.append(Field("pcs", off, 4, t.new()))
    off += 4

    # DateTime number (12 bytes)
    datetime_off = off
    if datetime_off + 12 <= file_size:
        fields.append(Field("creation_date_time", datetime_off, 12, t.new()))
        fields.append(Field("creation_date_time.year", datetime_off, 2, t.new()))
        fields.append(Field("creation_date_time.month", datetime_off + 2, 2, t.new()))
        fields.append(Field("creation_date_time.day", datetime_off + 4, 2, t.new()))
        fields.append(Field("creation_date_time.hour", datetime_off + 6, 2, t.new()))
        fields.append(Field("creation_date_time.minute", datetime_off + 8, 2, t.new()))
        fields.append(Field("creation_date_time.second", datetime_off + 10, 2, t.new()))
    off += 12

    # File signature
    sig_off = off
    fields.append(Field("file_signature", sig_off, 4, t.new()))
    off += 4

    # Primary platform
    fields.append(Field("primary_platform", off, 4, t.new()))
    off += 4

    # Profile flags (4 bytes)
    flags_off = off
    if flags_off + 4 <= file_size:
        fields.append(Field("profile_flags", flags_off, 4, t.new()))
        fields.append(Field("profile_flags.embedded", flags_off, 1, t.new()))
        fields.append(Field("profile_flags.independent", flags_off + 1, 1, t.new()))
    off += 4

    # Device manufacturer
    fields.append(Field("device_manufacturer", off, 4, t.new()))
    off += 4

    # Device model
    fields.append(Field("device_model", off, 4, t.new()))
    off += 4

    # Device attributes (8 bytes)
    attrs_off = off
    if attrs_off + 8 <= file_size:
        fields.append(Field("device_attributes", attrs_off, 8, t.new()))
    off += 8

    # Rendering intent
    fields.append(Field("rendering_intent", off, 4, t.new()))
    off += 4

    # XYZ number for illuminant (12 bytes)
    xyz_off = off
    if xyz_off + 12 <= file_size:
        fields.append(Field("illuminant_xyz", xyz_off, 12, t.new()))
        fields.append(Field("illuminant_xyz.X", xyz_off, 4, t.new()))
        fields.append(Field("illuminant_xyz.Y", xyz_off + 4, 4, t.new()))
        fields.append(Field("illuminant_xyz.Z", xyz_off + 8, 4, t.new()))
    off += 12

    # Creator
    fields.append(Field("creator", off, 4, t.new()))
    off += 4

    # Identifier (16 bytes)
    fields.append(Field("identifier", off, min(16, max(0, file_size - off)), t.new()))
    off += 16

    # Reserved data (28 bytes)
    fields.append(Field("reserved", off, min(28, max(0, file_size - off)), t.new()))
    off += 28

    # At this point, off should be 128 (end of header)
    # Parse tag table
    if off + 4 > file_size:
        return _finalize(file_format, file_size, fields, field_tag_base)

    tag_count_off = off
    tag_count = u32be(data, tag_count_off)
    fields.append(Field("tag_count", tag_count_off, 4, t.new()))
    off += 4

    # Limit tag count to prevent excessive parsing
    max_tags = min(tag_count, 1000)  # Reasonable upper limit

    tag_table_start = off
    parsed_tags = []

    for i in range(max_tags):
        tag_entry_off = tag_table_start + i * 12
        if tag_entry_off + 12 > file_size:
            break

        # Tag signature (4 bytes)
        tag_sig = u32be(data, tag_entry_off)
        tag_name = get_tag_name(tag_sig)
        fields.append(Field(f"tags[{i}].signature", tag_entry_off, 4, t.new()))

        # Offset to data (4 bytes)
        tag_offset = u32be(data, tag_entry_off + 4)
        fields.append(Field(f"tags[{i}].offset", tag_entry_off + 4, 4, t.new()))

        # Size of data (4 bytes)
        tag_size = u32be(data, tag_entry_off + 8)
        fields.append(Field(f"tags[{i}].size", tag_entry_off + 8, 4, t.new()))

        parsed_tags.append({
            "index": i,
            "signature": tag_sig,
            "name": tag_name,
            "offset": tag_offset,
            "size": tag_size
        })

    # Parse tag data elements
    for tag in parsed_tags:
        data_off = tag["offset"]
        data_size = min(tag["size"], max(0, file_size - data_off))

        if data_off < file_size and data_size > 0:
            # Tag type signature (first 4 bytes of data)
            tag_type_off = data_off
            if data_off + 4 <= file_size:
                tag_type = u32be(data, data_off)
                tag_type_name = get_tag_name(tag_type)
                fields.append(Field(f"tag_data.{tag['name']}.type", tag_type_off, 4, t.new()))

                # Parse specific tag types based on type signature
                _parse_tag_data_fields(fields, t, tag['name'], tag_type, data, data_off, data_size)
            else:
                # Not enough data for type, just record raw data
                fields.append(Field(f"tag_data.{tag['name']}.data", data_off, data_size, t.new()))
        elif tag["offset"] >= file_size:
            # Tag data is beyond file size - record as zero-size field
            fields.append(Field(f"tag_data.{tag['name']}.data", tag["offset"], 0, t.new()))

    return _finalize(file_format, file_size, fields, field_tag_base)


def _parse_tag_data_fields(
    fields: List[Field],
    t: Tagger,
    tag_name: str,
    tag_type: int,
    data: bytes,
    data_off: int,
    data_size: int
) -> None:
    """Parse semantic fields within tag data based on tag type."""

    # XYZ Type - 3 s15Fixed16Number values (X, Y, Z)
    if tag_type == 0x58595A20:  # 'XYZ '
        if data_size >= 12:
            fields.append(Field(f"tag_data.{tag_name}.xyz.X", data_off + 4, 4, t.new()))
            fields.append(Field(f"tag_data.{tag_name}.xyz.Y", data_off + 8, 4, t.new()))
            fields.append(Field(f"tag_data.{tag_name}.xyz.Z", data_off + 12, 4, t.new()))
            return

    # Curve Type - count + curve values
    if tag_type == 0x63757276:  # 'curv'
        if data_size >= 8:
            fields.append(Field(f"tag_data.{tag_name}.count", data_off + 4, 4, t.new()))
            count = u32be(data, data_off + 4)
            if count == 1:
                if data_size >= 9:
                    fields.append(Field(f"tag_data.{tag_name}.value", data_off + 8, 1, t.new()))
            elif count > 1 and data_size >= 8 + count * 2:
                curve_data_off = data_off + 8
                for i in range(min(count, 100)):  # Limit for safety
                    if curve_data_off + i * 2 + 2 <= data_off + data_size:
                        fields.append(Field(f"tag_data.{tag_name}.values[{i}]", curve_data_off + i * 2, 2, t.new()))
        return

    # Text Type - ASCII text
    if tag_type == 0x74657874:  # 'text'
        text_size = max(0, data_size - 4)
        fields.append(Field(f"tag_data.{tag_name}.text", data_off + 4, text_size, t.new()))
        return

    # Text Description Type (multiLocalizedUnicode or similar)
    if tag_type in [0x6D6C7563, 0x64657363]:  # 'mluc', 'desc'
        if data_size >= 8:
            fields.append(Field(f"tag_data.{tag_name}.data", data_off + 4, data_size - 4, t.new()))
        return

    # s15Fixed16 Array Type
    if tag_type == 0x73663332:  # 'sf32'
        if data_size >= 8:
            fields.append(Field(f"tag_data.{tag_name}.data", data_off + 4, data_size - 4, t.new()))
        return

    # DateTime Type
    if tag_type == 0x6474696D:  # 'dtim'
        if data_size >= 16:
            fields.append(Field(f"tag_data.{tag_name}.year", data_off + 4, 2, t.new()))
            fields.append(Field(f"tag_data.{tag_name}.month", data_off + 6, 2, t.new()))
            fields.append(Field(f"tag_data.{tag_name}.day", data_off + 8, 2, t.new()))
            fields.append(Field(f"tag_data.{tag_name}.hour", data_off + 10, 2, t.new()))
            fields.append(Field(f"tag_data.{tag_name}.minute", data_off + 12, 2, t.new()))
            fields.append(Field(f"tag_data.{tag_name}.second", data_off + 14, 2, t.new()))
        return

    # LUT types (mft1, mft2, mAB, mBA)
    if tag_type in [0x6D667431, 0x6D667432, 0x6D414220, 0x6D424120]:
        if data_size > 4:
            fields.append(Field(f"tag_data.{tag_name}.data", data_off + 4, data_size - 4, t.new()))
        return

    # For unknown tag types, just record the raw data
    if data_size > 4:
        fields.append(Field(f"tag_data.{tag_name}.data", data_off + 4, data_size - 4, t.new()))


def _finalize(file_format: str, file_size: int, fields: List[Field], field_tag_base: int) -> Dict[str, Any]:
    return {
        "file_format": file_format,
        "file_size": file_size,
        "fields": [{"name": f.name, "offset": f.offset, "size": f.size, "tag_id": f.tag_id} for f in fields],
        "field_tag_base": field_tag_base,
        "byte_tag_base": 10000,
        "total_fields": len(fields),
    }


# -----------------------------------
# NESTFuzz tree -> evidence extraction
# -----------------------------------

def collect_leaf_intervals_with_blobs(
    nest_root_wrapped: Dict[str, Any],
    *,
    max_leaf_len: int = 16,
) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """
    Split leaves into:
      - leafs_small: leaves with length <= max_leaf_len => evidence coverage
      - big_leaf_blobs: leaves with length  > max_leaf_len => unparsed blob candidates
    """
    if "start" not in nest_root_wrapped:
        nest_root = next(iter(nest_root_wrapped.values()))
    else:
        nest_root = nest_root_wrapped

    leafs_small: List[Tuple[int, int]] = []
    big_leaf_blobs: List[Tuple[int, int]] = []

    def walk(n: Dict[str, Any]):
        s = n.get("start")
        e = n.get("end")
        children = n.get("child") or {}
        if not children:
            if isinstance(s, int) and isinstance(e, int) and e > s:
                if (e - s) <= max_leaf_len:
                    leafs_small.append((s, e))
                else:
                    big_leaf_blobs.append((s, e))
            return
        for _k, ch in children.items():
            walk(ch)

    walk(nest_root)
    return leafs_small, big_leaf_blobs


def coarsen_leaf_coverage(
    leaf_intervals: List[Tuple[int, int]],
    *,
    gap_tolerance: int = 1,
    min_run_len: int = 2,
) -> List[Tuple[int, int]]:
    """
    Coarsen small intervals into continuous runs, bridging gaps <= gap_tolerance.
    gap_tolerance=1: allow 1-byte holes.
    """
    ints = [(s, e) for s, e in leaf_intervals if e > s]
    ints.sort()

    merged: List[Tuple[int, int]] = []
    for s, e in ints:
        if not merged:
            merged.append((s, e))
            continue
        ps, pe = merged[-1]
        if s <= pe + gap_tolerance:
            merged[-1] = (ps, max(pe, e))
        else:
            merged.append((s, e))

    if min_run_len > 1:
        merged = [(s, e) for s, e in merged if (e - s) >= min_run_len]
    return merged


def interval_covered_ratio(merged: List[Tuple[int, int]], s: int, e: int) -> float:
    """Fraction of [s,e) covered by merged intervals."""
    if e <= s:
        return 1.0
    covered = 0
    i = 0
    while i < len(merged) and merged[i][1] <= s:
        i += 1
    cur = s
    while i < len(merged) and merged[i][0] < e:
        a, b = merged[i]
        if b <= cur:
            i += 1
            continue
        if a > cur:
            cur = a
        if cur >= e:
            break
        covered += max(0, min(b, e) - cur)
        cur = min(b, e)
        i += 1
    return covered / (e - s)


def reliability_from_ratio(size: int, ratio: float) -> str:
    """
    Adaptive thresholds:
      size<=0 => unreliable (field absent/truncated)
      size==1 => must be covered
      size<=4 => 0.75
      size>4  => 0.90
    """
    if size <= 0:
        return "unreliable"
    if size == 1:
        return "reliable" if ratio >= 1.0 else "unreliable"
    if size <= 4:
        if ratio >= 0.75:
            return "reliable"
        return "partial" if ratio > 0 else "unreliable"
    if ratio >= 0.90:
        return "reliable"
    return "partial" if ratio > 0 else "unreliable"


def pick_tail_blob_from_big_leaves(
    big_leaf_blobs: List[Tuple[int, int]],
    file_size: int,
) -> Optional[Tuple[int, int]]:
    """
    Prefer a big leaf that reaches EOF; pick the one with the LARGEST start (most "tail").
    """
    cands: List[Tuple[int, int]] = []
    for s, e in big_leaf_blobs:
        s2 = max(0, min(s, file_size))
        e2 = max(0, min(e, file_size))
        if e2 >= file_size and e2 > s2:
            cands.append((s2, e2))
    if not cands:
        return None
    return sorted(cands, key=lambda x: x[0], reverse=True)[0]


# ----------------------------
# Annotation: embed into fields
# ----------------------------

def embed_reliability_into_fields(
    robust: Dict[str, Any],
    nest_json: Dict[str, Any],
    *,
    gap_tolerance: int = 1,
    min_run_len: int = 2,
    max_leaf_len: int = 16,
    treat_tail_blob_as_unreliable: bool = True,
) -> Dict[str, Any]:
    """
    Mutates fields in-place by adding:
      f["reliable"] = True/False
    Returns updated robust dict.
    """
    file_size = int(robust["file_size"])

    leafs_small, big_blobs = collect_leaf_intervals_with_blobs(nest_json, max_leaf_len=max_leaf_len)
    covered_runs = coarsen_leaf_coverage(leafs_small, gap_tolerance=gap_tolerance, min_run_len=min_run_len)
    tail_blob = pick_tail_blob_from_big_leaves(big_blobs, file_size) if treat_tail_blob_as_unreliable else None

    counts = {"true": 0, "false": 0}

    for f in robust["fields"]:
        off = int(f["offset"])
        size = int(f["size"])

        # size==0 or out-of-bounds => unreliable
        if size <= 0 or off < 0 or off > file_size or off + size > file_size:
            f["reliable"] = False
            counts["false"] += 1
            continue

        end = off + size

        # overlap with tail blob => unreliable
        if tail_blob is not None:
            ts, te = tail_blob
            if not (end <= ts or off >= te):
                f["reliable"] = False
                counts["false"] += 1
                continue

        ratio = interval_covered_ratio(covered_runs, off, end)
        rel = reliability_from_ratio(size, ratio)
        f["reliable"] = (rel == "reliable")
        counts["true" if f["reliable"] else "false"] += 1

    out = dict(robust)
    # optional debug stats
    out["coverage_stats"] = {
        "gap_tolerance": gap_tolerance,
        "min_run_len": min_run_len,
        "max_leaf_len": max_leaf_len,
        "tail_blob": {"start": tail_blob[0], "end": tail_blob[1]} if tail_blob else None,
        "covered_runs_preview": covered_runs[:80],
        "big_blobs_preview": big_blobs[:10],
        "reliable_counts": counts,
    }
    return out


# -------------
# CLI Entrypoint
# -------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Robust ICC/LCMS fields + embedded reliability from NESTFuzz")
    ap.add_argument("icc_path", help="input ICC profile file")
    ap.add_argument("nest_json_path", help="NESTFuzz parse json (structure tree)")
    ap.add_argument("--tag-base", type=int, default=1, help="field tag base (default: 1)")
    ap.add_argument("--out", default="", help="output json path (default: stdout)")
    ap.add_argument("--gap", type=int, default=1, help="gap tolerance for coverage coarsening (default: 1)")
    ap.add_argument("--min-run", type=int, default=2, help="minimum coarsened run length to keep (default: 2)")
    ap.add_argument("--max-leaf-len", type=int, default=16, help="max leaf length treated as evidence (default: 16)")
    ap.add_argument("--no-tail-unreliable", action="store_true", help="do not treat big-leaf tail as unreliable")
    args = ap.parse_args()

    with open(args.icc_path, "rb") as f:
        data = f.read()
    with open(args.nest_json_path, "r", encoding="utf-8") as f:
        nest = json.load(f)

    robust = parse_icc_fields(data, field_tag_base=args.tag_base, file_format=".icc")
    out = embed_reliability_into_fields(
        robust,
        nest,
        gap_tolerance=args.gap,
        min_run_len=args.min_run,
        max_leaf_len=args.max_leaf_len,
        treat_tail_blob_as_unreliable=(not args.no_tail_unreliable),
    )

    s = json.dumps(out, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(s)
    else:
        print(s)


if __name__ == "__main__":
    main()
