#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Robust PNG semantic parser + NESTFuzz-based reliability annotation (embedded into fields).

What you get:
- Output JSON schema matches your flat fields style:
    {
      "file_format": ".png",
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
1) Container field "chunks" is NOT emitted at all (no "chunks" node in fields).
2) Reliability is embedded into each field as boolean key "reliable".
   - Container fields are skipped (but we no longer output them anyway).
3) NESTFuzz "big leaf" (e.g., [149,EOF) as one leaf) is treated as UNPARSED_TAIL:
   - Big leaves are excluded from "evidence coverage"
   - The tail blob region is used to mark overlapped robust fields as unreliable
4) gap_tolerance=1 when coarsening leaf coverage (allow 1-byte holes).
5) size==0 fields are always unreliable.

Usage:
  python3 robust_png_embed_reliable.py sample.png nest.json --out out.json

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


PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


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


def u32be(b: bytes) -> int:
    return struct.unpack(">I", b)[0]


def parse_png_fields(
    data: bytes,
    field_tag_base: int = 1,
    file_format: str = ".png",
) -> Dict[str, Any]:
    """
    Produce flat fields list. DOES NOT include container field "chunks".
    Adds semantic subfields for:
      IHDR, gAMA, sRGB, cHRM, bKGD(2B common case), pHYs, tEXt.
    """
    fields: List[Field] = []
    t = Tagger(field_tag_base)
    file_size = len(data)

    # magic
    fields.append(Field("magic", 0, 8, t.new()))

    if file_size < 8 or data[:8] != PNG_MAGIC:
        return _finalize(file_format, file_size, fields, field_tag_base)

    # IHDR chunk (expected first)
    off = 8
    if off + 8 > file_size:
        return _finalize(file_format, file_size, fields, field_tag_base)

    ihdr_len_off = off
    ihdr_len = u32be(data[ihdr_len_off:ihdr_len_off + 4])
    fields.append(Field("ihdr_len", ihdr_len_off, 4, t.new()))

    ihdr_type_off = off + 4
    fields.append(Field("ihdr_type", ihdr_type_off, 4, t.new()))
    ihdr_type = data[ihdr_type_off:ihdr_type_off + 4]

    ihdr_data_off = off + 8
    ihdr_data_size = min(ihdr_len, max(0, file_size - ihdr_data_off))
    fields.append(Field("ihdr", ihdr_data_off, ihdr_data_size, t.new()))

    if ihdr_data_size >= 13:
        fields.append(Field("ihdr.width", ihdr_data_off + 0, 4, t.new()))
        fields.append(Field("ihdr.height", ihdr_data_off + 4, 4, t.new()))
        fields.append(Field("ihdr.bit_depth", ihdr_data_off + 8, 1, t.new()))
        fields.append(Field("ihdr.color_type", ihdr_data_off + 9, 1, t.new()))
        fields.append(Field("ihdr.compression_method", ihdr_data_off + 10, 1, t.new()))
        fields.append(Field("ihdr.filter_method", ihdr_data_off + 11, 1, t.new()))
        fields.append(Field("ihdr.interlace_method", ihdr_data_off + 12, 1, t.new()))

    # IHDR CRC: position from declared len, clamped
    ihdr_crc_off_decl = ihdr_data_off + ihdr_len
    ihdr_crc_off = min(ihdr_crc_off_decl, file_size)
    ihdr_crc_size = 4 if ihdr_crc_off + 4 <= file_size else max(0, file_size - ihdr_crc_off)
    fields.append(Field("ihdr_crc", ihdr_crc_off, ihdr_crc_size, t.new()))

    # advance to first non-IHDR chunk
    cur = min(ihdr_crc_off_decl + 4, file_size)

    # parse remaining chunks: [len(4) type(4) body(len) crc(4)]
    chunk_index = 0
    while cur + 8 <= file_size:
        clen_off = cur
        declared_len = u32be(data[clen_off:clen_off + 4])
        fields.append(Field(f"chunks[{chunk_index}].len", clen_off, 4, t.new()))

        ctype_off = cur + 4
        ctype = data[ctype_off:ctype_off + 4]
        fields.append(Field(f"chunks[{chunk_index}].type", ctype_off, 4, t.new()))

        body_off = cur + 8
        body_size = declared_len
        if body_off + body_size > file_size:
            body_size = max(0, file_size - body_off)
        fields.append(Field(f"chunks[{chunk_index}].body", body_off, body_size, t.new()))

        _parse_chunk_body_semantics(fields, t, chunk_index, ctype, data, body_off, body_size)

        crc_off_decl = body_off + declared_len
        crc_off = min(crc_off_decl, file_size)
        crc_size = 4 if crc_off + 4 <= file_size else max(0, file_size - crc_off)
        fields.append(Field(f"chunks[{chunk_index}].crc", crc_off, crc_size, t.new()))

        nxt = min(crc_off_decl + 4, file_size)
        if nxt <= cur:
            break
        cur = nxt
        chunk_index += 1

        if ctype == b"IEND":
            break

    return _finalize(file_format, file_size, fields, field_tag_base)


def _parse_chunk_body_semantics(fields: List[Field], t: Tagger, idx: int, ctype: bytes,
                               data: bytes, body_off: int, body_size: int) -> None:
    if ctype == b"gAMA" and body_size >= 4:
        fields.append(Field(f"chunks[{idx}].body.gamma_int", body_off, 4, t.new()))
        return

    if ctype == b"sRGB" and body_size >= 1:
        fields.append(Field(f"chunks[{idx}].body.render_intent", body_off, 1, t.new()))
        return

    if ctype == b"cHRM" and body_size >= 32:
        fields.append(Field(f"chunks[{idx}].body.white_point", body_off + 0, 8, t.new()))
        fields.append(Field(f"chunks[{idx}].body.white_point.x_int", body_off + 0, 4, t.new()))
        fields.append(Field(f"chunks[{idx}].body.white_point.y_int", body_off + 4, 4, t.new()))

        fields.append(Field(f"chunks[{idx}].body.red", body_off + 8, 8, t.new()))
        fields.append(Field(f"chunks[{idx}].body.red.x_int", body_off + 8, 4, t.new()))
        fields.append(Field(f"chunks[{idx}].body.red.y_int", body_off + 12, 4, t.new()))

        fields.append(Field(f"chunks[{idx}].body.green", body_off + 16, 8, t.new()))
        fields.append(Field(f"chunks[{idx}].body.green.x_int", body_off + 16, 4, t.new()))
        fields.append(Field(f"chunks[{idx}].body.green.y_int", body_off + 20, 4, t.new()))

        fields.append(Field(f"chunks[{idx}].body.blue", body_off + 24, 8, t.new()))
        fields.append(Field(f"chunks[{idx}].body.blue.x_int", body_off + 24, 4, t.new()))
        fields.append(Field(f"chunks[{idx}].body.blue.y_int", body_off + 28, 4, t.new()))
        return

    # bKGD varies by color type; your example used 2 bytes
    if ctype == b"bKGD" and body_size >= 2:
        fields.append(Field(f"chunks[{idx}].body.bkgd", body_off, 2, t.new()))
        fields.append(Field(f"chunks[{idx}].body.bkgd.value", body_off, 2, t.new()))
        return

    if ctype == b"pHYs" and body_size >= 9:
        fields.append(Field(f"chunks[{idx}].body.pixels_per_unit_x", body_off + 0, 4, t.new()))
        fields.append(Field(f"chunks[{idx}].body.pixels_per_unit_y", body_off + 4, 4, t.new()))
        fields.append(Field(f"chunks[{idx}].body.unit", body_off + 8, 1, t.new()))
        return

    if ctype == b"tEXt" and body_size >= 1:
        body = data[body_off:body_off + body_size]
        nul = body.find(b"\x00")
        if nul == -1:
            fields.append(Field(f"chunks[{idx}].body.keyword", body_off, body_size, t.new()))
        else:
            kw_len = nul
            txt_len = max(0, body_size - (nul + 1))
            fields.append(Field(f"chunks[{idx}].body.keyword", body_off, kw_len, t.new()))
            fields.append(Field(f"chunks[{idx}].body.text", body_off + nul + 1, txt_len, t.new()))
        return


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
    # optional debug stats (safe to keep; remove if you want a minimal JSON)
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
    ap = argparse.ArgumentParser(description="Robust PNG fields + embedded reliability from NESTFuzz")
    ap.add_argument("png_path", help="input PNG file")
    ap.add_argument("nest_json_path", help="NESTFuzz parse json (structure tree)")
    ap.add_argument("--tag-base", type=int, default=1, help="field tag base (default: 1)")
    ap.add_argument("--out", default="", help="output json path (default: stdout)")
    ap.add_argument("--gap", type=int, default=1, help="gap tolerance for coverage coarsening (default: 1)")
    ap.add_argument("--min-run", type=int, default=2, help="minimum coarsened run length to keep (default: 2)")
    ap.add_argument("--max-leaf-len", type=int, default=16, help="max leaf length treated as evidence (default: 16)")
    ap.add_argument("--no-tail-unreliable", action="store_true", help="do not treat big-leaf tail as unreliable")
    args = ap.parse_args()

    with open(args.png_path, "rb") as f:
        data = f.read()
    with open(args.nest_json_path, "r", encoding="utf-8") as f:
        nest = json.load(f)

    robust = parse_png_fields(data, field_tag_base=args.tag_base, file_format=".png")
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
