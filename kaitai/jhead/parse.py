#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Robust JPEG semantic parser + NESTFuzz-based reliability annotation (embedded into fields).

What you get:
- Output JSON schema matches the flat fields style used by kaitai/libpng/parse.py:
    {
      "file_format": ".jpg",
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
1) Container field "segments" is NOT emitted at all.
2) Reliability is embedded into each field as boolean key "reliable".
3) Large NESTFuzz tail blobs are treated as unreliable overlap regions.
4) gap_tolerance=1 when coarsening leaf coverage.
5) size==0 fields are always unreliable.

Usage:
  python3 parse.py sample.jpg nest.json --out out.json
"""

import argparse
import json
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"
MARKERS_WITHOUT_LENGTH = {
    0x01,  # TEM
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,  # RST0..RST7
    0xD8,  # SOI
    0xD9,  # EOI
}
SOF_MARKERS = {
    0xC0, 0xC1, 0xC2, 0xC3,
    0xC5, 0xC6, 0xC7,
    0xC9, 0xCA, 0xCB,
    0xCD, 0xCE, 0xCF,
}

MARKER_NAMES = {
    0x01: "tem",
    0xC0: "sof0",
    0xC1: "sof1",
    0xC2: "sof2",
    0xC3: "sof3",
    0xC4: "dht",
    0xC5: "sof5",
    0xC6: "sof6",
    0xC7: "sof7",
    0xC8: "jpg",
    0xC9: "sof9",
    0xCA: "sof10",
    0xCB: "sof11",
    0xCC: "dac",
    0xCD: "sof13",
    0xCE: "sof14",
    0xCF: "sof15",
    0xD0: "rst0",
    0xD1: "rst1",
    0xD2: "rst2",
    0xD3: "rst3",
    0xD4: "rst4",
    0xD5: "rst5",
    0xD6: "rst6",
    0xD7: "rst7",
    0xD8: "soi",
    0xD9: "eoi",
    0xDA: "sos",
    0xDB: "dqt",
    0xDC: "dnl",
    0xDD: "dri",
    0xDE: "dhp",
    0xDF: "exp",
    0xE0: "app0",
    0xE1: "app1",
    0xE2: "app2",
    0xE3: "app3",
    0xE4: "app4",
    0xE5: "app5",
    0xE6: "app6",
    0xE7: "app7",
    0xE8: "app8",
    0xE9: "app9",
    0xEA: "app10",
    0xEB: "app11",
    0xEC: "app12",
    0xED: "app13",
    0xEE: "app14",
    0xEF: "app15",
    0xFE: "com",
}


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


def u16be(data: bytes, off: int) -> Optional[int]:
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack(">H", data[off:off + 2])[0]


def marker_name(marker: int) -> str:
    return MARKER_NAMES.get(marker, f"marker_0x{marker:02x}")


def clamp_region(file_size: int, off: int, size: int) -> Tuple[int, int]:
    off2 = max(0, min(off, file_size))
    size2 = max(0, min(size, file_size - off2))
    return off2, size2


def find_next_marker_from_entropy(data: bytes, start: int) -> Tuple[int, Optional[int]]:
    i = max(0, start)
    n = len(data)
    while i + 1 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        j = i + 1
        while j < n and data[j] == 0xFF:
            j += 1
        if j >= n:
            return n, None
        marker = data[j]
        if marker == 0x00:
            i = j + 1
            continue
        if 0xD0 <= marker <= 0xD7:
            i = j + 1
            continue
        return i, marker
    return n, None


def parse_jpeg_fields(
    data: bytes,
    field_tag_base: int = 1,
    file_format: str = ".jpg",
) -> Dict[str, Any]:
    fields: List[Field] = []
    t = Tagger(field_tag_base)
    file_size = len(data)

    soi_size = 2 if file_size >= 2 else file_size
    fields.append(Field("soi", 0, soi_size, t.new()))

    if file_size < 2 or data[:2] != JPEG_SOI:
        return _finalize(file_format, file_size, fields, field_tag_base)

    cur = 2
    seg_idx = 0
    while cur < file_size:
        if data[cur] != 0xFF:
            tail_off, tail_size = clamp_region(file_size, cur, file_size - cur)
            fields.append(Field("trailing_data", tail_off, tail_size, t.new()))
            break

        magic_off = cur
        fields.append(Field(f"segments[{seg_idx}].magic", magic_off, 1, t.new()))
        cur += 1

        while cur < file_size and data[cur] == 0xFF:
            cur += 1
        if cur >= file_size:
            fields.append(Field(f"segments[{seg_idx}].marker", file_size, 0, t.new()))
            break

        marker_off = cur
        marker = data[cur]
        fields.append(Field(f"segments[{seg_idx}].marker", marker_off, 1, t.new()))
        cur += 1

        seg_name = marker_name(marker)
        if marker in MARKERS_WITHOUT_LENGTH:
            fields.append(Field(f"segments[{seg_idx}].{seg_name}", magic_off, cur - magic_off, t.new()))
            if marker == 0xD9:
                break
            seg_idx += 1
            continue

        length_off = cur
        length_val = u16be(data, length_off)
        length_size = 2 if length_val is not None else max(0, file_size - length_off)
        fields.append(Field(f"segments[{seg_idx}].length", length_off, length_size, t.new()))
        if length_val is None:
            break

        cur += 2
        payload_declared = max(0, length_val - 2)
        payload_off = cur
        payload_size = min(payload_declared, max(0, file_size - payload_off))
        fields.append(Field(f"segments[{seg_idx}].data", payload_off, payload_size, t.new()))
        _parse_segment_semantics(fields, t, seg_idx, marker, data, payload_off, payload_size)
        cur = payload_off + payload_size

        if marker == 0xDA:
            entropy_off = cur
            eoi_pos, found_marker = find_next_marker_from_entropy(data, entropy_off)
            image_size = max(0, eoi_pos - entropy_off)
            fields.append(Field(f"segments[{seg_idx}].image_data", entropy_off, image_size, t.new()))
            cur = eoi_pos
            seg_idx += 1

            if found_marker == 0xD9 and cur < file_size:
                fields.append(Field(f"segments[{seg_idx}].magic", cur, 1, t.new()))
                if cur + 1 < file_size:
                    fields.append(Field(f"segments[{seg_idx}].marker", cur + 1, 1, t.new()))
                    fields.append(Field(f"segments[{seg_idx}].eoi", cur, 2, t.new()))
                    cur += 2
                else:
                    fields.append(Field(f"segments[{seg_idx}].eoi", cur, 1, t.new()))
                    cur = file_size
            if cur < file_size:
                tail_off, tail_size = clamp_region(file_size, cur, file_size - cur)
                if tail_size > 0:
                    fields.append(Field("trailing_data", tail_off, tail_size, t.new()))
            break

        seg_idx += 1
        if payload_size < payload_declared:
            break

    return _finalize(file_format, file_size, fields, field_tag_base)


def _parse_segment_semantics(
    fields: List[Field],
    t: Tagger,
    seg_idx: int,
    marker: int,
    data: bytes,
    payload_off: int,
    payload_size: int,
) -> None:
    if marker == 0xE0:
        _parse_app0(fields, t, seg_idx, data, payload_off, payload_size)
        return
    if marker == 0xE1:
        _parse_app1(fields, t, seg_idx, data, payload_off, payload_size)
        return
    if marker in SOF_MARKERS:
        _parse_sof(fields, t, seg_idx, data, payload_off, payload_size)
        return
    if marker == 0xDA:
        _parse_sos(fields, t, seg_idx, data, payload_off, payload_size)


def _parse_app0(
    fields: List[Field],
    t: Tagger,
    seg_idx: int,
    data: bytes,
    payload_off: int,
    payload_size: int,
) -> None:
    base = f"segments[{seg_idx}].data"
    if payload_size >= 5:
        fields.append(Field(f"{base}.magic", payload_off, 5, t.new()))
    if payload_size >= 6:
        fields.append(Field(f"{base}.version_major", payload_off + 5, 1, t.new()))
    if payload_size >= 7:
        fields.append(Field(f"{base}.version_minor", payload_off + 6, 1, t.new()))
    if payload_size >= 8:
        fields.append(Field(f"{base}.density_units", payload_off + 7, 1, t.new()))
    if payload_size >= 10:
        fields.append(Field(f"{base}.density_x", payload_off + 8, 2, t.new()))
    if payload_size >= 12:
        fields.append(Field(f"{base}.density_y", payload_off + 10, 2, t.new()))
    if payload_size >= 13:
        fields.append(Field(f"{base}.thumbnail_x", payload_off + 12, 1, t.new()))
    if payload_size >= 14:
        fields.append(Field(f"{base}.thumbnail_y", payload_off + 13, 1, t.new()))
        thumb_x = data[payload_off + 12]
        thumb_y = data[payload_off + 13]
        thumb_off = payload_off + 14
        thumb_size = min(max(0, thumb_x * thumb_y * 3), max(0, payload_size - 14))
        fields.append(Field(f"{base}.thumbnail", thumb_off, thumb_size, t.new()))


def _parse_app1(
    fields: List[Field],
    t: Tagger,
    seg_idx: int,
    data: bytes,
    payload_off: int,
    payload_size: int,
) -> None:
    base = f"segments[{seg_idx}].data"
    if payload_size <= 0:
        return

    body = data[payload_off:payload_off + payload_size]
    nul = body.find(b"\x00")
    if nul == -1:
        fields.append(Field(f"{base}.magic", payload_off, payload_size, t.new()))
        return

    fields.append(Field(f"{base}.magic", payload_off, nul, t.new()))
    zero_off = payload_off + nul
    fields.append(Field(f"{base}.magic_terminator", zero_off, 1, t.new()))

    rest_off = zero_off + 1
    rest_size = max(0, payload_size - (nul + 1))
    if rest_size <= 0:
        return

    if body[:nul] == b"Exif":
        fields.append(Field(f"{base}.body.extra_zero", rest_off, min(1, rest_size), t.new()))
        if rest_size > 1:
            fields.append(Field(f"{base}.body.data", rest_off + 1, rest_size - 1, t.new()))
    else:
        fields.append(Field(f"{base}.body", rest_off, rest_size, t.new()))


def _parse_sof(
    fields: List[Field],
    t: Tagger,
    seg_idx: int,
    data: bytes,
    payload_off: int,
    payload_size: int,
) -> None:
    base = f"segments[{seg_idx}].data"
    if payload_size >= 1:
        fields.append(Field(f"{base}.bits_per_sample", payload_off, 1, t.new()))
    if payload_size >= 3:
        fields.append(Field(f"{base}.image_height", payload_off + 1, 2, t.new()))
    if payload_size >= 5:
        fields.append(Field(f"{base}.image_width", payload_off + 3, 2, t.new()))
    if payload_size >= 6:
        fields.append(Field(f"{base}.num_components", payload_off + 5, 1, t.new()))
        num_components = data[payload_off + 5]
        comp_off = payload_off + 6
        comp_avail = max(0, payload_size - 6)
        count = min(num_components, comp_avail // 3)
        for i in range(count):
            off = comp_off + i * 3
            fields.append(Field(f"{base}.components[{i}]", off, 3, t.new()))
            fields.append(Field(f"{base}.components[{i}].id", off, 1, t.new()))
            fields.append(Field(f"{base}.components[{i}].sampling_factors", off + 1, 1, t.new()))
            fields.append(Field(f"{base}.components[{i}].quantization_table_id", off + 2, 1, t.new()))


def _parse_sos(
    fields: List[Field],
    t: Tagger,
    seg_idx: int,
    data: bytes,
    payload_off: int,
    payload_size: int,
) -> None:
    base = f"segments[{seg_idx}].data"
    if payload_size >= 1:
        fields.append(Field(f"{base}.num_components", payload_off, 1, t.new()))
        num_components = data[payload_off]
    else:
        return

    comp_off = payload_off + 1
    comp_avail = max(0, payload_size - 1)
    count = min(num_components, comp_avail // 2)
    for i in range(count):
        off = comp_off + i * 2
        fields.append(Field(f"{base}.components[{i}]", off, 2, t.new()))
        fields.append(Field(f"{base}.components[{i}].id", off, 1, t.new()))
        fields.append(Field(f"{base}.components[{i}].huffman_table", off + 1, 1, t.new()))

    tail_off = comp_off + count * 2
    remain = max(0, payload_off + payload_size - tail_off)
    if remain >= 1:
        fields.append(Field(f"{base}.start_spectral_selection", tail_off, 1, t.new()))
    if remain >= 2:
        fields.append(Field(f"{base}.end_spectral", tail_off + 1, 1, t.new()))
    if remain >= 3:
        fields.append(Field(f"{base}.appr_bit_pos", tail_off + 2, 1, t.new()))


def _finalize(file_format: str, file_size: int, fields: List[Field], field_tag_base: int) -> Dict[str, Any]:
    return {
        "file_format": file_format,
        "file_size": file_size,
        "fields": [{"name": f.name, "offset": f.offset, "size": f.size, "tag_id": f.tag_id} for f in fields],
        "field_tag_base": field_tag_base,
        "byte_tag_base": 10000,
        "total_fields": len(fields),
    }


def collect_leaf_intervals_with_blobs(
    nest_root_wrapped: Dict[str, Any],
    *,
    max_leaf_len: int = 16,
) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    if "start" not in nest_root_wrapped:
        nest_root = next(iter(nest_root_wrapped.values()))
    else:
        nest_root = nest_root_wrapped

    leafs_small: List[Tuple[int, int]] = []
    big_leaf_blobs: List[Tuple[int, int]] = []

    def walk(node: Dict[str, Any]) -> None:
        start = node.get("start")
        end = node.get("end")
        children = node.get("child") or {}
        if not children:
            if isinstance(start, int) and isinstance(end, int) and end > start:
                if (end - start) <= max_leaf_len:
                    leafs_small.append((start, end))
                else:
                    big_leaf_blobs.append((start, end))
            return
        for child in children.values():
            walk(child)

    walk(nest_root)
    return leafs_small, big_leaf_blobs


def coarsen_leaf_coverage(
    leaf_intervals: List[Tuple[int, int]],
    *,
    gap_tolerance: int = 1,
    min_run_len: int = 2,
) -> List[Tuple[int, int]]:
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
    cands: List[Tuple[int, int]] = []
    for s, e in big_leaf_blobs:
        s2 = max(0, min(s, file_size))
        e2 = max(0, min(e, file_size))
        if e2 >= file_size and e2 > s2:
            cands.append((s2, e2))
    if not cands:
        return None
    return sorted(cands, key=lambda x: x[0], reverse=True)[0]


def embed_reliability_into_fields(
    robust: Dict[str, Any],
    nest_json: Dict[str, Any],
    *,
    gap_tolerance: int = 1,
    min_run_len: int = 2,
    max_leaf_len: int = 16,
    treat_tail_blob_as_unreliable: bool = True,
) -> Dict[str, Any]:
    file_size = int(robust["file_size"])

    leafs_small, big_blobs = collect_leaf_intervals_with_blobs(nest_json, max_leaf_len=max_leaf_len)
    covered_runs = coarsen_leaf_coverage(leafs_small, gap_tolerance=gap_tolerance, min_run_len=min_run_len)
    tail_blob = pick_tail_blob_from_big_leaves(big_blobs, file_size) if treat_tail_blob_as_unreliable else None

    counts = {"true": 0, "false": 0}

    for f in robust["fields"]:
        off = int(f["offset"])
        size = int(f["size"])

        if size <= 0 or off < 0 or off > file_size or off + size > file_size:
            f["reliable"] = False
            counts["false"] += 1
            continue

        end = off + size
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


def main() -> None:
    ap = argparse.ArgumentParser(description="Robust JPEG fields + embedded reliability from NESTFuzz")
    ap.add_argument("jpeg_path", help="input JPEG file")
    ap.add_argument("nest_json_path", help="NESTFuzz parse json (structure tree)")
    ap.add_argument("--tag-base", type=int, default=1, help="field tag base (default: 1)")
    ap.add_argument("--out", default="", help="output json path (default: stdout)")
    ap.add_argument("--gap", type=int, default=1, help="gap tolerance for coverage coarsening (default: 1)")
    ap.add_argument("--min-run", type=int, default=2, help="minimum coarsened run length to keep (default: 2)")
    ap.add_argument("--max-leaf-len", type=int, default=16, help="max leaf length treated as evidence (default: 16)")
    ap.add_argument("--no-tail-unreliable", action="store_true", help="do not treat big-leaf tail as unreliable")
    args = ap.parse_args()

    with open(args.jpeg_path, "rb") as f:
        data = f.read()
    with open(args.nest_json_path, "r", encoding="utf-8") as f:
        nest = json.load(f)

    robust = parse_jpeg_fields(data, field_tag_base=args.tag_base, file_format=".jpg")
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
