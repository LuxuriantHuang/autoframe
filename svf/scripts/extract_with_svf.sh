#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <input.bc|input.ll> <output-dir> [wpa-bin]" >&2
  exit 1
fi

INPUT="$1"
OUTDIR="$2"
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd -P)"
WPA_BIN="${3:-${ROOT_DIR}/third_party/SVF/Release-build/bin/wpa}"
EXTRACTOR="${ROOT_DIR}/build/ir_graph_extractor"
WPA_OUT="${OUTDIR}/svf_wpa.out"
WPA_ERR="${OUTDIR}/svf_wpa.err"

mkdir -p "${OUTDIR}"
"${WPA_BIN}" --ander --print-fp "${INPUT}" >"${WPA_OUT}" 2>"${WPA_ERR}"
"${EXTRACTOR}" "${INPUT}" -o "${OUTDIR}" --svf-wpa-output "${WPA_OUT}"
