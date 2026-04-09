#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOT'
用法:
  ./benchmarks/queue_region_cov.sh [--all-fuzzers] <库目录> <输出目录>

示例:
  ./benchmarks/queue_region_cov.sh benchmarks/pdf2text out
  ./benchmarks/queue_region_cov.sh benchmarks/jhead 6h
  ./benchmarks/queue_region_cov.sh --all-fuzzers benchmarks/pdf2text out

可选环境变量:
  TARGET_BIN        显式指定待分析二进制路径
  TARGET_ARGS       目标程序参数模板，默认是 "@@"，其中 @@ 会被替换成 queue 样本路径
  TARGET_TIMEOUT    单个样本的最长执行时间，例如 1s / 0.5s；默认自动推断，最少 1s
  TIMEOUT_MULTIPLIER 自动推断 TARGET_TIMEOUT 时使用的倍率，默认 10
  LLVM_COV_BIN      指定 llvm-cov 可执行文件名，默认自动探测
  LLVM_PROFDATA_BIN 指定 llvm-profdata 可执行文件名，默认自动探测
  KEEP_PROFILES=1   保留 /tmp 下的临时 profraw/profdata 文件，便于排查
  SHOW_REPORT=1     额外打印完整 llvm-cov report
EOT
}

collect_queue_dirs() {
  local lib_dir="$1"
  local out_dir="$2"
  local include_all="$3"

  if [[ "${include_all}" == "1" ]]; then
    find "${lib_dir}/${out_dir}" -mindepth 2 -maxdepth 2 -type d -name queue | sort
  else
    printf '%s\n' "${lib_dir}/${out_dir}/default/queue"
  fi
}

detect_target_timeout_from_stats() {
  local multiplier="${TIMEOUT_MULTIPLIER:-10}"
  shift
  local stats_path
  local exec_timeout_ms
  local max_exec_timeout_ms=0

  if [[ -n "${TARGET_TIMEOUT:-}" ]]; then
    printf '%s\n' "${TARGET_TIMEOUT}"
    return 0
  fi

  for stats_path in "$@"; do
    if [[ -f "${stats_path}" ]]; then
      exec_timeout_ms="$(awk -F: '/^exec_timeout/ {gsub(/ /, "", $2); print $2; exit}' "${stats_path}")"
      if [[ "${exec_timeout_ms}" =~ ^[0-9]+$ ]] && (( exec_timeout_ms > max_exec_timeout_ms )); then
        max_exec_timeout_ms="${exec_timeout_ms}"
      fi
    fi
  done

  if (( max_exec_timeout_ms > 0 )); then
    awk -v ms="${max_exec_timeout_ms}" -v mul="${multiplier}" '
      BEGIN {
        secs = (ms * mul) / 1000;
        if (secs < 1) secs = 1;
        printf "%.3fs\n", secs;
      }
    '
    return 0
  fi

  printf '1s\n'
}

find_llvm_tool() {
  local preferred="${1:-}"
  shift

  if [[ -n "${preferred}" ]] && command -v "${preferred}" >/dev/null 2>&1; then
    command -v "${preferred}"
    return 0
  fi

  local candidate
  for candidate in "$@"; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      command -v "${candidate}"
      return 0
    fi
  done

  return 1
}

find_target_bin() {
  local lib_dir="$1"
  local candidate
  local -a candidates=(
    "${lib_dir}/target/llvmcov/target"
  )

  for candidate in "${candidates[@]}"; do
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  return 1
}

resolve_lib_dir() {
  local raw_path="${1%/}"
  local candidate
  local -a candidates=(
    "${raw_path}"
    "./${raw_path}"
    "./benchmarks/${raw_path}"
  )

  for candidate in "${candidates[@]}"; do
    if [[ -d "${candidate}" ]]; then
      cd "${candidate}" && pwd
      return 0
    fi
  done

  return 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

all_fuzzers=0
if [[ "${1:-}" == "--all-fuzzers" ]]; then
  all_fuzzers=1
  shift
fi

if [[ $# -ne 2 ]]; then
  usage
  exit 1
fi

lib_dir="$(resolve_lib_dir "$1")" || {
  echo "错误: 库目录不存在: $1" >&2
  exit 1
}
out_dir="${2%/}"
lib_name="$(basename "${lib_dir}")"

mapfile -t queue_dirs < <(collect_queue_dirs "${lib_dir}" "${out_dir}" "${all_fuzzers}")
if [[ "${#queue_dirs[@]}" -eq 0 ]]; then
  echo "错误: 未找到任何 queue 目录: ${lib_dir}/${out_dir}" >&2
  exit 1
fi

existing_queue_dirs=()
stats_paths=()
for queue_dir in "${queue_dirs[@]}"; do
  if [[ -d "${queue_dir}" ]]; then
    existing_queue_dirs+=("${queue_dir}")
    stats_paths+=("${queue_dir%/queue}/fuzzer_stats")
  fi
done

if [[ "${#existing_queue_dirs[@]}" -eq 0 ]]; then
  echo "错误: 没有可用的 queue 目录: ${lib_dir}/${out_dir}" >&2
  exit 1
fi

target_bin="${TARGET_BIN:-}"
if [[ -z "${target_bin}" ]]; then
  target_bin="$(find_target_bin "${lib_dir}")" || {
    echo "错误: 找不到可执行目标文件。" >&2
    echo "请通过 TARGET_BIN=/path/to/bin 显式指定 coverage 二进制。" >&2
    exit 1
  }
fi

if [[ ! -x "${target_bin}" ]]; then
  echo "错误: 找不到可执行目标文件: ${target_bin}" >&2
  exit 1
fi

llvm_cov_bin="$(find_llvm_tool "${LLVM_COV_BIN:-}" llvm-cov-14 llvm-cov)" || {
  echo "错误: 找不到 llvm-cov。" >&2
  exit 1
}

llvm_profdata_bin="$(find_llvm_tool "${LLVM_PROFDATA_BIN:-}" llvm-profdata-14 llvm-profdata)" || {
  echo "错误: 找不到 llvm-profdata。" >&2
  exit 1
}

timeout_bin="$(find_llvm_tool "${TIMEOUT_BIN:-}" timeout gtimeout)" || {
  echo "错误: 找不到 timeout 命令。" >&2
  exit 1
}

target_timeout="$(detect_target_timeout_from_stats "${stats_paths[@]}")"

echo "使用 llvm-cov: ${llvm_cov_bin}"
echo "使用 llvm-profdata: ${llvm_profdata_bin}"
echo "使用 timeout: ${timeout_bin}"

tmp_dir="$(mktemp -d "/tmp/queue_region_cov.${lib_name}.${out_dir}.XXXXXX")"
cleanup() {
  if [[ "${KEEP_PROFILES:-0}" != "1" ]]; then
    rm -rf "${tmp_dir}"
  else
    echo "保留临时文件: ${tmp_dir}" >&2
  fi
}
trap cleanup EXIT

queue_files=()
for queue_dir in "${existing_queue_dirs[@]}"; do
  while IFS= read -r sample; do
    queue_files+=("${sample}")
  done < <(find "${queue_dir}" -maxdepth 1 -type f ! -name '.*' | sort)
done

if [[ "${#queue_files[@]}" -eq 0 ]]; then
  echo "错误: 未找到可用样本。" >&2
  exit 1
fi

echo "样本数量: ${#queue_files[@]}"
echo "Queue 目录数: ${#existing_queue_dirs[@]}"
echo "目标二进制: ${target_bin}"
echo "单样本超时: ${target_timeout}"
echo "临时目录: ${tmp_dir}"

target_args_template="${TARGET_ARGS:-@@}"
read -r -a target_args_parts <<< "${target_args_template}"

executed=0
timeout_count=0
signal_count=0
failure_count=0
timeout_log="${tmp_dir}/timeouts.txt"
signal_log="${tmp_dir}/signals.txt"
failure_log="${tmp_dir}/failures.txt"
for sample in "${queue_files[@]}"; do
  args=()
  for arg in "${target_args_parts[@]}"; do
    if [[ "${arg}" == "@@" ]]; then
      args+=("${sample}")
    else
      args+=("${arg}")
    fi
  done

  profile_path="${tmp_dir}/sample_${executed}.%p.%m.profraw"
  set +e
  LLVM_PROFILE_FILE="${profile_path}" \
    "${timeout_bin}" --kill-after=1s "${target_timeout}" "${target_bin}" "${args[@]}" \
    >/dev/null 2>&1
  rc=$?
  set -e

  if [[ "${rc}" -eq 124 ]]; then
    timeout_count=$((timeout_count + 1))
    printf '%s\n' "${sample}" >> "${timeout_log}"
  elif [[ "${rc}" -ge 128 ]]; then
    signal_count=$((signal_count + 1))
    printf 'rc=%s %s\n' "${rc}" "${sample}" >> "${signal_log}"
  elif [[ "${rc}" -ne 0 ]]; then
    failure_count=$((failure_count + 1))
    printf 'rc=%s %s\n' "${rc}" "${sample}" >> "${failure_log}"
  fi

  executed=$((executed + 1))

  if (( executed % 100 == 0 )); then
    echo "已处理: ${executed}/${#queue_files[@]}"
  fi
done

echo "执行完成: ${executed} 个样本"

shopt -s nullglob
profraw_files=("${tmp_dir}"/*.profraw)
shopt -u nullglob

if [[ "${#profraw_files[@]}" -eq 0 ]]; then
  echo "错误: 没有生成任何 .profraw 文件。" >&2
  echo "请确认目标程序是用 LLVM source-based coverage 编译的。" >&2
  exit 1
fi

echo "生成的 profraw 文件数: ${#profraw_files[@]}"

profdata_path="${tmp_dir}/coverage.profdata"
profraw_list_path="${tmp_dir}/profraw_files.txt"
printf '%s\n' "${profraw_files[@]}" > "${profraw_list_path}"
"${llvm_profdata_bin}" merge -sparse --input-files="${profraw_list_path}" -o "${profdata_path}"

report_text="$("${llvm_cov_bin}" report "${target_bin}" -instr-profile="${profdata_path}")"
total_line="$(awk '/^TOTAL/ {print; exit}' <<< "${report_text}")"

if [[ -z "${total_line}" ]]; then
  echo "错误: llvm-cov report 中未找到 TOTAL 行。" >&2
  if [[ "${SHOW_REPORT:-0}" == "1" ]]; then
    printf '%s\n' "${report_text}" >&2
  fi
  exit 1
fi

read -r -a total_fields <<< "${total_line}"
total_regions="${total_fields[1]}"
missed_regions="${total_fields[2]}"
region_coverage="${total_fields[3]}"
covered_regions=$((total_regions - missed_regions))

echo
echo "========== 覆盖率报告 =========="
echo "库目录: ${lib_dir}"
echo "输出目录: ${out_dir}"
if [[ "${all_fuzzers}" == "1" ]]; then
  echo "Queue 模式: 合并所有 fuzzer queue"
  echo "Queue 根目录: ${lib_dir}/${out_dir}"
else
  echo "Queue 模式: default queue"
  echo "Queue 目录: ${existing_queue_dirs[0]}"
fi
echo "目标二进制: ${target_bin}"
echo "profdata: ${profdata_path}"
echo "样本数量: ${executed}"
echo "超时样本: ${timeout_count}"
echo "信号终止: ${signal_count}"
echo "其他失败: ${failure_count}"
echo
echo "区域覆盖 (Regions):"
echo "  已覆盖: ${covered_regions}"
echo "  总区域: ${total_regions}"
echo "  覆盖率: ${region_coverage}"

if [[ "${#total_fields[@]}" -ge 13 ]]; then
  total_branches="${total_fields[10]}"
  missed_branches="${total_fields[11]}"
  branch_coverage="${total_fields[12]}"
  covered_branches=$((total_branches - missed_branches))
  echo
  echo "分支覆盖 (Branches):"
  echo "  已覆盖: ${covered_branches}"
  echo "  总分支: ${total_branches}"
  echo "  覆盖率: ${branch_coverage}"
fi

echo "================================"

if [[ "${timeout_count}" -gt 0 ]]; then
  echo "超时样本列表: ${timeout_log}"
fi

if [[ "${signal_count}" -gt 0 ]]; then
  echo "信号终止列表: ${signal_log}"
fi

if [[ "${failure_count}" -gt 0 ]]; then
  echo "其他失败列表: ${failure_log}"
fi

if [[ "${SHOW_REPORT:-0}" == "1" ]]; then
  echo
  echo "完整 llvm-cov report:"
  printf '%s\n' "${report_text}"
fi
