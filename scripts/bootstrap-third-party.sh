#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd -P)"
MANIFEST="${ROOT_DIR}/third_party/repos.tsv"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
GITHUB_USER="${GITHUB_USER:-LuxuriantHuang}"
PROTOCOL="${PROTOCOL:-ssh}"

DO_INIT=0
DO_PATCH=0
DO_BUILD=0
DO_STATUS=0
DO_SYNC_URLS=0

declare -a REQUESTED_COMPONENTS=()

usage() {
  cat <<'EOF'
Usage: scripts/bootstrap-third-party.sh [options]

Options:
  --init                 Initialize and update submodules
  --apply-patches        Apply tracked local patches when needed
  --build                Build selected third-party components
  --status               Print configured third-party repositories
  --sync-urls            Override submodule URLs in local git config for the chosen account/protocol
  --component NAME       Limit work to a component path or repo name; may be repeated
  --github-user USER     GitHub account that hosts the mirrored repositories
  --protocol MODE        ssh or https (default: ssh)
  --jobs N               Parallel build jobs
  -h, --help             Show this help

Examples:
  scripts/bootstrap-third-party.sh --init --sync-urls --apply-patches
  scripts/bootstrap-third-party.sh --build --component svf/third_party/SVF --component tracer
  GITHUB_USER=someone PROTOCOL=https scripts/bootstrap-third-party.sh --init --sync-urls
EOF
}

log() {
  printf '[third-party] %s\n' "$*"
}

die() {
  printf '[third-party] error: %s\n' "$*" >&2
  exit 1
}

have_component_filter() {
  [ "${#REQUESTED_COMPONENTS[@]}" -gt 0 ]
}

component_selected() {
  local path="$1"
  local repo_name="$2"
  if ! have_component_filter; then
    return 0
  fi

  local item
  for item in "${REQUESTED_COMPONENTS[@]}"; do
    if [ "${item}" = "${path}" ] || [ "${item}" = "${repo_name}" ]; then
      return 0
    fi
  done
  return 1
}

repo_url_for() {
  local repo_name="$1"
  case "${PROTOCOL}" in
    ssh)
      printf 'git@github.com:%s/%s.git\n' "${GITHUB_USER}" "${repo_name}"
      ;;
    https)
      printf 'https://github.com/%s/%s.git\n' "${GITHUB_USER}" "${repo_name}"
      ;;
    *)
      die "unsupported protocol: ${PROTOCOL}"
      ;;
  esac
}

ensure_manifest() {
  [ -f "${MANIFEST}" ] || die "manifest not found: ${MANIFEST}"
}

sync_submodule_urls() {
  ensure_manifest
  log "syncing submodule URLs for GitHub user ${GITHUB_USER} (${PROTOCOL})"

  local line path name repo_name _default_url _upstream patch_file _role override_url
  while IFS=$'\t' read -r path name repo_name _default_url _upstream patch_file _role; do
    [ "${path}" = "path" ] && continue
    if ! component_selected "${path}" "${repo_name}"; then
      continue
    fi
    override_url="$(repo_url_for "${repo_name}")"
    git -C "${ROOT_DIR}" config "submodule.${name}.url" "${override_url}"
    log "  ${path} -> ${override_url}"
  done < "${MANIFEST}"
}

init_submodules() {
  log "initializing submodules"
  if have_component_filter; then
    local line path name repo_name _default_url _upstream patch_file _role
    local -a paths=()
    while IFS=$'\t' read -r path name repo_name _default_url _upstream patch_file _role; do
      [ "${path}" = "path" ] && continue
      if component_selected "${path}" "${repo_name}"; then
        paths+=("${path}")
      fi
    done < "${MANIFEST}"
    [ "${#paths[@]}" -gt 0 ] || die "no matching components selected"
    git -C "${ROOT_DIR}" submodule update --init --recursive "${paths[@]}"
  else
    git -C "${ROOT_DIR}" submodule update --init --recursive
  fi
}

apply_patch_if_needed() {
  local path="$1"
  local patch_file="$2"
  [ -n "${patch_file}" ] || return 0

  if git -C "${ROOT_DIR}/${path}" apply --check "${ROOT_DIR}/${patch_file}" >/dev/null 2>&1; then
    log "applying ${patch_file} in ${path}"
    git -C "${ROOT_DIR}/${path}" apply "${ROOT_DIR}/${patch_file}"
    return 0
  fi

  if git -C "${ROOT_DIR}/${path}" apply --reverse --check "${ROOT_DIR}/${patch_file}" >/dev/null 2>&1; then
    log "patch already applied in ${path}: ${patch_file}"
    return 0
  fi

  die "cannot apply ${patch_file} in ${path}; repository may have diverged from the expected base"
}

apply_patches() {
  ensure_manifest
  local line path name repo_name _default_url _upstream patch_file _role
  while IFS=$'\t' read -r path name repo_name _default_url _upstream patch_file _role; do
    [ "${path}" = "path" ] && continue
    if ! component_selected "${path}" "${repo_name}"; then
      continue
    fi
    [ -d "${ROOT_DIR}/${path}" ] || die "missing component directory: ${path}"
    apply_patch_if_needed "${path}" "${patch_file}"
  done < "${MANIFEST}"
}

build_component() {
  local component="$1"
  case "${component}" in
    AFLplusplus)
      log "building AFLplusplus"
      make -C "${ROOT_DIR}/AFLplusplus" LLVM_CONFIG="${LLVM_CONFIG:-llvm-config-10}" -j"${JOBS}"
      ;;
    tracer)
      log "building tracer"
      make -C "${ROOT_DIR}/tracer" LLVM_CONFIG="${LLVM_CONFIG:-llvm-config-10}" -j"${JOBS}"
      ;;
    "svf/third_party/SVF")
      log "building upstream SVF"
      if [ -f "${ROOT_DIR}/svf/third_party/SVF/use_svf_llvm10.sh" ]; then
        bash -lc "source '${ROOT_DIR}/svf/third_party/SVF/use_svf_llvm10.sh' && cmake -S '${ROOT_DIR}/svf/third_party/SVF' -B '${ROOT_DIR}/svf/third_party/SVF/Release-build' -DCMAKE_BUILD_TYPE=Release && cmake --build '${ROOT_DIR}/svf/third_party/SVF/Release-build' -j'${JOBS}'"
      else
        cmake -S "${ROOT_DIR}/svf/third_party/SVF" \
          -B "${ROOT_DIR}/svf/third_party/SVF/Release-build" \
          -DCMAKE_BUILD_TYPE=Release
        cmake --build "${ROOT_DIR}/svf/third_party/SVF/Release-build" -j"${JOBS}"
      fi
      ;;
    svf-local)
      log "building local SVF consumers"
      cmake -S "${ROOT_DIR}/svf" -B "${ROOT_DIR}/svf/build"
      cmake --build "${ROOT_DIR}/svf/build" -j"${JOBS}"
      ;;
    AutoBug)
      log "building AutoBug"
      bash "${ROOT_DIR}/AutoBug/build.sh"
      ;;
    ipl-modeling)
      log "building ipl-modeling"
      bash "${ROOT_DIR}/ipl-modeling/build.sh"
      ;;
    *)
      die "unknown build component: ${component}"
      ;;
  esac
}

build_all() {
  local default_order=(
    AFLplusplus
    tracer
    "svf/third_party/SVF"
    svf-local
    AutoBug
    ipl-modeling
  )

  local component
  if have_component_filter; then
    for component in "${REQUESTED_COMPONENTS[@]}"; do
      case "${component}" in
        SVF)
          build_component "svf/third_party/SVF"
          ;;
        *)
          build_component "${component}"
          ;;
      esac
    done
    return 0
  fi

  for component in "${default_order[@]}"; do
    build_component "${component}"
  done
}

print_status() {
  ensure_manifest
  printf '%-24s %-24s %-45s %s\n' "PATH" "REPO" "EXPECTED URL" "PATCH"
  local line path name repo_name _default_url _upstream patch_file _role
  while IFS=$'\t' read -r path name repo_name _default_url _upstream patch_file _role; do
    [ "${path}" = "path" ] && continue
    if ! component_selected "${path}" "${repo_name}"; then
      continue
    fi
    printf '%-24s %-24s %-45s %s\n' \
      "${path}" \
      "${repo_name}" \
      "$(repo_url_for "${repo_name}")" \
      "${patch_file:--}"
  done < "${MANIFEST}"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --init)
      DO_INIT=1
      ;;
    --apply-patches)
      DO_PATCH=1
      ;;
    --build)
      DO_BUILD=1
      ;;
    --status)
      DO_STATUS=1
      ;;
    --sync-urls)
      DO_SYNC_URLS=1
      ;;
    --component)
      shift
      [ "$#" -gt 0 ] || die "--component requires a value"
      REQUESTED_COMPONENTS+=("$1")
      ;;
    --github-user)
      shift
      [ "$#" -gt 0 ] || die "--github-user requires a value"
      GITHUB_USER="$1"
      ;;
    --protocol)
      shift
      [ "$#" -gt 0 ] || die "--protocol requires a value"
      PROTOCOL="$1"
      ;;
    --jobs)
      shift
      [ "$#" -gt 0 ] || die "--jobs requires a value"
      JOBS="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
  shift
done

if [ "${DO_INIT}" -eq 0 ] && [ "${DO_PATCH}" -eq 0 ] && [ "${DO_BUILD}" -eq 0 ] && [ "${DO_STATUS}" -eq 0 ] && [ "${DO_SYNC_URLS}" -eq 0 ]; then
  usage
  exit 1
fi

if [ "${DO_STATUS}" -eq 1 ]; then
  print_status
fi
if [ "${DO_SYNC_URLS}" -eq 1 ]; then
  sync_submodule_urls
fi
if [ "${DO_INIT}" -eq 1 ]; then
  init_submodules
fi
if [ "${DO_PATCH}" -eq 1 ]; then
  apply_patches
fi
if [ "${DO_BUILD}" -eq 1 ]; then
  build_all
fi
