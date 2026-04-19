#!/usr/bin/env bash
#
# 统一的第三方依赖编译脚本
# 用于 Dockerfile 和本地开发环境
#
# 用法:
#   scripts/build-third-party.sh              # 构建所有组件
#   scripts/build-third-party.sh --component svf  # 只构建 SVF
#

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd -P)"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
LLVM_VERSION="${LLVM_VERSION:-10}"
LLVM_CONFIG="${LLVM_CONFIG:-llvm-config-${LLVM_VERSION}}"

# 颜色输出
log() {
    printf '\033[0;34m[third-party]\033[0m %s\n' "$*"
}
warn() {
    printf '\033[0;33m[third-party]\033[0m warning: %s\n' "$*" >&2
}
die() {
    printf '\033[0;31m[third-party]\033[0m error: %s\n' "$*" >&2
    exit 1
}

# 检查依赖
check_dependencies() {
    if ! command -v "$LLVM_CONFIG" >/dev/null 2>&1; then
        die "llvm-config-${LLVM_VERSION} not found in PATH"
    fi
    if ! command -v ninja >/dev/null 2>&1; then
        warn "ninja not found, some builds may be slow"
    fi
}

# 构建特定的 AFLplusplus 变体
build_aflplusplus() {
    log "Building AFLplusplus..."

    pushd "$ROOT_DIR/AFLplusplus" >/dev/null

    # 检查是否需要构建
    if [ -f "afl-fuzz" ] && [ -n "${SKIP_REBUILD:-}" ]; then
        log "AFLplusplus already built, skipping (set SKIP_REBUILD= to force)"
    else
        # 先清理
        make clean >/dev/null 2>&1 || true

        # AFL++ 使用 clang-14（如果有），其他组件用 clang-10
        local afl_llvm_config="llvm-config-14"
        if ! command -v llvm-config-14 >/dev/null 2>&1; then
            warn "llvm-config-14 not found, falling back to llvm-config-10"
            afl_llvm_config="$LLVM_CONFIG"
        fi

        # 构建，只构建 LLVM 模式（不需要 gcc_plugin）
        make LLVM_CONFIG="$afl_llvm_config" -j"$JOBS" \
            || die "AFLplusplus build failed"
    fi

    popd >/dev/null
}

# 构建 tracer
build_tracer() {
    log "Building tracer..."

    pushd "$ROOT_DIR/tracer" >/dev/null

    if [ -f "build/trace-id" ] && [ -n "${SKIP_REBUILD:-}" ]; then
        log "tracer already built, skipping"
    else
        make clean >/dev/null 2>&1 || true
        make LLVM_CONFIG="$LLVM_CONFIG" -j"$JOBS" \
            || die "tracer build failed"
    fi

    popd >/dev/null
}

# 构建 SVF
build_svf() {
    log "Building SVF..."

    # SVF 需要 libtinfo 和 libffi
    local linker_flags="-ltinfo -lffi"

    # 构建 SVF third_party
    pushd "$ROOT_DIR/svf/third_party/SVF" >/dev/null

    if [ -f "Release-build/bin/wpa" ] && [ -n "${SKIP_REBUILD:-}" ]; then
        log "SVF third_party already built, skipping"
    else
        rm -rf Release-build
        cmake -B Release-build \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_EXE_LINKER_FLAGS="$linker_flags"

        cmake --build Release-build -j"$JOBS" \
            || die "SVF third_party build failed"
    fi

    popd >/dev/null

    # 构建 svf (ir_graph_extractor 等)
    pushd "$ROOT_DIR/svf" >/dev/null

    if [ -f "build/ir_graph_extractor" ] && [ -n "${SKIP_REBUILD:-}" ]; then
        log "svf already built, skipping"
    else
        rm -rf build
        cmake -B build \
              -DCMAKE_BUILD_TYPE=Release \
              -DLLVM_DIR="$("$LLVM_CONFIG" --prefix)/lib/cmake/llvm" \
              -DCMAKE_EXE_LINKER_FLAGS="$linker_flags"

        cmake --build build -j"$JOBS" \
            || die "svf build failed"
    fi

    popd >/dev/null
}

# 构建 ipl-modeling
build_ipl_modeling() {
    log "Building ipl-modeling..."

    pushd "$ROOT_DIR/ipl-modeling" >/dev/null

    if [ -f "install/lib/libLLVMTrack.so" ] && [ -n "${SKIP_REBUILD:-}" ]; then
        log "ipl-modeling already built, skipping"
    else
        # 需要设置 CFLAGS 启用 GNU 扩展（fgets_unlocked 等）
        export PATH="/usr/lib/llvm-${LLVM_VERSION}/bin:$PATH"
        export CFLAGS="-D_GNU_SOURCE"

        bash build.sh \
            || die "ipl-modeling build failed"
    fi

    popd >/dev/null
}

# 构建 flag_var/flagrec
build_flagrec() {
    log "Building flagrec..."

    local linker_flags="-ltinfo -lffi"

    pushd "$ROOT_DIR/flag_var/flagrec" >/dev/null

    if [ -f "build/flagrec" ] && [ -n "${SKIP_REBUILD:-}" ]; then
        log "flagrec already built, skipping"
    else
        rm -rf build
        cmake -B build \
              -DCMAKE_BUILD_TYPE=Release \
              -DLLVM_DIR="$("$LLVM_CONFIG" --prefix)/lib/cmake/llvm" \
              -DBUILD_TESTS=ON \
              -DCMAKE_EXE_LINKER_FLAGS="$linker_flags"

        cmake --build build -j"$JOBS" \
            || die "flagrec build failed"
    fi

    popd >/dev/null
}

# 构建 AutoBug
build_autobug() {
    log "Building AutoBug..."

    if [ ! -f "$ROOT_DIR/AutoBug/build.sh" ]; then
        warn "AutoBug build.sh not found, skipping"
        return
    fi

    pushd "$ROOT_DIR/AutoBug" >/dev/null

    if [ -f "autobug/autobug" ] && [ -n "${SKIP_REBUILD:-}" ]; then
        log "AutoBug already built, skipping"
    else
        bash build.sh \
            || die "AutoBug build failed"
    fi

    popd >/dev/null
}

# 显示帮助
usage() {
    cat <<'EOF'
Usage: scripts/build-third-party.sh [options]

Options:
  --component NAME    Build only the specified component (afl, tracer, svf, ipl, flagrec, autobug, all)
  --skip-rebuild      Skip components that are already built
  --jobs N            Number of parallel jobs (default: $(nproc))
  --llvm-version N    LLVM version (default: 10)
  -h, --help          Show this help

Components:
  afl          AFLplusplus fuzzer
  tracer       Trace instrumentation
  svf          Static analysis framework
  ipl          IPL modeling runtime
  flagrec      Flag recognition tool
  autobug      Auto debugging tool
  all          Build all components (default)

Examples:
  scripts/build-third-party.sh
  scripts/build-third-party.sh --component svf
  scripts/build-third-party.sh --component afl --skip-rebuild
EOF
}

# 解析参数
declare -a REQUESTED_COMPONENTS=()
DO_SKIP_REBUILD=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --component)
            REQUESTED_COMPONENTS+=("$2")
            shift 2
            ;;
        --skip-rebuild)
            DO_SKIP_REBUILD=1
            shift
            ;;
        --jobs)
            JOBS="$2"
            shift 2
            ;;
        --llvm-version)
            LLVM_VERSION="$2"
            LLVM_CONFIG="llvm-config-${LLVM_VERSION}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1 (try --help)"
            ;;
    esac
done

if [ "$DO_SKIP_REBUILD" -eq 1 ]; then
    export SKIP_REBUILD=1
fi

# 默认构建所有
if [ ${#REQUESTED_COMPONENTS[@]} -eq 0 ]; then
    REQUESTED_COMPONENTS=(all)
fi

# 检查依赖
check_dependencies

# 构建请求的组件
for component in "${REQUESTED_COMPONENTS[@]}"; do
    case "$component" in
        all)
            build_aflplusplus
            build_tracer
            build_svf
            build_ipl_modeling
            build_flagrec
            build_autobug
            ;;
        afl|aflplusplus)
            build_aflplusplus
            ;;
        tracer)
            build_tracer
            ;;
        svf)
            build_svf
            ;;
        ipl|ipl-modeling)
            build_ipl_modeling
            ;;
        flagrec|flag_var)
            build_flagrec
            ;;
        autobug|AutoBug)
            build_autobug
            ;;
        *)
            die "Unknown component: $component"
            ;;
    esac
done

log "All requested components built successfully!"
