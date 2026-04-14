#!/usr/bin/env bash
set -euo pipefail

PROJECT="${1:?usage: build_single_dir.sh <project>}"
shift || true

BASE=/home/lab420/Desktop/autoframe
HOME_DIR="${BASE}/benchmarks/${PROJECT}"
SRC_DIR="${HOME_DIR}/src"
BUILD_ROOT="${HOME_DIR}/build"
JOBS="${JOBS:-4}"

install_binary() {
  local source_path="$1"
  local target_dir="$2"
  local output_name="$3"
  local target_path="${HOME_DIR}/target/${target_dir}/${output_name}"
  local staged_path="${target_path}.new"
  mkdir -p "${HOME_DIR}/target/${target_dir}"
  cp "${source_path}" "${staged_path}"
  mv -f "${staged_path}" "${target_path}"
}

run_trace_post() {
  local binary_name="$1"
  shift || true
  pushd "${HOME_DIR}/target/trace" >/dev/null
  get-bc "${binary_name}"
  "${BASE}/tracer/build/trace-id++" -g -O0 "${binary_name}.bc" -o "${binary_name}" \
    -mllvm --output-dir="${HOME_DIR}/static" "$@"
  popd >/dev/null
}

run_ipl_post() {
  local trace_name="$1"
  local ipl_name="$2"
  shift 2 || true
  pushd "${HOME_DIR}/target/ipl" >/dev/null
  cp "${HOME_DIR}/target/trace/${trace_name}.bc" "./${ipl_name}.bc"
  "${BASE}/ipl-modeling/install/test-clang++" "${ipl_name}.bc" -o "${ipl_name}" "$@"
  popd >/dev/null
}

run_svf_static() {
  local trace_name="$1"
  mkdir -p "${HOME_DIR}/static"
  bash "${BASE}/svf/scripts/extract_with_svf.sh" \
    "${HOME_DIR}/target/trace/${trace_name}.bc" \
    "${HOME_DIR}/static" \
    "${BASE}/svf/third_party/SVF/Release-build/bin/wpa"
}

clean_cmake_src() {
  rm -rf "${BUILD_ROOT}"
  rm -f "${SRC_DIR}/compile_commands.json"
  rm -f "${SRC_DIR}/fuzzing/afl-main" "${SRC_DIR}/target" "${SRC_DIR}/libcjson.a"
}

clean_autotools_src() {
  pushd "${SRC_DIR}" >/dev/null
  if [ -f Makefile ]; then
    make distclean >/dev/null 2>&1 || make clean >/dev/null 2>&1 || true
  fi
  popd >/dev/null
  find "${SRC_DIR}" -type d \( -name .deps -o -name .libs -o -name autom4te.cache \) -prune -exec rm -rf {} +
  find "${SRC_DIR}" -type f \( -name Makefile -o -name config.status -o -name config.log -o -name config.cache -o -name libtool -o -name compile_commands.json \) -delete
}

clean_make_src() {
  pushd "${SRC_DIR}" >/dev/null
  if [ -f Makefile ] || [ -f makefile ]; then
    make clean >/dev/null 2>&1 || true
  fi
  popd >/dev/null
  find "${SRC_DIR}" -type f \( -name '*.o' -o -name compile_commands.json \) -delete
}

prepare_targets() {
  mkdir -p "${HOME_DIR}/target/afl" "${HOME_DIR}/target/trace" "${HOME_DIR}/target/llvmcov" "${HOME_DIR}/target/ipl"
  case "${PROJECT}" in
    cjson|cflow|cxxfilt|jhead|lcms|libpng|xmllint|mujs|pdf2text|sqlite3)
      mkdir -p "${HOME_DIR}/target/cmplog"
      ;;
  esac
  case "${PROJECT}" in
    cjson|cflow|cxxfilt|mujs|xmllint|sqlite3)
    mkdir -p "${HOME_DIR}/target/autobug"
      ;;
  esac
}

build_cjson_variant() {
  local cc="$1" cflags="$2" outbin="$3" target_dir="$4" afl_cmplog="${5:-}"
  local build_dir="${BUILD_ROOT}/${target_dir}"
  rm -rf "${build_dir}"
  mkdir -p "${build_dir}"
  pushd "${HOME_DIR}" >/dev/null
  export CC="${cc}" CFLAGS="${cflags}" AFL_CC=clang-18 AFL_CXX=clang++-18 LLVM_COMPILER=clang
  if [ "${afl_cmplog}" = "1" ]; then export AFL_LLVM_CMPLOG=1; fi
  cmake -S "${SRC_DIR}" -B "${build_dir}" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_C_COMPILER="${CC}" \
    -DENABLE_FUZZING=On \
    -DENABLE_SANITIZERS=On \
    -DENABLE_CUSTOM_COMPILER_FLAGS=Off \
    -DBUILD_SHARED_LIBS=Off \
    -DCMAKE_C_FLAGS="${CFLAGS}"
  cmake --build "${build_dir}" -j"${JOBS}" --target afl-main
  install_binary "${build_dir}/fuzzing/afl-main" "${target_dir}" "${outbin}"
  unset AFL_LLVM_CMPLOG || true
  popd >/dev/null
}

build_cjson_bear() {
  local build_dir="${BUILD_ROOT}/bear"
  rm -rf "${build_dir}"
  mkdir -p "${build_dir}"
  pushd "${HOME_DIR}" >/dev/null
  export CC=clang CFLAGS="-g -O0"
  rm -f "${SRC_DIR}/compile_commands.json"
  cmake -S "${SRC_DIR}" -B "${build_dir}" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_C_COMPILER="${CC}" \
    -DENABLE_FUZZING=On \
    -DENABLE_SANITIZERS=On \
    -DENABLE_CUSTOM_COMPILER_FLAGS=Off \
    -DBUILD_SHARED_LIBS=Off \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=On \
    -DCMAKE_C_FLAGS="${CFLAGS}"
  bear --cdb "${build_dir}/compile_commands.json" --append cmake --build "${build_dir}" -j"${JOBS}" --target afl-main
  cp "${build_dir}/compile_commands.json" "${SRC_DIR}/compile_commands.json"
  python "${BASE}/batch_process.py" "${PROJECT}"
  popd >/dev/null
}

build_cflow_variant() {
  local cc="$1" cxx="$2" cflags="$3" cxxflags="$4" outbin="$5" target_dir="$6" configure_opts="${7:-}" afl_cmplog="${8:-}"
  clean_autotools_src
  pushd "${SRC_DIR}" >/dev/null
  export CC="${cc}" CXX="${cxx}" CFLAGS="${cflags}" CXXFLAGS="${cxxflags}" AFL_CC=clang-18 AFL_CXX=clang++-18
  if [ "${afl_cmplog}" = "1" ]; then export AFL_LLVM_CMPLOG=1; fi
  autoreconf -fi
  ./configure --enable-debug ${configure_opts}
  make -j"${JOBS}"
  install_binary "${SRC_DIR}/src/cflow" "${target_dir}" "${outbin}"
  unset AFL_LLVM_CMPLOG || true
  popd >/dev/null
}

build_cflow_bear() {
  clean_autotools_src
  pushd "${SRC_DIR}" >/dev/null
  export CC=clang CXX=clang++ CFLAGS="-g -O0" CXXFLAGS="-g -O0" BEAR_DB="${SRC_DIR}/compile_commands.json"
  autoreconf -fi
  ./configure --enable-debug
  bear make -j"${JOBS}"
  popd >/dev/null
}

build_cxxfilt_variant() {
  local cc="$1" cxx="$2" cflags="$3" cxxflags="$4" outbin="$5" target_dir="$6" afl_cmplog="${7:-0}"
  local build_cflags="${cflags} -no-pie"
  local support_src="${HOME_DIR}/cxxfilt_support.c"
  clean_autotools_src
  pushd "${SRC_DIR}" >/dev/null
  export CC="${cc}" CXX="${cxx}" CFLAGS="${cflags}" CXXFLAGS="${cxxflags}" AFL_CC=clang-18 AFL_CXX=clang++-18
  if [ "${afl_cmplog}" = "1" ]; then export AFL_LLVM_CMPLOG=1; fi
  LDFLAGS="-no-pie" ./configure --disable-shared --disable-gdb
  make configure-bfd
  make -C bfd bfdver.h bfd.h
  "${cc}" ${build_cflags} -DHAVE_CONFIG_H \
    -DTARGET_PREPENDS_UNDERSCORE=0 \
    -include ./bfd/bfdver.h \
    -I. -I./include -I./binutils -I./libiberty -I./bfd \
    binutils/cxxfilt.c \
    libiberty/cplus-dem.c \
    libiberty/cp-demangle.c \
    libiberty/d-demangle.c \
    libiberty/rust-demangle.c \
    libiberty/argv.c \
    libiberty/getopt.c \
    libiberty/getopt1.c \
    libiberty/xexit.c \
    libiberty/xmalloc.c \
    libiberty/xstrdup.c \
    libiberty/safe-ctype.c \
    "${support_src}" \
    -o "${outbin}"
  install_binary "${SRC_DIR}/${outbin}" "${target_dir}" "${outbin}"
  unset AFL_LLVM_CMPLOG || true
  popd >/dev/null
}

build_jhead_variant() {
  local cc="$1" cflags="$2" outbin="$3" target_dir="$4" afl_cmplog="${5:-0}"
  clean_make_src
  pushd "${SRC_DIR}" >/dev/null
  export CC="${cc}" CFLAGS="${cflags}" AFL_CC=clang-18 AFL_CXX=clang++-18
  if [ "${afl_cmplog}" = "1" ]; then export AFL_LLVM_CMPLOG=1; fi
  make -j"${JOBS}"
  install_binary "${SRC_DIR}/jhead" "${target_dir}" "${outbin}"
  unset AFL_LLVM_CMPLOG || true
  popd >/dev/null
}

build_jhead_bear() {
  clean_make_src
  pushd "${SRC_DIR}" >/dev/null
  export CC=clang CFLAGS="-g -O0" BEAR_DB="${SRC_DIR}/compile_commands.json"
  bear make -j"${JOBS}"
  python "${BASE}/batch_process.py" "${PROJECT}"
  popd >/dev/null
}

build_lcms_variant() {
  local cc="$1" cxx="$2" cflags="$3" cxxflags="$4" outbin="$5" target_dir="$6" extra_link_flags="${7:-}" afl_cmplog="${8:-}"
  clean_autotools_src
  pushd "${SRC_DIR}" >/dev/null
  export CC="${cc}" CXX="${cxx}" CFLAGS="${cflags}" CXXFLAGS="${cxxflags}" AFL_CC=clang-18 AFL_CXX=clang++-18
  if [ "${afl_cmplog}" = "1" ]; then export AFL_LLVM_CMPLOG=1; fi
  ./autogen.sh
  ./configure --disable-shared
  make -j"${JOBS}"
  "${CC}" ${CFLAGS} -c -w driver.c
  "${CXX}" ${CXXFLAGS} ${extra_link_flags} target.cc driver.o -I include/ src/.libs/liblcms2.a -o "${outbin}"
  install_binary "${SRC_DIR}/${outbin}" "${target_dir}" "${outbin}"
  unset AFL_LLVM_CMPLOG || true
  popd >/dev/null
}

build_lcms_bear() {
  clean_autotools_src
  pushd "${SRC_DIR}" >/dev/null
  export CC=clang CXX=clang++ CFLAGS="-g -O0" CXXFLAGS="-g -O0" BEAR_DB="${SRC_DIR}/compile_commands.json"
  ./autogen.sh
  ./configure --disable-shared
  bear make -j"${JOBS}"
  bear --append "${CC}" ${CFLAGS} -c -w driver.c
  bear --append "${CXX}" ${CXXFLAGS} target.cc driver.o -I include/ src/.libs/liblcms2.a -o target
  popd >/dev/null
}

build_libpng_variant() {
  local cc="$1" cxx="$2" cflags="$3" cxxflags="$4" outbin="$5" target_dir="$6" extra_link_flags="${7:-}" afl_cmplog="${8:-}"
  clean_autotools_src
  pushd "${SRC_DIR}" >/dev/null
  export CC="${cc}" CXX="${cxx}" CFLAGS="${cflags}" CXXFLAGS="${cxxflags}" AFL_CC=clang-18 AFL_CXX=clang++-18
  if [ "${afl_cmplog}" = "1" ]; then export AFL_LLVM_CMPLOG=1; fi
  ./configure --disable-shared
  make -j"${JOBS}"
  "${CC}" ${CFLAGS} -c -w driver.c
  "${CXX}" ${CXXFLAGS} ${extra_link_flags} target.cc driver.o .libs/libpng12.a -I . -lz -o "${outbin}"
  install_binary "${SRC_DIR}/${outbin}" "${target_dir}" "${outbin}"
  unset AFL_LLVM_CMPLOG || true
  popd >/dev/null
}

build_libpng_bear() {
  clean_autotools_src
  pushd "${SRC_DIR}" >/dev/null
  export CC=clang CXX=clang++ CFLAGS="-g -O0" CXXFLAGS="-g -O0" BEAR_DB="${SRC_DIR}/compile_commands.json"
  ./configure --disable-shared
  bear make -j"${JOBS}"
  bear --append "${CC}" ${CFLAGS} -c -w driver.c
  bear --append "${CXX}" ${CXXFLAGS} -std=c++11 target.cc driver.o .libs/libpng12.a -I . -lz -o target
  popd >/dev/null
}

build_xmllint_variant() {
  local cc="$1" cxx="$2" cflags="$3" cxxflags="$4" outbin="$5" target_dir="$6" _extra_link_flags="${7:-}" afl_cmplog="${8:-0}"
  clean_autotools_src
  pushd "${SRC_DIR}" >/dev/null
  export CC="${cc}" CXX="${cxx}" CFLAGS="${cflags}" CXXFLAGS="${cxxflags}" AFL_CC=clang-18 AFL_CXX=clang++-18
  if [ "${afl_cmplog}" = "1" ]; then export AFL_LLVM_CMPLOG=1; fi
  sh ./autogen.sh
  CCLD="${CXX} ${CXXFLAGS}" CC="${CC}" CFLAGS="${CFLAGS}" ./configure --disable-shared
  make -j"${JOBS}" xmllint
  install_binary "${SRC_DIR}/xmllint" "${target_dir}" "${outbin}"
  unset AFL_LLVM_CMPLOG || true
  popd >/dev/null
}

build_xmllint_bear() {
  clean_autotools_src
  pushd "${SRC_DIR}" >/dev/null
  export CC=clang CXX=clang++ CFLAGS="-g -O0" CXXFLAGS="-g -O0" BEAR_DB="${SRC_DIR}/compile_commands.json"
  sh ./autogen.sh
  CCLD="${CXX} ${CXXFLAGS}" ./configure --disable-shared
  bear make -j"${JOBS}" xmllint
  python "${BASE}/batch_process.py" "${PROJECT}"
  popd >/dev/null
}

build_mujs_variant() {
  local cc="$1" _cxx="$2" cflags="$3" _cxxflags="$4" outbin="$5" target_dir="$6" _extra="${7:-}" afl_cmplog="${8:-}"
  clean_make_src
  pushd "${SRC_DIR}" >/dev/null
  export CC="${cc}" CFLAGS="${cflags}" AFL_CC=clang-18 AFL_CXX=clang++-18
  if [ "${afl_cmplog}" = "1" ]; then export AFL_LLVM_CMPLOG=1; fi
  "${CC}" ${CFLAGS} -o "${outbin}" one.c main.c -lm
  install_binary "${SRC_DIR}/${outbin}" "${target_dir}" "${outbin}"
  unset AFL_LLVM_CMPLOG || true
  popd >/dev/null
}

build_mujs_bear() {
  clean_make_src
  pushd "${SRC_DIR}" >/dev/null
  export CC=clang CFLAGS="-g -O0" BEAR_DB="${SRC_DIR}/compile_commands.json"
  bear "${CC}" ${CFLAGS} -o tmp one.c main.c -lm
  python "${BASE}/batch_process.py" "${PROJECT}"
  popd >/dev/null
}

build_pcre2_variant() {
  local cc="$1" cxx="$2" cflags="$3" cxxflags="$4" outbin="$5" target_dir="$6"
  clean_autotools_src
  pushd "${SRC_DIR}" >/dev/null
  export CC="${cc}" CXX="${cxx}" CFLAGS="${cflags}" CXXFLAGS="${cxxflags}"
  ./autogen.sh
  ./configure --enable-fuzz-support --enable-never-backslash-C --with-match-limit=1000000 --with-match-limit-depth=1000000 --enable-jit
  make -j"${JOBS}" clean
  make -j"${JOBS}" all
  "${CC}" ${CFLAGS} -c -w driver.c
  "${CXX}" ${CXXFLAGS} -o "${outbin}" driver.o .libs/libpcre2-fuzzsupport.a .libs/libpcre2-8.a
  install_binary "${SRC_DIR}/${outbin}" "${target_dir}" "${outbin}"
  popd >/dev/null
}

build_pcre2_bear() {
  clean_autotools_src
  pushd "${SRC_DIR}" >/dev/null
  export CC=clang CXX=clang++ CFLAGS="-g -O0" CXXFLAGS="-g -O0" BEAR_DB="${SRC_DIR}/compile_commands.json"
  ./autogen.sh
  ./configure --enable-fuzz-support --enable-never-backslash-C --with-match-limit=1000000 --with-match-limit-depth=1000000 --enable-jit
  bear make -j"${JOBS}"
  bear --append "${CC}" ${CFLAGS} -c -w driver.c
  bear --append "${CXX}" ${CXXFLAGS} -o pcre2_fuzzer driver.o .libs/libpcre2-fuzzsupport.a .libs/libpcre2-8.a
  popd >/dev/null
}

build_pdf2text_variant() {
  local cc="$1" cxx="$2" cflags="$3" cxxflags="$4" outbin="$5" target_dir="$6" afl_cmplog="${7:-0}"
  local build_dir="${BUILD_ROOT}/${target_dir}"
  rm -rf "${build_dir}"
  mkdir -p "${build_dir}"
  pushd "${HOME_DIR}" >/dev/null
  if [ "${afl_cmplog}" = "1" ]; then export AFL_LLVM_CMPLOG=1; fi
  cmake -S "${SRC_DIR}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="${cc}" \
    -DCMAKE_CXX_COMPILER="${cxx}" \
    -DCMAKE_C_FLAGS="${cflags}" \
    -DCMAKE_CXX_FLAGS="${cxxflags}" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5
  cmake --build "${build_dir}" -j"${JOBS}"
  install_binary "${build_dir}/xpdf/pdftotext" "${target_dir}" "${outbin}"
  unset AFL_LLVM_CMPLOG || true
  popd >/dev/null
}

build_pdf2text_bear() {
  local build_dir="${BUILD_ROOT}/bear"
  rm -rf "${build_dir}"
  mkdir -p "${build_dir}"
  pushd "${HOME_DIR}" >/dev/null
  export CC=clang CXX=clang++ CFLAGS="-g -O0" CXXFLAGS="-g -O0"
  rm -f "${SRC_DIR}/compile_commands.json"
  cmake -S "${SRC_DIR}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_CXX_COMPILER="${CXX}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5
  bear --cdb "${build_dir}/compile_commands.json" --append cmake --build "${build_dir}" -j"${JOBS}"
  cp "${build_dir}/compile_commands.json" "${SRC_DIR}/compile_commands.json"
  popd >/dev/null
}

build_proj4_variant() {
  local cc="$1" cxx="$2" cflags="$3" cxxflags="$4" outbin="$5" target_dir="$6"
  clean_autotools_src
  pushd "${SRC_DIR}" >/dev/null
  export CC="${cc}" CXX="${cxx}" CFLAGS="${cflags}" CXXFLAGS="${cxxflags}"
  ./autogen.sh
  ./configure --disable-shared
  make -j"${JOBS}"
  "${CC}" ${CFLAGS} -c -w driver.c
  "${CXX}" ${CXXFLAGS} -std=c++11 standard_fuzzer.cpp driver.o -I src src/.libs/libproj.a -lpthread -o "${outbin}"
  install_binary "${SRC_DIR}/${outbin}" "${target_dir}" "${outbin}"
  popd >/dev/null
}

build_transform_variant() {
  local cc="$1" _cxx="$2" cflags="$3" _cxxflags="$4" outbin="$5" target_dir="$6"
  clean_make_src
  pushd "${SRC_DIR}" >/dev/null
  "${cc}" ${cflags} test-transform.c -o "${outbin}"
  install_binary "${SRC_DIR}/${outbin}" "${target_dir}" "${outbin}"
  popd >/dev/null
}

build_sqlite3_variant() {
  local cc="$1" cxx="$2" cflags="$3" outbin="$4" target_dir="$5" afl_cmplog="${6:-0}"
  local sqlite_limits="-DSQLITE_MAX_LENGTH=128000000 \
 -DSQLITE_MAX_SQL_LENGTH=128000000 \
 -DSQLITE_MAX_MEMORY=25000000 \
 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
 -DSQLITE_DEBUG=1 \
 -DSQLITE_MAX_PAGE_COUNT=16384"
  local sqlite_core_src="sqlite3-all.c"
  clean_make_src
  pushd "${SRC_DIR}" >/dev/null
  export CC="${cc}" CXX="${cxx}" CFLAGS="${cflags} ${sqlite_limits}" CXXFLAGS="${cflags}" AFL_CC=clang-18 AFL_CXX=clang++-18
  if [ "${afl_cmplog}" = "1" ]; then export AFL_LLVM_CMPLOG=1; fi
  if [ ! -f "${sqlite_core_src}" ]; then
    sqlite_core_src="sqlite3.c"
  fi
  "${CC}" ${CFLAGS} -c ossfuzz.c
  "${CC}" ${CFLAGS} -c -w driver.c
  "${CC}" ${CFLAGS} -c -w "${sqlite_core_src}"
  "${CXX}" ${CXXFLAGS} \
    "$(basename "${sqlite_core_src}" .c).o" ossfuzz.o driver.o \
    -ldl -pthread \
    -o "${outbin}"
  install_binary "${SRC_DIR}/${outbin}" "${target_dir}" "${outbin}"
  unset AFL_LLVM_CMPLOG || true
  popd >/dev/null
}

run_sqlite3_ipl_post() {
  local trace_name="$1"
  local ipl_name="$2"
  shift 2 || true
  pushd "${HOME_DIR}/target/ipl" >/dev/null
  cp "${HOME_DIR}/target/trace/${trace_name}.bc" "./${ipl_name}.bc"
  USE_ZLIB=1 "${BASE}/ipl-modeling/install/test-clang++" "${ipl_name}.bc" -o "${ipl_name}" "$@"
  popd >/dev/null
}

ensure_autobug_built() {
  local autobug_dir="${BASE}/AutoBug"
  if [ -x "${autobug_dir}/AutoTrace" ] && [ -x "${autobug_dir}/autobug" ] && [ -x "${autobug_dir}/e9tool" ]; then
    return
  fi
  pushd "${autobug_dir}" >/dev/null
  bash ./build.sh
  popd >/dev/null
}

instrument_with_autobug() {
  local binary_path="$1"
  local autobug_dir="${BASE}/AutoBug"
  local subject_name
  subject_name="$(basename "${binary_path}")"
  ensure_autobug_built
  pushd "${autobug_dir}" >/dev/null
  rm -f "${subject_name}.autotrace"
  ./AutoTrace instrument "${binary_path}"
  cp "${subject_name}.autotrace" "${HOME_DIR}/target/autobug/${subject_name}.autotrace"
  popd >/dev/null
}

build_cjson_autobug() {
  local build_dir="${BUILD_ROOT}/autobug"
  rm -rf "${build_dir}"
  mkdir -p "${build_dir}"
  pushd "${HOME_DIR}" >/dev/null
  export CC=clang CFLAGS="-O0 -g" AFL_CC=clang-18 AFL_CXX=clang++-18 LLVM_COMPILER=clang
  cmake -S "${SRC_DIR}" -B "${build_dir}" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_C_COMPILER="${CC}" \
    -DENABLE_FUZZING=On \
    -DENABLE_SANITIZERS=On \
    -DENABLE_CUSTOM_COMPILER_FLAGS=Off \
    -DBUILD_SHARED_LIBS=Off \
    -DCMAKE_C_FLAGS="${CFLAGS}"
  cmake --build "${build_dir}" -j"${JOBS}" --target afl-main
  install_binary "${build_dir}/fuzzing/afl-main" "autobug" "cjson_ori"
  instrument_with_autobug "${build_dir}/fuzzing/afl-main"
  popd >/dev/null
}

build_cflow_autobug() {
  clean_autotools_src
  pushd "${SRC_DIR}" >/dev/null
  export CC=gcc CXX=g++ CFLAGS="-O0 -g" CXXFLAGS="-O0 -g" AFL_CC=clang-18 AFL_CXX=clang++-18
  autoreconf -fi
  ./configure --enable-debug
  make -j"${JOBS}"
  install_binary "${SRC_DIR}/src/cflow" "autobug" "cflow_ori"
  instrument_with_autobug "${SRC_DIR}/src/cflow"
  popd >/dev/null
}

build_cxxfilt_autobug() {
  build_cxxfilt_variant gcc g++ "-O0 -g" "-O0 -g" cxxfilt autobug
  pushd "${HOME_DIR}/target/autobug" >/dev/null
  cp cxxfilt cxxfilt_ori
  popd >/dev/null
  instrument_with_autobug "${SRC_DIR}/cxxfilt"
}

build_xmllint_autobug() {
  build_xmllint_variant gcc g++ "-O0 -g" "-O0 -g" xmllint autobug
  pushd "${HOME_DIR}/target/autobug" >/dev/null
  cp xmllint xmllint_ori
  popd >/dev/null
  instrument_with_autobug "${SRC_DIR}/xmllint"
}

build_mujs_autobug() {
  build_mujs_variant gcc g++ "-O0 -g" "-O0 -g" mujs autobug
  pushd "${HOME_DIR}/target/autobug" >/dev/null
  cp mujs mujs_ori
  popd >/dev/null
  instrument_with_autobug "${SRC_DIR}/mujs"
}

build_sqlite3_autobug() {
  local sqlite_limits="-DSQLITE_MAX_LENGTH=128000000 \
 -DSQLITE_MAX_SQL_LENGTH=128000000 \
 -DSQLITE_MAX_MEMORY=25000000 \
 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
 -DSQLITE_DEBUG=1 \
 -DSQLITE_MAX_PAGE_COUNT=16384"
  local sqlite_core_src="sqlite3-all.c"
  clean_make_src
  pushd "${SRC_DIR}" >/dev/null
  export CC=gcc CXX=g++ CFLAGS="-O0 -g ${sqlite_limits}" CXXFLAGS="-O0 -g"
  if [ ! -f "${sqlite_core_src}" ]; then
    sqlite_core_src="sqlite3.c"
  fi
  "${CC}" ${CFLAGS} -c ossfuzz.c
  "${CC}" ${CFLAGS} -c -w driver.c
  "${CC}" ${CFLAGS} -c -w "${sqlite_core_src}"
  "${CXX}" ${CXXFLAGS} \
    "$(basename "${sqlite_core_src}" .c).o" ossfuzz.o driver.o \
    -ldl -pthread \
    -o "sqlite3_ori"
  install_binary "${SRC_DIR}/sqlite3_ori" "autobug" "sqlite3_ori"
  popd >/dev/null

  instrument_with_autobug "${SRC_DIR}/sqlite3_ori"
}

main() {
  prepare_targets
  case "${PROJECT}" in
    cjson)
      build_cjson_variant afl-clang-fast "-g -O0" cjson_fuzz afl
      build_cjson_variant afl-clang-fast "-g -O0" cjson_cmplog cmplog 1
      build_cjson_variant gclang "-g -O0" cjson_trace trace
      run_trace_post cjson_trace
      build_cjson_variant clang-14 "-fprofile-instr-generate -fcoverage-mapping -g -O0" target llvmcov
      run_ipl_post cjson_trace cjson_ipl
      run_svf_static cjson_trace
      build_cjson_autobug
      build_cjson_bear
      clean_cmake_src
      ;;
    cflow)
      build_cflow_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" cflow_fuzz afl
      build_cflow_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" cflow_cmplog cmplog "" 1
      build_cflow_variant gclang gclang++ "-g -O0" "-g -O0" cflow_trace trace
      run_trace_post cflow_trace
      build_cflow_variant clang-14 clang++-14 "-fprofile-instr-generate -fcoverage-mapping -g -O0" "-fprofile-instr-generate -fcoverage-mapping -g -O0" target llvmcov
      run_ipl_post cflow_trace cflow_ipl
      run_svf_static cflow_trace
      build_cflow_autobug
      build_cflow_bear
      clean_autotools_src
      ;;
    cxxfilt)
      build_cxxfilt_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" cxxfilt_fuzz afl
      build_cxxfilt_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" cxxfilt_cmplog cmplog 1
      build_cxxfilt_variant gclang gclang++ "-g -O0" "-g -O0" cxxfilt_trace trace
      run_trace_post cxxfilt_trace
      build_cxxfilt_variant clang-14 clang++-14 "-fprofile-instr-generate -fcoverage-mapping -g -O0" "-fprofile-instr-generate -fcoverage-mapping -g -O0" target llvmcov
      run_ipl_post cxxfilt_trace cxxfilt_ipl
      run_svf_static cxxfilt_trace
      build_cxxfilt_autobug
      clean_autotools_src
      ;;
    jhead)
      build_jhead_variant afl-clang-fast "-g -O0" jhead_fuzz afl
      build_jhead_variant afl-clang-fast "-O2 -fno-omit-frame-pointer" jhead_cmplog cmplog 1
      build_jhead_variant gclang "-g -O0" jhead_trace trace
      run_trace_post jhead_trace
      build_jhead_variant clang-14 "-fprofile-instr-generate -fcoverage-mapping -g -O0" target llvmcov
      run_ipl_post jhead_trace jhead_ipl
      run_svf_static jhead_trace
      build_jhead_bear
      clean_make_src
      ;;
    lcms)
      build_lcms_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" lcms_fuzz afl "-std=c++11"
      build_lcms_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" lcms_cmplog cmplog "-std=c++11" 1
      build_lcms_variant gclang gclang++ "-g -O0" "-g -O0" lcms_trace trace
      run_trace_post lcms_trace
      build_lcms_variant clang-14 clang++-14 "-fprofile-instr-generate -fcoverage-mapping -g -O0" "-fprofile-instr-generate -fcoverage-mapping -g -O0" target llvmcov "-std=c++11"
      run_ipl_post lcms_trace lcms_ipl
      run_svf_static lcms_trace
      build_lcms_bear
      clean_autotools_src
      ;;
    libpng)
      build_libpng_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" libpng_fuzz afl "-std=c++11"
      build_libpng_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" libpng_cmplog cmplog "-std=c++11" 1
      build_libpng_variant gclang gclang++ "-g -O0" "-g -O0" libpng_trace trace
      run_trace_post libpng_trace -lz
      build_libpng_variant clang-14 clang++-14 "-fprofile-instr-generate -fcoverage-mapping -g -O0" "-fprofile-instr-generate -fcoverage-mapping -g -O0" target llvmcov "-std=c++11"
      run_ipl_post libpng_trace libpng_ipl
      run_svf_static libpng_trace
      build_libpng_bear
      clean_autotools_src
      ;;
    xmllint)
      build_xmllint_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" xmllint_fuzz afl "-std=c++11" 0
      build_xmllint_variant afl-clang-fast afl-clang-fast++ "-O0 -g" "-O0 -g" xmllint_cmplog cmplog "-std=c++11" 1
      build_xmllint_variant gclang gclang++ "-g -O0" "-g -O0" xmllint_trace trace
      run_trace_post xmllint_trace -lz
      build_xmllint_variant clang-14 clang++-14 "-fprofile-instr-generate -fcoverage-mapping -g -O0" "-fprofile-instr-generate -fcoverage-mapping -g -O0" target llvmcov "-std=c++11" 0
      run_ipl_post xmllint_trace xmllint_ipl
      build_xmllint_bear
      run_svf_static xmllint_trace
      build_xmllint_autobug
      clean_autotools_src
      ;;
    mujs)
      build_mujs_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" mujs_fuzz afl "-std=c++11"
      build_mujs_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" mujs_cmplog cmplog "-std=c++11" 1
      build_mujs_variant gclang gclang++ "-g -O0" "-g -O0" mujs_trace trace
      run_trace_post mujs_trace -lm
      build_mujs_variant clang-14 clang++-14 "-fprofile-instr-generate -fcoverage-mapping -g -O0" "-fprofile-instr-generate -fcoverage-mapping -g -O0" target llvmcov "-std=c++11"
      run_ipl_post mujs_trace mujs_ipl -lm
      run_svf_static mujs_trace
      build_mujs_autobug
      build_mujs_bear
      clean_make_src
      ;;
    pcre2)
      build_pcre2_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" pcre2_fuzz afl
      build_pcre2_variant gclang gclang++ "-g -O0" "-g -O0" pcre2_trace trace
      run_trace_post pcre2_trace
      build_pcre2_variant clang-14 clang++-14 "-fprofile-instr-generate -fcoverage-mapping -g -O0" "-fprofile-instr-generate -fcoverage-mapping -g -O0" target llvmcov
      run_ipl_post pcre2_trace pcre2_ipl
      run_svf_static pcre2_trace
      build_pcre2_bear
      clean_autotools_src
      ;;
    pdf2text)
      build_pdf2text_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" pdf2text_fuzz afl
      build_pdf2text_variant afl-clang-fast afl-clang-fast++ "-O2 -fno-omit-frame-pointer" "-O2 -fno-omit-frame-pointer" pdf2text_cmplog cmplog 1
      build_pdf2text_variant gclang gclang++ "-g -O0" "-g -O0" pdf2text_trace trace
      run_trace_post pdf2text_trace
      build_pdf2text_variant clang-14 clang++-14 "-fprofile-instr-generate -fcoverage-mapping -g -O0" "-fprofile-instr-generate -fcoverage-mapping -g -O0" target llvmcov
      run_ipl_post pdf2text_trace pdf2text_ipl
      run_svf_static pdf2text_trace
      build_pdf2text_bear
      clean_cmake_src
      ;;
    proj4)
      build_proj4_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" proj4_fuzz afl
      build_proj4_variant gclang gclang++ "-g -O0" "-g -O0" proj4_trace trace
      run_trace_post proj4_trace -lpthread
      build_proj4_variant clang-14 clang++-14 "-fprofile-instr-generate -fcoverage-mapping -g -O0" "-fprofile-instr-generate -fcoverage-mapping -g -O0" target llvmcov
      run_svf_static proj4_trace
      clean_autotools_src
      ;;
    transform)
      build_transform_variant afl-clang-fast afl-clang-fast++ "-g -O0" "-g -O0" transform_fuzz afl
      build_transform_variant gclang gclang++ "-g -O0" "-g -O0" transform_trace trace
      run_trace_post transform_trace
      build_transform_variant clang-14 clang++-14 "-fprofile-instr-generate -fcoverage-mapping -g -O0" "-fprofile-instr-generate -fcoverage-mapping -g -O0" target llvmcov
      run_svf_static transform_trace
      clean_make_src
      ;;
    sqlite3)
      build_sqlite3_variant afl-clang-fast afl-clang-fast++ "-g -O0" sqlite3_fuzz afl
      build_sqlite3_variant afl-clang-fast afl-clang-fast++ "-g -O0" sqlite3_cmplog cmplog 1
      build_sqlite3_variant gclang gclang++ "-g -O0" sqlite3_trace trace
      run_trace_post sqlite3_trace -ldl -pthread
      build_sqlite3_variant clang-14 clang++-14 "-fprofile-instr-generate -fcoverage-mapping -g -O0" target llvmcov
      run_sqlite3_ipl_post sqlite3_trace sqlite3_ipl -ldl -pthread
      run_svf_static sqlite3_trace
      build_sqlite3_autobug
      clean_make_src
      ;;
    *)
      echo "unsupported project: ${PROJECT}" >&2
      exit 1
      ;;
  esac
}

main "$@"
