#!/bin/bash
# Copyright 2017 Google Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");

# Don't allow to call these scripts from their directories.
[ -e $(basename $0) ] && echo "PLEASE USE THIS SCRIPT FROM ANOTHER DIR" && exit 1

# Ensure that fuzzing engine, if defined, is valid
# FUZZING_ENGINE=${FUZZING_ENGINE:-"afl"}
POSSIBLE_FUZZING_ENGINE="libfuzzer afl honggfuzz coverage fsanitize_fuzzer hooks aflpp trace taint symsan taintfuzzer symcc"
!(echo "$POSSIBLE_FUZZING_ENGINE" | grep -w "$FUZZING_ENGINE" > /dev/null) && \
  echo "USAGE: Error: If defined, FUZZING_ENGINE should be one of the following:
  $POSSIBLE_FUZZING_ENGINE. However, it was defined as $FUZZING_ENGINE" && exit 1

SCRIPT_DIR=$(dirname $0)
# EXECUTABLE_NAME_BASE=$(basename $SCRIPT_DIR)-${FUZZING_ENGINE}
EXECUTABLE_NAME_BASE=${FUZZING_ENGINE}-test
LIBFUZZER_SRC=${LIBFUZZER_SRC:-/home/lab420/Desktop/fuzzer-test-suite/Fuzzer}
STANDALONE_TARGET=0
AFL_SRC=${AFL_SRC:-/home/lab420/Desktop/AFL}
TRACE_SRC=/root/Tracer
HONGGFUZZ_SRC=${HONGGFUZZ_SRC:-$(dirname $(dirname $SCRIPT_DIR))/honggfuzz}
COVERAGE_FLAGS="-O0 -fsanitize-coverage=trace-pc-guard"
# FUZZ_CXXFLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -fsanitize=address -fsanitize-address-use-after-scope -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div"
FUZZ_CXXFLAGS="-g -O0 -fno-omit-frame-pointer -gline-tables-only"
CORPUS=CORPUS-$EXECUTABLE_NAME_BASE
JOBS=${JOBS:-"8"}


export CC=${CC:-"clang"}
export CXX=${CXX:-"clang++"}
export CPPFLAGS=${CPPFLAGS:-"-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"}
export LIB_FUZZING_ENGINE="libFuzzingEngine-${FUZZING_ENGINE}.a"

if [[ $FUZZING_ENGINE == "fsanitize_fuzzer" ]]; then
  FSANITIZE_FUZZER_FLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -fsanitize=address,fuzzer-no-link -fsanitize-address-use-after-scope"
  export CFLAGS=${CFLAGS:-$FSANITIZE_FUZZER_FLAGS}
  export CXXFLAGS=${CXXFLAGS:-$FSANITIZE_FUZZER_FLAGS}
elif [[ $FUZZING_ENGINE == "honggfuzz" ]]; then
  export CC=$(realpath -s "$HONGGFUZZ_SRC/hfuzz_cc/hfuzz-clang")
  export CXX=$(realpath -s "$HONGGFUZZ_SRC/hfuzz_cc/hfuzz-clang++")
elif [[ $FUZZING_ENGINE == "coverage" ]]; then
  export CFLAGS=${CFLAGS:-$COVERAGE_FLAGS}
  export CXXFLAGS=${CXXFLAGS:-$COVERAGE_FLAGS}
elif [[ $FUZZING_ENGINE == "symsan" ]]; then
  # export CFLAGS=${CFLAGS:-"$FUZZ_CXXFLAGS"}
  export CFLAGS="${CFLAGS:+${CFLAGS} }$FUZZ_CXXFLAGS"
  export CXXFLAGS="${CXXFLAGS:+${CXXFLAGS} }$FUZZ_CXXFLAGS"
else
  export CFLAGS=${CFLAGS:-"$FUZZ_CXXFLAGS"}
  export CXXFLAGS=${CXXFLAGS:-"$FUZZ_CXXFLAGS"}
fi

get_git_revision() {
  GIT_REPO="$1"
  GIT_REVISION="$2"
  TO_DIR="$3"
  [ ! -e $TO_DIR ] && git clone $GIT_REPO $TO_DIR && (cd $TO_DIR && git reset --hard $GIT_REVISION)
}

get_git_tag() {
  GIT_REPO="$1"
  GIT_TAG="$2"
  TO_DIR="$3"
  [ ! -e $TO_DIR ] && git clone $GIT_REPO $TO_DIR && (cd $TO_DIR && git checkout $GIT_TAG)
}

get_svn_revision() {
  SVN_REPO="$1"
  SVN_REVISION="$2"
  TO_DIR="$3"
  [ ! -e $TO_DIR ] && svn co -r$SVN_REVISION $SVN_REPO $TO_DIR
}

build_afl() {
  # $CC $CFLAGS -c -w $AFL_SRC/llvm_mode/afl-llvm-rt.o.c
  # $CXX $CXXFLAGS -std=c++11 -O2 -c ${LIBFUZZER_SRC}/afl_driver.cpp -I$LIBFUZZER_SRC
  # ar r $LIB_FUZZING_ENGINE afl_driver.o afl-llvm-rt.o.o
  # rm *.o
  $CC $CFLAGS -c -w ${LIBFUZZER_SRC}/driver.c
}

build_libfuzzer() {
  $LIBFUZZER_SRC/build.sh
  mv libFuzzer.a $LIB_FUZZING_ENGINE
}

build_honggfuzz() {
  cp "$HONGGFUZZ_SRC/libhfuzz/persistent.o" $LIB_FUZZING_ENGINE
}

# Uses the capability for "fsanitize=fuzzer" in the current clang
build_fsanitize_fuzzer() {
  LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
}

# This provides a build with no fuzzing engine, just to measure coverage
build_coverage () {
  STANDALONE_TARGET=1
  $CC -O2 -c $LIBFUZZER_SRC/standalone/StandaloneFuzzTargetMain.c
  ar rc $LIB_FUZZING_ENGINE StandaloneFuzzTargetMain.o
  rm *.o
}

# Build with user-defined main and hooks.
build_hooks() {
  LIB_FUZZING_ENGINE=libFuzzingEngine-hooks.o
  $CXX -c $HOOKS_FILE -o $LIB_FUZZING_ENGINE
}

build_aflpp() {
  # echo "nothing todo"
  
  $CC $CFLAGS -c -w ${LIBFUZZER_SRC}/driver.c
}

build_trace() {
  set -x
  # $CC $CFLAGS -c -w $TRACE_SRC/trace-id-rt.o.c
  # $CXX $CXXFLAGS -std=c++11 -O2 -c ${LIBFUZZER_SRC}/afl_driver.cpp -I$LIBFUZZER_SRC
  # ar r $LIB_FUZZING_ENGINE afl_driver.o trace-id-rt.o.o
  # rm *.o

  # $CC $CFLAGS -g -c -w ${LIBFUZZER_SRC}/afl-llvm-rt.o.c
  # $CXX $CXXFLAGS -O2 -c ${LIBFUZZER_SRC}/afl_driver.cpp -I$LIBFUZZER_SRC
  # llvm-ar r $LIB_FUZZING_ENGINE afl_driver.o afl-llvm-rt.o.o
  # rm *.o
  $CC $CFLAGS -c -w ${LIBFUZZER_SRC}/driver.c
  set +x
}

build_taint() {
  # echo "nothing todo"
  set -x
  clang $CFLAGS -g -c -w ${LIBFUZZER_SRC}/afl-llvm-rt.o.c
  clang++ $CXXFLAGS -O2 -c ${LIBFUZZER_SRC}/afl_driver.cpp -I$LIBFUZZER_SRC
  set +x
}

build_symsan() {
  set -x
  echo $CFLAGS
  # read
  # ${CC} $CFLAGS -fPIE -g -c -w ${LIBFUZZER_SRC}/afl-llvm-rt.o.c
  # ${CXX} $CXXFLAGS -fPIE -O2 -c ${LIBFUZZER_SRC}/afl_driver.cpp -I$LIBFUZZER_SRC
  $CC $CFLAGS -c -w -fPIE ${LIBFUZZER_SRC}/driver.c
  set +x
}

build_taintfuzzer() {
  # build_aflpp
  $CC $CFLAGS -c -w ${LIBFUZZER_SRC}/driver.c
}

build_symcc() {
  echo ${LIBFUZZER_SRC}
  cd ~
  $CC $CFLAGS -c -w ${LIBFUZZER_SRC}/driver.c
  cd -
  cp ~/driver.o .
}

build_fuzzer() {
  echo "Building with $FUZZING_ENGINE"
  build_${FUZZING_ENGINE}
}

