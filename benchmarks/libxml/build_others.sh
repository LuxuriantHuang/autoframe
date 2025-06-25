#!/bin/bash
mkdir build
cp -r src build/fuzz
cp -r src build/trace
mkdir target/afl target/trace

cd build/fuzz
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CFLAGS="-g -O0"
export CXXFLAGS="-g -O0"
CC=clang-14 CXX=clang++-14 sh ./autogen.sh
CCLD="$CXX $CXXFLAGS" ./configure \
    --disable-shared \
    --without-debug \
    --without-ftp \
    --without-http \
    --without-legacy \
    --without-python
make -j4
$CC $CFLAGS -c -w driver.c
$CXX $CXXFLAGS target.cc driver.o -I include .libs/libxml2.a -lz -o libxml_fuzz

cp libxml_fuzz ../../target/afl

cd ../trace
export CC=gclang
export CXX=gclang++
export CFLAGS="-g -O0"
export CXXFLAGS="-g -O0"
CC=clang-14 CXX=clang++-14 sh ./autogen.sh
CCLD="$CXX $CXXFLAGS" ./configure \
    --disable-shared \
    --without-debug \
    --without-ftp \
    --without-http \
    --without-legacy \
    --without-python
make -j4
$CC $CFLAGS -c -w driver.c
$CXX $CXXFLAGS target.cc driver.o -I include .libs/libxml2.a -lz -o libxml_trace
cp libxml_trace ../../target/trace
cd ../../target/trace
get-bc libxml_trace
~/Desktop/autoframe/tracer/build/trace-id++ -g -O0 libxml_trace.bc -o libxml_trace -mllvm --output-dir="/home/lab420/Desktop/autoframe/benchmarks/libxml/static" -lz