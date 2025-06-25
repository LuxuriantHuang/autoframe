export CC=gclang
export CXX=gclang++
export CFLAGS="-g -O0"
export CXXFLAGS="-g -O0"
export LLVM_COMPILER=clang
export HOME=~/Desktop/autoframe

cd $HOME/benchmarks_old/build
rm -r libxml_trace
cp -r ../libxml ./libxml_trace
cd libxml_trace

CC=clang-14 CXX=clang++-14 ./autogen.sh
CCLD="$CXX $CXXFLAGS" ./configure --disable-shared \
    --disable-shared \
    --without-debug \
    --without-ftp \
    --without-http \
    --without-legacy \
    --without-python
make -j4

cd $HOME/benchmarks_old/targets/libxml
$CC $CFLAGS -c -w ../driver.c -o ../driver.o
$CXX $CXXFLAGS target.cc ../driver.o -o libxml_trace1 -I $HOME/benchmarks_old/build/libxml_trace/include $HOME/benchmarks_old/build/libxml_trace/.libs/libxml2.a -lz
get-bc libxml_trace1
$HOME/tracer/build/trace-id++ -g -O0 libxml_trace1.bc -o libxml_trace -mllvm --output-dir="$HOME/benchmarks/targets/libxml/static" -lz -lpthread
rm libxml_trace1 libxml_trace1.bc

echo "trace target built"