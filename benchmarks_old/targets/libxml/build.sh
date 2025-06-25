export CC=~/Desktop/autoframe/AFLplusplus/afl-clang-fast
export CXX=~/Desktop/autoframe/AFLplusplus/afl-clang-fast++

cd ~/Desktop/autoframe/benchmarks/build
rm -r libxml
cp -r ../libxml .
cd libxml
CC=clang-14 CXX=clang++-14 ./autogen.sh
CCLD="$CXX $CXXFLAGS" ./configure --disable-shared \
    --disable-shared \
    --without-debug \
    --without-ftp \
    --without-http \
    --without-legacy \
    --without-python
make -j4

cd ~/Desktop/autoframe/benchmarks/targets/libxml
$CC $CFLAGS -c -w ../driver.c -o ../driver.o
$CXX $CXXFLAGS target.cc ../driver.o -o libxml_fuzz -I ~/Desktop/autoframe/benchmarks/build/libxml/include ~/Desktop/autoframe/benchmarks/build/libxml/.libs/libxml2.a -lz

echo "fuzz target built"

