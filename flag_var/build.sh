export CC=gclang
export CXX=gclang++
export CFLAGS="-g -O0 -fno-discard-value-names"
export CXXFLAGS="-g -O0 -fno-discard-value-names"
./configure --disable-shared
make -j
"$CC" $CFLAGS -c -w driver.c
"$CXX" $CXXFLAGS -std=c++11 target.cc driver.o .libs/libpng12.a -I . -lz -o libpng-flag
