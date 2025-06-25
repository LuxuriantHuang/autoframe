echo "[X] Entering target's build dir: $TARGET_DIR"
cd $TARGET_DIR

######################### COMPILATION INSTRUCTIONS ############################


# WARNING: $POLYTRACKER ENV is necessary here for poly container, it will be set
# to null in other cases, so MAKE SURE TO ADD $POLYTRACKER when writing compilation
# commands
# with make or cmake or ninja, use
# $POLYTRACKER cmake... ; $POLYTRACKER ./configure ; $POLYTRACKER make ...

# DO NOT CHANGE $CC $CXX, DO append arguments after $CFLAGS $CXXFLAGS

# MAKE SURE TO COMPILE WITH CFLAGS/CXXFLAGS

# $POLYTRACKER $CC $CFLAGS -c -w /root/Project/driver_lib/driver/afl-llvm-rt.o.c
# $POLYTRACKER $CXX $CXXFLAGS -std=c++11 -O2 -c /root/Project/driver_lib/driver/afl_driver.cpp
# ar r libFuzzingEngine-afl.a afl_driver.o afl-llvm-rt.o.o
# rm *.o
# $POLYTRACKER cmake -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_COMPILER="$CC" -DCMAKE_C_FLAGS="$CFLAGS -Wno-deprecated-declarations" -DCMAKE_CXX_COMPILER="$CXX" -DCMAKE_CXX_FLAGS="$CXXFLAGS -Wno-error=main"
# $POLYTRACKER make -j4
# $POLYTRACKER $CXX $CXXFLAGS -I include fuzz/privkey.cc ./ssl/libssl.a ./crypto/libcrypto.a -lpthread libFuzzingEngine-afl.a -o boringssl

# echo "[X] cd to src"
# cd libxml2
# # rm -rf build
# mkdir -p build && cd build
# $(dirname $PWD)/build.sh
apt update
apt install -y locales
locale-gen en_US.UTF-8
update-locale LANG=en_US.UTF-8
apt install liblzma-dev zlib1g-dev autoconf libtool build-essential pkg-config -y
apt install /root/Project/automake_1.16.5-1.3_all.deb

mkdir -p /usr/local/share/aclocal/ && cp /usr/share/aclocal/*.m4 /usr/local/share/aclocal/

CC=clang CXX=clang++ ./autogen.sh
CCLD="$CXX $CXXFLAGS" ./configure --host=x86_64-pc-linux-gnu \
    --disable-shared \
    --without-debug \
    --without-ftp \
    --without-http \
    --without-legacy \
    --without-python
make -j4
if [[ $FUZZING_ENGINE == "symsan" ]]; then
  export CXXFLAGS="${CXXFLAGS:+${CXXFLAGS} } -fPIE"
fi
$CC $CFLAGS -c -w driver.c
$CXX $CXXFLAGS -std=c++11 target.cc driver.o -I include .libs/libxml2.a -lz -o ${FUZZING_ENGINE}-test


############################# MOVING TARGET ###################################

# if [ -n "$POLYTRACKER" ]; then
#     echo "[X] polytracker instrument"
#     polytracker instrument-targets boringssl
#     cp $TARGET_DIR/boringssl.instrumented $PREFIX/target_binary
# else
    echo "[X] Copying binary to its dedicated location"
    cp $TARGET_DIR/${FUZZING_ENGINE}-test $PREFIX/target_binary
# fi

