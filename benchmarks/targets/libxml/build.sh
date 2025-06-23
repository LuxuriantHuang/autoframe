$CC $CFLAGS -c -w ../driver.c
$CXX $CXXFLAGS target.cc driver.o -o libxml_target -I ../../build/libxml2/include ../../build/libxml2/.libs/libxml2.a -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic