./autogen.sh
cd depends
make HOST=x86_64-w64-mingw32 -j16
cd ..
./configure --prefix=`pwd`/depends/x86_64-w64-mingw32 --enable-cxx --disable-shared --enable-static --with-pic
make -j 16


