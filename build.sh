./autogen.sh
cd depends
make HOST=x86_64-unknown-linux-gnu -j16
cd ..
./configure --prefix=`pwd`/depends/x86_64-unknown-linux-gnu --enable-cxx --enable-shared --enable-static --with-pic
make -j 16


