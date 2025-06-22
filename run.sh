export CC=~/git/llvm-project/build/bin/clang
export CXX=~/git/llvm-project/build/bin/clang++

cmake -B build -D CMAKE_BUILD_TYPE=Debug -D USE_MOLD=1
cmake --build build
./build/DataFlowAnalysis snippets/deterministic.cpp -- -x c++ -I/usr/include -I/usr/lib/gcc/x86_64-linux-gnu/12/include
