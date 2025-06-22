cmake_minimum_required(VERSION 3.20)
project(DataFlowAnalysis LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(USE_MOLD "Use the mold linker" ON)

set(_linker_flag "")

if (USE_MOLD)
  find_program(_MOLD mold)
  if (_MOLD)
    set(_linker_flag "-fuse-ld=mold")
    message(STATUS "Linker: mold")
  endif()
endif()

if (_linker_flag)
  add_link_options(${_linker_flag} -Wl,--threads)
endif()

# Required Clang version: 21.0.0
set(LLVM_DIR ~/git/llvm-project/build/lib/cmake/llvm)
set(Clang_DIR ~/git/llvm-project/build/lib/cmake/clang)
set(DENABLE_LLVM_SHARED 1)

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS})
include_directories(${CLANG_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_executable(DataFlowAnalysis src/DataFlowAnalysis.cpp)
target_compile_options(DataFlowAnalysis PRIVATE -pipe)

if (NOT LLVM_ENABLE_RTTI)
  target_compile_options(DataFlowAnalysis PRIVATE -fno-rtti -fno-exceptions)
endif()

target_link_libraries(DataFlowAnalysis
  clangFrontend
  clangAST
  clangBasic
  clangTooling
  clangAnalysis
  clangStaticAnalyzerCore
  clangStaticAnalyzerCheckers
  clangAnalysisFlowSensitiveModels
  clangAnalysisFlowSensitive
)

