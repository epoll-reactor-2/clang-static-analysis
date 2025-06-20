cmake_minimum_required(VERSION 3.13)
project(DataFlowAnalysis LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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

