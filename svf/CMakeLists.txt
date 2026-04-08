cmake_minimum_required(VERSION 3.13)
project(llvm_ir_graphs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(LLVM 10 REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

set(SVF_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/SVF)
set(SVF_BUILD_ROOT ${SVF_ROOT}/Release-build)

add_executable(ir_graph_extractor
  src/main.cpp
)

add_executable(BranchConditionSlicer
  src/BranchConditionSlicer.cpp
)

llvm_map_components_to_libnames(LLVM_LIBS
  Core
  Support
  IRReader
  BitReader
  Analysis
  Passes
)

target_link_libraries(ir_graph_extractor PRIVATE ${LLVM_LIBS})
target_link_libraries(BranchConditionSlicer PRIVATE ${LLVM_LIBS})
target_include_directories(BranchConditionSlicer PRIVATE
  ${SVF_ROOT}/include
)
target_link_libraries(BranchConditionSlicer PRIVATE
  ${SVF_BUILD_ROOT}/lib/libSvf.a
  ${SVF_BUILD_ROOT}/lib/CUDD/libCudd.a
)
