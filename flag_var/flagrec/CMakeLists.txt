cmake_minimum_required(VERSION 3.10)
project(flagrec VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find LLVM package
find_package(LLVM 10 REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# Add LLVM definitions and include directories
include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

# Find Clang - use alternative approach for shared libraries
# Don't use find_package(Clang) as it requires static libs
find_path(CLANG_INCLUDE_DIR clang/Basic/Version.inc
    PATHS
        /usr/lib/llvm-10/include
        /usr/include/clang-10
    NO_DEFAULT_PATH
)

if(CLANG_INCLUDE_DIR)
    include_directories(${CLANG_INCLUDE_DIR})
    message(STATUS "Found Clang headers: ${CLANG_INCLUDE_DIR}")
else()
    message(WARNING "Clang headers not found, trying system paths")
    include_directories(/usr/include/clang-10)
endif()

# Source files
set(FLAGREC_SOURCES
    src/ConstantFinder.cpp
    src/VariableFilter.cpp
    src/FlagIdentifier.cpp
    src/ASTParser.cpp
    src/FlagRec.cpp
    src/main.cpp
)

set(FLAGREC_HEADERS
    include/Types.h
    include/ConstantFinder.h
    include/VariableFilter.h
    include/FlagIdentifier.h
    include/ASTParser.h
    include/FlagRec.h
)

# Create the flagrec executable
add_executable(flagrec ${FLAGREC_SOURCES})

# Include directories
target_include_directories(flagrec PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LLVM_INCLUDE_DIRS}
)

# Link libraries
llvm_map_components_to_libnames(llvm_libs
    support
    core
    irreader
    bitreader
    analysis
    transformutils
)

target_link_libraries(flagrec
    ${llvm_libs}
)

# Installation rules
install(TARGETS flagrec DESTINATION bin)

# Install examples
install(DIRECTORY examples/ DESTINATION share/flagrec/examples)

# Print build info
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "C++ flags: ${CMAKE_CXX_FLAGS}")

# Option to build tests
option(BUILD_TESTS "Build test programs" ON)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()
