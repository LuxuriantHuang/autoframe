#!/bin/bash
# Build script for flagrec

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
INSTALL_DIR="$SCRIPT_DIR/install"

echo "=========================================="
echo "Flag Variable Recognition - Build Script"
echo "=========================================="
echo ""

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v cmake &> /dev/null; then
    echo "Error: cmake not found. Please install cmake."
    exit 1
fi

if ! command -v llvm-config &> /dev/null && ! command -v llvm-config-10 &> /dev/null; then
    echo "Error: llvm-config not found. Please install LLVM 10 or later."
    exit 1
fi

LLVM_VERSION=$(llvm-config --version 2>/dev/null || llvm-config-10 --version 2>/dev/null)
echo "Found LLVM: $LLVM_VERSION"

# Parse version and check if >= 10
LLVM_MAJOR=$(echo $LLVM_VERSION | cut -d. -f1)
if [ "$LLVM_MAJOR" -lt 10 ]; then
    echo "Error: LLVM version 10 or later required. Found: $LLVM_VERSION"
    exit 1
fi

echo ""

# Create build directory
echo "Creating build directory..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure
echo "Configuring with CMake..."
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_DIR="$(llvm-config --prefix 2>/dev/null || llvm-config-10 --prefix)/lib/cmake/llvm" \
    -DBUILD_TESTS=ON

# Build
echo ""
echo "Building..."
make -j$(nproc 2>/dev/null || echo 4)

echo ""
echo "=========================================="
echo "Build Complete!"
echo "=========================================="
echo ""
echo "Executable: $BUILD_DIR/flagrec"
echo ""
echo "To run the tool:"
echo "  cd $BUILD_DIR"
echo "  ./flagrec --compile_commands <path> --targets <files> --out <output-dir>"
echo ""
echo "To run tests:"
echo "  cd $BUILD_DIR"
echo "  chmod +x tests/run_tests.sh"
echo "  ./tests/run_tests.sh"
echo ""
