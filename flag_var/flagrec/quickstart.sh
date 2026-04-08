#!/bin/bash
# Quick start script for flagrec
# This script builds the project and runs a demo analysis

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

echo "=========================================="
echo "Flag Variable Recognition - Quick Start"
echo "=========================================="
echo ""

# Step 1: Build
if [ ! -f "$BUILD_DIR/flagrec" ]; then
    echo "Step 1: Building flagrec..."
    bash "$SCRIPT_DIR/build.sh"
    echo ""
else
    echo "Step 1: Already built (skip)"
fi

# Step 2: Create a simple demo compile_commands.json
echo "Step 2: Setting up demo..."

cd "$BUILD_DIR"

# Create a minimal compile_commands.json for the demo
cat > compile_commands.json << 'EOF'
[
  {
    "directory": "/tmp",
    "command": "clang -c /tmp/test.c",
    "file": "/tmp/test.c"
  }
]
EOF

# Copy demo files to build directory
cp "$SCRIPT_DIR/examples/demo1_flags.c" . 2>/dev/null || true

# Step 3: Run analysis on demo1
echo ""
echo "Step 3: Running analysis on demo1_flags.c..."

# First, compile demo1 to bitcode manually
if [ -f "demo1_flags.c" ]; then
    clang -emit-llvm -c demo1_flags.c -o demo1_flags.bc 2>/dev/null || {
        echo "Warning: Could not compile demo1_flags.c"
    }
fi

# Run flagrec
echo ""
echo "Running flagrec..."
"$BUILD_DIR/flagrec" \
    --compile_commands "$BUILD_DIR" \
    --targets "$SCRIPT_DIR/examples/demo1_flags.c" \
    --out "$BUILD_DIR/demo_output" \
    --verbose || {
    echo ""
    echo "Note: The tool may have issues if compile_commands.json is not properly set up."
    echo "This is expected for the quick start demo."
    echo ""
    echo "For production use, ensure your project has a compile_commands.json file."
    echo "You can generate one with CMake or Bear:"
    echo "  cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .."
    echo "  bear -- make"
}

# Step 4: Show results
echo ""
echo "=========================================="
echo "Quick Start Complete!"
echo "=========================================="
echo ""
echo "Results:"
if [ -d "$BUILD_DIR/demo_output" ]; then
    echo ""
    echo "Files generated:"
    ls -la "$BUILD_DIR/demo_output/" 2>/dev/null || echo "  (none)"
    echo ""

    if [ -f "$BUILD_DIR/demo_output/flags.json" ]; then
        echo "=== flags.json (first 50 lines) ==="
        head -50 "$BUILD_DIR/demo_output/flags.json"
    fi

    if [ -f "$BUILD_DIR/demo_output/report.md" ]; then
        echo ""
        echo "=== report.md ==="
        cat "$BUILD_DIR/demo_output/report.md"
    fi
else
    echo "Output directory not created. Check for errors above."
fi

echo ""
echo "=========================================="
echo "Next Steps"
echo "=========================================="
echo ""
echo "1. Analyze your own project:"
echo "   ./flagrec --compile_commands /path/to/your/build --targets src/main.c --out ./results"
echo ""
echo "2. Run all tests:"
echo "   chmod +x tests/run_tests.sh && ./tests/run_tests.sh"
echo ""
echo "3. Read the documentation:"
echo "   cat ../README.md"
echo ""
