#!/bin/bash
# 快速测试libpng flag变量识别
# 使用已有的pngread.bc文件

set -e

FLAGREC_DIR="/home/lab420/Desktop/autoframe/flag_var/flagrec"
LIBPNG_DIR="/home/lab420/Desktop/autoframe/flag_var/libpng"
OUTPUT_DIR="$FLAGREC_DIR/build/test_results"

mkdir -p "$OUTPUT_DIR"

echo "========================================"
echo "LibPNG Flag变量识别 (快速测试)"
echo "========================================"
echo ""

cd "$FLAGREC_DIR/build"

# 使用pngread.bc（已经编译好的libpng核心文件）
echo "使用: $LIBPNG_DIR/pngread.bc"
echo ""

./flagrec \
    --bitcode "$LIBPNG_DIR/pngread.bc" \
    --source-dir "$LIBPNG_DIR" \
    --out "$OUTPUT_DIR/quick_test" \
    --min-confidence 0.4 2>/dev/null

echo ""
echo "========================================"
echo "识别到的结构体成员flag变量:"
echo "========================================"
echo ""

if [ -f "$OUTPUT_DIR/quick_test/flags.json" ]; then
    echo "名称 | 函数 | 置信度 | 常量赋值"
    echo "------|------|--------|----------"
    jq -r '.flagVariables[] | select(.name | contains("->")) | "\(.name) | \(.function) | \(.confidence * 100)% | \([.assignments[].value] | join(", "))"' "$OUTPUT_DIR/quick_test/flags.json" 2>/dev/null
fi

echo ""
echo "完整报告: $OUTPUT_DIR/quick_test/report.md"
echo "JSON数据: $OUTPUT_DIR/quick_test/flags.json"
