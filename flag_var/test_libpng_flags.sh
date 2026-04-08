#!/bin/bash
# 测试libpng的flag变量识别
# 此脚本会编译libpng的核心源文件到bitcode，然后运行flagrec工具

set -e

# 配置路径
FLAGREC_DIR="/home/lab420/Desktop/autoframe/flag_var/flagrec"
LIBPNG_DIR="/home/lab420/Desktop/autoframe/flag_var/libpng"
OUTPUT_DIR="$FLAGREC_DIR/build/test_results"
BCC_DIR="/home/lab420/Desktop/autoframe/wllvm"  # wllvm/bcc路径

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

echo "========================================"
echo "LibPNG Flag变量识别测试"
echo "========================================"
echo ""

# 步骤1: 编译libpng核心源文件到bitcode
echo "步骤1: 编译libpng源文件到bitcode..."

cd "$LIBPNG_DIR"

# 核心源文件列表（包含主要的flag变量使用）
SOURCES=(
    "png.c"
    "pngread.c"
    "pngrtran.c"
    "pngrutil.c"
    "pngset.c"
    "pngtrans.c"
    "pngget.c"
    "pngerror.c"
    "pngmem.c"
    "pngwio.c"
)

BC_FILES=()
for src in "${SOURCES[@]}"; do
    if [ -f "$src" ]; then
        bc="${src%.c}.bc"
        echo "  编译 $src -> $bc"
        clang -emit-llvm -g -O0 -c -I . "$src" -o "$bc" 2>/dev/null || {
            echo "  警告: $src 编译失败，跳过"
            continue
        }
        BC_FILES+=("$LIBPNG_DIR/$bc")
    fi
done

echo ""
echo "步骤2: 链接所有bitcode文件..."

# 使用llvm-link合并所有bitcode文件
COMBINED_BC="$OUTPUT_DIR/libpng_combined.bc"
if [ ${#BC_FILES[@]} -gt 0 ]; then
    llvm-link "${BC_FILES[@]}" -o "$COMBINED_BC" 2>/dev/null || {
        echo "  警告: llvm-link失败，尝试使用第一个文件"
        if [ -f "${BC_FILES[0]}" ]; then
            cp "${BC_FILES[0]}" "$COMBINED_BC"
        fi
    }
    echo "  合并的bitcode: $COMBINED_BC"
else
    echo "  错误: 没有成功编译任何bitcode文件"
    exit 1
fi

echo ""
echo "步骤3: 运行flagrec工具识别flag变量..."

cd "$FLAGREC_DIR/build"

# 清理之前的调试输出（只显示摘要）
./flagrec \
    --bitcode "$COMBINED_BC" \
    --source-dir "$LIBPNG_DIR" \
    --out "$OUTPUT_DIR/libpng_analysis" \
    --min-confidence 0.4 2>/dev/null | grep -E "Summary|Flag variables|Top Flag|png_ptr|transformations|flags"

echo ""
echo "========================================"
echo "分析完成！"
echo "========================================"
echo ""
echo "结果文件位置:"
echo "  - JSON: $OUTPUT_DIR/libpng_analysis/flags.json"
echo "  - 报告: $OUTPUT_DIR/libpng_analysis/report.md"
echo ""

# 显示识别到的结构体成员flag变量
echo "识别到的结构体成员flag变量:"
echo "----------------------------------------"
if [ -f "$OUTPUT_DIR/libpng_analysis/flags.json" ]; then
    # 使用jq提取包含'->'的结构体成员
    if command -v jq &> /dev/null; then
        jq -r '.flagVariables[] | select(.name | contains("->")) | "\(.name) (\(.confidence * 100)% confidence) - \(.function):\(.location)"' "$OUTPUT_DIR/libpng_analysis/flags.json" 2>/dev/null || echo "  无结构体成员flag变量"
    else
        grep -o '"png_ptr[^"]*"' "$OUTPUT_DIR/libpng_analysis/flags.json" | sort -u | while read -r name; do
            echo "  $name"
        done
    fi
else
    echo "  结果文件不存在"
fi

echo ""
echo "所有识别到的flag变量 (按置信度排序):"
echo "----------------------------------------"
if [ -f "$OUTPUT_DIR/libpng_analysis/report.md" ]; then
    grep -A 5 "### " "$OUTPUT_DIR/libpng_analysis/report.md" | grep -E "###|Confidence|Location" | paste - - - | head -20
fi

echo ""
echo "查看详细结果:"
echo "  cat $OUTPUT_DIR/libpng_analysis/report.md"
echo "  cat $OUTPUT_DIR/libpng_analysis/flags.json | jq '.flagVariables[]'"
