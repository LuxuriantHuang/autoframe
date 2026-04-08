# LibPNG Flag变量识别测试指南

## 概述

本指南说明如何使用flagrec工具识别libpng库中的flag变量，特别是结构体成员flag变量（如`png_ptr->mode`、`png_ptr->transformations`等）。

## 测试方法

### 方法1: 快速测试（使用预编译的bitcode）

```bash
cd /home/lab420/Desktop/autoframe/flag_var
./quick_test.sh
```

这会使用已编译好的`pngread.bc`文件进行分析。

### 方法2: 完整测试（编译多个源文件）

```bash
cd /home/lab420/Desktop/autoframe/flag_var
./test_libpng_flags.sh
```

这会：
1. 编译libpng的多个核心源文件到bitcode
2. 链接所有bitcode文件
3. 运行完整的flag变量分析

### 方法3: 手动测试

```bash
# 1. 编译单个源文件到bitcode
cd /home/lab420/Desktop/autoframe/flag_var/libpng
clang -emit-llvm -g -O0 -c -I . pngread.c -o pngread.bc

# 2. 运行flagrec工具
cd /home/lab420/Desktop/autoframe/flag_var/flagrec/build
./flagrec \
    --bitcode /home/lab420/Desktop/autoframe/flag_var/libpng/pngread.bc \
    --source-dir /home/lab420/Desktop/autoframe/flag_var/libpng \
    --out ./test_output \
    --min-confidence 0.4
```

## 预期结果

工具应该识别出以下结构体成员flag变量：

| 变量名 | 置信度 | 描述 |
|--------|--------|------|
| `png_ptr->mode` | 86%-100% | PNG状态标志 (PNG_HAVE_IHDR, PNG_HAVE_PLTE等) |
| `png_ptr->transformations` | 45%+ | PNG转换标志 (PNG_TRANSFORM_*) |
| `png_ptr->flags` | ? | 其他标志位 |

## 查看结果

### 查看Markdown报告
```bash
cat /home/lab420/Desktop/autoframe/flag_var/flagrec/build/test_results/libpng_analysis/report.md
```

### 查看JSON数据
```bash
# 查看所有flag变量
cat /home/lab420/Desktop/autoframe/flag_var/flagrec/build/test_results/libpng_analysis/flags.json | jq '.flagVariables[]'

# 只查看结构体成员
cat /home/lab420/Desktop/autoframe/flag_var/flagrec/build/test_results/libpng_analysis/flags.json | jq '.flagVariables[] | select(.name | contains("->"))'
```

## 测试自定义代码

如果你有其他C/C++项目需要测试：

```bash
# 1. 编译到bitcode
clang -emit-llvm -g -O0 -c your_file.c -o your_file.bc

# 2. 运行分析
./flagrec \
    --bitcode /path/to/your_file.bc \
    --source-dir /path/to/your/source \
    --out ./output_dir
```

## 常见问题

### Q: 为什么只检测到`<unnamed>`变量？
A: 原始的`libpng-flag.bc`只包含fuzzer harness代码，不包含完整的libpng库。需要编译libpng源文件到bitcode才能检测结构体成员。

### Q: 为什么`png_ptr->transformations`置信度较低？
A: 因为该字段的访问模式复杂，且常量匹配可能不完整。可以通过添加更多的字段名映射来改进。

### Q: 如何添加新的结构体字段映射？
A: 编辑`VariableFilter.cpp`中的`getFieldNameFromGEP()`函数，添加新的字段索引到名称的映射。
