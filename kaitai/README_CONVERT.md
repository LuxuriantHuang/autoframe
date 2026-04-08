# ISI JSON 转换为 Kaitai 格式工具

将 `tseed.isi.json` 转换为类似 Kaitai 标准解析器输出的格式，并将哈希ID替换为有意义的字段名。

## 文件说明

### 脚本文件

1. **`convert_isi_to_kaitai_final.py`** - 推荐使用的最终版本
   - 自动为二进制文件生成 Kaitai 参考输出
   - 通过偏移量匹配建立哈希ID到字段名的映射
   - 自动去除重复字段
   - 最智能、最准确

2. **`convert_isi_to_kaitai_best.py`** - 功能完整的中间版本
   - 类似最终版本，但不包含去重功能

3. **`convert_isi_to_kaitai_smart.py`** - 智能推断版本
   - 不需要参考文件，通过分析PNG结构推断字段名
   - 适用于无法生成Kaitai参考输出的情况

4. **`convert_isi_to_kaitai.py`** - 基础版本
   - 简单的格式转换，不进行字段名映射
   - 需要手动提供参考文件

## 使用方法

### 方法1：自动模式（推荐）

自动为同一文件生成Kaitai参考输出并进行匹配：

```bash
python3 convert_isi_to_kaitai_final.py <input.isi.json> -b <binary_file> -o <output.json>
```

**示例**：
```bash
python3 convert_isi_to_kaitai_final.py \
    /home/lab420/Desktop/autoframe/benchmarks/libpng/tseed.isi.json \
    -b /home/lab420/Desktop/autoframe/benchmarks/libpng/tseed.isi \
    -o tseed_kaitai.json
```

### 方法2：使用已有参考文件

如果已经有一个Kaitai解析器的输出文件：

```bash
python3 convert_isi_to_kaitai_final.py <input.isi.json> -r <reference.json> -o <output.json>
```

**示例**：
```bash
python3 convert_isi_to_kaitai_final.py \
    /home/lab420/Desktop/autoframe/benchmarks/libpng/tseed.isi.json \
    -r /home/lab420/Desktop/autoframe/benchmarks/libpng/root_kaitai.json \
    -o output.json
```

### 方法3：保留重复项

如果需要保留所有字段（包括同一偏移的多个字段）：

```bash
python3 convert_isi_to_kaitai_final.py <input.isi.json> -b <binary_file> --keep-duplicates
```

## 输出格式

```json
{
  "file_path": "/path/to/input.isi.json",
  "fields": [
    {
      "name": "magic",
      "offset": 0,
      "size": 8
    },
    {
      "name": "ihdr.width",
      "offset": 16,
      "size": 1
    },
    {
      "name": "ihdr.height",
      "offset": 20,
      "size": 1
    },
    {
      "name": "chunks[0].type",
      "offset": 37,
      "size": 4
    },
    {
      "name": "chunks[0].body.gamma_int",
      "offset": 41,
      "size": 4
    }
  ]
}
```

## 字段名映射原理

### ISI 格式特点

- **粒度**: 字节级别，每个字节甚至每个位都是独立的叶子节点
- **结构**: 嵌套的哈希ID树，没有语义化的字段名
- **偏移**: 相对偏移，需要计算绝对偏移

### Kaitai 格式特点

- **粒度**: 语义级别，多个字节组合成一个字段（如4字节的width）
- **结构**: 扁平的列表，有语义化的字段名
- **偏移**: 绝对偏移

### 匹配策略

1. **完美匹配**: 偏移和大小完全相同
2. **起始匹配**: 偏移相同，大小不同（ISI可能细分了字段）
3. **重叠匹配**: 有重叠部分，根据重叠比例评分

### 粒度差异示例

对于 `ihdr.width` 字段（4字节）：
- **Kaitai**: 一个字段 `{"name": "ihdr.width", "offset": 16, "size": 4}`
- **ISI**: 四个字段
  ```json
  {"name": "ihdr.width", "offset": 16, "size": 1}
  {"name": "ihdr.width", "offset": 17, "size": 1}
  {"name": "ihdr.width", "offset": 18, "size": 1}
  {"name": "ihdr.width", "offset": 19, "size": 1}
  ```

## 高级选项

### 指定 test.py 路径

如果 `test.py` 不在默认位置：

```bash
python3 convert_isi_to_kaitai_final.py \
    <input.isi.json> \
    -b <binary_file> \
    -t /path/to/test.py
```

### 调试模式

查看生成的中间文件：

```bash
# Kaitai参考输出会自动生成为 <binary_file>.kaitai.json
ls -l /home/lab420/Desktop/autoframe/benchmarks/libpng/tseed.isi.kaitai.json
```

## 常见问题

### Q: 为什么有些字段名重复但偏移不同？

A: 这是正常的。ISI格式将多字节字段拆分成单字节节点。例如，4字节的 `width` 会被拆分成4个字段，每个字段的名字相同但偏移递增。

### Q: 可以合并连续的同名字段吗？

A: 当前版本保持ISI的原始粒度。如需合并，可以使用 `convert_isi_to_kaitai_smart.py` 的输出作为参考。

### Q: 映射失败的字段会怎样？

A: 如果无法找到匹配的Kaitai字段，会保留原始的哈希ID路径作为字段名。

### Q: 支持其他文件格式吗？

A: 当前主要针对PNG优化。理论上支持任何可以通过Kaitai解析的格式，但字段名推断功能是PNG特定的。

## 示例输出对比

### 原始ISI格式（哈希ID）

```json
{
  "name": "000000040B5335C3.FE65A5AF97D0C9C6.00000000004000E4",
  "offset": 0,
  "size": 8
}
```

### 转换后格式（语义化字段名）

```json
{
  "name": "magic",
  "offset": 0,
  "size": 8
}
```

## 技术细节

### 依赖项

- Python 3.6+
- kaitaistruct (用于生成参考输出)
- json (标准库)

### 算法复杂度

- 遍历ISI树: O(n)，n为节点数
- 偏移匹配: O(m*n)，m为Kaitai字段数，n为ISI字段数
- 去重排序: O(n log n)

### 内存占用

- 主要取决于ISI树的大小
- 通常小于100MB（对于典型的PNG文件）

## 更新日志

- **v1.0** (2024-01-30): 初始版本，基础转换功能
- **v1.1** (2024-01-30): 添加智能推断功能
- **v1.2** (2024-01-30): 添加自动参考生成和去重功能
- **v1.3** (2024-01-30): 最终版本，优化匹配算法

## 作者

Generated for PNG format conversion from ISI to Kaitai structure.

## 许可

与原项目保持一致。
