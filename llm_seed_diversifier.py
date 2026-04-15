#!/usr/bin/env python3
"""Generate diverse initial seeds for a target input type with an LLM.

This script implements a staged strategy:
1. Ask the model to enumerate variation dimensions first.
2. Generate seeds per dimension while keeping other dimensions stable.
3. Repeat from multiple personas to widen the sampling distribution.
4. Optionally apply structure-aware mutations for JSON/XML/HTML-like inputs.
5. Run an extra diversity sweep conditioned on already generated seeds.
6. Deduplicate and save seeds to the user-specified output path.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from difflib import SequenceMatcher
from importlib.util import find_spec
from pathlib import Path
from typing import Iterable

from openai import OpenAI


LIBRARY_PRESETS = {
    "libxml": {
        "format_name": "xml",
        "type_desc": "输入是 XML 文本，重点覆盖标签、属性、实体、命名空间、DTD、CDATA、编码声明与非法字符。",
        "signature": "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)",
        "target_function": "xmlDocPtr xmlReadMemory(const char *buffer, int size, const char *URL, const char *encoding, int options)",
        "call_chain": "LLVMFuzzerTestOneInput -> xmlReadMemory -> xmlParseDocument",
        "baseline_file": "benchmarks/libxml/in/xlink.xml",
        "output_encoding": "text",
        "generation_mode": "direct",
        "preferred_python_libraries": [],
    },
    "libpng": {
        "format_name": "png",
        "type_desc": "输入是 PNG 二进制文件，重点覆盖 PNG 签名、IHDR、PLTE、IDAT、IEND、辅助 chunk、CRC、长度字段与 chunk 顺序。",
        "signature": "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)",
        "target_function": "void png_read_info(png_structrp png_ptr, png_inforp info_ptr)",
        "call_chain": "LLVMFuzzerTestOneInput -> png_create_read_struct -> png_create_info_struct -> png_read_info -> png_read_image",
        "baseline_file": "benchmarks/libpng/in/seed.png",
        "output_encoding": "base64",
        "generation_mode": "python-generator",
        "preferred_python_libraries": ["PIL", "png"],
    },
    "lcms": {
        "format_name": "icc",
        "type_desc": "输入是 ICC profile 二进制数据，重点覆盖 header、tag table、tag offset/size、颜色空间、渲染意图、曲线和 LUT 相关字段。",
        "signature": "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)",
        "target_function": "cmsHPROFILE cmsOpenProfileFromMem(const void *MemPtr, cmsUInt32Number dwSize)",
        "call_chain": "LLVMFuzzerTestOneInput -> cmsOpenProfileFromMem -> cmsCreateTransform",
        "baseline_file": "benchmarks/lcms/in/seed",
        "output_encoding": "base64",
        "generation_mode": "python-generator",
        "preferred_python_libraries": [],
    },
    "mujs": {
        "format_name": "javascript",
        "type_desc": "输入是 JavaScript 源码，重点覆盖对象/数组、原型链、函数调用、异常路径、模块、Unicode 标识符和语法边界。",
        "signature": "int main(int argc, char **argv)",
        "target_function": "int js_dofile(js_State *J, const char *filename)",
        "call_chain": "main -> js_dofile -> js_loadfile -> js_loadstring -> js_loadstringx -> jsP_parse -> jsC_compile -> js_newscript -> js_call",
        "baseline_file": "benchmarks/mujs/in/test_1.js",
        "output_encoding": "text",
        "generation_mode": "direct",
        "preferred_python_libraries": [],
    },
    "sqlite3": {
        "format_name": "sql",
        "type_desc": "输入是 SQLite SQL 脚本文本，重点覆盖 DDL、DML、事务、触发器、视图、CTE、PRAGMA、表达式边界、超长字符串和轻微语法错误恢复。",
        "signature": "int main(int argc, char **argv)",
        "target_function": "static int process_input(ShellState *p, const char *zSrc)",
        "call_chain": "main -> process_input -> shell_exec -> sqlite3_prepare_v2 -> sqlite3_step",
        "baseline_file": "benchmarks/sqlite3/in/analyze.test",
        "output_encoding": "text",
        "generation_mode": "direct",
        "preferred_python_libraries": [],
    },
    "pcre2": {
        "format_name": "regex",
        "type_desc": "输入是正则表达式模式文本，重点覆盖分组、回溯、断言、字符类、转义、量词嵌套、递归和非法模式。",
        "signature": "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)",
        "target_function": "pcre2_code *pcre2_compile(PCRE2_SPTR pattern, PCRE2_SIZE length, uint32_t options, int *errorcode, PCRE2_SIZE *erroroffset, pcre2_compile_context *ccontext)",
        "call_chain": "LLVMFuzzerTestOneInput -> pcre2_compile",
        "baseline_file": "benchmarks/pcre2/in/seed",
        "output_encoding": "text",
        "generation_mode": "direct",
        "preferred_python_libraries": [],
    },
    "pdf2text": {
        "format_name": "pdf",
        "type_desc": "输入是 PDF 二进制文件，重点覆盖 header、xref、trailer、stream/filter、对象引用、页面树、字体和编码对象。",
        "signature": "int main(int argc, char *argv[])",
        "target_function": "PDFDoc::PDFDoc(GString *fileNameA, GString *ownerPassword, GString *userPassword, ...)",
        "call_chain": "main -> parseArgs -> new PDFDoc(fileName, ownerPW, userPW) -> doc->isOk -> new TextOutputDev -> doc->displayPages",
        "baseline_file": "benchmarks/pdf2text/in/test.pdf",
        "output_encoding": "base64",
        "generation_mode": "python-generator",
        "preferred_python_libraries": ["PyPDF2", "reportlab"],
    },
    "proj4": {
        "format_name": "proj4",
        "type_desc": "输入是 PROJ.4 投影参数字符串，重点覆盖投影类型、坐标系参数、重复键、非法值、边界数值和编码。",
        "signature": "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)",
        "target_function": "PJ *proj_create(PJ_CONTEXT *ctx, const char *definition)",
        "call_chain": "LLVMFuzzerTestOneInput -> proj_create",
        "baseline_file": "benchmarks/proj4/in/in",
        "output_encoding": "text",
        "generation_mode": "direct",
        "preferred_python_libraries": [],
    },
    "transform": {
        "format_name": "transform",
        "type_desc": "输入是几何/坐标转换相关文本参数，重点覆盖操作链、顺序依赖、数值边界、非法参数和重复定义。",
        "signature": "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)",
        "target_function": "transform_parse(const char *input, size_t size)",
        "call_chain": "LLVMFuzzerTestOneInput -> transform parser entry -> transform execution setup",
        "baseline_file": "benchmarks/transform/in/in",
        "output_encoding": "text",
        "generation_mode": "direct",
        "preferred_python_libraries": [],
    },
    "jhead": {
        "format_name": "jpeg",
        "type_desc": "输入是 JPEG/EXIF 二进制文件，重点覆盖 JPEG marker、段长度、EXIF IFD、缩略图、字节序、偏移和元数据字符串。",
        "signature": "int main(int argc, char **argv)",
        "target_function": "static void ProcessFile(const char *FileName)",
        "call_chain": "main -> ProcessFile -> ReadJpegFile -> ReadJpegSections",
        "baseline_file": "benchmarks/jhead/in/103.jpg",
        "output_encoding": "base64",
        "generation_mode": "python-generator",
        "preferred_python_libraries": ["PIL", "piexif"],
    },
    "cjson": {
        "format_name": "json",
        "type_desc": "输入是 JSON 文本，重点覆盖对象、数组、数字、Unicode、转义、重复键、深层嵌套和轻微结构违规。",
        "signature": "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)",
        "target_function": "cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length)",
        "call_chain": "LLVMFuzzerTestOneInput -> cJSON_ParseWithLength",
        "baseline_file": "benchmarks/cjson/in/test3.uu",
        "output_encoding": "text",
        "generation_mode": "direct",
        "preprocess_note": "AFL harness 要求输入前两个字节为打印模式前缀；实际 JSON 从偏移 2 开始解析，生成时应面向纯 JSON，落盘时再补前缀。",
        "seed_prefix": "uu",
        "preferred_python_libraries": [],
    },
    "cflow": {
        "format_name": "c_source",
        "type_desc": "输入是 C 源码文本，重点覆盖声明、定义、宏、函数指针、注释、字符串、预处理边界和语法错误恢复。",
        "signature": "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)",
        "target_function": "parse_c_source(const char *text, size_t size)",
        "call_chain": "LLVMFuzzerTestOneInput -> lexer -> parser -> control-flow extraction",
        "baseline_file": "benchmarks/cflow/in/test.c",
        "output_encoding": "text",
        "generation_mode": "direct",
        "preferred_python_libraries": [],
    },
    "cxxfilt": {
        "format_name": "txt",
        "type_desc": "输入是符号名文本流，cxxfilt 会从 stdin 中扫描可疑 mangled symbol，并以分隔符切开；重点覆盖 Itanium/GNU v3、Rust、D、Java 风格符号、下划线前缀、模板/命名空间嵌套、超长标识符、混合分隔符和轻微损坏的 mangled 名称。",
        "signature": "int main(int argc, char **argv)",
        "target_function": "static void demangle_it(char *mangled_name)",
        "call_chain": "main -> getchar/argv scan -> demangle_it -> cplus_demangle / rust_demangle / dlang_demangle",
        "baseline_file": "benchmarks/cxxfilt/in/seed",
        "output_encoding": "text",
        "generation_mode": "direct",
        "preprocess_note": "AFL harness 直接将 seed 作为 stdin 文本输入；程序会把字母数字和符号字符组成的 token 视为候选 mangled name，空白与其他字符更多充当分隔符。生成时优先输出短文本或多 token 文本，而不是结构化二进制。",
        "preferred_python_libraries": [],
    },
    "calc": {
        "format_name": "calc",
        "type_desc": "输入是 calc 解释器脚本文本/表达式流，重点覆盖整数与分数运算、复数、内建函数、变量赋值、条件/循环、函数定义、字符串、格式配置以及轻微语法错误恢复。",
        "signature": "int main(int argc, char **argv)",
        "target_function": "top-level calc command parser/evaluator",
        "call_chain": "main -> openinput/read commands -> scanner/parser -> evaluator",
        "baseline_file": "benchmarks/calc/in/seed.cal",
        "output_encoding": "text",
        "generation_mode": "direct",
        "preprocess_note": "优先生成可直接通过 stdin 喂给 calc 的短脚本或多行表达式；保持单文件文本输入，不依赖额外 include/script 文件。",
        "preferred_python_libraries": [],
    },
}


DEFAULT_PERSONAS = [
    "你是一个专门寻找整数溢出漏洞的安全研究员。",
    "你是一个测试国际化支持的 QA 工程师，专注于 Unicode 和编码问题。",
    "你是一个寻找内存越界读写的 fuzzer，关注缓冲区边界。",
    "你是一个寻找逻辑漏洞的渗透测试工程师，关注语义合法但行为异常的输入。",
    "你是一个测试错误处理路径的开发者，专门构造各种错误状态。",
    "你是一个寻找解析器漏洞的研究员，专注于格式规范的歧义区域。",
]

TEXTUAL_FORMAT_NAMES = {
    "xml",
    "html",
    "json",
    "yaml",
    "yml",
    "javascript",
    "sql",
    "regex",
    "proj4",
    "transform",
    "c_source",
    "csv",
    "txt",
    "calc",
}

LONG_TEXT_HINT_KEYWORDS = [
    "超长",
    "最大",
    "嵌套深度",
    "深度",
    "重复",
    "大尺寸",
    "large",
    "long",
    "length",
    "size",
    "nested",
    "deep",
    "repeat",
]


DIMENSION_PROMPT = """
你是一个专业的模糊测试种子生成器。

分析上下文：
{analysis_context}
输入类型描述：{type_desc}

任务：先系统性列出这个输入类型的“可变维度”，不要生成具体输入。

必须考虑但不限于以下类别：
- 数值边界（整型溢出、浮点特殊值）
- 长度/大小（空、最小有效、最大合法、超最大）
- 编码与字符集（ASCII 边界、多字节、非法编码）
- 结构完整性（缺字段、重复字段、嵌套深度）
- 语义合法性（语法合法但语义非法）
- 顺序与时序（乱序、重复、缺失步骤）
- 并发与状态（若适用）

严格输出 JSON 数组，不要输出解释。每个元素都必须是对象，格式如下：
{{
  "name": "维度名称",
  "description": "维度说明",
  "boundary_direction": "最小/最大/特殊值等"
}}
"""


SEED_PER_DIMENSION_PROMPT = """
输入类型描述：{type_desc}
分析上下文：
{analysis_context}
当前聚焦维度：{dimension_name}
维度说明：{dimension_desc}
边界方向：{boundary_direction}

要求：
1. 只围绕当前维度变化。
2. 其他维度保持正常、常见、合法值。
3. 覆盖该维度的不同边界方向。
4. 输出必须彼此明显不同，避免只改一个字符或一个数字。
5. 如果适用，请覆盖“合法但危险”和“轻微违规”两类情况。

已生成的种子（不要生成与这些相似的）：
{existing_seeds}

输出编码：{output_encoding}
如果输出编码是 `base64`，`value` 必须是完整的 base64 编码内容，对应最终要落盘的原始字节。

严格输出 JSON 数组，不要输出解释。每个元素格式：
{{
  "value": "种子内容",
  "category": "该种子覆盖的子方向",
  "notes": "一句极短说明"
}}

请生成 {n} 个种子。
"""


STRUCTURAL_MUTATION_PROMPT = """
输入格式：{format_name}
分析上下文：
{analysis_context}
输入类型描述：{type_desc}
基准合法输入：
{baseline_input}

输出编码：{output_encoding}
如果输出编码是 `base64`，`value` 必须是完整的 base64 编码内容，对应最终要落盘的原始字节。

请生成结构化变体，覆盖以下类别：

【类型 A：结构合法，值极端】
- 数值字段取最大/最小/溢出值
- 字符串字段取空/超长/全特殊字符

【类型 B：结构轻微违规】
- 缺少一个必须字段
- 增加一个未定义字段
- 字段值类型错误

【类型 C：嵌套深度攻击】
- 递归嵌套到最大合理深度
- 空嵌套结构

【类型 D：编码/转义攻击】
- 格式控制字符
- Unicode 零宽字符、方向控制字符
- 转义序列边界、未终止转义

严格输出 JSON 数组，不要输出解释。每个元素格式：
{{
  "type": "A/B/C/D",
  "value": "变体内容"
}}
"""


DIVERSITY_PROMPT = """
分析上下文：
{analysis_context}
输入类型描述：{type_desc}

已生成的种子（不要生成与这些相似的）：
{existing_seeds}

相似度规则：
- 不要只改变一个字符或数字
- 不要生成结构相同但值略有不同的变体
- 必须覆盖在结构或语义层面都明显不同的情况

输出编码：{output_encoding}
如果输出编码是 `base64`，`value` 必须是完整的 base64 编码内容，对应最终要落盘的原始字节。

严格输出 JSON 数组，不要输出解释。每个元素格式：
{{
  "value": "种子内容",
  "category": "它与已有种子最不同的点"
}}

请生成 {n} 个最不相似的新种子。
"""


PYTHON_GENERATOR_PROMPT = """
你要为 fuzzing 生成一个 Python 种子生成器脚本，而不是直接给最终输入。

分析上下文：
{analysis_context}
输入类型描述：{type_desc}
输入格式：{format_name}
推荐生成策略：优先使用现有 Python 库；如果现有库不够用，就基于 baseline 样本做结构化变异。
当前环境可用的 Python 库：{available_libraries}
推荐优先尝试的库：{preferred_libraries}
baseline 文件路径：{baseline_file}

请生成一个完整 Python 脚本，要求如下：
1. 运行方式：`python generator.py OUTPUT_DIR`
2. 脚本必须在 `OUTPUT_DIR` 中生成多个初始输入文件
3. 脚本必须写出 `manifest.json`
4. `manifest.json` 格式为 JSON 对象，包含：
   - `seed_count`
   - `files`: 数组，每个元素至少包含 `file`、`category`、`notes`
5. 优先用现有库构造“结构真的合法”的样本
6. 在合法样本附近，再加入少量受控变体
7. 不要依赖网络，不要依赖当前环境里未列出的库
8. 如果没有合适库，就读取 baseline 文件并做可解释的字节级或结构级变异
9. 使用 UTF-8，输出应可直接运行
10. 如果需要生成特别长的文本输入，禁止把超长文本整段硬编码在脚本里；必须优先使用循环、字符串乘法、模板拼接、辅助函数或分段构造来节省脚本长度
11. 当文本样本可能超过 {long_text_threshold} 个字符时，优先把“重复片段”和“深层结构”抽象成参数化构造逻辑

请只输出一个 ```python fenced code block```，不要加解释。
"""


PYTHON_GENERATOR_REPAIR_PROMPT = """
你之前生成了一个用于 fuzzing 的 Python 种子生成器脚本，但它在本地执行或产物校验时失败了。

分析上下文：
{analysis_context}
输入类型描述：{type_desc}
输入格式：{format_name}
当前环境可用的 Python 库：{available_libraries}
推荐优先尝试的库：{preferred_libraries}
baseline 文件路径：{baseline_file}

运行约束保持不变：
1. 运行方式：`python generator.py OUTPUT_DIR`
2. 脚本必须在 `OUTPUT_DIR` 中生成多个初始输入文件
3. 脚本必须写出 `manifest.json`
4. `manifest.json` 格式为 JSON 对象，包含：
   - `seed_count`
   - `files`: 数组，每个元素至少包含 `file`、`category`、`notes`
5. 不要依赖网络，不要依赖当前环境里未列出的库
6. 输出应可直接运行

上一个失败脚本：
```python
{previous_code}
```

失败原因：
{failure_reason}

请修复脚本，重点解决上述失败原因，同时保留“尽量生成结构合法样本并加入少量受控变体”的目标。
请只输出一个 ```python fenced code block```，不要加解释。
"""


SYSTEM_PROMPT = """
你是一个面向 fuzzing 的高级种子生成器。
目标不是“随便举例”，而是系统性扩大输入分布覆盖面。
优先考虑边界值、结构差异、语义反常、编码异常和错误处理路径。
除非明确要求，否则不要解释，只输出用户要求的 JSON。
"""


LOGGER = logging.getLogger("llm_seed_diversifier")


@dataclass
class Dimension:
    name: str
    description: str
    boundary_direction: str


@dataclass
class SeedRecord:
    value: str
    source_stage: str
    persona: str | None = None
    dimension: str | None = None
    category: str | None = None
    notes: str | None = None
    similarity_score: float | None = None
    output_encoding: str | None = None


class SeedGenerator:
    def __init__(self, model: str, api_key: str, base_url: str | None, temperature: float):
        client_kwargs = {"api_key": api_key}
        if base_url:
            client_kwargs["base_url"] = base_url
        self.client = OpenAI(**client_kwargs)
        self.model = model
        self.temperature = temperature

    def ask_json(self, prompt: str, max_retries: int = 3) -> list[dict]:
        last_error = None
        for attempt in range(1, max_retries + 1):
            try:
                LOGGER.info("LLM request start: attempt=%d model=%s", attempt, self.model)
                LOGGER.debug("LLM prompt begin\n%s\nLLM prompt end", prompt.strip())
                response = self.client.chat.completions.create(
                    model=self.model,
                    temperature=self.temperature,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT.strip()},
                        {"role": "user", "content": prompt.strip()},
                    ],
                )
                content = response.choices[0].message.content or ""
                LOGGER.debug("LLM raw response begin\n%s\nLLM raw response end", content)
                payload = extract_json_array(content)
                LOGGER.debug(
                    "LLM parsed response begin\n%s\nLLM parsed response end",
                    json.dumps(payload, ensure_ascii=False, indent=2),
                )
                LOGGER.info("LLM request success: attempt=%d items=%d", attempt, len(payload))
                return payload
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                LOGGER.warning("LLM request failed: attempt=%d error=%s", attempt, exc)
                if attempt == max_retries:
                    break
                time.sleep(min(2 * attempt, 5))
        raise RuntimeError(f"LLM call failed after {max_retries} attempts: {last_error}")

    def ask_text(self, prompt: str, max_retries: int = 3) -> str:
        last_error = None
        for attempt in range(1, max_retries + 1):
            try:
                LOGGER.info("LLM text request start: attempt=%d model=%s", attempt, self.model)
                LOGGER.debug("LLM prompt begin\n%s\nLLM prompt end", prompt.strip())
                response = self.client.chat.completions.create(
                    model=self.model,
                    temperature=self.temperature,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT.strip()},
                        {"role": "user", "content": prompt.strip()},
                    ],
                )
                content = response.choices[0].message.content or ""
                LOGGER.debug("LLM raw response begin\n%s\nLLM raw response end", content)
                LOGGER.info("LLM text request success: attempt=%d chars=%d", attempt, len(content))
                return content
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                LOGGER.warning("LLM text request failed: attempt=%d error=%s", attempt, exc)
                if attempt == max_retries:
                    break
                time.sleep(min(2 * attempt, 5))
        raise RuntimeError(f"LLM text call failed after {max_retries} attempts: {last_error}")


def extract_json_array(text: str) -> list[dict]:
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\[.*\])\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass

    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        data = json.loads(text[start : end + 1])
        if isinstance(data, list):
            return data
    raise ValueError(f"Model did not return a valid JSON array: {text[:500]}")


def extract_python_code(text: str) -> str:
    match = re.search(r"```python\s*(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip() + "\n"
    raise ValueError(f"Model did not return a valid Python code block: {text[:500]}")


def normalize_seed_text(value: str, output_encoding: str) -> str:
    if output_encoding == "base64":
        return re.sub(r"\s+", "", value.strip())
    return re.sub(r"\s+", " ", value.strip())


def similarity(a: str, b: str, output_encoding: str) -> float:
    return SequenceMatcher(
        None,
        normalize_seed_text(a, output_encoding),
        normalize_seed_text(b, output_encoding),
    ).ratio()


def is_too_similar(
    candidate: str,
    existing: Iterable[str],
    threshold: float,
    output_encoding: str,
) -> tuple[bool, float]:
    best = 0.0
    for item in existing:
        score = similarity(candidate, item, output_encoding)
        if score > best:
            best = score
        if score >= threshold:
            return True, best
    return False, best


def trim_existing_seeds(seeds: list[SeedRecord], limit: int = 20) -> str:
    if not seeds:
        return "[]"
    sample = seeds[-limit:]
    payload = [
        {
            "value": record.value,
            "source_stage": record.source_stage,
            "dimension": record.dimension,
            "category": record.category,
        }
        for record in sample
    ]
    return json.dumps(payload, ensure_ascii=False, indent=2)


def build_analysis_context(args: argparse.Namespace) -> str:
    lines: list[str] = []
    if args.library:
        lines.append(f"库类型: {args.library}")
    if args.target_function:
        lines.append(f"实际目标函数: {args.target_function}")
    if args.call_chain:
        lines.append(f"关键调用链: {args.call_chain}")
    if args.preprocess_note:
        lines.append(f"输入预处理: {args.preprocess_note}")
    if args.signature:
        lines.append(f"入口/补充签名: {args.signature}")
    return "\n".join(lines) if lines else "未提供额外分析上下文"


def _first_non_whitespace_char(text: str) -> str | None:
    stripped = text.lstrip()
    if not stripped:
        return None
    return stripped[0]


def strip_cjson_harness_prefix(text: str) -> str:
    if len(text) < 2:
        return text
    candidate = text[2:]
    starter = _first_non_whitespace_char(candidate)
    if starter in {'{', '[', '"', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 't', 'f', 'n'}:
        return candidate
    if len(candidate) >= 2:
        nested_candidate = candidate[2:]
        nested_starter = _first_non_whitespace_char(nested_candidate)
        if nested_starter in {'{', '[', '"', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 't', 'f', 'n'}:
            return nested_candidate
    return candidate


def setup_logger(log_level: str, log_file: str | None) -> None:
    logger_level = getattr(logging, log_level.upper(), logging.INFO)
    LOGGER.setLevel(logging.DEBUG)
    LOGGER.handlers.clear()
    LOGGER.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logger_level)
    console_handler.setFormatter(formatter)
    LOGGER.addHandler(console_handler)

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        LOGGER.addHandler(file_handler)


def default_log_file(output: str) -> str:
    output_path = Path(output)
    if output_path.suffix.lower() == ".json":
        return str(output_path.with_suffix(".log"))
    return str(output_path / "meta" / "generation.log")


def output_subdirs(output_dir: Path) -> tuple[Path, Path]:
    seed_dir = output_dir / "seeds"
    meta_dir = output_dir / "meta"
    return seed_dir, meta_dir


def default_extension(format_name: str | None) -> str:
    if not format_name:
        return ".txt"
    lowered = format_name.lower()
    mapping = {
        "json": ".json",
        "xml": ".xml",
        "html": ".html",
        "yaml": ".yaml",
        "yml": ".yml",
        "csv": ".csv",
        "javascript": ".js",
        "sql": ".sql",
        "regex": ".txt",
        "proj4": ".txt",
        "transform": ".txt",
        "c_source": ".c",
        "txt": ".txt",
        "calc": ".cal",
        "png": ".png",
        "jpeg": ".jpg",
        "icc": ".icc",
        "pdf": ".pdf",
    }
    return mapping.get(lowered, ".txt")


def final_seed_bytes(record: SeedRecord, library: str | None) -> bytes:
    if record.output_encoding == "base64":
        raw = base64.b64decode(record.value, validate=False)
    else:
        raw = record.value.encode("utf-8")
    if library == "cjson":
        prefix = LIBRARY_PRESETS["cjson"].get("seed_prefix", "")
        raw = prefix.encode("ascii") + raw
    return raw


def serialize_seed_record(record: SeedRecord, library: str | None) -> dict:
    payload = asdict(record)
    raw = final_seed_bytes(record, library)
    if record.output_encoding == "base64":
        payload["value"] = base64.b64encode(raw).decode("ascii")
    else:
        payload["value"] = raw.decode("utf-8")
    return payload


def save_as_json(output_path: Path, config_payload: dict, seeds: list[SeedRecord], library: str | None) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "config": config_payload,
        "seed_count": len(seeds),
        "seeds": [serialize_seed_record(seed, library) for seed in seeds],
    }
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def save_as_directory(
    output_dir: Path,
    config_payload: dict,
    seeds: list[SeedRecord],
    format_name: str | None,
    library: str | None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    seed_dir, meta_dir = output_subdirs(output_dir)
    seed_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)
    ext = default_extension(format_name)
    manifest = {
        "config": config_payload,
        "seed_count": len(seeds),
        "files": [],
    }
    for index, record in enumerate(seeds):
        filename = f"seed_{index:04d}{ext}"
        path = seed_dir / filename
        path.write_bytes(final_seed_bytes(record, library))
        file_entry = serialize_seed_record(record, library)
        file_entry["file"] = f"seeds/{filename}"
        manifest["files"].append(file_entry)
    (meta_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def resolve_output_mode(output: Path, save_mode: str) -> str:
    if save_mode != "auto":
        return save_mode
    if output.suffix.lower() == ".json":
        return "json"
    return "dir"


def read_baseline(args: argparse.Namespace) -> str | None:
    if args.baseline_input:
        if args.library == "cjson":
            return strip_cjson_harness_prefix(args.baseline_input)
        return args.baseline_input
    if args.baseline_file:
        return read_baseline_for_prompt(Path(args.baseline_file), args.output_encoding, args.library)
    return None


def read_baseline_for_prompt(path: Path, output_encoding: str, library: str | None = None) -> str:
    raw = path.read_bytes()
    if output_encoding == "base64":
        return base64.b64encode(raw).decode("ascii")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return base64.b64encode(raw).decode("ascii")
    if library == "cjson":
        return strip_cjson_harness_prefix(text)
    return text


def detect_available_python_libraries() -> list[str]:
    candidates = ["PIL", "png", "PyPDF2", "pikepdf", "piexif", "exif", "reportlab"]
    return [name for name in candidates if find_spec(name)]


def textual_format(format_name: str | None, output_encoding: str) -> bool:
    return output_encoding == "text" and (format_name or "").lower() in TEXTUAL_FORMAT_NAMES


def dimensions_suggest_long_text(dimensions: list[Dimension]) -> bool:
    for dimension in dimensions:
        haystack = " ".join(
            [
                dimension.name.lower(),
                dimension.description.lower(),
                dimension.boundary_direction.lower(),
            ]
        )
        if any(keyword in haystack for keyword in LONG_TEXT_HINT_KEYWORDS):
            return True
    return False


def should_switch_text_to_python_generator(args: argparse.Namespace, dimensions: list[Dimension]) -> bool:
    if args.output_encoding != "text":
        return False
    if not textual_format(args.format_name, args.output_encoding):
        return False
    if not dimensions_suggest_long_text(dimensions):
        return False
    type_desc = (args.type_desc or "").lower()
    if any(token in type_desc for token in ["xml", "html", "json", "javascript", "source", "regex"]):
        return True
    return True


def execute_generated_script(script_path: Path, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [sys.executable, str(script_path), str(output_dir)],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    LOGGER.debug("Generator stdout begin\n%s\nGenerator stdout end", result.stdout)
    LOGGER.debug("Generator stderr begin\n%s\nGenerator stderr end", result.stderr)
    if result.returncode != 0:
        raise RuntimeError(
            "generated script failed with exit code "
            f"{result.returncode}\nstdout:\n{result.stdout.strip() or '(empty)'}"
            f"\nstderr:\n{result.stderr.strip() or '(empty)'}"
        )


def validate_generated_manifest(seed_dir: Path, meta_dir: Path) -> dict:
    manifest_path = seed_dir / "manifest.json"
    if not manifest_path.exists():
        raise RuntimeError(f"generated script did not create manifest.json in {seed_dir}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"generated manifest.json is invalid: {exc}") from exc

    final_manifest_path = meta_dir / "manifest.json"
    normalized_files = []
    for item in manifest.get("files", []):
        normalized = dict(item)
        file_name = str(normalized.get("file", ""))
        if file_name and not file_name.startswith("seeds/"):
            normalized["file"] = f"seeds/{file_name}"
        normalized_files.append(normalized)
    manifest["files"] = normalized_files
    final_manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest_path.unlink(missing_ok=True)
    return manifest


def run_python_generator_mode(
    args: argparse.Namespace,
    generator: SeedGenerator,
    analysis_context: str,
    output_path: Path,
    config_payload: dict,
) -> int:
    available_libraries = detect_available_python_libraries()
    preferred_libraries = []
    if args.library and args.library in LIBRARY_PRESETS:
        preferred_libraries = LIBRARY_PRESETS[args.library].get("preferred_python_libraries", [])

    generator_prompt = PYTHON_GENERATOR_PROMPT.format(
        analysis_context=analysis_context,
        type_desc=args.type_desc,
        format_name=args.format_name or "unknown",
        available_libraries=", ".join(available_libraries) if available_libraries else "(none)",
        preferred_libraries=", ".join(preferred_libraries) if preferred_libraries else "(none)",
        baseline_file=args.baseline_file or "(none)",
        long_text_threshold=args.long_text_threshold,
    )
    LOGGER.info("Python generator mode start: available_libs=%s", ",".join(available_libraries) or "(none)")
    response_text = generator.ask_text(generator_prompt)
    generator_code = extract_python_code(response_text)

    output_dir = output_path if resolve_output_mode(output_path, args.save_mode) == "dir" else output_path.with_suffix("")
    output_dir.mkdir(parents=True, exist_ok=True)
    seed_dir, meta_dir = output_subdirs(output_dir)
    seed_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)
    script_path = meta_dir / "generated_seed_generator.py"
    max_fix_attempts = max(0, args.generator_fix_attempts)
    failure_reason = None
    manifest: dict | None = None

    for attempt in range(0, max_fix_attempts + 1):
        script_path.write_text(generator_code, encoding="utf-8")
        LOGGER.info(
            "Generated Python seed generator written to %s (repair_attempt=%d/%d)",
            script_path,
            attempt,
            max_fix_attempts,
        )
        try:
            execute_generated_script(script_path, seed_dir)
            manifest = validate_generated_manifest(seed_dir, meta_dir)
            break
        except Exception as exc:  # noqa: BLE001
            failure_reason = str(exc)
            LOGGER.warning(
                "Generated script execution/validation failed: repair_attempt=%d/%d error=%s",
                attempt,
                max_fix_attempts,
                failure_reason,
            )
            if attempt >= max_fix_attempts:
                raise RuntimeError(
                    "generated script could not be repaired within "
                    f"{max_fix_attempts} attempts: {failure_reason}"
                ) from exc
            repair_prompt = PYTHON_GENERATOR_REPAIR_PROMPT.format(
                analysis_context=analysis_context,
                type_desc=args.type_desc,
                format_name=args.format_name or "unknown",
                available_libraries=", ".join(available_libraries) if available_libraries else "(none)",
                preferred_libraries=", ".join(preferred_libraries) if preferred_libraries else "(none)",
                baseline_file=args.baseline_file or "(none)",
                previous_code=generator_code,
                failure_reason=failure_reason,
            )
            repaired_text = generator.ask_text(repair_prompt)
            generator_code = extract_python_code(repaired_text)

    if manifest is None:
        raise RuntimeError(
            "generated script finished without a valid manifest, "
            f"last error: {failure_reason or 'unknown'}"
        )

    config_payload["generation_mode"] = "python-generator"
    config_payload["available_python_libraries"] = available_libraries
    config_payload["preferred_python_libraries"] = preferred_libraries
    config_payload["generated_script"] = f"meta/{script_path.name}"
    config_payload["generator_fix_attempts"] = max_fix_attempts

    if output_path.suffix.lower() == ".json":
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "config": config_payload,
            "generator_script": str(script_path),
            "artifact_dir": str(output_dir),
            "manifest": manifest,
        }
        output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    LOGGER.info(
        "Python generator mode finished: seed_count=%s seed_dir=%s meta_dir=%s",
        manifest.get("seed_count", "unknown"),
        seed_dir,
        meta_dir,
    )
    print(f"generated {manifest.get('seed_count', 'unknown')} seeds -> {output_dir}")
    return 0


def merge_preset_args(args: argparse.Namespace) -> argparse.Namespace:
    if not args.library:
        return args
    preset = LIBRARY_PRESETS.get(args.library)
    if not preset:
        known = ", ".join(sorted(LIBRARY_PRESETS))
        raise SystemExit(f"unknown library '{args.library}', known libraries: {known}")
    if not args.signature:
        args.signature = preset["signature"]
    if not args.target_function:
        args.target_function = preset.get("target_function")
    if not args.call_chain:
        args.call_chain = preset.get("call_chain")
    if not args.type_desc:
        args.type_desc = preset["type_desc"]
    if not args.format_name:
        args.format_name = preset["format_name"]
    if not args.output_encoding:
        args.output_encoding = preset["output_encoding"]
    if not args.baseline_file and not args.baseline_input:
        args.baseline_file = preset["baseline_file"]
    if not args.generation_mode:
        args.generation_mode = preset.get("generation_mode")
    if not args.preprocess_note and preset.get("preprocess_note"):
        args.preprocess_note = preset["preprocess_note"]
    return args


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="用大模型按维度和多视角生成多样化初始输入种子。"
    )
    parser.add_argument("--library", choices=sorted(LIBRARY_PRESETS), help="按库种类套用预设。")
    parser.add_argument("--signature", help="兼容旧参数：入口签名或概括性签名。")
    parser.add_argument("--target-function", help="实际消费输入的目标函数签名。")
    parser.add_argument("--call-chain", help="关键调用链摘要，例如 A -> B -> C。")
    parser.add_argument("--preprocess-note", help="输入预处理说明，例如解压、转码、去头、切片。")
    parser.add_argument("--type-desc", help="输入类型描述。")
    parser.add_argument("--output", required=True, help="输出 JSON 文件或输出目录。")
    parser.add_argument("--model", default=os.getenv("SEED_LLM_MODEL", os.getenv("OPENAI_MODEL", "qwen3-max")))
    parser.add_argument("--api-key", default=os.getenv("SEED_LLM_API_KEY", os.getenv("OPENAI_API_KEY")))
    parser.add_argument("--base-url", default=os.getenv("SEED_LLM_BASE_URL", os.getenv("OPENAI_BASE_URL")))
    parser.add_argument("--temperature", type=float, default=0.8, help="生成温度。")
    parser.add_argument("--per-dimension", type=int, default=3, help="每个维度每个 persona 生成的种子数。")
    parser.add_argument("--extra-diverse", type=int, default=8, help="最后一轮多样性补充生成数。")
    parser.add_argument("--max-dimensions", type=int, default=8, help="最多处理多少个维度。")
    parser.add_argument("--long-text-threshold", type=int, default=4096, help="文本 seed 超过该长度时优先切换到 Python 生成器模式。")
    parser.add_argument("--generator-fix-attempts", type=int, default=2, help="Python 生成器脚本失败后，最多尝试让大模型修复几次。")
    parser.add_argument("--similarity-threshold", type=float, default=0.90, help="相似度阈值，超过则丢弃。")
    parser.add_argument("--save-mode", choices=["auto", "json", "dir"], default="auto")
    parser.add_argument(
        "--generation-mode",
        choices=["auto", "direct", "python-generator"],
        help="生成模式：直接生成 seed，或先生成 Python 生成器脚本。",
    )
    parser.add_argument("--log-file", help="日志文件路径；默认跟随输出路径生成。")
    parser.add_argument("--log-level", default="INFO", help="日志级别，例如 DEBUG/INFO/WARNING。")
    parser.add_argument("--format-name", help="结构化格式名，如 json/xml/html。")
    parser.add_argument(
        "--output-encoding",
        choices=["text", "base64"],
        help="种子输出编码。文本库一般用 text；二进制库建议用 base64。",
    )
    parser.add_argument("--baseline-input", help="结构化输入的基准合法样例。")
    parser.add_argument("--baseline-file", help="从文件读取结构化基准输入。")
    parser.add_argument(
        "--persona",
        action="append",
        default=[],
        help="可重复传入，追加自定义 persona；不传时使用内置 personas。",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    args = merge_preset_args(args)
    if not args.log_file:
        args.log_file = default_log_file(args.output)
    setup_logger(args.log_level, args.log_file)

    if not args.api_key:
        parser.error("缺少 API key，请通过 --api-key 或环境变量 OPENAI_API_KEY / SEED_LLM_API_KEY 提供。")
    if not args.signature:
        parser.error("缺少 signature，请通过 --signature 提供，或使用 --library 自动套用。")
    if not args.type_desc:
        parser.error("缺少 type-desc，请通过 --type-desc 提供，或使用 --library 自动套用。")
    if not args.output_encoding:
        args.output_encoding = "text"
    if not args.generation_mode:
        args.generation_mode = "direct"
    if args.generation_mode == "auto":
        args.generation_mode = LIBRARY_PRESETS.get(args.library, {}).get("generation_mode", "direct")

    analysis_context = build_analysis_context(args)
    LOGGER.info(
        "Start generation: library=%s model=%s output=%s format=%s encoding=%s",
        args.library,
        args.model,
        args.output,
        args.format_name,
        args.output_encoding,
    )
    LOGGER.info("Generation mode: %s", args.generation_mode)
    LOGGER.info(
        "Generation config: per_dimension=%d extra_diverse=%d max_dimensions=%d similarity_threshold=%.2f personas=%d",
        args.per_dimension,
        args.extra_diverse,
        args.max_dimensions,
        args.similarity_threshold,
        len(DEFAULT_PERSONAS + args.persona if args.persona else DEFAULT_PERSONAS),
    )
    LOGGER.debug("Analysis context:\n%s", analysis_context)

    generator = SeedGenerator(
        model=args.model,
        api_key=args.api_key,
        base_url=args.base_url,
        temperature=args.temperature,
    )

    baseline_input = read_baseline(args)
    if args.baseline_file:
        LOGGER.info("Using baseline file: %s", args.baseline_file)
    personas = DEFAULT_PERSONAS + args.persona if args.persona else DEFAULT_PERSONAS

    early_config_payload = {
        "signature": args.signature,
        "target_function": args.target_function,
        "call_chain": args.call_chain,
        "preprocess_note": args.preprocess_note,
        "type_desc": args.type_desc,
        "library": args.library,
        "model": args.model,
        "format_name": args.format_name,
        "generation_mode": args.generation_mode,
        "output_encoding": args.output_encoding,
        "per_dimension": args.per_dimension,
        "extra_diverse": args.extra_diverse,
        "max_dimensions": args.max_dimensions,
        "long_text_threshold": args.long_text_threshold,
        "generator_fix_attempts": args.generator_fix_attempts,
        "similarity_threshold": args.similarity_threshold,
        "personas": personas,
    }

    if args.generation_mode == "python-generator":
        return run_python_generator_mode(args, generator, analysis_context, Path(args.output), early_config_payload)

    dimension_prompt = DIMENSION_PROMPT.format(
        analysis_context=analysis_context,
        type_desc=args.type_desc,
    )
    raw_dimensions = generator.ask_json(dimension_prompt)
    dimensions: list[Dimension] = []
    for item in raw_dimensions:
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        dimensions.append(
            Dimension(
                name=name,
                description=str(item.get("description", "")).strip(),
                boundary_direction=str(item.get("boundary_direction", "")).strip(),
            )
        )
    dimensions = dimensions[: args.max_dimensions]
    LOGGER.info("Dimension discovery complete: total=%d", len(dimensions))
    for index, dimension in enumerate(dimensions, start=1):
        LOGGER.debug(
            "Dimension %d: name=%s boundary=%s desc=%s",
            index,
            dimension.name,
            dimension.boundary_direction,
            dimension.description,
        )

    if args.generation_mode == "direct" and should_switch_text_to_python_generator(args, dimensions):
        LOGGER.info(
            "Switching to python-generator mode due to likely long text generation: format=%s threshold=%d",
            args.format_name,
            args.long_text_threshold,
        )
        early_config_payload["generation_mode"] = "python-generator"
        early_config_payload["dimensions"] = [asdict(item) for item in dimensions]
        return run_python_generator_mode(args, generator, analysis_context, Path(args.output), early_config_payload)

    accepted: list[SeedRecord] = []
    accepted_values: list[str] = []

    def maybe_add_seed(record: SeedRecord) -> None:
        value = normalize_seed_text(record.value, args.output_encoding)
        if not value:
            LOGGER.debug("Discard empty seed: stage=%s dimension=%s", record.source_stage, record.dimension)
            return
        too_similar, best_score = is_too_similar(
            value,
            accepted_values,
            args.similarity_threshold,
            args.output_encoding,
        )
        if too_similar:
            LOGGER.debug(
                "Discard similar seed: stage=%s dimension=%s similarity=%.3f",
                record.source_stage,
                record.dimension,
                best_score,
            )
            return
        if args.output_encoding == "base64":
            try:
                base64.b64decode(value, validate=False)
            except Exception:  # noqa: BLE001
                LOGGER.debug("Discard invalid base64 seed: stage=%s dimension=%s", record.source_stage, record.dimension)
                return
        record.value = value
        record.similarity_score = best_score
        record.output_encoding = args.output_encoding
        accepted.append(record)
        accepted_values.append(value)
        LOGGER.debug(
            "Accept seed: stage=%s dimension=%s category=%s total=%d similarity=%.3f",
            record.source_stage,
            record.dimension,
            record.category,
            len(accepted),
            best_score,
        )

    for persona in personas:
        LOGGER.info("Persona start: %s", persona)
        for dimension in dimensions:
            before_count = len(accepted)
            LOGGER.info("Dimension generation start: persona=%s dimension=%s", persona, dimension.name)
            prompt = f"{persona}\n\n" + SEED_PER_DIMENSION_PROMPT.format(
                type_desc=args.type_desc,
                analysis_context=analysis_context,
                dimension_name=dimension.name,
                dimension_desc=dimension.description,
                boundary_direction=dimension.boundary_direction,
                existing_seeds=trim_existing_seeds(accepted),
                output_encoding=args.output_encoding,
                n=args.per_dimension,
            )
            items = generator.ask_json(prompt)
            for item in items:
                maybe_add_seed(
                    SeedRecord(
                        value=str(item.get("value", "")).strip(),
                        source_stage="per_dimension",
                        persona=persona,
                        dimension=dimension.name,
                        category=str(item.get("category", "")).strip() or None,
                        notes=str(item.get("notes", "")).strip() or None,
                    )
                )
            LOGGER.info(
                "Dimension generation done: persona=%s dimension=%s accepted_delta=%d total=%d",
                persona,
                dimension.name,
                len(accepted) - before_count,
                len(accepted),
            )

    if args.format_name and baseline_input:
        before_count = len(accepted)
        LOGGER.info("Structural mutation start: format=%s", args.format_name)
        items = generator.ask_json(
            STRUCTURAL_MUTATION_PROMPT.format(
                format_name=args.format_name,
                analysis_context=analysis_context,
                type_desc=args.type_desc,
                baseline_input=baseline_input,
                output_encoding=args.output_encoding,
            )
        )
        for item in items:
            maybe_add_seed(
                SeedRecord(
                    value=str(item.get("value", "")).strip(),
                    source_stage="structural_mutation",
                    category=str(item.get("type", "")).strip() or None,
                    )
                )
        LOGGER.info(
            "Structural mutation done: accepted_delta=%d total=%d",
            len(accepted) - before_count,
            len(accepted),
        )

    if args.extra_diverse > 0:
        before_count = len(accepted)
        LOGGER.info("Diversity sweep start: request=%d", args.extra_diverse)
        items = generator.ask_json(
            DIVERSITY_PROMPT.format(
                analysis_context=analysis_context,
                type_desc=args.type_desc,
                existing_seeds=trim_existing_seeds(accepted, limit=40),
                output_encoding=args.output_encoding,
                n=args.extra_diverse,
                    )
                )
        LOGGER.info(
            "Diversity sweep done: accepted_delta=%d total=%d",
            len(accepted) - before_count,
            len(accepted),
        )
        for item in items:
            maybe_add_seed(
                SeedRecord(
                    value=str(item.get("value", "")).strip(),
                    source_stage="diversity_sweep",
                    category=str(item.get("category", "")).strip() or None,
                )
            )

    output_path = Path(args.output)
    save_mode = resolve_output_mode(output_path, args.save_mode)
    config_payload = {
        **early_config_payload,
        "dimensions": [asdict(item) for item in dimensions],
    }

    if save_mode == "json":
        save_as_json(output_path, config_payload, accepted, args.library)
    else:
        save_as_directory(output_path, config_payload, accepted, args.format_name, args.library)

    LOGGER.info("Generation finished: seeds=%d output=%s log=%s", len(accepted), output_path, args.log_file)
    print(f"generated {len(accepted)} seeds -> {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
