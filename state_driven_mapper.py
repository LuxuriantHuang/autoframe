"""
state_driven_mapper.py - 状态驱动型程序的输入映射方案

针对像 lcms 这样存在多层状态转换的程序：
- 输入 → 解析器 → 内部状态 → 业务逻辑
- 污点分析只能追踪到"输入影响状态"，无法建立精确字节映射

解决方案：
1. 代码切片分析：理解解析逻辑
2. 状态变量推断：识别状态变量的来源
3. 解析器逆向：从状态变量回溯到输入偏移
4. LLM 语义增强：理解格式规范和状态含义
"""

import hashlib
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import ujson

from config import LOGGER_NAME, PROJECT_HOME, SEED_PATH, PROJECT, prompts, get_formatted_user_prompt
from LLM.LLMUtil import LLMUtil

logger = logging.getLogger(LOGGER_NAME + __name__)


# ============================================================
# 第一层：解析器模式识别
# ============================================================

class ParserPatternExtractor:
    """从代码切片中提取解析器模式"""

    def __init__(self, code_slice: str):
        self.code_slice = code_slice

    def extract_parser_logic(self) -> List[Dict[str, Any]]:
        """提取输入解析的逻辑模式

        识别如：
        - 直接读取：profile->field = *(uint32_t*)(input + offset)
        - 函数调用：profile->field = read_uint32_be(input + offset)
        - 宏调用：READ_FIELD(input, offset, &profile->field)
        """
        patterns = []

        lines = self.code_slice.split('\n')

        for i, line in enumerate(lines):
            # 模式1: 直接指针解引用读取
            direct_match = re.search(
                r'(\w+(?:->\w+)*)\s*=\s*\*(?:\(\s*\w+\s*\*\s*\))?'
                r'(?:input|buf|data|ptr)\s*\[\s*(\w+)\s*\]\s*;',
                line
            )
            if direct_match:
                patterns.append({
                    'type': 'direct_read',
                    'target_var': direct_match.group(1),
                    'offset_var': direct_match.group(2),
                    'line': line.strip(),
                    'line_num': i
                })

            # 模式2: 带偏移的指针读取
            offset_match = re.search(
                r'(\w+(?:->\w+)*)\s*=\s*\*\(\s*\w+\s*\*\s*\)'
                r'(?:\(?input|buf|data|ptr\)?\s*\+\s*(\d+))\);',
                line
            )
            if offset_match:
                patterns.append({
                    'type': 'offset_read',
                    'target_var': offset_match.group(1),
                    'offset': int(offset_match.group(2)),
                    'line': line.strip(),
                    'line_num': i
                })

            # 模式3: 函数调用读取
            func_match = re.search(
                r'(\w+(?:->\w+)*)\s*=\s*(\w+)\s*\('
                r'(?:input|buf|data|ptr)\s*,\s*(\d+|\w+)\s*\);',
                line
            )
            if func_match and func_match.group(2) not in ['printf', 'memcpy', 'memset']:
                patterns.append({
                    'type': 'function_read',
                    'target_var': func_match.group(1),
                    'function': func_match.group(2),
                    'offset_or_param': func_match.group(3),
                    'line': line.strip(),
                    'line_num': i
                })

            # 模式4: 宏调用
            macro_match = re.search(
                r'(\w+(?:->\w+)*)\s*=\s*([A-Z_]+)\s*\('
                r'[^)]*\);',
                line
            )
            if macro_match:
                patterns.append({
                    'type': 'macro_read',
                    'target_var': macro_match.group(1),
                    'macro': macro_match.group(2),
                    'line': line.strip(),
                    'line_num': i
                })

        return patterns

    def extract_state_variables(self) -> List[Dict[str, Any]]:
        """提取状态变量定义

        识别结构体字段、全局变量等
        """
        state_vars = []

        # 匹配结构体字段访问模式
        struct_pattern = re.compile(
            r'(\w+)\s*->\s*(\w+)(?:\s*\[\s*(\d+)\s*\])?'
        )

        for match in struct_pattern.finditer(self.code_slice):
            base = match.group(1)  # 如 profile, hprofile
            field = match.group(2)  # 如 data_color_space
            index = match.group(3)  # 数组索引

            # 过滤掉常见非状态变量
            if base not in ['input', 'data', 'buffer', 'buf', 'ptr']:
                state_vars.append({
                    'full_name': f"{base}->{field}" + (f"[{index}]" if index else ""),
                    'base': base,
                    'field': field,
                    'index': index,
                    'access_count': 0  # 稍后统计访问次数
                })

        # 统计访问频率，识别高频状态变量
        code_lower = self.code_slice.lower()
        for var in state_vars:
            var['access_count'] = code_lower.count(var['full_name'].lower())

        # 按访问频率排序
        state_vars.sort(key=lambda x: x['access_count'], reverse=True)

        return state_vars[:20]  # 返回前20个

    def find_parser_function(self, target_var: str) -> Optional[Dict[str, Any]]:
        """查找负责解析特定变量的函数

        在代码切片中寻找将输入数据赋值给目标变量的代码
        """
        lines = self.code_slice.split('\n')

        for i, line in enumerate(lines):
            # 查找赋值语句
            if f'{target_var}=' in line or f'{target_var} =' in line:
                # 提取右边的表达式
                parts = line.split('=')
                if len(parts) >= 2:
                    rhs = parts[1].strip()

                    # 分析右边的表达式
                    return {
                        'line_num': i,
                        'line': line.strip(),
                        'expression': rhs,
                        'likely_parser': self._classify_parser(rhs)
                    }

        return None

    def _classify_parser(self, expression: str) -> str:
        """分类解析器类型"""
        if 'input' in expression or 'buf' in expression or 'data' in expression:
            if '+' in expression:
                # 检查是否包含十六进制或数字
                hex_and_numbers = ['0x'] + [str(d) for d in range(100)]
                if any(x in expression for x in hex_and_numbers):
                    return 'offset_based_parser'
            if '(' in expression:
                return 'function_parser'
            else:
                return 'direct_parser'
        return 'unknown_parser'


# ============================================================
# 第二层：LLM 增强的状态-输入映射
# ============================================================

class StateInputMapper:
    """使用 LLM 建立状态变量与输入的映射"""

    def __init__(self, llm_util: LLMUtil):
        self.llm_util = llm_util

    def infer_state_to_input_mapping(
        self,
        code_slice: str,
        roadblock: Dict[str, Any],
        state_vars: List[Dict[str, Any]],
        parser_patterns: List[Dict[str, Any]],
        sample_seed: bytes,
        known_format_info: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """推断状态变量与输入字节的映射关系

        Args:
            code_slice: 代码切片
            roadblock: 目标分支信息
            state_vars: 状态变量列表
            parser_patterns: 解析器模式
            sample_seed: 示例输入
            known_format_info: 已知的格式信息（如有）

        Returns:
            状态变量到输入的映射关系
        """
        logger.info("[STATE_MAP] Inferring state-to-input mappings...")

        # 构建 prompt
        prompt = self._build_mapping_prompt(
            code_slice=code_slice,
            roadblock=roadblock,
            state_vars=state_vars,
            parser_patterns=parser_patterns,
            sample_seed=sample_seed,
            known_format_info=known_format_info or {}
        )

        messages = [
            {'role': 'system', 'content': self._get_system_prompt()},
            {'role': 'user', 'content': prompt}
        ]

        try:
            max_retries = 3
            for attempt in range(max_retries):
                response = self.llm_util.get_response(messages)
                result = self._parse_mapping_response(response, state_vars)
                if result.get('state_mappings') is not None:
                    return result

                if attempt < max_retries - 1:
                    messages.append({'role': 'assistant', 'content': response})
                    messages.append({
                        'role': 'user',
                        'content': '请只返回一个 JSON object，并包含列表字段 state_mappings。'
                    })

        except Exception as e:
            logger.error(f"[STATE_MAP] LLM inference failed: {e}")
            return self._fallback_mapping(state_vars, parser_patterns)

        return self._fallback_mapping(state_vars, parser_patterns)

    def _get_system_prompt(self) -> str:
        return prompts['prompt']['state_input_mapping']['sys_prompt']
    def _build_mapping_prompt(
        self,
        code_slice: str,
        roadblock: Dict[str, Any],
        state_vars: List[Dict[str, Any]],
        parser_patterns: List[Dict[str, Any]],
        sample_seed: bytes,
        known_format_info: Dict[str, Any]
    ) -> str:
        """构建映射推断的 prompt"""

        # 代码切片（限制长度）
        code_preview = code_slice[:2000]

        # 状态变量（前10个）
        state_desc = []
        for var in state_vars[:10]:
            state_desc.append(
                f"- {var['full_name']} (访问次数: {var['access_count']})"
            )

        # 解析器模式
        parser_desc = []
        for pattern in parser_patterns[:10]:
            parser_desc.append(
                f"- {pattern['type']}: {pattern.get('line', '')[:80]}"
            )

        # 输入样本（前64字节）
        sample_hex = sample_seed[:64].hex()
        sample_formatted = ' '.join([
            sample_hex[i:i+2] for i in range(0, min(128, len(sample_hex)), 2)
        ])

        # 已知格式信息
        format_info = known_format_info.get('format_info', {})
        format_desc = ""
        if format_info.get('format_type'):
            format_desc = f"\n**已知格式**: {format_info['format_type']}"
            if format_info.get('category'):
                format_desc += f" (类别: {format_info['category']})"

        return get_formatted_user_prompt(
            'state_input_mapping',
            filename=roadblock.get('filename'),
            line=roadblock.get('line'),
            branch_code=roadblock.get('code', 'unknown'),
            status=roadblock.get('status', 'unknown'),
            format_desc=format_desc,
            code_preview=code_preview,
            state_variables=chr(10).join(state_desc) if state_desc else '（未识别）',
            parser_patterns=chr(10).join(parser_desc) if parser_desc else '（未识别）',
            sample_preview=sample_formatted,
        )

    def _parse_mapping_response(
        self,
        response: str,
        state_vars: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """解析 LLM 的响应"""
        try:
            # 提取 JSON
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
            if json_match:
                response = json_match.group(1)

            result = ujson.loads(response)
            if not isinstance(result, dict):
                raise ValueError(f"mapping result must be a JSON object, got {type(result).__name__}")
            if 'state_mappings' not in result:
                raise ValueError("missing required key: state_mappings")
            if not isinstance(result['state_mappings'], list):
                raise ValueError("state_mappings must be a list")

            # 验证和增强结果
            if 'state_mappings' in result:
                # 检查是否匹配已知状态变量
                state_var_names = {v['full_name'] for v in state_vars}

                for mapping in result['state_mappings']:
                    state_var = mapping.get('state_variable', '')

                    # 标记是否是高频状态变量
                    if state_var in state_var_names:
                        mapping['is_frequent_state_var'] = True

                        # 查找访问次数
                        for sv in state_vars:
                            if sv['full_name'] == state_var:
                                mapping['access_count'] = sv['access_count']
                                break
                    else:
                        mapping['is_frequent_state_var'] = False

                logger.info(
                    f"[STATE_MAP] Parsed {len(result['state_mappings'])} mappings, "
                    f"{sum(1 for m in result['state_mappings'] if m.get('is_frequent_state_var'))} "
                    f"match frequent state vars"
                )

            return result

        except Exception as e:
            logger.warning(f"[STATE_MAP] Failed to parse response: {e}")
            return {}

    def _fallback_mapping(
        self,
        state_vars: List[Dict[str, Any]],
        parser_patterns: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """回退方案：使用启发式规则"""
        mappings = []

        # 从解析器模式提取信息
        for pattern in parser_patterns:
            if pattern['type'] == 'offset_read':
                mappings.append({
                    'state_variable': pattern['target_var'],
                    'input_offset': pattern['offset'],
                    'input_size': 4,  # 默认4字节
                    'semantic_name': pattern['target_var'].split('->')[-1],
                    'byte_order': 'unknown',
                    'offset_confidence': 0.7,
                    'reasoning': 'From code pattern analysis'
                })

        return {
            'state_mappings': mappings,
            'format_structure': 'Inferred from code patterns',
            'parsing_strategy': 'pattern_based'
        }


# ============================================================
# 第三层：结合已知格式规范的增强
# ============================================================

class FormatSpecEnhancer:
    """使用已知格式规范增强映射"""

    # ICC Profile 标准偏移
    ICC_PROFILE_OFFSETS = {
        'profile_size': (8, 12, 'uint32_be'),
        'device_class': (12, 16, 'enum4'),
        'color_space': (16, 20, 'enum4'),
        'pcs': (20, 24, 'enum4'),
        'date': (24, 36, 'datetime'),
        'magic': (36, 40, 'magic4'),
        'platform': (40, 44, 'enum4'),
        'flags': (44, 48, 'uint32'),
        'manufacturer': (48, 52, 'enum4'),
        'model': (52, 56, 'enum4'),
        'attributes': (56, 60, 'uint64'),
        'rendering_intent': (64, 68, 'enum'),
        'illuminant': (68, 84, 'xyz_number'),
    }

    # PNG 标准偏移
    PNG_SIGNATURE = (0, 8, 'magic')
    PNG_IHDR_WIDTH = (16, 20, 'uint32_be')
    PNG_IHDR_HEIGHT = (20, 24, 'uint32_be')

    @classmethod
    def enhance_with_specs(
        cls,
        mappings: Dict[str, Any],
        format_type: str
    ) -> Dict[str, Any]:
        """使用格式规范增强映射"""
        if format_type.upper() in ['ICC', 'ICCPROFILE', 'LCMS']:
            return cls._enhance_icc(mappings)
        elif format_type.upper() == 'PNG':
            return cls._enhance_png(mappings)
        else:
            return mappings

    @classmethod
    def _enhance_icc(cls, mappings: Dict[str, Any]) -> Dict[str, Any]:
        """增强 ICC Profile 映射"""
        enhanced = {'state_mappings': []}

        # 添加标准偏移
        for field_name, (start, end, field_type) in cls.ICC_PROFILE_OFFSETS.items():
            enhanced['state_mappings'].append({
                'state_variable': f'profile->{field_name}',
                'input_offset': start,
                'input_size': end - start,
                'semantic_name': field_name,
                'byte_order': 'big',
                'offset_confidence': 0.95,
                'reasoning': 'ICC Profile specification',
                'field_type': field_type,
                'from_spec': True
            })

        # 合并 LLM 推断的结果
        for mapping in mappings.get('state_mappings', []):
            # 检查是否与规范冲突
            conflict = False
            for spec_mapping in enhanced['state_mappings']:
                if (mapping.get('state_variable') == spec_mapping['state_variable'] and
                    mapping.get('input_offset') != spec_mapping['input_offset']):
                    conflict = True
                    # 使用规范的偏移，但保留 LLM 的推理
                    spec_mapping['llm_reasoning'] = mapping.get('reasoning', '')
                    break

            if not conflict:
                enhanced['state_mappings'].append(mapping)

        enhanced['format_structure'] = 'ICC Profile (with standard offsets)'
        enhanced['parsing_strategy'] = 'spec_based'

        return enhanced

    @classmethod
    def _enhance_png(cls, mappings: Dict[str, Any]) -> Dict[str, Any]:
        """增强 PNG 映射"""
        # PNG 的实现...
        return mappings


# ============================================================
# 主类：状态驱动映射器
# ============================================================

class StateDrivenMapper:
    """状态驱动型程序的映射器

    针对像 lcms 这样的程序，通过多层分析建立状态-输入映射
    """

    def __init__(self, llm_util: LLMUtil):
        self.llm_util = llm_util

    def analyze(
        self,
        code_slice: str,
        roadblock: Dict[str, Any],
        sample_seed_path: Path,
        taint_info: Dict[str, Any] = None,
        known_format_info: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """执行完整的状态驱动映射分析"""

        logger.info("[STATE_DRIVER] Starting state-driven mapping analysis...")

        # 读取样本
        try:
            with open(sample_seed_path, 'rb') as f:
                sample_seed = f.read()
        except Exception as e:
            logger.error(f"[STATE_DRIVER] Failed to read sample: {e}")
            return None

        # 第一层：提取解析器模式和状态变量
        extractor = ParserPatternExtractor(code_slice)

        parser_patterns = extractor.extract_parser_logic()
        logger.info(f"[STATE_DRIVER] Found {len(parser_patterns)} parser patterns")

        state_vars = extractor.extract_state_variables()
        logger.info(f"[STATE_DRIVER] Found {len(state_vars)} state variables")

        # 第二层：LLM 推断映射
        mapper = StateInputMapper(self.llm_util)

        mappings = mapper.infer_state_to_input_mapping(
            code_slice=code_slice,
            roadblock=roadblock,
            state_vars=state_vars,
            parser_patterns=parser_patterns,
            sample_seed=sample_seed,
            known_format_info=known_format_info
        )

        # 第三层：使用格式规范增强
        if known_format_info:
            format_type = known_format_info.get('format_info', {}).get('format_type', '')
            if format_type:
                logger.info(f"[STATE_DRIVER] Enhancing with {format_type} format spec")
                mappings = FormatSpecEnhancer.enhance_with_specs(
                    mappings, format_type
                )

        # 添加元数据
        mappings['analysis_metadata'] = {
            'sample_size': len(sample_seed),
            'sample_hash': hashlib.md5(sample_seed).hexdigest()[:8],
            'num_state_vars': len(state_vars),
            'num_parser_patterns': len(parser_patterns),
            'format_type': known_format_info.get('format_info', {}).get('format_type', 'unknown')
        }

        logger.info("[STATE_DRIVER] Analysis completed")
        return mappings

    def generate_mutation_script(
        self,
        mappings: Dict[str, Any],
        constraints: List[str],
        output_path: Path
    ) -> str:
        """基于状态驱动映射生成变异脚本"""

        if not mappings or 'state_mappings' not in mappings:
            return ""

        mapping_details = []

        # 添加映射信息
        for mapping in mappings['state_mappings'][:10]:
            from_spec = " ✓(规范)" if mapping.get('from_spec') else ""
            mapping_details.append(f"""
**{mapping['state_variable']}**{from_spec}
- 输入偏移: {mapping['input_offset']} - {mapping['input_offset'] + mapping['input_size']}
- 字节序: {mapping.get('byte_order', 'unknown')}
- 类型: {mapping.get('field_type', 'unknown')}
- 推理: {mapping.get('reasoning', 'N/A')}
""")

        prompt = get_formatted_user_prompt(
            'state_input_mapping_script_generation',
            mapping_details=''.join(mapping_details) if mapping_details else '（无可用映射）',
            format_structure=mappings.get('format_structure', 'N/A'),
            constraints=chr(10).join(f'- {c}' for c in constraints[:5]) if constraints else '（无额外约束）',
        )

        try:
            response = self.llm_util.get_response([
                {'role': 'system', 'content': prompts['prompt']['state_input_mapping_script_generation']['sys_prompt']},
                {'role': 'user', 'content': prompt}
            ])

            return response

        except Exception as e:
            logger.error(f"[STATE_DRIVER] Script generation failed: {e}")
            return ""

    def get_mapping_summary(self, mappings: Dict[str, Any]) -> str:
        """获取映射摘要"""
        if not mappings:
            return "No mappings available"

        parts = []

        parts.append(f"## 状态驱动映射 ({len(mappings.get('state_mappings', []))} 个状态变量)")

        for mapping in mappings['state_mappings'][:8]:
            spec_marker = " [规范]" if mapping.get('from_spec') else ""
            conf = mapping.get('offset_confidence', 0)
            parts.append(
                f"- 偏移 {mapping['input_offset']}: "
                f"{mapping['state_variable']}{spec_marker} "
                f"(置信度: {conf:.2f})"
            )

        if mappings.get('format_structure'):
            parts.append(f"\n格式: {mappings['format_structure']}")

        return "\n".join(parts)
