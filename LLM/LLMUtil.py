import logging
import os
import re
import subprocess
from pathlib import Path

from openai import OpenAI

import config
from Excep.ScriptExtractError import ScriptExtractError
from Excep.ScriptNotFoundError import ScriptNotFoundError
from config import LOGGER_NAME
from prompt_constructor import *
from pyTracer.CodeHeat import CodeHeat
from pyTracer.InfoProcessor import Bitmap
from pyTracer.SeedTracer import SeedTracer

logger = logging.getLogger(LOGGER_NAME + __name__)


def get_message(user_prompt):
    return [{
        "role": "system",
        "content": get_sys_prompt()
    }, {
        "role": "user",
        "content": user_prompt
    }]


def message_with_prefix(user_prompt):
    chat_messages = get_message(user_prompt)

    if "deepseek" in config.model:
        chat_messages.append({
            'role': 'assistant',
            'content': get_prefix(),
            'prefix': True
        })
    elif "qwen" in config.model or "kimi" in config.model:
        chat_messages.append({
            'role': 'assistant',
            'content': get_prefix(),
            'partial': True
        })

    return chat_messages


def extract_generator(generator_text):
    code_pattern = r"```python(.*?)```"
    code_match = re.search(code_pattern, generator_text, re.DOTALL)

    if not code_match:
        raise ScriptNotFoundError("生成文本中未找到有效的Python代码块")

    raw_code = code_match.group(1).strip()
    return raw_code


def run_generator(generator, bottleneck_id, id):
    # 将generator代码写入.py文件中
    file_path = os.path.join(config.PROJECT_HOME, 'generator.py')
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(generator)

    new_seed_path = os.path.join(config.LLM_TMP_PATH, f"id:{int(id):06},bid:{int(bottleneck_id):06}")
    # 使用 subprocess 运行文件并捕获输出
    try:
        # 运行命令，捕获标准输出和标准错误
        result = subprocess.run(
            ["python", file_path, new_seed_path],  # 执行的命令
            text=True,  # 以文本形式返回输出
            capture_output=True,  # 捕获标准输出和标准错误
            encoding="utf-8"  # 显式指定编码为 UTF-8
        )
        return result.stdout, result.stderr, new_seed_path
    except Exception as e:
        logger.error(f"运行generator代码的子线程异常: {e}")
        raise ScriptExtractError("运行generator代码的子线程异常")


def get_coverage_report_by_trace(execution_path, call_chain):
    function_coverage = ""
    code_heat = CodeHeat()
    code_heat.merge(execution_path, config.bbs)
    for fname in call_chain:
        f = next((item for item in config.funcs if item.get("name") == fname), None)
        filename = f['file_name']
        start = f['lineStart']
        end = f['lineEnd']
        fid = f['id']
        with open(Path(config.PROJECT_HOME) / "src" / filename) as f:
            code = [line.rstrip('\n') for line in f.readlines()]
        file_heat = code_heat.code_heat[filename]
        # print(code)
        # print(file_heat)
        for key in file_heat:
            code[key - 1] += f'  // coverage: {file_heat[key]}'

        function_snippet_list = code[start - 1:end]
        function_snippet = '\n'.join(function_snippet_list)
        function_coverage += function_snippet
        function_coverage += '\n\n'
    return function_coverage


def get_coverage_report(execution_path, call_chain):
    return get_coverage_report_by_trace(execution_path, call_chain)


class LLMUtil:
    def __init__(self, model, key, base_url):
        self.model = model
        self.client = OpenAI(api_key=key, base_url=base_url)

    def get_response(self, messages, temp=0, suffix=None):
        if suffix is None:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                stream=False,
                temperature=temp
            )
        else:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                stream=False,
                temperature=temp,
                stop=[suffix]
            )
        return response.choices[0].message.content

    def first_chat(self, code_snippet, callee, bcode):
        prompt = first_prompt(code_snippet, callee, bcode)
        chat_messages = message_with_prefix(prompt)
        return self.get_response(chat_messages, get_suffix())

    def fix_chat(self, generator, stderr):
        prompt = fix_prompt(generator, stderr)
        chat_messages = message_with_prefix(prompt)
        return self.get_response(chat_messages, get_suffix())

    def no_cover_chat(self, generator, coverage, bottleneck_code, funcname):
        prompt = both_no_cover_improve_prompt(generator, coverage, bottleneck_code, funcname)
        chat_messages = get_message(prompt)
        return self.get_response(chat_messages)

    def no_break_chat(self, generator, coverage, bottleneck_code, funcname, not_cover):
        prompt = breakthrough_improve_prompt(generator, coverage, bottleneck_code, funcname, not_cover)
        chat_messages = get_message(prompt)
        return self.get_response(chat_messages)

    def improve_generator_chat(self, generator, coverage, message):
        prompt = improve_generator_with_advice_prompt(generator, coverage, message)
        chat_messages = message_with_prefix(prompt)
        return self.get_response(chat_messages, get_suffix())

    def first_solve(self, code_snippet, callee, bcode):
        # 保存本次使用的代码等信息到一个指定路径文件

        # 第一次对话，得到初始生成器脚本
        try:
            resp = self.first_chat(code_snippet, callee, bcode)
        except Exception as e:
            logger.error(e)
            resp = f"Error generating seed: {str(e)}"
        return resp

    def fix_solve(self, generator, stderr):
        try:
            resp = self.fix_chat(generator, stderr)
        except Exception as e:
            logger.error(e)
            resp = f"Error fixing seed: {str(e)}"
        return resp

    def test_seed(self, seed_id, bid, freq_global, target_prog):
        tracer = SeedTracer(target_prog, config.EXEC_ARGS)
        trace_data, _ = tracer.trace_seed(os.path.join(config.LLM_TMP_PATH, seed_id), 60.0)
        bb_data = trace_data['basic_blocks']

        bottleneck_next = config.bbs[int(bid)]
        successor = bottleneck_next['successors']
        if len(successor) != 2:
            # print("skip")
            return True, bb_data, []
        # print(successor[0], successor[1])
        bitmap = Bitmap()
        bitmap.merge({"seed": seed_id, "info": trace_data})
        bb_freq1 = bitmap.bitmap

        sum_s1 = bb_freq1[int(successor[0])]
        sum_s2 = bb_freq1[int(successor[1])]
        print(sum_s1, sum_s2)
        print(freq_global[successor[0]], freq_global[successor[1]])

        def check_conditions(left0, right0, left1, right1):
            case1 = (left0 > 0 and left1 > 0) and (right0 == 0 and right1 == 0)
            case2 = (left0 == 0 and left1 == 0) and (right0 > 0 and right1 > 0)
            return case1 or case2

        if check_conditions(freq_global[successor[0]], freq_global[successor[1]], sum_s1, sum_s2):
            return False, bb_data, [successor[0] if sum_s1 == 0 else successor[1]]
        if sum_s1 == 0 and sum_s2 == 0:
            return False, bb_data, [successor[0], successor[1]]
        return True, bb_data, []

    def get_advice(self, rb_info: dict, no_exec_bid_lst: list, coverage, generator):
        not_covered_code = []
        for bid in no_exec_bid_lst:
            file_name = config.bbs['functions'][int(config.bbs['basic_blocks'][bid]['function'])]['file_name']
            begin_line_num = config.bbs['basic_blocks'][bid]['lineStart']
            with open(Path(config.PROJECT_HOME) / "src" / file_name) as f:
                not_covered_code.append([line.rstrip('\n') for line in f.readlines()][begin_line_num - 1])
        if len(no_exec_bid_lst) > 1:
            advice = self.no_cover_chat(generator, coverage, rb_info['code'], rb_info['func_name'])
        else:
            advice = self.no_break_chat(generator, coverage, rb_info['code'], rb_info['func_name'], not_covered_code)
        return advice

    def improve_script(self, generator, coverage, advice):
        try:
            resp = self.improve_generator_chat(generator, coverage, advice)
        except Exception as e:
            logger.error(e)
            resp = f"Error improve script: {str(e)}"
        return resp
