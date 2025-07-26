import logging
import os
import re
import subprocess
from pathlib import Path

from openai import OpenAI

import config
from config import LOGGER_NAME, PROJECT_HOME, LLM_TMP_PATH, EXEC_ARGS, bbs, funcs
from pyTracer.CodeHeat import CodeHeat
from pyTracer.InfoProcessor import Bitmap
from pyTracer.SeedTracer import SeedTracer

logger = logging.getLogger(LOGGER_NAME + __name__)


def get_sys_prompt():
    return """As a professional security engineer,your task is to develop a Python script that generates a new test casefile.\
This file should adhere to the format required by the fuzzing harness code and pass the specified constraint in the snippet.\
The script will play a crucial role in creating diverse and effective test cases for thorough security testing."""


def get_prefix():
    return """```python\n"""


def get_suffix():
    return """if __name__ == __main__ :
    if(len(sys.argv)<2):
        print("usage: python3 generator.py <output_path>")
        sys.exit(1)
    # Some setup codes
    with open(sys.argv[1],'wb') as f:
        case_generator(f)
```"""


def construct_prompt_generator(call_chain, code_snippet, bcode):
    if len(call_chain) < 1:
        raise ValueError("call_chain must contain at least one element")
    callee = call_chain[-1]
    # caller = call_chain[-2] if len(call_chain) >= 2 else "unknown_caller"

    template = f"""## STEPS:
1. Understand the core functionality of the program from the code snippet.
2. Analyze the key constraints in the call chain execution and use them to guide subsequent steps.
3. Hypothetically analyze What characteristics does seeds need to meet to meet these constraints. You should consider all of the key constraints.
4. Provide the python script that can generate seeds satisfying these constraints. Remember the generated seeds should functioning correctly.

## code snippet
```{code_snippet}```
the bottleneck constraint is ```{bcode}``` in function ```{callee}```.
As an integrated component of an automated system , you should \
perform the tasks without seeking human confirmation or \
help.
## Instructions
The script should:
1. enclosed with ``` ```.
2. include the full valid Python script in your response.
3. Has one argument , which is the output file path.
4. Generate one test case and write it to the output file.
5. The generated test case should be compatible with the fuzzing harness code provided and pass the specified constraint in the snippet.
## Example
```python
# Some libraries that should be imported
def case_generator(out):
    # generative process of cases
if **name** == **main** :
    if(len(sys.argv)<2):
        print("usage: python3 generator.py <output_path>")
        sys.exit(1)
    # Some setup codes
    with open(sys.argv[1],'wb') as f:
        case_generator(f)
```"""
    return template


def extract_generator(generator_text):
    code_pattern = r"```python(.*?)```"
    code_match = re.search(code_pattern, generator_text, re.DOTALL)

    if not code_match:
        raise ValueError("生成文本中未找到有效的Python代码块")

    raw_code = code_match.group(1).strip()
    return raw_code


def run_generator(generator, bottleneck_id, id):
    # 将generator代码写入.py文件中
    file_path = os.path.join(PROJECT_HOME, 'generator.py')
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(generator)

    new_seed_id = os.path.join(LLM_TMP_PATH, f"id:{int(id):06},bid:{int(bottleneck_id):06}")
    # 使用 subprocess 运行文件并捕获输出
    try:
        # 运行命令，捕获标准输出和标准错误
        result = subprocess.run(
            ["python", file_path, new_seed_id],  # 执行的命令
            text=True,  # 以文本形式返回输出
            capture_output=True,  # 捕获标准输出和标准错误
            encoding="utf-8"  # 显式指定编码为 UTF-8
        )
        return result.stdout, result.stderr, new_seed_id
    except Exception as e:
        logger.error(f"运行generator代码的子线程异常: {e}")
        return None


class LLM_util:
    def __init__(self, model, key, base_url):
        self.model = model
        self.client = OpenAI(api_key=key, base_url=base_url)
        pass

    def solve(self, call_chain, code_slice, roadblock_code, roadblock_id, seedid):
        # if not config.test:
        prompt = construct_prompt_generator(call_chain, code_slice, roadblock_code)
        logger.info(f"prompt如下：{prompt}")

        logger.info("start generate python script")
        response, messages = self.generate_seed(prompt)
        if "Error generating seed" in response:
            logger.error(response)

        # logger.info(f"response如下：{response}")
        logger.info("extracting python script")
        generator = extract_generator(response)
        # else:
        #     with open(os.path.join(PROJECT_HOME, "generator.py"), "r", encoding="utf-8") as f:
        #         generator = f.read()
        # generator = None
        logger.info("running python script")
        out, err, new_seed_path = run_generator(generator, roadblock_id, seedid)
        while err:
            logger.info("fixing python scripts")
            response = self.fix_generator(generator, err)
            if "Error fixing generator" in response:
                continue
            generator = extract_generator(response)
            out, err, new_seed_path = run_generator(generator, roadblock_id, seedid)

        messages.append({
            'role': 'assistant',
            'content': response
        })

        return out, err, new_seed_path, messages, generator  # 返回的是带脚本的messages，没有错误修正相关的对话

    def get_response(self, messages, temperature=0):
        completion = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            stream=False,
            temperature=temperature
        )
        return completion

    def generate_seed(self, user_prompt):
        messages = [{
            "role": "system",
            "content": get_sys_prompt()
        }, {
            "role": "user",
            "content": user_prompt
        }]

        if "deepseek" in config.model:
            messages.append({
                'role': 'assistant',
                'content': get_prefix(),
                'prefix': True
            })
        elif "qwen" in config.model:
            messages.append({
                'role': 'assistant',
                'content': get_prefix(),
                'partial': True
            })

        try:
            logger.info("chatting with llm")
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0,
                stop=[get_suffix()]
            )
            logger.info("end chat")

            seed = get_prefix() + response.choices[0].message.content
            messages.pop()
            return seed, messages

        except Exception as e:
            return f"Error generating seed: {str(e)}", messages

    def fix_generator(self, generator, stderr):
        prompt_template = f"""You generated the following Python code, but it encounters some issues
during execution and raises an error. Please modify the code to make it
run correctly and optimize it where possible. Below are the code and the
error message:

### Code:
{generator}

### Error Message:
{stderr}

Please address the following in your response:
1. Fix the error in the code so that it runs correctly.
2. If possible, optimize the code for better performance, readability, or logic.
3. DON'T provide any explanations for the changes made. just give the python code in the following format:
```python
<your code here>
```
"""

        messages = [{
            "role": "system",
            "content": get_sys_prompt()
        }, {
            "role": "user",
            "content": prompt_template
        }]
        if "deepseek" in config.model:
            messages.append({
                'role': 'assistant',
                'content': get_prefix(),
                'prefix': True
            })
        elif "qwen" in config.model:
            messages.append({
                'role': 'assistant',
                'content': get_prefix(),
                'partial': True
            })

        try:
            logger.info("fixing with LLM")
            # response = self.get_response(message)
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                stop=[get_suffix()],
                temperature=0
            )
            logger.info("end fixing")
            new_script = get_prefix() + response.choices[0].message.content
            return new_script

        except Exception as e:
            return f"Error fixing generator: {str(e)}"

    def improve_both_no_cover(self, messages, bottleneck_code, funcname, not_cover, coverage):
        not_cover_lines = ','.join(not_cover)
        prompt_template = f'''The code information of your generator is as follows:
```
{coverage}
```
The number of times the seed generated by the generator covers each line of code is marked with "//coverage:" after the code.
please give some suggestions to help generator breaking through the bottleneck mentioned above, including:
- A 2-3 short sentences summary of the relationship between the script and the coverage. For example, "The script not cover part X because it generates only Y type of data."
- A 2-3 short sentences general guideline on how to improve the script based on the coverage information received. You don’t need to provide a new script, just some advice on how to improve the current one.
'''
        messages.append({
            "role": "user",
            "content": prompt_template
        })

        try:
            logger.info("improving generator")
            response = self.get_response(messages, 1)

            assistant_message = response.choices[0].message
            improve_text = assistant_message.content
            # messages.append({"role": "assistant", "content": improve_text})
            return improve_text, messages
        except Exception as e:
            return f"Error improving generator: {str(e)}", messages

    def improve_geneator(self, messages, bottleneck_code, funcname, not_cover, coverage):
        prompt_template = f'''You have generated a generator to finish the task, but the final goal for the generator is to break the bottleneck located in the line ```{bottleneck_code}``` in function ```{funcname}```. The branch that has not been run begins at line ```{not_cover}```. The specific code coverage is as follows:
```
{coverage}
```
The number of times the seed generated by the generator covers each line of code is marked with "//coverage:" after the code.
please give some suggestions to help generator breaking through the bottleneck mentioned above, including:
- A 2-3 short sentences summary of the relationship between the script and the coverage. For example, "The script not cover part X because it generates only Y type of data."
- A 2-3 short sentences general guideline on how to improve the script based on the coverage information received. You don’t need to provide a new script, just some advice on how to improve the current one.
'''
        messages.append({
            "role": "user",
            "content": prompt_template
        })

        try:
            logger.info("improving generator")
            # print(prompt_template)
            response = self.get_response(messages, 1)

            assistant_message = response.choices[0].message
            improve_text = assistant_message.content
            # messages.append({"role": "assistant", "content": assistant_message})
            # improve_text = assistant_message.content.strip()
            # return improve_text

            return improve_text, messages
        except Exception as e:
            return f"Error improving generator: {str(e)}", messages

    def test_seed(self, seed_id, freq_global, target_prog):
        exec_path = target_prog
        tracer = SeedTracer(exec_path, EXEC_ARGS)
        trace_data, _ = tracer.trace_seed(
            os.path.join(LLM_TMP_PATH, seed_id), 60.0)
        bb_data = trace_data['basic_blocks']
        bb_static = bbs

        match = re.match(r"id:(\d+),bid:(\d+)", seed_id)
        if not match:
            raise
        id, bid = match.groups()
        bottleneck_next = bb_static[int(bid)]
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
        if (sum_s1 == 0 and sum_s2 == 0):
            return False, bb_data, [successor[0], successor[1]]
        return True, bb_data, []

    def refine(self, bid, execution_path, messages, call_chain, not_exec_bid):
        function_coverage = ""
        code_heat = CodeHeat()
        code_heat.merge(execution_path, bbs)
        for fname in call_chain:
            f = next((item for item in funcs if item.get("name") == fname), None)
            filename = f['file_name']
            start = f['lineStart']
            end = f['lineEnd']
            fid = f['id']
            with open(Path(PROJECT_HOME) / "src" / filename) as f:
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

        bb = next((item for item in bbs if item.get("id") == bid), None)
        f = next((item for item in funcs if item.get("id") == bb["function"]), None)
        filename = f["file_name"]
        fname = f['name']
        with open(Path(PROJECT_HOME) / "src" / filename) as f:
            code = [line.rstrip('\n') for line in f.readlines()]
        bottleneck_code = code[bb['lineEnd'] - 1]
        if len(not_exec_bid) > 1:
            print("not reach branch")
            not_cover = []
            for i in not_exec_bid:
                not_cover.append(code[bbs[int(i)]['lineStart'] - 1])
            advices, messages = self.improve_both_no_cover(messages, bottleneck_code, fname, not_cover,
                                                           function_coverage)
            return advices, function_coverage
        not_cover = code[bbs[int(not_exec_bid[0])]['lineStart'] - 1]
        advices, messages = self.improve_geneator(messages, bottleneck_code, fname, not_cover, function_coverage)
        return advices, function_coverage

    def improve_script(self, generator, coverage, message):
        prompt = f"""Here is a seed generation script:
```
{generator}
```
Our coverage report indicates that the generated seeds with this script cover parts of the code:
```
{coverage}
```
(In the report,static functions and initializers are marked as uncovered. This is intentional,as these elements are not meant to be included in fuzzer coverage.)
To enhance code coverage,consider refining the script to produce more effective seeds. Here is someadvice to help you improve the script:
```
{message}
```"""
        messages = [{
            "role": "system",
            "content": get_sys_prompt()
        }, {
            "role": "user",
            "content": prompt
        }]

        if "deepseek" in config.model:
            messages.append({
                'role': 'assistant',
                'content': get_prefix(),
                'prefix': True
            })
        elif "qwen" in config.model:
            messages.append({
                'role': 'assistant',
                'content': get_prefix(),
                'partial': True
            })

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            stop=[get_suffix()],
            temperature=0
        )

        return get_prefix() + response.choices[0].message.content
