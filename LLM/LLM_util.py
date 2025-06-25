import logging
import os
import re
import subprocess

from openai import OpenAI

from config import LOGGER_NAME, MAX_TIME, static

logger = logging.getLogger(LOGGER_NAME + __name__)


def construct_prompt_generator(call_chain, code_snippet, bcode):
    if len(call_chain) < 1:
        raise ValueError("call_chain must contain at least one element")
    callee = call_chain[-1]
    caller = call_chain[-2] if len(call_chain) >= 2 else "unknown_caller"

    template = f"""You are a professional program code analyst. Given a code snippet with full call chain and the bottleneck constraint, please generate a python script step by step which can pass the specified constraint in the snippet:
1. Understand the core functionality of the program from the code snippet.
2. Analyze the key constraints in the call chain execution and use them to guide subsequent steps.
3. Hypothetically analyze What characteristics does seeds need to meet to meet these constraints. You should consider all of the key constraints.
4. Provide the python script that can generate seeds satisfying these constraints. Remember the generated seeds should functioning correctly.
5. Ensure the final output is enclosed with ``` ```.

Given the code snippet as follows:
```
{code_snippet}
```
, the bottleneck constraint is ```{bcode}``` in function ```{callee}```. What is the python script?

Lets take a deep breath and think step by step. Please show your thoughts in each step.

Instructions:
- For necessary operation results, please use inverse operation instead of using the result.
- One python code ONLY generates one case.


Example generator:
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
    file_path = os.path.join('/', 'root', 'Project', 'generator.py')
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(generator)


    os.makedirs(seed_path, exist_ok=True)
    # 使用 subprocess 运行文件并捕获输出
    try:
        # 运行命令，捕获标准输出和标准错误
        result = subprocess.run(
            ["python", file_path, os.path.join(seed_path, f"id:{int(id):06},bid:{int(bottleneck_id):06}")],  # 执行的命令
            text=True,  # 以文本形式返回输出
            capture_output=True,  # 捕获标准输出和标准错误
            encoding="utf-8"  # 显式指定编码为 UTF-8
        )
        return result.stdout, result.stderr
    except Exception as e:
        print(f"运行generator代码的子线程异常: {e}")
        return None


class LLM_util:
    def __init__(self, model, key, base_url):
        self.model = model
        self.client = OpenAI(api_key=key, base_url=base_url)
        pass

    def generate_seed(self, prompt, info, messages):
        if messages is None:
            messages = [{"role": "user", "content": prompt}]
        else:
            messages.append({"role": "user", "content": info})

        try:
            print("chatting with llm", flush=True)
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=8192,
                stream=False,
                temperature=0
            )
            print("end chat", flush=True)
            # response = client.ChatCompletion.create(
            #     model="deepseek-chat",
            #     messages=messages,
            #     max_tokens=8192
            # )

            assistant_message = response.choices[0].message
            messages.append(assistant_message)
            seed = assistant_message.content.strip()

            return seed, messages

        except Exception as e:
            return f"Error generating seed: {str(e)}", messages

    def fix_generator(self, generator, message, stderr):
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

        if not message:
            message = [{
                "role": "user",
                "content": prompt_template
            }]
        else:
            message.append({
                "role": "user",
                "content": prompt_template
            })

        try:
            print("fixing with LLM", flush=True)
            response = self.client.chat.completions.create(
                model=self.model,
                messages=message,
                temperature=0,
                max_tokens=8192
            )
            print("end fixing", flush=True)
            assistant_message = response.choices[0].message
            message.append(assistant_message)
            fix_text = assistant_message.content.strip()
            return fix_text

        except Exception as e:
            return f"Error fixing generator: {str(e)}", message

    def solve(self, call_chain, code_slice, roadblock_code, roadblock_id, seedid):
        prompt = construct_prompt_generator(call_chain, code_slice, roadblock_code)
        logger.info(f"prompt如下：{prompt}")
        bottleneck_bypassed = False
        info = None
        messages = None
        times = 0
        while not bottleneck_bypassed and times < MAX_TIME:
            print("start generate python script", flush=True)
            response, messages = self.generate_seed(prompt, info, messages)
            # with open("response.txt", 'w') as fr:
            #     fr.write(response)
            logger.info(f"response如下：{prompt}")
            print("extracting python script", flush=True)
            generator = extract_generator(response)
            print("running python script", flush=True)
            out, err = run_generator(generator, roadblock_id, seedid)
            # print("out:", out)
            # print("err:", err)
            while err:
                print("fixing python scripts", flush=True)
                response = self.fix_generator(generator, messages, err)
                generator = extract_generator(response)
                out, err = run_generator(generator, roadblock_id, seedid)
                # print("out:", out)
                # print("err:", err)
        #     print("testing if breaking through", flush=True)
        #     bottleneck_bypassed, execution_path, not_exec_bid = test_seed(seedid, roadblock_id, exec_arg)
        #     if not bottleneck_bypassed:
        #         print("getting advices to improve python script", flush=True)
        #         messages = refine(bottleneck_id, execution_path, messages, call_chain, not_exec_bid)
        #
        #         info = "Please improve the python script you generated previously according to the advices above."
        #         times += 1
        #     else:
        #         print(f"id: {bottleneck_id} is breaked.", flush=True)
        #         break
        # print("done")
        # pass


# def test_seed(id, bid, exec_args):
#     exec_path = os.path.join('/', 'root', 'Project', 'target', 'trace', 'target_binary')
#
#     tracer = SeedTracer(exec_path, exec_args)
#     print(os.path.join('/', 'root', 'Project', 'out', 'LLM', 'queue', f"id:{id:06},bid:{bid:06}"))
#     trace_data, _ = tracer.trace_seed(
#         os.path.join('/', 'root', 'Project', 'out', 'LLM', 'queue', f"id:{id:06},bid:{bid:06}"), 60.0)
#     cmd_lines = cmd_line = ["python3", "/root/Tracer/id_tracer.py",
#                             "-tp", "single",
#                             "-o", "/root/Project/out",
#                             "-a", 'LLM',
#                             "-t", "/root/Project/target/trace/target_binary",
#                             "-arg", "@@",
#                             "-s", os.path.join("/root/Project/out",
#                                                "LLM",
#                                                "queue", os.path.join('/', 'root', 'Project', 'out', 'LLM', 'queue',
#                                                                      f"id:{id:06},bid:{bid:06}"))]
#     process0 = subprocess.Popen(cmd_line, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#     process0.wait()
#     bb_data = trace_data['basic_blocks']
#
#     bb_static = static['basic_blocks']
#     bottleneck_next = next((item for item in bb_static if item.get("id") == bid), None)
#     # print(bottleneck_next)
#     successor = bottleneck_next['successors']
#     # print(successor)
#     if len(successor) != 2:
#         print("skip")
#         return True, bb_data
#     print(successor[0], successor[1])
#     with open(os.path.join('/', 'root', 'Project', 'static', 'single', f"id:{id:06},bid:{bid:06}", 'block_freq.json'),
#               'r') as f:
#         bb_freq1 = json.load(f)['freq']
#     # print(bb_freq1)
#     sum_s1 = bb_freq1[int(successor[0])]
#     sum_s2 = bb_freq1[int(successor[1])]
#     print(sum_s1, sum_s2)
#
#     with open(os.path.join('/', 'root', 'Project', 'static', 'global', 'block_freq.json'), 'r') as f:
#         bb_freq = json.load(f)['freq']
#     print(bb_freq[successor[0]], bb_freq[successor[1]])
#
#     def check_conditions(left0, right0, left1, right1):
#         case1 = (left0 > 0 and left1 > 0) and (right0 == 0 and right1 == 0)
#         case2 = (left0 == 0 and left1 == 0) and (right0 > 0 and right1 > 0)
#         return case1 or case2
#
#     if check_conditions(bb_freq[successor[0]], bb_freq[successor[1]], sum_s1, sum_s2):
#         return False, bb_data, [successor[0] if sum_s1 == 0 else successor[1]]
#     if (sum_s1 == 0 and sum_s2 == 0):
#         return False, bb_data, [successor[0], successor[1]]
#     return True, bb_data, []