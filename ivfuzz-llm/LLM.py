from openai import OpenAI
# from testSeed import run_generator
import json

model = "deepseek-chat"

client = OpenAI(api_key="sk-440547e4c10e4c82b09d848a68d3b078", base_url="https://api.deepseek.com")
# model = "qwq:32b-fp16"
# client = OpenAI(api_key="ollama", base_url='http://10.1.112.69:11434/v1')
# model = "qwen-max-latest"
# client = OpenAI(api_key="sk-f42296797a7147c4b1089a58ba12abd6",base_url="https://dashscope.aliyuncs.com/compatible-mode/v1")
def construct_prompt(src1, src2, method):
    pass

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

#     template = f"""You are a professional program code analyst. Your task is to analyze the provided code snippet and develop a Python script to generate test cases.

# ### Task

# Your Task is to write a generator of test cases for
# ```LLVMFuzzerTestOneInput```. The generator should generate an
# input that can call ```{callee}``` called in the function ```{caller}``` and pass the code ```{bcode}```.

# ### Instrument

# Generate the input case that ```LLVMFuzzerTestOneInput``` can
# accept. The struct and file format should be accepted by
# ```LLVMFuzzerTestOneInput```.

# ### Code Snippet
# ```
# {code_snippet}
# ```

# ### Additional Notes

# - Your code MUST generate input cases automatically because the code
# will become an integrated part of an automated system.

# - You MUST give the generated code in the following format, so we can
# extract the code conveniently:

# ```Python
# {{your code}}
# ```

# - You MUST include the full valid Python script in your response.

# - One python code ONLY generates one case.

# - WHEN ENCOUNTERING OPERATIONS SUCH AS XOR, YOU MUST GENERATE THE REVERSE EQUATION INSTEAD OF CALCULATING THE RESULT DIRECTLY. FOR EXAMPLE:
#   - If the code contains `b = a ^ 0x2` and later checks `b == 0x1`, you MUST generate the equation `a = 0x1 ^ 0x2` in the test case generator.
#   - DO NOT SIMPLIFY OR CALCULATE THE RESULT OF `0x1 ^ 0x2`. INSTEAD, LEAVE IT AS AN EQUATION.

# - DO NOT consider all the constraints after ```{bcode}```.

# Example of a generator
# ```python
# # Some libraries that should be imported
# def case_generator(out):
#     # generative process of cases
# if **name** == **main** :
#     if(len(sys.argv)<2):
#         print("usage: python3 generator.py <output_path>")
#         sys.exit(1)
#     # Some setup codes
#     with open(sys.argv[1],'wb') as f:
#         case_generator(f)
# ```"""
#     template = f"""You are a professional program code analyst. Your task is to analyze the provided code snippet and develop a Python script to generate test cases.

# ### Task

# Your Task is to write a generator of test cases for
# ```LLVMFuzzerTestOneInput```. The generator should generate an
# input that can call ```{callee}``` called in the function ```{caller}``` and pass the code ```{bcode}```.

# ### Instrument

# Generate the input case that ```LLVMFuzzerTestOneInput``` can
# accept. The struct and file format should be accepted by
# ```LLVMFuzzerTestOneInput```.

# ### Code Snippet
# ```
# {code_snippet}
# ```
# ### Additional Notes

# - Your code MUST generate input cases automatically because the code
# will become an integrated part of an automated system.

# - You MUST give the generated code in the following format, so we can
# extract the code conveniently:

# ```Python
# {{your code}}
# ```

# - You MUST include the full valid Python script in your response.

# - One python code ONLY generates one case.

# - DONT calculate the corresponding results for the parts involving operations(Especially complex operations such as XOR), but instead list the backward equations.
# for example, if you meet b = a ^ 0x2, and later examine b == 0x1 in the programme, you should put a = 0x1^0x2 in the generator, no a = 3.

# - DONT consider all the constraints after ```{bcode}```

# Example of a generator
# ```python
# # Some libraries that should be imported
# def case_generator(out):
#     # generative process of cases
# if **name** == **main** :
#     if(len(sys.argv)<2):
#         print("usage: python3 generator.py <output_path>")
#         sys.exit(1)
#     # Some setup codes
#     with open(sys.argv[1],'wb') as f:
#         case_generator(f)
# ```"""
    # print(template,flush=True)



def generate_seed(prompt, info, messages):
    if messages is None:
        messages = [{"role": "user", "content": prompt}]
    else:
        messages.append({"role": "user", "content": info})

    try:
        print("chatting with llm",flush=True)
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=8192,
            stream=False,
            temperature=0
        )
        print("end chat",flush=True)
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


def fix_generator(generator, message, stderr):
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
        print("fixing with LLM",flush=True)
        response = client.chat.completions.create(
            model=model,
            messages=message,
            temperature=0,
            max_tokens=8192
        )
        print("end fixing",flush=True)
        assistant_message = response.choices[0].message
        message.append(assistant_message)
        fix_text = assistant_message.content.strip()
        return fix_text

    except Exception as e:
        return f"Error fixing generator: {str(e)}", message
    

def improve_geneator(messages, bottleneck_code, funcname, not_cover, coverage):
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
        "role":"user",
        "content":prompt_template
    })

    try:
        print("improving generator",flush=True)
        # print(prompt_template)
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=1,
            max_tokens=8192
        )

        assistant_message = response.choices[0].message
        messages.append(assistant_message)
        # improve_text = assistant_message.content.strip()
        # return improve_text
        
        return messages
    except Exception as e:
        return f"Error improving generator: {str(e)}", messages
    
    
    

def improve_both_no_cover(messages, bottleneck_code, funcname, not_cover, coverage):
    not_cover_lines = ','.join(not_cover)
    prompt_template = f'''You have generated a generator to finish the task, but the final goal for the generator is to break the bottleneck located in the line ```{bottleneck_code}``` in function ```{funcname}```. The both branch after the bottleneck has not been run, which are ```{not_cover_lines}``` in the code. The specific code coverage is as follows:
```
{coverage}
```
The number of times the seed generated by the generator covers each line of code is marked with "//coverage:" after the code.
please give some suggestions to help generator breaking through the bottleneck mentioned above, including:
- A 2-3 short sentences summary of the relationship between the script and the coverage. For example, "The script not cover part X because it generates only Y type of data."
- A 2-3 short sentences general guideline on how to improve the script based on the coverage information received. You don’t need to provide a new script, just some advice on how to improve the current one.
'''
    messages.append({
        "role":"user",
        "content":prompt_template
    })

    try:
        print("improving generator",flush=True)
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            # temperature=0.3,
            max_tokens=8192
        )

        assistant_message = response.choices[0].message
        messages.append(assistant_message)
        # improve_text = assistant_message.content.strip()
        # return improve_text
        return messages
    except Exception as e:
        return f"Error improving generator: {str(e)}", messages


