import json
import os


# def get_source_code(func_name:str) -> str:
#     pass


def get_code_snippet(call_chain:list, bottleneck_id):
    with open("/root/Project/static/static.json",'r') as f:
        data = json.load(f)

    code_snippet = ""
    fs = data['functions']
    bbs = data['basic_blocks']
    for i, fname in enumerate(call_chain):
        f = next((item for item in fs if item.get("name") == fname), None)
        file = f['file_name']
        start = f['lineStart']
        end = f['lineEnd']
        with open(os.path.join('/','root','Project','src',file)) as f:
            code = f.readlines()
        function_snippet_list = code[start-1:end]
        function_snippet = ''.join(function_snippet_list)
        code_snippet += function_snippet
        if i == len(call_chain)-1:
            bcode = code[bbs[int(bottleneck_id)]['lineEnd']-1]
    # print(bcode)
    return code_snippet, bcode
