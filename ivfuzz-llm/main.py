import argparse
import os
import yaml
from callChain import get_call_chain
from navigator import get_code_snippet
from LLM import construct_prompt, construct_prompt_generator, generate_seed, fix_generator
from testSeed import test_seed, refine, extract_generator, run_generator
import re

seed_path = os.path.join('/', 'root', 'Project', 'out', 'LLM')


def get_parser():
    parser = argparse.ArgumentParser(description="LLM interaction interface")
    parser.add_argument("-m", "--method", type=int, choices=[0, 1], required=True,
                        help="0 for generate seed directly, 1 for seed generator")
    parser.add_argument("-bid", "--bottleneck_id", type=int, required=True,
                        help="bottleneck id")
    parser.add_argument("-t", "--times", type=int, default=3,
                        help="number of tries to generate seed")
    return parser


def main():
    parser = get_parser()
    args = parser.parse_args()
    method = args.method
    bottleneck_id = args.bottleneck_id
    max_times = args.times
    bottleneck_bypassed = False
    info = None
    times = 0
    messages = None
    seedid = 0

    generator_path = os.path.join('/', 'root', 'Project', "generator.py")

    with open(os.path.join('/', 'root', 'Project', 'config.yaml'), 'r') as f:
        conf = yaml.safe_load(f)
    exec_arg = conf['fuzzer']['target_args']
    os.makedirs(os.path.join('/', 'root', 'Project', 'out', 'LLM', 'queue'), exist_ok=True)
    files = os.listdir(os.path.join('/', 'root', 'Project', 'out', 'LLM', 'queue'))
    if len(files) == 0:
        seedid = 0
    else:
        for file in files:
            match = re.search(r'id:(\d{6})', file)
            if match:
                if int(match.group(1)) > seedid:
                    seedid = int(match.group(1))
        seedid += 1

    call_chain = get_call_chain(bottleneck_id)
    if method == 1:
        # # 生成generator
        code_snippet, bcode = get_code_snippet(call_chain, bottleneck_id)
        prompt = construct_prompt_generator(call_chain, code_snippet, bcode)
        with open("prompt.txt", 'w') as f:
            f.write(prompt)

        while not bottleneck_bypassed and times < max_times:
            print("start generate python script", flush=True)
            response, messages = generate_seed(prompt, info, messages)
            with open("response.txt", 'w') as fr:
                fr.write(response)
            print("extracting python script", flush=True)
            generator = extract_generator(response)
            # print(generator)
            print("running python script", flush=True)
            out, err = run_generator(generator, bottleneck_id, seedid)
            # print("out:", out)
            # print("err:", err)
            while err:
                print("fixing python scripts", flush=True)
                response = fix_generator(generator, messages, err)
                generator = extract_generator(response)
                out, err = run_generator(generator, bottleneck_id, seedid)
                # print("out:", out)
                # print("err:", err)
            print("testing if breaking through", flush=True)
            bottleneck_bypassed, execution_path, not_exec_bid = test_seed(seedid, bottleneck_id, exec_arg)
            if not bottleneck_bypassed:
                print("getting advices to improve python script", flush=True)
                messages = refine(bottleneck_id, execution_path, messages, call_chain, not_exec_bid)

                info = "Please improve the python script you generated previously according to the advices above."
                times += 1
            else:
                print(f"id: {bottleneck_id} is breaked.", flush=True)
                break
        print("done")
    else:
        # 直接生成
        pass


if __name__ == '__main__':
    main()
