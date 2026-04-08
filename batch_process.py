#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import re
from typing import List, Tuple, Optional


def parse_args():
    parser = argparse.ArgumentParser(description="Process compile_commands.json for a project")
    parser.add_argument("project", help="Project name (e.g., lcms, libpng, cflow)")
    return parser.parse_args()


args = parse_args()
PROJECT = args.project

BASE = Path(__file__).resolve().parent
PROJECT_HOME = BASE / "benchmarks" / PROJECT

DB = PROJECT_HOME / 'src' / "compile_commands.json"
OUT_DIR = PROJECT_HOME / 'src_bear'

SRC_EXTS = (".c", ".cc", ".cpp", ".cxx", ".C", ".m", ".mm")

# Linemarker examples:
#   # 123 "target.cc" 2
#   # 1 "/usr/include/stdio.h" 1 3 4
LM = re.compile(r'^#\s+(\d+)\s+"([^"]+)"(?:\s+\d+)*\s*$')


def is_source_file(p: str) -> bool:
    return p.endswith(SRC_EXTS)


def is_cc1(argv: List[str]) -> bool:
    return "-cc1" in argv


def norm_path(p: str) -> str:
    return os.path.realpath(os.path.abspath(p))


def pick_driver_compiler(argv: List[str], src: str) -> str:
    """
    For normal compile_commands entries, reuse argv[0].
    For -cc1 style entries, switch to clang/clang++ driver in the same directory.
    Prefer clang++ for C++ sources.
    """
    comp0 = argv[0]
    if not is_cc1(argv):
        return comp0

    d = os.path.dirname(comp0)
    prefer_cxx = src.endswith((".cc", ".cpp", ".cxx", ".C", ".mm"))
    if prefer_cxx:
        cand = os.path.join(d, "clang++")
        if os.path.exists(cand):
            return cand
    cand = os.path.join(d, "clang")
    if os.path.exists(cand):
        return cand

    return comp0


def extract_pp_flags(argv: List[str]) -> List[str]:
    """
    Keep only flags that affect preprocessing results.
    Drop link/object/archive args, -o outputs, and cc1/internal-only args.
    """
    keep: List[str] = []
    i = 0
    n = len(argv)

    # flags where we must keep the next token too
    paired = {
        "-I", "-isystem", "-iquote", "-include", "-imacros", "-idirafter",
        "-x", "--sysroot", "--target", "-target",
        "-resource-dir",  # optional but harmless
    }

    drop_single = {
        "-cc1", "-emit-obj", "-disable-free", "-disable-llvm-verifier",
        "-discard-value-names", "-fcolor-diagnostics", "-faddrsig",
    }

    while i < n:
        a = argv[i]

        if a == "-c":
            i += 1
            continue
        if a == "-o":
            i += 2
            continue

        if a in drop_single:
            i += 1
            continue

        # cc1 internal include flags
        if a.startswith("-internal-"):
            i += 2 if i + 1 < n else 1
            continue

        # cc1 paired flags we don't want to carry into driver mode
        if a in ("-triple", "-main-file-name", "-mrelocation-model", "-target-cpu",
                 "-debugger-tuning", "-ferror-limit", "-fgnuc-version",
                 "-fdebug-compilation-dir"):
            i += 2 if i + 1 < n else 1
            continue

        if a in paired:
            if i + 1 < n:
                keep.extend([a, argv[i + 1]])
                i += 2
                continue
            i += 1
            continue

        if a.startswith(("-I", "-D", "-U", "-std=")):
            keep.append(a)
            i += 1
            continue

        if a in ("-nostdinc", "-nostdinc++"):
            keep.append(a)
            i += 1
            continue

        i += 1

    return keep


def infer_lang_and_ext(argv: List[str], src: str) -> Tuple[Optional[str], str]:
    """
    Try to infer language from '-x <lang>' if present; decide output extension (.i/.ii).
    """
    lang = None
    if "-x" in argv:
        try:
            idx = argv.index("-x")
            if idx + 1 < len(argv):
                lang = argv[idx + 1]
        except ValueError:
            pass

    is_cxx = src.endswith((".cc", ".cpp", ".cxx", ".C", ".mm"))
    if lang and ("c++" in lang or "objective-c++" in lang):
        is_cxx = True

    out_ext = ".ii" if is_cxx else ".i"
    return lang, out_ext


def output_path_for(src: str, out_ext: str) -> str:
    """
    使用原始文件名作为输出文件名，不添加任何后缀。
    例如: buf.c -> buf.c
    """
    base = os.path.basename(src)
    # 直接使用原始文件名，不添加任何额外后缀
    return os.path.join(OUT_DIR, base)


def load_compile_db(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_argv(entry: dict) -> List[str]:
    if "arguments" in entry and isinstance(entry["arguments"], list):
        return entry["arguments"]
    if "command" in entry and isinstance(entry["command"], str):
        return shlex.split(entry["command"])
    return []


def preprocess_and_filter(
        compiler: str,
        flags: List[str],
        directory: str,
        src_abs: str,
        out_file: str,
        use_dI: bool = True,
) -> None:
    """
    Run preprocessor, stream stdout, keep only lines that belong to src_abs (by linemarkers),
    annotate each kept line with /* file:line */.
    """
    src_abs_norm = norm_path(src_abs)

    pp_cmd = [compiler, "-E", "-dD", "-w"]
    if use_dI:
        # GCC supports -dI (emit #include directives); clang may or may not.
        # We try it; if it fails, caller will handle.
        pp_cmd.append("-dI")
    pp_cmd.extend(flags)
    pp_cmd.append(src_abs)

    # Start preprocessor
    p = subprocess.Popen(
        pp_cmd,
        cwd=directory,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        bufsize=1,
        universal_newlines=True,
    )

    cur_file = "<unknown>"
    cur_line = 0
    in_target = False
    output_line = 0  # 当前输出的行号

    def resolve_marker_path(marker_path: str) -> str:
        # linemarkers can be relative; resolve relative to compilation directory
        if os.path.isabs(marker_path):
            return norm_path(marker_path)
        return norm_path(os.path.join(directory, marker_path))

    def to_relative_path(abs_path: str) -> str:
        """
        将绝对路径转换为相对路径格式。
        如果路径中包含'tmp/'，返回'tmp/xxx.c'这样的格式。
        否则返回basename。
        """
        # 查找'tmp/'在路径中的位置
        tmp_idx = abs_path.find('/tmp/')
        if tmp_idx != -1:
            # 从'tmp/'开始截取（包含'tmp/'）
            return abs_path[tmp_idx + 1:]  # +1 去掉开头的'/'
        # 如果没有'tmp/'，返回basename
        return os.path.basename(abs_path)

    with open(out_file, "w", encoding="utf-8", errors="ignore") as fout:
        assert p.stdout is not None
        # fout.write(p.stdout.read())
        for raw in p.stdout:
            line = raw.rstrip("\n")

            m = LM.match(line)
            if m:
                cur_line = int(m.group(1))
                cur_file = m.group(2)
                cur_file_abs = resolve_marker_path(cur_file)
                in_target = (cur_file_abs == src_abs_norm)
                continue

            if not in_target:
                continue

            # 将绝对路径转换为相对路径格式用于注释（如 "tmp/xxx.c"）
            relative_path = to_relative_path(cur_file_abs)

            # 如果当前源文件行号大于已输出行号，添加空行来对齐
            while output_line < cur_line - 1:
                fout.write("\n")
                output_line += 1

            # 写入当前行，确保它在正确的行号位置
            # fout.write(f"{line} /* {relative_path}:{cur_line} */\n")
            fout.write(f"{line}\n")
            output_line += 1
            cur_line += 1

    _, stderr = p.communicate()
    if p.returncode != 0:
        raise subprocess.CalledProcessError(p.returncode, pp_cmd, output=None, stderr=stderr)


def main() -> int:
    if not os.path.exists(DB):
        print(f"[ERR] {DB} not found in current directory.")
        return 2

    os.makedirs(OUT_DIR, exist_ok=True)

    entries = load_compile_db(DB)
    ok = 0
    fail = 0
    skipped = 0

    for e in entries:
        directory = e.get("directory") or "."
        src = e.get("file")
        if not src or not is_source_file(src):
            skipped += 1
            continue

        argv = get_argv(e)
        if not argv:
            skipped += 1
            continue

        compiler = pick_driver_compiler(argv, src)
        flags = extract_pp_flags(argv)
        _, out_ext = infer_lang_and_ext(argv, src)
        out_path = output_path_for(src, out_ext)

        # 将相对路径转换为绝对路径（相对于directory）
        src_abs = src if os.path.isabs(src) else os.path.join(directory, src)

        # 先尝试带 -dI；如果 clang 不支持则自动回退不带 -dI
        try:
            preprocess_and_filter(
                compiler=compiler,
                flags=flags,
                directory=directory,
                src_abs=src_abs,
                out_file=out_path,
                use_dI=True,
            )
            ok += 1
        except subprocess.CalledProcessError as ex:
            # 如果是 -dI 不支持导致的错误，回退重试一次（不再问你）
            err = (ex.stderr or "")
            if "-dI" in " ".join(ex.cmd) and ("unknown argument" in err or "unrecognized command line option" in err):
                try:
                    # 重新计算src_abs（与上面相同的逻辑）
                    src_abs_retry = src if os.path.isabs(src) else os.path.join(directory, src)
                    preprocess_and_filter(
                        compiler=compiler,
                        flags=flags,
                        directory=directory,
                        src_abs=src_abs_retry,
                        out_file=out_path,
                        use_dI=False,
                    )
                    ok += 1
                except subprocess.CalledProcessError as ex2:
                    fail += 1
                    err2 = (ex2.stderr or "")
                    print(f"[FAIL] {src} (cwd={directory}) -> {out_path}")
                    print("PP CMD:", " ".join(ex2.cmd))
                    print(err2.strip(), "\n")
            else:
                fail += 1
                print(f"[FAIL] {src} (cwd={directory}) -> {out_path}")
                print("PP CMD:", " ".join(ex.cmd))
                print(err.strip(), "\n")

    print(f"Done. success={ok}, fail={fail}, skipped={skipped}. outputs in ./{OUT_DIR}/")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
