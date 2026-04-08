import logging
import os
from pathlib import Path
import subprocess
import config
from config import *

branch_slicer_bin = Path(PWD) / "svf" / "build" / "BranchConditionSlicer"
logger = logging.getLogger(LOGGER_NAME + __name__)

def llvm_slice(
    file: str,
    line: int,
    bc_file: str,
    out_path: str | None = None,
    case_line: int | None = None,
    use_svf_callpath: bool = True,
):
    resolved_out_path = Path(out_path) if out_path else config.get_slice_output_path(f"{Path(file).name}_{line}")
    resolved_out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        branch_slicer_bin.as_posix(),
        bc_file,
        f"-slice-loc={file}:{line}",
        "-slice-cd=true",
        "-slice-src=true",
        "-slice-src-context=3",
        f"-slice-out={resolved_out_path.as_posix()}",
    ]
    if use_svf_callpath:
        cmd.append("-slice-svf-callpath=true")
    if case_line and case_line > 0 and case_line != line:
        cmd.append(f"-slice-case-loc={file}:{case_line}")
    logger.info(f"[SLICE] Starting slice: {file}:{line}")
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if res.returncode != 0:
            logger.error(f"[SLICE] Slice command failed with return code {res.returncode}")
            if res.stderr:
                logger.error(f"[SLICE] Error output: {res.stderr.decode('utf-8', errors='ignore')}")
        else:
            logger.debug(f"[SLICE] Slice command succeeded for {file}:{line}")

    except subprocess.CalledProcessError as e:
        logger.error(f"[SLICE] Command execution failed, exit code: {e.returncode}")
        if e.stderr:
            logger.error(f"[SLICE] stderr: {e.stderr}")
        if e.stdout:
            logger.error(f"[SLICE] stdout: {e.stdout}")

    except FileNotFoundError as e:
        logger.error(f"[SLICE] BranchConditionSlicer not found: {e}")
        print(f"未找到切片工具 '{branch_slicer_bin}'，请先在 svf/build 中完成构建。")
