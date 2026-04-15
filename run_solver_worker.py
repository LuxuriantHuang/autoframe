from __future__ import annotations

import argparse

from run_path_common import run_path_program


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a standalone AutoFrame solver worker")
    parser.add_argument("--path", required=True)
    return parser.parse_known_args()[0]


if __name__ == "__main__":
    args = parse_args()
    run_path_program(args.path)
