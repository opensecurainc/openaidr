#!/usr/bin/env python3
"""Resolve the canonical build identity before invoking a component build."""

import argparse
import json
from pathlib import Path
import runpy
import shlex
import sys

ROOT = Path(__file__).resolve().parents[1]
metadata = runpy.run_path(str(ROOT / "src/openaidr/build_info.py"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--format", choices=("json", "version", "shell"), default="json")
    parser.add_argument("--development", action="store_true", help="Identify source execution without building an artifact")
    args = parser.parse_args()
    try:
        info = metadata["resolve"](args.root, clean=not args.development)
        if args.format == "version":
            print(info["version"])
        elif args.format == "shell":
            for key, value in metadata["environment"](info).items():
                print(f"export {key}={shlex.quote(value)}")
        else:
            print(json.dumps(info))
    except (OSError, ValueError) as error:
        parser.exit(1, f"build identity: {error}\n")


if __name__ == "__main__":
    main()
