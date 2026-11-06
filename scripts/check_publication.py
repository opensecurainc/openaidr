#!/usr/bin/env python3
"""Check public source and nested distributions for known private implementation."""

import argparse
import ast
import io
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import zipfile

from verify_public_dependencies import verify_files


PRIVATE_FILES = {"promotion-provenance.json", "intelligence-api.json", "api_dependencies.py"}
ADMIN_METHODS = {"create_admin", "get_admin", "get_admin_by_email", "list_admins", "delete_admin",
                 "count_admins", "touch_admin_login", "create_admin_session", "get_admin_session",
                 "delete_admin_session", "list_platform_audit", "get_platform_overview",
                 "admin_auth_route", "admin_principal"}


def check_file(name, data, *, location=None, depth=0):
    location = location or name
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        raise ValueError("Unsafe publication path: " + location)
    normalized = "/" + str(path).lstrip("./")
    if (path.name in PRIVATE_FILES or "/openaidr/platform/" in normalized
            or normalized.endswith("/packages/ui/src/api/admin.ts")
            or "/openaidr_api/" in normalized or path.name.startswith("openaidr_api-")):
        raise ValueError("Private implementation or promotion metadata: " + location)
    if depth > 6:
        raise ValueError("Excessive archive nesting: " + location)
    if name.endswith((".whl", ".zip")):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("Duplicate archive member: " + location)
            for member in archive.infolist():
                if stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError("Archive link: " + location + "!" + member.filename)
                if not member.is_dir():
                    check_file(member.filename, archive.read(member), location=location + "!" + member.filename, depth=depth + 1)
        return
    if name.endswith((".tar", ".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            seen = set()
            dependencies = {}
            for member in archive:
                if member.name in seen or not (member.isfile() or member.isdir()):
                    raise ValueError("Duplicate or non-file archive member: " + location + "!" + member.name)
                seen.add(member.name)
                if member.isfile():
                    content = archive.extractfile(member).read()
                    check_file(member.name, content, location=location + "!" + member.name, depth=depth + 1)
                    if member.name.startswith("dependencies/api-runtime/"):
                        dependencies[member.name.removeprefix("dependencies/api-runtime/")] = content
            if dependencies:
                try:
                    verify_files(dependencies)
                except (KeyError, ValueError) as error:
                    raise ValueError("Invalid embedded dependency manifest: " + location) from error
        return
    if not name.endswith(".py"):
        return
    tree = ast.parse(data, filename=location)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in ADMIN_METHODS:
            raise ValueError("Private admin implementation: " + location + ":" + str(node.lineno))
        if (normalized.endswith("/openaidr/server/skill_worker.py") and isinstance(node, ast.Dict)
                and any(isinstance(key, ast.Constant) and key.value == "SKILLSPECTOR_PROVIDER" for key in node.keys)):
            raise ValueError("Private scanner provider selection: " + location)
        if isinstance(node, ast.Assign):
            names = {n.id for target in node.targets for n in ast.walk(target) if isinstance(n, ast.Name)}
            if (normalized.endswith("/openaidr/server/guardrail/scoring.py")
                    and names & {"GUIDANCE", "CATEGORY_CRITERIA", "LEVELS"}):
                raise ValueError("Private guardrail rubric definition: " + location)
            if (any(normalized.endswith("/openaidr/server/" + module + ".py")
                    for module in ("page_chat", "application_assessment", "overview_summary"))
                    and "INSTRUCTIONS" in names):
                raise ValueError("Private provider prompt definition: " + location)
            if (normalized.endswith("/openaidr/server/model_costs.py") and "RATES" in names
                    and isinstance(node.value, ast.Dict) and node.value.keys):
                raise ValueError("Private provider price table: " + location)
            if (normalized.endswith("/openaidr/server/skill_llm.py") and "MODEL" in names
                    and isinstance(node.value, ast.Constant) and node.value.value is not None):
                raise ValueError("Private skill model selection: " + location)


def check_tree(root):
    paths = subprocess.check_output(["git", "ls-files", "-c", "-o", "--exclude-standard", "-z"], cwd=root).decode().split("\0")
    count = 0
    for name in sorted(set(paths) - {""}):
        path = root / name
        if path.is_file():
            if path.is_symlink():
                raise ValueError("Publication symlink: " + name)
            check_file(name, path.read_bytes())
            count += 1
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, nargs="?", default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    if args.path.is_dir():
        print(f"Checked {check_tree(args.path)} public files and their nested archives")
    else:
        check_file(args.path.name, args.path.read_bytes())
        print("Checked distribution and its nested archives")
