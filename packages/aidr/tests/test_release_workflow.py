"""Release validation must stop on failures before upload and publication."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.skipif(os.name == "nt", reason="The release runs on an Ubuntu runner")
@pytest.mark.parametrize("failure", [None, "manifest", "source", "install", "tests", "dependencies", "wheel", "sdist"])
def test_aidr_release_checks_stop_before_upload(tmp_path, failure):
    workflow = yaml.safe_load((ROOT / ".github/workflows/pypi.yml").read_text())
    steps = workflow["jobs"]["build"]["steps"]
    gate = next(step for step in steps if step.get("name") == "Verify the aidr release")
    upload = next(step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert steps.index(gate) < steps.index(upload)
    assert gate["if"] == "steps.select.outputs.package == 'aidr'"
    assert workflow["jobs"]["publish"]["needs"] == "build"
    assert not gate.get("continue-on-error", False)
    assert not upload.get("if")

    dist = tmp_path / "dist"
    dist.mkdir()
    for name in ("aidr-0.1.0-py3-none-any.whl", "aidr-0.1.0.tar.gz"):
        (dist / name).touch()
    commands = [
        ("manifest", ["scripts/verify_public_dependencies.py"]),
        ("source", ["scripts/check_publication.py"]),
        ("install", ["-m", "pip", "install", "--upgrade", "setuptools>=77", "wheel", "pytest", "dist/aidr-0.1.0-py3-none-any.whl"]),
        ("tests", ["-I", "-m", "pytest", "-q", "packages/aidr/tests"]),
        ("dependencies", ["-m", "pip", "check"]),
        ("wheel", ["scripts/check_publication.py", "dist/aidr-0.1.0-py3-none-any.whl"]),
        ("sdist", ["scripts/check_publication.py", "dist/aidr-0.1.0.tar.gz"]),
    ]
    failed_args = next((args for name, args in commands if name == failure), None)
    tools = tmp_path / "tools"
    tools.mkdir()
    python = tools / "python"
    python.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "with open(os.environ['COMMAND_LOG'], 'a') as log:\n"
        "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "raise SystemExit(17 if sys.argv[1:] == json.loads(os.environ['FAILED_ARGS']) else 0)\n"
    )
    python.chmod(0o755)
    log = tmp_path / "commands.jsonl"
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", gate["run"]], cwd=tmp_path,
        env={**os.environ, "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}",
             "COMMAND_LOG": str(log), "FAILED_ARGS": json.dumps(failed_args)},
        capture_output=True, text=True,
    )
    assert result.returncode == (17 if failure else 0), result.stderr
    expected = [args for _, args in commands]
    if failed_args is not None:
        expected = expected[:expected.index(failed_args) + 1]
    assert [json.loads(line) for line in log.read_text().splitlines()] == expected
