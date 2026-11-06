"""The released artifact must build and run independently of this repository."""

import ast
from email.parser import Parser
import importlib.metadata
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import zipfile


PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[1]


def run(*args, cwd):
    return subprocess.run([sys.executable, *args], cwd=cwd, check=True,
                          capture_output=True, text=True)


def test_source_distribution_builds_independent_wheel_with_reused_sources(tmp_path):
    dist = tmp_path / "dist"
    run("-m", "build", "--no-isolation", "--sdist", "--outdir", str(dist), str(PACKAGE), cwd=tmp_path)
    with tarfile.open(next(dist.glob("*.tar.gz"))) as archive:
        archive.extractall(tmp_path / "source", filter="data")
    source = next((tmp_path / "source").iterdir())
    run("-m", "build", "--no-isolation", "--wheel", "--outdir", str(dist), str(source), cwd=tmp_path)
    wheel = next(dist.glob("*.whl"))
    sdk = json.loads((ROOT / "dependencies/api-runtime/manifest.json").read_text())["wheels"]["sdk"]
    with zipfile.ZipFile(wheel) as built, zipfile.ZipFile(ROOT / "dependencies/api-runtime" / sdk["name"]) as upstream:
        names = built.namelist()
        assert all(name.startswith("aidr/") or ".dist-info/" in name for name in names)
        assert "aidr/_vendor/LICENSE" in names
        assert "aidr/_vendor/openaidr_common/secret-redaction.yaml" in names
        assert "aidr/_vendor/openaidr_common/secret-redaction.LICENSE" in names
        for name in upstream.namelist():
            if name.startswith("openaidr_api_client/"):
                original = upstream.read(name)
                if name.endswith(".py"):
                    original = re.sub(rb"(?m)^(\s*from )(openaidr_api_client|openaidr_common)(?=[ .])",
                                      rb"\1aidr._vendor.\2", original)
                assert built.read("aidr/_vendor/" + name) == original
        for name in names:
            if not name.endswith(".py"):
                continue
            for node in ast.walk(ast.parse(built.read(name))):
                imports = ([node.module] if isinstance(node, ast.ImportFrom) and node.level == 0
                           else [alias.name for alias in node.names] if isinstance(node, ast.Import) else [])
                assert all(not item.startswith(("openaidr_api", "openaidr_common")) for item in imports)
        metadata = Parser().parsestr(built.read(next(n for n in names if n.endswith("/METADATA"))).decode())
        assert not any("openaidr" in item for item in metadata.get_all("Requires-Dist"))
        assert metadata["Version"] == importlib.metadata.version("aidr")

    installed = tmp_path / "installed"
    run("-m", "pip", "install", "--no-deps", "--target", str(installed), str(wheel), cwd=tmp_path)
    proof = '''
import importlib.abc
import sys

class ForbidPrivateDependencies(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'openaidr', 'openaidr_api_client', 'openaidr_api', 'openaidr_common', 'fastapi'}:
            raise AssertionError('Unexpected dependency: ' + fullname)

sys.meta_path.insert(0, ForbidPrivateDependencies())
sys.path.insert(0, sys.argv[1])
from aidr import AIDR, AsyncAIDR, GuardrailError, ScanError
from aidr._vendor.openaidr_common.redact import redact_value
assert redact_value({'password': 'example'}) == {'password': '[REDACTED]'}
import pytest
raise SystemExit(pytest.main(['-q', sys.argv[2]]))
'''
    tests = tmp_path / "test_installed.py"
    tests.write_bytes((PACKAGE / "tests/test_client.py").read_bytes())
    run("-I", "-c", proof, str(installed), str(tests), cwd=tmp_path)
