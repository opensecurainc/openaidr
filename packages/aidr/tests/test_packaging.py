"""The released artifact must build and run independently of this repository."""

import ast
from email.parser import Parser
import importlib.metadata
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile

import pytest


PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[1]


def run(*args, cwd):
    return subprocess.run([sys.executable, *args], cwd=cwd, check=True,
                          capture_output=True, text=True)


@pytest.fixture
def clean_package(tmp_path):
    repository = tmp_path / "repository"
    package = repository / "packages/aidr"
    ignore = shutil.ignore_patterns("_vendor", "build", "dist", "*.egg-info", "__pycache__", ".pytest_cache")
    shutil.copytree(PACKAGE, package, ignore=ignore)
    shutil.copytree(ROOT / "packages/common/src", repository / "packages/common/src", ignore=ignore)
    shutil.copytree(ROOT / "dependencies/api-runtime", repository / "dependencies/api-runtime")
    shutil.copyfile(ROOT / "LICENSE", repository / "LICENSE")
    return package


def test_source_distribution_builds_independent_wheel_with_reused_sources(tmp_path, clean_package):
    dist = tmp_path / "dist"
    run("-m", "build", "--no-isolation", "--sdist", "--outdir", str(dist), str(clean_package), cwd=tmp_path)
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
    tests = tmp_path / "runtime_tests"
    tests.mkdir()
    for name in ("test_client.py", "test_credentials.py", "test_cli.py"):
        (tests / name).write_bytes((PACKAGE / "tests" / name).read_bytes())
    run("-I", "-c", proof, str(installed), str(tests), cwd=tmp_path)


@pytest.mark.parametrize("failure", ["missing_manifest", "modified_wheel"])
def test_repository_build_rejects_invalid_dependencies_despite_cached_vendor(tmp_path, clean_package, failure):
    vendor = clean_package / "src/aidr/_vendor"
    vendor.mkdir()
    (vendor / "provenance.json").write_text("{}")
    manifest = clean_package.parents[1] / "dependencies/api-runtime/manifest.json"
    if failure == "missing_manifest":
        manifest.unlink()
        expected = "Build aidr from the repository or its complete source distribution"
    else:
        sdk = json.loads(manifest.read_text())["wheels"]["sdk"]
        wheel = manifest.parent / sdk["name"]
        wheel.write_bytes(wheel.read_bytes() + b"modified")
        expected = "The API client wheel does not match its reviewed checksum"
    with pytest.raises(subprocess.CalledProcessError) as caught:
        run("-m", "build", "--no-isolation", "--sdist", "--outdir", str(tmp_path / "dist"),
            str(clean_package), cwd=tmp_path)
    assert expected in caught.value.stderr
    assert (vendor / "provenance.json").read_text() == "{}"
