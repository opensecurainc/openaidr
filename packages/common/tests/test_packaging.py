"""The public-safe helper artifact must work without either application checkout."""

import json
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parents[3]
PACKAGE = ROOT / "packages/common"


def run(*args, cwd):
    return subprocess.run([sys.executable, *args], cwd=cwd, check=True,
                          capture_output=True, text=True)


def test_source_archive_builds_an_independent_installed_wheel(tmp_path):
    dist = tmp_path / "dist"
    run("-m", "build", "--sdist", "--outdir", str(dist), str(PACKAGE), cwd=tmp_path)
    archive = next(dist.glob("*.tar.gz"))
    with tarfile.open(archive) as source:
        source.extractall(tmp_path / "source", filter="data")
    extracted = next((tmp_path / "source").iterdir())
    assert (extracted / "_build_support.py").read_bytes() == (
        ROOT / "src/openaidr/build_info.py").read_bytes()
    run("-m", "build", "--wheel", "--outdir", str(dist), str(extracted), cwd=tmp_path)
    wheel = next(dist.glob("*.whl"))
    with zipfile.ZipFile(wheel) as artifact:
        names = artifact.namelist()
        assert all(name.startswith("openaidr_common/") or ".dist-info/" in name for name in names)
        assert not any("_build_support" in name for name in names)
        info = json.loads(artifact.read("openaidr_common/_build.json"))
        assert info == json.loads((extracted / "src/openaidr_common/_build.json").read_text())
        metadata = artifact.read(next(name for name in names if name.endswith(".dist-info/METADATA"))).decode()
        assert [line for line in metadata.splitlines() if line.startswith("Requires-Dist:")] == [
            "Requires-Dist: PyYAML<7,>=6"]
    installed = tmp_path / "installed"
    run("-m", "pip", "install", "--no-deps", "--target", str(installed), str(wheel), cwd=tmp_path)
    proof = r'''
import importlib.abc
import json
import sys
from pathlib import Path

class ApplicationImportsForbidden(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'openaidr', 'api', 'fastapi', 'psycopg', 'httpx'}:
            raise AssertionError('shared helpers imported application dependency: ' + fullname)

sys.meta_path.insert(0, ApplicationImportsForbidden())
sys.path.insert(0, sys.argv[1])
from openaidr_common.event import EVIDENCE_GAPS, PRODUCTS
from openaidr_common.policy import compile_glob, compile_rules
from openaidr_common.redact import redact_string, redact_value

assert 'content_redacted' in EVIDENCE_GAPS and 'codex-cli' in PRODUCTS
pattern = compile_glob('/srv/payroll/**')
assert pattern.match('/srv/payroll/private.csv')
assert not pattern.match('/srv/public/readme.txt')
assert compile_rules({'rules': [{'match': {'command_regex': '['}}]})[1]
assert not compile_rules({'rules': [{'match': {'command_regex': 'safe.*'}}]})[1]
for case in json.loads(Path(sys.argv[2]).read_text()):
    text = case['before'] + case['secret'] + case['after']
    result, names = redact_string(text)
    assert names and case['secret'] not in result
    assert result.startswith(case['before'] + '[REDACTED:')
    assert result.endswith(']' + case['after'])
    assert redact_string(result) == (result, [])
assert redact_value({'password': 'synthetic-password'}) == {'password': '[REDACTED]'}
'''
    fixtures = tmp_path / "redaction.json"
    fixtures.write_bytes((ROOT / "tests/fixtures/secret-redaction.json").read_bytes())
    run("-I", "-c", proof, str(installed), str(fixtures), cwd=tmp_path)
