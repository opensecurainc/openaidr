"""Publication checks cover nested artifacts and preserve the public SDK contract."""

import io
from pathlib import Path
import runpy
import shutil
import sys
import tarfile
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
boundary = runpy.run_path(str(ROOT / "scripts/check_publication.py"))
verify = runpy.run_path(str(ROOT / "scripts/verify_public_dependencies.py"))["verify"]


def nested_wheel(name, contents):
    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(name, contents)
    bundle = io.BytesIO()
    with tarfile.open(fileobj=bundle, mode="w:gz") as archive:
        member = tarfile.TarInfo("dependencies/client.whl")
        member.size = len(wheel.getvalue())
        archive.addfile(member, io.BytesIO(wheel.getvalue()))
    return bundle.getvalue()


@pytest.mark.parametrize("name,contents", [
    ("openaidr_api/providers/guardrail.py", "PROMPT = 'private'"),
    ("openaidr/platform/store.py", "class Store: pass"),
    ("openaidr/server/store.py", "class Store:\n    def create_admin(self): pass"),
    ("promotion-provenance.json", "{}"),
    ("openaidr/server/guardrail/scoring.py", "CATEGORY_CRITERIA = {'test': 'private'}"),
    ("openaidr/server/model_costs.py", "RATES = {('provider', 'model'): (1, 2)}"),
    ("openaidr/server/page_chat.py", "INSTRUCTIONS = 'private provider prompt'"),
    ("openaidr/server/skill_worker.py", "settings = {'SKILLSPECTOR_PROVIDER': 'vendor'}"),
    ("../outside.py", ""),
])
def test_nested_private_content_is_rejected(name, contents):
    with pytest.raises(ValueError, match="runtime.tar.gz!dependencies/client.whl!"):
        boundary["check_file"]("runtime.tar.gz", nested_wheel(name, contents))


def test_shared_sdk_validation_migrations_and_provider_behavior_tests_are_public():
    boundary["check_file"]("runtime.tar.gz", nested_wheel(
        "openaidr_api_client/validation/assessment.py", "def score(levels):\n    return (sum(levels) * 100 + 6) // 12"))
    boundary["check_file"]("src/openaidr/server/migrations/0010_cloud_deployments.sql", b"CREATE TABLE deployments(id uuid);")
    boundary["check_file"]("tests/test_risk.py", b"from openaidr_api.providers.guardrail import CATEGORY_CRITERIA\nassert len(CATEGORY_CRITERIA) == 8")


def test_runtime_bundle_is_reproducible_and_refuses_private_copies(tmp_path):
    build = runpy.run_path(str(ROOT / "scripts/bundle_local_runtime.py"))["bundle"]
    source, output = tmp_path / "source.tar", tmp_path / "runtime.tar.gz"
    commit = "a" * 40

    def write_source(files, timestamp, mode=0o644):
        with tarfile.open(source, "w") as archive:
            for name, content in files:
                member = tarfile.TarInfo("openaidr-" + commit + "/" + name)
                member.size, member.mtime = len(content), timestamp
                member.mode = mode | (0o111 if name.startswith("scripts/") else 0)
                archive.addfile(member, io.BytesIO(content))

    files = [("src/openaidr/__init__.py", b""), ("README.md", b"public client"),
             ("scripts/local_bootstrap.py", b"# public startup")]
    write_source(files, 1, mode=0o664)
    first = build(source, output, commit)
    approved = output.read_bytes()
    with tarfile.open(output) as archive:
        assert archive.getmember("README.md").mode == 0o644
        assert archive.getmember("scripts/local_bootstrap.py").mode == 0o755
    write_source(list(reversed(files)), 2)
    assert build(source, output, commit) == first
    write_source(files + [("src/openaidr/platform/store.py", b"class Store: pass")], 3)
    with pytest.raises(ValueError, match="Private"):
        build(source, output, commit)
    assert output.read_bytes() == approved


def test_public_dependencies_reject_changed_wheels_and_private_metadata(tmp_path):
    source = ROOT / "dependencies/api-runtime"
    if not (source / "manifest.json").exists():
        pytest.skip("The private checkout retains its private dependency record")
    target = tmp_path / "dependencies"
    shutil.copytree(source, target)
    record = verify(target)
    private = target / "promotion-provenance.json"
    private.write_text("{}")
    with pytest.raises(ValueError, match="exactly"):
        verify(target)
    private.unlink()
    wheel = target / record["wheels"]["sdk"]["name"]
    wheel.write_bytes(wheel.read_bytes() + b"modified")
    with pytest.raises(ValueError, match="checksum"):
        verify(target)


def test_published_source_and_embedded_runtime_are_checked():
    if not (ROOT / "PUBLICATION.json").exists():
        pytest.skip("Run this check against the assembled public checkout")
    verify(ROOT / "dependencies/api-runtime")
    assert boundary["check_tree"](ROOT) > 0
