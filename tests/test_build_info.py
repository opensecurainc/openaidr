"""Source identity at Git, frontend, and Python distribution boundaries."""

from datetime import datetime, timezone
from importlib.metadata import distribution
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import zipfile

import pytest
from packaging.version import Version

from openaidr.build_info import environment, requires_clean_source, resolve, validate

ROOT = Path(__file__).resolve().parents[1]
STAMP = int(datetime(2026, 10, 7, 1, 30, tzinfo=timezone.utc).timestamp())


@pytest.fixture
def source(tmp_path):
    for name in ("setup.py", "MANIFEST.in", "src/openaidr/__init__.py", "src/openaidr/build_info.py",
                 "scripts/build_version.py", "scripts/build-version.mjs",
                 "packages/common/setup.py", "packages/common/pyproject.toml", "packages/common/README.md"):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)
    for name in ("api/__init__.py", "packages/common/src/openaidr_common/__init__.py"):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# Separately owned package must stay outside the tenant artifact.\n")
    (tmp_path / "pyproject.toml").write_text('''[build-system]
requires = ["setuptools>=77", "wheel"]
build-backend = "setuptools.build_meta"
[project]
name = "openaidr"
dynamic = ["version"]
[tool.setuptools]
package-dir = {"" = "src"}
[tool.setuptools.packages.find]
where = ["src"]
include = ["openaidr", "openaidr.*"]
namespaces = false
[tool.setuptools.package-data]
openaidr = ["_build.json"]
''')
    (tmp_path / ".gitignore").write_text("build/\ndist/\n*.egg-info/\n__pycache__/\n")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    env = {**os.environ, "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.test",
           "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.test",
           "GIT_AUTHOR_DATE": "2020-01-01T00:00:00Z", "GIT_COMMITTER_DATE": f"@{STAMP} +0000"}
    subprocess.run(["git", "commit", "-qm", "Source identity fixture"], cwd=tmp_path, env=env, check=True)
    return tmp_path


def test_all_build_entrypoints_resolve_one_identity_and_reject_dirty_source(source):
    info = resolve(source, environ={"OPENAIDR_BUILD_DATE": "2030-01-01T00:00:00Z"})
    assert info["version"] == "2026.10.6+" + info["source_commit"][:7]
    assert info["source_timestamp"] == STAMP
    env = {**os.environ, **environment(info), "OPENAIDR_PYTHON": sys.executable}
    node = subprocess.check_output(
        ["node", "--input-type=module", "-e", "import {buildInfo} from './scripts/build-version.mjs'; console.log(JSON.stringify(buildInfo()));"],
        cwd=source, env=env, text=True,
    )
    assert json.loads(node) == info
    assert resolve(source, environ={**environment(info), "OPENAIDR_VERSION": info["version"] + info["source_commit"][7:10]})["version"].endswith(info["source_commit"][:10])
    with pytest.raises(ValueError, match="does not match"):
        resolve(source, environ={**environment(info), "OPENAIDR_BUILD_COMMIT": "a" * 40})
    (source / "uncommitted").write_text("change")
    with pytest.raises(ValueError, match="commit the intended"):
        resolve(source, environ={})
    (source / "uncommitted").unlink()
    (source / "src/openaidr/__init__.py").write_text("# changed\n")
    with pytest.raises(ValueError, match="commit the intended"):
        resolve(source, environ=environment(info))


@pytest.mark.parametrize("argv, strict", [
    (["setup.py", "editable_wheel", "--dist-dir", "/tmp/out"], False),
    (["setup.py", "egg_info"], False),
    (["setup.py", "dist_info", "--output-dir", "/tmp/out", "--keep-egg-info"], False),
    (["setup.py", "develop"], False),
    (["setup.py", "bdist_wheel"], True),
    (["setup.py", "sdist"], True),
    (["setup.py", "egg_info", "bdist_wheel"], True),
    (["setup.py", "bdist_egg"], True),
    (["setup.py", "--version"], True),
])
def test_only_metadata_and_editable_commands_tolerate_uncommitted_changes(argv, strict):
    assert requires_clean_source(argv) is strict


@pytest.mark.parametrize("project, name", [(".", "openaidr"), ("packages/common", "openaidr_common")])
def test_editable_installs_accept_uncommitted_changes_but_artifacts_do_not(source, tmp_path, project, name):
    (source / "src/openaidr/__init__.py").write_text("# work in progress\n")
    dist = tmp_path / "dist"
    dist.mkdir()

    def build(hook):
        # The same hook sequence pip runs for the install kind.
        kind = hook.split("_")[-1]
        metadata = f"m.prepare_metadata_for_build_{kind}({str(dist)!r}); " if kind != "sdist" else ""
        code = (f"from setuptools import build_meta as m; m.get_requires_for_build_{kind}(); "
                f"{metadata}print(m.{hook}({str(dist)!r}))")
        return subprocess.run([sys.executable, "-c", code], cwd=source / project, capture_output=True, text=True)

    editable = build("build_editable")
    assert editable.returncode == 0, editable.stderr
    with zipfile.ZipFile(dist / editable.stdout.strip().splitlines()[-1]) as wheel:
        metadata = wheel.read(next(entry for entry in wheel.namelist() if entry.endswith("METADATA"))).decode()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    assert "Name: " + name.replace("_", "-") in metadata
    assert "Version: 2026.10.6+" + head[:7] in metadata
    for hook in ("build_wheel", "build_sdist"):
        result = build(hook)
        assert result.returncode != 0 and "commit the intended changes" in result.stderr


@pytest.mark.parametrize("instant, expected", [
    ("2026-03-08T07:59:59+00:00", "2026.3.7"),
    ("2026-03-08T08:00:00+00:00", "2026.3.8"),
    ("2026-11-01T06:59:59+00:00", "2026.10.31"),
    ("2026-11-01T07:00:00+00:00", "2026.11.1"),
])
def test_git_free_builds_use_committer_date_in_los_angeles(tmp_path, instant, expected):
    env = {"OPENAIDR_BUILD_COMMIT": "a" * 40, "OPENAIDR_COMMIT_TIMESTAMP": str(int(datetime.fromisoformat(instant).timestamp()))}
    info = resolve(tmp_path, environ=env)
    assert info["version"] == expected + "+aaaaaaa"
    for missing in env:
        with pytest.raises(ValueError, match="Git-free builds require"):
            resolve(tmp_path, environ={key: value for key, value in env.items() if key != missing})
    with pytest.raises(ValueError, match="must match"):
        validate({**info, "version": expected + "+bbbbbbb"})


@pytest.mark.parametrize("prefix_length", [7, 10])
def test_wheel_and_sdist_preserve_identity_without_git_or_runtime_environment(source, tmp_path, prefix_length):
    info = resolve(source, environ={})
    info["version"] = info["version"].split("+")[0] + "+" + info["source_commit"][:prefix_length]
    env = {**os.environ, **environment(info)}
    result = subprocess.run([sys.executable, "-m", "build", "--no-isolation"], cwd=source, env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    wheel, = (source / "dist").glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        assert json.loads(archive.read("openaidr/_build.json")) == info
        assert not any(name.startswith(("api/", "openaidr_common/", "openaidr_api", "packages/common/"))
                       for name in archive.namelist())
        metadata, = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        assert f"Version: {Version(info['version'])}" in archive.read(metadata).decode()
        installed = tmp_path / "installed"
        archive.extractall(installed)
    sdist, = (source / "dist").glob("*.tar.gz")
    with tarfile.open(sdist) as archive:
        record, = [member for member in archive.getmembers() if member.name.endswith("src/openaidr/_build.json")]
        assert json.load(archive.extractfile(record)) == info
        assert not any("/api/" in member.name or "/packages/common/" in member.name
                       for member in archive.getmembers())
    # Import the installed package outside the checkout; runtime environment
    # values cannot change an artifact's recorded identity.
    output = subprocess.check_output(
        [sys.executable, "-c", "import openaidr; from openaidr.build_info import current; import json; print(json.dumps([openaidr.__version__, current()]))"],
        cwd=installed, env={**env, "PYTHONPATH": str(installed), "OPENAIDR_VERSION": "0.1.0"}, text=True,
    )
    assert json.loads(output) == [info["version"], info]


def test_sensor_and_backend_clis_report_the_same_source_identity():
    from openaidr import __version__
    from openaidr.sensor.cli import app_version
    assert app_version() == __version__
    entrypoints = {entry.name: entry for entry in distribution('openaidr').entry_points
                   if entry.group == 'console_scripts'}
    for name, expected in [('openaidr', 'openaidr'), ('openaidr-sensor', 'openaidr'),
                           ('openaidr-server', 'openaidr-server')]:
        entry = entrypoints[name]
        code = f'from {entry.module} import {entry.attr} as main; raise SystemExit(main(["version"]))'
        result = subprocess.check_output([sys.executable, '-c', code], cwd=ROOT, text=True).strip()
        assert result == f'{expected} {__version__}'
