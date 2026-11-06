import hashlib
import io
import json
import os
import signal
import sys
import tarfile
import time

import pytest

from openaidr.sensor import cli, osquery_runtime as runtime
from scripts import build_osquery as build


def test_download_checks_new_and_cached_artifacts(tmp_path, monkeypatch):
    downloads = tmp_path / "downloads"
    artifact = b"pinned osquery archive"
    pin = {
        "url": "https://example.invalid/osquery.tar.gz",
        "sha256": hashlib.sha256(artifact).hexdigest(),
    }
    requests = []

    def fetch(url, timeout):
        requests.append(url)
        return io.BytesIO(artifact)

    monkeypatch.setattr(build.urllib.request, "urlopen", fetch)
    archive = build.download(pin, downloads)
    assert archive.read_bytes() == artifact
    assert build.download(pin, downloads) == archive
    assert requests == [pin["url"]]
    archive.write_bytes(b"corrupt cache")
    with pytest.raises(ValueError, match="checksum mismatch"):
        build.download(pin, downloads)
    archive.unlink()
    with pytest.raises(ValueError, match="checksum mismatch"):
        build.download({**pin, "sha256": "0" * 64}, downloads)
    assert not list(downloads.iterdir())


@pytest.mark.parametrize("kind", ["file", "symlink", "duplicate", "missing"])
def test_extracts_only_the_pinned_regular_member(tmp_path, kind):
    archive = tmp_path / "osquery.tar.gz"
    destination = tmp_path / "osqueryi"
    with tarfile.open(archive, "w:gz") as bundle:
        unwanted = tarfile.TarInfo("../unexpected")
        unwanted.size = 1
        bundle.addfile(unwanted, io.BytesIO(b"x"))
        if kind != "missing":
            member = tarfile.TarInfo("osqueryd")
            if kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = "../unexpected"
                bundle.addfile(member)
            else:
                member.size = 6
                bundle.addfile(member, io.BytesIO(b"binary"))
                if kind == "duplicate":
                    bundle.addfile(member, io.BytesIO(b"binary"))
    if kind == "file":
        build.extract_binary(archive, "osqueryd", destination)
        assert destination.read_bytes() == b"binary"
        assert destination.stat().st_mode & 0o777 == 0o755
    else:
        with pytest.raises(ValueError, match="one regular executable"):
            build.extract_binary(archive, "osqueryd", destination)
        assert not destination.exists()
    assert not (tmp_path.parent / "unexpected").exists()


@pytest.mark.skipif(
    os.name != "posix", reason="macOS runtime uses POSIX process groups"
)
@pytest.mark.parametrize("failure", ["timeout", "stdout", "stderr", "parent_exit"])
def test_runtime_bounds_output_and_cleans_up_descendants(
    tmp_path, monkeypatch, failure
):
    script = tmp_path / "fixture.py"
    script.write_text(
        "import os, signal, sys, time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "child = os.fork()\n"
        "if child == 0:\n"
        "    while True: time.sleep(60)\n"
        "Path('pids').write_text(f'{os.getpid()} {child}')\n"
        "if sys.argv[1] in ('stdout', 'stderr'):\n"
        "    fd = 1 if sys.argv[1] == 'stdout' else 2\n"
        "    while True: os.write(fd, b'x' * 8192)\n"
        "if sys.argv[1] == 'parent_exit': sys.exit(0)\n"
        "while True: time.sleep(60)\n"
    )
    monkeypatch.setattr(runtime, "TIMEOUT", 2)
    pids = []
    try:
        with pytest.raises(runtime.OsqueryError, match="timed out|output limit"):
            runtime._run([sys.executable, str(script), failure], tmp_path)
        pids = [int(pid) for pid in (tmp_path / "pids").read_text().split()]
        # Give the OS time to reap the orphan after the process group is killed.
        for pid in pids:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                pytest.fail(f"osquery descendant {pid} survived cleanup")
    finally:
        if not pids and (tmp_path / "pids").exists():
            pids = [int(pid) for pid in (tmp_path / "pids").read_text().split()]
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [
            {
                "osquery_version": "wrong",
                "extension_version": "0.1.0",
                "schema_version": "1",
            }
        ],
        [
            {
                "osquery_version": "5.23.1",
                "extension_version": "wrong",
                "schema_version": "1",
            }
        ],
    ],
)
def test_check_rejects_missing_or_mismatched_registration(tmp_path, monkeypatch, rows):
    monkeypatch.setattr(runtime.sys, "platform", "darwin")
    monkeypatch.setattr(runtime, "runtime_directory", lambda: tmp_path)
    monkeypatch.setattr(runtime, "_run", lambda *args, **kwargs: rows)
    for name in ("osqueryi", "openaidr-osquery.ext"):
        (tmp_path / name).touch()
    (tmp_path / "osquery.lock.json").write_text(json.dumps({"version": "5.23.1"}))
    with pytest.raises(runtime.OsqueryError, match="version mismatch"):
        runtime.check_runtime()


@pytest.mark.parametrize(
    "failure, diagnostic", [("exit", "exit 7"), ("json", "invalid JSON")]
)
def test_runtime_failure_diagnostics_exclude_process_output(
    tmp_path, failure, diagnostic
):
    script = (
        "import sys; sys.stderr.write('private-stderr-token'); "
        "print('private-stdout-token'); "
        f"sys.exit({7 if failure == 'exit' else 0})"
    )
    with pytest.raises(runtime.OsqueryError, match=diagnostic) as caught:
        runtime._run([sys.executable, "-c", script], tmp_path)
    assert "private-" not in str(caught.value)


def test_cli_check_reports_unavailable_without_enrollment(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(runtime.sys, "platform", "darwin")
    monkeypatch.setattr(runtime, "runtime_directory", lambda: tmp_path)
    assert cli.main(["osquery-check"]) == 1
    assert "Bundled osquery is unavailable" in capsys.readouterr().err
