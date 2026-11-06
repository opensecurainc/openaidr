"""CLI discovery through real files, including native Windows launcher layouts."""

import io
import json
import os
from pathlib import Path
import shutil
import stat
import threading
from types import SimpleNamespace
from unittest.mock import Mock
import zipfile

import pytest

from openaidr.sensor import cli, component_inventory as inventory, inventory_service
from openaidr.sensor.config import Config
from openaidr.sensor.privacy import PrivacyGuard, PrivacySkip
from openaidr.server.component_inventory import validate_snapshot


def write(path, body, *, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(body, bytes):
        path.write_bytes(body)
    else:
        path.write_text(body, encoding="utf-8")
    if executable:
        path.chmod(0o755)
    return path


def launcher(path, python, script):
    # distlib's format: native PE prefix, interpreter shebang, stored zip script.
    stream = io.BytesIO(b'MZ\0#!"' + str(python).encode() + b'" -I\n')
    stream.seek(0, 2)
    with zipfile.ZipFile(stream, "a") as archive:
        archive.writestr("__main__.py", script)
    return write(path, stream.getvalue())


def options(**values):
    return inventory.settings({"inventory": {"components": {"include_default_roots": False, **values}}})


def rows(snapshot):
    validate_snapshot("b8c94c3e-8ecf-4734-939c-1a44b43cae49", snapshot)
    assert all(root["source"] == "openaidr-cli" for root in snapshot["roots"])
    assert all(root["status"] == "ok" for root in snapshot["roots"]), snapshot["roots"]
    return {item["key"]: item for root in snapshot["roots"] for item in root["components"]}


@pytest.fixture
def windows(tmp_path, monkeypatch):
    home = tmp_path.resolve() / "user with spaces"
    monkeypatch.setattr(inventory.sys, "platform", "win32")
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("LOCALAPPDATA", str(home / "AppData/Local"))
    monkeypatch.setenv("APPDATA", str(home / "AppData/Roaming"))
    monkeypatch.setattr(inventory, "inventory_rows", Mock(side_effect=AssertionError("No osquery on Windows")))
    return home


def test_windows_default_launchers_identify_packages_without_execution(windows, capsys):
    local = windows / "AppData/Local"
    project = local / "hermes/hermes-agent"
    write(project / "pyproject.toml", '[project]\nname="hermes-agent"\nversion="1.2"\n'
          '[project.scripts]\nhermes="hermes_cli.main:main"\n')
    marker = windows / "must-not-run"
    script = (f'import sys\nsys.path.insert(0, {str(project)!r})\n'
              f'from pathlib import Path\nPath({str(marker)!r}).touch()\n'
              'from hermes_cli.main import main\nsys.exit(main())\n')
    launcher(local / "hermes/bin/hermes.exe", local / "hermes/tools/python.exe", script)

    npm = windows / "AppData/Roaming/npm"
    write(npm / "node_modules/@openai/codex/bin/codex.js", "process.exit(1)")
    write(npm / "node_modules/@openai/codex/package.json", json.dumps({
        "name": "@openai/codex", "version": "2.0", "bin": {"codex": "bin/codex.js"},
    }))
    write(npm / "codex.cmd", '@ECHO off\nGOTO start\n:find_dp0\nSET dp0=%~dp0\nEXIT /b\n:start\nSETLOCAL\nCALL :find_dp0\n'
          '"%dp0%\\node.exe" "%dp0%\\node_modules\\@openai\\codex\\bin\\codex.js" %*\n')
    write(npm / "codex.ps1", '#!/usr/bin/env pwsh\n$basedir=Split-Path $MyInvocation.MyCommand.Definition -Parent\n'
          '& "$basedir/node.exe" "$basedir/node_modules/@openai/codex/bin/codex.js" $args\n')

    env = local / "uv/tools/aider-chat"
    metadata = env / "Lib/site-packages/aider_chat-1.0.dist-info"
    write(metadata / "entry_points.txt", "[console_scripts]\naider = aider.main:main\n")
    write(metadata / "METADATA", "Name: aider-chat\nVersion: 1.0\n")
    launcher(windows / ".local/bin/aider.exe", env / "Scripts/python.exe",
             "from aider.main import main\nmain()\n")
    write(windows / ".local/bin/codex.exe", b"MZ\0unidentified executable")
    write(windows / ".local/bin/README.txt", "not a launcher")
    write(windows / ".local/bin/library.dll", b"MZ\0not an executable command")

    result = inventory.collect_inventory(options(include_default_roots=True))
    found = rows(result)
    assert result["platform"] == "windows"
    assert set(found) == {"hermes.exe", "codex.cmd", "codex.ps1", "aider.exe", "codex.exe"}
    assert found["hermes.exe"]["identifier"] == "pypi:hermes-agent"
    assert found["hermes.exe"]["version"] == "1.2"
    assert found["aider.exe"]["identifier"] == "pypi:aider-chat"
    assert found["codex.cmd"]["identifier"] == found["codex.ps1"]["identifier"] == "npm:@openai/codex"
    assert found["codex.exe"]["identifier"].startswith("executable:")
    assert not marker.exists()
    assert "sys.path" not in json.dumps(result) and "must-not-run" not in json.dumps(result)
    assert cli.main(["component-inventory", "--json", "--no-default-roots", "--bin-root", str(local / "hermes/bin")]) == 0
    assert rows(json.loads(capsys.readouterr().out))["hermes.exe"]["identifier"] == "pypi:hermes-agent"


def test_windows_python_scripts_and_unconfirmed_metadata(windows):
    env = windows / "AppData/Local/Programs/Python/Python314"
    command = write(env / "Scripts/agent.exe", b"MZ\0native stub")
    metadata = env / "Lib/site-packages/sample-1.0.dist-info"
    write(metadata / "entry_points.txt", "[console_scripts]\nagent = sample:main\n")
    write(metadata / "METADATA", "Name: Sample_Agent\nVersion: 1.0\n")
    cfg = options(include_default_roots=True)
    assert rows(inventory.collect_inventory(cfg))["agent.exe"]["identifier"] == "pypi:sample-agent"
    write(metadata / "entry_points.txt", "[console_scripts]\nother = sample:main\n")
    assert rows(inventory.collect_inventory(cfg))["agent.exe"]["identifier"].startswith("executable:")
    # An opaque native executable and an unrelated project declaration are insufficient.
    write(env / "pyproject.toml", '[project]\nname="hermes-agent"\n[project.scripts]\nhermes="sample:main"\n')
    command.rename(command.with_name("hermes.exe"))
    assert rows(inventory.collect_inventory(cfg))["hermes.exe"]["identifier"].startswith("executable:")


def test_windows_launcher_requires_matching_declarations(windows):
    base = windows / "bin"
    project = windows / "source"
    metadata = write(project / "pyproject.toml", '[project]\nname="hermes-agent"\n'
                     '[project.scripts]\nhermes="hermes_cli.main:main"\n')
    launcher(base / "hermes.exe", windows / "python.exe",
             f'import sys\nsys.path.insert(0, {str(project)!r})\nfrom unrelated import main\n')
    npm = base / "node_modules/tool"
    write(npm / "package.json", '{"name":"@openai/codex","bin":{"codex":"other.js"}}')
    write(npm / "main.js", "process.exit(1)")
    write(base / "codex.cmd", 'SET "dp0=%~dp0"\n"%dp0%\\node_modules\\tool\\main.js" %*\n')
    cfg = options(bin_roots=[str(base)])
    found = rows(inventory.collect_inventory(cfg))
    assert all(item["identifier"].startswith("executable:") for item in found.values())
    metadata.write_text('[project]\nname="hermes-agent"\n[project.scripts]\nhermes=["bad"]\n')
    assert rows(inventory.collect_inventory(cfg))["hermes.exe"]["identifier"].startswith("executable:")


@pytest.mark.skipif(os.name != "nt", reason="Windows path and drive APIs")
def test_windows_rejects_remote_paths_before_reading(windows, monkeypatch):
    import ctypes

    remote = r"\\inventory-test.invalid\share\project"
    base = windows / "bin"
    launcher(base / "hermes.exe", windows / "python.exe",
             f'import sys\nsys.path.insert(0, {remote!r})\nfrom hermes_cli.main import main\n')
    lstat = Path.lstat

    def local_only(path, *args, **kwargs):
        assert not path.drive.startswith("\\") and path.drive.lower() != "z:"
        if path == windows / "junction":
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        return lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", local_only)
    monkeypatch.setattr(os, "readlink", lambda path: remote)
    drive_type = Mock(side_effect=lambda drive: 4 if drive.lower() == "z:\\" else 3)
    monkeypatch.setattr(ctypes.windll.kernel32, "GetDriveTypeW", drive_type)
    guard = PrivacyGuard()
    for path in (remote, r"Z:\project", windows / "junction/pyproject.toml"):
        with pytest.raises(PrivacySkip, match="local fixed disk"):
            guard.check(path)
    root, = inventory.collect_inventory(options(bin_roots=[str(base)]))["roots"]
    assert root["status"] == "partial"
    assert root["components"][0]["identifier"].startswith("executable:")
    # Local junctions retain normal discovery after resolving the NT prefix.
    monkeypatch.setattr(os, "readlink", lambda path: "\\\\?\\" + str(base))
    assert guard.check(windows / "junction/hermes.exe") == base / "hermes.exe"


@pytest.mark.parametrize("script", ["invalid syntax!", "x = '" + "a" * 65536 + "'"], ids=["syntax", "oversized"])
def test_windows_bad_launchers_keep_unknown_identity_and_partial_coverage(windows, script):
    base = windows / "bin"
    launcher(base / "hermes.exe", windows / "python.exe", script)
    root, = inventory.collect_inventory(options(bin_roots=[str(base)]))["roots"]
    assert root["status"] == "partial"
    assert root["components"][0]["identifier"].startswith("executable:")
    shutil.rmtree(base)
    assert inventory.collect_inventory(options(bin_roots=[str(base)]), [root])["roots"][0]["status"] == "unavailable"
    base.mkdir()
    assert inventory.collect_inventory(options(bin_roots=[str(base)]), [root])["roots"][0]["components"] == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher and symlink semantics")
def test_linux_hermes_and_npm_launchers(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(inventory.sys, "platform", "linux")
    home = tmp_path.resolve()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setattr(inventory, "inventory_rows", Mock(side_effect=AssertionError("No osquery on Linux")))
    project = home / ".hermes/hermes-agent"
    target = write(project / ".hermes/bin/hermes", "#!/bin/sh\nexit 1\n", executable=True)
    write(project / "pyproject.toml", '[project]\nname="hermes-agent"\nversion="1.2"\n'
          '[project.scripts]\nhermes="hermes_cli.main:main"\n')
    bin_dir = home / ".local/bin"
    write(bin_dir / "hermes", f'#!/bin/sh\nexec "{target}" "$@"\n', executable=True)
    (bin_dir / "hermes-alias").symlink_to(bin_dir / "hermes")
    node = home / ".npm-global/lib/node_modules/@openai/codex"
    target = write(node / "bin/codex.js", "#!/usr/bin/env node\nprocess.exit(1)\n", executable=True)
    write(node / "package.json", json.dumps({"name": "@openai/codex", "bin": {"codex": "bin/codex.js"}}))
    write(home / ".npm-global/bin/placeholder", "not executable")
    (home / ".npm-global/bin/codex").symlink_to(target)
    # Keep host system directories out of the test while exercising real discovery.
    expand = inventory._Scan.expand

    def isolated(scan, base, pattern):
        return iter(()) if base == "/" else expand(scan, base, pattern)

    monkeypatch.setattr(inventory._Scan, "expand", isolated)
    found = rows(inventory.collect_inventory(options(include_default_roots=True)))
    assert found["hermes"]["identifier"] == found["hermes-alias"]["identifier"] == "pypi:hermes-agent"
    assert found["codex"]["identifier"] == "npm:@openai/codex"
    assert cli.main(["component-inventory", "--json", "--no-default-roots", "--bin-root", str(bin_dir)]) == 0
    assert json.loads(capsys.readouterr().out)["platform"] == "linux"


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_cli_upload_retry_and_lifecycle_coexist_with_native_inventory(tmp_path, monkeypatch, platform):
    monkeypatch.setattr(inventory.sys, "platform", platform)
    write(tmp_path / "bin/tool.exe", b"MZ\0unknown", executable=True)
    cfg = Config(tmp_path / "config.yaml", data_dir=str(tmp_path), sensor_id="sensor-a",
                 server_url="https://tenant.example", inventory={"components": {
                     "include_default_roots": False, "bin_roots": [str(tmp_path / "bin")],
                     "app_roots": [str(tmp_path / "unsupported-apps")],
                     "project_roots": [str(tmp_path / "unsupported-project")],
                 }})
    client = Mock()
    client.post.side_effect = OSError("offline")
    service = inventory_service.InventoryService(cfg, client, components=True)
    with pytest.raises(OSError, match="offline"):
        service.sync_once()
    sample = json.loads(service.path.read_text())["snapshot"]
    assert sample["platform"] == ("windows" if platform == "win32" else "linux")
    assert rows(sample)["tool.exe"]["identifier"].startswith("executable:")
    monkeypatch.setattr(inventory, "collect_inventory", Mock(side_effect=AssertionError("No rescan for retry")))
    client.post.side_effect = None
    restarted = inventory_service.InventoryService(cfg, client, components=True)
    restarted.sync_once()
    assert client.post.call_args.args == ("inventory/snapshots", sample)
    assert not restarted.status()["pending"]
    native = Mock(return_value={"schema_version": 1, "collected_at": sample["collected_at"],
                               "platform": sample["platform"], "applications": [], "sources": []})
    monkeypatch.setattr(inventory_service, "collect_inventory", native)
    inventory_service.InventoryService(cfg, client).sync_once()
    assert client.post.call_args.args[0] == "inventory/applications"
    assert (tmp_path / "application-inventory.json").exists()
    for disabled in ("paused", "stopped", "components", "inventory"):
        client.post.reset_mock()
        stop = threading.Event()
        if disabled == "stopped":
            stop.set()
        if disabled == "components":
            cfg["inventory"]["components"]["enabled"] = False
        if disabled == "inventory":
            cfg["inventory"]["components"]["enabled"] = True
            cfg["inventory"]["enabled"] = False
        service = inventory_service.InventoryService(cfg, client, components=True, paused=lambda: disabled == "paused")
        service.sync_once(stop)
        client.post.assert_not_called()
