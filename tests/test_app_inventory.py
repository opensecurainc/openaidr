import json
import subprocess
import sys
import time
import types
from pathlib import Path

import pytest

from openaidr.sensor import inventory as inv


def mock_commands(monkeypatch, outputs):
    calls = []

    def run(argv):
        calls.append(argv)
        result = outputs.get(
            tuple(argv), outputs.get(argv[0], ("", "unavailable", "missing"))
        )
        return result

    monkeypatch.setattr(inv, "_run", run)
    return calls


def test_linux_sources_and_desktop_spec_version(tmp_path, monkeypatch):
    monkeypatch.setattr(inv.sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "user"))
    monkeypatch.setenv("XDG_DATA_DIRS", str(tmp_path / "system"))
    desktop = tmp_path / "user/applications"
    desktop.mkdir(parents=True)
    (desktop / "demo.desktop").write_text(
        "[Desktop Entry]\nType=Application\nName=Desktop Demo\nVersion=1.5\nExec=do-not-run\n"
    )
    (desktop / "hidden.desktop").write_text(
        "[Desktop Entry]\nType=Application\nName=Hidden\nHidden=true\n"
    )
    calls = mock_commands(
        monkeypatch,
        {
            "dpkg-query": (
                "installed\tdemo\t1.0\tamd64\nconfig-files\tremoved\t2\tall\n",
                "ok",
                "",
            ),
            "rpm": ("demo\t2.0-1\tx86_64\tVendor\t(none)\n", "ok", ""),
            "flatpak": ("org.demo.App\tDemo\t3\tx86_64\tstable\n", "ok", ""),
            "snap": (
                "Name Version Rev Tracking Publisher Notes\ndemo 4 1 latest/stable vendor -\n",
                "ok",
                "",
            ),
        },
    )
    result = inv.collect_inventory()
    apps = result["applications"]
    assert len(apps) == 6
    assert {a["source"] for a in apps} == {
        "linux-dpkg",
        "linux-rpm",
        "linux-desktop",
        "linux-flatpak",
        "linux-snap",
    }
    assert {a["scope"] for a in apps if a["source"] == "linux-flatpak"} == {
        "system",
        "user",
    }
    assert next(a for a in apps if a["source"] == "linux-desktop")["version"] == ""
    assert all(a["identifier"] != "removed" for a in apps)
    assert all(a["status"] == "ok" for a in result["sources"])
    assert not any("do-not-run" in str(call) for call in calls)


def test_failures_truncation_and_partial_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(inv.sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_DIRS", str(tmp_path))
    mock_commands(
        monkeypatch,
        {
            "dpkg-query": (
                "installed\tgood\t1\tall\ninstalled\tbroken",
                "partial",
                "limit",
            ),
            "rpm": ("bad\t1\tall\tvendor\n", "error", "failure"),
            (
                "flatpak",
                "list",
                "--app",
                "--system",
                "--columns=application,name,version,arch,branch",
            ): ("", "error", "failure"),
            (
                "flatpak",
                "list",
                "--app",
                "--user",
                "--columns=application,name,version,arch,branch",
            ): ("org.demo\tDemo\t1\tall\tstable\n", "ok", ""),
        },
    )
    result = inv.collect_inventory()
    statuses = {s["source"]: s["status"] for s in result["sources"]}
    assert statuses["linux-dpkg"] == statuses["linux-flatpak"] == "partial"
    assert statuses["linux-rpm"] == "error"
    assert statuses["linux-snap"] == "unavailable"
    assert {a["identifier"] for a in result["applications"]} == {
        "good",
        "org.demo/all/stable",
    }


def test_identity_budget_and_serialized_size(monkeypatch):
    data = inv._Inventory()
    source = data.source("linux-dpkg")
    fields = dict(identifier="a", name="A", version="1", kind="package", scope="system")
    data.add(source, **fields)
    data.add(source, **{**fields, "version": "2"})
    assert len(data.result["applications"]) == 1
    monkeypatch.setattr(inv, "MAX_RECORDS", 1)
    data.add(source, **{**fields, "identifier": "b"})
    assert data.full and source["status"] == "partial"
    monkeypatch.setattr(inv, "MAX_RECORDS", 10000)
    data = inv._Inventory()
    source = data.source("linux-dpkg")
    monkeypatch.setattr(inv, "MAX_BYTES", 5000)
    for i in range(100):
        data.add(source, **{**fields, "identifier": str(i)})
    assert len(json.dumps(data.result).encode()) <= 5000
    assert source["status"] == "partial"


def test_runner_missing_failure_timeout_and_output_cap(monkeypatch):
    monkeypatch.setattr(inv.shutil, "which", lambda _: None)
    assert inv._run(["missing"])[1] == "unavailable"
    monkeypatch.setattr(inv.shutil, "which", lambda _: sys.executable)
    assert inv._run(["python", "-c", "raise SystemExit(7)"])[1] == "error"
    monkeypatch.setattr(inv, "MAX_OUTPUT", 100)
    text, status, _ = inv._run(["python", "-c", "print('a'*10000)"])
    assert len(text) <= 100 and status == "partial"
    monkeypatch.setattr(inv, "COMMAND_TIMEOUT", 0.1)
    start = time.monotonic()
    assert inv._run(["python", "-c", "import time; time.sleep(10)"])[1] == "partial"
    assert time.monotonic() - start < 3


class RegistryKey:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def test_windows_views_appx_current_user_and_errors(monkeypatch):
    monkeypatch.setattr(inv.sys, "platform", "win32")
    opened = []

    def open_key(parent, name, reserved=0, flags=0):
        if isinstance(parent, RegistryKey):
            return RegistryKey("app")
        opened.append((parent, flags))
        if parent == "HKCU" and flags == 65:
            raise PermissionError("restricted")
        return RegistryKey("root")

    def query_value(key, name):
        values = {
            "DisplayName": "Registry Demo",
            "DisplayVersion": "1",
            "InstallLocation": "C:\\Demo",
            "Publisher": "Vendor",
        }
        return values[name], 1

    fake = types.SimpleNamespace(
        HKEY_LOCAL_MACHINE="HKLM",
        HKEY_CURRENT_USER="HKCU",
        KEY_READ=1,
        KEY_WOW64_64KEY=64,
        KEY_WOW64_32KEY=32,
        OpenKey=open_key,
        QueryInfoKey=lambda _: (1, 0, 0),
        EnumKey=lambda *_: "demo-id",
        QueryValueEx=query_value,
    )
    monkeypatch.setitem(sys.modules, "winreg", fake)
    calls = mock_commands(
        monkeypatch,
        {
            "powershell.exe": (
                json.dumps(
                    [
                        {
                            "Name": "Appx Demo",
                            "PackageFamilyName": "demo_family",
                            "Version": "2",
                            "Architecture": "X64",
                        }
                    ]
                ),
                "ok",
                "",
            )
        },
    )
    result = inv.collect_inventory()
    assert len(opened) == 4
    assert len(result["applications"]) == 3  # duplicate HKLM views collapse
    assert result["sources"][0]["status"] == "partial"
    appx = next(a for a in result["applications"] if a["source"] == "windows-appx")
    assert appx["scope"] == "user" and appx["identifier"] == "demo_family"
    assert "Get-AppxPackage" in calls[0][-1]
    assert "Win32_Product" not in str(calls) and "-AllUsers" not in str(calls)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows console windows")
def test_windows_inventory_tools_open_no_console_window(tmp_path):
    # pythonw has no console, like the windowless sensor. A console tool it
    # starts gets a new console, visible unless created without a window.
    result = tmp_path / "result"
    script = (
        "import sys\nfrom openaidr.sensor import inventory as inv\n"
        "console = sys.executable.lower().replace('pythonw.exe', 'python.exe')\n"
        "probe = 'import ctypes; print(ctypes.windll.kernel32.GetConsoleWindow() or 0)'\n"
        "text, status, _ = inv._run([console, '-c', probe])\n"
        f"open({str(result)!r}, 'w').write(status + ' ' + text.strip())\n"
    )
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    subprocess.run([str(pythonw), "-c", script], check=True, timeout=60)
    assert result.read_text() == "ok 0"


def test_invalid_appx_and_unsupported_platform(monkeypatch):
    monkeypatch.setattr(inv.sys, "platform", "win32")
    monkeypatch.setattr(
        inv,
        "_registry",
        lambda data: data.source("windows-registry", "unavailable", "not available"),
    )
    mock_commands(monkeypatch, {"powershell.exe": ("invalid", "ok", "")})
    result = inv.collect_inventory()
    assert result["sources"][1]["status"] == "partial"
    assert result["applications"] == []
    monkeypatch.setattr(inv.sys, "platform", "freebsd")
    assert inv.collect_inventory()["sources"][0]["status"] == "unavailable"


def test_oversized_metadata_is_reported():
    data = inv._Inventory()
    source = data.source("linux-dpkg")
    data.add(source, identifier="test", name="Test", publisher="x" * 1025)
    assert source["status"] == "partial"
    assert not data.result["applications"]


def test_nonascii_serialization_stays_bounded(monkeypatch):
    monkeypatch.setattr(inv, "MAX_BYTES", 10000)
    data = inv._Inventory()
    source = data.source("linux-dpkg")
    for index in range(100):
        data.add(
            source,
            identifier=str(index),
            name="界" * 500,
            kind="package",
            scope="system",
        )
    assert len(json.dumps(data.result).encode()) <= 10000
    assert source["status"] == "partial"


def test_unsafe_metadata_skipped():
    data = inv._Inventory()
    source = data.source("linux-desktop")
    for field, value in [
        ("name", "  \t"),
        ("name", "bad\0name"),
        ("path", "bad\ud800path"),
        ("identifier", " "),
    ]:
        data.add(
            source,
            **{
                **dict(identifier="id", name="Name", kind="application", scope="user"),
                field: value,
            },
        )
    assert not data.result["applications"]
    assert source["status"] == "partial"


def test_side_by_side_packages_and_flatpak_branches(tmp_path, monkeypatch):
    monkeypatch.setattr(inv.sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_DIRS", str(tmp_path))
    mock_commands(
        monkeypatch,
        {
            "rpm": (
                "kernel\t1-1\tx86_64\tVendor\t(none)\nkernel\t2-1\tx86_64\tVendor\t0\n",
                "ok",
                "",
            ),
            "flatpak": (
                "org.demo\tDemo\t1\tx86_64\tstable\norg.demo\tDemo\t2\tx86_64\tbeta\n",
                "ok",
                "",
            ),
        },
    )
    result = inv.collect_inventory()
    assert {
        a["identifier"] for a in result["applications"] if a["source"] == "linux-rpm"
    } == {"kernel-0:1-1.x86_64", "kernel-0:2-1.x86_64"}
    assert (
        len([a for a in result["applications"] if a["source"] == "linux-flatpak"]) == 4
    )
    assert {
        a["identifier"]
        for a in result["applications"]
        if a["source"] == "linux-flatpak"
    } == {"org.demo/x86_64/stable", "org.demo/x86_64/beta"}


def test_desktop_precedence_hidden_masks_and_directory_bound(tmp_path, monkeypatch):
    user, system = tmp_path / "user", tmp_path / "system"
    monkeypatch.setenv("XDG_DATA_HOME", str(user))
    monkeypatch.setenv("XDG_DATA_DIRS", str(system))
    for base in (user, system):
        (base / "applications").mkdir(parents=True)
        (base / "applications/same.desktop").write_text(
            f"[Desktop Entry]\nType=Application\nName={base.name}\n"
        )
        (base / "applications/hide.desktop").write_text(
            "[Desktop Entry]\nType=Application\nName=Hidden\n"
            + ("Hidden=true\n" if base == user else "")
        )
    data = inv._Inventory()
    inv._desktop(data)
    assert [a["name"] for a in data.result["applications"]] == ["user"]
    monkeypatch.setattr(inv, "MAX_RECORDS", 0)
    data = inv._Inventory()
    inv._desktop(data)
    assert data.result["sources"][0]["status"] == "partial"


def test_runner_forces_stable_locale(monkeypatch):
    monkeypatch.setattr(inv.shutil, "which", lambda _: sys.executable)
    monkeypatch.setenv("LC_ALL", "a_different_locale")
    text, status, _ = inv._run(
        ["python", "-c", "import os; print(os.environ['LC_ALL'])"]
    )
    assert status == "ok" and text.strip() == "C"
