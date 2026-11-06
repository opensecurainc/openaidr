"""Device identity collection stays best effort on every platform."""

import subprocess

import pytest

from openaidr.sensor import hostinfo

BLANK = {"serial_number": "", "hardware_uuid": "", "machine_id": "", "source": ""}


def test_darwin_parses_ioreg_and_tolerates_failures(monkeypatch):
    monkeypatch.setattr(hostinfo.platform, "system", lambda: "Darwin")
    commands = []

    def run(args):
        commands.append(args)
        return (
            '  "IOPlatformSerialNumber" = "C02XYZ123"\n'
            '  "IOPlatformUUID" = "A1B2C3D4-0000-1111-2222-333344445555"\n'
        )

    monkeypatch.setattr(hostinfo, "_run", run)
    assert hostinfo.device() == {
        "serial_number": "C02XYZ123",
        "hardware_uuid": "A1B2C3D4-0000-1111-2222-333344445555",
        "machine_id": "",
        "source": "ioreg",
    }
    assert commands == [["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]]
    monkeypatch.setattr(hostinfo, "_run", lambda args: "")
    assert hostinfo.device() == BLANK
    monkeypatch.setattr(hostinfo, "_run", lambda args: 1 / 0)
    assert hostinfo.device() == BLANK


def test_windows_reads_cim_lines_and_machine_guid(monkeypatch):
    monkeypatch.setattr(hostinfo.platform, "system", lambda: "Windows")
    monkeypatch.setattr(hostinfo, "_run", lambda args: "PF1ABC\r\n4C4C4544-0000-2010-8020-B4C04F000001\r\n")
    monkeypatch.setattr(hostinfo, "_windows_machine_guid", lambda: "9f1c-guid")
    assert hostinfo.device() == {
        "serial_number": "PF1ABC",
        "hardware_uuid": "4C4C4544-0000-2010-8020-B4C04F000001",
        "machine_id": "9f1c-guid",
        "source": "cim",
    }
    # A missing PowerShell leaves only the registry value.
    monkeypatch.setattr(hostinfo, "_run", lambda args: "")
    assert hostinfo.device() == dict(BLANK, machine_id="9f1c-guid", source="cim")


def test_linux_prefers_dmi_and_falls_back_to_machine_id(monkeypatch):
    monkeypatch.setattr(hostinfo.platform, "system", lambda: "Linux")
    files = {
        "/sys/class/dmi/id/product_serial": "SN-77\n",
        "/sys/class/dmi/id/product_uuid": "11111111-2222-3333-4444-555555555555\n",
        "/etc/machine-id": "0123456789abcdef0123456789abcdef\n",
    }
    monkeypatch.setattr(hostinfo, "_read", lambda path: files.get(str(path), ""))
    assert hostinfo.device() == {
        "serial_number": "SN-77",
        "hardware_uuid": "11111111-2222-3333-4444-555555555555",
        "machine_id": "0123456789abcdef0123456789abcdef",
        "source": "dmi",
    }
    # Without root the DMI files are unreadable; the installation ID remains.
    unprivileged = {"/etc/machine-id": files["/etc/machine-id"]}
    monkeypatch.setattr(hostinfo, "_read", lambda path: unprivileged.get(str(path), ""))
    assert hostinfo.device() == dict(
        BLANK, machine_id="0123456789abcdef0123456789abcdef", source="machine-id"
    )


@pytest.mark.parametrize(
    "serial, expected",
    [
        ("To Be Filled By O.E.M.", ""),
        ("00000000-0000-0000-0000-000000000000", ""),
        ("  0 ", ""),
        ("bad\x00serial", ""),
        ("x" * 200, "x" * hostinfo.DEVICE_MAX_LENGTH),
        ("  C02XYZ  ", "C02XYZ"),
    ],
)
def test_placeholders_and_unsafe_values_are_dropped(monkeypatch, serial, expected):
    monkeypatch.setattr(hostinfo.platform, "system", lambda: "Linux")
    monkeypatch.setattr(hostinfo, "_read", lambda path: serial if "serial" in str(path) else "")
    result = hostinfo.device()
    assert result["serial_number"] == expected
    assert result["source"] == ("dmi" if expected else "")


def test_commands_are_bounded_and_failures_return_nothing(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(kwargs)
        raise subprocess.TimeoutExpired(args, kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", run)
    assert hostinfo._run(["ioreg"]) == ""
    assert calls[0]["timeout"] == hostinfo.DEVICE_TIMEOUT_S == 2
    assert calls[0]["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)
    assert calls[0]["stdin"] == subprocess.DEVNULL

    def missing(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(subprocess, "run", missing)
    assert hostinfo._run(["missing"]) == ""
    assert hostinfo._read("/nonexistent/openaidr/machine-id") == ""


def test_latest_login_uses_session_times_not_process_identity(monkeypatch):
    from types import SimpleNamespace

    # Session records supplied by the existing cross-platform system library:
    # Windows has no terminal; Unix can have console, local, and SSH sessions.
    sessions = [
        SimpleNamespace(name="older", terminal="console", started=1700000000),
        SimpleNamespace(name="DOMAIN\\newer", terminal=None, started=1700000200),
        SimpleNamespace(name="older", terminal="pts/1", started=1700000100),
    ]
    monkeypatch.setattr(hostinfo.psutil, "users", lambda: sessions)
    monkeypatch.setattr(hostinfo.getpass, "getuser", lambda: "service-account")
    assert hostinfo.signed_in_user() == {
        "name": "DOMAIN\\newer", "signed_in_at": "2023-11-14T22:16:40+00:00",
    }
    sessions.append(SimpleNamespace(name="DOMAIN\\newer", started=1700000200))
    assert hostinfo.signed_in_user()["name"] == "DOMAIN\\newer"
    # Equal newest times for different identities cannot establish a latest user.
    sessions.append(SimpleNamespace(name="ambiguous", started=1700000200))
    assert hostinfo.signed_in_user() is None
    sessions.clear()
    assert hostinfo.signed_in_user() is None
    monkeypatch.setattr(hostinfo.psutil, "users", lambda: 1 / 0)
    assert hostinfo.signed_in_user() is None


@pytest.mark.parametrize("name,started", [
    ("", 1700000000), (" ", 1700000000), ("bad\nname", 1700000000),
    ("x" * 257, 1700000000), ("alice", 0), ("alice", -1),
    ("alice", float("nan")), ("alice", float("inf")), ("alice", 999999999999),
])
def test_invalid_login_evidence_is_omitted(monkeypatch, name, started):
    from types import SimpleNamespace

    monkeypatch.setattr(hostinfo.psutil, "users", lambda: [SimpleNamespace(name=name, started=started)])
    assert hostinfo.signed_in_user() is None
