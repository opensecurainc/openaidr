import getpass
import os
import platform
import re
import socket
from datetime import datetime, timezone
from pathlib import Path

import psutil

from .config import is_root


def current():
    return {
        "hostname": socket.gethostname(),
        "os": {"Darwin": "darwin", "Windows": "windows"}.get(
            platform.system(), "linux"
        ),
        "arch": {"x86_64": "amd64", "aarch64": "arm64", "AMD64": "amd64"}.get(
            platform.machine(), platform.machine()
        ),
        "user": getpass.getuser().split("\\")[-1],
    }


def signed_in_user():
    """Most recent OS login session, never the sensor process account.

    Missing session records, failed lookups, and tied usernames are unknown.
    The backend retains the last known login after logout or collection failure.
    """
    try:
        sessions = psutil.users()
        if not sessions:
            return None
        latest = max(session.started for session in sessions)
        names = {session.name for session in sessions if session.started == latest}
        if len(names) != 1:
            return None
        name = names.pop()
        if not isinstance(name, str) or not name.strip() or len(name) > 256 or not name.isprintable():
            return None
        stamp = datetime.fromtimestamp(latest, timezone.utc)
        if latest <= 0 or stamp > datetime.now(timezone.utc):
            return None
        return {"name": name, "signed_in_at": stamp.isoformat()}
    except Exception:
        return None


def homes():
    result = {Path.home()}
    if is_root():
        root = Path(
            "/Users"
            if platform.system() == "Darwin"
            else os.environ.get("SystemDrive", "C:") + "/Users"
            if os.name == "nt"
            else "/home"
        )
        if root.exists():
            result.update(
                p
                for p in root.iterdir()
                if p.is_dir()
                and not p.name.startswith(".")
                and p.name.lower()
                not in {
                    "shared",
                    "public",
                    "default",
                    "default user",
                    "all users",
                    "lost+found",
                }
            )
        if platform.system() == "Linux":
            result.add(Path("/root"))
    return sorted(str(p) for p in result if p.is_dir())


def user_from_path(path):
    path = str(path).replace("\\", "/")
    m = re.match(r"(?:/Users/|/home/|[A-Za-z]:/Users/)([^/]+)/", path, re.I)
    return m[1] if m else "root" if path.startswith("/root/") else ""


# Identifiers for the machine the sensor runs on. They let the backend
# recognize the same hardware across reinstalls and renames. They are reported
# evidence and never authenticate the sensor; the enrolled sensor ID does that.
DEVICE_FIELDS = ("serial_number", "hardware_uuid", "machine_id", "source")
DEVICE_TIMEOUT_S = 2
DEVICE_MAX_LENGTH = 128
# Firmware fills these in when the vendor supplied nothing. Treat them as absent
# so one placeholder can never link unrelated machines.
DEVICE_PLACEHOLDERS = {
    "0",
    "none",
    "null",
    "unknown",
    "default string",
    "to be filled by o.e.m.",
    "system serial number",
    "not specified",
    "not available",
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "03000200-0400-0500-0006-000700080009",
}


def device():
    """Best-effort device identifiers. Never raises; bounded to one timeout.

    Each command is bounded by DEVICE_TIMEOUT_S. Unreadable, placeholder, or
    unprintable values become empty strings, which the backend treats as not
    reported, so a failed collection never erases a value it already holds.
    """
    system = platform.system()
    try:
        if system == "Darwin":
            fields = _darwin_device()
        elif system == "Windows":
            fields = _windows_device()
        else:
            fields = _linux_device()
    except Exception:
        fields = {}
    result = {name: _clean(fields.get(name)) for name in DEVICE_FIELDS[:-1]}
    result["source"] = _clean(fields.get("source")) if any(result.values()) else ""
    return result


def _clean(value):
    if not isinstance(value, str):
        return ""
    value = value.strip()[:DEVICE_MAX_LENGTH].strip()
    if not value.isprintable() or value.lower() in DEVICE_PLACEHOLDERS:
        return ""
    return value


def _run(args):
    import subprocess

    try:
        completed = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=DEVICE_TIMEOUT_S,
            check=False,
            # The windowless Windows sensor has no console; without this flag
            # PowerShell opens a visible window on every start and enrollment.
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return ""


def _darwin_device():
    output = _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
    found = dict(re.findall(r'"(IOPlatformSerialNumber|IOPlatformUUID)" = "([^"]*)"', output))
    return {
        "serial_number": found.get("IOPlatformSerialNumber", ""),
        "hardware_uuid": found.get("IOPlatformUUID", ""),
        "source": "ioreg",
    }


def _windows_device():
    lines = _run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "(Get-CimInstance Win32_BIOS).SerialNumber; (Get-CimInstance Win32_ComputerSystemProduct).UUID",
    ]).splitlines()
    lines += ["", ""]
    return {
        "serial_number": lines[0],
        "hardware_uuid": lines[1],
        "machine_id": _windows_machine_guid(),
        "source": "cim",
    }


def _windows_machine_guid():
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
        ) as key:
            return str(winreg.QueryValueEx(key, "MachineGuid")[0])
    except (ImportError, OSError, IndexError, TypeError):
        return ""


def _linux_device():
    # The DMI serial and UUID are root-only on most distributions. A sensor
    # running as the user still gets the OS installation ID.
    serial = _read("/sys/class/dmi/id/product_serial")
    uuid = _read("/sys/class/dmi/id/product_uuid")
    machine_id = _read("/etc/machine-id") or _read("/var/lib/dbus/machine-id")
    return {
        "serial_number": serial,
        "hardware_uuid": uuid,
        "machine_id": machine_id,
        "source": "dmi" if (serial.strip() or uuid.strip()) else "machine-id",
    }
