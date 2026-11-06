"""Read-only installed software discovery; never launches discovered applications.

macOS uses the shared osquery component collector. Linux package managers cover
their databases and desktop entries cover configured XDG data directories.
Windows covers uninstall registrations plus current-user Appx packages.
Portable executables and other users' private registrations are not exhaustively
discoverable. This is inventory, not activity.
"""

import configparser
import json
import os
import shutil
import signal
import time
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

MAX_RECORDS = 10_000
MAX_BYTES = 4 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
COMMAND_TIMEOUT = 20


def _run(argv):
    """Bound both process lifetime and captured stdout, without a shell."""
    executable = shutil.which(argv[0])
    if not executable:
        return "", "unavailable", "Discovery tool is not installed or on PATH."
    output = bytearray()
    truncated = threading.Event()
    try:
        process = subprocess.Popen(
            [executable, *argv[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={**os.environ, "LC_ALL": "C"},
            start_new_session=os.name == "posix",
            # The windowless Windows sensor has no console; without this flag
            # each console tool, such as PowerShell, opens a visible window.
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError:
        return "", "error", "Discovery tool could not be started."

    def stop():
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass

    def read():
        try:
            while chunk := process.stdout.read(65536):
                remaining = MAX_OUTPUT - len(output)
                output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated.set()
                    stop()
                    break
        except (OSError, ValueError):
            truncated.set()
        finally:
            process.stdout.close()

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    timed_out = False
    try:
        process.wait(timeout=COMMAND_TIMEOUT)
    except subprocess.TimeoutExpired:
        timed_out = True
        stop()
        process.wait()
    reader.join(timeout=2)
    if reader.is_alive():
        stop()
        reader.join(timeout=2)
    if reader.is_alive():
        return "", "error", "Discovery output reader did not finish."
    text = output.decode("utf-8-sig", errors="replace")
    if timed_out or truncated.is_set():
        return text, "partial", "Discovery exceeded the time or output limit."
    if process.returncode:
        return text, "error", "Discovery tool returned a nonzero exit status."
    return text, "ok", ""


class _Inventory:
    def __init__(self):
        self.result = {
            "schema_version": 1,
            "collected_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "platform": {"win32": "windows"}.get(sys.platform, sys.platform),
            "sources": [],
            "applications": [],
        }
        self.identities = set()
        self.used = 4096  # reserve space for fixed source summaries and envelope
        self.full = False

    def source(self, name, status="ok", message=""):
        item = {"source": name, "status": status, "message": message}
        self.result["sources"].append(item)
        return item

    def partial(self, source, message="Some discovery records could not be read."):
        if source["status"] in ("ok", "partial"):
            source.update(status="partial", message=message)

    def add(self, source, **fields):
        item = {
            key: str(fields.get(key, "") or "")
            for key in (
                "identifier",
                "name",
                "version",
                "path",
                "publisher",
                "architecture",
                "kind",
                "scope",
            )
        }
        limits = {
            "identifier": 2048,
            "name": 1024,
            "version": 256,
            "path": 8192,
            "publisher": 1024,
            "architecture": 128,
        }
        if (
            any(len(item[key]) > limit for key, limit in limits.items())
            or not item["identifier"].strip()
            or not item["name"].strip()
            or any(
                "\0" in value or any(0xD800 <= ord(char) <= 0xDFFF for char in value)
                for value in item.values()
            )
        ):
            self.partial(source, "Some records had missing or oversized metadata.")
            return
        item["source"] = source["source"]
        identity = tuple(
            item[k] for k in ("source", "identifier", "path", "architecture", "scope")
        )
        if identity in self.identities:
            return
        size = len(json.dumps(item).encode("utf-8")) + 2
        if len(self.identities) >= MAX_RECORDS or self.used + size > MAX_BYTES:
            self.full = True
            self.partial(source, "Inventory record or serialized size limit reached.")
            return
        self.used += size
        self.identities.add(identity)
        self.result["applications"].append(item)

    def command(self, source, argv):
        text, status, message = _run(argv)
        item = self.source(source, status, message)
        if status in ("error", "unavailable"):
            text = ""
        elif status != "ok":
            # Keep only complete records from interrupted command output.
            text = text.rsplit("\n", 1)[0] if "\n" in text else ""
        return item, text


def _scope(path):
    try:
        return "user" if Path(path).is_relative_to(Path.home()) else "system"
    except (ValueError, OSError):
        return "unknown"


def _desktop(inv):
    source = inv.source("linux-desktop")
    dirs = [os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local/share")]
    dirs += (os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share").split(
        ":"
    )
    visited = 0
    directories = 0
    started = time.monotonic()
    seen_ids = set()
    for directory in dict.fromkeys(dirs):
        if not os.path.isabs(directory):
            inv.partial(source, "Relative XDG data directories were ignored.")
            continue
        base = Path(directory) / "applications"
        if not base.exists():
            continue

        def onerror(_):
            inv.partial(source, "Some desktop directories could not be read.")

        for root, children, files in os.walk(base, onerror=onerror, followlinks=False):
            directories += 1
            if (
                directories > MAX_RECORDS
                or time.monotonic() - started > COMMAND_TIMEOUT
            ):
                inv.partial(
                    source, "Desktop discovery directory or time limit reached."
                )
                return
            children.sort()
            for filename in sorted(files):
                if not filename.endswith(".desktop"):
                    continue
                visited += 1
                if visited > MAX_RECORDS or inv.full:
                    inv.partial(source, "Desktop discovery record limit reached.")
                    return
                path = Path(root) / filename
                identifier = str(path.relative_to(base)).replace(os.sep, "-")
                if identifier in seen_ids:
                    continue
                seen_ids.add(identifier)
                try:
                    with path.open("rb") as stream:
                        body = stream.read(262145)
                    if len(body) > 262144:
                        raise ValueError("oversize desktop entry")
                    parser = configparser.ConfigParser(interpolation=None, strict=False)
                    parser.read_string(body.decode("utf-8"))
                    entry = parser["Desktop Entry"]
                    if (
                        entry.get("Type") != "Application"
                        or entry.get("Hidden", "false").lower() == "true"
                    ):
                        continue
                    inv.add(
                        source,
                        identifier=identifier,
                        name=entry.get("Name", path.stem),
                        path=str(path),
                        kind="application",
                        scope=_scope(path),
                    )
                except (OSError, ValueError, KeyError, configparser.Error):
                    inv.partial(source)


def _linux(inv):
    source, text = inv.command(
        "linux-dpkg",
        [
            "dpkg-query",
            "-W",
            "-f=${db:Status-Status}\t${binary:Package}\t${Version}\t${Architecture}\n",
        ],
    )
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            inv.partial(source)
            continue
        status, name, version, arch = fields
        if status == "installed":
            inv.add(
                source,
                identifier=name,
                name=name,
                version=version,
                architecture=arch,
                kind="package",
                scope="system",
            )
        if inv.full:
            break
    source, text = inv.command(
        "linux-rpm",
        [
            "rpm",
            "-qa",
            "--qf",
            "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{EPOCH}\n",
        ],
    )
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 5:
            inv.partial(source)
            continue
        name, version, arch, vendor, epoch = fields
        inv.add(
            source,
            identifier=f"{name}-{epoch if epoch != '(none)' else '0'}:{version}.{arch}",
            name=name,
            version=version,
            architecture=arch,
            publisher="" if vendor == "(none)" else vendor,
            kind="package",
            scope="system",
        )
        if inv.full:
            break
    _desktop(inv)
    # Keep a single status per source, while recording actual installation scope.
    source = inv.source("linux-flatpak")
    statuses = []
    for scope in ("system", "user"):
        text, status, message = _run(
            [
                "flatpak",
                "list",
                "--app",
                f"--{scope}",
                "--columns=application,name,version,arch,branch",
            ]
        )
        statuses.append(status)
        if status in ("error", "unavailable"):
            text = ""
        elif status == "partial":
            text = text.rsplit("\n", 1)[0] if "\n" in text else ""
        for line in text.splitlines():
            fields = line.split("\t")
            if len(fields) != 5:
                inv.partial(source)
                continue
            ident, name, version, arch, branch = fields
            inv.add(
                source,
                identifier=f"{ident}/{arch}/{branch}",
                name=name,
                version=version,
                architecture=arch,
                kind="application",
                scope=scope,
            )
            if inv.full:
                break
        if status == "unavailable":
            break
    if any(status != "ok" for status in statuses):
        status = "partial" if "ok" in statuses or "partial" in statuses else statuses[0]
        source.update(
            status=status,
            message="One or more Flatpak installation scopes could not be fully queried.",
        )
    source, text = inv.command("linux-snap", ["snap", "list"])
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6:
            inv.partial(source)
            continue
        inv.add(
            source,
            identifier=fields[0],
            name=fields[0],
            version=fields[1],
            publisher=fields[4],
            kind="package",
            scope="system",
        )
        if inv.full:
            break


def _registry(inv):
    source = inv.source("windows-registry")
    try:
        import winreg
    except ImportError:
        source.update(
            status="unavailable", message="Windows registry access is unavailable."
        )
        return
    for hive, scope in (
        (winreg.HKEY_LOCAL_MACHINE, "system"),
        (winreg.HKEY_CURRENT_USER, "user"),
    ):
        for view, arch in ((winreg.KEY_WOW64_64KEY, ""), (winreg.KEY_WOW64_32KEY, "")):
            # Registry view is not reliable evidence of an application's architecture.
            try:
                key = winreg.OpenKey(
                    hive,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    0,
                    winreg.KEY_READ | view,
                )
            except FileNotFoundError:
                continue
            except OSError:
                inv.partial(source, "Some uninstall registry views could not be read.")
                continue
            with key:
                try:
                    count = winreg.QueryInfoKey(key)[0]
                    for index in range(min(count, MAX_RECORDS)):
                        if inv.full:
                            inv.partial(source, "Inventory limit reached.")
                            return
                        ident = winreg.EnumKey(key, index)
                        try:
                            with winreg.OpenKey(key, ident) as app:

                                def value(name):
                                    try:
                                        result, _ = winreg.QueryValueEx(app, name)
                                        return result if isinstance(result, str) else ""
                                    except FileNotFoundError:
                                        return ""

                                name = value("DisplayName")
                                if name:
                                    inv.add(
                                        source,
                                        identifier=ident,
                                        name=name,
                                        version=value("DisplayVersion"),
                                        path=value("InstallLocation"),
                                        publisher=value("Publisher"),
                                        architecture=arch,
                                        kind="application",
                                        scope=scope,
                                    )
                        except OSError:
                            inv.partial(source)
                    if count > MAX_RECORDS:
                        inv.partial(source, "Registry discovery record limit reached.")
                except OSError:
                    inv.partial(source)


def _windows(inv):
    _registry(inv)
    source, text = inv.command(
        "windows-appx",
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); @(Get-AppxPackage | Select-Object Name,PackageFamilyName,Version,InstallLocation,Publisher,@{Name='Architecture';Expression={$_.Architecture.ToString()}}) | ConvertTo-Json -Compress -Depth 3",
        ],
    )
    if not text.strip():
        return
    try:
        records = json.loads(text)
        if isinstance(records, dict):
            records = [records]
        if not isinstance(records, list):
            raise ValueError("invalid Appx response")
        for item in records:
            if not isinstance(item, dict) or not item.get("Name"):
                inv.partial(source)
                continue
            inv.add(
                source,
                identifier=item.get("PackageFamilyName") or item["Name"],
                name=item["Name"],
                version=item.get("Version"),
                path=item.get("InstallLocation"),
                publisher=item.get("Publisher"),
                architecture=item.get("Architecture"),
                kind="application",
                scope="user",
            )
            if inv.full:
                break
    except (ValueError, TypeError):
        inv.partial(source, "Appx discovery returned invalid or incomplete JSON.")


def collect_inventory():
    """Collect a component snapshot on macOS, native applications elsewhere."""
    if sys.platform == "darwin":
        from . import component_inventory

        return component_inventory.collect_inventory(component_inventory.settings({}))
    inv = _Inventory()
    if sys.platform.startswith("linux"):
        _linux(inv)
    elif sys.platform == "win32":
        _windows(inv)
    else:
        inv.source(
            "platform",
            "unavailable",
            "No installed-software discovery source for this platform.",
        )
    inv.result["applications"].sort(
        key=lambda app: tuple(
            app[k] for k in ("source", "identifier", "path", "architecture", "scope")
        )
    )
    return inv.result
