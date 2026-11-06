"""Versioned per-user copies of the frozen Windows sensor, as ADR stages its runtime.

The Windows sensor is a one-directory build: starting it needs no extraction,
which keeps agent hooks inside their deadline. The desktop app runs it from
its installation, and installing the background service copies it to
``%LOCALAPPDATA%\\OpenAIDR\\data\\runtime\\<version>-<build>``. A new build
gets a new directory, so files a running sensor or hook has open are never
replaced. ``current.json`` names the runtime the Scheduled Task and agent
hooks use. Desktop setup selects its bundled version exactly; standalone
installation only moves to a newer version. Superseded runtimes are removed,
keeping the previous one for hooks that are still running.
"""

import json
import os
import re
import shutil
import time
from pathlib import Path

from .config import atomic_write

MANIFEST = "runtime.json"
POINTER = "current.json"
COMPLETE = ".complete"
CONSOLE = "openaidr.exe"
LEGACY_CONSOLE = "openaidr-sensor.exe"
NAME = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,79}")


def root(environ=None):
    from .windows_layout import state_root

    return state_root(environ) / "runtime"


def manifest(directory):
    """The build's runtime.json: {"name": ..., "version": ...}, or None."""
    try:
        value = json.loads((Path(directory) / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("name"), str) or not NAME.fullmatch(value["name"])
        or not isinstance(value.get("version"), str)
    ):
        return None
    return value


def bundled(executable):
    """The runtime directory a frozen one-directory sensor runs from, or None."""
    directory = Path(executable).resolve().parent
    return directory if manifest(directory) else None


def console(directory):
    """Use the name actually shipped by this runtime, including older builds."""
    directory = Path(directory)
    current = directory / CONSOLE
    return current if current.is_file() else directory / LEGACY_CONSOLE


def _complete(directory):
    return (directory / COMPLETE).is_file() and console(directory).is_file()


def current(runtime_root):
    """The runtime ``current.json`` names, if it is completely staged."""
    try:
        name = json.loads((runtime_root / POINTER).read_text(encoding="utf-8")).get("name")
    except (OSError, ValueError, AttributeError):
        return None
    if not isinstance(name, str) or not NAME.fullmatch(name):
        return None
    directory = runtime_root / name
    return directory if _complete(directory) else None


def stage(source, runtime_root):
    """Copy a bundled runtime to its own versioned directory, once."""
    name = manifest(source)["name"]
    destination = runtime_root / name
    if _complete(destination):
        return destination
    runtime_root.mkdir(parents=True, exist_ok=True)
    temporary = runtime_root / f".{name}.new-{os.getpid()}"
    shutil.rmtree(temporary, ignore_errors=True)
    shutil.copytree(source, temporary)
    # Written last: a directory without it was interrupted and is replaced.
    (temporary / COMPLETE).write_text(name, encoding="utf-8")
    if destination.exists():
        shutil.rmtree(destination)
    os.replace(temporary, destination)
    return destination


def select(source, runtime_root, *, match_version=False):
    """Select the bundled runtime exactly for desktop setup, otherwise preserve order.

    Returns the runtime the service and hooks should use.
    """
    active = current(runtime_root)
    if not match_version and active is not None and active.name != manifest(source)["name"]:
        from .bridge import keep_existing

        old, new = manifest(active) or {}, manifest(source)
        if keep_existing(old.get("version", ""), new["version"], old.get("build"), new.get("build")):
            return active
    staged = stage(source, runtime_root)
    previous = active
    atomic_write(runtime_root / POINTER, json.dumps({"name": staged.name}))
    prune(runtime_root, {staged.name} | ({previous.name} if previous else set()))
    return staged


def prune(runtime_root, keep):
    """Remove other runtimes; one still in use stays until a later prune.

    Each is renamed aside first: Windows refuses to rename a directory with
    files in use, so a runtime a process still runs from is never partly
    deleted. A recent staging copy may belong to another process.
    """
    try:
        entries = list(runtime_root.iterdir())
    except OSError:
        return
    for entry in entries:
        if not entry.is_dir() or entry.is_symlink() or entry.name in keep:
            continue
        try:
            if ".new-" in entry.name and time.time() - entry.stat().st_mtime < 3600:
                continue
            aside = runtime_root / f".{entry.name.lstrip('.')}.remove-{os.getpid()}"
            os.replace(entry, aside)
        except OSError:
            continue
        shutil.rmtree(aside, ignore_errors=True)


class RemovalError(RuntimeError):
    """The staged runtimes could not be removed; uninstall must stop."""


def remove(runtime_root):
    """Remove every staged runtime, for uninstall, or raise RemovalError.

    The directory is renamed aside first, as prune does: Windows refuses that
    while a sensor or hook still uses a runtime, so a failed uninstall leaves
    the runtimes whole for a retry. An absent directory is already removed,
    and leftovers of an earlier interrupted removal are removed too.
    """
    runtime_root = Path(runtime_root)
    pending = sorted(runtime_root.parent.glob(f"{runtime_root.name}.remove-*"))
    if runtime_root.exists():
        aside = runtime_root.with_name(f"{runtime_root.name}.remove-{os.getpid()}")
        try:
            os.replace(runtime_root, aside)
        except OSError as exc:
            raise RemovalError(
                f"Cannot remove the staged sensor runtimes in {runtime_root}: {exc}. "
                "Close the coding agents and OpenAIDR, then retry."
            ) from exc
        pending.append(aside)
    for directory in pending:
        try:
            shutil.rmtree(directory)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RemovalError(
                f"Cannot remove the staged sensor runtimes in {directory}: {exc}. "
                "Close the coding agents and OpenAIDR, then retry."
            ) from exc
