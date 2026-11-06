"""Validate and retain immutable support directories for the macOS sensor."""

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

MARKER = b"pyi-contents-directory openaidr-runtime-"
NAME = re.compile(r"openaidr-runtime-[0-9a-f]{64}")
DIGEST = re.compile(r"[0-9a-f]{64}")
MANIFEST = "runtime.json"


@dataclass(frozen=True)
class Runtime:
    directory: Path
    manifest: dict


def _error(path):
    return ValueError(f"Cannot verify the sensor runtime {path}. Repair it before replacing the service.")


def _path(value):
    return (isinstance(value, str) and value and "\\" not in value
            and "\0" not in value and all(part not in ("", ".", "..") for part in value.split("/")))


def _manifest(directory, name):
    if directory.is_symlink() or not directory.is_dir():
        raise _error(directory)
    path = directory / MANIFEST
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise _error(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise _error(path) from exc
    if (not isinstance(value, dict) or set(value) != {"schema", "name", "entries"}
            or type(value.get("schema")) is not int
            or value["schema"] != 1 or value.get("name") != name
            or not isinstance(value.get("entries"), dict) or not 0 < len(value["entries"]) <= 10000):
        raise _error(path)
    for relative, entry in value["entries"].items():
        if not _path(relative) or relative == MANIFEST or not isinstance(entry, dict):
            raise _error(path)
        kind = entry.get("kind")
        if kind == "file":
            if (set(entry) != {"kind", "sha256"} or not isinstance(entry.get("sha256"), str)
                    or not DIGEST.fullmatch(entry["sha256"])):
                raise _error(path)
        elif kind == "symlink":
            target = entry.get("target")
            if (set(entry) != {"kind", "target"} or not isinstance(target, str) or not target or "\\" in target
                    or "\0" in target or Path(target).is_absolute()):
                raise _error(path)
        elif kind != "directory" or set(entry) != {"kind"}:
            raise _error(path)
    return value


def _validate(directory, manifest):
    if directory.is_symlink() or not directory.is_dir():
        raise _error(directory)
    entries = manifest["entries"]
    found = set()
    root = directory.resolve()

    def visit(parent):
        for path in parent.iterdir():
            relative = path.relative_to(directory).as_posix()
            if relative == MANIFEST:
                continue
            entry = entries.get(relative)
            if entry is None:
                raise _error(path)
            found.add(relative)
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                try:
                    depth = len(Path(relative).parts) - 1
                    for part in Path(entry.get("target", "")).parts:
                        if part == "..":
                            depth -= 1
                            if depth < 0:
                                raise _error(path)
                        elif part != ".":
                            depth += 1
                    valid = (entry["kind"] == "symlink" and os.readlink(path) == entry["target"]
                             and path.resolve(strict=True).is_relative_to(root))
                except (OSError, RuntimeError):
                    valid = False
                if not valid:
                    raise _error(path)
            elif stat.S_ISDIR(mode):
                if entry["kind"] != "directory":
                    raise _error(path)
                visit(path)
            elif stat.S_ISREG(mode):
                if entry["kind"] != "file":
                    raise _error(path)
                with path.open("rb") as stream:
                    if hashlib.file_digest(stream, "sha256").hexdigest() != entry["sha256"]:
                        raise _error(path)
            else:
                raise _error(path)

    visit(directory)
    if found != entries.keys():
        raise _error(directory)


def inspect(binary, data=None):
    """Return a verified runtime, or None for an existing one-file sensor."""
    binary = Path(binary)
    if data is None:
        data = binary.read_bytes()
    if MARKER not in data:
        return None
    if data.count(MARKER) != 1 or binary.is_symlink():
        raise _error(binary)
    suffix = data.split(MARKER, 1)[1]
    if len(suffix) < 65 or suffix[64] != 0:
        raise _error(binary)
    try:
        name = "openaidr-runtime-" + suffix[:64].decode("ascii")
    except UnicodeError as exc:
        raise _error(binary) from exc
    if not NAME.fullmatch(name):
        raise _error(binary)
    parent = binary.parent
    if parent.is_symlink():
        raise _error(parent)
    if parent.name == "MacOS" and parent.parent.name == "Contents":
        contents = parent.parent
        frameworks = contents / "Frameworks"
        resources = contents / "Resources"
        if (contents.is_symlink() or parent.is_symlink() or resources.is_symlink() or not frameworks.is_symlink()
                or os.readlink(frameworks) != f"Resources/{name}"):
            raise _error(frameworks)
        directory = resources / name
    else:
        directory = parent / name
    manifest = _manifest(directory, name)
    _validate(directory, manifest)
    return Runtime(directory, manifest)


def stage(runtime, parent):
    """Publish all support files before the caller replaces executable aliases."""
    parent = Path(parent)
    if parent.is_symlink():
        raise _error(parent)
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = runtime.manifest["name"]
    destination = parent / name

    def existing():
        if destination.is_symlink():
            raise _error(destination)
        manifest = _manifest(destination, name)
        if manifest != runtime.manifest:
            raise _error(destination)
        _validate(destination, manifest)

    if destination.exists() or destination.is_symlink():
        existing()
        return
    temporary = Path(tempfile.mkdtemp(prefix=".openaidr-runtime-new-", dir=parent))
    try:
        shutil.copytree(runtime.directory, temporary, symlinks=True, dirs_exist_ok=True)
        if _manifest(temporary, name) != runtime.manifest:
            raise _error(temporary)
        _validate(temporary, runtime.manifest)
        try:
            os.rename(temporary, destination)
        except OSError:
            # Another setup can publish the same complete artifact first.
            existing()
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
