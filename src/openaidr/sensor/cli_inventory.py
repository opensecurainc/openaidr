"""Discover executable launchers without importing or running installed code."""

import ast
import configparser
from email.parser import Parser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import tomllib
import zipfile

from .privacy import PrivacySkip, SKIPPED


def _read(path, scan, *, prefix=False, binary=False):
    scan.check()
    path = scan.privacy.check(path)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Metadata is not a regular file.")
        flags = os.O_RDONLY
        for flag in ("O_NONBLOCK", "O_CLOEXEC", "O_NOFOLLOW", "O_BINARY"):
            flags |= getattr(os, flag, 0)
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("Metadata changed before collection.")
        limit = 8192 if prefix and not binary else 1 << 20
        body = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if any(getattr(before, key) != getattr(after, key)
               for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
            raise ValueError("Executable metadata changed during collection.")
        if len(body) > limit:
            if prefix:
                return None
            raise ValueError("Executable metadata exceeds 1 MiB.")
    if binary:
        return body
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        if prefix:
            return None
        raise ValueError("Executable metadata is not UTF-8.") from None


def _executable(path, info):
    if not stat.S_ISREG(info.st_mode):
        return False
    if sys.platform == "win32":
        return path.suffix.lower() in (".exe", ".com", ".cmd", ".bat", ".ps1")
    return bool(info.st_mode & 0o111)


def _target(path, scan):
    visited = set()
    for _ in range(8):
        scan.check()
        path = scan.privacy.check(path)
        if path in visited:
            raise ValueError("Launcher cycle or chain limit.")
        visited.add(path)
        info = path.stat()
        if not _executable(path, info):
            raise ValueError("Launcher target is not an executable file.")
        body = _read(path, scan, prefix=True)
        lines = [line.strip() for line in (body or "").splitlines() if line.strip()]
        if len(lines) != 2 or lines[0] not in ("#!/bin/sh", "#!/bin/bash"):
            return path
        try:
            words = shlex.split(lines[1])
        except ValueError:
            return path
        if (len(words) < 3 or words[0] != "exec" or words[-1] != "$@"
                or not words[1].startswith("/")
                or any(c in word for word in words[1:-1] for c in "$`;&|<>()\n\r")):
            return path
        path = Path(words[1])
    raise ValueError("Launcher cycle or chain limit.")


def _distribution(site, command, scan, imports=None):
    matches = []
    for entry in scan.entries_at(site):
        if not entry.name.endswith(".dist-info"):
            continue
        metadata = Path(entry.path)
        body = _read(metadata / "entry_points.txt", scan)
        if body is None:
            continue
        points = configparser.ConfigParser(interpolation=None)
        points.optionxform = str.lower if sys.platform == "win32" else str
        points.read_string(body)
        if not points.has_option("console_scripts", command):
            continue
        entry_point = points.get("console_scripts", command).split("[", 1)[0].strip()
        if imports is not None and entry_point not in imports:
            continue
        body = _read(metadata / "METADATA", scan)
        if body is not None:
            fields = Parser().parsestr(body, headersonly=True)
            matches.append(("pypi", fields.get("Name"), fields.get("Version", "")))
    return matches


def _windows_package(target, scan):
    if target.suffix.lower() in (".cmd", ".ps1"):
        body = _read(target, scan, prefix=True) or ""
        # npm's generated shims use only these literal paths. Do not expand
        # variables or evaluate PowerShell / cmd syntax.
        if not (re.search(r'(?im)^\s*SET (?:"dp0=%~dp0"|dp0=%~dp0)\s*$', body)
                or re.search(r'(?m)^\$basedir=Split-Path \$MyInvocation\.MyCommand\.Definition -Parent\s*$', body)):
            return None
        paths = set(re.findall(r'''["'](?:%dp0%[\\/]|\$basedir[\\/])(node_modules[\\/][^"'\r\n]+)["']''', body))
        if len(paths) != 1:
            return None
        relative = paths.pop().replace("\\", "/")
        if any(char in relative for char in "$%`") or ".." in Path(relative).parts:
            return None
        entry = scan.privacy.check(target.parent / relative)
        if entry.is_file():
            return _package(entry, scan, launcher=False)
        return None
    if target.suffix.lower() != ".exe":
        return None
    body = _read(target, scan, prefix=True, binary=True)
    if not body or not body.startswith(b"MZ"):
        return None
    # distlib console launchers contain one Python entry script. Read it as
    # data, never import it, and bound both the archive and expanded script.
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            files = archive.infolist()
            if len(files) != 1 or files[0].filename != "__main__.py":
                return None
            if files[0].file_size > 65536:
                raise ValueError("Launcher entry script exceeds 64 KiB.")
            if files[0].compress_type != zipfile.ZIP_STORED:
                return None
            script = archive.read(files[0]).decode("utf-8")
            prefix = body[:files[0].header_offset]
    except zipfile.BadZipFile:
        return None
    tree = ast.parse(script)
    imports = {f"{node.module}:{name.name}" for node in ast.walk(tree)
               if isinstance(node, ast.ImportFrom) and node.level == 0 for name in node.names}
    command = target.stem.lower()
    matches = []
    for node in tree.body:
        if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if (ast.unparse(call.func) != "sys.path.insert" or len(call.args) != 2
                or not isinstance(call.args[0], ast.Constant) or call.args[0].value != 0
                or not isinstance(call.args[1], ast.Constant) or not isinstance(call.args[1].value, str)):
            continue
        project_path = Path(call.args[1].value)
        if not project_path.is_absolute():
            continue
        metadata = _read(project_path / "pyproject.toml", scan)
        if metadata is not None:
            project = tomllib.loads(metadata).get("project", {})
            scripts = project.get("scripts", {}) if isinstance(project, dict) else {}
            entry_point = scripts.get(command) if isinstance(scripts, dict) else None
            if isinstance(entry_point, str) and entry_point in imports:
                matches.append(("pypi", project.get("name"), project.get("version", "")))
    if matches:
        return matches[0] if len(matches) == 1 else None
    # Copied pip/uv launchers can live outside Scripts. Their embedded shebang
    # identifies the environment; its declaration must match the entry script.
    line = prefix[prefix.rfind(b"\0") + 1:]
    match = re.fullmatch(rb'#!"?([^"\r\n]+?python(?:w)?\.exe)"?(?: -I)?\r?\n', line, re.I)
    if match:
        python = Path(match[1].decode("utf-8"))
        if python.is_absolute():
            env = python.parent.parent if python.parent.name.lower() == "scripts" else python.parent
            for site in scan.expand(env, "Lib/site-packages"):
                matches.extend(_distribution(site, command, scan, imports))
    return matches[0] if len(matches) == 1 else None


def _package(target, scan, *, launcher=True):
    if sys.platform == "win32" and launcher:
        package = _windows_package(target, scan)
        if package:
            return package
    command = target.stem if sys.platform == "win32" else target.name
    # A declared entry point must match the launcher, not just a nearby name.
    projects = []
    for parent in list(target.parents)[:5]:
        body = _read(parent / "package.json", scan)
        if body is not None:
            package = json.loads(body)
            if not isinstance(package, dict):
                raise ValueError("Invalid package metadata.")
            bins = package.get("bin", {})
            if isinstance(bins, str):
                bins = {"": bins}
            if isinstance(bins, dict):
                for entry in bins.values():
                    scan.check()
                    if (isinstance(entry, str) and not Path(entry).is_absolute()
                            and scan.privacy.check(parent / entry) == target):
                        return "npm", package.get("name"), package.get("version", "")
        body = _read(parent / "pyproject.toml", scan)
        if body is not None:
            project = tomllib.loads(body).get("project", {})
            if (isinstance(project, dict) and isinstance(project.get("scripts"), dict)
                    and command in project["scripts"] and target.parent.name == "bin"
                    and (target.parent.parent == parent or (
                        target.parent.parent.parent == parent and target.parent.parent.name.startswith(".")))):
                projects.append(("pypi", project.get("name"), project.get("version", "")))

    windows = sys.platform == "win32" and target.parent.name.lower() == "scripts"
    if target.parent.name != "bin" and not windows:
        return None
    matches = []
    pattern = "Lib/site-packages" if windows else "lib/python*/site-packages"
    for site in scan.expand(target.parent.parent, pattern):
        matches.extend(_distribution(site, command, scan))
    if matches:
        return matches[0] if len(matches) == 1 else None
    return projects[0] if len(projects) == 1 else None


def collect(root, scan):
    # Reuse the component worker's time, entry, privacy and payload limits.
    from .component_inventory import _Limit, _partial, _text, MAX_COMPONENTS

    base = Path(root["root"])
    try:
        before = scan.privacy.check(base).stat()
        for entry in scan.entries_at(base):
            try:
                path = Path(entry.path)
                resolved = scan.privacy.check(path)
                info = resolved.stat()
                if not _executable(resolved, info):
                    continue
                target = _target(path, scan)
                target_info = target.stat()
                name = entry.name
                identifier = "executable:" + hashlib.sha256(str(target).encode()).hexdigest()
                version = ""
                try:
                    package = _package(target, scan)
                    if package:
                        ecosystem, name, version = package
                        if not _text(name, 1024) or (version != "" and not _text(version, 256)):
                            raise ValueError("Invalid package identity.")
                        package_name = re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "pypi" else name
                        identifier = ecosystem + ":" + package_name
                except (OSError, ValueError, SyntaxError, configparser.Error, RecursionError,
                        zipfile.BadZipFile, NotImplementedError, RuntimeError):
                    name, version = entry.name, ""
                    _partial(root, "Some executable identities could not be confirmed from metadata.")
                if not all((_text(name, 1024), _text(identifier, 2048), _text(str(path), 8192), _text(entry.name, 2048))):
                    raise ValueError("Invalid executable identity.")
                final_target = _target(path, scan)
                final_info = final_target.stat()
                if final_target != target or any(
                    getattr(target_info, key) != getattr(final_info, key)
                    for key in ("st_dev", "st_ino", "st_mtime_ns", "st_ctime_ns")
                ):
                    raise ValueError("Executable changed during collection.")
                root["components"].append(dict(
                    key=entry.name, name=name, identifier=identifier, version=version,
                    path=str(path), kind="application", ecosystem="", evidence="installed",
                ))
                if len(root["components"]) >= MAX_COMPONENTS:
                    raise _Limit("Executable scan reached its component limit.")
            except PrivacySkip as exc:
                _partial(root, str(exc) or SKIPPED)
            except (OSError, ValueError):
                _partial(root, "Some executable entries were unavailable or changed during collection.")
        after = scan.privacy.check(base).stat()
        if (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
            _partial(root, "Executable directory changed during collection.")
    except PrivacySkip as exc:
        root.update(status="unavailable", message=str(exc) or SKIPPED, components=[])
    except FileNotFoundError:
        root.update(status="unavailable", message="Executable directory is unavailable.", components=[])
    except OSError:
        _partial(root, "Executable directory could not be read completely.")
    except _Limit as exc:
        _partial(root, str(exc))
