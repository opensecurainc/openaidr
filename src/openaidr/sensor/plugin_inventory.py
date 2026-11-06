"""Read bounded plugin manifest declarations inside the osquery extension."""

import json
import os
from pathlib import Path
import stat
import time
from urllib.parse import urlsplit

from .privacy import PrivacyGuard, PrivacySkip, SKIPPED

MAX_FILE = 1 << 20
MAX_NODES = 20000
MAX_JSON_DEPTH = 32
MAX_DEPTH = 8
MAX_ENTRIES = 100000
MAX_COMPONENTS = 10000
MAX_BYTES = 4 << 20
MAX_SECONDS = 20
MAX_SKILL_DIRECTORIES = 64
PORTABLE_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
MANIFEST_DIRS = (".claude-plugin", ".codex-plugin", ".cursor-plugin", ".codebuddy-plugin")
COLUMNS = (
    "record",
    "directory",
    "path",
    "name",
    "version",
    "publisher",
    "metadata",
    "skill_directories",
    "status",
    "message",
)


class _Limit(Exception):
    pass


def _invalid(*args):
    raise ValueError("Invalid plugin manifest")


def _mapping(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        _invalid()
    return result


def _text(value, limit):
    if (
        not isinstance(value, str)
        or len(value) > limit
        or any(ord(c) < 32 and c not in "\n\r\t" or ord(c) == 127 for c in value)
    ):
        _invalid()
    value.encode("utf-8")
    return value.strip()


def _metadata(document):
    name = _text(document.get("name", ""), 1024)
    if not name or any(c.isspace() for c in name):
        _invalid()
    author = document.get("author", {})
    if not isinstance(author, dict):
        _invalid()
    metadata = {}
    for field, limit in (("description", 2048), ("license", 1024)):
        value = _text(document.get(field, ""), limit)
        if value and not (field == "license" and "://" in value):
            metadata[field] = value
    repository = _text(document.get("repository", ""), 2048)
    if repository:
        # URL credentials, query strings and fragments may contain private data.
        # Unsupported or unsafe URLs are omitted, including from diagnostics.
        try:
            parts = urlsplit(repository)
            valid = (
                parts.scheme in ("http", "https")
                and parts.hostname
                and parts.username is None
                and parts.password is None
                and not parts.query
                and not parts.fragment
                and not any(c.isspace() or ord(c) < 32 for c in repository)
            )
            parts.port
        except ValueError:
            valid = False
        if valid:
            metadata["repository_url"] = repository
    return dict(
        name=name,
        version=_text(document.get("version", ""), 256),
        publisher=_text(author.get("name", ""), 1024),
        metadata=json.dumps(metadata),
    )


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _Scan:
    def __init__(self):
        self.deadline = time.monotonic() + MAX_SECONDS
        self.entries = self.components = self.bytes = 0
        self.privacy = PrivacyGuard()

    def check(self):
        if self.entries >= MAX_ENTRIES or time.monotonic() >= self.deadline:
            raise _Limit()

    def parse(self, data):
        document = json.loads(
            data.decode("utf-8-sig"),
            object_pairs_hook=_mapping,
            parse_constant=_invalid,
        )
        if not isinstance(document, dict):
            _invalid()
        stack, nodes = [(document, 0)], 0
        while stack:
            self.check()
            value, depth = stack.pop()
            nodes += 1
            if nodes > MAX_NODES or depth > MAX_JSON_DEPTH:
                _invalid()
            if isinstance(value, str):
                value.encode("utf-8")
            if isinstance(value, (dict, list)):
                children = value.values() if isinstance(value, dict) else value
                stack.extend((child, depth + 1) for child in children)
        return document

    def root(self, directory):
        rows, stamps = [], {}
        coverage = dict.fromkeys(COLUMNS, "")
        coverage.update(record="coverage", directory=directory, status="ok")

        def partial(message="Some plugin manifests could not be read or parsed."):
            coverage.update(status="partial", message=message)

        def manifest(path, portable):
            self.check()
            self.privacy.check(path)
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    before = os.fstat(fd)
                    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
                        _invalid()
                    data = stream.read(MAX_FILE + 1)
                    if len(data) > MAX_FILE:
                        _invalid()
                    if _signature(os.fstat(fd)) != _signature(before):
                        partial("Plugin manifest changed during collection.")
            finally:
                os.close(fd)
            stamps[path] = _signature(before)
            document = self.parse(data)
            if portable and document.get("$schema") != PORTABLE_SCHEMA:
                _invalid()
            row = dict.fromkeys(COLUMNS, "")
            row.update(record="component", directory=directory, path=str(path))
            row.update(_metadata(document))
            directories = []
            if not portable and path.parent.name in (".claude-plugin", ".codebuddy-plugin"):
                declared = document.get("skills", [])
                if isinstance(declared, str):
                    declared = [declared]
                if not isinstance(declared, list):
                    partial("Some declared skill locations could not be inspected.")
                    declared = []
                if len(declared) > MAX_SKILL_DIRECTORIES:
                    partial("Plugin skill declarations reached their location limit.")
                base = self.privacy.check(path.parent.parent)
                for value in declared[:MAX_SKILL_DIRECTORIES]:
                    try:
                        self.check()
                        _text(value, 2048)
                        relative = Path(value)
                        if (
                            not value
                            or (value != "." and not value.startswith("./"))
                            or relative.is_absolute()
                            or ".." in relative.parts
                            or any(c in value for c in "\\$*?[]{}")
                            or any(ord(c) < 32 for c in value)
                        ):
                            _invalid()
                        target = self.privacy.check(base / relative)
                        if not target.is_relative_to(base) or len(str(target)) > 2048:
                            _invalid()
                        directories.append(str(target))
                    except (OSError, ValueError):
                        partial("Some declared skill locations could not be inspected.")
            row["skill_directories"] = json.dumps(list(dict.fromkeys(directories)))
            if len(row["path"]) > 8192:
                _invalid()
            size = len(json.dumps(row))
            if self.components >= MAX_COMPONENTS or self.bytes + size > MAX_BYTES:
                raise _Limit()
            rows.append(row)
            self.components += 1
            self.bytes += size

        def walk(path, depth=0, ancestors=frozenset()):
            self.check()
            self.privacy.check(path)
            info = path.stat()
            identity = (info.st_dev, info.st_ino)
            if identity in ancestors or depth > MAX_DEPTH:
                partial("Plugin traversal reached a cycle or depth limit.")
                return
            stamps[path] = _signature(info)
            children, markers = [], []
            portable = None
            with os.scandir(path) as entries:
                for entry in entries:
                    self.entries += 1
                    self.check()
                    if entry.name == "plugin.json":
                        portable = Path(entry.path)
                    elif entry.name in MANIFEST_DIRS:
                        markers.append(Path(entry.path))
                    elif entry.name != ".git":
                        try:
                            self.privacy.check(entry.path)
                            if entry.is_dir():
                                children.append(Path(entry.path))
                            elif entry.is_symlink():
                                entry.stat()
                        except PrivacySkip:
                            partial(SKIPPED)
            candidates = [portable] if portable else []
            if not portable:
                for marker in markers:
                    try:
                        self.privacy.check(marker)
                        stamps[marker] = _signature(marker.stat())
                        candidate = marker / "plugin.json"
                        try:
                            self.privacy.check(candidate)
                            candidate.lstat()
                        except FileNotFoundError:
                            continue
                        candidates.append(candidate)
                    except OSError:
                        partial()
            for candidate in candidates:
                try:
                    manifest(candidate, portable is not None)
                except (OSError, ValueError, RecursionError):
                    partial()
            if candidates:
                # A plugin's supporting files are not separate declarations.
                return
            for child in children:
                try:
                    walk(child, depth + 1, ancestors | {identity})
                except (OSError, ValueError):
                    partial()

        base = Path(directory)
        try:
            self.privacy.check(base)
            base.stat()
        except PrivacySkip:
            coverage.update(status="unavailable", message=SKIPPED)
            return [coverage]
        except FileNotFoundError:
            coverage.update(
                status="unavailable", message="Plugin location is unavailable."
            )
            return [coverage]
        except OSError:
            coverage.update(
                status="error", message="Plugin location could not be read."
            )
            return [coverage]
        try:
            walk(base)
            for path, before in stamps.items():
                self.check()
                self.privacy.check(path)
                if _signature(path.stat()) != before:
                    partial("Plugin files or directories changed during collection.")
        except (OSError, ValueError):
            partial()
        except _Limit:
            partial("Plugin scan reached its time, structure, entry or output limit.")
        return [coverage, *rows]


def plugin_rows(context):
    """Only scan explicit absolute directory equality constraints."""
    directories = list(
        dict.fromkeys(
            constraint["expr"]
            for column in context.get("constraints", [])
            if column.get("name") == "directory"
            for constraint in column.get("list", [])
            if constraint.get("op") == 2
        )
    )
    if len(directories) > 256:
        _invalid()
    scan = _Scan()
    rows = []
    for directory in directories:
        if not _text(directory, 2048) or not Path(directory).is_absolute():
            _invalid()
        rows.extend(scan.root(directory))
    return rows
