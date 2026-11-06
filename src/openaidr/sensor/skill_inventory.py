"""Bounded SKILL.md discovery used inside the OpenAIDR osquery extension."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit

import yaml

from .privacy import PrivacyGuard, PrivacySkip, SKIPPED

MAX_FILE = 1 << 20
MAX_HEADER = 64 << 10
MAX_ENTRIES = 100000
MAX_COMPONENTS = 10000
MAX_BYTES = 4 << 20
MAX_DEPTH = 8
MAX_SECONDS = 20
COLUMNS = (
    "record",
    "directory",
    "path",
    "name",
    "version",
    "publisher",
    "metadata",
    "status",
    "message",
)


class _Invalid(ValueError):
    pass


class _Limit(Exception):
    pass


class _Loader(yaml.SafeLoader):
    # Treat version numbers and other plain scalars as text. Reject aliases,
    # duplicate keys and excessive structure before constructing YAML objects.
    yaml_implicit_resolvers = {}

    def __init__(self, stream):
        super().__init__(stream)
        self.nodes = self.depth = 0

    def compose_node(self, parent, index):
        self.nodes += 1
        self.depth += 1
        try:
            if self.nodes > 512 or self.depth > 16 or self.check_event(yaml.AliasEvent):
                raise _Invalid()
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node, deep=False):
        result = super().construct_mapping(node, deep=deep)
        if len(result) != len(node.value):
            raise _Invalid()
        return result


def _text(value, limit):
    if not isinstance(value, str) or len(value) > limit or "\0" in value:
        raise _Invalid()
    value.encode("utf-8")
    return value.strip()


def _metadata(data, fallback):
    # Only YAML between the first two delimiter lines is metadata. The body is
    # hashed as bytes and is never interpreted, returned, or included in errors.
    lines = data.removeprefix(b"\xef\xbb\xbf")[: MAX_HEADER + 1].splitlines(
        keepends=True
    )
    if not lines or lines[0].rstrip(b" \t\r\n") != b"---":
        raise _Invalid()
    end = next(
        (i for i in range(1, len(lines)) if lines[i].rstrip(b" \t\r\n") == b"---"),
        None,
    )
    if end is None or len(b"".join(lines[: end + 1])) > MAX_HEADER:
        raise _Invalid()
    header = yaml.load(b"".join(lines[1:end]).decode("utf-8"), Loader=_Loader)
    if not isinstance(header, dict):
        raise _Invalid()
    name = _text(header.get("name", fallback), 1024)
    if not name:
        raise _Invalid()
    declared = header.get("metadata", {})
    if not isinstance(declared, dict):
        raise _Invalid()
    metadata = {"content_sha256": hashlib.sha256(data).hexdigest()}
    for field, limit in (("description", 2048), ("license", 1024)):
        value = _text(header.get(field, ""), limit)
        if value and not (field == "license" and "://" in value):
            metadata[field] = value
    for field in ("repository_url", "source_url", "revision"):
        value = _text(declared.get(field, ""), 256 if field == "revision" else 2048)
        if not value:
            continue
        if field.endswith("_url"):
            parts = urlsplit(value)
            if (
                parts.scheme not in ("http", "https")
                or not parts.hostname
                or parts.username is not None
                or parts.password is not None
                or parts.query
                or parts.fragment
                or any(c.isspace() or ord(c) < 32 for c in value)
            ):
                # Do not forward credentials from declared URLs, even in errors.
                continue
            parts.port
        metadata[field] = value
    tools = header.get("allowed-tools", [])
    if isinstance(tools, str):
        tools = re.sub(r"\([^()]*\)", "", _text(tools, 32768))
        if "(" in tools or ")" in tools:
            raise _Invalid()
        tools = re.split(r"[\s,]+", tools)
    if not isinstance(tools, list) or len(tools) > 128:
        raise _Invalid()
    names = []
    for tool in tools:
        # Keep tool names only; permission arguments may contain private data.
        name_only = _text(tool, 2048).split("(", 1)[0]
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_:-]{0,255}", name_only):
            names.append(name_only)
    if names:
        metadata["tools"] = list(dict.fromkeys(names))
    return dict(
        name=name,
        version=_text(declared.get("version", ""), 256),
        publisher=_text(declared.get("author", ""), 1024),
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

    def root(self, directory):
        rows, stamps = [], {}
        coverage = dict.fromkeys(COLUMNS, "")
        coverage.update(record="coverage", directory=directory, status="ok")

        def partial(message):
            coverage.update(status="partial", message=message)

        def within_root(path):
            if not self.privacy.check(path).is_relative_to(canonical_base):
                partial("Some skill paths resolve outside their scan location.")
                return False
            return True

        def walk(path, depth=0, ancestors=frozenset()):
            self.check()
            if not within_root(path):
                return
            info = path.stat()
            identity = (info.st_dev, info.st_ino)
            if identity in ancestors or depth > MAX_DEPTH:
                partial("Skill traversal reached a cycle or depth limit.")
                return
            stamps[path] = _signature(info)
            with os.scandir(path) as entries:
                children = []
                manifest = None
                for entry in entries:
                    self.entries += 1
                    self.check()
                    if entry.name == "SKILL.md":
                        manifest = Path(entry.path)
                    elif entry.name != ".git":
                        try:
                            if not within_root(entry.path):
                                continue
                            if entry.is_dir():
                                children.append(Path(entry.path))
                            elif entry.is_symlink():
                                # A broken link could conceal an installation.
                                entry.stat()
                        except PrivacySkip:
                            partial(SKIPPED)
            if manifest is not None:
                self.check()
                if not within_root(manifest):
                    return
                # O_NONBLOCK prevents a named pipe from hanging before fstat.
                fd = os.open(manifest, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                with os.fdopen(fd, "rb") as stream:
                    before = os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
                        raise _Invalid()
                    data = stream.read(MAX_FILE + 1)
                    if len(data) > MAX_FILE or _signature(
                        os.fstat(stream.fileno())
                    ) != _signature(before):
                        raise _Invalid()
                stamps[manifest] = _signature(before)
                if len(str(manifest)) > 8192:
                    raise _Invalid()
                row = dict.fromkeys(COLUMNS, "")
                row.update(record="component", directory=directory, path=str(manifest))
                row.update(_metadata(data, path.name))
                size = len(json.dumps(row))
                if self.components >= MAX_COMPONENTS or self.bytes + size > MAX_BYTES:
                    raise _Limit()
                rows.append(row)
                self.bytes += size
                self.components += 1
                # Supporting files inside a skill are not separate installations.
                return
            for child in children:
                try:
                    walk(child, depth + 1, ancestors | {identity})
                except (OSError, ValueError, yaml.YAMLError):
                    partial("Some skill metadata could not be read or parsed.")

        base = Path(directory)
        try:
            canonical_base = self.privacy.check(base)
            base.stat()
        except PrivacySkip:
            coverage.update(status="unavailable", message=SKIPPED)
            return [coverage]
        except FileNotFoundError:
            coverage.update(
                status="unavailable", message="Skill location is unavailable."
            )
            return [coverage]
        except OSError:
            coverage.update(status="error", message="Skill location could not be read.")
            return [coverage]
        try:
            walk(base)
            for path, before in stamps.items():
                self.check()
                if not within_root(path):
                    continue
                if _signature(path.stat()) != before:
                    partial("Skill files or directories changed during collection.")
        except (OSError, ValueError, yaml.YAMLError):
            partial("Some skill metadata could not be read or parsed.")
        except _Limit:
            partial("Skill scan reached its time, entry, component or output limit.")
        return [coverage, *rows]


def skill_rows(context):
    """No scan without explicit absolute directory equality constraints."""
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
        raise _Invalid()
    scan = _Scan()
    rows = []
    for directory in directories:
        if not _text(directory, 2048) or not Path(directory).is_absolute():
            raise _Invalid()
        rows.extend(scan.root(directory))
    return rows
