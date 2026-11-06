"""Read bounded MCP configuration declarations inside the osquery extension."""

import json
import os
from pathlib import Path
import stat
import time
import tomllib

from .privacy import PrivacyGuard, PrivacySkip, SKIPPED

MAX_FILE = 1 << 20
MAX_NODES = 20000
MAX_DEPTH = 32
MAX_COMPONENTS = 10000
MAX_BYTES = 4 << 20
MAX_SECONDS = 20
COLUMNS = ("record", "path", "identifier", "name", "status", "message")


class _Limit(Exception):
    pass


def _invalid(*args):
    raise ValueError("Invalid MCP configuration")


def _mapping(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        _invalid()
    return result


def _text(value, limit):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > limit
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        _invalid()
    value.encode("utf-8")
    return value


def _pointer(parts):
    return "/" + "/".join(part.replace("~", "~0").replace("/", "~1") for part in parts)


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _Scan:
    def __init__(self):
        self.deadline = time.monotonic() + MAX_SECONDS
        self.components = self.bytes = 0
        self.privacy = PrivacyGuard()

    def check(self):
        if time.monotonic() >= self.deadline:
            raise _Limit()

    def parse(self, data, toml):
        text = data.decode("utf-8-sig")
        document = (
            tomllib.loads(text)
            if toml
            else json.loads(text, object_pairs_hook=_mapping, parse_constant=_invalid)
        )
        if not isinstance(document, dict):
            _invalid()
        stack = [(document, 0)]
        nodes = 0
        while stack:
            self.check()
            value, depth = stack.pop()
            nodes += 1
            if nodes > MAX_NODES or depth > MAX_DEPTH:
                raise _Limit()
            if isinstance(value, str):
                value.encode("utf-8")
            if isinstance(value, (dict, list)):
                children = value.values() if isinstance(value, dict) else value
                stack.extend((child, depth + 1) for child in children)
        return document

    def root(self, filename):
        coverage = dict.fromkeys(COLUMNS, "")
        coverage.update(record="coverage", path=filename, status="ok")
        rows = []

        def partial(message="Some MCP configuration entries could not be parsed."):
            coverage.update(status="partial", message=message)

        path = Path(filename)
        try:
            self.check()
            self.privacy.check(path)
            # Opening a FIFO must not block before we can reject its file type.
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        except PrivacySkip:
            coverage.update(status="unavailable", message=SKIPPED)
            return [coverage]
        except FileNotFoundError:
            coverage.update(
                status="unavailable", message="MCP configuration is unavailable."
            )
            return [coverage]
        except OSError:
            coverage.update(
                status="error", message="MCP configuration could not be read."
            )
            return [coverage]
        except _Limit:
            partial("MCP collection reached its time limit.")
            return [coverage]
        try:
            try:
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    before = os.fstat(fd)
                    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
                        _invalid()
                    data = stream.read(MAX_FILE + 1)
                    if len(data) > MAX_FILE:
                        _invalid()
                    if _signature(os.fstat(fd)) != _signature(before):
                        partial("MCP configuration changed during collection.")
            finally:
                # fdopen can reject a directory before returning a stream.
                os.close(fd)
            toml = path.suffix.lower() == ".toml"
            document = self.parse(data, toml)
            field = "mcp_servers" if toml else "mcpServers"
            if any(
                key in document
                for key in {"servers", "mcpServers", "mcp_servers"} - {field}
            ):
                partial("MCP configuration contains an unsupported server map.")
            groups = [((field,), document.get(field, {}))]
            if not toml:
                projects = document.get("projects", {})
                if not isinstance(projects, dict):
                    partial()
                else:
                    for project, config in projects.items():
                        self.check()
                        try:
                            _text(project, 2048)
                            if not Path(project).is_absolute() or not isinstance(
                                config, dict
                            ):
                                _invalid()
                            groups.append(
                                (("projects", project, field), config.get(field, {}))
                            )
                        except ValueError:
                            partial()
            for prefix, servers in groups:
                if not isinstance(servers, dict):
                    partial()
                    continue
                for name, definition in servers.items():
                    self.check()
                    try:
                        _text(name, 1024)
                        if not isinstance(definition, dict):
                            _invalid()
                    except ValueError:
                        partial()
                        continue
                    # Presence in the server map is configuration evidence only.
                    # Never return or interpret command, URL, env, auth or tool policy.
                    row = dict.fromkeys(COLUMNS, "")
                    row.update(
                        record="component",
                        path=filename,
                        name=name,
                        identifier=_pointer((*prefix, name)),
                    )
                    size = len(json.dumps(row))
                    if (
                        self.components >= MAX_COMPONENTS
                        or self.bytes + size > MAX_BYTES
                    ):
                        raise _Limit()
                    rows.append(row)
                    self.components += 1
                    self.bytes += size
            self.privacy.check(path)
            if _signature(path.stat()) != _signature(before):
                partial("MCP configuration changed during collection.")
        except (OSError, ValueError, RecursionError):
            partial("MCP configuration could not be read or parsed completely.")
        except _Limit:
            partial(
                "MCP collection reached its time, structure, component or output limit."
            )
        return [coverage, *rows]


def mcp_rows(context):
    """Only read files named by explicit absolute path equality constraints."""
    paths = list(
        dict.fromkeys(
            constraint["expr"]
            for column in context.get("constraints", [])
            if column.get("name") == "path"
            for constraint in column.get("list", [])
            if constraint.get("op") == 2
        )
    )
    if len(paths) > 256:
        _invalid()
    scan = _Scan()
    rows = []
    for path in paths:
        _text(path, 2048)
        if not Path(path).is_absolute():
            _invalid()
        rows.extend(scan.root(path))
    return rows
