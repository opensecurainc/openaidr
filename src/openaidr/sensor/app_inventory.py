"""Read explicitly selected app bundles inside the osquery extension."""

import json
import os
from pathlib import Path
import plistlib
import stat
import time
from xml.parsers.expat import ExpatError

from .privacy import PrivacyGuard

COLUMNS = ("path", "name", "identifier", "version")


def app_rows(context):
    """Require literal bundle paths; never consult Spotlight or LaunchServices."""
    paths = list(
        dict.fromkeys(
            constraint["expr"]
            for column in context.get("constraints", [])
            if column.get("name") == "path"
            for constraint in column.get("list", [])
            if constraint.get("op") == 2
        )
    )
    if len(paths) > 10000:
        raise ValueError("Application query exceeds its path limit.")
    guard = PrivacyGuard()
    deadline = time.monotonic() + 20
    rows, size = [], 0
    for path in paths:
        if time.monotonic() >= deadline:
            raise ValueError("Application query reached its time limit.")
        if (
            not isinstance(path, str)
            or len(path) > 8192
            or "\0" in path
            or not Path(path).is_absolute()
            or not path.endswith(".app")
        ):
            raise ValueError("Application query requires absolute bundle paths.")
        metadata = Path(path) / "Contents/Info.plist"
        try:
            guard.check(metadata)
            fd = os.open(metadata, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > 1 << 20:
                    continue
                body = stream.read((1 << 20) + 1)
                after = os.fstat(stream.fileno())
                if len(body) > 1 << 20 or any(
                    getattr(before, key) != getattr(after, key)
                    for key in ("st_size", "st_mtime_ns", "st_ctime_ns")
                ):
                    continue
            fmt = (
                plistlib.FMT_BINARY
                if body.startswith(b"bplist00")
                else plistlib.FMT_XML
            )
            info = plistlib.loads(body, fmt=fmt)
            if not isinstance(info, dict):
                continue
            info = {key: value for key, value in info.items() if isinstance(value, str)}
        except (
            OSError,
            ValueError,
            plistlib.InvalidFileException,
            ExpatError,
            RecursionError,
        ):
            # The sensor audits expected paths and reports missing rows as partial.
            continue
        row = dict(
            path=path,
            name=info.get("CFBundleDisplayName")
            or info.get("CFBundleName")
            or Path(path).name,
            identifier=info.get("CFBundleIdentifier", ""),
            version=info.get("CFBundleShortVersionString")
            or info.get("CFBundleVersion", ""),
        )
        size += len(json.dumps(row))
        if size > 4 << 20:
            raise ValueError("Application query reached its output limit.")
        rows.append(row)
    return rows
