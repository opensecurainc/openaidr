"""Durable private files shared by endpoint collection and enforcement."""

import os
import tempfile
from pathlib import Path

_ANY_CONTENT = object()


class ConcurrentFileChange(OSError):
    """The caller's source changed before its replacement was published."""


def file_content(path):
    try:
        return Path(path).read_bytes()
    except FileNotFoundError:
        return None


def sync_directory(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def durable_directory(path):
    """Publish each new directory entry before files depend on its existence."""
    path = Path(path).absolute()
    missing, parent = [], path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    # A previous attempt may have created this anchor before its sync failed.
    if parent != parent.parent:
        sync_directory(parent.parent)
    for entry in reversed(missing):
        entry.mkdir(mode=0o700, exist_ok=True)
        sync_directory(entry.parent)
    return path


def atomic_write(path, data, *, expected=_ANY_CONTENT):
    path = Path(path)
    durable_directory(path.parent)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if expected is not _ANY_CONTENT and file_content(path) != expected:
            raise ConcurrentFileChange(f"{path} changed during setup; retry the operation")
        os.replace(tmp, path)
        sync_directory(path.parent)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
