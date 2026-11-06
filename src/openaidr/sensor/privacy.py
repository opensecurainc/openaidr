"""Avoid macOS consent prompts and Windows remote or removable inventory reads."""

import ctypes
import errno
import os
from collections import deque
from pathlib import Path
import stat
import sys

SKIPPED = "Location skipped to avoid macOS privacy prompts."


class PrivacySkip(PermissionError):
    pass


class _Statfs(ctypes.Structure):
    # Darwin's statfs64 ABI (sys/mount.h). Reuse the type: ctypes.POINTER keeps
    # structure types alive in Python 3.13 and older, even after a scan ends.
    _fields_ = [
        ("bsize", ctypes.c_uint32),
        ("iosize", ctypes.c_int32),
        ("counts", ctypes.c_uint64 * 5),
        ("fsid", ctypes.c_int32 * 2),
        ("owner", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("subtype", ctypes.c_uint32),
        ("fstype", ctypes.c_char * 16),
        ("mountpoint", ctypes.c_char * 1024),
        ("source", ctypes.c_char * 1024),
        ("reserved", ctypes.c_uint32 * 8),
    ]


def _protected_mounts():
    # MNT_NOWAIT reads the kernel's cached mount table without contacting
    # network filesystems or probing mount paths. Refresh it for every guard.
    getfsstat = ctypes.CDLL(None, use_errno=True).getfsstat64
    getfsstat.argtypes = [ctypes.POINTER(_Statfs), ctypes.c_int, ctypes.c_int]
    getfsstat.restype = ctypes.c_int
    count = getfsstat(None, 0, 2)
    if count < 0:
        raise OSError(ctypes.get_errno(), "Cannot read mount table")
    mounts = (_Statfs * (count + 16))()
    count = getfsstat(mounts, ctypes.sizeof(mounts), 2)
    if count < 0 or count >= len(mounts):
        raise OSError("Cannot read complete mount table")
    return [
        Path(os.fsdecode(mount.mountpoint))
        for mount in mounts[:count]
        if not mount.flags & 0x1000 or mount.flags & 0x200  # MNT_LOCAL / REMOVABLE
    ]


def _parts(path):
    parts = Path(str(path).casefold()).parts
    # The writable system volume is also reachable through its physical path.
    if parts[:4] == ("/", "system", "volumes", "data"):
        parts = ("/", *parts[4:])
    return parts


class PrivacyGuard:
    def __init__(self):
        self.macos = sys.platform == "darwin"
        self.windows = os.name == "nt"
        self.home = _parts(Path.home())
        self.mounts = None

    def _check_location(self, path):
        if self.windows:
            # Reject UNC and device namespaces before any filesystem operation.
            # GetDriveType reads the drive classification, not remote contents.
            drive_type = ctypes.windll.kernel32.GetDriveTypeW
            drive_type.argtypes = [ctypes.c_wchar_p]
            drive_type.restype = ctypes.c_uint
            if path.drive.startswith("\\") or drive_type(path.anchor) not in (3, 6):
                raise PrivacySkip("Location skipped because it is not on a local fixed disk.")
            return
        parts = _parts(path)
        if any(parts[: len(root)] == root for root in self.mounts):
            raise PrivacySkip(SKIPPED)
        if parts[1:2] in (("volumes",), ("network",), ("net",), ("home",)):
            raise PrivacySkip(SKIPPED)
        relative = ()
        if parts[: len(self.home)] == self.home:
            relative = parts[len(self.home) :]
        elif parts[1:2] == ("users",) and len(parts) >= 3:
            relative = parts[3:]
        elif parts[1:3] == ("var", "root"):
            relative = parts[3:]
        elif parts[1:4] == ("private", "var", "root"):
            relative = parts[4:]
        elif parts[1:2] == ("library",):
            relative = parts[1:]
        if relative[:1] in (
            ("desktop",),
            ("documents",),
            ("downloads",),
            ("movies",),
            ("music",),
            ("pictures",),
        ) or relative[:2] in (
            ("library", "cloudstorage"),
            ("library", "mobile documents"),
            ("library", "containers"),
            ("library", "group containers"),
            ("library", "application support"),
            ("library", "application scripts"),
            ("library", "webkit"),
            ("library", "preferences"),
            ("library", "saved application state"),
            ("library", "mail"),
            ("library", "messages"),
            ("library", "safari"),
            ("library", "calendars"),
            ("library", "cookies"),
            ("library", "homekit"),
        ):
            raise PrivacySkip(SKIPPED)

    def check(self, path):
        """Resolve symlinks one component at a time, checking before each lstat.

        A normal resolve() can already traverse a protected or remote target.
        Keep this check next to the read; never cache path approvals across scans.
        """
        path = Path(path).expanduser()
        if not self.macos and not self.windows:
            return path.resolve()
        if self.macos and self.mounts is None:
            try:
                self.mounts = [_parts(p) for p in _protected_mounts()]
            except (OSError, AttributeError) as exc:
                raise PrivacySkip(
                    "Mount information unavailable; scan skipped."
                ) from exc
        if not path.is_absolute():
            path = Path.cwd() / path
        self._check_location(path)
        pending = deque(path.parts[1:])
        resolved = Path(path.anchor)
        links = 0
        while pending:
            part = pending.popleft()
            if part == "..":
                resolved = resolved.parent
                continue
            candidate = resolved / part
            self._check_location(candidate)
            try:
                info = candidate.lstat()
            except FileNotFoundError:
                resolved = candidate
                continue
            if stat.S_ISLNK(info.st_mode) or (self.windows and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                links += 1
                if links > 40:
                    raise OSError(errno.ELOOP, "Too many symbolic links")
                target_text = os.readlink(candidate)
                # readlink returns local Windows junctions in the extended path
                # namespace. Strip only the prefix of an ordinary drive path.
                if self.windows and target_text.startswith("\\\\?\\") and target_text[5:7] == ":\\":
                    target_text = target_text[4:]
                target = Path(target_text)
                if target.is_absolute():
                    self._check_location(target)
                    resolved = Path(target.anchor)
                    pending.extendleft(reversed(target.parts[1:]))
                else:
                    pending.extendleft(reversed(target.parts))
            else:
                resolved = candidate
        return resolved
