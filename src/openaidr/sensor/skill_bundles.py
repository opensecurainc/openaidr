"""Capture installed skill directories without following bundled links."""

import base64
import os
from pathlib import Path
import stat
import time

from openaidr.core.skill_bundle import (
    MAX_FILES,
    MAX_FILE_BYTES,
    MAX_BUNDLE_BYTES,
    MAX_MANIFEST_BYTES,
    canonical,
    digest,
    validate_manifest,
    valid_path,
)
from .privacy import PrivacyGuard, PrivacySkip

PRIVATE_NAMES = {
    ".git",
    ".env",
    ".ssh",
    ".aws",
    ".kube",
    ".azure",
    ".gnupg",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    "credentials",
    "credentials.json",
    "id_rsa",
    "id_ed25519",
}


def capture(skill_path, cancelled=lambda: False):
    """Read through directory descriptors, anchored to one approved directory.

    Component inventory currently runs on macOS. Descriptor-relative opens also
    work on Linux; other platforms must not silently use weaker link checks.
    """
    if os.name != "posix":
        raise OSError("Skill bundle capture requires descriptor-relative file access")
    guard = PrivacyGuard()
    root = guard.check(Path(skill_path).parent)
    files, manifest, stamps = {}, [], []
    used, visited = 0, 0
    complete = True
    deadline = time.monotonic() + 15
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY

    def stamp(info):
        return (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def skip(path, reason):
        nonlocal complete
        complete = False
        if valid_path(path) and len(manifest) < MAX_FILES:
            manifest.append({"path": path, "skip": reason})

    def walk(fd, prefix="", depth=0):
        nonlocal used, complete, visited
        before = stamp(os.fstat(fd))
        stamps.append((prefix.rstrip("/"), before))
        # scandir is lazy, so a hostile directory cannot allocate an unbounded list.
        with os.scandir(fd) as entries:
            for entry in entries:
                if cancelled():
                    raise InterruptedError("Skill collection cancelled")
                if (
                    len(manifest) >= MAX_FILES
                    or visited >= 2048
                    or time.monotonic() >= deadline
                ):
                    complete = False
                    break
                visited += 1
                path = prefix + entry.name
                if not valid_path(path):
                    complete = False
                    continue
                name = entry.name.casefold()
                if (
                    name in PRIVATE_NAMES
                    or name.startswith(".env.")
                    or name.endswith((".pem", ".key", ".p12", ".pfx"))
                ):
                    skip(path, "privacy")
                    continue
                try:
                    if guard.macos:
                        # Use the cached mount/location policy before any child stat.
                        guard._check_location(root / path)
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        skip(path, "symlink")
                    elif stat.S_ISDIR(info.st_mode):
                        if depth >= 16:
                            skip(path, "collection_limit")
                            continue
                        child = os.open(entry.name, flags, dir_fd=fd)
                        try:
                            walk(child, path + "/", depth + 1)
                        finally:
                            os.close(child)
                    elif not stat.S_ISREG(info.st_mode):
                        skip(path, "special_file")
                    elif (
                        info.st_size > MAX_FILE_BYTES
                        or used + info.st_size > MAX_BUNDLE_BYTES
                    ):
                        skip(path, "size_limit")
                    else:
                        child = os.open(
                            entry.name,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=fd,
                        )
                        with os.fdopen(child, "rb") as stream:
                            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                                skip(path, "special_file")
                                continue
                            data = stream.read(MAX_FILE_BYTES + 1)
                            after = stamp(os.fstat(stream.fileno()))
                        if stamp(info) != after or len(data) != info.st_size:
                            skip(path, "changed")
                            continue
                        manifest.append(
                            {"path": path, "size": len(data), "sha256": digest(data)}
                        )
                        files[path] = base64.b64encode(data).decode("ascii")
                        used += len(data)
                        stamps.append((path, after))
                except PrivacySkip:
                    skip(path, "privacy")
                except OSError:
                    skip(path, "unreadable")
        if stamp(os.fstat(fd)) != before:
            complete = False

    # Walk the canonical absolute root with no-follow opens for every ancestor.
    fd = os.open("/", flags)
    try:
        for part in root.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        walk(fd)
        # Recheck each captured file through no-follow directory descriptors.
        for path, before in stamps:
            parent = os.dup(fd)
            try:
                parts = path.split("/")
                for part in parts[:-1]:
                    child = os.open(part, flags, dir_fd=parent)
                    os.close(parent)
                    parent = child
                current = (
                    os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                    if path
                    else os.fstat(parent)
                )
                if stamp(current) != before:
                    complete = False
            except OSError:
                complete = False
            finally:
                os.close(parent)
    finally:
        os.close(fd)
    result = {
        "version": 1,
        "complete": complete,
        "files": sorted(manifest, key=lambda f: f["path"]),
    }
    while len(canonical(result)) > MAX_MANIFEST_BYTES:
        removed = result["files"].pop()
        files.pop(removed["path"], None)
        result["complete"] = False
    bundle_hash, _ = validate_manifest(result)
    return {"manifest": result, "sha256": bundle_hash, "files": files}


def upload(client, snapshot, cancelled=lambda: False):
    for root in snapshot["roots"]:
        if root["source"] != "openaidr-skills":
            continue
        for component in root["components"]:
            if cancelled():
                return False
            try:
                bundle = capture(component["path"], cancelled)
            except OSError:
                if cancelled():
                    return False
                # Report unavailable coverage without exposing local exception text.
                manifest = {"version": 1, "complete": False, "files": []}
                bundle = {
                    "manifest": manifest,
                    "sha256": validate_manifest(manifest)[0],
                    "files": {},
                }
            request = {
                "reference": {
                    "source": root["source"],
                    "root": root["root"],
                    "key": component["key"],
                },
                "collected_at": snapshot["collected_at"],
                "manifest": bundle["manifest"],
                "sha256": bundle["sha256"],
            }
            if cancelled():
                return False
            reply = client.post("inventory/skills/manifest", request)
            if reply.get("needs_content"):
                if cancelled():
                    return False
                client.post(
                    "inventory/skills/content", {**request, "files": bundle["files"]}
                )
    return True
