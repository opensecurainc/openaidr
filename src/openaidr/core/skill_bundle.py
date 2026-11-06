"""Versioned, bounded skill snapshots shared by sensors and scan workers."""

import base64
import hashlib
import json
import re
from pathlib import PurePosixPath

MAX_FILES = 256
MAX_FILE_BYTES = 1 << 20
MAX_BUNDLE_BYTES = 4 << 20
MAX_MANIFEST_BYTES = 128 << 10
SKIPS = {
    "privacy",
    "symlink",
    "size_limit",
    "unreadable",
    "special_file",
    "changed",
    "collection_limit",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def valid_path(value):
    return (
        isinstance(value, str)
        and 0 < len(value) <= 1024
        and not any(ord(c) < 32 or ord(c) == 127 or c in "\\:" for c in value)
        and not value.startswith("/")
        and all(p not in ("", ".", "..") for p in value.split("/"))
    )


def validate_manifest(manifest):
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"version", "complete", "files"}
        or type(manifest["version"]) is not int
        or manifest["version"] != 1
        or type(manifest["complete"]) is not bool
        or not isinstance(manifest["files"], list)
        or len(manifest["files"]) > MAX_FILES
        or len(canonical(manifest)) > MAX_MANIFEST_BYTES
    ):
        raise ValueError("Invalid skill manifest")
    paths, total, skipped = set(), 0, False
    for item in manifest["files"]:
        if not isinstance(item, dict) or not valid_path(item.get("path")):
            raise ValueError("Invalid skill file path")
        path = item["path"]
        if path in paths:
            raise ValueError("Duplicate skill file path")
        paths.add(path)
        if "skip" in item:
            if set(item) != {"path", "skip"} or item["skip"] not in SKIPS:
                raise ValueError("Invalid collection omission")
            skipped = True
        elif (
            set(item) != {"path", "size", "sha256"}
            or type(item["size"]) is not int
            or not 0 <= item["size"] <= MAX_FILE_BYTES
            or not isinstance(item["sha256"], str)
            or not re.fullmatch("[0-9a-f]{64}", item["sha256"])
        ):
            raise ValueError("Invalid skill file metadata")
        else:
            total += item["size"]
    if total > MAX_BUNDLE_BYTES or skipped and manifest["complete"]:
        raise ValueError("Invalid skill bundle coverage or size")
    if any(
        str(parent) in paths
        for path in paths
        for parent in PurePosixPath(path).parents
        if str(parent) != "."
    ):
        raise ValueError("Conflicting skill file paths")
    if manifest["files"] != sorted(manifest["files"], key=lambda f: f["path"]):
        raise ValueError("Skill manifest must be sorted")
    return digest(canonical(manifest)), total


def validate_files(manifest, files):
    validate_manifest(manifest)
    included = {f["path"]: f for f in manifest["files"] if "skip" not in f}
    if not isinstance(files, dict) or set(files) != set(included):
        raise ValueError("Skill content does not match manifest")
    decoded = {}
    for path, item in included.items():
        encoded = files[path]
        if not isinstance(encoded, str) or len(encoded) > 4 * (
            (MAX_FILE_BYTES + 2) // 3
        ):
            raise ValueError("Invalid skill file content")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, UnicodeError):
            raise ValueError("Invalid skill file encoding") from None
        if len(data) != item["size"] or digest(data) != item["sha256"]:
            raise ValueError("Skill content hash mismatch")
        decoded[path] = data
    return decoded
