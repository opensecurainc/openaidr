#!/usr/bin/env python3
"""Verify the public SDK and common wheels without private release credentials."""

import argparse
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path
import zipfile


PACKAGES = {"sdk": ("openaidr-api-client", "openaidr_api_client"),
            "common": ("openaidr-common", "openaidr_common")}


def verify(directory):
    if any(not p.is_file() or p.is_symlink() for p in directory.iterdir()):
        raise ValueError("Dependency directory must contain regular files")
    return verify_files({p.name: p.read_bytes() for p in directory.iterdir()})


def verify_files(files):
    record = json.loads(files["manifest.json"])
    if set(record) != {"schema_version", "wheels"} or record["schema_version"] != 1 or set(record["wheels"]) != set(PACKAGES):
        raise ValueError("Expected the public SDK and common artifact manifest")
    expected = {"manifest.json"}
    for role, (distribution, namespace) in PACKAGES.items():
        pin = record["wheels"][role]
        if set(pin) != {"distribution", "name", "sha256", "size", "source"}:
            raise ValueError("Unexpected public dependency metadata")
        name = pin["name"]
        if Path(name).name != name or not name.endswith(".whl") or name in expected:
            raise ValueError("Invalid public dependency filename")
        expected.add(name)
        data = files[name]
        if pin["distribution"] != distribution or len(data) != pin["size"] or hashlib.sha256(data).hexdigest() != pin["sha256"]:
            raise ValueError("Artifact checksum or distribution mismatch: " + name)
        with zipfile.ZipFile(io.BytesIO(data)) as wheel:
            names = wheel.namelist()
            if len(names) != len(set(names)) or any(Path(n).is_absolute() or ".." in Path(n).parts for n in names):
                raise ValueError("Unsafe wheel members: " + name)
            metadata = [n for n in names if n.endswith(".dist-info/METADATA")]
            if len(metadata) != 1:
                raise ValueError("Ambiguous wheel metadata: " + name)
            info = BytesParser().parsebytes(wheel.read(metadata[0]))
            if info["Name"] != distribution or info["Version"] != pin["source"]["version"]:
                raise ValueError("Wheel identity mismatch: " + name)
            build = json.loads(wheel.read(namespace + "/_build.json"))
            if set(pin["source"]) != {"version", "source_commit", "source_timestamp", "built_at"} or any(
                    build.get(key) != value for key, value in pin["source"].items()):
                raise ValueError("Wheel source identity mismatch: " + name)
            allowed = {namespace, metadata[0].split("/", 1)[0]}
            if {n.split("/", 1)[0] for n in names} - allowed:
                raise ValueError("Wheel contains a foreign namespace: " + name)
    if set(files) != expected:
        raise ValueError("Dependency directory must contain exactly the public manifest and its wheels")
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", default=Path(__file__).resolve().parents[1] / "dependencies/api-runtime")
    args = parser.parse_args()
    verify(args.directory)
    print("Public dependency checksums, namespaces, and source identities verified")
