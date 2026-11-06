"""Bundle the reviewed client and shared helpers without a second implementation."""

import hashlib
import json
from pathlib import Path
import re
import shutil
import zipfile

from setuptools import setup


ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[1]
VENDOR = ROOT / "src/aidr/_vendor"
MANIFEST = REPOSITORY / "dependencies/api-runtime/manifest.json"


def write_source(name, content):
    target = VENDOR / name
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.suffix == ".py":
        # Relocate absolute imports only; keep the upstream client logic intact.
        content = re.sub(
            rb"(?m)^(\s*from )(openaidr_api_client|openaidr_common)(?=[ .])",
            rb"\1aidr._vendor.\2", content,
        )
    target.write_bytes(content)


if MANIFEST.is_file():
    sdk = json.loads(MANIFEST.read_text())["wheels"]["sdk"]
    wheel = REPOSITORY / "dependencies/api-runtime" / sdk["name"]
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != sdk["sha256"]:
        raise ValueError("The API client wheel does not match its reviewed checksum")
    if VENDOR.exists():
        shutil.rmtree(VENDOR)
    write_source("__init__.py", b'"""Bundled implementation details; use the aidr public interface."""\n')
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.startswith("openaidr_api_client/") and not name.endswith("/"):
                write_source(name, archive.read(name))
    common = REPOSITORY / "packages/common/src/openaidr_common"
    for path in common.iterdir():
        if path.is_file() and path.suffix in (".py", ".yaml", ".LICENSE"):
            write_source("openaidr_common/" + path.name, path.read_bytes())
    write_source("LICENSE", (REPOSITORY / "LICENSE").read_bytes())
    write_source("provenance.json", json.dumps({
        "sdk": sdk["name"], "sha256": sdk["sha256"],
        "common": "packages/common/src/openaidr_common",
        "changes": "Absolute imports relocated under aidr._vendor.",
    }, indent=2).encode() + b"\n")
elif not (VENDOR / "provenance.json").is_file():
    raise RuntimeError("Build aidr from the repository or its complete source distribution")


setup()
