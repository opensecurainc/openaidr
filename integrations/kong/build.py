#!/usr/bin/env python3
"""Package the Kong plugin with the repository's canonical source identity."""

import argparse
import io
import json
from pathlib import Path
import runpy
import tarfile

import yaml

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = Path(__file__).parent / "kong/plugins/openaidr"


def package(destination):
    metadata = runpy.run_path(str(ROOT / "src/openaidr/build_info.py"))["resolve"](ROOT)
    rules = yaml.safe_load((ROOT / "packages/common/src/openaidr_common/secret-redaction.yaml").read_text())
    # Validate the rule schema and expressions through the existing implementation.
    redactor = runpy.run_path(str(ROOT / "packages/common/src/openaidr_common/redact.py"))["_REDACTOR"]
    assert len(redactor.patterns) == len(rules["patterns"])
    destination.mkdir(parents=True, exist_ok=True)
    artifact = destination / f"openaidr-kong-{metadata['version']}.tar.gz"
    files = {f"kong/plugins/openaidr/{p.name}": p.read_bytes() for p in PLUGIN.glob("*.lua")}
    files["kong/plugins/openaidr/version.lua"] = (
        "return " + json.dumps(metadata["version"]) + "\n"
    ).encode()
    # JSON is parsed by Kong's existing cjson dependency, with no YAML runtime.
    encoded_rules = json.dumps(rules, separators=(",", ":"))
    files["kong/plugins/openaidr/rules.lua"] = (
        "return require('cjson').decode([====[" + encoded_rules + "]====])\n"
    ).encode()
    files["_build.json"] = (json.dumps(metadata, indent=2) + "\n").encode()
    files["README.md"] = (ROOT / "docs/kong-integration.md").read_bytes()
    files["secret-redaction.LICENSE"] = (ROOT / "packages/common/src/openaidr_common/secret-redaction.LICENSE").read_bytes()
    with tarfile.open(artifact, "x:gz") as archive:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o644, metadata["source_timestamp"]
            archive.addfile(info, io.BytesIO(data))
    return artifact


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/kong")
    args = parser.parse_args()
    print(package(args.output))
