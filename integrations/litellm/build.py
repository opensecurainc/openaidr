#!/usr/bin/env python3
"""Package only OpenAIDR source. Never resolve or install LiteLLM dependencies."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import runpy
import tarfile

ROOT = Path(__file__).resolve().parents[2]


def package(destination):
    metadata = runpy.run_path(str(ROOT / "src/openaidr/build_info.py"))["resolve"](ROOT)
    files = {"openaidr_litellm/" + name: (Path(__file__).parent / name).read_bytes()
             for name in ("__init__.py", "handler.py")}
    for name in ("redact.py", "secret-redaction.yaml", "secret-redaction.LICENSE"):
        files["openaidr_litellm/" + name] = (ROOT / "packages/common/src/openaidr_common" / name).read_bytes()
    files["openaidr_litellm/_build.json"] = (json.dumps(metadata, indent=2) + "\n").encode()
    files["README.md"] = (ROOT / "docs/litellm-integration.md").read_bytes()
    destination.mkdir(parents=True, exist_ok=True)
    artifact = destination / f"openaidr-litellm-{metadata['version']}.tar.gz"
    with tarfile.open(artifact, "x:gz") as archive:
        for name, content in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(content), 0o644, metadata["source_timestamp"]
            archive.addfile(info, io.BytesIO(content))
    artifact.with_suffix(artifact.suffix + ".sha256").write_text(hashlib.sha256(artifact.read_bytes()).hexdigest() + "  " + artifact.name + "\n")
    return artifact


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/litellm")
    print(package(parser.parse_args().output))
