#!/usr/bin/env python3
"""Reproduce the desktop's pinned public-runtime archive from a GitHub tarball."""
import argparse
import gzip
import hashlib
import io
from pathlib import Path
import tarfile

from check_publication import check_file

SOURCE = "ade7e73ea7b5661f41598e3026688ed5cb4ab60b"
ROOT_FILES = {"pyproject.toml", "setup.py", "MANIFEST.in", "README.md", "LICENSE", "compose.yaml",
              ".dockerignore", "package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml"}
PREFIXES = ("src/", "dependencies/api-runtime/", "packages/ui/", "apps/dashboard/",
            "apps/desktop/package.json", "deploy/server.Dockerfile", "deploy/dashboard.Dockerfile",
            "scripts/local_bootstrap.py", "scripts/build-version.", "scripts/build_version.py",
            "scripts/sync-agent-icons.")


def bundle(source_path, output_path, commit=SOURCE):
    output = io.BytesIO()
    with tarfile.open(source_path) as source:
        members = []
        for member in source:
            root, _, name = member.name.partition("/")
            if not root.endswith(commit):
                raise ValueError("Source archive does not match the pinned commit")
            if (member.isfile() and name != "src/openaidr/sensor/local_runtime_source.tar.gz"
                    and (name in ROOT_FILES or name.startswith(PREFIXES))):
                if Path(name).is_absolute() or ".." in Path(name).parts:
                    raise ValueError("Invalid source path")
                check_file(name, source.extractfile(member).read())
                members.append((name, member))
        with gzip.GzipFile(filename="local_runtime_source.tar", mode="wb", fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name, member in sorted(members):
                    clean = tarfile.TarInfo(name)
                    clean.size = member.size
                    clean.mode = 0o755 if member.mode & 0o111 else 0o644
                    archive.addfile(clean, source.extractfile(member))
    data = output.getvalue()
    check_file("local_runtime_source.tar.gz", data)
    output_path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(bundle(args.source, args.output))


if __name__ == "__main__":
    main()
