#!/usr/bin/env python3
"""Prepare local Compose credentials and immutable source build metadata."""
import argparse
import os
from pathlib import Path
import runpy
import secrets
import sys
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]


def free_device_id():
    if sys.platform == "darwin":
        directory = Path.home() / "Library/Application Support/OpenAIDR"
    elif sys.platform == "win32":
        directory = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "OpenAIDR"
    else:
        directory = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "openaidr"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "free-device-id"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return str(UUID(path.read_text().strip()))
    value = str(uuid4())
    with os.fdopen(fd, "w") as stream:
        stream.write(value + "\n")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["configure"])
    args = parser.parse_args()
    try:
        info = runpy.run_path(str(ROOT / "src/openaidr/build_info.py"))["resolve"](ROOT)
    except ValueError as error:
        print("build identity: " + str(error), file=sys.stderr)
        if not (ROOT / ".git").exists():
            print(
                "This copy has no Git history, so the build identity must be supplied. Set\n"
                "OPENAIDR_BUILD_COMMIT to the full source commit SHA and OPENAIDR_COMMIT_TIMESTAMP\n"
                "to that commit's committer time as a Unix epoch. Both are shown on the GitHub\n"
                "release this copy came from; on a Git checkout `git show -s --format='%H %ct'`\n"
                "prints them. A clone made with `git clone` needs neither variable.",
                file=sys.stderr,
            )
        sys.exit(1)
    target = ROOT / ".env"
    current = target.read_text() if target.exists() else ""
    lines = [line for line in current.splitlines() if not line.startswith(("OPENAIDR_BUILD_COMMIT=", "OPENAIDR_COMMIT_TIMESTAMP="))]
    if not current:
        lines.extend(["POSTGRES_PASSWORD=" + secrets.token_hex(24), "OPENAIDR_ADMIN_PASSWORD=" + secrets.token_urlsafe(24),
                      "OPENAIDR_ADMIN_EMAIL=admin@localhost", "OPENAIDR_PUBLIC_URL=http://localhost:8080",
                      "OPENAIDR_FREE_INSTALLATION_ID=" + str(uuid4()),
                      "OPENAIDR_FREE_DEVICE_ID=" + free_device_id(),
                      "OPENAIDR_FREE_SECRET=" + secrets.token_urlsafe(32)])
    lines.extend(["OPENAIDR_BUILD_COMMIT=" + info["source_commit"], "OPENAIDR_COMMIT_TIMESTAMP=" + str(info["source_timestamp"])])
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write("\n".join(lines) + "\n")
    print("Configured " + str(target) + ". The admin password is in this file.")


if __name__ == "__main__":
    main()
