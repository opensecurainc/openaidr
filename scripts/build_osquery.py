"""Stage the pinned macOS osquery and frozen OpenAIDR extension for the sensor."""

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MAX_DOWNLOAD = 256 * 1024 * 1024


def download(pin, downloads):
    downloads.mkdir(parents=True, exist_ok=True)
    archive = downloads / pin["url"].rsplit("/", 1)[1]
    if not archive.exists():
        temporary = archive.with_suffix(".partial")
        try:
            with urllib.request.urlopen(pin["url"], timeout=60) as source:
                with temporary.open("wb") as destination:
                    size = 0
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_DOWNLOAD:
                            raise ValueError("osquery download exceeded the size limit")
                        destination.write(chunk)
            verify_checksum(temporary, pin["sha256"])
            temporary.replace(archive)
        finally:
            temporary.unlink(missing_ok=True)
    # Cached artifacts must pass the same check as a fresh download.
    verify_checksum(archive, pin["sha256"])
    return archive


def verify_checksum(path, expected):
    with path.open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if actual != expected:
        raise ValueError(f"osquery checksum mismatch: remove {path} and rebuild")


def extract_binary(archive, member, destination):
    with tarfile.open(archive, "r:gz") as bundle:
        matches = [item for item in bundle.getmembers() if item.name == member]
        if (
            len(matches) != 1
            or not matches[0].isfile()
            or not 0 < matches[0].size <= MAX_DOWNLOAD
        ):
            raise ValueError("osquery archive must contain one regular executable")
        with bundle.extractfile(matches[0]) as source, destination.open("wb") as output:
            shutil.copyfileobj(source, output)
    destination.chmod(0o755)


def stage_osquery(work, options=()):
    manifest = ROOT / "apps" / "desktop" / "osquery.lock.json"
    pin = json.loads(manifest.read_text())
    if (
        sys.platform != pin["platform"]
        or platform.machine() not in pin["architectures"]
    ):
        raise ValueError("The pinned osquery artifact requires an arm64 or x86_64 Mac")
    runtime = work / "osquery"
    runtime.mkdir(parents=True, exist_ok=True)
    archive = download(pin, work / "downloads")
    extract_binary(archive, pin["member"], runtime / "osqueryi")
    shutil.copy2(manifest, runtime / manifest.name)
    shutil.copytree(
        ROOT / "apps" / "desktop" / "licenses", runtime / "licenses", dirs_exist_ok=True
    )
    entry = work / "extension_entry.py"
    entry.write_text(
        "from openaidr.sensor.osquery_extension import main\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n"
    )
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        "openaidr-osquery.ext",
        "--paths",
        str(ROOT / "src"),
        "--add-data",
        f"{work / '_build.json'}{os.pathsep}openaidr",
        "--add-data",
        f"{next((work / 'package-metadata').glob('*.dist-info'))}{os.pathsep}{next((work / 'package-metadata').glob('*.dist-info')).name}",
        "--recursive-copy-metadata",
        "osquery",
        "--distpath",
        str(runtime),
        "--workpath",
        str(work / "extension-work"),
        "--specpath",
        str(work),
    ]
    if identity := os.environ.get("APPLE_SIGNING_IDENTITY"):
        command.extend(["--codesign-identity", identity])
    subprocess.run([*command, *options, str(entry)], cwd=ROOT, check=True)
    return runtime
