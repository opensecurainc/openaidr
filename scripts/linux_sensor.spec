"""Build both Linux sensor layouts from one dependency analysis."""

import json
from pathlib import Path
import subprocess
import tarfile

from PyInstaller.utils.hooks import collect_data_files, collect_submodules


root = Path(SPECPATH).parent
work = Path(DISTPATH).parent
metadata = next((work / "package-metadata").glob("*.dist-info"))
info = json.loads((work / "_build.json").read_text())
analysis = Analysis(
    [str(work / "sensor_entry.py")],
    pathex=[str(root / "src")],
    datas=[
        (str(work / "_build.json"), "openaidr"),
        (str(metadata), metadata.name),
        (str(root / "src/openaidr/sensor/hook_opencode.js"), "openaidr/sensor"),
        *([] if info.get("desktop_edition") == "enterprise" else [
            (str(root / "src/openaidr/sensor/local_runtime_source.tar.gz"), "openaidr/sensor"),
        ]),
        (str(root / "src/openaidr/sensor/cowork_plugin_client.py"), "openaidr/sensor"),
        *collect_data_files("openaidr_common"),
    ],
    hiddenimports=["tzdata", *collect_submodules("opentelemetry.proto"), *collect_submodules("google.protobuf")],
)
modules = PYZ(analysis.pure)
hook = EXE(modules, analysis.scripts, [], exclude_binaries=True,
           name="openaidr-sensor", strip=True, upx=True, console=True)
COLLECT(hook, analysis.binaries, analysis.datas, strip=True, upx=True, name="openaidr-sensor")

# Hooks use the unpacked runtime to stay within the native decision deadline.
# Preserve the same archive and staging contract as the other POSIX builds.
hook_client = Path(DISTPATH) / "openaidr-sensor"
actual = json.loads(subprocess.check_output([hook_client / "openaidr-sensor", "build-info"], text=True))
if actual != info:
    raise ValueError("Hook runtime build metadata does not match the selected source")
(hook_client / "build.json").write_text(json.dumps(info))
archive = work / "hook-client.tar"
with tarfile.open(archive, "w") as output:
    output.add(hook_client, arcname=".")

EXE(modules, analysis.scripts, analysis.binaries, analysis.datas,
    [("hook-client.tar", str(archive), "DATA")], name="openaidr", strip=True, upx=True, console=True)
