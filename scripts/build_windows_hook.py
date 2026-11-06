"""Build the small Windows hook executable with the selected source identity."""

import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def verify_runtime_dependencies(executable):
    from PyInstaller.depend.bindepend import get_imports

    shared = sorted(name for name, _ in get_imports(str(executable))
                    if name.lower().startswith(("vcruntime", "msvcp", "msvcr", "concrt", "vcomp")))
    if shared:
        raise ValueError(f"Native Windows hook requires external Visual C++ runtime DLLs: {', '.join(shared)}")


def build(destination, info, *, target_dir):
    destination = Path(destination)
    cargo = shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo")
    env = {**os.environ, "OPENAIDR_HOOK_BUILD_INFO": json.dumps(info)}
    # Hooks run outside the Python runtime and on PCs without a VC++ install.
    # Cargo gives encoded flags precedence over RUSTFLAGS; preserve either form.
    if "CARGO_ENCODED_RUSTFLAGS" in env:
        flags = env["CARGO_ENCODED_RUSTFLAGS"]
        env["CARGO_ENCODED_RUSTFLAGS"] = (flags + "\x1f" if flags else "") + "-Ctarget-feature=+crt-static"
    else:
        env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -Ctarget-feature=+crt-static").strip()
    subprocess.run([
        cargo, "build", "--release", "--locked", "--manifest-path",
        str(ROOT / "packages/windows-hook/Cargo.toml"), "--target-dir", str(target_dir),
    ], check=True, env=env)
    executable = Path(target_dir) / "release/openaidr-hook.exe"
    verify_runtime_dependencies(executable)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(executable, destination)
    if json.loads(subprocess.check_output([destination, "build-info"], text=True)) != info:
        raise ValueError("Native Windows hook build metadata differs from the selected source")
    return destination
