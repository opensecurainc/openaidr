"""Check desktop source inputs before running platform-specific builds."""

from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tomllib

import pytest
import yaml

from openaidr.sensor.config import windows_base_dir
from openaidr.sensor import windows_runtime


ROOT = Path(__file__).resolve().parents[1]


def test_notification_plugin_versions_match_across_javascript_and_rust():
    javascript = yaml.safe_load((ROOT / "pnpm-lock.yaml").read_text())
    rust = tomllib.loads((ROOT / "apps/desktop/src-tauri/Cargo.lock").read_text())
    javascript_version = javascript["importers"]["apps/desktop"]["dependencies"]["@tauri-apps/plugin-notification"]["version"]
    rust_version = next(package["version"] for package in rust["package"]
                        if package["name"] == "tauri-plugin-notification")
    assert javascript_version.split(".")[:2] == rust_version.split(".")[:2]


def test_desktop_builder_offers_the_unsigned_local_options(tmp_path):
    script = ROOT / "scripts/build_desktop.py"
    result = subprocess.run([sys.executable, str(script), "--help"], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    for option in ("--sidecar-only", "--no-bundle", "--simulation", "--bundle-only"):
        assert option in result.stdout


def test_native_desktop_source_inputs_are_complete():
    native = ROOT / "apps/desktop/src-tauri"
    manifest = tomllib.loads((native / "Cargo.toml").read_text())
    missing = []
    for target in manifest.get("test", []):
        path = native / target.get("path", f"tests/{target['name']}.rs")
        if not path.is_file():
            missing.append(str(path.relative_to(ROOT)))
    # Check every platform, including modules excluded by the host's Rust cfg.
    references = re.compile(
        r'#\[path\s*=\s*"([^"]+)"\]|include(?:_str|_bytes)?!\(\s*"([^"]+)"'
    )
    for source in [*native.glob("*.rs"), *native.joinpath("src").rglob("*.rs"),
                   *native.joinpath("tests").rglob("*.rs")]:
        text = source.read_text()
        for module, resource in references.findall(text):
            path = source.parent / (module or resource)
            if not path.is_file():
                missing.append(f"{source.relative_to(ROOT)}: {module or resource}")
        for resource in re.findall(
            r'include(?:_str|_bytes)?!\(\s*concat!\(\s*env!\("CARGO_MANIFEST_DIR"\),\s*"([^"]+)"', text
        ):
            if not Path(str(native) + resource).is_file():
                missing.append(f"{source.relative_to(ROOT)}: {resource}")
    assert not missing, "Missing desktop source inputs:\n" + "\n".join(sorted(missing))
    # The macOS build merges its generated version into this source plist.
    with (native / "Info.plist").open("rb") as stream:
        assert plistlib.load(stream)["LSUIElement"] is True


@pytest.mark.parametrize("layout", ["fresh", "legacy", "current", "conflicting"])
def test_windows_configuration_and_runtime_use_the_exported_layout(tmp_path, layout):
    environ = {"LOCALAPPDATA": str(tmp_path), "ProgramData": str(tmp_path / "machine")}
    legacy = tmp_path / "OpenAIDR Sensor"
    current = tmp_path / "OpenAIDR/data"
    for directory, selected in [(legacy, ("legacy", "conflicting")),
                                (current, ("current", "conflicting"))]:
        if layout in selected:
            directory.mkdir(parents=True)
            (directory / "sensor.yaml").write_text("sensor_id: retained-device\n")
    if layout == "conflicting":
        for resolve in (windows_base_dir, windows_runtime.root):
            with pytest.raises(ValueError, match="Both Windows configurations exist"):
                resolve(environ)
        assert (legacy / "sensor.yaml").is_file()
        assert (current / "sensor.yaml").is_file()
    else:
        expected = legacy if layout == "legacy" else current
        assert windows_base_dir(environ) == expected
        assert windows_runtime.root(environ) == expected / "runtime"
