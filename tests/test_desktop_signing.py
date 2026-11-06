"""Ad hoc macOS prereleases need no hosted credentials and seal the full bundle."""

import importlib
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def builder(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("build_desktop")


def test_ad_hoc_prerelease_does_not_enter_hosted_release_flow(builder, tmp_path, monkeypatch):
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    monkeypatch.setattr(builder.sys, "platform", "darwin")
    monkeypatch.setattr(builder.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(sys, "argv", ["build_desktop.py", "--signing-mode", "ad-hoc"])
    monkeypatch.setitem(builder.metadata, "resolve", lambda root: {"version": "2026.11.4+abcdef0"})
    monkeypatch.setitem(builder.metadata, "environment", lambda info: {})
    for name in ("TAURI_SIGNING_PRIVATE_KEY", "TAURI_SIGNING_PUBLIC_KEY", "OPENAIDR_RELEASE_DATE"):
        monkeypatch.delenv(name, raising=False)
    # An explicit ad hoc build must not inherit an Apple identity or notarize.
    for name in ("APPLE_SIGNING_IDENTITY", "APPLE_API_KEY", "APPLE_ID", "APPLE_PASSWORD"):
        monkeypatch.setenv(name, "unused-test-credential")
    configurations = []
    configure = builder.adhoc_macos_config

    def capture_config():
        configuration = configure()
        configurations.append(configuration)
        return configuration

    def hosted_release(*args, **kwargs):
        pytest.fail("Ad hoc prereleases must not require hosted updater configuration")

    class BuildStarted(Exception):
        pass

    def start_build(*args, **kwargs):
        raise BuildStarted

    monkeypatch.setattr(builder, "release_config", hosted_release)
    monkeypatch.setattr(builder, "adhoc_macos_config", capture_config)
    monkeypatch.setattr(builder, "run", start_build)
    with pytest.raises(BuildStarted):
        builder.main()
    assert configurations == [{"signingIdentity": "-", "hardenedRuntime": False}]
    assert all(name not in builder.os.environ
               for name in ("APPLE_SIGNING_IDENTITY", "APPLE_API_KEY", "APPLE_ID", "APPLE_PASSWORD"))


@pytest.mark.parametrize(("platform", "arguments", "message"), [
    ("darwin", ["--signing-mode", "developer-id"], "developer-id requires --release"),
    ("linux", ["--signing-mode", "ad-hoc"], "requires macOS"),
    ("darwin", ["--signing-mode", "ad-hoc", "--sidecar-only"], "complete application bundle"),
    ("darwin", ["--signing-mode", "ad-hoc", "--no-bundle"], "complete application bundle"),
])
def test_signing_mode_rejects_invalid_builds(builder, tmp_path, monkeypatch, capsys,
                                            platform, arguments, message):
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    monkeypatch.setattr(builder.sys, "platform", platform)
    monkeypatch.setattr(sys, "argv", ["build_desktop.py", *arguments])
    with pytest.raises(SystemExit) as error:
        builder.main()
    assert error.value.code == 2
    assert message in capsys.readouterr().err
    assert not (tmp_path / "build").exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="Needs native macOS codesign and disk images")
@pytest.mark.parametrize("tamper", [False, True], ids=["valid", "damaged-resource"])
def test_installer_checks_the_app_inside_the_dmg(builder, tmp_path, monkeypatch, tamper):
    monkeypatch.delenv("APPLE_SIGNING_IDENTITY", raising=False)
    app = tmp_path / "source/Test.app"
    contents = app / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    shutil.copy("/usr/bin/true", contents / "MacOS/test-app")
    (contents / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleExecutable": "test-app", "CFBundleIdentifier": "com.example.signing-test",
        "CFBundlePackageType": "APPL",
    }))
    (contents / "Resources").mkdir()
    payload = contents / "Resources/payload.txt"
    payload.write_text("original")
    # Model PyInstaller's individually signed binary in an unsealed framework.
    framework = contents / "Frameworks/Test.framework"
    version = framework / "Versions/A"
    (version / "Resources").mkdir(parents=True)
    shutil.copy("/usr/bin/true", version / "Test")
    (version / "Resources/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleExecutable": "Test", "CFBundleIdentifier": "com.example.test-framework",
        "CFBundlePackageType": "FMWK",
    }))
    (framework / "Versions/Current").symlink_to("A")
    (framework / "Test").symlink_to("Versions/Current/Test")
    (framework / "Resources").symlink_to("Versions/Current/Resources")
    builder.sign_macos_frameworks(contents)
    subprocess.run(["codesign", "--verify", "--deep", "--strict", framework], check=True)
    subprocess.run(["codesign", "--force", "--sign", "-", app], check=True)
    if tamper:
        payload.write_text("modified after signing")
    dmg = tmp_path / "test.dmg"
    subprocess.run(["hdiutil", "create", "-quiet", "-srcfolder", app.parent,
                    "-format", "UDZO", dmg], check=True)
    # Restore the loose app, so only verification inside the image can fail.
    payload.write_text("original")
    if tamper:
        with pytest.raises(subprocess.CalledProcessError) as error:
            builder.verify_macos_installer(app, dmg)
        assert error.value.cmd[0].endswith("codesign")
        assert str(app) not in error.value.cmd
    else:
        builder.verify_macos_installer(app, dmg)
    mounts = plistlib.loads(subprocess.check_output(["hdiutil", "info", "-plist"]))
    assert not any(image.get("image-path") == str(dmg) for image in mounts["images"])
