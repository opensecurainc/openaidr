#!/usr/bin/env python3
"""Freeze the sensor and stage the host-native optional Tauri desktop bundle."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import runpy
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

from build_osquery import stage_osquery
from build_version import metadata
import macos_universal

ROOT = Path(__file__).resolve().parents[1]
DESKTOP = ROOT / "apps" / "desktop"
# Tauri compiles one app for each slice and combines them under this target.
UNIVERSAL_TARGET = "universal-apple-darwin"
UNIVERSAL_SLICES = ("aarch64-apple-darwin", "x86_64-apple-darwin")
# Release channels and their update verification keys under deploy/desktop.
# build.rs compiles the same selection into the app.
RELEASE_CHANNELS = {"openaidr": "updater.pub", "openaidr-oss": "updater-oss.pub"}
macos_runtime = runpy.run_path(str(ROOT / "src/openaidr/sensor/macos_runtime.py"))


def run(args, cwd=ROOT, env=None):
    args = [str(arg) for arg in args]
    # Windows resolves npm only through its .cmd shim on PATH.
    args[0] = shutil.which(args[0]) or args[0]
    subprocess.run(args, cwd=cwd, check=True, env=env)


def release_channel():
    """Return the release channel for this build; the enterprise channel is the default."""
    channel = os.environ.get("OPENAIDR_RELEASE_CHANNEL", "openaidr")
    if channel not in RELEASE_CHANNELS:
        raise ValueError("Unknown OPENAIDR_RELEASE_CHANNEL; use openaidr or openaidr-oss")
    return channel


def release_feed(channel):
    return f"https://releases.opensecura.ai/{channel}/rollout-v2.json"


def updater_public_key(channel):
    path = ROOT / "deploy" / "desktop" / RELEASE_CHANNELS[channel]
    if not path.is_file():
        raise ValueError(f"The {channel} release channel requires deploy/desktop/{RELEASE_CHANNELS[channel]}")
    return path


def adhoc_macos_config():
    # PyInstaller uses ad hoc signing when no identity is supplied. Passing
    # '-' explicitly enables hardened runtime and breaks its Python loader.
    for name in (
        "APPLE_SIGNING_IDENTITY", "APPLE_CERTIFICATE", "APPLE_CERTIFICATE_PASSWORD",
        "APPLE_ID", "APPLE_PASSWORD", "APPLE_TEAM_ID", "APPLE_API_KEY",
        "APPLE_API_ISSUER", "APPLE_API_KEY_PATH", "APPLE_API_PRIVATE_KEY",
    ):
        os.environ.pop(name, None)
    return {"signingIdentity": "-", "hardenedRuntime": False}


def release_config(work, signing_mode="developer-id", *, bundle=True):
    """Require distribution credentials before starting an expensive release build."""
    if sys.platform == "win32":
        version = json.loads((work / "_build.json").read_text())["version"]
        run([sys.executable, ROOT / "scripts/desktop_release.py", "check", "--version", version])
        channel = release_channel()
        public = base64.b64encode(updater_public_key(channel).read_bytes()).decode("ascii")
        if bundle and not os.environ.get("TAURI_SIGNING_PRIVATE_KEY", "").strip():
            raise ValueError("Missing release settings: TAURI_SIGNING_PRIVATE_KEY")
        if not os.environ.get("OPENAIDR_RELEASE_DATE"):
            raise ValueError("Release builds require OPENAIDR_RELEASE_DATE, reserved once for this publication")
        config = work / "release.conf.json"
        config.write_text(json.dumps({
            "bundle": {"createUpdaterArtifacts": bundle},
            "plugins": {"updater": {"pubkey": public,
                "endpoints": [release_feed(channel)],
                "windows": {"installMode": "quiet"}}},
        }))
        return config
    if sys.platform != "darwin":
        raise ValueError("Desktop releases must be built natively on a supported platform")
    if signing_mode not in ("ad-hoc", "developer-id"):
        raise ValueError("Unknown release signing mode")
    required = ("TAURI_SIGNING_PRIVATE_KEY", "TAURI_SIGNING_PUBLIC_KEY")
    if signing_mode == "developer-id":
        required += (
            "APPLE_SIGNING_IDENTITY", "APPLE_API_KEY", "APPLE_API_ISSUER",
            "APPLE_API_KEY_PATH",
        )
    missing = [name for name in required if not os.environ.get(name, "").strip()]
    if missing:
        raise ValueError("Missing release settings: " + ", ".join(missing))
    if signing_mode == "developer-id":
        if os.environ["APPLE_SIGNING_IDENTITY"].strip() == "-":
            raise ValueError("developer-id requires an Apple signing identity; use ad-hoc for '-'")
        if not Path(os.environ["APPLE_API_KEY_PATH"]).is_file():
            raise ValueError("APPLE_API_KEY_PATH must point to the notarization key file")
    version = json.loads((work / "_build.json").read_text())["version"]
    run([sys.executable, ROOT / "scripts/desktop_release.py", "check", "--version", version])
    if not os.environ.get("OPENAIDR_RELEASE_DATE"):
        raise ValueError("Release builds require OPENAIDR_RELEASE_DATE, reserved once for this publication")
    channel = release_channel()
    bundle = {"createUpdaterArtifacts": True}
    if signing_mode == "ad-hoc":
        bundle["macOS"] = adhoc_macos_config()
    config = work / "release.conf.json"
    config.write_text(json.dumps({
        "bundle": bundle,
        "plugins": {"updater": {
            "pubkey": os.environ["TAURI_SIGNING_PUBLIC_KEY"].strip(),
            "endpoints": [release_feed(channel)],
        }},
    }))
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--edition", choices=("standard", "enterprise"),
        default=os.environ.get("OPENAIDR_DESKTOP_EDITION", "standard"),
        help="Enterprise requires organization enrollment and omits personal and local runtime setup",
    )
    parser.add_argument(
        "--sidecar-only",
        action="store_true",
        help="Stage only the sensor executable for cargo test or desktop development",
    )
    parser.add_argument(
        "--no-bundle",
        action="store_true",
        help="Compile the desktop executable without producing installers",
    )
    parser.add_argument(
        "--release", action="store_true",
        help="Require release versions and credentials; create signed updater archives",
    )
    parser.add_argument("--simulation", action="store_true", help="Include local device simulation controls in a development build")
    parser.add_argument("--e2e-ui", action="store_true", help="Include macOS WebDriver for disposable hosted E2E tests")
    parser.add_argument(
        "--macos-universal", action="store_true",
        help="Build one app and DMG for Apple Silicon and Intel Macs on macOS 12 or later, "
             "signed when combined with --release; run scripts/macos_universal.py first",
    )
    parser.add_argument(
        "--signing-mode", choices=("ad-hoc", "developer-id"),
        help="macOS signing mode; ad-hoc needs no Apple credentials, developer-id requires --release",
    )
    parser.add_argument(
        "--windows-sign", action="store_true",
        help="Authenticode-sign the Windows sensor runtime, app, and installer with Artifact Signing",
    )
    parser.add_argument(
        "--bundle-only", action="store_true",
        help="Windows: package the sensor runtime and desktop executable a --no-bundle build staged",
    )
    args = parser.parse_args()
    if args.edition not in ("standard", "enterprise"):
        parser.error("OPENAIDR_DESKTOP_EDITION must be standard or enterprise")
    os.environ["OPENAIDR_DESKTOP_EDITION"] = args.edition
    if args.macos_universal:
        if sys.platform != "darwin":
            parser.error("--macos-universal requires macOS")
        if args.e2e_ui or args.no_bundle:
            parser.error("--macos-universal builds a complete app and DMG; it cannot be combined with "
                         "--e2e-ui or --no-bundle")
    if args.e2e_ui and (sys.platform != "darwin" or args.release or args.simulation or args.bundle_only):
        parser.error("--e2e-ui requires an unsigned macOS test build and cannot be combined with release or simulation")
    if args.bundle_only:
        if os.name != "nt":
            parser.error("--bundle-only requires a native Windows build")
        if args.sidecar_only or args.no_bundle or args.simulation:
            parser.error("--bundle-only requires a complete application bundle")
    if args.windows_sign:
        if os.name != "nt":
            parser.error("--windows-sign requires a native Windows build")
        if args.sidecar_only or args.no_bundle:
            parser.error("--windows-sign requires a complete installer")
        if not args.release:
            parser.error("--windows-sign requires --release to enable in-app updates")
        # Fail before the build when the signing tools or settings are missing.
        # Imported only here: other platforms' build images omit Windows tools.
        global sign_windows
        import sign_windows
        try:
            sign_windows.settings()
        except ValueError as error:
            parser.error(str(error))
    if args.simulation and args.release:
        parser.error("--simulation cannot be included in a desktop release")
    if args.release and (args.sidecar_only or (args.no_bundle and os.name != "nt")):
        parser.error("--release requires a complete application bundle")
    if args.release and os.name == "nt" and not args.no_bundle and not args.windows_sign:
        parser.error("Windows release installers require --windows-sign")
    if args.signing_mode == "developer-id" and not args.release:
        parser.error("--signing-mode developer-id requires --release")
    if args.signing_mode and sys.platform != "darwin":
        parser.error("--signing-mode requires macOS")
    if args.signing_mode and (args.sidecar_only or args.no_bundle):
        parser.error("--signing-mode requires a complete application bundle")
    if (sys.platform == "darwin" and not args.release
            and args.signing_mode != "ad-hoc"
            and not (args.sidecar_only or args.no_bundle)
            and os.environ.get("APPLE_SIGNING_IDENTITY", "").strip() not in {"", "-"}):
        parser.error("macOS signed installers require --release to enable in-app updates; "
                     "unset APPLE_SIGNING_IDENTITY for a development build")
    if sys.platform == "darwin" and platform.machine() != "arm64":
        parser.error("OpenAIDR for macOS requires native Apple Silicon Python and Rust; Intel builds are not supported")
    if args.macos_universal:
        try:
            macos_universal.require_universal_interpreter()
        except ValueError as error:
            parser.error(str(error))
    work = ROOT / "build" / "desktop"
    work.mkdir(parents=True, exist_ok=True)
    info = metadata["resolve"](ROOT)
    if args.bundle_only:
        runtime = DESKTOP / "src-tauri" / "binaries" / WINDOWS_RUNTIME
        info = windows_package_build(runtime, info)
    os.environ.update(metadata["environment"](info))
    os.environ["OPENAIDR_PYTHON"] = sys.executable
    (work / "_build.json").write_text(json.dumps(info) + "\n")
    config = work / "build.conf.json"
    settings = {"version": info["version"], "bundle": {"resources": {str(work / "_build.json"): "build.json"}}}
    if sys.platform == "darwin":
        native = info["version"].split("+")[0]
        plist = work / "Info.plist"
        plist.write_bytes(plistlib.dumps({
            **plistlib.loads((DESKTOP / "src-tauri/Info.plist").read_bytes()),
            "CFBundleShortVersionString": native, "CFBundleVersion": native,
            "OpenAIDRVersion": info["version"], "OpenAIDRBuild": info,
            "OpenAIDRIdentityMigration": 1,
        }))
        settings["bundle"]["macOS"] = {"infoPlist": str(plist), "bundleVersion": native}
        if args.signing_mode == "ad-hoc" and not args.release:
            settings["bundle"]["macOS"].update(adhoc_macos_config())
    if args.release:
        release = json.loads(release_config(work, args.signing_mode or "developer-id", bundle=not args.no_bundle).read_text())
        if "macOS" in release["bundle"]:
            settings["bundle"].setdefault("macOS", {}).update(release["bundle"].pop("macOS"))
        settings["bundle"].update(release["bundle"])
        settings["plugins"] = release["plugins"]
    if args.bundle_only:
        # Runs no build tooling and none of the build's executables: the signing
        # job trusts only this checkout and pinned tools, never earlier outputs
        # beyond the runtime files and desktop executable it packages.
        runtime = DESKTOP / "src-tauri" / "binaries" / WINDOWS_RUNTIME
        app = DESKTOP / "src-tauri" / "target" / "release" / "openaidr-desktop.exe"
        if not (runtime / "openaidr.exe").is_file() or not app.is_file():
            raise ValueError("--bundle-only needs the staged sensor runtime and desktop executable")
        finish_windows_runtime(runtime, info, sign=args.windows_sign)
        package(args, work, settings, config, info)
        return
    # Package metadata comes from the same source as the frozen modules, even
    # when this interpreter has an older editable installation.
    package_metadata = work / "package-metadata"
    shutil.rmtree(package_metadata, ignore_errors=True)
    with tempfile.TemporaryDirectory(dir=work) as wheels:
        run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", wheels, ROOT])
        wheel, = Path(wheels).glob("*.whl")
        with zipfile.ZipFile(wheel) as archive:
            for member in archive.namelist():
                if ".dist-info/" in member:
                    archive.extract(member, package_metadata)
    rustc = shutil.which("rustc") or str(Path.home() / ".cargo/bin/rustc")
    target = subprocess.check_output(
        [rustc, "--print", "host-tuple"], text=True
    ).strip()
    if sys.platform == "darwin" and target != "aarch64-apple-darwin":
        parser.error("OpenAIDR for macOS requires the native Apple Silicon Rust toolchain")
    runtime_options = []
    # PyInstaller rejects any collected binary that lacks either architecture.
    architecture = ["--target-arch", "universal2"] if args.macos_universal else []
    if sys.platform == "darwin":
        runtime = stage_osquery(work, architecture)
        if args.macos_universal:
            macos_universal.require_universal(runtime)
        runtime_options = [
            "--add-binary",
            f"{runtime / 'osqueryi'}{os.pathsep}osquery",
            "--add-binary",
            f"{runtime / 'openaidr-osquery.ext'}{os.pathsep}osquery",
            "--add-data",
            f"{runtime / 'osquery.lock.json'}{os.pathsep}osquery",
            "--add-data",
            f"{runtime / 'licenses'}{os.pathsep}osquery/licenses",
        ]
        if identity := os.environ.get("APPLE_SIGNING_IDENTITY"):
            runtime_options.extend(["--codesign-identity", identity])
    entry = work / "sensor_entry.py"
    entry.write_text(
        "import multiprocessing\nif __name__ == '__main__':\n"
        "    multiprocessing.freeze_support()\n"
        "    from openaidr.sensor.cli import main\n    raise SystemExit(main())\n"
    )
    windows = os.name == "nt"
    if sys.platform == "linux":
        run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
             "--distpath", work / "dist", "--workpath", work / "work/linux-sensor",
             ROOT / "scripts/linux_sensor.spec"])
    elif not windows:
        # Hooks must not extract the sensor and bundled inventory tools inside
        # their two-second deadline. The service stages this unpacked runtime
        # once; it uses the same CLI and forwarding code as the main sensor.
        signing = (["--codesign-identity", os.environ["APPLE_SIGNING_IDENTITY"]]
                   if sys.platform == "darwin" and os.environ.get("APPLE_SIGNING_IDENTITY") else []) + architecture
        freeze(work, entry, "openaidr-sensor", signing, onedir=True)
        hook_client = work / "dist/openaidr-sensor"
        if args.macos_universal:
            # The archive below hides these files from the final bundle check.
            macos_universal.require_universal(hook_client)
        if json.loads(subprocess.check_output([hook_client / "openaidr-sensor", "build-info"], text=True)) != info:
            raise ValueError("Hook runtime build metadata does not match the selected source")
        (hook_client / "build.json").write_text(json.dumps(info))
        # Keep the inner runtime's library paths and signatures unchanged by
        # the outer freezer. Extract this archive only during hook setup.
        archive = work / "hook-client.tar"
        with tarfile.open(archive, "w") as output:
            output.add(hook_client, arcname=".")
        runtime_options += ["--add-data", f"{archive}{os.pathsep}."]
    macos = sys.platform == "darwin"
    if macos:
        # Each artifact gets its own immutable support directory, including
        # rebuilds of the same source with different signed library bytes.
        runtime_name = "openaidr-runtime-" + secrets.token_hex(32)
        runtime_options += ["--contents-directory", runtime_name, *architecture]
    # Directory builds avoid extracting the full runtime on every invocation.
    if sys.platform != "linux":
        freeze(work, entry, "openaidr", runtime_options, onedir=windows or macos)
    if windows:
        from build_windows_hook import build as build_hook

        build_hook(work / "dist/openaidr/openaidr-hook.exe", info,
                   target_dir=work / "windows-hook-target")
        # The per-user Scheduled Task runs a windowless build so no console
        # window opens at logon; hooks and the CLI keep the console build.
        service_entry = work / "sensor_service_entry.py"
        # Policy matching runs in worker processes, which the frozen service
        # starts as itself; freeze_support turns those starts into workers.
        service_entry.write_text(
            "import multiprocessing\nif __name__ == '__main__':\n"
            "    multiprocessing.freeze_support()\n"
            "    from openaidr.sensor.windows_task import service_main\n"
            "    raise SystemExit(service_main())\n"
        )
        freeze(work, service_entry, "openaidr-service", runtime_options, windowed=True, onedir=True)
    extension = ".exe" if windows else ""
    sensor = work / "dist" / (f"openaidr/openaidr{extension}" if windows or macos else "openaidr")
    if sys.platform == "darwin":
        # Check with the frozen sensor's selected version. Source imports use
        # the default short SHA even when the release retains a longer prefix.
        run([sensor, "osquery-check"])
    run([sensor, "version"])
    if json.loads(subprocess.check_output([sensor, "build-info"], text=True)) != info:
        raise ValueError("Frozen sensor build metadata does not match the selected source")
    if args.macos_universal:
        macos_universal.require_universal(sensor.parent)
        verify_intel_slice(sensor, info)
    binaries = DESKTOP / "src-tauri" / "binaries"
    binaries.mkdir(parents=True, exist_ok=True)
    if macos:
        contents = work / "macos-contents"
        runtime_manifest = stage_macos_runtime(sensor, runtime_name, binaries, contents)
        # Mapping the parent tree preserves its Frameworks symlink. Mapping
        # the symlink itself makes the bundler follow and duplicate its target.
        settings["bundle"]["macOS"]["files"] = {".": str(contents)}
    if windows:
        runtime = stage_windows_runtime(work / "dist", binaries / WINDOWS_RUNTIME)
        finish_windows_runtime(runtime, info, sign=args.windows_sign)
        print(f"Staged sensor runtime: {runtime}")
    else:
        # Old signed updaters require a regular file at the legacy path.
        # Stage both copies before Tauri signs and packages the application.
        # Universal builds compile each slice with its own Cargo target, and
        # every one of those builds requires the sidecar under its name.
        targets = (*UNIVERSAL_SLICES, UNIVERSAL_TARGET) if args.macos_universal else (target,)
        for name in ("openaidr", "openaidr-sensor"):
            for staged_target in targets:
                destination = binaries / f"{name}-{staged_target}{extension}"
                shutil.copy2(sensor, destination)
                print(f"Staged executable: {destination}")
                if macos:
                    verify_macos_sensor(destination, info, runtime_manifest)
    if args.sidecar_only:
        return
    package(args, work, settings, config, info)
    if macos:
        cargo = shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo")
        cargo_metadata = json.loads(subprocess.check_output(
            [cargo, "metadata", "--format-version", "1", "--no-deps"],
            cwd=DESKTOP / "src-tauri", text=True,
        ))
        output = Path(cargo_metadata["target_directory"])
        output = output / UNIVERSAL_TARGET / "release" if args.macos_universal else output / "release"
        if args.no_bundle:
            for name in ("openaidr", "openaidr-sensor"):
                verify_macos_sensor(output / name, info, runtime_manifest)
            return
        bundle = output / "bundle"
        app = bundle / "macos/OpenAIDR.app"
        if args.release and args.signing_mode != "ad-hoc":
            run([sys.executable, ROOT / "scripts/macos_stapler.py", "stapler", "validate", app])
        packaged = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        if packaged.get("OpenAIDRVersion") != info["version"] or packaged.get("OpenAIDRBuild") != info:
            raise ValueError("Packaged app build metadata does not match the selected source")
        if any(packaged.get(key) != native for key in ("CFBundleShortVersionString", "CFBundleVersion")):
            raise ValueError("Packaged app native versions do not match the source date")
        if json.loads((app / "Contents/Resources/build.json").read_text()) != info:
            raise ValueError("Packaged app resources do not match the selected source")
        for name in ("openaidr", "openaidr-sensor"):
            executable = app / "Contents/MacOS" / name
            verify_macos_sensor(executable, info, runtime_manifest)
            run([executable, "osquery-check"])
            if args.macos_universal:
                verify_intel_slice(executable, info)
        if args.macos_universal:
            macos_universal.require_universal(app)
        suffix = "universal" if args.macos_universal else "aarch64"
        dmg = bundle / "dmg" / f"OpenAIDR_{info['version']}_{suffix}.dmg"
        if not dmg.is_file():
            raise ValueError("Installer filename does not contain the canonical version")
        if args.release or args.signing_mode:
            verify_macos_installer(app, dmg)
        print(f"Built installer: {dmg}")


def verify_macos_installer(app, dmg):
    """Check the completed bundle and the copy users receive inside the DMG."""
    run(["codesign", "--verify", "--deep", "--strict", app])
    run(["hdiutil", "verify", dmg])
    with tempfile.TemporaryDirectory(prefix="openaidr-dmg-") as directory:
        mount = Path(directory) / "volume"
        mount.mkdir()
        run(["hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", mount, dmg])
        try:
            run(["codesign", "--verify", "--deep", "--strict", mount / app.name])
        finally:
            run(["hdiutil", "detach", mount])


def package(args, work, settings, config, info):
    """Generate icons and Tauri settings, then build or, with --bundle-only, bundle."""
    # Bundling runs only Tauri's own CLI; dependency install scripts never run.
    selection = ["--filter", "openaidr-desktop...", "--fail-if-no-match"] if sys.platform in {"win32", "linux"} else []
    run(["pnpm", *selection, "install", "--frozen-lockfile", *(["--ignore-scripts"] if args.bundle_only else [])])
    generated_icons = work / "icons"
    run(
        [
            "pnpm",
            "exec",
            "tauri",
            "icon",
            "public/icon.svg",
            "--output",
            generated_icons,
        ],
        DESKTOP,
    )
    settings["bundle"]["icon"] = [str(generated_icons / name) for name in ("icon.png", "icon.icns", "icon.ico")]
    if args.windows_sign:
        # The installer runs this script before the app's first start. Bundle a
        # signed copy in place of the checked-in one, leaving the source unchanged.
        script = work / "signed" / "harden-installation.ps1"
        script.parent.mkdir(exist_ok=True)
        shutil.copy2(DESKTOP / "src-tauri/windows/harden-installation.ps1", script)
        sign_windows.sign([script], keep_vendor=False)
        settings["bundle"]["resources"].update({"windows/harden-installation.ps1": None,
                                                str(script): "harden-installation.ps1"})
        # Tauri runs this for the app executable, the uninstaller, and the installer.
        settings["bundle"]["windows"] = {"signCommand": {
            "cmd": sys.executable, "args": [str(ROOT / "scripts/sign_windows.py"), "%1"],
        }}
    config.write_text(json.dumps(settings))
    command = ["pnpm", "exec", "tauri", "bundle" if args.bundle_only else "build"]
    if args.simulation:
        command.extend(["--features", "simulation"])
    if args.e2e_ui:
        command.extend(["--features", "e2e-ui"])
    if args.macos_universal:
        command.extend(["--target", UNIVERSAL_TARGET])
    command.extend(["--config", config])
    if args.no_bundle:
        command.append("--no-bundle")
    universal = None
    if args.macos_universal:
        # build.rs accepts the Intel slice only inside a universal build, and
        # both slices compile for the app's minimum macOS version.
        universal = {**os.environ, "OPENAIDR_MACOS_UNIVERSAL": "1",
                     "MACOSX_DEPLOYMENT_TARGET": ".".join(map(str, macos_universal.MINIMUM_MACOS))}
    if sys.platform == "darwin" and args.release and args.signing_mode != "ad-hoc":
        # Tauri 2.12 ignores stapler's exit status. Attach and validate the
        # ticket during its stapling call, before it creates the DMG/archive.
        with tempfile.TemporaryDirectory(prefix="openaidr-stapler-") as directory:
            shim = Path(directory) / "xcrun"
            shim.write_text(
                "#!/bin/sh\nexec " + shlex.join([
                    sys.executable, str(ROOT / "scripts/macos_stapler.py"),
                ]) + ' "$@"\n'
            )
            shim.chmod(0o700)
            environment = universal or os.environ
            run(command, DESKTOP, env={**environment, "PATH": directory + os.pathsep + environment["PATH"]})
    elif universal:
        run(command, DESKTOP, env=universal)
    elif sys.platform == "linux":
        # AppImage build tools must also work in CI and containers without FUSE.
        run(command, DESKTOP, env={**os.environ, "APPIMAGE_EXTRACT_AND_RUN": "1"})
    else:
        run(command, DESKTOP)

WINDOWS_RUNTIME = "openaidr-runtime"


def windows_package_build(runtime, selected):
    """Preserve the compiled build time while checking the signer's release selection."""
    info = metadata["validate"](json.loads((runtime / "runtime.json").read_text())["build"])
    if info.get("desktop_edition", "standard") != selected.get("desktop_edition", "standard"):
        raise ValueError("The staged Windows runtime uses a different desktop edition")
    for field in ("version", "source_commit", "source_timestamp", "published_at", "publication_timestamp"):
        required = field in ("version", "source_commit", "source_timestamp")
        if info.get(field) != selected.get(field) or (required and info.get(field) is None):
            raise ValueError("Windows binaries differ from the selected release")
    return info


def stage_macos_runtime(sensor, name, binaries, contents):
    """Inventory signed support bytes and prepare flat and app bundle layouts."""
    directory = sensor.parent / name
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("The frozen macOS support directory must be a real directory")
    entries = {}
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory).as_posix()
        if relative == "runtime.json":
            continue
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            entry = {"kind": "symlink", "target": os.readlink(path)}
        elif stat.S_ISDIR(mode):
            entry = {"kind": "directory"}
        elif stat.S_ISREG(mode):
            with path.open("rb") as stream:
                entry = {"kind": "file", "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}
        else:
            raise ValueError(f"Unsupported file in the frozen macOS runtime: {path}")
        entries[relative] = entry
    manifest = {"schema": 1, "name": name, "entries": entries}
    (directory / "runtime.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    runtime = macos_runtime["inspect"](sensor)
    if runtime is None or runtime.manifest != manifest:
        raise ValueError("The frozen sensor does not identify its macOS runtime")
    macos_runtime["stage"](runtime, binaries)
    shutil.rmtree(contents, ignore_errors=True)
    resources = contents / "Resources"
    macos_runtime["stage"](runtime, resources)
    (contents / "Frameworks").symlink_to(f"Resources/{name}")
    return manifest


def verify_intel_slice(executable, info):
    """Run the x86_64 slice through Rosetta, as an Intel Mac runs it natively."""
    intel = ["arch", "-x86_64", str(executable)]
    try:
        version = subprocess.check_output([*intel, "version"], text=True).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError(f"Cannot run the Intel slice of {executable.name}; install Rosetta 2 with "
                         "softwareupdate --install-rosetta --agree-to-license") from error
    if version != f"openaidr {info['version']}":
        raise ValueError(f"Intel slice of {executable.name} has a different version")
    if json.loads(subprocess.check_output([*intel, "build-info"], text=True)) != info:
        raise ValueError(f"Intel slice of {executable.name} does not match the selected source")
    run([*intel, "osquery-check"])


def verify_macos_sensor(executable, info, manifest):
    if executable.is_symlink() or not executable.is_file():
        raise ValueError(f"Packaged executable {executable.name} must be a regular file")
    runtime = macos_runtime["inspect"](executable)
    if runtime is None or runtime.manifest != manifest:
        raise ValueError(f"Packaged executable {executable.name} has a different runtime")
    if subprocess.check_output([executable, "version"], text=True).strip() != f"openaidr {info['version']}":
        raise ValueError(f"Packaged executable {executable.name} has a different version")
    if json.loads(subprocess.check_output([executable, "build-info"], text=True)) != info:
        raise ValueError(f"Packaged executable {executable.name} does not match the selected source")


# Compatibility aliases: byte-identical copies under the earlier names.
WINDOWS_ALIASES = (("openaidr.exe", "openaidr-sensor.exe"),
                   ("openaidr-service.exe", "openaidr-sensor-service.exe"))


def stage_windows_runtime(dist, runtime):
    """One runtime directory for the desktop bundle.

    The windowless service executable shares the console build's support
    files, as ADR's does.
    """
    if runtime.exists():
        shutil.rmtree(runtime)
    shutil.copytree(dist / "openaidr", runtime)
    shutil.copy2(
        dist / "openaidr-service" / "openaidr-service.exe",
        runtime / "openaidr-service.exe",
    )
    return runtime


def finish_windows_runtime(runtime, info, sign=False):
    """Sign the runtime when requested, add its aliases, and write its manifest.

    runtime.json names the directory the sensor is staged to per user, so
    every build gets its own. Signing happens before the digest, so the name
    identifies the signed files that are installed. The version and build
    come from the selected source, which the frozen sensor was checked
    against, so packaging never runs the sensor.
    """
    manifest = runtime / "runtime.json"
    manifest.unlink(missing_ok=True)
    for _, legacy in WINDOWS_ALIASES:
        (runtime / legacy).unlink(missing_ok=True)
    if sign:
        signed = sign_windows.sign(sign_windows.tree(runtime))
        print(f"Signed {len(signed)} sensor runtime files")
    # Copy the completed signatures too, so compatibility aliases have the same
    # signed bytes instead of receiving separate Authenticode timestamps.
    for canonical, legacy in WINDOWS_ALIASES:
        shutil.copy2(runtime / canonical, runtime / legacy)
    digest = hashlib.sha256()
    for path in sorted(p for p in runtime.rglob("*") if p.is_file()):
        digest.update(path.relative_to(runtime).as_posix().encode() + b"\0")
        digest.update(path.read_bytes())
    manifest.write_text(json.dumps(
        {"name": f"{info['version']}-{digest.hexdigest()[:12]}", "version": info["version"], "build": info}
    ))


def freeze(work, entry, name, runtime_options, windowed=False, onedir=False):
    run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onedir" if onedir else "--onefile",
            *(["--windowed"] if windowed else []),
            "--name",
            name,
            "--paths",
            ROOT / "src",
            "--add-data",
            f"{work / '_build.json'}{os.pathsep}openaidr",
            "--add-data",
            f"{next((work / 'package-metadata').glob('*.dist-info'))}{os.pathsep}{next((work / 'package-metadata').glob('*.dist-info')).name}",
            "--collect-data",
            "openaidr_common",
            "--hidden-import",
            "tzdata",
            "--add-data",
            f"{ROOT / 'src' / 'openaidr' / 'sensor' / 'hook_opencode.js'}{os.pathsep}openaidr/sensor",
            *([] if os.environ.get("OPENAIDR_DESKTOP_EDITION") == "enterprise" else [
                "--add-data",
                f"{ROOT / 'src' / 'openaidr' / 'sensor' / 'local_runtime_source.tar.gz'}{os.pathsep}openaidr/sensor",
            ]),
            "--add-data",
            f"{ROOT / 'src' / 'openaidr' / 'sensor' / 'cowork_plugin_client.py'}{os.pathsep}openaidr/sensor",
            "--collect-submodules",
            "opentelemetry.proto",
            "--collect-submodules",
            "google.protobuf",
            "--distpath",
            work / "dist",
            "--workpath",
            work / "work" / name,
            "--specpath",
            work,
            *runtime_options,
            entry,
        ]
    )
    if sys.platform == "darwin" and onedir:
        sign_macos_frameworks(work / "dist" / name)


def sign_macos_frameworks(directory):
    """Seal complete frameworks before archiving or inventorying their bytes."""
    identity = os.environ.get("APPLE_SIGNING_IDENTITY") or "-"
    # PyInstaller signs individual binaries but its onedir output does not
    # seal framework resources. Apple also validates the archived hook client.
    frameworks = sorted(directory.rglob("*.framework"), key=lambda path: len(path.parts), reverse=True)
    for framework in frameworks:
        if framework.is_symlink():
            continue
        options = ["--timestamp", "--options", "runtime"] if identity != "-" else []
        run(["codesign", "--force", "--sign", identity, *options, framework])
        run(["codesign", "--verify", "--strict", framework])


if __name__ == "__main__":
    main()
