"""Universal macOS test builds: architecture and minimum macOS checks."""

import importlib.util
import json
from pathlib import Path
import struct
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("macos_universal", ROOT / "scripts/macos_universal.py")
universal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(universal)

ARM64, X86_64 = 0x0100000C, 0x01000007


def version(major, minor):
    return major << 16 | minor << 8


def image(cpu, minimum=(12, 0), command="build"):
    if command == "build":
        load = struct.pack("<IIIIII", 0x32, 24, 1, version(*minimum), version(15, 0), 0)
    elif command == "legacy":
        load = struct.pack("<IIII", 0x24, 16, version(*minimum), version(15, 0))
    else:
        load = struct.pack("<II", 0x19, 8)
    return b"\xcf\xfa\xed\xfe" + struct.pack("<iiIIIII", cpu, 0, 2, 1, len(load), 0, 0) + load


def fat(*images):
    header = b"\xca\xfe\xba\xbe" + struct.pack(">I", len(images))
    body, offset = b"", 4096
    for item in images:
        cpu = struct.unpack("<i", item[4:8])[0]
        header += struct.pack(">IIIII", cpu, 0, offset, len(item), 12)
        body += item.ljust(4096, b"\0")
        offset += 4096
    return header.ljust(4096, b"\0") + body


@pytest.mark.parametrize(("content", "expected", "issues"), [
    (fat(image(ARM64, (11, 0)), image(X86_64, (10, 13), "legacy")), {"arm64": (11, 0), "x86_64": (10, 13)}, None),
    (fat(image(ARM64, (12, 0)), image(X86_64, (12, 0))), {"arm64": (12, 0), "x86_64": (12, 0)}, None),
    (image(ARM64, (11, 0)), {"arm64": (11, 0)}, ["missing x86_64"]),
    (image(X86_64, (10, 9), "legacy"), {"x86_64": (10, 9)}, ["missing arm64"]),
    # A dependency wheel pip selected on a newer build host.
    (fat(image(ARM64, (14, 0)), image(X86_64, (10, 12))), {"arm64": (14, 0), "x86_64": (10, 12)},
     ["arm64 requires macOS 14.0"]),
    (fat(image(ARM64, (12, 1)), image(X86_64, (13, 0))), {"arm64": (12, 1), "x86_64": (13, 0)},
     ["arm64 requires macOS 12.1", "x86_64 requires macOS 13.0"]),
    # Without a version command, the loader's own default applies.
    (fat(image(ARM64, command=None), image(X86_64, command=None)), {"arm64": None, "x86_64": None}, None),
    # A Java class file shares the 32-bit fat magic.
    (b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"\0" * 64, None, None),
    (b"#!/bin/sh\nexit 0\n", None, None),
    (b"", None, None),
], ids=["fat-legacy-x86", "fat-at-minimum", "thin-arm64", "thin-x86_64", "arm64-too-new",
        "both-too-new", "no-version-command", "java-class", "script", "empty"])
def test_reads_architectures_and_minimum_macos(tmp_path, content, expected, issues):
    path = tmp_path / "binary"
    path.write_bytes(content)
    assert universal.slices(path) == expected
    assert universal.problems(path) == issues


def test_require_universal_lists_each_incompatible_file(tmp_path):
    (tmp_path / "Contents/MacOS").mkdir(parents=True)
    (tmp_path / "Contents/MacOS/ok").write_bytes(fat(image(ARM64), image(X86_64)))
    (tmp_path / "Contents/MacOS/data.json").write_text("{}")
    universal.require_universal(tmp_path)
    (tmp_path / "Contents/MacOS/thin.so").write_bytes(image(ARM64))
    (tmp_path / "Contents/MacOS/new.so").write_bytes(fat(image(ARM64, (15, 0)), image(X86_64)))
    with pytest.raises(ValueError) as error:
        universal.require_universal(tmp_path)
    message = str(error.value)
    assert "thin.so: missing x86_64" in message
    assert "new.so: arm64 requires macOS 15.0" in message
    assert "/ok:" not in message.replace("\\", "/")


def test_wheel_tags_never_exceed_the_minimum_macos():
    for arch in universal.REQUIRED:
        tags = universal.platform_tags(arch)
        assert tags and all(tag.endswith((f"_{arch}", "_universal2")) for tag in tags)
        versions = {tuple(map(int, tag.split("_")[1:3])) for tag in tags}
        assert max(versions) == universal.MINIMUM_MACOS
        assert min(versions) == ((11, 0) if arch == "arm64" else (10, 9))


def test_minimum_macos_matches_the_app_bundle():
    config = json.loads((ROOT / "apps/desktop/src-tauri/tauri.macos.conf.json").read_text())
    declared = tuple(map(int, config["bundle"]["macOS"]["minimumSystemVersion"].split(".")))
    assert declared == universal.MINIMUM_MACOS


@pytest.mark.parametrize(("platform", "machine", "arguments", "message"), [
    ("darwin", "arm64", ["--e2e-ui"], "complete app and DMG"),
    ("darwin", "arm64", ["--no-bundle"], "complete app and DMG"),
    ("darwin", "arm64", [], "universal2 Python"),
    ("darwin", "x86_64", [], "Intel builds are not supported"),
    ("linux", "x86_64", [], "--macos-universal requires macOS"),
])
def test_universal_build_checks_host_before_preparing_files(tmp_path, monkeypatch, capsys,
                                                            platform, machine, arguments, message):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    build = importlib.import_module("build_desktop")
    monkeypatch.setattr(build, "ROOT", tmp_path)
    monkeypatch.setattr(build.sys, "platform", platform)
    monkeypatch.setattr(build.platform, "machine", lambda: machine)
    monkeypatch.setattr(build.macos_universal, "interpreter_files", lambda: [tmp_path / "python"])
    (tmp_path / "python").write_bytes(image(ARM64))
    monkeypatch.setattr(sys, "argv", ["build_desktop.py", "--macos-universal", *arguments])
    monkeypatch.delenv("APPLE_SIGNING_IDENTITY", raising=False)
    with pytest.raises(SystemExit) as error:
        build.main()
    assert error.value.code == 2
    assert message in capsys.readouterr().err
    assert not (tmp_path / "build").exists()
