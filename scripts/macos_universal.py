#!/usr/bin/env python3
"""Prepare and verify universal (Apple Silicon and Intel) macOS desktop builds.

PyInstaller freezes a universal sensor only when the interpreter and every
native extension it collects contain both architectures. The official
python.org interpreter is universal2, but most dependencies publish separate
arm64 and x86_64 wheels, and pip on a current build host may select wheels that
require a newer macOS than the app supports. ``python scripts/macos_universal.py``
rebuilds each such installed native file from the arm64 and x86_64 wheels of
the same release that support the minimum macOS version, so the environment can
freeze with ``--target-arch universal2``.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import sysconfig
import tempfile
import zipfile

REQUIRED = ("arm64", "x86_64")
# Keep in sync with bundle.macOS.minimumSystemVersion in tauri.macos.conf.json.
MINIMUM_MACOS = (12, 0)
CPU_TYPES = {0x01000007: "x86_64", 0x0100000C: "arm64"}
THIN_MAGIC = {b"\xcf\xfa\xed\xfe": ("<", 32), b"\xfe\xed\xfa\xcf": (">", 32),
              b"\xce\xfa\xed\xfe": ("<", 28), b"\xfe\xed\xfa\xce": (">", 28)}
FAT_MAGIC = {b"\xca\xfe\xba\xbe": (">IIIII", 20), b"\xca\xfe\xba\xbf": (">IIQQII", 32)}
# Java class files share the 32-bit fat magic; their version field is large.
MAX_FAT_ARCHES = 30
LC_VERSION_MIN_MACOSX, LC_BUILD_VERSION, PLATFORM_MACOS = 0x24, 0x32, 1


def _version(encoded):
    return encoded >> 16, (encoded >> 8) & 0xFF


def _thin(stream, offset):
    """Return (architecture, minimum macOS) for the Mach-O image at offset."""
    stream.seek(offset)
    header = stream.read(32)
    if header[:4] not in THIN_MAGIC or len(header) < 28:
        return None
    order, size = THIN_MAGIC[header[:4]]
    cpu, _, _, count, commands = struct.unpack(order + "IIIII", header[4:24])
    stream.seek(offset + size)
    table = stream.read(commands)
    minimum, position = None, 0
    for _ in range(count):
        if position + 8 > len(table):
            break
        command, length = struct.unpack(order + "II", table[position:position + 8])
        if command == LC_BUILD_VERSION and position + 16 <= len(table):
            platform, encoded = struct.unpack(order + "II", table[position + 8:position + 16])
            if platform == PLATFORM_MACOS:
                minimum = _version(encoded)
        elif command == LC_VERSION_MIN_MACOSX and position + 12 <= len(table):
            minimum = _version(struct.unpack(order + "I", table[position + 8:position + 12])[0])
        if length < 8:
            break
        position += length
    return CPU_TYPES.get(cpu, f"cpu-{cpu:#x}"), minimum


def slices(path):
    """Return {architecture: minimum macOS or None} for a Mach-O file, or None."""
    with open(path, "rb") as stream:
        header = stream.read(8)
        if header[:4] in THIN_MAGIC:
            image = _thin(stream, 0)
            return None if image is None else dict([image])
        if header[:4] not in FAT_MAGIC or len(header) < 8:
            return None
        count, = struct.unpack(">I", header[4:8])
        if not 0 < count <= MAX_FAT_ARCHES:
            return None
        layout, size = FAT_MAGIC[header[:4]]
        table = stream.read(count * size)
        if len(table) != count * size:
            return None
        found = {}
        for index in range(count):
            offset = struct.unpack(layout, table[index * size:(index + 1) * size])[2]
            image = _thin(stream, offset)
            if image is None:
                return None
            found[image[0]] = image[1]
        return found


def architectures(path):
    found = slices(path)
    return None if found is None else frozenset(found)


def problems(path, minimum=MINIMUM_MACOS):
    """Describe why a Mach-O file is not universal for the minimum macOS, or None."""
    found = slices(path)
    if found is None:
        return None
    issues = [f"missing {arch}" for arch in REQUIRED if arch not in found]
    issues += [f"{arch} requires macOS {'.'.join(map(str, version))}"
               for arch, version in sorted(found.items()) if arch in REQUIRED and version and version > minimum]
    return issues or None


def noncompliant(paths, minimum=MINIMUM_MACOS):
    """Map each Mach-O file that is thin or too new to its problems."""
    result = {}
    for path in map(Path, paths):
        if path.is_symlink() or not path.is_file():
            continue
        if issues := problems(path, minimum):
            result[path] = issues
    return result


def require_universal(root, minimum=MINIMUM_MACOS):
    """Fail unless every Mach-O file under root runs on both Macs at the minimum macOS."""
    root = Path(root)
    found = noncompliant([root] if root.is_file() else sorted(root.rglob("*")), minimum)
    if found:
        listed = "\n".join(f"  {path}: {'; '.join(issues)}" for path, issues in sorted(found.items()))
        raise ValueError(
            f"Universal build for macOS {'.'.join(map(str, minimum))} contains incompatible Mach-O files:\n{listed}"
        )
    return root


def interpreter_files():
    """The running interpreter and, for framework builds, its shared library."""
    files = [Path(sys.executable).resolve()]
    prefix, library = sysconfig.get_config_var("PYTHONFRAMEWORKPREFIX"), sysconfig.get_config_var("LDLIBRARY")
    if prefix and library:
        files.append(Path(prefix) / library)
    elif library and sysconfig.get_config_var("LIBDIR"):
        files.append(Path(sysconfig.get_config_var("LIBDIR")) / library)
    return [path for path in files if path.is_file()]


def require_universal_interpreter():
    found = noncompliant(interpreter_files())
    if found:
        raise ValueError(
            "Universal macOS builds require a universal2 Python that supports macOS "
            f"{'.'.join(map(str, MINIMUM_MACOS))}, such as the python.org installer: "
            + "; ".join(f"{path}: {', '.join(issues)}" for path, issues in found.items())
        )


def platform_tags(arch, minimum=MINIMUM_MACOS):
    """Wheel platform tags pip may select for one architecture at the minimum macOS."""
    versions = [(10, minor) for minor in range(9, 16)] + [(major, 0) for major in range(11, minimum[0] + 1)]
    if arch == "arm64":
        versions = [version for version in versions if version >= (11, 0)]
    return [f"macosx_{major}_{minor}_{tag}" for major, minor in reversed(versions)
            if (major, minor) <= minimum for tag in (arch, "universal2")]


def download_wheel(dist, arch, directory):
    """Download the release wheel of an installed distribution for one architecture."""
    version = f"{sys.version_info.major}{sys.version_info.minor}"
    command = [sys.executable, "-m", "pip", "download", "--quiet", "--no-deps", "--only-binary=:all:",
               "--dest", str(directory), "--python-version", version, "--implementation", "cp",
               "--abi", f"cp{version}", "--abi", "abi3", "--abi", "none"]
    for tag in platform_tags(arch):
        command += ["--platform", tag]
    name = dist.metadata["Name"]
    try:
        subprocess.run([*command, f"{name}=={dist.version}"], check=True)
    except subprocess.CalledProcessError as error:
        raise ValueError(
            f"{name} {dist.version} has no {arch} wheel for macOS {'.'.join(map(str, MINIMUM_MACOS))}; "
            "pin a release that publishes one"
        ) from error
    wheels = list(Path(directory).glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError(f"Expected one {arch} wheel for {name} {dist.version}")
    return wheels[0]


def extract_slice(source, arch, destination):
    found = slices(source)
    if found is None or arch not in found:
        raise ValueError(f"{source} does not contain {arch}")
    if set(found) == {arch}:
        shutil.copyfile(source, destination)
    else:
        subprocess.run(["lipo", str(source), "-thin", arch, "-output", str(destination)], check=True)


def rebuild_distribution(dist, native, scratch):
    """Replace each native file with slices from the compatible arm64 and x86_64 wheels."""
    name = dist.metadata["Name"]
    recorded = {path: Path(str(file)).as_posix() for path, file in native.items()}
    extracted = {}
    for arch in REQUIRED:
        (scratch / arch / "wheel").mkdir(parents=True)
        wheel = download_wheel(dist, arch, scratch / arch / "wheel")
        with zipfile.ZipFile(wheel) as archive:
            members = set(archive.namelist())
            # A library present for only one architecture would be missing
            # from the other slice; refuse instead of shipping a broken import.
            extra = sorted(member for member in members
                           if member.endswith((".so", ".dylib")) and member not in recorded.values())
            if extra:
                raise ValueError(f"{name} {arch} wheel has native files the installed release lacks: {extra}")
            for member in recorded.values():
                if member not in members:
                    raise ValueError(f"{name} {arch} wheel lacks {member}")
                archive.extract(member, scratch / arch / "files")
        extracted[arch] = scratch / arch / "files"
    for path, member in recorded.items():
        parts = []
        for arch in REQUIRED:
            part = scratch / f"{len(parts)}-{path.name}.{arch}"
            extract_slice(extracted[arch] / member, arch, part)
            parts.append(part)
        merged = scratch / f"{path.name}.universal"
        subprocess.run(["lipo", "-create", *map(str, parts), "-output", str(merged)], check=True)
        mode = path.stat().st_mode
        os.replace(merged, path)
        path.chmod(mode)
    print(f"Rebuilt {len(recorded)} native files in {name} {dist.version} for arm64 and x86_64")
    return len(recorded)


def installed_native(dist):
    files = {Path(dist.locate_file(file)): file for file in dist.files or ()}
    return {path: file for path, file in files.items()
            if not path.is_symlink() and path.is_file() and slices(path) is not None}


def make_environment_universal():
    """Rebuild every installed distribution with a thin or too-new native file."""
    require_universal_interpreter()
    rebuilt = 0
    for dist in importlib.metadata.distributions():
        native = installed_native(dist)
        if not noncompliant(native):
            continue
        with tempfile.TemporaryDirectory(prefix="openaidr-universal-") as directory:
            rebuilt += rebuild_distribution(dist, native, Path(directory))
    remaining = {}
    for dist in importlib.metadata.distributions():
        remaining.update(noncompliant(installed_native(dist)))
    if remaining:
        raise ValueError("Native files remain incompatible: "
                         + "; ".join(f"{path}: {', '.join(issues)}" for path, issues in remaining.items()))
    print(f"Python environment is universal for macOS {'.'.join(map(str, MINIMUM_MACOS))} "
          f"({rebuilt} files rebuilt)")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", type=Path, metavar="PATH",
                        help="only verify every Mach-O file under PATH; do not change the environment")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("Universal macOS builds require macOS")
    try:
        if args.check:
            require_universal(args.check)
            print(f"Every Mach-O file under {args.check} supports arm64 and x86_64 on macOS "
                  f"{'.'.join(map(str, MINIMUM_MACOS))}")
        else:
            make_environment_universal()
    except (ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
