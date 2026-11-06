import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

from openaidr.sensor import privacy
from openaidr.sensor import mcp_inventory, plugin_inventory, skill_inventory


@pytest.mark.skipif(sys.platform != "darwin", reason="Uses the macOS mount table")
def test_repeated_native_privacy_checks_have_bounded_memory(tmp_path):
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent("""
            import gc
            from pathlib import Path
            import sys
            import tracemalloc
            from openaidr.sensor.privacy import PrivacyGuard

            path = Path(sys.argv[1]).resolve()
            tracemalloc.start()
            # Warm native and pathlib caches before measuring sustained growth.
            for _ in range(2000):
                assert PrivacyGuard().check(path) == path
            gc.collect()
            before = tracemalloc.get_traced_memory()[0]
            for _ in range(2000):
                assert PrivacyGuard().check(path) == path
            gc.collect()
            retained = tracemalloc.get_traced_memory()[0] - before
            assert retained < 256 * 1024, f"Privacy checks retained {retained:,} bytes"
        """), str(tmp_path)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "path",
    [
        "/Volumes/Share/App.app",
        "/Network/Share/App.app",
        "/Users/alice/Desktop/file",
        "/Users/alice/Documents/file",
        "/Users/alice/downloads/file",
        "/Users/bob/Pictures/Photos.photoslibrary",
        "/Users/alice/Library/Mobile Documents/file",
        "/Users/alice/Library/CloudStorage/file",
        "/Users/alice/Library/Containers/app/file",
        "/Users/alice/Library/Group Containers/app/file",
        "/Users/alice/Library/Application Support/Google/Chrome/file",
        "/Users/alice/Library/Application Support/Claude/claude_desktop_config.json",
        "/Users/alice/Library/Application Scripts/com.example.app/file",
        "/Users/alice/Library/WebKit/com.example.app/file",
        "/Users/alice/Library/Preferences/com.example.app.plist",
        "/Users/alice/Library/Saved Application State/com.example.app/file",
        "/Library/Application Support/com.example.app/file",
        "/System/Volumes/Data/Users/alice/Documents/file",
        "/System/Volumes/Data/Volumes/Share/file",
    ],
)
def test_protected_paths_are_rejected_without_filesystem_probes(monkeypatch, path):
    monkeypatch.setattr(privacy.sys, "platform", "darwin")

    def unexpected(*args, **kwargs):
        raise AssertionError("Protected paths must be rejected before filesystem I/O")

    with monkeypatch.context() as patch:
        patch.setattr(os, "lstat", unexpected)
        patch.setattr(os, "stat", unexpected)
        with pytest.raises(privacy.PrivacySkip):
            privacy.PrivacyGuard().check(path)


def test_safe_links_work_but_protected_and_mounted_targets_are_not_probed(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(privacy.sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    safe = tmp_path / "safe"
    safe.mkdir()
    (safe / "file").touch()
    (tmp_path / "linked").symlink_to(safe)
    protected = tmp_path / "Documents"
    (tmp_path / "private-link").symlink_to(protected)
    mounted = tmp_path / "custom-mount"
    (tmp_path / "mount-link").symlink_to(mounted)
    monkeypatch.setattr(privacy, "_protected_mounts", lambda: [mounted])
    guard = privacy.PrivacyGuard()
    lstat = os.lstat

    def checked(path, *args, **kwargs):
        assert not any(Path(path).is_relative_to(p) for p in (protected, mounted))
        return lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", checked)
    assert guard.check(tmp_path / "linked/file") == safe / "file"
    for path in (
        tmp_path / "private-link/file",
        tmp_path / "mount-link/file",
        tmp_path / "private-link/../safe/file",
        mounted / "file",
    ):
        with pytest.raises(privacy.PrivacySkip):
            guard.check(path)


def test_unavailable_mount_table_skips_scans_and_other_platforms_are_unchanged(
    tmp_path, monkeypatch
):
    def unavailable():
        raise OSError("mount table unavailable")

    monkeypatch.setattr(privacy, "_protected_mounts", unavailable)
    monkeypatch.setattr(privacy.sys, "platform", "darwin")
    with pytest.raises(privacy.PrivacySkip, match="Mount information unavailable"):
        privacy.PrivacyGuard().check(tmp_path)
    monkeypatch.setattr(privacy.sys, "platform", "linux")
    assert privacy.PrivacyGuard().check(tmp_path) == tmp_path.resolve()


@pytest.mark.parametrize("kind", ["skill", "plugin", "mcp"])
@pytest.mark.parametrize(
    "folder",
    [
        "Documents",
        "Library/Containers/app",
        "Library/Application Support/Google/Chrome",
    ],
)
def test_extensions_keep_safe_metadata_and_skip_protected_targets(
    tmp_path, monkeypatch, kind, folder
):
    monkeypatch.setattr(privacy.sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    root = tmp_path / "inventory"
    root.mkdir()
    protected = tmp_path / folder
    if kind == "mcp":
        safe = root / "safe.json"
        safe.write_text('{"mcpServers": {"safe": {}}}')
        linked = root / "linked.json"
        linked.symlink_to(protected / "config.json")
        reader, column = mcp_inventory.mcp_rows, "path"
        paths = [safe, linked, protected / "config.json"]
    else:
        filename = "SKILL.md" if kind == "skill" else ".claude-plugin/plugin.json"
        manifest = root / "safe" / filename
        manifest.parent.mkdir(parents=True)
        manifest.write_text(
            "---\nname: safe\n---\n" if kind == "skill" else '{"name": "safe"}'
        )
        (root / "linked").symlink_to(protected)
        linked_manifest = root / "linked-file" / filename
        linked_manifest.parent.mkdir(parents=True)
        linked_manifest.symlink_to(protected / "manifest")
        reader = (
            skill_inventory.skill_rows
            if kind == "skill"
            else plugin_inventory.plugin_rows
        )
        column, paths = "directory", [root, protected]
    lstat = os.lstat

    def checked(path, *args, **kwargs):
        assert not Path(path).is_relative_to(protected)
        return lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", checked)
    rows = reader(
        {
            "constraints": [
                {"name": column, "list": [{"op": 2, "expr": str(p)} for p in paths]}
            ]
        }
    )
    assert [r["name"] for r in rows if r["record"] == "component"] == ["safe"]
    coverage = [r for r in rows if r["record"] == "coverage"]
    assert coverage[0]["status"] == ("ok" if kind == "mcp" else "partial")
    assert all(r["status"] == "unavailable" for r in coverage[1:])
