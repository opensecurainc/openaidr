import json
import os
from pathlib import Path
import shutil
from unittest.mock import Mock

import pytest

from openaidr.sensor import (
    component_inventory as inventory,
    plugin_inventory as plugins,
    skill_inventory as skills,
)
from openaidr.server.component_inventory import validate_snapshot

SENSOR = "b8c94c3e-8ecf-4734-939c-1a44b43cae49"


def manifest(path, data=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    if data is None:
        data = {"name": "example", "version": "1.0"}
    path.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
    return path


def query(*paths, source="openaidr-plugins"):
    collect = skills.skill_rows if source == "openaidr-skills" else plugins.plugin_rows
    return collect(
        {
            "constraints": [
                {
                    "name": "directory",
                    "list": [{"op": 2, "expr": str(p)} for p in paths],
                }
            ]
        }
    )


def snapshot(monkeypatch, *paths, previous=()):
    monkeypatch.setattr(inventory.sys, "platform", "darwin")
    monkeypatch.setattr(
        inventory,
        "inventory_rows",
        lambda source, paths, **kw: [
            {**r, "identifier": r["name"]} for r in query(*paths, source=source)
        ],
    )
    options = inventory.settings(
        {
            "inventory": {
                "components": {
                    "include_default_roots": False,
                    "plugin_roots": list(map(str, paths)),
                }
            }
        }
    )
    result = inventory.collect_inventory(options, previous)
    validate_snapshot(SENSOR, result)
    return result


def test_formats_metadata_privacy_and_stable_identity(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "plugins"
    paths = [
        manifest(root / f"host-{i}" / marker / "plugin.json")
        for i, marker in enumerate(plugins.MANIFEST_DIRS)
    ]
    portable = manifest(
        root / "portable/plugin.json",
        {
            "$schema": plugins.PORTABLE_SCHEMA,
            "name": "example",
            "version": "2.0",
            "description": "Fixture plugin",
            "author": {
                "name": "Example",
                "email": "private-email",
                "url": "private-url",
            },
            "license": "MIT",
            "repository": "https://github.com/example/plugin",
            "homepage": "https://example.com/private-homepage",
            "extensions": {"com.openai": {"token": "private-token"}},
            "hooks": {"command": f"touch {root / 'executed'}"},
            "mcpServers": {"docs": {"env": {"TOKEN": "private-env"}}},
            "metadata": {"tools": ["private-tool"], "integrity": "private-integrity"},
        },
    )
    # Portable core metadata takes precedence over a compatibility overlay.
    manifest(portable.parent / ".codex-plugin/plugin.json", b"private-invalid")
    manifest(portable.parent / "references/example/.claude-plugin/plugin.json")
    manifest(root / ".git/fixture/.claude-plugin/plugin.json")
    first = snapshot(monkeypatch, root)
    coverage = first["roots"][0]
    assert coverage["status"] == "ok" and len(coverage["components"]) == len(paths) + 1
    assert {c["path"] for c in coverage["components"]} == set(
        map(str, [*paths, portable])
    )
    assert all(
        c["kind"] == "plugin" and c["evidence"] == "declared"
        for c in coverage["components"]
    )
    item = next(c for c in coverage["components"] if c["path"] == str(portable))
    assert item["metadata"] == {
        "description": "Fixture plugin",
        "license": "MIT",
        "repository_url": "https://github.com/example/plugin",
    }
    assert item["publisher"] == "Example" and item["version"] == "2.0"
    assert "private-" not in json.dumps(first) and not (root / "executed").exists()
    before = set(next(iter(validate_snapshot(SENSOR, first)[2].values()))["components"])
    manifest(paths[0], {"name": "renamed", "version": "9.0"})
    after = snapshot(monkeypatch, root)
    assert before == set(
        next(iter(validate_snapshot(SENSOR, after)[2].values()))["components"]
    )


@pytest.mark.parametrize(
    "data",
    [
        b'{"name":"one","name":"two"}',
        b'{"name":"one","ignored":NaN}',
        b'{"name":"\xff"}',
        b'{"name":"\\ud800"}',
        b'{"name":"\\u0000"}',
        b'{"name":[]}',
        b'{"name":""}',
        b'{"name":"one","author":"private-author"}',
        b'{"name":"one","version":1}',
        b'{"name":"one","repository":{}}',
        b'{/* comment */ "name":"one"}',
        b'{"name":"one",}',
        b"[]",
        b"",
        b'{"name":"one","ignored":' + b"[" * 1000 + b"]" * 1000 + b"}",
        b'{"name":"one","ignored":"' + b"x" * plugins.MAX_FILE + b'"}',
    ],
    ids=[
        "duplicate",
        "nonfinite",
        "utf8",
        "surrogate",
        "nul",
        "name-type",
        "empty-name",
        "author-type",
        "version-type",
        "repository-type",
        "jsonc",
        "trailing-comma",
        "array",
        "empty-file",
        "depth",
        "size",
    ],
)
def test_invalid_manifests_preserve_valid_siblings_and_partial_coverage(
    tmp_path, monkeypatch, data
):
    root = tmp_path.resolve()
    manifest(root / "good/.claude-plugin/plugin.json")
    manifest(root / "bad/.codex-plugin/plugin.json", data)
    result = snapshot(monkeypatch, root)
    assert result["roots"][0]["status"] == "partial"
    assert [c["key"] for c in result["roots"][0]["components"]] == [
        "good/.claude-plugin/plugin.json",
    ]
    assert "private-" not in json.dumps(result)


@pytest.mark.parametrize(
    "repository",
    [
        "https://user:private-password@example.com/plugin",
        "https://example.com/plugin?token=private-token",
        "https://example.com/plugin#private-token",
        "https://example.com:private-port/plugin",
        "https://exam ple.com/plugin",
        "ssh://git@example.com/plugin",
        "git@example.com:plugin.git",
    ],
)
def test_unsafe_or_unsupported_urls_are_not_returned(tmp_path, monkeypatch, repository):
    manifest(
        tmp_path / ".cursor-plugin/plugin.json",
        {
            "name": "example",
            "repository": repository,
        },
    )
    result = snapshot(monkeypatch, tmp_path.resolve())
    assert result["roots"][0]["status"] == "ok"
    assert result["roots"][0]["components"][0]["metadata"] == {}
    assert repository not in json.dumps(result)


def test_empty_missing_unreadable_changed_and_linked_locations(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "plugins"
    path = manifest(root / "example/.claude-plugin/plugin.json")
    shared = manifest(tmp_path / "shared/.codex-plugin/plugin.json")
    (root / "linked").symlink_to(shared.parent.parent, target_is_directory=True)
    first = snapshot(monkeypatch, root)
    assert first["roots"][0]["status"] == "ok"
    assert len(first["roots"][0]["components"]) == 2
    original = plugins._metadata

    def changed(document):
        result = original(document)
        path.write_text("private-changed")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(plugins, "_metadata", changed)
        assert query(root)[0]["status"] == "partial"
    with monkeypatch.context() as patch:
        patch.setattr(
            plugins.os, "scandir", Mock(side_effect=PermissionError("private-error"))
        )
        rows = query(root)
        assert rows[0]["status"] == "partial" and "private-error" not in json.dumps(
            rows
        )
    shutil.rmtree(path.parent.parent)
    (root / "linked").unlink()
    assert query(root)[0]["status"] == "ok" and len(query(root)) == 1
    (root / "cycle").symlink_to(root, target_is_directory=True)
    assert query(root)[0]["status"] == "partial"
    (root / "cycle").unlink()
    (root / ".claude-plugin").symlink_to(root / "absent")
    assert query(root)[0]["status"] == "partial"
    (root / ".claude-plugin").unlink()
    (root / "broken").symlink_to(root / "absent")
    assert query(root)[0]["status"] == "partial"
    shutil.rmtree(root)
    result = snapshot(monkeypatch, root, previous=first["roots"])
    assert result["roots"][0]["status"] == "unavailable"


def test_nonregular_files_limits_portable_schema_and_constraints(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    path = manifest(root / ".claude-plugin/plugin.json")
    for limit in (
        "MAX_NODES",
        "MAX_JSON_DEPTH",
        "MAX_ENTRIES",
        "MAX_COMPONENTS",
        "MAX_BYTES",
        "MAX_SECONDS",
    ):
        with monkeypatch.context() as patch:
            patch.setattr(plugins, limit, 0)
            assert query(root)[0]["status"] == "partial"
    with monkeypatch.context() as patch:
        patch.setattr(plugins, "MAX_DEPTH", 0)
        assert query(root.parent)[0]["status"] == "partial"
    path.unlink()
    os.mkfifo(path)
    assert query(root)[0]["status"] == "partial"
    path.unlink()
    path.mkdir()
    descriptor = os.open(path, os.O_RDONLY)
    with monkeypatch.context() as patch:
        patch.setattr(plugins.os, "open", lambda *a, **kw: descriptor)
        assert query(root)[0]["status"] == "partial"
        with pytest.raises(OSError):
            os.fstat(descriptor)
    path.rmdir()
    # An unrecognized portable schema is incomplete, including with an overlay.
    manifest(root / "plugin.json", {"name": "example", "$schema": "unsupported"})
    manifest(path)
    assert query(root)[0]["status"] == "partial" and len(query(root)) == 1
    with monkeypatch.context() as patch:
        patch.setattr(
            plugins.os, "scandir", Mock(side_effect=AssertionError("no scan"))
        )
        assert plugins.plugin_rows({}) == []
        assert (
            plugins.plugin_rows(
                {
                    "constraints": [
                        {
                            "name": "directory",
                            "list": [{"op": 65, "expr": "%"}],
                        }
                    ]
                }
            )
            == []
        )
    with pytest.raises(ValueError):
        query("relative")
    with pytest.raises(ValueError):
        query(*(root / str(i) for i in range(257)))


def test_default_cache_roots_and_custom_locations(tmp_path, monkeypatch):
    home, custom = tmp_path.resolve() / "home", tmp_path.resolve() / "codex"
    expected = [
        home / ".claude/plugins/cache",
        home / ".cursor/plugins/local",
        custom / "plugins/cache",
    ]
    for path in expected:
        manifest(path / "market/example/1.0/.codex-plugin/plugin.json")
    manifest(home / ".codex/plugins/cache/ignored/.codex-plugin/plugin.json")
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("CODEX_HOME", str(custom))
    expand = inventory._Scan.expand
    monkeypatch.setattr(
        inventory._Scan,
        "expand",
        lambda self, base, pattern: (
            expand(self, base, pattern) if Path(base) != Path("/") else []
        ),
    )
    cfg = inventory.settings({})
    selected = [
        r
        for r in inventory._discover(cfg, (), inventory._Scan())
        if r["source"] == "openaidr-plugins"
    ]
    assert {r["root"] for r in selected} == set(map(str, expected))
    assert {r["scope"] for r in selected} == {"user"}
    shutil.rmtree(expected[0])
    later = inventory._discover(cfg, selected, inventory._Scan())
    assert any(r["root"] == str(expected[0]) for r in later)
    cfg = inventory.settings(
        {
            "inventory": {
                "components": {
                    "include_default_roots": False,
                    "plugin_roots": [str(custom)],
                }
            }
        }
    )
    explicit = inventory._discover(cfg, (), inventory._Scan())
    assert [(r["root"], r["scope"]) for r in explicit] == [(str(custom), "unknown")]


@pytest.mark.parametrize("marker", [".claude-plugin", ".codebuddy-plugin"])
def test_declared_skills_collect_once_with_stable_relationships(tmp_path, monkeypatch, marker):
    base = tmp_path.resolve()
    skill = base / "skills/review/SKILL.md"
    manifest(skill, b"---\nname: review\n---\nprivate-skill-body\n")
    path = manifest(
        base / marker / "plugin.json",
        {
            "name": "review-plugin",
            "skills": ["./skills", "./skills/", "./skills"],
        },
    )
    first = snapshot(monkeypatch, base)
    assert len(first["roots"]) == 2
    plugin_root, skill_root = first["roots"]
    assert {r["status"] for r in first["roots"]} == {"ok"}
    assert [c["name"] for c in skill_root["components"]] == ["review"]
    (link,) = plugin_root["relationships"]
    assert link == {
        "from": {
            "source": "openaidr-plugins",
            "root": str(base),
            "key": marker + "/plugin.json",
        },
        "to": {
            "source": "openaidr-skills",
            "root": str(skill.parent.parent),
            "key": "review/SKILL.md",
        },
        "kind": "provides",
        "evidence": "declared",
        "path": str(path),
    }
    assert "private-" not in json.dumps(first)
    manifest(skill, b"---\nname: renamed\nmetadata:\n  version: '2.0'\n---\n")
    second = snapshot(monkeypatch, base, previous=first["roots"])
    assert second["roots"][0]["relationships"] == [link]
    # A single skill folder and the plugin root itself are valid declarations.
    for directory in ("./skills/review", "."):
        manifest(path, {"name": "review-plugin", "skills": directory})
        result = snapshot(monkeypatch, base)
        assert len(result["roots"][0]["relationships"]) == 1
    manifest(base / " skills /SKILL.md", b"---\nname: literal-path\n---\n")
    manifest(path, {"name": "review-plugin", "skills": "./ skills "})
    result = snapshot(monkeypatch, base)
    assert result["roots"][1]["root"] == str(base / " skills ")
    assert result["roots"][1]["components"][0]["name"] == "literal-path"


@pytest.mark.parametrize(
    "declared",
    [
        None,
        1,
        {},
        [False],
        "",
        "skills",
        "skills/",
        " ./skills ",
        "../private-outside",
        "/private-outside",
        "$PRIVATE",
        "skills/*",
        "skills/../private-outside",
        "skills\\private-outside",
    ],
)
def test_invalid_skill_declarations_preserve_plugin_and_do_not_expand(
    tmp_path, monkeypatch, declared
):
    base = tmp_path.resolve()
    manifest(
        base / ".claude-plugin/plugin.json", {"name": "plugin", "skills": declared}
    )
    manifest(base / "skills/SKILL.md", b"---\nname: should-not-be-collected\n---\n")
    result = snapshot(monkeypatch, base)
    (root,) = result["roots"]
    assert root["status"] == "partial" and len(root["components"]) == 1
    assert root["relationships"] == []
    assert "private-" not in json.dumps(result)


def test_skill_declaration_failures_and_limits_retain_valid_siblings(
    tmp_path, monkeypatch
):
    base = tmp_path.resolve()
    manifest(base / "skills/review/SKILL.md", b"---\nname: review\n---\n")
    path = manifest(
        base / ".claude-plugin/plugin.json",
        {
            "name": "plugin",
            "skills": ["./skills", "./missing"],
        },
    )
    result = snapshot(monkeypatch, base)
    assert result["roots"][0]["status"] == "partial"
    assert len(result["roots"][0]["relationships"]) == 1
    assert result["roots"][2]["status"] == "unavailable"
    manifest(path, {"name": "plugin", "skills": "./skills"})
    for limit, value in (
        ("MAX_ROOTS", 1),
        ("MAX_COMPONENTS", 1),
        ("MAX_RELATIONSHIPS", 0),
        ("MAX_BYTES", 1600),
    ):
        with monkeypatch.context() as patch:
            patch.setattr(inventory, limit, value)
            result = snapshot(patch, base)
            assert result["roots"][0]["status"] == "partial"
            assert not result["roots"][0]["relationships"]
            assert len(json.dumps(result)) <= inventory.MAX_BYTES
    with monkeypatch.context() as patch:
        patch.setattr(plugins, "MAX_SKILL_DIRECTORIES", 1)
        manifest(path, {"name": "plugin", "skills": ["./skills", "./missing"]})
        result = snapshot(patch, base)
        assert result["roots"][0]["status"] == "partial"
        assert len(result["roots"][0]["relationships"]) == 1
    # Other manifest formats keep their metadata without interpreting this field.
    path.unlink()
    manifest(
        base / ".codex-plugin/plugin.json", {"name": "plugin", "skills": "./skills"}
    )
    result = snapshot(monkeypatch, base)
    assert len(result["roots"]) == 1 and result["roots"][0]["status"] == "ok"


@pytest.mark.parametrize("marker", [".claude-plugin", ".codebuddy-plugin"])
def test_declared_skill_symlinks_cannot_escape_plugin_or_privacy_guard(
    tmp_path, monkeypatch, marker
):
    from openaidr.sensor.privacy import PrivacyGuard, PrivacySkip

    base = tmp_path.resolve() / "plugin"
    path = manifest(
        base / marker / "plugin.json", {"name": "plugin", "skills": "./linked"}
    )
    external = tmp_path.resolve() / "external"
    manifest(external / "SKILL.md", b"---\nname: private-external\n---\n")
    link = base / "linked"
    link.symlink_to(external, target_is_directory=True)
    result = snapshot(monkeypatch, base)
    assert result["roots"][0]["status"] == "partial" and len(result["roots"]) == 1
    link.unlink()
    internal = base / "safe"
    manifest(internal / "SKILL.md", b"---\nname: allowed\n---\n")
    link.symlink_to(internal, target_is_directory=True)
    first = snapshot(monkeypatch, base)
    assert len(first["roots"][0]["relationships"]) == 1
    # A cached root must not follow a replacement symlink outside its old location.
    shutil.rmtree(internal)
    internal.symlink_to(external, target_is_directory=True)
    redirected = snapshot(monkeypatch, base, previous=first["roots"])
    assert redirected["roots"][1]["status"] == "unavailable"
    assert not redirected["roots"][1]["components"]
    assert "private-external" not in json.dumps(redirected)
    internal.unlink()
    manifest(internal / "SKILL.md", b"---\nname: allowed\n---\n")
    original = PrivacyGuard.check

    def protected(self, target):
        if Path(target) in (link, internal):
            raise PrivacySkip("private-denied")
        return original(self, target)

    monkeypatch.setattr(PrivacyGuard, "check", protected)
    result = snapshot(monkeypatch, base)
    assert result["roots"][0]["status"] == "partial" and len(result["roots"]) == 1
    assert "private-" not in json.dumps(result)
    assert path.exists()


@pytest.mark.parametrize("link_kind", ["directory", "manifest"])
def test_nested_skill_symlinks_cannot_escape_declared_root(
    tmp_path, monkeypatch, link_kind
):
    base = tmp_path.resolve() / "plugin"
    manifest(
        base / ".claude-plugin/plugin.json", {"name": "plugin", "skills": "./skills"}
    )
    root = base / "skills"
    manifest(root / "allowed/SKILL.md", b"---\nname: allowed\n---\n")
    external = manifest(
        tmp_path.resolve() / "external/SKILL.md",
        b"---\nname: private-external\ndescription: private-description\n---\n",
    )
    if link_kind == "directory":
        (root / "escape").symlink_to(external.parent, target_is_directory=True)
    else:
        (root / "escape").mkdir()
        (root / "escape/SKILL.md").symlink_to(external)
    result = snapshot(monkeypatch, base)
    owner, skills = result["roots"]
    assert owner["status"] == skills["status"] == "partial"
    assert [item["name"] for item in skills["components"]] == ["allowed"]
    assert len(owner["relationships"]) == 1
    assert "private-" not in json.dumps(result)
    # The external location is readable when it is itself an explicit scan root.
    rows = query(external.parent, source=inventory.SOURCES["skills"])
    assert rows[0]["status"] == "ok"
    assert rows[1]["name"] == "private-external"
