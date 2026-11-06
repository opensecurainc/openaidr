import hashlib
import json
import os
import shutil
from pathlib import Path
from unittest.mock import Mock

import pytest

from openaidr.sensor import component_inventory as inventory, skill_inventory as skills
from openaidr.server.component_inventory import validate_snapshot

SENSOR = "b8c94c3e-8ecf-4734-939c-1a44b43cae49"


def skill(
    path, header="name: example\ndescription: A fixture skill\n", body="Private body"
):
    path.mkdir(parents=True, exist_ok=True)
    manifest = path / "SKILL.md"
    manifest.write_text(f"---\n{header}---\n{body}\n")
    return manifest


def query(*paths):
    return skills.skill_rows(
        {
            "constraints": [
                {
                    "name": "directory",
                    "list": [{"op": 2, "expr": str(path)} for path in paths],
                    "affinity": "TEXT",
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
            {**row, "identifier": row["name"]} for row in query(*paths)
        ],
    )
    options = inventory.settings(
        {
            "inventory": {
                "components": {
                    "include_default_roots": False,
                    "skill_roots": [str(p) for p in paths],
                }
            }
        }
    )
    result = inventory.collect_inventory(options, previous)
    validate_snapshot(SENSOR, result)
    return result


def test_metadata_symlinks_and_stable_installation_identity(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "skills"
    manifest = skill(
        root / "example",
        """name: example
description: |
  An example skill.
  ---
  A literal separator in the description.
license: MIT
allowed-tools: Read, Bash(git:* private-argument), mcp__docs__search
metadata:
  version: 1.2
  author: Example
  repository_url: https://github.com/example/skills
  source_url: https://user:private-password@example.com/skill?token=private-token
  revision: abc123
  token: private-token
unknown-field: private-field
""",
    )
    # Never interpret commands in the Markdown body or scan supporting examples.
    with manifest.open("a") as stream:
        stream.write(f"!`touch {tmp_path / 'executed'}`\n")
    skill(manifest.parent / "references/embedded")
    shared = manifest.parent / "references/shared"
    skill(shared, "description: Skill without an explicit name\n")
    (root / "linked").symlink_to(shared, target_is_directory=True)
    first = snapshot(monkeypatch, root)
    coverage = first["roots"][0]
    assert coverage["status"] == "ok"
    example, linked = coverage["components"]
    assert example["metadata"] == {
        "description": "An example skill.\n---\nA literal separator in the description.",
        "license": "MIT",
        "revision": "abc123",
        "repository_url": "https://github.com/example/skills",
        "content_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "tools": ["Read", "Bash", "mcp__docs__search"],
    }
    assert example["version"] == "1.2" and example["publisher"] == "Example"
    assert example["key"] == "example/SKILL.md"
    assert linked["name"] == "linked" and linked["path"] == str(
        root / "linked/SKILL.md"
    )
    assert "private-" not in json.dumps(first) and "Private body" not in json.dumps(
        first
    )
    assert not (tmp_path / "executed").exists()
    before_ids = set(
        next(iter(validate_snapshot(SENSOR, first)[2].values()))["components"]
    )
    skill(manifest.parent, "name: renamed\nmetadata:\n  version: 2.0\n")
    second = snapshot(monkeypatch, root)
    after_ids = set(
        next(iter(validate_snapshot(SENSOR, second)[2].values()))["components"]
    )
    assert before_ids == after_ids
    assert (
        second["roots"][0]["components"][0]["metadata"]["content_sha256"]
        != example["metadata"]["content_sha256"]
    )


@pytest.mark.parametrize(
    "data",
    [
        b"No frontmatter",
        b"---\nname: [broken\n---\n",
        b"---\n- list\n---\n",
        b"---\nname: one\nname: two\n---\n",
        b"---\nname: !!python/object/apply:os.system ['never-run']\n---\n",
        b"---\nname: &a example\ndescription: *a\n---\n",
        b"---\nname: example\nmetadata: " + b"[" * 30 + b"]" * 30 + b"\n---\n",
        b"---\nname: example\n" + b"x: y\n" * 600 + b"---\n",
        b"---\nname: \xff\n---\n",
        b'---\nname: "\\0"\n---\n',
        b"---\nname: example\n" + b"#comment\n" * 9000 + b"---\n",
        b"---\nname: example\n---\n" + b"x" * skills.MAX_FILE,
    ],
)
def test_malformed_or_unbounded_metadata_is_partial(data, tmp_path, monkeypatch):
    root = tmp_path.resolve()
    skill(root / "good")
    broken = skill(root / "broken")
    broken.write_bytes(data)
    result = snapshot(monkeypatch, root)
    assert result["roots"][0]["status"] == "partial"
    assert [c["key"] for c in result["roots"][0]["components"]] == ["good/SKILL.md"]
    assert data.decode("utf-8", errors="ignore") not in result["roots"][0]["message"]


def test_empty_missing_unreadable_changed_and_cyclic_roots(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "skills"
    manifest = skill(root / "example")
    first = snapshot(monkeypatch, root)
    original = skills._metadata

    def changed(data, fallback):
        result = original(data, fallback)
        manifest.write_text("changed during scan")
        return result

    monkeypatch.setattr(skills, "_metadata", changed)
    assert snapshot(monkeypatch, root)["roots"][0]["status"] == "partial"
    monkeypatch.setattr(skills, "_metadata", original)
    shutil.rmtree(manifest.parent)
    assert snapshot(monkeypatch, root)["roots"][0]["status"] == "ok"
    (root / "loop").symlink_to(root, target_is_directory=True)
    assert snapshot(monkeypatch, root)["roots"][0]["status"] == "partial"
    (root / "loop").unlink()
    (root / "broken-link").symlink_to(root / "absent")
    assert snapshot(monkeypatch, root)["roots"][0]["status"] == "partial"
    with monkeypatch.context() as denied:
        denied.setattr(
            skills.os, "scandir", Mock(side_effect=PermissionError("private-error"))
        )
        result = snapshot(monkeypatch, root)
        assert result["roots"][0]["status"] == "partial"
        assert "private-error" not in json.dumps(result)
    shutil.rmtree(root)
    result = snapshot(monkeypatch, root, previous=first["roots"])
    assert result["roots"][0]["status"] == "unavailable"
    assert result["roots"][0]["components"] == []


def test_symlinked_files_nonregular_files_and_scan_limits(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "skills"
    target = skill(root / "linked/target")
    (root / "linked/SKILL.md").symlink_to(target)
    assert snapshot(monkeypatch, root)["roots"][0]["status"] == "ok"
    (root / "fifo").mkdir()
    os.mkfifo(root / "fifo/SKILL.md")
    result = snapshot(monkeypatch, root)
    assert result["roots"][0]["status"] == "partial"
    assert len(result["roots"][0]["components"]) == 1
    shutil.rmtree(root / "fifo")
    for limit in (
        "MAX_COMPONENTS",
        "MAX_BYTES",
        "MAX_ENTRIES",
        "MAX_SECONDS",
        "MAX_DEPTH",
    ):
        with monkeypatch.context() as limited:
            limited.setattr(skills, limit, 0)
            assert snapshot(monkeypatch, root)["roots"][0]["status"] == "partial"


def test_unconstrained_table_never_scans_and_missing_coverage_is_an_error(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        skills.os, "scandir", Mock(side_effect=AssertionError("no scan"))
    )
    assert skills.skill_rows({}) == []
    assert (
        skills.skill_rows(
            {"constraints": [{"name": "directory", "list": [{"op": 65, "expr": "%"}]}]}
        )
        == []
    )
    with pytest.raises(ValueError):
        query("relative")
    monkeypatch.setattr(inventory.sys, "platform", "darwin")
    monkeypatch.setattr(inventory, "inventory_rows", lambda *a, **kw: [])
    cfg = inventory.settings(
        {
            "inventory": {
                "components": {
                    "include_default_roots": False,
                    "skill_roots": [str(tmp_path)],
                }
            }
        }
    )
    assert inventory.collect_inventory(cfg)["roots"][0]["status"] == "error"


def test_default_custom_and_project_roots_are_bounded(tmp_path, monkeypatch):
    home = tmp_path.resolve() / "home"
    custom = tmp_path.resolve() / "custom-codex"
    project = tmp_path.resolve() / "literal*project"
    for path in (
        home / ".agents/skills",
        home / ".claude/skills",
        custom / "skills/.system",
        project / ".agents/skills",
        project / ".codex/skills",
        project / ".claude/skills",
        home / "unconfigured-project/.agents/skills",
    ):
        skill(path / "example")
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
    cfg = inventory.settings(
        {"inventory": {"components": {"project_roots": [str(project)]}}}
    )
    roots = inventory._discover(cfg, (), inventory._Scan())
    selected = [r for r in roots if r["source"] == "openaidr-skills"]
    assert len(selected) == 6
    assert {r["scope"] for r in selected} == {"user", "project"}
    assert all("unconfigured-project" not in r["root"] for r in selected)
    assert all(
        r["environment"] == str(project) for r in selected if r["scope"] == "project"
    )
