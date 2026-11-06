import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from openaidr.sensor import component_inventory as inventory, mcp_inventory as mcp
from openaidr.server.component_inventory import validate_snapshot

SENSOR = "b8c94c3e-8ecf-4734-939c-1a44b43cae49"


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data) if isinstance(data, dict) else data)
    return path


def query(*paths):
    return mcp.mcp_rows(
        {
            "constraints": [
                {
                    "name": "path",
                    "list": [{"op": 2, "expr": str(path)} for path in paths],
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
            {**row, "directory": row["path"]} for row in query(*paths)
        ],
    )
    options = inventory.settings(
        {
            "inventory": {
                "components": {
                    "include_default_roots": False,
                    "mcp_configs": list(map(str, paths)),
                }
            }
        }
    )
    result = inventory.collect_inventory(options, previous)
    validate_snapshot(SENSOR, result)
    return result


def test_json_toml_identity_symlinks_and_private_values(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    config = write(
        root / ".claude.json",
        {
            "mcpServers": {
                "docs/~one": {
                    "command": "sh",
                    "args": ["-c", f"touch {root / 'executed'}"],
                    "env": {"TOKEN": "private-env"},
                    "url": "https://user:private-password@example.com/private-path?token=private-token",
                    "headers": {"Authorization": "private-header"},
                    "auth": {"CLIENT_SECRET": "private-secret"},
                    "enabled_tools": ["private-tool"],
                    "version": "private-version",
                }
            },
            "projects": {
                "/project/one": {"mcpServers": {"docs/~one": {"url": "private-url"}}},
                "/project/two": {"mcpServers": {"docs/~one": {"disabled": True}}},
            },
            "oauthAccount": {"token": "private-account"},
        },
    )
    target = write(
        root / "shared-config",
        '\ufeff[mcp_servers.docs]\r\nenabled = false\r\ncommand = "private-command"\r\n',
    )
    linked = root / "config.toml"
    linked.symlink_to(target)
    first = snapshot(monkeypatch, config, linked)
    assert all(r["status"] == "ok" for r in first["roots"])
    items = [c for r in first["roots"] for c in r["components"]]
    assert len(items) == 4
    assert all(
        c["kind"] == "mcp_server" and c["evidence"] == "configured" for c in items
    )
    assert {c["key"] for c in items} == {
        "/mcpServers/docs~1~0one",
        "/projects/~1project~1one/mcpServers/docs~1~0one",
        "/projects/~1project~1two/mcpServers/docs~1~0one",
        "/mcp_servers/docs",
    }
    assert first["roots"][1]["root"] == str(linked)
    assert "private-" not in json.dumps(first) and not (root / "executed").exists()
    assert all("metadata" not in c and "version" not in c for c in items)
    before = list(validate_snapshot(SENSOR, first)[2].values())[1]["components"]
    target.write_text('[mcp_servers.docs]\nurl = "https://changed.example.com"\n')
    after = list(
        validate_snapshot(SENSOR, snapshot(monkeypatch, config, linked))[2].values()
    )[1]["components"]
    assert set(before) == set(after)


@pytest.mark.parametrize(
    "filename,data",
    [
        ("config.json", b'{"mcpServers": {"one": {}, "one": {}}}'),
        ("config.json", b'{"mcpServers": {"one": {"token": NaN}}}'),
        ("config.json", b'{"mcpServers": {"one": {"token": "\xff"}}}'),
        ("config.json", b'{"mcpServers": {"one": {"token": "\\ud800"}}}'),
        ("config.json", b'{"mcpServers": {"\\u0000": {}}}'),
        ("config.json", b'{"mcpServers": []}'),
        ("config.json", b'{"servers": {"one": {}}}'),
        ("config.json", b'{/* comment */ "mcpServers": {}}'),
        ("config.json", b'{"mcpServers": {},}'),
        ("config.json", b'{"mcpServers": {"one": "private-invalid"}}'),
        ("config.json", b'{"projects": {"/project": {"mcpServers": []}}}'),
        ("config.json", b"[]"),
        ("config.json", b""),
        ("config.json", b'{"private-key":' + b"[" * 1000 + b"]" * 1000 + b"}"),
        ("config.json", b'{"private-key": "' + b"x" * mcp.MAX_FILE + b'"}'),
        ("config.toml", b'[mcp_servers.one]\ncommand="first"\ncommand="second"\n'),
    ],
)
def test_malformed_or_oversized_configs_retain_coverage(filename, data, tmp_path):
    path = tmp_path.resolve() / filename
    path.write_bytes(data)
    rows = query(path)
    assert rows[0]["status"] == "partial" and len(rows) == 1
    assert "private-" not in json.dumps(rows)


def test_valid_siblings_empty_missing_changed_and_unreadable(tmp_path, monkeypatch):
    path = tmp_path.resolve() / "config.json"
    write(
        path, {"mcpServers": {"good": {}, "broken": 42}, "projects": {"/invalid": []}}
    )
    first = snapshot(monkeypatch, path)
    assert first["roots"][0]["status"] == "partial"
    assert [c["name"] for c in first["roots"][0]["components"]] == ["good"]
    write(path, {"mcpServers": {"good": {}}})
    original = mcp._Scan.parse

    def changed(self, data, toml):
        result = original(self, data, toml)
        path.write_text("changed during collection")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(mcp._Scan, "parse", changed)
        assert query(path)[0]["status"] == "partial"
    with monkeypatch.context() as patch:
        patch.setattr(
            mcp.os, "open", Mock(side_effect=PermissionError("private-error"))
        )
        rows = query(path)
        assert rows[0]["status"] == "error" and "private-error" not in json.dumps(rows)
    write(path, {"mcpServers": {}})
    assert query(path)[0]["status"] == "ok" and len(query(path)) == 1
    empty_toml = write(path.parent / "empty.toml", "")
    assert query(empty_toml)[0]["status"] == "ok" and len(query(empty_toml)) == 1
    path.unlink()
    result = snapshot(monkeypatch, path, previous=first["roots"])
    assert result["roots"][0]["status"] == "unavailable"
    assert result["roots"][0]["components"] == []
    os.mkfifo(path)
    assert query(path)[0]["status"] == "partial"
    path.unlink()
    path.symlink_to(path)
    assert query(path)[0]["status"] == "error"


def test_bounds_and_explicit_constraints(tmp_path, monkeypatch):
    path = write(tmp_path.resolve() / "config.json", {"mcpServers": {"one": {}}})
    for limit in (
        "MAX_NODES",
        "MAX_DEPTH",
        "MAX_BYTES",
        "MAX_COMPONENTS",
        "MAX_SECONDS",
    ):
        with monkeypatch.context() as patch:
            patch.setattr(mcp, limit, 0)
            assert query(path)[0]["status"] == "partial"
    with monkeypatch.context() as patch:
        patch.setattr(mcp.os, "open", Mock(side_effect=AssertionError("no read")))
        assert mcp.mcp_rows({}) == []
        assert (
            mcp.mcp_rows(
                {"constraints": [{"name": "path", "list": [{"op": 65, "expr": "%"}]}]}
            )
            == []
        )
    with pytest.raises(ValueError):
        query("relative.json")
    with pytest.raises(ValueError):
        query(*(path.parent / str(i) for i in range(257)))
    snapshot(monkeypatch, path)
    monkeypatch.setattr(inventory, "inventory_rows", lambda *a, **kw: [])
    cfg = inventory.settings(
        {
            "inventory": {
                "components": {
                    "include_default_roots": False,
                    "mcp_configs": [str(path)],
                }
            }
        }
    )
    assert inventory.collect_inventory(cfg)["roots"][0]["status"] == "error"


def test_directory_rejection_closes_the_open_descriptor(tmp_path, monkeypatch):
    descriptor = os.open(tmp_path, os.O_RDONLY)
    monkeypatch.setattr(mcp.os, "open", lambda *a, **kw: descriptor)
    try:
        assert query(tmp_path.resolve())[0]["status"] == "partial"
        with pytest.raises(OSError):
            os.fstat(descriptor)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def test_default_and_project_file_discovery_is_bounded(tmp_path, monkeypatch):
    home = tmp_path.resolve() / "home"
    custom = tmp_path.resolve() / "codex"
    project = tmp_path.resolve() / "literal*project"
    paths = [
        home / ".claude.json",
        home / ".cursor/mcp.json",
        home / "Library/Application Support/Claude/claude_desktop_config.json",
        custom / "config.toml",
        project / ".mcp.json",
        project / ".cursor/mcp.json",
        project / ".codex/config.toml",
    ]
    for path in [
        *paths,
        home / "unconfigured-project/.mcp.json",
        home / ".codex/config.toml",
    ]:
        write(path, "")
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
    selected = [
        r
        for r in inventory._discover(cfg, (), inventory._Scan())
        if r["source"] == "openaidr-mcp-servers"
    ]
    assert {r["root"] for r in selected} == set(map(str, paths))
    assert {r["scope"] for r in selected} == {"user", "project"}
    assert all(
        r["environment"] == str(project) for r in selected if r["scope"] == "project"
    )
    paths[0].unlink()
    later = inventory._discover(cfg, selected, inventory._Scan())
    assert any(r["root"] == str(paths[0]) for r in later)
