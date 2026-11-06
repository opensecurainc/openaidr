import errno
import json
import plistlib
import shutil
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock

import pytest

from openaidr.sensor import cli, component_inventory as inventory, osquery_runtime
from openaidr.sensor.config import Config
from openaidr.sensor.app_inventory import app_rows
from openaidr.server.component_inventory import validate_snapshot

SENSOR = "b8c94c3e-8ecf-4734-939c-1a44b43cae49"


def options(**values):
    return inventory.settings(
        {
            "inventory": {
                "components": {
                    "include_default_roots": False,
                    **values,
                }
            }
        }
    )


def package(path, name="example", version="1.0"):
    path.mkdir(parents=True)
    metadata = path / "package.json"
    metadata.write_text(json.dumps({"name": name, "version": version}))
    return metadata


def distribution(site, name="Example_Package", version="1.0"):
    path = site / f"{name}-{version}.dist-info"
    path.mkdir(parents=True)
    (path / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nLicense: MIT\n"
    )
    return path


def test_cli_launchers_identify_packages_without_execution(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    bin_dir = base / ".local/bin"
    bin_dir.mkdir(parents=True)
    marker = base / "must-not-exist"

    def executable(path, text=None):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text or f"#!/bin/sh\ntouch {marker}\n")
        path.chmod(0o755)
        return path

    hermes = base / ".hermes/hermes-agent"
    target = executable(hermes / ".hermes/bin/hermes")
    (hermes / "pyproject.toml").write_text(
        '[project]\nname="hermes-agent"\nversion="1.2"\n'
        '[project.scripts]\nhermes="hermes_cli.main:main"\n')
    executable(bin_dir / "hermes", f'#!/bin/sh\nexec "{target}" "$@"\n')
    executable(bin_dir / "hermes-agent", f'#!/bin/sh\nexec "{target}" --run-module run_agent "$@"\n')
    (bin_dir / "hermes-alias").symlink_to(bin_dir / "hermes")
    node = base / "node_modules/@openai/codex"
    target = executable(node / "bin/codex.js")
    (node / "package.json").write_text(json.dumps({
        "name": "@openai/codex", "version": "2.0", "bin": {"codex": "bin/codex.js"},
    }))
    (bin_dir / "codex-cli").symlink_to(target)
    venv = base / "private-env"
    target = executable(venv / "bin/aider")
    metadata = distribution(venv / "lib/python3.14/site-packages", "aider_chat")
    (metadata / "entry_points.txt").write_text("[console_scripts]\naider = aider.main:main\n")
    (venv / "pyproject.toml").write_text(
        '[project]\nname="unrelated-project"\n[project.scripts]\naider="other:main"\n')
    (bin_dir / "aider").symlink_to(target)
    executable(bin_dir / "codex")  # A name is insufficient identity evidence.
    executable(bin_dir / "dynamic", '#!/bin/sh\nexec "$(touch bad)" "$@"\n')
    (bin_dir / "readme").write_text("not executable")
    (bin_dir / "subfolder").mkdir()
    executable(bin_dir / "subfolder/hidden")
    monkeypatch.setattr(inventory, "inventory_rows", Mock(side_effect=AssertionError("No query needed")))
    snapshot = inventory.collect_inventory(options(bin_roots=[str(bin_dir)]))
    root, = snapshot["roots"]
    assert root["status"] == "ok", root["message"]
    rows = {item["key"]: item for item in root["components"]}
    assert set(rows) == {"hermes", "hermes-agent", "hermes-alias", "codex-cli", "aider", "codex", "dynamic"}
    assert rows["hermes"]["identifier"] == rows["hermes-alias"]["identifier"] == "pypi:hermes-agent"
    assert rows["hermes"]["version"] == "1.2"
    assert rows["hermes-agent"]["identifier"] == "pypi:hermes-agent"
    assert rows["codex-cli"]["identifier"] == "npm:@openai/codex"
    assert rows["aider"]["identifier"] == "pypi:aider-chat"
    assert rows["codex"]["identifier"].startswith("executable:")
    assert rows["dynamic"]["identifier"].startswith("executable:")
    assert not marker.exists()
    validate_snapshot(SENSOR, snapshot)


def test_cli_coverage_privacy_limits_and_removal(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    monkeypatch.setattr(Path, "home", lambda: base)
    bin_dir = base / "bin"
    bin_dir.mkdir()
    good = bin_dir / "tool"
    good.write_text("#!/bin/sh\nexit 0\n")
    good.chmod(0o755)
    protected = base / "Documents/private"
    protected.parent.mkdir()
    protected.write_text("#!/bin/sh\nexit 0\n")
    protected.chmod(0o755)
    (bin_dir / "protected").symlink_to(protected)
    (bin_dir / "dangling").symlink_to(base / "absent")
    (bin_dir / "cycle").symlink_to(bin_dir / "cycle")
    cfg = options(bin_roots=[str(bin_dir)])
    snapshot = inventory.collect_inventory(cfg)
    root, = snapshot["roots"]
    assert root["status"] == "partial"
    assert [item["name"] for item in root["components"]] == ["tool"]
    validate_snapshot(SENSOR, snapshot)
    monkeypatch.setattr(inventory, "MAX_ENTRIES", 0)
    assert inventory.collect_inventory(cfg)["roots"][0]["status"] == "partial"
    monkeypatch.setattr(inventory, "MAX_ENTRIES", 100000)
    shutil.rmtree(bin_dir)
    assert inventory.collect_inventory(cfg)["roots"][0]["status"] == "unavailable"
    bin_dir.mkdir()
    empty = inventory.collect_inventory(cfg)["roots"][0]
    assert empty["status"] == "ok" and empty["components"] == []


def test_cli_default_locations_and_command_option(tmp_path, monkeypatch, capsys):
    base = tmp_path.resolve()
    monkeypatch.setattr(Path, "home", lambda: base)
    (base / ".local/bin").mkdir(parents=True)
    (base / "bin").mkdir()
    roots = inventory._discover(inventory.settings({}), (), inventory._Scan())
    assert {str(base / name) for name in (".local/bin", "bin")} <= {
        root["root"] for root in roots if root["source"] == "openaidr-cli"}
    assert cli.main(["component-inventory", "--json", "--no-default-roots", "--bin-root", str(base / "bin")]) == 0
    snapshot = json.loads(capsys.readouterr().out)
    root, = snapshot["roots"]
    assert root["source"] == "openaidr-cli" and root["status"] == "ok"


@pytest.mark.parametrize("failure", ["malformed", "oversized", "changed", "cancelled"])
def test_cli_incomplete_metadata_never_confirms_a_product(tmp_path, monkeypatch, failure):
    from openaidr.sensor import cli_inventory

    base = tmp_path.resolve()
    bin_dir = base / "bin"
    bin_dir.mkdir()
    command = bin_dir / "tool"
    command.write_text("#!/bin/sh\nexit 0\n")
    command.chmod(0o755)
    manifest = base / "package.json"
    manifest.write_text("{" if failure == "malformed" else " " * ((1 << 20) + 1))
    if failure == "changed":
        def changed(*args):
            command.write_text("#!/bin/sh\nexit 1\n")
            return "npm", "claimed-product", "1"

        monkeypatch.setattr(cli_inventory, "_package", changed)
    result = inventory.collect_inventory(options(bin_roots=[str(bin_dir)]), cancelled=lambda: failure == "cancelled")
    assert all(root["status"] != "ok" for root in result["roots"])
    assert all(item["identifier"].startswith("executable:")
               for root in result["roots"] for item in root["components"])
    validate_snapshot(SENSOR, result)


def row(path, root, name="example", version="1.0"):
    return dict(
        path=str(path),
        directory=str(root),
        name=name,
        identifier=name,
        version=version,
        publisher="",
        license="MIT",
    )


@pytest.fixture(autouse=True)
def macos(monkeypatch):
    monkeypatch.setattr(inventory.sys, "platform", "darwin")


def test_partial_missing_malformed_and_changing_metadata(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    good = package(base / "node_modules/good")
    broken = package(base / "node_modules/broken")
    broken.write_text("invalid json")
    cfg = options(npm_roots=[str(base)])
    monkeypatch.setattr(inventory, "inventory_rows", lambda *a, **k: [row(good, base)])
    snapshot = inventory.collect_inventory(cfg)
    root = snapshot["roots"][0]
    assert root["status"] == "partial"
    assert [item["key"] for item in root["components"]] == ["node_modules/good"]
    assert f"First missing path: {broken}" in root["message"]
    validate_snapshot(SENSOR, snapshot)
    shutil.rmtree(broken.parent)
    (base / "node_modules/empty").mkdir()
    (base / "node_modules/@scope/remnant/lib/.empty").mkdir(parents=True)
    (good.parent / "node_modules/old/node_modules/nested").mkdir(parents=True)
    assert inventory.collect_inventory(cfg)["roots"][0]["status"] == "ok"

    def changed(*args, **kwargs):
        good.write_text('{"name":"example", "version":"2.0"}')
        return [row(good, base)]

    monkeypatch.setattr(inventory, "inventory_rows", changed)
    assert inventory.collect_inventory(cfg)["roots"][0]["status"] == "partial"


@pytest.mark.parametrize(
    "failure", ["file", "link", "protected", "permission", "limit", "changed"]
)
def test_missing_npm_manifest_requires_a_verified_empty_tree(
    tmp_path, monkeypatch, failure
):
    base = tmp_path.resolve()
    good = package(base / "node_modules/good")
    remnant = base / "node_modules/remnant/lib"
    remnant.mkdir(parents=True)
    if failure == "file":
        (remnant / "index.js").touch()
    elif failure in ("link", "protected"):
        monkeypatch.setattr(Path, "home", lambda: base)
        target = base / ("Documents" if failure == "protected" else "empty")
        target.mkdir()
        (remnant / "link").symlink_to(target)
    elif failure == "permission":
        scandir = inventory.os.scandir

        def unreadable(path):
            if Path(path) == remnant:
                raise PermissionError("cannot inspect remnant")
            return scandir(path)

        monkeypatch.setattr(inventory.os, "scandir", unreadable)
    elif failure == "limit":
        monkeypatch.setattr(inventory, "MAX_ENTRIES", 2)

    def query(*args, **kwargs):
        if failure == "changed":
            (remnant / "index.js").touch()
        return [row(good, base)]

    queries = Mock(side_effect=query)
    monkeypatch.setattr(inventory, "inventory_rows", queries)
    snapshot = inventory.collect_inventory(options(npm_roots=[str(base)]))
    root = snapshot["roots"][0]
    assert root["status"] == (
        "unavailable" if failure in ("protected", "permission") else "partial"
    )
    if failure in ("protected", "permission", "limit"):
        queries.assert_not_called()
        assert root["components"] == []
    else:
        assert [item["key"] for item in root["components"]] == ["node_modules/good"]
        assert "Cannot read package manifest (ENOENT)" in root["message"]
        assert str(remnant.parent / "package.json") in root["message"]
    validate_snapshot(SENSOR, snapshot)


def test_unavailable_environment_keeps_coverage_and_empty_root_can_remove_packages(
    tmp_path, monkeypatch
):
    project = tmp_path.resolve()
    site = project / ".venv/lib/python3.13/site-packages"
    dist = distribution(site)
    cfg = options(project_roots=[str(project)])
    monkeypatch.setattr(inventory, "inventory_rows", lambda *a, **k: [row(dist, site)])
    first = inventory.collect_inventory(cfg)
    python = next(r for r in first["roots"] if r["source"] == "osquery-python-packages")
    assert python["status"] == "ok"
    assert python["scope"] == "project" and python["environment"] == str(project)
    shutil.rmtree(project / ".venv")
    second = inventory.collect_inventory(cfg, first["roots"])
    failed = next(r for r in second["roots"] if r["source"] == python["source"])
    assert failed["status"] == "unavailable"
    assert failed["components"] == []
    assert all(
        failed[key] == python[key] for key in ("root", "scope", "environment", "user")
    )
    # The npm project still exists and a complete empty scan can remove packages.
    assert second["roots"][0]["status"] == "ok"
    assert second["roots"][0]["components"] == []
    validate_snapshot(SENSOR, second)


@pytest.mark.parametrize("kind", ["apps", "npm"])
def test_permission_failure_and_table_failure_retain_inventory(
    tmp_path, monkeypatch, kind
):
    base = tmp_path.resolve()
    cfg = options(**{("app_roots" if kind == "apps" else "npm_roots"): [str(base)]})
    scandir = inventory.os.scandir
    monkeypatch.setattr(inventory.os, "scandir", Mock(side_effect=PermissionError()))
    queries = Mock(return_value=[])
    monkeypatch.setattr(inventory, "inventory_rows", queries)
    root = inventory.collect_inventory(cfg)["roots"][0]
    assert root["status"] == ("partial" if kind == "apps" else "unavailable")
    assert root["components"] == []
    assert all(not call.args[1] for call in queries.call_args_list)
    monkeypatch.setattr(inventory.os, "scandir", scandir)
    monkeypatch.setattr(
        inventory, "inventory_rows", Mock(side_effect=RuntimeError("timeout"))
    )
    root = inventory.collect_inventory(cfg)["roots"][0]
    assert root["status"] == "error" and root["components"] == []


@pytest.mark.parametrize("kind", ["npm", "skill"])
@pytest.mark.parametrize(
    "error, diagnostic",
    [
        (
            osquery_runtime.OsqueryError(
                "Bundled osquery query timed out after 2.00 seconds."
            ),
            "timed out after 2.00 seconds",
        ),
        (
            PermissionError(errno.EACCES, "private-token"),
            "Operating-system error (EACCES)",
        ),
        (ValueError("private-token"), "Invalid scan data (ValueError)"),
        (RuntimeError("private-token"), "Metadata collection failed (RuntimeError)"),
    ],
)
def test_query_failures_report_safe_causes_for_native_and_extension_roots(
    tmp_path, monkeypatch, kind, error, diagnostic
):
    base = tmp_path.resolve()
    if kind == "npm":
        package(base / "node_modules/example")
    else:
        (base / "SKILL.md").touch()
    monkeypatch.setattr(inventory, "inventory_rows", Mock(side_effect=error))
    snapshot = inventory.collect_inventory(options(**{f"{kind}_roots": [str(base)]}))
    root = snapshot["roots"][0]
    assert root["status"] == "error" and root["components"] == []
    assert root["message"].startswith(
        "Metadata query:" if kind == "npm" else "Extension query:"
    )
    assert diagnostic in root["message"]
    assert "private-token" not in json.dumps(snapshot)
    validate_snapshot(SENSOR, snapshot)


def test_protected_roots_and_previous_locations_never_reach_osquery(
    tmp_path, monkeypatch
):
    from openaidr.sensor import privacy

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    mounted = tmp_path / "mounted"
    monkeypatch.setattr(privacy, "_protected_mounts", lambda: [mounted])
    protected = tmp_path / "Documents/project"
    linked = tmp_path / "linked"
    linked.symlink_to(protected)
    cfg = options(
        npm_roots=[str(protected), str(linked), str(mounted)],
        mcp_configs=[str(protected / "config.json")],
    )
    old = dict(
        source="openaidr-skills",
        root=str(protected / "skills"),
        scope="user",
        components=[],
        relationships=[],
        status="ok",
        message="",
    )
    queries = Mock(return_value=[])
    monkeypatch.setattr(inventory, "inventory_rows", queries)
    result = inventory.collect_inventory(cfg, [old])
    assert len(result["roots"]) == 5
    assert all(r["status"] == "unavailable" for r in result["roots"])
    assert all("privacy prompts" in r["message"] for r in result["roots"])
    queries.assert_not_called()
    validate_snapshot(SENSOR, result)


@pytest.mark.parametrize(
    "kind", ["npm", "python", "python-nested", "npm-glob", "python-glob"]
)
def test_native_package_queries_skip_roots_with_protected_links(
    tmp_path, monkeypatch, kind
):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    base = tmp_path / ("packages*" if kind.endswith("-glob") else "packages")
    if kind.startswith("npm"):
        package(base / "node_modules/good")
        link = base / "node_modules/blocked"
    else:
        distribution(base)
        # The native table checks even non-metadata directory entries.
        link = base / (
            "package/nested/blocked" if kind == "python-nested" else "blocked"
        )
        link.parent.mkdir(parents=True, exist_ok=True)
    if not kind.endswith("-glob"):
        link.symlink_to(tmp_path / "Downloads/blocked")
    queried = []
    monkeypatch.setattr(
        inventory,
        "inventory_rows",
        lambda source, paths, **kw: queried.extend(paths) or [],
    )
    result = inventory.collect_inventory(
        options(**{f"{kind.split('-')[0]}_roots": [str(base)]})
    )
    assert result["roots"][0]["status"] == "unavailable"
    assert result["roots"][0]["components"] == []
    assert queried == []
    validate_snapshot(SENSOR, result)


def test_known_user_environments_are_discovered_without_searching_projects(
    tmp_path, monkeypatch
):
    home = tmp_path.resolve()
    node = home / ".nvm/versions/node/v22/lib"
    package(node / "node_modules/example")
    site = home / ".local/share/uv/tools/tool/lib/python3.13/site-packages"
    distribution(site)
    distribution(home / "some-project/.venv/lib/python3.13/site-packages")
    monkeypatch.setattr(Path, "home", lambda: home)
    expand = inventory._Scan.expand
    monkeypatch.setattr(
        inventory._Scan,
        "expand",
        lambda self, base, pattern: (
            expand(self, base, pattern) if Path(base) == home else []
        ),
    )
    roots = inventory._discover(
        options(include_default_roots=True), (), inventory._Scan()
    )
    npm = next(r for r in roots if r["source"] == "osquery-npm-packages")
    python = next(r for r in roots if r["source"] == "osquery-python-packages")
    assert npm["root"] == str(node) and python["root"] == str(site)
    assert npm["scope"] == python["scope"] == "user"
    assert all("some-project" not in r["root"] for r in roots)
    desktop_config = next(
        r for r in roots if r["root"].endswith("Claude/claude_desktop_config.json")
    )
    assert desktop_config["status"] == "unavailable"
    assert "privacy prompts" in desktop_config["message"]


@pytest.mark.parametrize("override", ["", "   ", "custom"])
def test_workbuddy_profiles_discover_only_existing_component_locations(
    tmp_path, monkeypatch, override
):
    home = tmp_path.resolve()
    profiles = [home / name for name in (".workbuddy", ".workbuddy-ai", "custom", ".codebuddy")]
    for root in profiles:
        for directory in ("skills", "plugins/cache", "plugins/marketplaces"):
            (root / directory).mkdir(parents=True)
        (root / "mcp.json").write_text('{"mcpServers":{}}')
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setattr(inventory.sys, "platform", "darwin")
    monkeypatch.setenv("WORKBUDDY_CONFIG_DIR", str(home / "custom") if override == "custom" else override)
    expand = inventory._Scan.expand
    monkeypatch.setattr(inventory._Scan, "expand", lambda self, base, pattern: (
        expand(self, base, pattern) if Path(base).is_relative_to(home) else []
    ))
    roots = inventory._discover(options(include_default_roots=True), (), inventory._Scan())
    selected = profiles[2:3] if override == "custom" else profiles[:2]
    expected = {str(root / child) for root in selected
                for child in ("skills", "plugins/cache", "plugins/marketplaces", "mcp.json")}
    found = {r["root"] for r in roots if any(Path(r["root"]).is_relative_to(p) for p in profiles)}
    assert found == expected
    assert all(r["scope"] == "user" for r in roots if r["root"] in expected)
    assert not any((root / "settings.json").exists() for root in profiles)
    monkeypatch.setenv("WORKBUDDY_CONFIG_DIR", str(home / "absent"))
    inventory._discover(options(include_default_roots=True), (), inventory._Scan())
    assert not (home / "absent").exists()


@pytest.mark.parametrize(
    "folder", ["Documents", "Library/Application Support/Google/Chrome"]
)
def test_application_extension_keeps_metadata_scoped_and_private(
    tmp_path, monkeypatch, folder
):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    base = tmp_path / "Applications"
    metadata = base / "Safe.app/Contents/Info.plist"
    metadata.parent.mkdir(parents=True)
    metadata.write_bytes(
        plistlib.dumps(
            {
                "CFBundleIdentifier": "example.safe",
                "CFBundleName": "Safe",
                "CFBundleShortVersionString": "1.2",
                "LSEnvironment": {"TOKEN": "private-value"},
            }
        )
    )
    blocked = base / "Blocked.app/Contents/Info.plist"
    blocked.parent.mkdir(parents=True)
    protected = tmp_path / folder
    blocked.symlink_to(protected / "Info.plist")
    lstat = inventory.os.lstat

    def checked(path, *args, **kwargs):
        assert not Path(path).is_relative_to(protected)
        return lstat(path, *args, **kwargs)

    monkeypatch.setattr(inventory.os, "lstat", checked)

    def query(source, paths, **kwargs):
        assert source == "osquery-apps"
        return app_rows(
            {
                "constraints": [
                    {
                        "name": "path",
                        "list": [{"op": 2, "expr": path} for path in paths],
                    }
                ]
            }
        )

    queries = Mock(side_effect=query)
    monkeypatch.setattr(inventory, "inventory_rows", queries)
    result = inventory.collect_inventory(options(app_roots=[str(base)]))
    root = result["roots"][0]
    assert root["source"] == "osquery-apps"  # Preserve existing installation IDs.
    assert root["status"] == "partial"
    assert [(c["name"], c["version"]) for c in root["components"]] == [("Safe", "1.2")]
    assert "private-value" not in json.dumps(root["components"])
    assert queries.call_args.args[1] == [str(metadata.parent.parent)]
    # Direct extension calls enforce the same exclusions and require equality.
    assert app_rows({}) == []
    assert (
        app_rows(
            {
                "constraints": [
                    {"name": "path", "list": [{"op": 65, "expr": str(base / "%.app")}]}
                ]
            }
        )
        == []
    )
    assert (
        app_rows(
            {
                "constraints": [
                    {
                        "name": "path",
                        "list": [{"op": 2, "expr": str(blocked.parent.parent)}],
                    }
                ]
            }
        )
        == []
    )
    validate_snapshot(SENSOR, result)
    blocked.unlink()
    blocked.write_text("invalid plist")
    assert (
        inventory.collect_inventory(options(app_roots=[str(base)]))["roots"][0][
            "status"
        ]
        == "partial"
    )


def test_project_path_wildcards_are_literal(tmp_path):
    project = tmp_path.resolve() / "literal*project"
    site = project / ".venv/lib/python3.13/site-packages"
    distribution(site)
    distribution(
        tmp_path.resolve() / "literal-other-project/.venv/lib/python3.13/site-packages"
    )
    roots = inventory._discover(
        options(project_roots=[str(project)]), (), inventory._Scan()
    )
    assert {r["root"] for r in roots} == {str(project), str(site)}


def test_first_scan_discovery_failure_is_visible_without_installations(
    tmp_path, monkeypatch
):
    project = tmp_path.resolve()
    cfg = options(project_roots=[str(project)])
    monkeypatch.setattr(inventory._Scan, "expand", Mock(side_effect=PermissionError()))
    monkeypatch.setattr(inventory, "inventory_rows", Mock(return_value=[]))
    failed = inventory.collect_inventory(cfg)
    coverage = next(
        r for r in failed["roots"] if r["source"] == "osquery-python-packages"
    )
    assert coverage["root"] == "discovery" and coverage["status"] == "partial"
    assert not coverage["components"]
    validate_snapshot(SENSOR, failed)
    monkeypatch.setattr(inventory._Scan, "expand", Mock(return_value=[]))
    recovered = inventory.collect_inventory(cfg, failed["roots"])
    coverage = next(
        r for r in recovered["roots"] if r["source"] == "osquery-python-packages"
    )
    assert coverage["status"] == "ok" and not coverage["components"]
    assert all(
        "discovery" not in call.args[1]
        for call in inventory.inventory_rows.call_args_list
    )


def test_ambiguous_python_installations_are_partial_and_not_arbitrarily_overwritten(
    tmp_path, monkeypatch
):
    site = tmp_path.resolve()
    first = distribution(site, version="1.0")
    second = distribution(site, version="2.0")
    monkeypatch.setattr(
        inventory,
        "inventory_rows",
        lambda *a, **k: [
            row(first, site, "example", "1.0"),
            row(second, site, "example", "2.0"),
        ],
    )
    snapshot = inventory.collect_inventory(options(python_roots=[str(site)]))
    assert snapshot["roots"][0]["status"] == "partial"
    assert snapshot["roots"][0]["components"] == []
    validate_snapshot(SENSOR, snapshot)


@pytest.mark.parametrize("limit", ["entries", "time", "recheck"])
def test_large_python_tree_does_not_block_other_inventory(tmp_path, monkeypatch, limit):
    base = tmp_path.resolve()
    first, large, last = [base / name for name in ("first", "large", "last")]
    distributions = [distribution(site) for site in (first, large, last)]
    tree = large / "package/nested"
    tree.mkdir(parents=True)
    for index in range(20):
        (tree / str(index)).touch()
    queried = False
    if limit == "entries":
        monkeypatch.setattr(inventory, "MAX_ENTRIES", 20)
    else:
        clock = [0]
        monkeypatch.setattr(inventory.time, "monotonic", lambda: clock[0])
        scandir = inventory.os.scandir

        @contextmanager
        def slow_directory(path):
            with scandir(path) as entries:

                def walk():
                    for entry in entries:
                        if Path(path).is_relative_to(large) and (
                            limit == "time" or queried
                        ):
                            clock[0] += 20 if limit == "recheck" else 10
                        yield entry

                yield walk()

        monkeypatch.setattr(inventory.os, "scandir", slow_directory)
    skill = base / "skills/example/SKILL.md"
    plugin = base / "plugins/example/plugin.json"
    config = base / "mcp.json"
    for path in (skill, plugin, config):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    extension_roots = {
        inventory.SOURCES["skills"]: (skill, base / "skills"),
        inventory.SOURCES["mcp"]: (config, config),
        inventory.SOURCES["plugins"]: (plugin, base / "plugins"),
    }

    def query(source, paths, **kwargs):
        nonlocal queried
        queried = True
        if source == inventory.SOURCES["python"]:
            # An incomplete privacy audit must never reach the native table.
            expected = (first, large, last) if limit == "recheck" else (first, last)
            assert paths == list(map(str, expected))
            return [row(path, path.parent) for path in distributions]
        path, root = extension_roots[source]
        assert paths == [str(root)]
        return [
            dict(record="coverage", directory=str(root), status="ok", message=""),
            dict(row(path, root), record="component", metadata="{}"),
        ]

    queries = Mock(side_effect=query)
    monkeypatch.setattr(inventory, "inventory_rows", queries)
    snapshot = inventory.collect_inventory(
        options(
            python_roots=list(map(str, (first, large, last))),
            skill_roots=[str(base / "skills")],
            mcp_configs=[str(config)],
            plugin_roots=[str(base / "plugins")],
        )
    )
    roots = {root["root"]: root for root in snapshot["roots"]}
    assert roots[str(large)]["status"] == "partial"
    assert len(roots[str(large)]["components"]) == (1 if limit == "recheck" else 0)
    message = roots[str(large)]["message"]
    assert (
        "Final" if limit == "recheck" else "Initial"
    ) + " metadata audit:" in message
    assert ("directory-entry limit" if limit == "entries" else "time limit") in message
    for path, root in roots.items():
        if path != str(large):
            assert root["status"] == "ok", root
            assert len(root["components"]) == 1
    assert queries.call_count == 4
    validate_snapshot(SENSOR, snapshot)


def test_many_python_environments_receive_time_for_each_location(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    sites = [base / f"env-{index}" for index in range(20)]
    distributions = [distribution(site) for site in sites]
    clock = [0]
    monkeypatch.setattr(inventory.time, "monotonic", lambda: clock[0])
    check_tree = inventory._Scan.check_tree

    def audit(scan, path):
        check_tree(scan, path)
        clock[0] += 2

    monkeypatch.setattr(inventory._Scan, "check_tree", audit)
    extension_roots = {
        inventory.SOURCES["mcp"]: base / "mcp.json",
        inventory.SOURCES["plugins"]: base / "plugins",
        inventory.SOURCES["skills"]: base / "skills",
    }
    for path in extension_roots.values():
        if path.suffix == ".json":
            path.write_text("{}")
        else:
            path.mkdir()

    def query(source, paths, **kwargs):
        clock[0] += 1
        if source == inventory.SOURCES["python"]:
            assert paths == list(map(str, sites))
            return [row(path, path.parent) for path in distributions]
        assert paths == [str(extension_roots[source])]
        return [dict(record="coverage", directory=paths[0], status="ok", message="")]

    monkeypatch.setattr(inventory, "inventory_rows", query)
    snapshot = inventory.collect_inventory(
        options(
            python_roots=list(map(str, sites)),
            mcp_configs=[str(extension_roots[inventory.SOURCES["mcp"]])],
            plugin_roots=[str(extension_roots[inventory.SOURCES["plugins"]])],
            skill_roots=[str(extension_roots[inventory.SOURCES["skills"]])],
        )
    )
    assert all(root["status"] == "ok" for root in snapshot["roots"])
    assert sum(len(root["components"]) for root in snapshot["roots"]) == len(sites)
    assert clock[0] < inventory.MAX_SECONDS
    validate_snapshot(SENSOR, snapshot)


@pytest.mark.parametrize("stop", ["cancel", "deadline"])
def test_root_budgets_preserve_cancellation_and_snapshot_deadline(
    tmp_path, monkeypatch, stop
):
    base = tmp_path.resolve()
    dist = distribution(base)
    clock = [0]
    cancelled = [False]
    monkeypatch.setattr(inventory.time, "monotonic", lambda: clock[0])

    def query(*args, **kwargs):
        if stop == "cancel":
            cancelled[0] = True
        else:
            clock[0] = inventory.MAX_SECONDS
        return [row(dist, base)]

    queries = Mock(side_effect=query)
    monkeypatch.setattr(inventory, "inventory_rows", queries)
    snapshot = inventory.collect_inventory(
        options(python_roots=[str(base)], skill_roots=[str(base / "skills")]),
        cancelled=lambda: cancelled[0],
    )
    assert queries.call_count == 1
    assert [r["status"] for r in snapshot["roots"]] == ["partial", "error"]
    message = snapshot["roots"][1]["message"]
    assert ("cancelled" if stop == "cancel" else "time limit") in message
    validate_snapshot(SENSOR, snapshot)


def test_limits_and_unsupported_layouts_never_report_complete(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    paths = [package(base / "node_modules" / name, name) for name in ("one", "two")]
    monkeypatch.setattr(
        inventory,
        "inventory_rows",
        lambda *a, **k: [row(path, base, path.parent.name) for path in paths],
    )
    cfg = options(npm_roots=[str(base)])
    monkeypatch.setattr(inventory, "MAX_COMPONENTS", 1)
    limited = inventory.collect_inventory(cfg)
    assert limited["roots"][0]["status"] == "partial"
    assert len(limited["roots"][0]["components"]) <= 1
    validate_snapshot(SENSOR, limited)
    monkeypatch.setattr(inventory, "MAX_COMPONENTS", 10000)
    monkeypatch.setattr(inventory, "MAX_BYTES", 1100)
    limited = inventory.collect_inventory(cfg)
    assert len(json.dumps(limited)) <= 1100
    assert limited["roots"][0]["status"] == "partial"
    monkeypatch.setattr(inventory, "MAX_BYTES", 4 << 20)
    (base / "node_modules/.pnpm").mkdir()
    assert inventory.collect_inventory(cfg)["roots"][0]["status"] == "partial"
    shutil.rmtree(base / "node_modules")
    (base / ".pnp.cjs").write_text("must never execute")
    assert inventory.collect_inventory(cfg)["roots"][0]["status"] == "partial"
    monkeypatch.setattr(inventory, "MAX_ENTRIES", 0)
    package(base / "node_modules/limited")
    queries = Mock(return_value=[])
    monkeypatch.setattr(inventory, "inventory_rows", queries)
    assert inventory.collect_inventory(cfg)["roots"][0]["status"] == "partial"
    queries.assert_not_called()


@pytest.mark.parametrize(
    "values",
    [
        {"enabled": 1},
        {"include_default_roots": "yes"},
        {"project_roots": "~/project"},
        {"project_roots": ["relative"]},
        {"npm_roots": ["/bad\0path"]},
        {"python_roots": ["/bad\ud800path"]},
        {"app_roots": ["/app"] * 65},
        {"skill_roots": ["relative"]},
    ],
)
def test_invalid_config_is_rejected(values):
    with pytest.raises(ValueError):
        options(**values)


@pytest.mark.parametrize("command", ["component-inventory", "inventory"])
def test_local_cli_needs_no_enrollment_or_upload(
    tmp_path, monkeypatch, capsys, command
):
    scan = Mock(return_value={"schema_version": 1, "roots": []})
    monkeypatch.setattr(inventory, "collect_inventory", scan)
    monkeypatch.setattr(
        Config, "load", Mock(side_effect=AssertionError("no enrollment"))
    )
    if command == "inventory":
        assert cli.main([command, "--json"]) == 0
        assert json.loads(capsys.readouterr().out) == scan.return_value
        assert scan.call_args.args[0] == inventory.settings({})
        return
    assert (
        cli.main(
            [
                "component-inventory",
                "--json",
                "--no-default-roots",
                "--project-root",
                str(tmp_path),
                "--skill-root",
                str(tmp_path / "skills"),
                "--mcp-config",
                str(tmp_path / "mcp.json"),
                "--plugin-root",
                str(tmp_path / "plugins"),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == scan.return_value
    assert scan.call_args.args[0]["project_roots"] == [str(tmp_path.resolve())]
    assert scan.call_args.args[0]["skill_roots"] == [str(tmp_path.resolve() / "skills")]
    assert scan.call_args.args[0]["mcp_configs"] == [
        str(tmp_path.resolve() / "mcp.json")
    ]
    assert scan.call_args.args[0]["plugin_roots"] == [
        str(tmp_path.resolve() / "plugins")
    ]


@pytest.mark.skipif(
    sys.platform != "darwin"
    or not (osquery_runtime.runtime_directory() / "osqueryi").is_file(),
    reason="requires the staged pinned macOS osquery runtime",
)
def test_real_osquery_collectors_share_a_snapshot_despite_a_large_python_tree(
    tmp_path, monkeypatch
):
    # A SQL-looking pathname verifies that roots are literal values. Package
    # scripts and application environment values must never run or be uploaded.
    base = (tmp_path / "project's; SELECT 1;").resolve()
    app = base / "Applications/Fixture.app/Contents/Info.plist"
    app.parent.mkdir(parents=True)
    app.write_bytes(
        plistlib.dumps(
            {
                "CFBundleIdentifier": "com.example.fixture",
                "CFBundleName": "Fixture",
                "CFBundleShortVersionString": "1.2",
                "LSEnvironment": {"TOKEN": "private-secret"},
            }
        )
    )
    for name, fmt in (
        ("Binary", plistlib.FMT_BINARY),
        ("Declarationless", plistlib.FMT_XML),
    ):
        metadata = base / f"Applications/{name}.app/Contents/Info.plist"
        metadata.parent.mkdir(parents=True)
        body = plistlib.dumps(
            {"CFBundleIdentifier": name, "CFBundleName": name}, fmt=fmt
        )
        metadata.write_bytes(
            body if fmt == plistlib.FMT_BINARY else body.split(b"\n", 1)[1]
        )
    skill = base / ".agents/skills/fixture/SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text(
        "---\nname: fixture\ndescription: Test skill\n---\nprivate-skill-body\n"
    )
    (base / ".mcp.json").write_text('{"mcpServers": {"docs": {}}}')
    plugin = base / "plugins/fixture/.codex-plugin/plugin.json"
    plugin.parent.mkdir(parents=True)
    plugin.write_text('{"name": "fixture", "version": "1.0"}')
    manifest = package(base / "node_modules/@scope/agent", "@scope/agent", "2.0")
    manifest.write_text(
        json.dumps(
            {
                "name": "@scope/agent",
                "version": "2.0",
                "scripts": {"postinstall": "never-run-this"},
                "token": "private-secret",
            }
        )
    )
    package(manifest.parent / "node_modules/nested", "nested", "3.0")
    (base / "node_modules/removed/lib/.empty").mkdir(parents=True)
    site = base / ".venv/lib/python3.13/site-packages"
    other = base / "venv/lib/python3.13/site-packages"
    distribution(site)
    distribution(other, version="2.0")
    large = base / "large-site-packages"
    distribution(large)
    tree = large / "package/nested"
    tree.mkdir(parents=True)
    for index in range(20):
        (tree / str(index)).touch()
    monkeypatch.setattr(inventory, "MAX_ENTRIES", 20)
    cfg = options(
        project_roots=[str(base)],
        app_roots=[str(base / "Applications")],
        python_roots=[str(large)],
        plugin_roots=[str(base / "plugins")],
    )
    snapshot = inventory.collect_inventory(cfg)
    assert len(snapshot["roots"]) == 8
    for root in snapshot["roots"]:
        if root["root"] == str(large):
            assert root["status"] == "partial" and not root["components"]
        else:
            assert root["status"] == "ok", root
    apps = next(r for r in snapshot["roots"] if r["source"] == "osquery-apps")
    assert {
        item["identifier"]: item.get("version", "") for item in apps["components"]
    } == {"com.example.fixture": "1.2", "Binary": "", "Declarationless": ""}
    skills = next(r for r in snapshot["roots"] if r["source"] == "openaidr-skills")
    assert [item["name"] for item in skills["components"]] == ["fixture"]
    mcp = next(r for r in snapshot["roots"] if r["source"] == "openaidr-mcp-servers")
    assert [item["name"] for item in mcp["components"]] == ["docs"]
    plugins = next(r for r in snapshot["roots"] if r["source"] == "openaidr-plugins")
    assert [item["name"] for item in plugins["components"]] == ["fixture"]
    assert "private-skill-body" not in json.dumps(snapshot)
    npm = next(r for r in snapshot["roots"] if r["source"] == "osquery-npm-packages")
    assert [item["key"] for item in npm["components"]] == [
        "node_modules/@scope/agent",
        "node_modules/@scope/agent/node_modules/nested",
    ]
    python = [
        r
        for r in snapshot["roots"]
        if r["source"] == "osquery-python-packages" and r["root"] != str(large)
    ]
    assert len({r["root"] for r in python}) == 2
    assert {r["components"][0]["key"] for r in python} == {
        "distribution/example-package"
    }
    assert "private-secret" not in json.dumps(
        snapshot
    ) and "postinstall" not in json.dumps(snapshot)
    validate_snapshot(SENSOR, snapshot)
    # Upgrading a distribution preserves its collector key in that environment.
    old = python[0]["components"][0]
    shutil.rmtree(Path(old["path"]))
    distribution(Path(python[0]["root"]), version="9.0")
    broken = base / "Applications/Broken.app/Contents/Info.plist"
    broken.parent.mkdir(parents=True)
    broken.write_bytes(b"invalid plist")
    flat = base / "Applications/Flat.app/Info.plist"
    flat.parent.mkdir(parents=True)
    flat.write_bytes(plistlib.dumps({"CFBundleIdentifier": "flat"}))
    updated = inventory.collect_inventory(cfg)
    updated_apps = next(r for r in updated["roots"] if r["source"] == "osquery-apps")
    assert updated_apps["status"] == "partial"
    assert updated_apps["components"] == apps["components"]
    validate_snapshot(SENSOR, updated)
    current = next(r for r in updated["roots"] if r["root"] == python[0]["root"])
    assert current["components"][0]["key"] == old["key"]
    assert current["components"][0]["version"] == "9.0"
    rows, _ = osquery_runtime._query("SELECT * FROM openaidr_apps;")
    assert rows == []
    protected = "/Users/openaidr-fixture/Library/Application Support/Claude/Private.app"
    rows = osquery_runtime.inventory_rows(
        "osquery-apps", [str(app.parent.parent), protected]
    )
    assert [r["identifier"] for r in rows] == ["com.example.fixture"]


@pytest.mark.skipif(
    sys.platform != "darwin"
    or not (osquery_runtime.runtime_directory() / "osqueryi").is_file(),
    reason="requires the staged pinned macOS osquery runtime",
)
def test_real_osquery_skill_extension_metadata_and_coverage(tmp_path):
    root = (tmp_path / "skills'; SELECT 1;").resolve()
    manifest = root / ".system/example/SKILL.md"
    manifest.parent.mkdir(parents=True)
    manifest.write_bytes(
        b"\xef\xbb\xbf"
        + (
            b"---\nname: example\ndescription: |\n  Fixture\n  ---\n"
            b"metadata:\n  version: 1.0\n  token: private-token\n---\n"
            b"Private body: !`never-run`\n"
        ).replace(b"\n", b"\r\n")
    )
    broken = root / "broken/SKILL.md"
    broken.parent.mkdir()
    broken.write_text("---\nname: [broken\n---\n")
    empty = tmp_path.resolve() / "empty"
    empty.mkdir()
    missing = tmp_path.resolve() / "missing"
    snapshot = inventory.collect_inventory(
        options(skill_roots=list(map(str, [root, empty, missing])))
    )
    assert [r["status"] for r in snapshot["roots"]] == ["partial", "ok", "unavailable"]
    assert len(snapshot["roots"][0]["components"]) == 1
    item = snapshot["roots"][0]["components"][0]
    assert item["key"] == ".system/example/SKILL.md" and item["version"] == "1.0"
    assert item["metadata"]["description"] == "Fixture\n---"
    assert "private-token" not in json.dumps(
        snapshot
    ) and "Private body" not in json.dumps(snapshot)
    validate_snapshot(SENSOR, snapshot)
    # A broad SQL query must not cause the extension to traverse the filesystem.
    rows, _ = osquery_runtime._query("SELECT * FROM openaidr_skills;")
    assert rows == []


@pytest.mark.skipif(
    sys.platform != "darwin"
    or not (osquery_runtime.runtime_directory() / "osqueryi").is_file(),
    reason="requires the staged pinned macOS osquery runtime",
)
def test_real_osquery_mcp_configuration_privacy_and_coverage(tmp_path):
    base = (tmp_path / "config's; SELECT 1;").resolve()
    base.mkdir()
    config = base / ".claude.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "docs": {
                        "command": "sh",
                        "args": ["-c", f"touch {base / 'executed'}"],
                        "env": {"TOKEN": "private-token"},
                        "url": "https://private-user:private-password@example.com/private-path?token=private-token",
                        "headers": {"Authorization": "private-auth"},
                    }
                },
                "projects": {
                    "/fixture/project": {"mcpServers": {"docs": {"disabled": True}}}
                },
            }
        )
    )
    toml = base / "config.toml"
    toml.write_text('[mcp_servers.docs]\nurl = "https://example.com/private-token"\n')
    broken = base / "broken.json"
    broken.write_text('{"mcpServers": {"broken": "private-invalid", "good": {}}}')
    empty = base / "empty.json"
    empty.write_text('{"mcpServers": {}}')
    missing = base / "missing.json"
    snapshot = inventory.collect_inventory(
        options(mcp_configs=list(map(str, [config, toml, broken, empty, missing])))
    )
    assert [r["status"] for r in snapshot["roots"]] == [
        "ok",
        "ok",
        "partial",
        "ok",
        "unavailable",
    ]
    assert [len(r["components"]) for r in snapshot["roots"]] == [2, 1, 1, 0, 0]
    assert all(
        c["kind"] == "mcp_server" and c["evidence"] == "configured"
        for r in snapshot["roots"]
        for c in r["components"]
    )
    assert "private-" not in json.dumps(snapshot) and not (base / "executed").exists()
    validate_snapshot(SENSOR, snapshot)
    rows, _ = osquery_runtime._query("SELECT * FROM openaidr_mcp_servers;")
    assert rows == []
    # The frozen extension must also enforce app-data exclusions when called
    # directly, without the sensor's discovery checks.
    protected = "/Users/openaidr-fixture/Library/Application Support/Claude/config.json"
    rows = osquery_runtime.inventory_rows(
        "openaidr-mcp-servers", [str(config), protected]
    )
    blocked = next(r for r in rows if r["path"] == protected)
    assert blocked["record"] == "coverage" and blocked["status"] == "unavailable"
    assert "privacy prompts" in blocked["message"]
    assert any(r["record"] == "component" and r["name"] == "docs" for r in rows)


@pytest.mark.skipif(
    sys.platform != "darwin"
    or not (osquery_runtime.runtime_directory() / "osqueryi").is_file(),
    reason="requires the staged pinned macOS osquery runtime",
)
def test_real_osquery_plugin_metadata_privacy_and_coverage(tmp_path):
    from openaidr.sensor.plugin_inventory import PORTABLE_SCHEMA

    root = (tmp_path / "plugins'; SELECT 1;").resolve()
    manifest = root / "fixture/plugin.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_bytes(
        b"\xef\xbb\xbf"
        + json.dumps(
            {
                "$schema": PORTABLE_SCHEMA,
                "name": "fixture",
                "version": "1.0",
                "repository": "https://github.com/example/fixture",
                "author": {"name": "Example", "email": "private-email"},
                "extensions": {
                    "com.openai": {
                        "mcpServers": {"docs": {"env": {"TOKEN": "private-token"}}}
                    }
                },
                "hooks": {"command": f"touch {root / 'executed'}"},
            }
        ).encode()
    )
    broken = root / "broken/.codex-plugin/plugin.json"
    broken.parent.mkdir(parents=True)
    broken.write_text("private-invalid")
    declared = root / "declared/.claude-plugin/plugin.json"
    declared.parent.mkdir(parents=True)
    declared.write_text('{"name":"declared-plugin","skills":"./skills"}')
    skill = declared.parent.parent / "skills/review/SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: review\n---\nprivate-skill-body\n")
    external = tmp_path.resolve() / "external/SKILL.md"
    external.parent.mkdir()
    external.write_text("---\nname: private-external\n---\n")
    (skill.parent.parent / "escape").symlink_to(
        external.parent, target_is_directory=True
    )
    linked_file = skill.parent.parent / "linked/SKILL.md"
    linked_file.parent.mkdir()
    linked_file.symlink_to(external)
    empty = tmp_path.resolve() / "empty"
    empty.mkdir()
    missing = tmp_path.resolve() / "missing"
    snapshot = inventory.collect_inventory(
        options(plugin_roots=list(map(str, [root, empty, missing])))
    )
    assert [r["status"] for r in snapshot["roots"]] == [
        "partial",
        "ok",
        "unavailable",
        "partial",
    ]
    assert len(snapshot["roots"][0]["components"]) == 2
    item = next(c for c in snapshot["roots"][0]["components"] if c["name"] == "fixture")
    assert (item["key"], item["kind"], item["evidence"], item["version"]) == (
        "fixture/plugin.json",
        "plugin",
        "declared",
        "1.0",
    )
    assert item["metadata"] == {"repository_url": "https://github.com/example/fixture"}
    assert "private-" not in json.dumps(snapshot) and not (root / "executed").exists()
    (link,) = snapshot["roots"][0]["relationships"]
    assert link["kind"] == "provides" and link["path"] == str(declared)
    assert link["to"]["root"] == str(skill.parent.parent)
    assert link["to"]["key"] == "review/SKILL.md"
    validate_snapshot(SENSOR, snapshot)
    rows, _ = osquery_runtime._query("SELECT * FROM openaidr_plugins;")
    assert rows == []
