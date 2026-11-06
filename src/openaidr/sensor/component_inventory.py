"""Bounded CLI inventory, plus macOS components from the bundled osquery runtime."""

import errno
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from openaidr.core.event import now
from .hostinfo import user_from_path
from .osquery_runtime import OsqueryError, inventory_rows
from .privacy import PrivacyGuard, PrivacySkip, SKIPPED
from .workbuddy import config_roots as workbuddy_roots

SOURCES = {
    "apps": "osquery-apps",
    "npm": "osquery-npm-packages",
    "python": "osquery-python-packages",
    "mcp": "openaidr-mcp-servers",
    "plugins": "openaidr-plugins",
    "skills": "openaidr-skills",
    "bin": "openaidr-cli",
}
MAX_ROOTS = 256
MAX_COMPONENTS = 10000
MAX_RELATIONSHIPS = 20000
MAX_BYTES = 4 << 20
MAX_ENTRIES = 100000
MAX_SECONDS = 120


def settings(config):
    values = config.get("inventory", {}).get("components", {})
    if not isinstance(values, dict):
        raise ValueError("inventory.components must be a mapping")
    result = {}
    guard = PrivacyGuard()
    for key in ("enabled", "include_default_roots"):
        result[key] = values.get(key, True)
        if type(result[key]) is not bool:
            raise ValueError(f"inventory.components.{key} must be a boolean")
    for key in (
        "project_roots",
        "app_roots",
        "npm_roots",
        "python_roots",
        "skill_roots",
        "mcp_configs",
        "plugin_roots",
        "bin_roots",
    ):
        paths = values.get(key, [])
        if not isinstance(paths, list) or len(paths) > 64:
            raise ValueError(
                f"inventory.components.{key} must be a list of at most 64 paths"
            )
        result[key] = []
        for path in paths:
            if not _text(path, 2048) or not Path(path).expanduser().is_absolute():
                raise ValueError(f"inventory.components.{key} requires absolute paths")
            path = Path(path).expanduser()
            # Keep a config file's final symlink and suffix: it identifies the
            # client location and selects its JSON or TOML format.
            try:
                resolved = str(
                    guard.check(path.parent) / path.name
                    if key == "mcp_configs"
                    else guard.check(path)
                )
            except PrivacySkip:
                # Keep the locator for coverage without traversing it at setup.
                resolved = str(path)
            if not _text(resolved, 2048):
                raise ValueError(
                    f"inventory.components.{key} contains an invalid resolved path"
                )
            result[key].append(resolved)
        result[key] = list(dict.fromkeys(result[key]))
    return result


def _text(value, limit):
    if not isinstance(value, str) or not value or len(value) > limit or "\0" in value:
        return False
    try:
        value.encode("utf-8")
        return True
    except UnicodeError:
        return False


class _Limit(Exception):
    pass


def _query_failure(exc):
    if isinstance(exc, (OsqueryError, _Limit)):
        return str(exc)
    # Exception text can contain metadata or process output. Report only the
    # category for errors that do not carry a fixed runtime diagnostic.
    if isinstance(exc, OSError):
        return f"Operating-system error ({errno.errorcode.get(exc.errno, 'OSError')})."
    if isinstance(exc, ValueError):
        return f"Invalid scan data ({type(exc).__name__})."
    return f"Metadata collection failed ({type(exc).__name__})."


class _Scan:
    def __init__(self, cancelled=lambda: False):
        self.deadline = time.monotonic() + MAX_SECONDS
        self.entries = 0
        self.cancelled = cancelled
        self.privacy = PrivacyGuard()

    def check(self):
        if self.cancelled():
            raise _Limit("Scan cancelled.")
        if time.monotonic() >= self.deadline:
            raise _Limit("Scan reached its time limit.")

    def share(self, remaining, weight=1):
        """Give the next source or root a share of the remaining work time."""
        scan = _Scan(self.cancelled)
        current = time.monotonic()
        scan.deadline = current + (self.deadline - current) * weight / remaining
        scan.privacy = self.privacy
        return scan

    def entries_at(self, path):
        self.check()
        self.privacy.check(path)
        with os.scandir(path) as entries:
            for entry in entries:
                self.check()
                if self.entries >= MAX_ENTRIES:
                    raise _Limit("Scan reached its directory-entry limit.")
                self.entries += 1
                yield entry

    def check_tree(self, path):
        # The native python_packages table lists directories recursively, even
        # though our inventory only uses top-level distribution metadata.
        pending, visited = [Path(path)], set()
        while pending:
            self.check()
            path = self.privacy.check(pending.pop())
            if path in visited:
                continue
            visited.add(path)
            for entry in self.entries_at(path):
                self.privacy.check(entry.path)
                if entry.is_dir():
                    pending.append(Path(entry.path))

    def expand(self, base, pattern):
        """Expand known directory layouts, without recursive globs or silent errors."""
        paths = [Path(base)]
        for part in Path(pattern).parts:
            if part == "/":
                continue
            next_paths = []
            for path in paths:
                if "*" in part:
                    try:
                        for entry in self.entries_at(path):
                            if fnmatch.fnmatchcase(entry.name, part):
                                self.privacy.check(entry.path)
                                if entry.is_dir():
                                    next_paths.append(Path(entry.path))
                    except FileNotFoundError:
                        continue
                else:
                    next_paths.append(path / part)
            paths = next_paths
        for path in paths:
            try:
                self.privacy.check(path)
                if stat.S_ISDIR(path.stat().st_mode):
                    yield path
            except FileNotFoundError:
                continue


def _partial(root, message):
    if root["status"] in ("ok", "partial"):
        root["status"] = "partial"
        if message not in root.get("message", ""):
            root["message"] = (root.get("message", "") + " " + message).strip()[:2048]


def _discover(options, previous, scan):
    roots = {}
    problems = set()
    discovery_sources = set()
    supported_sources = SOURCES.values() if sys.platform == "darwin" else (SOURCES["bin"],)
    home = Path.home()
    home_user = user_from_path(str(home) + "/")

    def add(kind, path, scope, environment="", user=""):
        path = Path(path)
        status, message = "ok", ""
        try:
            resolved = scan.privacy.check(path)
            path = str(
                scan.privacy.check(path.parent) / path.name
                if kind == "mcp"
                else resolved
            )
        except PrivacySkip as exc:
            path = str(path)
            status, message = "unavailable", str(exc) or SKIPPED
        except OSError:
            path = str(path)
            status, message = "error", "Inventory location could not be inspected."
        if not _text(path, 2048):
            problems.add(SOURCES[kind])
            return
        key = (SOURCES[kind], path)
        roots[key] = dict(
            source=key[0],
            root=path,
            scope=scope,
            user=user,
            environment=str(environment),
            status=status,
            message=message,
            components=[],
            relationships=[],
        )

    def expand(kind, patterns, scope, user="", environment="", base="/"):
        for pattern in patterns:
            try:
                for path in scan.expand(base, pattern):
                    add(kind, path, scope, environment or str(path), user)
                    if len(roots) >= MAX_ROOTS:
                        raise _Limit()
            except (OSError, ValueError, _Limit):
                problems.add(SOURCES[kind])

    def configs(paths, scope, user="", environment=""):
        for path in paths:
            try:
                scan.check()
                path = Path(path)
                scan.privacy.check(path)
                path.lstat()
                add("mcp", path, scope, environment, user)
                if len(roots) >= MAX_ROOTS:
                    raise _Limit()
            except FileNotFoundError:
                continue
            except PrivacySkip:
                add("mcp", path, scope, environment, user)
            except (OSError, ValueError, _Limit):
                problems.add(SOURCES["mcp"])

    if options["include_default_roots"]:
        expand("bin", (".local/bin", "bin"), "user", home_user, base=home)
        if sys.platform == "win32":
            local = Path(os.environ.get("LOCALAPPDATA") or home / "AppData/Local")
            roaming = Path(os.environ.get("APPDATA") or home / "AppData/Roaming")
            expand("bin", ("hermes/bin", "Microsoft/WinGet/Links", "Programs/Python/Python*/Scripts"),
                   "user", home_user, base=local)
            expand("bin", ("npm", "Python/Python*/Scripts"), "user", home_user, base=roaming)
        else:
            paths = ("/opt/homebrew/bin", "/usr/local/bin") if sys.platform == "darwin" else ("/usr/local/bin",)
            expand("bin", paths, "system")
            expand("bin", (".npm-global/bin", ".nvm/versions/node/*/bin"), "user", home_user, base=home)

    if options["include_default_roots"] and sys.platform == "darwin":
        # Let the scan guard resolve this environment path before touching it.
        codex = Path(os.environ.get("CODEX_HOME") or home / ".codex").expanduser()

        expand("skills", ("/etc/codex/skills",), "system")
        expand(
            "skills", (".agents/skills", ".claude/skills"), "user", home_user, base=home
        )
        try:
            expand("skills", ("skills",), "user", home_user, base=codex)
        except (OSError, ValueError):
            problems.add(SOURCES["skills"])
        expand(
            "plugins",
            (".claude/plugins/cache", ".cursor/plugins/local"),
            "user",
            home_user,
            base=home,
        )
        try:
            expand("plugins", ("plugins/cache",), "user", home_user, base=codex)
        except (OSError, ValueError):
            problems.add(SOURCES["plugins"])
        configs(
            (
                home / ".claude.json",
                home / ".cursor/mcp.json",
                home / "Library/Application Support/Claude/claude_desktop_config.json",
            ),
            "user",
            home_user,
        )
        try:
            configs((codex / "config.toml",), "user", home_user)
        except (OSError, ValueError):
            problems.add(SOURCES["mcp"])
        for root in workbuddy_roots(home):
            expand("skills", ("skills",), "user", home_user, base=root)
            expand("plugins", ("plugins/cache", "plugins/marketplaces"), "user", home_user, base=root)
            configs((root / "mcp.json",), "user", home_user)
        for path in (
            "/Applications",
            "/System/Applications",
            "/System/Library/CoreServices/Applications",
        ):
            add("apps", path, "system")
        add("apps", home / "Applications", "user", user=home_user)
        expand("npm", ("/opt/homebrew/lib", "/usr/local/lib"), "system")
        expand(
            "npm",
            (
                ".npm-global/lib",
                ".nvm/versions/node/*/lib",
                ".asdf/installs/nodejs/*/lib",
                ".local/share/mise/installs/node/*/lib",
                ".local/share/fnm/node-versions/*/installation/lib",
                ".volta/tools/image/node/*/lib",
            ),
            "user",
            home_user,
            base=home,
        )
        expand(
            "python",
            (
                "/opt/homebrew/lib/python*/site-packages",
                "/usr/local/lib/python*/site-packages",
                "/Library/Python/*/site-packages",
                "/Library/Frameworks/Python.framework/Versions/*/lib/python*/site-packages",
            ),
            "system",
        )
        expand(
            "python",
            (
                "Library/Python/*/lib/python/site-packages",
                "Library/Python/*/site-packages",
                ".local/lib/python*/site-packages",
                ".pyenv/versions/*/lib/python*/site-packages",
                ".local/share/uv/tools/*/lib/python*/site-packages",
                ".local/share/pipx/venvs/*/lib/python*/site-packages",
                ".local/pipx/venvs/*/lib/python*/site-packages",
                "Library/Caches/pypoetry/virtualenvs/*/lib/python*/site-packages",
                ".virtualenvs/*/lib/python*/site-packages",
                "miniconda3/lib/python*/site-packages",
                "miniconda3/envs/*/lib/python*/site-packages",
                "miniforge3/lib/python*/site-packages",
                "miniforge3/envs/*/lib/python*/site-packages",
            ),
            "user",
            home_user,
            base=home,
        )
    for project in options["project_roots"] if sys.platform == "darwin" else ():
        add("npm", project, "project", project)
        configs(
            (
                Path(project) / name
                for name in (".mcp.json", ".cursor/mcp.json", ".codex/config.toml")
            ),
            "project",
            environment=project,
        )
        expand(
            "skills",
            (".agents/skills", ".claude/skills", ".codex/skills"),
            "project",
            environment=project,
            base=project,
        )
        expand(
            "python",
            [
                str(Path(name) / "lib/python*/site-packages")
                for name in (".venv", "venv")
            ],
            "project",
            environment=project,
            base=project,
        )
    for kind, option in (
        ("apps", "app_roots"),
        ("npm", "npm_roots"),
        ("python", "python_roots"),
        ("skills", "skill_roots"),
        ("mcp", "mcp_configs"),
        ("plugins", "plugin_roots"),
        ("bin", "bin_roots"),
    ):
        if sys.platform != "darwin" and kind != "bin":
            continue
        for path in options[option]:
            add(kind, path, "unknown", path)
    # Keep coverage for previously discovered environments after their directory
    # disappears or a discovery parent becomes unreadable. Never infer removal.
    for old in previous:
        if sys.platform != "darwin" and old["source"] != SOURCES["bin"]:
            continue
        if old["root"] == "discovery":
            discovery_sources.add(old["source"])
            continue
        key = (old["source"], old["root"])
        if key not in roots:
            roots[key] = {
                **old,
                "status": "ok",
                "message": "",
                "components": [],
                "relationships": [],
            }
    if len(roots) > MAX_ROOTS:
        problems.update(supported_sources)
    discovery_sources.update(problems)
    limit = MAX_ROOTS - len(discovery_sources)
    if len(roots) > limit:
        problems.update(supported_sources)
        discovery_sources.update(problems)
        limit = MAX_ROOTS - len(discovery_sources)
    result = list(roots.values())[:limit]
    for root in result:
        if root["source"] in problems:
            _partial(root, "Root discovery was incomplete or reached its limit.")
    # Report discovery failures even on the first scan, when no installation
    # roots are known yet. This reserved locator is never passed to osquery.
    for source in sorted(discovery_sources):
        result.append(
            dict(
                source=source,
                root="discovery",
                scope="unknown",
                status="partial" if source in problems else "ok",
                message="Root discovery was incomplete or reached its limit."
                if source in problems
                else "Root discovery completed for configured locations.",
                components=[],
                relationships=[],
            )
        )
    return result


def _metadata_paths(root, scan, *, before_query=True):
    """Audit metadata paths; return None if a native preflight reaches a limit."""
    base = Path(root["root"])
    found = {}
    started, entries_before = time.monotonic(), scan.entries

    def native_path(path):
        resolved = scan.privacy.check(path)
        if any(char in str(path) or char in str(resolved) for char in "*?[]{}%\\"):
            raise PrivacySkip("osquery cannot constrain a path with glob characters.")

    def record(path, metadata):
        scan.privacy.check(metadata)
        info = metadata.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1 << 20:
            _partial(root, "Metadata is not a regular file or exceeds 1 MiB.")
            return
        found[str(path)] = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        if len(found) >= MAX_COMPONENTS:
            raise _Limit("Root reached its metadata limit.")

    def apps(path, depth=0):
        for entry in scan.entries_at(path):
            try:
                scan.privacy.check(entry.path)
            except PrivacySkip:
                _partial(root, SKIPPED)
                continue
            if entry.is_symlink():
                _partial(root, "Symlinked application locations were not traversed.")
            elif entry.is_dir(follow_symlinks=False):
                if entry.name.endswith(".app"):
                    try:
                        record(
                            Path(entry.path), Path(entry.path) / "Contents/Info.plist"
                        )
                    except OSError:
                        _partial(root, "An application bundle has unreadable metadata.")
                elif depth < 3:
                    apps(entry.path, depth + 1)
                else:
                    _partial(root, "Application directory depth exceeded three levels.")

    def empty_tree(path):
        # Package removal can leave directories behind. Only ignore a remnant
        # after checking its entire tree, without following links or reading files.
        pending = [path]
        while pending:
            for entry in scan.entries_at(pending.pop()):
                scan.privacy.check(entry.path)
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    return False
                pending.append(entry.path)
        return True

    def npm(path, depth=0):
        native_path(path)
        modules = Path(path) / "node_modules"
        try:
            entries = list(scan.entries_at(modules))
        except FileNotFoundError:
            return
        for entry in entries:
            scan.privacy.check(entry.path)
            if entry.name.startswith("."):
                if entry.name not in (".bin", ".package-lock.json"):
                    _partial(root, "Hidden package layouts are not fully covered.")
                continue
            packages = (
                scan.entries_at(entry.path)
                if entry.name.startswith("@") and entry.is_dir()
                else [entry]
            )
            for package in packages:
                scan.privacy.check(package.path)
                if package.is_symlink():
                    _partial(
                        root, f"Linked package is not fully covered: {package.path}"
                    )
                if not package.is_dir():
                    continue
                try:
                    record(
                        Path(package.path) / "package.json",
                        Path(package.path) / "package.json",
                    )
                except PrivacySkip:
                    raise
                except OSError as exc:
                    if isinstance(exc, FileNotFoundError) and empty_tree(package.path):
                        continue
                    reason = errno.errorcode.get(exc.errno, type(exc).__name__)
                    _partial(
                        root,
                        f"Cannot read package manifest ({reason}): "
                        f"{Path(package.path) / 'package.json'}",
                    )
                if depth < 8:
                    npm(package.path, depth + 1)
                else:
                    nested = Path(package.path) / "node_modules"
                    scan.privacy.check(nested)
                    if nested.exists():
                        _partial(root, "Nested package traversal was incomplete.")

    try:
        # A missing root is unavailable, including a removed virtual environment.
        # Retain the server's earlier components until removal is established.
        scan.privacy.check(base)
        with os.scandir(base):
            pass
        if root["source"] == SOURCES["apps"]:
            apps(base)
        elif root["source"] == SOURCES["npm"]:
            for name in (".pnp.cjs", ".pnp.js"):
                scan.privacy.check(base / name)
                if (base / name).exists():
                    _partial(root, "Yarn Plug'n'Play is not covered by npm_packages.")
            npm(base)
        else:
            native_path(base)
            if before_query:
                scan.check_tree(base)
            for entry in scan.entries_at(base):
                # osquery tests every entry's directory type before its suffix.
                scan.privacy.check(entry.path)
                suffix = Path(entry.name).suffix
                if suffix in (".dist-info", ".egg-info"):
                    metadata = "METADATA" if suffix == ".dist-info" else "PKG-INFO"
                    scan.privacy.check(Path(entry.path) / metadata)
                    if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                        _partial(
                            root, "Linked or file-based Python metadata is not covered."
                        )
                        continue
                    try:
                        record(Path(entry.path), Path(entry.path) / metadata)
                    except PrivacySkip:
                        raise
                    except OSError:
                        _partial(
                            root, "A distribution has unreadable or missing metadata."
                        )
                elif suffix in (".egg-link", ".egg"):
                    _partial(root, "Legacy Python egg installations are not covered.")
    except PrivacySkip as exc:
        # Native package tables traverse a root themselves. Do not give osquery
        # a root containing an unsafe link, even if other metadata was readable.
        root.update(status="unavailable", message=str(exc))
        found.clear()
    except FileNotFoundError:
        root.update(status="unavailable", message="Inventory location is unavailable.")
    except OSError:
        if root["source"] == SOURCES["apps"]:
            _partial(root, "A directory could not be read completely.")
        else:
            root.update(
                status="unavailable",
                message="Package location could not be checked safely before querying osquery.",
            )
            found.clear()
    except _Limit as exc:
        phase = "Initial" if before_query else "Final"
        _partial(
            root,
            f"{phase} metadata audit: {exc} "
            f"Inspected {scan.entries - entries_before} directory entries "
            f"in {time.monotonic() - started:.2f} seconds.",
        )
        if before_query and root["source"] != SOURCES["apps"]:
            # Native package tables traverse the entire supplied root. Never
            # query one whose privacy audit stopped before checking every path.
            return None
    return found


def _component(root, row):
    path = row["path"]
    name = row.get("name", "").strip()
    source = root["source"]
    kind, ecosystem = (
        ("application", "")
        if source == SOURCES["apps"]
        else ("package", "npm" if source == SOURCES["npm"] else "pypi")
    )
    if source == SOURCES["skills"]:
        kind, ecosystem = "skill", ""
    elif source == SOURCES["mcp"]:
        kind, ecosystem = "mcp_server", ""
    elif source == SOURCES["plugins"]:
        kind, ecosystem = "plugin", ""
    identifier = row.get("identifier", "") or path
    if ecosystem == "pypi":
        identifier = re.sub(r"[-_.]+", "-", name).lower()
        # A wheel's metadata directory includes its version; its installation
        # identity must survive an upgrade within the same environment.
        key = "distribution/" + identifier
    elif source == SOURCES["mcp"]:
        key, identifier = identifier, name
    else:
        if ecosystem == "npm":
            path = str(Path(path).parent)
        key = str(Path(path).relative_to(root["root"]))
    if not all((_text(name, 1024), _text(identifier, 2048), _text(path, 8192))):
        raise ValueError("Invalid component identity")
    if len(key) > 2048:
        key = "sha256/" + hashlib.sha256(key.encode("utf-8")).hexdigest()
    result = dict(
        key=key,
        identifier=identifier,
        name=name,
        kind=kind,
        ecosystem=ecosystem,
        path=path,
        evidence=(
            "configured"
            if source == SOURCES["mcp"]
            else "declared"
            if source == SOURCES["plugins"]
            else "installed"
        ),
    )
    for field, limit in (("version", 256), ("publisher", 1024)):
        value = row.get(field, "").strip()
        if value and _text(value, limit):
            result[field] = value
        elif value:
            _partial(root, "Some metadata fields were invalid or oversized.")
    license_value = row.get("license", "").strip()
    if _text(license_value, 1024) and "://" not in license_value:
        result["metadata"] = {"license": license_value}
    if source in (SOURCES["skills"], SOURCES["plugins"]):
        result["metadata"] = json.loads(row["metadata"])
    return result


def _collect_extension(roots, scan):
    declarations = []
    try:
        scan.check()
        rows = inventory_rows(
            roots[0]["source"],
            [root["root"] for root in roots],
            timeout=min(30, scan.deadline - time.monotonic()),
        )
    except (OSError, RuntimeError, ValueError, _Limit) as exc:
        for root in roots:
            root.update(
                status="error", message=f"Extension query: {_query_failure(exc)}"
            )
        return declarations
    for root in roots:
        selected = [row for row in rows if row.get("directory") == root["root"]]
        coverage = [row for row in selected if row.get("record") == "coverage"]
        if len(coverage) != 1 or coverage[0].get("status") not in (
            "ok",
            "partial",
            "error",
            "unavailable",
        ):
            root.update(
                status="error",
                message="Bundled osquery did not report extension coverage.",
            )
            continue
        status = coverage[0]["status"]
        if status in ("error", "unavailable"):
            root.update(status=status, message=coverage[0]["message"])
            continue
        if status == "partial":
            _partial(root, coverage[0]["message"])
        components = {}
        for row in selected:
            if row.get("record") != "component":
                continue
            try:
                item = _component(root, row)
                if item["key"] in components:
                    raise ValueError("Duplicate component identity")
                components[item["key"]] = item
                if root["source"] == SOURCES["plugins"]:
                    directories = json.loads(row.get("skill_directories") or "[]")
                    if not isinstance(directories, list) or len(directories) > 64:
                        raise ValueError("Invalid skill locations")
                    for directory in directories:
                        if (
                            not _text(directory, 2048)
                            or not Path(directory).is_absolute()
                        ):
                            raise ValueError("Invalid skill location")
                        declarations.append((root, item, directory))
            except (KeyError, ValueError, TypeError):
                _partial(root, "Some extension metadata could not be parsed.")
        root["components"] = sorted(components.values(), key=lambda item: item["key"])
    return declarations


def _declared_skill_roots(roots, declarations, scan):
    links = []
    for owner, plugin, directory in declarations:
        try:
            scan.check()
            base = scan.privacy.check(Path(plugin["path"]).parent.parent)
            target = scan.privacy.check(directory)
            if not target.is_relative_to(base) or str(target) != directory:
                raise ValueError("Skill location escaped its plugin")
            candidates = [
                root
                for root in roots
                if root["source"] == SOURCES["skills"] and root["root"] == directory
            ]
            if candidates:
                skill_root = candidates[0]
            else:
                if len(roots) >= MAX_ROOTS:
                    raise _Limit()
                skill_root = dict(
                    source=SOURCES["skills"],
                    root=directory,
                    scope=owner["scope"],
                    user=owner.get("user", ""),
                    environment=owner.get("environment", ""),
                    status="ok",
                    message="",
                    components=[],
                    relationships=[],
                )
                roots.append(skill_root)
            links.append((owner, plugin, skill_root, directory))
        except (OSError, ValueError, _Limit):
            _partial(owner, "Some declared skill locations could not be collected.")
    return links


def _link_skills(result, links, scan):
    roots = result["roots"]
    retained = {
        id(root): {item["key"] for item in root["components"]} for root in roots
    }
    used = len(json.dumps(result)) + 512 * len(roots)
    seen = set()
    try:
        for owner, plugin, target, directory in links:
            scan.check()
            if id(owner) not in retained or plugin["key"] not in retained[id(owner)]:
                continue
            if id(target) not in retained or target["status"] != "ok":
                _partial(owner, "Declared skill collection was incomplete.")
            if id(target) not in retained:
                continue
            for skill in target["components"]:
                scan.check()
                if not Path(skill["path"]).is_relative_to(directory):
                    continue
                identity = (id(owner), plugin["key"], id(target), skill["key"])
                if identity in seen:
                    continue
                relationship = {
                    "from": dict(
                        source=owner["source"], root=owner["root"], key=plugin["key"]
                    ),
                    "to": dict(
                        source=target["source"], root=target["root"], key=skill["key"]
                    ),
                    "kind": "provides",
                    "evidence": "declared",
                    "path": plugin["path"],
                }
                size = len(json.dumps(relationship)) + 2
                if len(seen) >= MAX_RELATIONSHIPS or used + size > MAX_BYTES:
                    _partial(
                        owner, "Snapshot reached its relationship or payload limit."
                    )
                    continue
                owner["relationships"].append(relationship)
                seen.add(identity)
                used += size
    except _Limit:
        for owner, _, _, _ in links:
            _partial(owner, "Declared skill relationships reached the scan time limit.")


def collect_inventory(options, previous=(), *, cancelled=lambda: False):
    """Collect per-root snapshots; partial scans never authorize removals."""
    if sys.platform not in ("darwin", "linux", "win32"):
        raise RuntimeError("Component collection is unsupported on this platform.")
    scan = _Scan(cancelled)
    roots = _discover(options, previous, scan)
    for root in roots:
        if root["root"] == "discovery":
            continue
        try:
            resolved = scan.privacy.check(root["root"])
            if root["source"] == SOURCES["skills"] and str(resolved) != root["root"]:
                root.update(
                    status="unavailable",
                    message="Skill location now resolves to a different path.",
                )
        except PrivacySkip as exc:
            root.update(status="unavailable", message=str(exc) or SKIPPED)
        except OSError:
            root.update(
                status="error", message="Inventory location could not be inspected."
            )
    platform = "windows" if sys.platform == "win32" else sys.platform
    result = dict(schema_version=1, platform=platform, collected_at=now(), roots=roots)
    active_sources = {
        root["source"]
        for root in roots
        if root["root"] != "discovery" and root["status"] in ("ok", "partial")
    }
    if SOURCES["plugins"] in active_sources:
        active_sources.add(SOURCES["skills"])
    sources = [source for source in SOURCES.values() if source in active_sources]
    links = []
    for index, source in enumerate(sources):
        selected = [
            root
            for root in roots
            if root["source"] == source
            and root["root"] != "discovery"
            and root["status"] in ("ok", "partial")
        ]
        if not selected:
            continue
        # Share time by location so a source with many environments does not
        # receive the same budget as a source with a single configuration file.
        # Recount after plugins add their declared skill locations.
        weights = {
            pending: max(
                1,
                sum(
                    root["source"] == pending
                    and root["root"] != "discovery"
                    and root["status"] in ("ok", "partial")
                    for root in roots
                ),
            )
            for pending in sources[index:]
        }
        source_scan = scan.share(sum(weights.values()), weights[source])
        if source == SOURCES["bin"]:
            from .cli_inventory import collect

            for position, root in enumerate(selected):
                collect(root, source_scan.share(len(selected) - position))
            continue
        if source in (SOURCES["skills"], SOURCES["mcp"], SOURCES["plugins"]):
            declarations = _collect_extension(selected, source_scan)
            if source == SOURCES["plugins"]:
                links = _declared_skill_roots(roots, declarations, source_scan)
            continue
        # Reserve half this source's time for osquery and the metadata recheck.
        # Share audit time across roots so one large tree cannot starve siblings.
        audits = source_scan.share(2)
        scans, before = {}, {}
        for position, root in enumerate(selected):
            root_scan = audits.share(len(selected) - position)
            scans[root["root"]] = root_scan
            before[root["root"]] = _metadata_paths(root, root_scan)
        selected = [
            root
            for root in selected
            if before[root["root"]] is not None and root["status"] in ("ok", "partial")
        ]
        if not selected:
            continue
        paths = (
            [path for root in selected for path in before[root["root"]]]
            if source == SOURCES["apps"]
            else [root["root"] for root in selected]
        )
        try:
            source_scan.check()
            rows = inventory_rows(
                source, paths, timeout=min(30, source_scan.deadline - time.monotonic())
            )
        except (OSError, RuntimeError, ValueError, _Limit) as exc:
            for root in selected:
                root.update(
                    status="error",
                    message=f"Metadata query: {_query_failure(exc)}",
                )
            continue
        for position, root in enumerate(selected):
            if root["status"] not in ("ok", "partial"):
                continue
            expected = before[root["root"]]
            seen, ambiguous, components = set(), set(), {}
            for row in rows:
                path = row.get("path")
                if path not in expected:
                    continue
                if source != SOURCES["apps"] and row.get("directory") != root["root"]:
                    continue
                try:
                    item = _component(root, row)
                    if item["key"] in ambiguous:
                        continue
                    if item["key"] in components and components[item["key"]] != item:
                        del components[item["key"]]
                        ambiguous.add(item["key"])
                        raise ValueError("Ambiguous installation identity")
                    components[item["key"]] = item
                    seen.add(path)
                except (ValueError, TypeError):
                    _partial(root, "Some installed metadata could not be parsed.")
            if seen != set(expected):
                missing = set(expected) - seen
                _partial(
                    root,
                    f"{len(missing)} discovered metadata records could not be read. "
                    f"First missing path: {min(missing)}",
                )
            root_scan = scans[root["root"]]
            root_scan.deadline = source_scan.share(len(selected) - position).deadline
            after = _metadata_paths(root, root_scan, before_query=False)
            if root["status"] in ("ok", "partial"):
                if after != expected:
                    _partial(root, "Installed metadata changed during collection.")
                root["components"] = sorted(
                    components.values(), key=lambda item: item["key"]
                )
    # Bound the whole upload, never split an authoritative root across requests.
    used = len(
        json.dumps({**result, "roots": [{**r, "components": []} for r in roots]})
    )
    used += 512 * len(roots)
    count = 0
    for root in roots:
        kept = []
        for item in root["components"]:
            size = len(json.dumps(item)) + 2
            if count >= MAX_COMPONENTS or used + size > MAX_BYTES:
                _partial(root, "Snapshot reached its component or payload limit.")
                continue
            kept.append(item)
            used += size
            count += 1
        root["components"] = kept
    # Link only retained components so the server can resolve every new endpoint.
    _link_skills(result, links, scan)
    # Long root names can consume the budget even before component records.
    while roots and len(json.dumps(result)) > MAX_BYTES:
        removed = roots.pop()
        for root in roots:
            root["relationships"] = [
                link
                for link in root["relationships"]
                if all(
                    (link[end]["source"], link[end]["root"])
                    != (removed["source"], removed["root"])
                    for end in ("from", "to")
                )
            ]
            _partial(root, "Snapshot reached its root or payload limit.")
    return result
