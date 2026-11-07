"""Coding agent hooks: installation and the local listener behind them.

Claude Code reads hook definitions from ``settings.json`` in its configuration
directory (``CLAUDE_CONFIG_DIR``, default ``~/.claude``). Codex reads
``hooks.json`` in ``CODEX_HOME`` (default ``~/.codex``) and runs a user-level
hook only after its definition has been trusted; that trust is a hash of the
normalized definition recorded in that directory's ``config.toml``. Installed
macOS per-user hooks send stdin directly to the private listener using curl;
other installs run ``openaidr hook``. The listener turns input into events and
requests backend decisions at supported boundaries.
"""

import base64
import copy
import errno
import hashlib
import hmac
import json
import logging
import ntpath
import os
import re
import shlex
import shutil
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import httpx
import psutil
import tomlkit
import tomlkit.exceptions
import tomlkit.items
import yaml
from openaidr.core.event import now
from openaidr.core.hook_protocol import APP_EVENTS, PRODUCTS, ROUTES, controls, normalize
from openaidr.core.files import atomic_write
from openaidr.core.protocol import AGENT_HOOK_TIMEOUTS_NS, HOOK_TIMEOUT_SECONDS, HOOK_WORK_TIMEOUT_SECONDS, WINDOWS_AGENT_HOOK_TIMEOUT_SECONDS
from openaidr.core.reasoning import reasoning_effort
from openaidr.guardrail.hooks import native_response
from .config import Config, default_path as default_config_path, is_root
from .settings_files import content_hash, edit_settings, publication_state
from openaidr.core.toolmap import map_tool
from .collectors import content_text
from .local_http import BoundedThreadingMixIn, HookAdmissionMixIn, LoopbackHTTPServer, loopback_host
from . import hook_runtime, workbuddy

AGENTS = tuple(PRODUCTS)

EVENTS = (
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "UserPromptSubmit",
    "SessionStart",
    "SessionEnd",
    "Stop",
)
# Prompts, tool calls, and supported tool results wait for the backend decision.
# Final observations wait too: Codex can cancel async Stop hooks on exit.
CODEX_EVENTS = {
    "SessionStart": (HOOK_TIMEOUT_SECONDS, True),
    "SubagentStart": (HOOK_TIMEOUT_SECONDS, True),
    "SubagentStop": (HOOK_TIMEOUT_SECONDS, True),
    "UserPromptSubmit": (HOOK_TIMEOUT_SECONDS, False),
    "PreToolUse": (HOOK_TIMEOUT_SECONDS, False),
    "PostToolUse": (HOOK_TIMEOUT_SECONDS, False),
    "Stop": (HOOK_TIMEOUT_SECONDS, False),
    "SessionEnd": (HOOK_TIMEOUT_SECONDS, False),
}
# A hook command's reported start older than this is a clock jump, not latency.
MAX_E2E_MS = 60_000
DECISION_EVENTS = {"PreToolUse", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit"}
CODEX_EVENT_LABELS = {
    "PreToolUse": "pre_tool_use",
    "PostToolUse": "post_tool_use",
    "UserPromptSubmit": "user_prompt_submit",
    "SessionStart": "session_start",
    "SubagentStart": "subagent_start",
    "SubagentStop": "subagent_stop",
    "SessionEnd": "session_end",
    "Stop": "stop",
}


# Each agent's configuration directory, its environment override, and the
# file that holds its hook definitions.
HOMES = {
    "claude": ("CLAUDE_CONFIG_DIR", ".claude", "settings.json"),
    "codex": ("CODEX_HOME", ".codex", "hooks.json"),
    "copilot": ("COPILOT_HOME", ".copilot", "hooks/openaidr.json"),
    "cursor": (None, ".cursor", "hooks.json"),
    "antigravity": (None, ".gemini/config", "hooks.json"),
    "opencode": ("OPENCODE_CONFIG_DIR", ".config/opencode", "plugins/openaidr.js"),
    "hermes": ("HERMES_HOME", ".hermes", "config.yaml"),
    "workbuddy": ("WORKBUDDY_CONFIG_DIR", ".workbuddy-ai", "settings.json"),
}


def _environment_home(agent):
    variable, default, _ = HOMES[agent]
    # Codex canonicalizes CODEX_HOME, and its trust keys use that path; the
    # default ~/.codex is used as is. Claude Code's directory follows suit.
    value = os.environ.get(variable) if variable else None
    if agent == "workbuddy" and value:
        value = value.strip()
    if agent == "opencode" and not value and os.environ.get("XDG_CONFIG_HOME"):
        value = str(Path(os.environ["XDG_CONFIG_HOME"]) / "opencode")
    return Path(value).expanduser().resolve() if value else None


def recorded_home(config, agent):
    """The agent directory a shell recorded for processes without its variable."""
    homes = ((config.get("hooks") or {}).get("homes") if config is not None else None) or {}
    value = homes.get(agent) if isinstance(homes, dict) else None
    return Path(value) if isinstance(value, str) and Path(value).is_absolute() else None


def agent_home(agent, config=None):
    """The directory whose settings this agent's sessions load.

    A shell that sets the variable knows the answer. The desktop app and the
    background service never see shell variables, so they use the directory
    recorded by the last CLI command that ran with it, then the default.
    """
    if agent not in HOMES:
        raise ValueError("unknown agent: " + str(agent))
    if agent == "workbuddy" and not (_environment_home(agent) or recorded_home(config, agent)):
        international, domestic = Path.home() / ".workbuddy-ai", Path.home() / ".workbuddy"
        return domestic if domestic.is_dir() and not international.is_dir() else international
    return (_environment_home(agent) or recorded_home(config, agent)
            or Path.home() / HOMES[agent][1])


def codex_home(config=None):
    return agent_home("codex", config)


def claude_home(config=None):
    return agent_home("claude", config)


def settings_path(agent="claude", config=None):
    return agent_home(agent, config) / HOMES[agent][2]


def codex_config_path(config=None):
    return codex_home(config) / "config.toml"


def codex_paths(config=None):
    """Discover profile directories, keeping profiles with shared config files distinct."""
    selected = settings_path("codex", config)
    paths = {selected: codex_config_path(config)}
    seen = {selected.parent.resolve()}
    for home in sorted(Path.home().glob(".codex*")):
        if home.is_dir() and (home / "config.toml").is_file() and home.resolve() not in seen:
            home = home.resolve()
            seen.add(home)
            paths[home / "hooks.json"] = home / "config.toml"
    return paths


def remember_homes(config):
    """Record agent directories set in this shell for the service and desktop.

    Only a set variable changes the record: a process without it (the service
    or desktop app) cannot tell a custom directory from the default. Setting
    the variable to the default directory clears the record.
    """
    if config is None or not Path(config.path).exists():
        return
    current = Config.load(config.path)
    section = dict(current.get("hooks") or {})
    homes = dict(section.get("homes") or {}) if isinstance(section.get("homes"), dict) else {}
    for agent in HOMES:
        home = _environment_home(agent)
        if home is None:
            continue
        if home == Path.home() / HOMES[agent][1]:
            homes.pop(agent, None)
        else:
            homes[agent] = str(home)
    if homes:
        section["homes"] = homes
    else:
        section.pop("homes", None)
    if section != (current.get("hooks") or {}):
        if section:
            current["hooks"] = section
        else:
            current.pop("hooks", None)
        current.save()
    if section:
        config["hooks"] = section
    else:
        config.pop("hooks", None)


def settings_paths(config=None):
    """Settings paths for ``status`` and checks, as seen by this process."""
    return {**{agent: settings_path(agent, config) for agent in AGENTS},
            "codex_config": codex_config_path(config)}


def detect_apps(config=None):
    """Find local apps without mistaking a Gemini config directory for Antigravity."""
    from .integrations import BINARY_DIRECTORIES

    result = {}
    home = Path.home()
    for agent in APP_EVENTS:
        directories = ([home / ".gemini" / name for name in ("antigravity", "antigravity-cli", "antigravity-ide")]
                       if agent == "antigravity" else [agent_home(agent, config)])
        if sys.platform == "win32" and agent in ("cursor", "antigravity"):
            local = Path(os.environ.get("LOCALAPPDATA") or home / "AppData/Local")
            directories.append(local / ("cursor-agent" if agent == "cursor" else "agy/bin"))
        names = {"cursor": ("cursor", "cursor-agent"), "antigravity": ("agy", "antigravity")}.get(agent, (agent,))
        found = any(path.is_dir() for path in directories) or any(shutil.which(name) for name in names)
        for directory in BINARY_DIRECTORIES + ("~/.opencode/bin",):
            for name in names:
                path = Path(directory).expanduser() / (name + ".exe" if os.name == "nt" else name)
                found = found or (path.is_file() and os.access(path, os.X_OK))
        if agent == "copilot":
            found = found or any(any((home / folder / "extensions").glob("github.copilot-chat-*"))
                                 for folder in (".vscode", ".vscode-insiders"))
        if sys.platform == "darwin" and agent in ("cursor", "antigravity"):
            found = found or any((base / (agent.capitalize() + ".app")).is_dir()
                                 for base in (Path("/Applications"), home / "Applications"))
        result[agent] = bool(found)
    return result


def load_settings(path, *, text=None):
    path = Path(path)
    if text is None:
        text = path.read_text() if path.exists() else ""
    try:
        value = yaml.safe_load(text or "{}") if path.suffix in (".yaml", ".yml") else json.loads(text or "{}")
        if value is None and path.suffix in (".yaml", ".yml"):
            value = {}
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: invalid YAML") from exc
    if not isinstance(value, dict):
        raise ValueError(str(path) + " must be an object")
    return value


def settings_text(path, settings):
    if Path(path).suffix in (".yaml", ".yml"):
        return yaml.safe_dump(settings, sort_keys=False, allow_unicode=True)
    return json.dumps(settings, indent=2) + "\n"


def hermes_approved(path):
    """Inspect persistent native consent without granting or restoring it."""
    try:
        settings = load_settings(path)
        auto = settings.get("hooks_auto_accept", False)
        if auto is True or isinstance(auto, str) and auto.strip().lower() in ("1", "true", "yes", "on"):
            return True
        approvals = load_settings(Path(path).parent / "shell-hooks-allowlist.json").get("approvals", [])
        approved = {(item.get("event"), item.get("command")) for item in approvals
                    if isinstance(item, dict) and isinstance(item.get("event"), str)
                    and isinstance(item.get("command"), str)}
        return all((APP_EVENTS["hermes"][event], handler["command"]) in approved
                   for event in managed_events("hermes")
                   for group in groups(settings, event, "hermes")
                   for handler in group["hooks"] if our_handler(handler))
    except (OSError, ValueError, TypeError):
        return False


def our_handler(handler):
    """Recognize our canonical command and previously installed sensor hooks."""
    if not isinstance(handler, dict) or not isinstance(handler.get("command"), str):
        return False
    try:
        parts, _ = hook_runtime.arguments(handler["command"], windows=os.name == "nt")
        if len(parts) < 3 or parts[1] != "hook":
            return False
        name = ntpath.basename(parts[0]).lower() if os.name == "nt" else Path(parts[0]).name
        return name in ("openaidr", "openaidr.exe") or "openaidr-sensor" in parts[0]
    except (ValueError, KeyError, TypeError):
        return False


def ours(entry):
    """True for a hook group with a handler of ours. Tolerates any shape."""
    if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
        return False
    return any(our_handler(h) for h in entry["hooks"])


def available(entry, event, agent):
    """An unrestricted managed command that can run for the whole event."""
    if not ours(entry):
        return False
    if entry.get("matcher") is not None and not isinstance(entry["matcher"], str):
        return False
    # Both native clients ignore matchers on prompt submission and stop events.
    filtered = event not in ("UserPromptSubmit", "Stop")
    if filtered and entry.get("matcher") not in (None, "", "*", ".*"):
        return False
    for handler in entry["hooks"]:
        if not our_handler(handler) or handler.get("type") != "command":
            continue
        timeout = handler.get("timeoutSec", handler.get("timeout")) if agent == "copilot" else handler.get("timeout")
        if timeout != hook_timeout(event, agent):
            continue
        if agent == "cursor" and handler.get("failClosed", False) is not False:
            continue
        if agent == "hermes" and handler.get("fail_closed", handler.get("failClosed", False)) is not False:
            continue
        if agent == "claude" and handler.get("if"):
            continue
        # WorkBuddy starts only PowerShell 7 for an explicit PowerShell hook
        # shell, so that handler cannot start on stock Windows. Its default
        # shell falls back to Git Bash or Windows PowerShell; repair to it.
        if agent == "workbuddy" and handler.get("shell") == "powershell":
            continue
        # Decisions and final Codex observations must finish before agent exit.
        synchronous = event in DECISION_EVENTS or (
            agent == "codex" and event in CODEX_EVENTS and not CODEX_EVENTS[event][1]
        )
        if synchronous and (
            handler.get("async", False) is not False
            or (agent in ("claude", "workbuddy") and handler.get("asyncRewake", False) is not False)
        ):
            continue
        try:
            parts, quiet = hook_runtime.arguments(handler["command"], windows=os.name == "nt")
            if quiet and shutil.which(parts[0]):
                return True
        except (OSError, ValueError):
            continue
    return False


def hook_timeout(event, agent):
    # Codex caps shutdown hooks at three seconds regardless of configuration.
    if agent == "codex" and event in ("SessionEnd", "Interrupt"):
        return HOOK_TIMEOUT_SECONDS
    return WINDOWS_AGENT_HOOK_TIMEOUT_SECONDS if os.name == "nt" else HOOK_TIMEOUT_SECONDS


def managed_events(agent):
    if agent in APP_EVENTS:
        return tuple(APP_EVENTS[agent])
    return tuple(CODEX_EVENTS) if agent == "codex" else EVENTS


def groups(settings, event, agent="claude"):
    """The event's hook groups, or none for any malformed shape."""
    hooks = settings.get("openaidr" if agent == "antigravity" else "hooks") if isinstance(settings, dict) else None
    value = hooks.get(APP_EVENTS.get(agent, {}).get(event, event)) if isinstance(hooks, dict) else None
    value = value if isinstance(value, list) else []
    if flat_hooks(agent, event):
        return [{"hooks": [entry], "matcher": entry.get("matcher")} if isinstance(entry, dict)
                else {"hooks": [entry]} for entry in value]
    return value


def flat_hooks(agent, event):
    return agent in ("copilot", "cursor", "hermes") or (agent == "antigravity" and event not in ("PreToolUse", "PostToolUse"))


def command_args(executable, event, agent="claude", config_path=None):
    """The hook arguments; the sensor config is named only when it is not the default.

    Agents run the command from the project directory, so the config path is
    made absolute.
    """
    parts = [executable, "hook"]
    if agent != "claude":
        parts += ["--agent", agent]
    if config_path:
        config_path = Path(config_path).expanduser().resolve()
        if config_path != default_config_path().expanduser().resolve():
            parts += ["--config", str(config_path)]
    parts.append(event)
    return parts


def command_line(executable, event, agent="claude", config_path=None, *, health_dir=None):
    return hook_runtime.command(
        command_args(executable, event, agent, config_path),
        health_dir or hook_runtime.directory(settings_path(agent)), agent, event,
        windows=os.name == "nt",
        socket_path=native_socket(config_path),
    )


def native_socket(config_path):
    """Use the system curl only for per-user macOS installs with a known socket."""
    if config_path is None or os.name == "nt" or sys.platform != "darwin" or is_root():
        return None
    config = Config.load(config_path)
    path = str(Path(config["data_dir"]).absolute() / "sensor.sock")
    # Longer paths cannot bind on macOS; the CLI retains authenticated TCP
    # fallback for those installs and for system-wide services.
    return path if len(os.fsencode(path)) < 104 else None


def editable_hooks(settings, path, agent):
    """The settings' hooks object, checked writable for every managed event."""
    hooks = settings.setdefault("openaidr" if agent == "antigravity" else "hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"{path}: hooks must be an object")
    for event in managed_events(agent):
        event = APP_EVENTS.get(agent, {}).get(event, event)
        if not isinstance(hooks.get(event, []), list):
            raise ValueError(f"{path}: hooks.{event} must be an array")
    return hooks


def place(existing, group):
    """Put our group in the event's list, removing every other handler of ours.

    Our group takes the place of the first group that held only our
    handlers, or goes last. A group that also holds the user's own handlers
    keeps them, and its position; only our handlers leave it. Returns the new
    list and where each kept handler of the user moved, as
    ``{(group, handler): (group, handler)}``, so trust recorded against a
    handler's position can move with it.
    """
    result, moves, placed = [], {}, False
    for g, entry in enumerate(existing):
        handlers = entry.get("hooks") if isinstance(entry, dict) else None
        if not isinstance(handlers, list) or not ours(entry):
            if isinstance(handlers, list):
                for h in range(len(handlers)):
                    moves[(g, h)] = (len(result), h)
            result.append(entry)
            continue
        kept = [(h, handler) for h, handler in enumerate(handlers) if not our_handler(handler)]
        if not kept:
            if group is not None and not placed:
                result.append(group)
                placed = True
            continue
        for new_h, (h, _) in enumerate(kept):
            moves[(g, h)] = (len(result), new_h)
        result.append({**entry, "hooks": [handler for _, handler in kept]})
    if group is not None and not placed:
        result.append(group)
    return result, moves


WORKBUDDY_NO_SHELL = ("WorkBuddy cannot start Git Bash or PowerShell on this device, so OpenAIDR guardrails "
                      "are off for WorkBuddy and its actions are not blocked. Install Git for Windows or allow "
                      "PowerShell, then turn WorkBuddy guardrails on again.")


def remove_unstartable_workbuddy(path, config_path=None):
    """Fail open on Windows when WorkBuddy cannot start a hook shell.

    WorkBuddy rejects every action whose hook shell fails to start, even in
    Shadow mode. Remove only OpenAIDR handlers and record no opt-out, so
    setup installs them again once a shell starts. Returns True if removed.
    """
    # Probe a shell only while our WorkBuddy hooks exist on Windows.
    if not workbuddy.WINDOWS or not present(path, "workbuddy") or not workbuddy.hook_shell_unavailable():
        return False
    uninstall(path, "workbuddy", config_path=config_path)
    logging.warning("WorkBuddy cannot start a hook shell; removed OpenAIDR WorkBuddy hooks so actions are not blocked")
    return True


def install(path, executable="openaidr", agent="claude", config_path=None, *, explicit=False,
            config_toml=None):
    """Install or repair our hooks. ``explicit`` is a person asking for them
    (CLI or administrator command); only that re-enables handlers the user
    turned off in Codex or Antigravity. Automatic setup passes the default."""
    if agent == "codex":
        return install_codex(path, executable, config_toml, config_path=config_path, explicit=explicit)
    if agent == "opencode":
        from . import hook_opencode

        return hook_opencode.install(path, executable, config_path)
    if agent == "workbuddy" and workbuddy.hook_shell_unavailable():
        remove_unstartable_workbuddy(path, config_path)
        if explicit:
            raise ValueError(WORKBUDDY_NO_SHELL)
        return
    path = Path(path)
    hook_runtime.register(config_path, hook_runtime.directory(path))

    def update(files):
        settings = load_settings(path, text=files.text(path))
        if agent in ("copilot", "cursor"):
            if type(settings.get("version", 1)) is not int or settings.get("version", 1) != 1:
                raise ValueError(f"{path}: unsupported hook configuration version")
            settings["version"] = 1
        hooks = editable_hooks(settings, path, agent)
        if agent == "antigravity" and explicit and hooks.get("enabled") is False:
            hooks["enabled"] = True
        for event in managed_events(agent):
            entries, _ = place(
                groups(settings, event, agent),
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": command_line(executable, event, agent, config_path,
                                                    health_dir=hook_runtime.directory(path)),
                            "timeout": hook_timeout(event, agent),
                            **({"failClosed": False} if agent == "cursor" else {}),
                            **({"fail_closed": False} if agent == "hermes" else {}),
                        }
                    ]
                },
            )
            hooks[APP_EVENTS.get(agent, {}).get(event, event)] = (
                [handler for entry in entries for handler in entry["hooks"]]
                if flat_hooks(agent, event) else entries
            )
        files.write(path, settings_text(path, settings))

    edit_settings([path], update)
    if agent == "claude":
        record_result_capability(config_path, agent)


def uninstall(path, agent="claude", config_toml=None, *, config_path=None):
    """Remove our handlers, then this agent's launcher scripts and measurements.

    ``config_path`` names the sensor config whose measurement registry should
    forget the directory once it is empty.
    """
    if agent == "codex":
        return uninstall_codex(path, config_toml, config_path=config_path)
    if agent == "opencode":
        from . import hook_opencode

        return hook_opencode.uninstall(path, config_path)
    path = Path(path)

    def update(files):
        settings = load_settings(path, text=files.text(path))
        key = "openaidr" if agent == "antigravity" else "hooks"
        hooks = settings.get(key)
        if isinstance(hooks, dict):
            for event in list(hooks):
                if isinstance(hooks[event], list):
                    if flat_hooks(agent, event):
                        hooks[event] = [handler for handler in hooks[event] if not our_handler(handler)]
                    else:
                        hooks[event], _ = place(hooks[event], None)
                    if not hooks[event]:
                        del hooks[event]
            if (not hooks and agent not in ("copilot", "cursor")) or (agent == "antigravity" and set(hooks) <= {"enabled"}):
                settings.pop(key, None)
        files.write(path, settings_text(path, settings))

    edit_settings([path], update)
    hook_runtime.cleanup(hook_runtime.directory(path), agent, config_path)


def present(path=None, agent="claude"):
    """True when the settings still hold any OpenAIDR handler, runnable or not."""
    if agent == "opencode":
        from . import hook_opencode

        return hook_opencode.present(path or settings_path(agent))
    try:
        settings = load_settings(path or settings_path(agent))
    except (OSError, ValueError):
        return False
    events = settings.get("openaidr" if agent == "antigravity" else "hooks")
    return isinstance(events, dict) and any(
        ours(entry) for event in events for entry in groups(settings, event, agent)
    )


def settings_disabled(settings, agent, path=None):
    if agent == "antigravity":
        return isinstance(settings.get("openaidr"), dict) and settings["openaidr"].get("enabled") is False
    if agent == "copilot" and path and Path(path).parent.name == "hooks":
        if load_settings(Path(path).parent.parent / "settings.json").get("disableAllHooks") is True:
            return True
    return (agent in ("claude", "copilot", "workbuddy") and settings.get("disableAllHooks") is True
            or agent == "workbuddy" and settings.get("allowManagedHooksOnly") is True)


def coverage(path=None, agent="claude"):
    """The managed events with an available OpenAIDR hook executable."""
    if agent == "opencode":
        from . import hook_opencode

        return set(managed_events(agent)) if hook_opencode.available(path or settings_path(agent)) else set()
    try:
        settings = load_settings(path or settings_path(agent))
        if settings_disabled(settings, agent, path or settings_path(agent)):
            return set()
        if agent in ("copilot", "cursor") and (type(settings.get("version")) is not int or settings.get("version") != 1):
            return set()
        if agent == "codex":
            validate_codex_matchers(settings)
    except (OSError, ValueError):
        return set()
    return {
        event
        for event in managed_events(agent)
        if any(available(entry, event, agent) for entry in groups(settings, event, agent))
    }


def installed(path=None, agent="claude"):
    """True when every managed event has an available OpenAIDR hook executable."""
    return coverage(path, agent) == set(managed_events(agent))


def current(config_path, agent="claude", path=None):
    """Every managed event uses the desired agent, event and sensor config."""
    path = path or settings_path(agent)
    if agent == "opencode":
        from . import hook_opencode

        return hook_opencode.current(path, config_path)
    if agent == "codex" and codex_pending_path(path).exists():
        return False
    try:
        socket_path = native_socket(config_path)
        settings = load_settings(path)
        if agent == "codex":
            validate_codex_matchers(settings)
        if settings_disabled(settings, agent, path):
            return False
        if agent in ("copilot", "cursor") and (type(settings.get("version")) is not int or settings.get("version") != 1):
            return False
        for event in managed_events(agent):
            expected = command_args("", event, agent, config_path)[1:]
            found = False
            for entry in groups(settings, event, agent):
                if not ours(entry):
                    continue
                if not available(entry, event, agent):
                    return False
                for handler in entry["hooks"]:
                    if our_handler(handler):
                        parts, quiet = hook_runtime.arguments(handler["command"], windows=os.name == "nt")
                        if not quiet or parts[1:] != expected:
                            return False
                        if os.name != "nt":
                            runner = Path(shlex.split(handler["command"])[4])
                            runtime = hook_runtime.posix_config(runner.read_text())
                            if runtime.get("socket_path") != socket_path:
                                return False
                            stable = hook_runtime.stable_posix_runner(runtime)
                            if stable is not None and runner != stable:
                                return False
                        found = True
            if not found:
                return False
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return True


def validate_codex_matchers(settings):
    # Codex parses these types before ignoring an event's matcher. One invalid
    # group, including a user-owned group, invalidates the complete JSON source.
    events = (*CODEX_EVENT_LABELS, "PermissionRequest", "PreCompact", "PostCompact", "Interrupt")
    for event in events:
        for group in groups(settings, event):
            if isinstance(group, dict) and group.get("matcher") is not None and not isinstance(group["matcher"], str):
                raise ValueError(f"Codex hooks.{event} matcher must be a string or null; correct the invalid hook group before setup")


def executables(agent="claude", path=None):
    """The executables this agent's OpenAIDR hook commands run."""
    if agent == "opencode":
        from . import hook_opencode

        return hook_opencode.executables(path or settings_path(agent))
    found = set()
    try:
        settings = load_settings(path or settings_path(agent))
        for event in managed_events(agent):
            for entry in groups(settings, event, agent):
                for handler in entry["hooks"] if ours(entry) else []:
                    if our_handler(handler):
                        found.add(hook_runtime.arguments(handler["command"], windows=os.name == "nt")[0][0])
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        pass
    return found


def codex_hook_hash(event, group, handler):
    """Reproduce Codex's trust hash for one command handler.

    Codex hashes the normalized definition (event label, matcher, and the
    handler with its effective timeout) as sorted compact JSON, so the hash is
    the same whether the hook came from hooks.json or config.toml. Checked
    against codex-rs ``hooks/src/engine/discovery.rs`` and
    ``config/src/fingerprint.rs`` on 2026-09-29. Codex drops
    ``commandWindows`` when normalizing, so it is not hashed.
    """
    if group.get("matcher") is not None and not isinstance(group["matcher"], str):
        raise ValueError("Codex hook matcher must be a string or null")
    timeout = handler.get("timeout")
    if event in ("SessionEnd", "Interrupt"):
        timeout = min(max(int(timeout if timeout is not None else 1), 1), 3)
    else:
        timeout = max(int(timeout if timeout is not None else 600), 1)
    normalized = {
        "type": "command",
        "command": handler["command"],
        "timeout": timeout,
        "async": bool(handler.get("async", False)),
    }
    if handler.get("statusMessage") is not None:
        normalized["statusMessage"] = handler["statusMessage"]
    limit = handler.get("additionalContextLimit")
    if limit is not None and limit != 2500:
        normalized["additionalContextLimit"] = limit
    identity = {"event_name": CODEX_EVENT_LABELS[event], "hooks": [normalized]}
    if group.get("matcher") is not None and event not in ("UserPromptSubmit", "Stop"):
        identity["matcher"] = group["matcher"]
    data = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def codex_trust_entries(path, settings):
    """State keys and hashes for every command handler of ours, by event."""
    entries = {}
    for event, label in CODEX_EVENT_LABELS.items():
        for g, group in enumerate(groups(settings, event)):
            if not ours(group):
                continue
            for h, handler in enumerate(group["hooks"]):
                # Only our own handlers are trusted by the installer; a user
                # command that shares the group keeps whatever trust Codex has.
                if our_handler(handler):
                    try:
                        digest = codex_hook_hash(event, group, handler)
                    except (TypeError, ValueError):
                        continue
                    entries[f"{path}:{label}:{g}:{h}"] = (event, digest)
    return entries


def our_positions(path, settings):
    """Trust keys of every handler of ours, by event, hashable or not.

    Ownership and the user's disablement belong to a position even when its
    definition is malformed; only trust needs a hash.
    """
    positions = {}
    for event, label in CODEX_EVENT_LABELS.items():
        for g, group in enumerate(groups(settings, event)):
            if ours(group):
                for h, handler in enumerate(group["hooks"]):
                    if our_handler(handler):
                        positions[f"{path}:{label}:{g}:{h}"] = event
    return positions


def load_codex_config(path, *, text=None):
    path = Path(path)
    if text is None:
        text = path.read_text(encoding="utf-8") if path.exists() else ""
    return tomlkit.parse(text)


def codex_state(document):
    hooks = document.get("hooks")
    state = hooks.get("state") if isinstance(hooks, dict) else None
    return state if isinstance(state, dict) else {}


def trust_document(config_toml, entries, remove, moves=None, *, text=None, unchanged=(), enable=False,
                   disabled=(), carried=None):
    """config.toml with trust for our hooks, prepared in memory before any file is written.

    ``moves`` renames the trust of the user's own groups whose position in
    hooks.json changed. Recording trust here is the same act as trusting the
    hooks in Codex's ``/hooks`` browser; without it Codex lists them as needing
    review and never runs them. Everything else in the file is preserved.

    ``unchanged`` names the keys whose handler definition did not change. A
    hash Codex itself recorded for one of them (after the user trusted the hook
    in ``/hooks``) is kept, so a reinstall never reverts that trust. With
    ``enable``, an explicit install also clears ``enabled = false`` that the
    user set in Codex; otherwise that choice is preserved. ``disabled`` names
    new keys that inherit ``enabled = false`` because our handler moved, and
    ``carried`` maps such keys to the trust hash recorded at the old position.
    """
    config_toml = Path(config_toml)
    document = load_codex_config(config_toml, text=text)
    hooks = document.get("hooks")
    if hooks is None:
        hooks = tomlkit.table(True)
        document["hooks"] = hooks
    elif isinstance(hooks, tomlkit.items.InlineTable) or not isinstance(hooks, dict):
        raise ValueError(
            f"{config_toml}: hooks must be a [hooks] table, not an inline table or value"
        )
    state = hooks.get("state")
    if state is None:
        state = tomlkit.table(True)
        hooks["state"] = state
    elif isinstance(state, tomlkit.items.InlineTable) or not isinstance(state, dict):
        raise ValueError(
            f"{config_toml}: hooks.state must be a [hooks.state] table, not an inline table or value"
        )
    moved = {}
    for old, new in (moves or {}).items():
        if old in state:
            moved[new] = state[old]
            del state[old]
    for key in list(state):
        if key in remove and key not in entries:
            del state[key]
    for key, value in moved.items():
        state[key] = value
    for key, digest in entries.items():
        current = state.get(key)
        if not isinstance(current, dict):
            current = tomlkit.table()
            state[key] = current
        if (carried or {}).get(key) and not recorded_trust(current):
            current["trusted_hash"] = carried[key]
        elif key not in unchanged or not recorded_trust(current):
            current["trusted_hash"] = digest
        if enable and current.get("enabled") is False:
            del current["enabled"]
        elif not enable and key in disabled:
            current["enabled"] = False
    return document


def recorded_trust(entry):
    """The trust hash recorded for a handler, by the installer or by Codex."""
    value = entry.get("trusted_hash") if isinstance(entry, dict) else None
    return value if isinstance(value, str) and value else None


def trust_moves(path, event, moves):
    """Trust keys of the user's handlers that changed position in one event."""
    label = CODEX_EVENT_LABELS[event]
    return {
        f"{path}:{label}:{g}:{h}": f"{path}:{label}:{new_g}:{new_h}"
        for (g, h), (new_g, new_h) in moves.items()
        if (g, h) != (new_g, new_h)
    }


def codex_pending_path(path):
    path = Path(path).expanduser().resolve()
    return path.with_name(path.name + ".openaidr-trust-pending.json")


def codex_record_path(path):
    """Our digests at the last install, beside the hook file.

    A trust hash that differs from our digest is accepted only while the
    handler still has the definition we installed: then it is Codex's own
    value for that definition. Any edit to the handler makes it stale.
    """
    path = Path(path).expanduser().resolve()
    return path.with_name(path.name + ".openaidr-trust.json")


def installed_digests(path, *, text=None):
    try:
        if text is None:
            text = codex_record_path(path).read_text()
        record = json.loads(text)
        digests = record.get("digests") if record.get("version") == 1 else None
        return {k: v for k, v in digests.items() if isinstance(k, str) and isinstance(v, str)} \
            if isinstance(digests, dict) else {}
    except (OSError, ValueError, AttributeError):
        return {}


def trust_values(document):
    state = codex_state(document)
    return state.unwrap() if hasattr(state, "unwrap") else copy.deepcopy(state)


def edit_codex(path, config_toml, operation, update):
    """Recover the recorded layout/trust pair before starting another edit."""
    journal = codex_pending_path(path)
    canonical_hook, canonical_trust = path.expanduser().resolve(), config_toml.expanduser().resolve()

    def recover(files):
        if files.content(journal) is None:
            return
        try:
            record = json.loads(files.text(journal))
            keys = record["keys"]
            identity = record["identity"]
            if (record["version"] != 1 or record["hook_path"] != str(canonical_hook)
                    or record["trust_path"] != str(canonical_trust)
                    or Path(identity).expanduser().resolve() != canonical_hook
                    or record["operation"] not in ("install", "uninstall")
                    or not isinstance(keys, list) or len(keys) != len(set(keys))
                    or not all(isinstance(key, str) and key.startswith(identity + ":") for key in keys)
                    or not all(isinstance(record[name], dict) and set(record[name]) <= set(keys)
                               for name in ("trust_before", "trust_after"))):
                raise ValueError
            layout = publication_state(record["hooks_before"], record["hooks_after"],
                                       content_hash(files.content(path)))
        except (ValueError, TypeError, KeyError, AttributeError):
            raise OSError(f"Invalid pending Codex trust record in {journal}; ask your administrator to recover it") from None
        if record["operation"] == "uninstall" and operation == "install":
            raise OSError(f"Codex hook removal is pending in {journal}; retry hook uninstall --agent codex before installing again")
        if layout is None:
            raise OSError(f"Codex hooks changed during an interrupted update; keep {path} and ask your administrator to recover {journal}")
        # Equal layouts occur when only trust needed repair. Complete that act.
        if record["hooks_before"] == record["hooks_after"]:
            layout = "after"
        if keys:
            document = load_codex_config(config_toml, text=files.text(config_toml))
            values = trust_values(document)
            current = {key: values[key] for key in keys if key in values}
            trust = publication_state(record["trust_before"], record["trust_after"], current)
            if trust is None:
                raise OSError(f"Codex trust changed during an interrupted update; keep {config_toml} and ask your administrator to recover {journal}")
            if trust != layout:
                document = trust_document(config_toml, {}, set(), text=files.text(config_toml))
                state = codex_state(document)
                wanted = record["trust_" + layout]
                for key in keys:
                    if key in wanted:
                        state[key] = wanted[key]
                    else:
                        state.pop(key, None)
                files.write(config_toml, tomlkit.dumps(document))
        files.delete(journal)

    def prepare(files):
        update(files)
        replacement = files.pending[canonical_hook]
        before, after = {}, {}
        if canonical_trust in files.pending:
            before = trust_values(load_codex_config(config_toml, text=files.text(config_toml)))
            after = trust_values(load_codex_config(config_toml, text=files.pending[canonical_trust]))
        keys = sorted(key for key in before.keys() | after.keys() if before.get(key) != after.get(key))
        record = json.dumps({
            "version": 1, "operation": operation, "identity": str(path),
            "hook_path": str(canonical_hook), "trust_path": str(canonical_trust),
            "hooks_before": content_hash(files.content(path)),
            "hooks_after": content_hash(replacement.encode("utf-8")),
            "keys": keys,
            "trust_before": {key: before[key] for key in keys if key in before},
            "trust_after": {key: after[key] for key in keys if key in after},
        }, indent=2)
        replacements = files.pending
        files.pending = {}
        files.write(journal, record)
        for target, text in replacements.items():
            files.write(target, text)
        return record

    def complete(files, record):
        if files.content(journal) != record.encode("utf-8"):
            raise OSError(f"Pending Codex trust record changed in {journal}; recover it before retrying")
        files.delete(journal)

    edit_settings([path, config_toml, journal, codex_record_path(path)], prepare,
                  recover=recover, complete=complete)


def install_codex(path, executable="openaidr", config_toml=None, config_path=None, *, explicit=False):
    path = Path(path)
    config_toml = Path(config_toml or codex_config_path())
    hook_runtime.register(config_path, hook_runtime.directory(path))

    def update(files):
        settings = load_settings(path, text=files.text(path))
        hooks = editable_hooks(settings, path, "codex")
        previous = codex_trust_entries(path, settings)
        owned = our_positions(path, settings)
        moves = {}
        for event, (timeout, run_async) in CODEX_EVENTS.items():
            timeout = hook_timeout(event, "codex")
            handler = {
                "type": "command",
                "command": command_line(executable, event, "codex", config_path,
                                        health_dir=hook_runtime.directory(path)),
                "timeout": timeout,
            }
            if run_async:
                handler["async"] = True
            hooks[event], moved = place(hooks.get(event, []), {"hooks": [handler]})
            moves.update(trust_moves(path, event, moved))
        validate_codex_matchers(settings)
        located = codex_trust_entries(path, settings)
        entries = {key: digest for key, (_, digest) in located.items()}
        record = codex_record_path(path)
        known = installed_digests(path, text=files.text(record) or "{}")
        recorded = codex_state(load_codex_config(config_toml, text=files.text(config_toml)))
        # Placement can move our handler out of a group shared with the
        # user's handlers, which changes its trust key. An automatic repair
        # carries the user's per-event disablement to the new position.
        off = {event for key, event in owned.items()
               if isinstance(recorded.get(key), dict) and recorded[key].get("enabled") is False}
        disabled = set() if explicit else {key for key, (event, _) in located.items() if event in off}
        # An unchanged handler that only moved keeps the trust recorded for
        # it, including a hash Codex computed under different rules.
        before = {}
        for key, (event, digest) in previous.items():
            before.setdefault(event, (key, digest))
        carried = {}
        for key, (event, digest) in located.items():
            old, old_digest = before.get(event, (None, None))
            value = recorded_trust(recorded.get(old)) if old else None
            if (old != key and old_digest == digest and value
                    and digest in (value, known.get(old, digest))):
                carried[key] = value
        # Keep a hash only for a definition that did not change and whose
        # recorded trust belongs to it: our own digest, or Codex's value for
        # the definition we installed. Anything else is stale.
        # Installs from before the digest record have no entry yet: an
        # unchanged definition keeps its hash, and the record starts here.
        unchanged = {
            key for key, digest in entries.items()
            if previous.get(key, (None, None))[1] == digest
            and digest in (recorded_trust(recorded.get(key)), known.get(key, digest))
        }
        # Prepared first: a config.toml that cannot take the trust leaves
        # hooks.json untouched instead of holding hooks Codex will not run.
        document = trust_document(config_toml, entries, set(owned), moves,
                                  text=files.text(config_toml), unchanged=unchanged,
                                  enable=explicit, disabled=disabled, carried=carried)
        files.write(path, json.dumps(settings, indent=2) + "\n")
        files.write(config_toml, tomlkit.dumps(document))
        files.write(record, json.dumps({"version": 1, "digests": entries}, indent=2, sort_keys=True))

    edit_codex(path, config_toml, "install", update)
    record_result_capability(config_path, "codex")


def uninstall_codex(path, config_toml=None, *, config_path=None):
    path = Path(path)
    config_toml = Path(config_toml or codex_config_path())

    def update(files):
        settings = load_settings(path, text=files.text(path))
        previous = our_positions(path, settings)
        hooks = settings.get("hooks")
        moves = {}
        if isinstance(hooks, dict):
            for event in list(hooks):
                if isinstance(hooks[event], list):
                    hooks[event], moved = place(hooks[event], None)
                    if event in CODEX_EVENT_LABELS:
                        moves.update(trust_moves(path, event, moved))
                    if not hooks[event]:
                        del hooks[event]
        document = (
            trust_document(config_toml, {}, set(previous), moves, text=files.text(config_toml))
            if (previous or moves) and files.content(config_toml) is not None
            else None
        )
        files.write(path, json.dumps(settings, indent=2) + "\n")
        if document is not None:
            files.write(config_toml, tomlkit.dumps(document))
        if files.content(codex_record_path(path)) is not None:
            files.delete(codex_record_path(path))

    edit_codex(path, config_toml, "uninstall", update)
    hook_runtime.cleanup(hook_runtime.directory(path), "codex", config_path)


def _codex_trust_state(path, config_toml):
    """Our handlers' trust keys and the recorded ``hooks.state`` table, or None."""
    path = Path(path or settings_path("codex"))
    try:
        settings = load_settings(path)
        validate_codex_matchers(settings)
        entries = codex_trust_entries(path, settings)
        state = codex_state(load_codex_config(config_toml or codex_config_path()))
    except (OSError, ValueError, TypeError, AttributeError, tomlkit.exceptions.TOMLKitError):
        return None
    return entries, state


def codex_trusted(path=None, config_toml=None):
    """True when every managed event has a hook of ours and all of them are trusted and enabled.

    Our digest counts. A different hash counts only while the handler keeps
    the definition we installed: Codex records its own normalization when the
    user trusts that hook in ``/hooks``. After any edit to the handler, the
    old hash is stale and Codex would ask for review again.
    """
    path = Path(path or settings_path("codex"))
    if codex_pending_path(path).exists():
        return False
    loaded = _codex_trust_state(path, config_toml)
    if loaded is None:
        return False
    entries, state = loaded
    if {event for event, _ in entries.values()} != set(CODEX_EVENTS):
        return False
    known = installed_digests(path)
    for key, (_, digest) in entries.items():
        recorded = state.get(key)
        value = recorded_trust(recorded)
        if value is None or recorded.get("enabled") is False:
            return False
        if value != digest and known.get(key) != digest:
            return False
    return True


def codex_disabled(path=None, config_toml=None):
    """True when the user disabled one of our handlers in Codex's ``/hooks`` browser.

    That choice is reported like Claude Code's ``disableAllHooks`` and left in
    place by automatic setup; an explicit ``hook install --agent codex`` clears it.
    An interrupted update takes precedence, so setup runs its recovery.
    """
    if codex_pending_path(Path(path or settings_path("codex"))).exists():
        return False
    path = Path(path or settings_path("codex"))
    try:
        positions = our_positions(path, load_settings(path))
        state = codex_state(load_codex_config(config_toml or codex_config_path()))
    except (OSError, ValueError, TypeError, AttributeError, tomlkit.exceptions.TOMLKitError):
        return False
    return any(isinstance(state.get(key), dict) and state[key].get("enabled") is False for key in positions)


def status(paths=None, config=None):
    """Per-agent installation state, for status output and automatic setup.

    ``installed`` means every managed event has a quiet, available hook command;
    ``partial`` means only some do. Malformed files read as not installed.
    Without explicit paths, the agent directories this process sees are used.
    """
    paths = {**settings_paths(config), **(paths or {})}
    detected = detect_apps(config)
    result = {}
    for agent in AGENTS:
        try:
            covered = coverage(paths.get(agent), agent)
        except Exception:
            covered = set()
        result[agent] = {
            "installed": covered == set(managed_events(agent)),
            "partial": bool(covered) and covered != set(managed_events(agent)),
        }
        if agent in APP_EVENTS:
            result[agent]["available"] = detected[agent]
            # Without a startable shell, setup must not add WorkBuddy hooks
            # (they would block every action), so the app is not set up.
            if agent == "workbuddy" and detected[agent] and workbuddy.hook_shell_unavailable():
                result[agent].update(available=False, shell_unavailable=True)
            result[agent]["control_events"] = [event for event in managed_events(agent) if controls(PRODUCTS[agent], event)]
        if agent == "hermes":
            result[agent]["approval_pending"] = present(paths[agent], agent) and not hermes_approved(paths[agent])
        try:
            if agent != "opencode" and settings_disabled(load_settings(paths[agent]), agent, paths[agent]):
                result[agent]["disabled"] = True
        except (OSError, ValueError):
            pass
    result["codex"]["trusted"] = result["codex"]["installed"] and codex_trusted(
        paths.get("codex"), paths.get("codex_config")
    )
    if codex_disabled(paths.get("codex"), paths.get("codex_config")):
        result["codex"]["disabled"] = True
    return result


def set_opt_out(config, agent, opted_out, *, profile=None):
    """Record an explicit per-agent hook removal in the sensor config.

    Automatic setup installs hooks for detected agents; this record is what
    keeps it from reinstalling hooks the operator removed on purpose. It is
    only written when a sensor config already exists, and it is applied to
    the file as it is now, so a long-running service never writes back a
    stale copy of other settings.
    """
    if config is None or not Path(config.path).exists():
        return
    current = Config.load(config.path)
    section = dict(current.get("hooks") or {})
    disabled = list(section.get("disabled_agents") or [])
    if profile is not None:
        profiles = set(section.get("disabled_codex_profiles") or [])
        if not opted_out and "codex" in disabled:
            profiles.update(str(path) for path in codex_paths(config))
            disabled.remove("codex")
        if opted_out:
            profiles.add(profile)
        else:
            profiles.discard(profile)
        if profiles:
            section["disabled_codex_profiles"] = sorted(profiles)
        else:
            section.pop("disabled_codex_profiles", None)
    else:
        disabled = [name for name in disabled if name != agent]
        if opted_out:
            disabled.append(agent)
        elif agent == "codex":
            profiles = [path for path in section.get("disabled_codex_profiles") or []
                        if path != str(settings_path("codex", config))]
            if profiles:
                section["disabled_codex_profiles"] = profiles
            else:
                section.pop("disabled_codex_profiles", None)
    if disabled:
        section["disabled_agents"] = disabled
    else:
        section.pop("disabled_agents", None)
    if section != (current.get("hooks") or {}):
        if section:
            current["hooks"] = section
        else:
            current.pop("hooks", None)
        current.save()
    if section:
        config["hooks"] = section
    else:
        config.pop("hooks", None)


def opted_out(config, agent, *, profile=None):
    section = config.get("hooks") or {}
    return (agent in (section.get("disabled_agents") or [])
            or (profile is not None and profile in (section.get("disabled_codex_profiles") or [])))


def codex_profiles(config, paths=None):
    profiles = []
    for path, config_toml in (paths if paths is not None else codex_paths(config)).items():
        try:
            covered = coverage(path, "codex")
            disabled = settings_disabled(load_settings(path), "codex", path) or codex_disabled(path, config_toml)
        except (OSError, ValueError):
            covered, disabled = set(), False
        installed = covered == set(managed_events("codex"))
        trusted = installed and codex_trusted(path, config_toml)
        profiles.append(dict(
            name=path.parent.name, config_path=str(path), config_exists=path.is_file(),
            available=config_toml.is_file() or path.is_file(), installed=installed,
            partial=bool(covered) and not installed, trusted=trusted, disabled=disabled,
            current=bool(trusted and current(config.path, "codex", path)),
            opted_out=opted_out(config, "codex", profile=str(path)),
            control_events=[event for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse")
                            if event in managed_events("codex") and controls(PRODUCTS["codex"], event)],
        ))
    return profiles


def result_text(value):
    """Tool output as text: Claude's stdout/stderr, MCP content blocks, or plain text."""
    if isinstance(value, dict):
        if value.get("stdout") or value.get("stderr"):
            return "\n".join(
                [str(value.get("stdout") or ""), str(value.get("stderr") or "")]
            ).strip()
        if isinstance(value.get("content"), list):
            return content_text(value["content"])
    return content_text(value)


def result_error(value):
    if isinstance(value, dict):
        for key in ("isError", "is_error"):
            if isinstance(value.get(key), bool):
                return value[key]
    return None


def exit_code(text):
    match = re.match(r"\s*Exit code:\s*(-?\d+)", text or "")
    return int(match[1]) if match else None


def executable_identity(path):
    path = Path(path).resolve(strict=True)
    stat = path.stat()
    return {"path": str(path), "size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "inode": stat.st_ino}


def npm_codex_binary(executable):
    """Resolve only the official npm launcher's known platform package layout."""
    node = shutil.which("node")
    if not node:
        raise ValueError("Node runtime unavailable")
    script = r"""
const fs = require('fs'), path = require('path');
const launcher = process.argv[1], root = path.dirname(path.dirname(launcher));
if (JSON.parse(fs.readFileSync(path.join(root, 'package.json'))).name !== '@openai/codex') process.exit(1);
const cpu = {x64: 'x86_64', arm64: 'aarch64'}[process.arch];
const target = {linux: `${cpu}-unknown-linux-musl`, darwin: `${cpu}-apple-darwin`,
                win32: `${cpu}-pc-windows-msvc`}[process.platform];
if (!cpu || !target) process.exit(1);
const resolve = require('module').createRequire(launcher).resolve;
let vendor;
try { vendor = path.join(path.dirname(resolve(`@openai/codex-${process.platform}-${process.arch}/package.json`)), 'vendor'); }
catch { vendor = path.join(root, 'vendor'); }
process.stdout.write(path.join(vendor, target, 'bin', process.platform === 'win32' ? 'codex.exe' : 'codex'));
"""
    result = subprocess.run([node, "-e", script, str(executable)], capture_output=True, text=True, timeout=1)
    if result.returncode or not result.stdout:
        raise ValueError("Unknown npm Codex layout")
    return result.stdout


def record_result_capability(config_path, agent):
    """Probe only during installation, never while an agent waits for a hook."""
    if config_path is None:
        return
    try:
        config = Config.load(config_path)
        path = Path(config["data_dir"]) / (agent + "-hook-capability.json")
        # Invalidate a prior probe even if the new binary cannot be inspected.
        path.unlink(missing_ok=True)
        executable = shutil.which(agent)
        if not executable:
            return
        identity = executable_identity(executable)
        result = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=1)
        match = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", result.stdout)
        if result.returncode or not match:
            return
        version = tuple(int(part) for part in match.groups())
        minimum = {"codex": (0, 160, 0), "claude": (2, 1, 285)}[agent]
        if version < minimum or identity != executable_identity(executable):
            return
        record = {"version": list(version), "executable": identity}
        if agent == "codex" and Path(identity["path"]).name == "codex.js":
            native = npm_codex_binary(identity["path"])
            native_identity = executable_identity(native)
            probe = subprocess.run([native, "--version"], capture_output=True, text=True, timeout=1)
            native_version = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", probe.stdout)
            if (probe.returncode or not native_version or tuple(map(int, native_version.groups())) != version
                    or native_identity != executable_identity(native) or identity != executable_identity(executable)):
                return
            record.update(launcher=identity, executable=native_identity)
        atomic_write(path, json.dumps(record))
    except (OSError, ValueError, subprocess.SubprocessError):
        # Lack of capability evidence only disables result replacement.
        return


def result_capable(config, agent, *, pid=None):
    """Bind result replacement to the probed native executable, including upgrades."""
    try:
        path = Path(config["data_dir"]) / (agent + "-hook-capability.json")
        with path.open() as stream:
            record = json.loads(stream.read(4096))
        if (not isinstance(record.get("version"), list) or len(record["version"]) != 3
                or any(type(part) is not int or part < 0 for part in record["version"])):
            return False
        identity = record["executable"]
        launcher = record.get("launcher", identity)
        if executable_identity(launcher["path"]) != launcher or executable_identity(identity["path"]) != identity:
            return False
        minimum = {"codex": (0, 160, 0), "claude": (2, 1, 285)}[agent]
        if tuple(record["version"]) < minimum:
            return False
        if pid is not None and pid <= 0:
            return False
        current = psutil.Process(pid) if pid is not None else psutil.Process()
        for _ in range(12):
            current = current.parent()
            if current is None:
                break
            if Path(current.exe()).resolve() == Path(identity["path"]):
                return True
    except (OSError, ValueError, KeyError, TypeError, psutil.Error):
        pass
    return False


class HookServer:
    def __init__(
        self, listen, socket_path, emit, status, host, emit_actions=False, check=None,
        token=None, disconnected=None,
    ):
        self.listen, self.socket_path = listen, Path(socket_path)
        self.check = check
        self.disconnected = disconnected
        # Required on loopback TCP by every per-user sensor, because every
        # local account shares loopback; see local_token. None for a root
        # service, which serves all accounts.
        self.token = token
        self.emit, self.status, self.host = emit, status, host
        # Action events (prompts, tool calls, results) are emitted for a product
        # only when its transcript collector is off, so nothing is recorded twice.
        self.emit_actions = (
            dict(emit_actions)
            if isinstance(emit_actions, dict)
            else {product: bool(emit_actions) for product in PRODUCTS.values()}
        )
        self.stats = dict(
            received=0,
            evaluated=0,
            denied=0,
            asked=0,
            warned=0,
            last_at=None,
            by_product={},
        )
        self.lock = threading.RLock()

    def evaluate(self, p, product="claude-code", started_ns=None, execution_id=None,
                 deadline_ns=None, result_supported=False, path_home=None, timeout_owner=None):
        """``started_ns`` is the hook command's own start time, in wall clock
        nanoseconds, so a decision's latency covers the hop from the agent."""
        begun = time.perf_counter()
        try:
            p = normalize(product, p)
        except (ValueError, TypeError):
            return {"decision": "allow", "claude_code": {}, "output": {}, "failed": True}
        if execution_id is not None and not re.fullmatch(r"[A-Za-z0-9]{6,64}", execution_id):
            execution_id = ""
        remaining = 1.8
        if timeout_owner in ("agent", "sensor"):
            # Bound backend work independently of delivery. A late result must
            # still be recorded after the launcher stops waiting.
            remaining = HOOK_WORK_TIMEOUT_SECONDS
        elif isinstance(deadline_ns, int):
            # Leave time to format and deliver the native response, including
            # the CLI client's own 50ms transport reserve when it is used.
            remaining = min(remaining, (deadline_ns - time.time_ns()) / 1e9 - 0.1)
        deadline = time.monotonic() + remaining
        if timeout_owner == "sensor" and isinstance(deadline_ns, int):
            # The backend may finish later. Reserve time to deliver an empty
            # response before the launcher's own fallback ends the wait.
            delivery_deadline_ns = deadline_ns - hook_runtime.RESPONSE_RESERVE_NS
            response_deadline = time.monotonic() + (delivery_deadline_ns - time.time_ns()) / 1e9
            completed, result = threading.Event(), {}

            def evaluate_in_background():
                try:
                    result.update(self._evaluate(
                        p, product, begun, started_ns, execution_id, deadline,
                        result_supported, path_home, timeout_owner, delivery_deadline_ns,
                    ))
                except Exception:
                    pass
                finally:
                    completed.set()

            threading.Thread(target=evaluate_in_background, daemon=True).start()
            if completed.wait(max(0, response_deadline - time.monotonic())) and time.monotonic() < response_deadline:
                return result or {"decision": "allow", "claude_code": {}, "output": {}, "failed": True}
            if self.disconnected:
                try:
                    self.disconnected({"hook": {
                        "execution_id": execution_id, "outcome": "failed", "exit_code": 124,
                    }})
                except Exception:
                    pass
            return {"decision": "allow", "claude_code": {}, "output": {}, "failed": True}
        return self._evaluate(p, product, begun, started_ns, execution_id, deadline,
                              result_supported, path_home, timeout_owner, deadline_ns)

    def _evaluate(self, p, product, begun=None, started_ns=None, execution_id=None,
                  deadline=None, result_supported=False, path_home=None,
                  timeout_owner=None, delivery_deadline_ns=None):
        begun = time.perf_counter() if begun is None else begun
        with self.lock:
            self.stats["received"] += 1
            self.stats["last_at"] = now()
            self.stats["by_product"][product] = self.stats["by_product"].get(product, 0) + 1
        emit_actions = self.emit_actions.get(product, False)
        name = p.get("hook_event_name")
        if name in DECISION_EVENTS and (
            not isinstance(p.get("session_id"), str) or not p["session_id"]
            or (name == "UserPromptSubmit" and not isinstance(p.get("prompt"), str))
            or (name != "UserPromptSubmit" and (
                not isinstance(p.get("tool_name"), str) or not p["tool_name"]
            ))
        ):
            return {"decision": "allow", "claude_code": {}, "output": {}, "failed": True}
        agent = {"product": product}
        if isinstance(p.get("model"), str) and p["model"]:
            agent["model"] = p["model"]
        if effort := reasoning_effort(p):
            agent["reasoning_effort"] = effort
        event = {
            "time": now(),
            "host": copy.deepcopy(self.host),
            "agent": agent,
            "session": {"id": p.get("session_id", ""), "cwd": p.get("cwd", "")},
            "source": {"collector": "hook", "path": p.get("transcript_path") or ""},
        }
        allow = {"decision": "allow", "claude_code": {}, "output": {}}
        request_id = str(uuid.uuid4())
        if name in DECISION_EVENTS:
            event["source"]["hook_request_id"] = request_id
        actions = []
        if name == "PreToolUse":
            tool = {"name": p.get("tool_name", ""), "call_id": p.get("tool_use_id", ""),
                    "input": p.get("tool_input")}
            for part in map_tool(product, p.get("tool_name", ""), p.get("tool_input")):
                action_event = copy.deepcopy(event)
                action_event.update(part)
                action_event["tool"] = copy.deepcopy(tool)
                if action_event.get("command") and not action_event["command"].get("cwd"):
                    action_event["command"]["cwd"] = p.get("cwd", "")
                actions.append(action_event)
        elif name == "UserPromptSubmit":
            actions = [dict(event, kind="prompt", text=str(p.get("prompt", "")))]
        elif name in ("PostToolUse", "PostToolUseFailure"):
            value = p.get("error") if name == "PostToolUseFailure" else p.get("tool_response")
            text = result_text(value)
            tool = {"name": p.get("tool_name", ""), "call_id": p.get("tool_use_id", ""), "output": text}
            if result_error(value) is not None:
                tool["is_error"] = result_error(value)
            result = dict(event, kind="tool.result", tool=tool)
            code = exit_code(text) if isinstance(value, str) else None
            if code is not None:
                result["command"] = {"exit_code": code}
            actions = [result]
        try:
            if emit_actions:
                for action_event in actions:
                    self.emit(copy.deepcopy(action_event))
            if name == "SessionEnd":
                self.emit(dict(event, kind="session.end", text=p.get("reason", "")))
            elif name == "SessionStart":
                self.emit(dict(event, kind="session.start", text=p.get("source", "")))
            elif product == "codex-cli" and name in ("SubagentStart", "SubagentStop"):
                child = p.get("agent_id")
                if isinstance(child, str) and child and child != p.get("session_id"):
                    self.emit(dict(event,
                        kind="session.start" if name == "SubagentStart" else "session.end",
                        session={"id": child, "parent_id": p.get("session_id", "")},
                    ))
            elif emit_actions and name == "Stop" and str(p.get("last_assistant_message") or "").strip():
                self.emit(dict(event, kind="response", text=str(p["last_assistant_message"])))
        except Exception:
            pass
        if name not in DECISION_EVENTS:
            return allow
        with self.lock:
            self.stats["evaluated"] += 1
        reply, output, action, failure = {}, {}, "allow", ""
        try:
            if self.check is None:
                raise ValueError("backend_unavailable")
            availability = "available" if controls(product, name) else "unsupported_boundary"
            if name in ("PostToolUse", "PostToolUseFailure"):
                if name == "PostToolUseFailure" or not result_supported:
                    availability = "unsupported_boundary"
                else:
                    try:
                        native_response(product, name, "deny", "", p)
                    except ValueError:
                        availability = "unsupported_boundary"
            reply = self.check({
                "product": product, "hook_event": name,
                "session_id": str(p.get("session_id", "")),
                "tool_call_id": str(p.get("tool_use_id", "")),
                "execution_id": execution_id, "request_id": request_id, "actions": actions,
                "availability": availability, "path_home": path_home,
                "timeout_owner": timeout_owner,
            }, deadline)
            if time.monotonic() >= deadline:
                raise TimeoutError("deadline_expired")
            if not isinstance(reply, dict) or (
                reply.get("status") != "evaluated" or reply.get("product") != product
                or reply.get("hook_event") != name
                or reply.get("mode") not in ("shadow", "enforce")
                or reply.get("evaluated_decision") not in ("allow", "warn", "ask", "deny")
                or reply.get("returned_decision") not in ("allow", "warn", "ask", "deny")
                or any(type(reply.get(key)) is not int or reply[key] < 0
                       for key in ("settings_version", "policy_version"))
                or any(not isinstance(reply.get(key), str)
                       for key in ("id", "request_id", "reason", "rule_id", "rule_name"))
                or (reply["mode"] == "shadow" and reply["returned_decision"] != "allow")
                or (reply["mode"] == "enforce" and reply["returned_decision"] != reply["evaluated_decision"]
                    and not (availability == "unsupported_boundary" and reply["returned_decision"] == "allow"))
            ):
                raise ValueError("invalid_backend_response")
            for key in ("id", "request_id"):
                if str(uuid.UUID(reply[key])) != reply[key]:
                    raise ValueError("invalid_backend_response")
            if availability == "unsupported_boundary":
                if reply["returned_decision"] != "allow":
                    raise ValueError("unsupported_boundary")
                action, output = "allow", {}
            else:
                action, output = native_response(product, name, reply["returned_decision"], reply["reason"], p)
        except Exception as exc:
            action, output = "allow", {}
            failure = "deadline_expired" if isinstance(exc, TimeoutError) else "backend_unavailable"
        if (timeout_owner in ("agent", "sensor") and isinstance(delivery_deadline_ns, int)
                and time.time_ns() >= delivery_deadline_ns):
            action, output, failure = "allow", {}, "deadline_expired"
        hook = {"hook_event": name, "decision": action, "request_id": request_id,
                "latency_ms": round((time.perf_counter() - begun) * 1000, 3)}
        if timeout_owner in ("agent", "sensor"):
            hook["timeout_owner"] = timeout_owner
        if reply and isinstance(reply, dict) and not failure:
            hook.update({key: reply[key] for key in (
                "evaluated_decision", "returned_decision", "mode", "settings_version",
                "policy_version", "reason", "rule_id", "rule_name", "request_id",
            )})
            hook["check_id"] = reply["id"]
        if failure:
            hook["failure_reason"] = failure
        if isinstance(started_ns, int):
            e2e = (time.time_ns() - started_ns) / 1e6
            if 0 <= e2e <= MAX_E2E_MS:
                hook["e2e_ms"] = round(e2e, 3)
        # Keep directory metadata for accounting. The normal capture projection
        # still removes it when tool-input capture is disabled.
        decision_event = copy.deepcopy(event)
        decision_event["source"] = {"collector": "hook"}
        if p.get("tool_use_id"):
            decision_event["tool"] = {"call_id": p["tool_use_id"]}
        decision_event.update(kind="hook.decision", hook=hook)
        if execution_id is not None:
            hook.update(execution_id=execution_id, delivery="pending")
        try:
            self.emit(decision_event)
        except Exception:
            pass
        if time.monotonic() >= deadline or failure:
            return dict(allow, failed=True)
        return {"decision": action, "reason": reply["reason"], "rule_id": reply["rule_id"],
                "claude_code": output, "output": output}

    def delivered(self, event):
        action = event["hook"].get("enforced") or event["hook"]["decision"]
        counter = {"deny": "denied", "ask": "asked", "warn": "warned"}.get(action)
        if counter:
            with self.lock:
                self.stats[counter] += 1

    def run(self, stop):
        owner = self
        products = {route: product for product, route in ROUTES.items()}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def rejected(self, post=False):
                """Reply and return True unless the request may proceed.

                Hook clients never send Origin. Browsers send it on cross-origin
                and same-origin posts, so a web page cannot submit events here.
                A Host other than a loopback address on this port means DNS
                rebinding. Requiring JSON makes a browser preflight a post.
                """
                if "Origin" in self.headers or (
                    post and self.headers.get_content_type() != "application/json"
                ):
                    self.send_json(403, {"error": "forbidden"})
                    return True
                if getattr(self.server, "private_socket", False):
                    # The private socket is restricted to the sensor account.
                    # Windows has no Unix server class, so test a marker.
                    return False
                if not loopback_host(self.headers.get("Host"), self.server.server_port):
                    self.send_json(403, {"error": "forbidden"})
                    return True
                if owner.token and not hmac.compare_digest(
                    self.headers.get("Authorization", "").encode(),
                    ("Bearer " + owner.token).encode(),
                ):
                    self.send_json(401, {"error": "unauthorized"})
                    return True
                return False

            def do_GET(self):
                if self.rejected():
                    return
                if self.path == "/v1/status":
                    self.send_json(200, owner.status())
                elif self.path == "/healthz":
                    self.send_json(200, {"status": "ok"})
                else:
                    self.send_json(404, {"error": "not found"})

            def do_POST(self):
                if self.rejected(post=True):
                    return
                url = urlsplit(self.path)
                native = url.path.endswith("/native")
                product = products.get(url.path.removesuffix("/native") if native else url.path)
                if not product:
                    return self.send_json(404, {"error": "not found"})
                # The direct client has no account token. It can only use the
                # socket whose permissions already restrict it to this account.
                if native and not getattr(self.server, "private_socket", False):
                    return self.send_json(403, {"error": "private socket required"})
                query = {}
                try:
                    length = int(self.headers.get("Content-Length", 0))
                    if length < 0 or length > 4 << 20:
                        raise ValueError("payload too large")
                    payload = json.loads(self.rfile.read(length))
                    if not isinstance(payload, dict):
                        raise ValueError("object required")
                    query = parse_qs(url.query, keep_blank_values=True)
                    if not payload.get("hook_event_name"):
                        payload["hook_event_name"] = query.get("event", [""])[0]
                    started = query.get("started", [""])[0]
                    deadline = query.get("deadline", [""])[0]
                    timeout_owner = query.get("timeout_owner", [None])[0]
                    if timeout_owner == "agent" and not (
                        started.isdigit() and deadline.isdigit()
                        and int(deadline) - int(started) in AGENT_HOOK_TIMEOUTS_NS
                    ):
                        raise ValueError("invalid agent hook deadline")
                    if timeout_owner == "sensor" and not (
                        started.isdigit() and deadline.isdigit()
                        and 0 < int(deadline) - int(started) <= (
                            HOOK_TIMEOUT_SECONDS * 1_000_000_000 - hook_runtime.EXIT_RESERVE_NS
                        )
                    ):
                        raise ValueError("invalid sensor hook deadline")
                    supported = query.get("result_capable", [""])[0] == "1"
                    # The small Windows client leaves capability inspection in
                    # the running sensor. TCP authentication has already passed.
                    if not native and "client_pid" in query and payload["hook_event_name"] == "PostToolUse":
                        pid = query["client_pid"][0]
                        agent = next(agent for agent, value in PRODUCTS.items() if value == product)
                        supported = pid.isdigit() and result_capable(
                            {"data_dir": str(owner.socket_path.parent)}, agent, pid=int(pid),
                        )
                    path_home = query.get("path_home", [None])[0]
                    if native:
                        if not re.fullmatch(r"[A-Za-z0-9]{6,64}", query.get("execution", [""])[0]):
                            raise ValueError("execution ID required")
                        if timeout_owner not in ("agent", "sensor") and deadline.isdigit() and started.isdigit():
                            # Older immutable launchers advertise two seconds,
                            # although curl stops after 1.4 seconds. Account for
                            # setup already spent before this request arrived.
                            deadline = str(min(int(deadline), int(started) + 1_400_000_000))
                        if not deadline.isdigit() or (timeout_owner != "agent" and time.time_ns() >= int(deadline)):
                            return self.send_json(503, {"error": "hook deadline expired"})
                        encoded_home = self.headers.get("X-OpenAIDR-Home", "")
                        path_home = base64.b64decode(encoded_home, validate=True).decode("utf-8") or None
                        pid = self.headers.get("X-OpenAIDR-Client-Pid", "")
                        supported = False
                        if payload["hook_event_name"] == "PostToolUse" and pid.isdigit():
                            agent = next(agent for agent, value in PRODUCTS.items() if value == product)
                            supported = result_capable(
                                {"data_dir": str(owner.socket_path.parent)}, agent, pid=int(pid),
                            )
                    result = owner.evaluate(
                        payload,
                        product,
                        int(started) if started.isdigit() else None,
                        query.get("execution", [None])[0],
                        int(deadline) if deadline.isdigit() else None,
                        supported,
                        path_home,
                        timeout_owner,
                    )
                    if native:
                        if result.get("failed") or time.time_ns() >= int(deadline):
                            return self.send_json(503, {"error": "hook unavailable"})
                        # All backend validation and agent-specific formatting
                        # stays in the daemon. Empty allows have no native output.
                        output = result["output"]
                        if not isinstance(output, dict):
                            raise ValueError("invalid native response")
                        return self.send_json(200 if output else 204, output)
                    self.send_json(200, result)
                except (ValueError, TypeError):
                    self.send_json(
                        400, {"decision": "allow", "claude_code": {}, "output": {}}
                    )
                except (BrokenPipeError, ConnectionResetError):
                    # Disconnection is delivery failure, but not proof of why
                    # the agent stopped waiting. Queue evidence without disk I/O.
                    if query.get("timeout_owner") in (["agent"], ["sensor"]) and owner.disconnected:
                        owner.disconnected({"hook": {
                            "execution_id": query.get("execution", [""])[0],
                            "outcome": "failed",
                        }})

            def send_json(self, status, body):
                data = b"" if status == 204 else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if data:
                    self.wfile.write(data)

        host, port = self.listen.rsplit(":", 1)
        host = host.strip("[]")
        servers, threads, errors = [], [], []
        unix_identity = None

        def remove_bound_socket():
            try:
                if unix_identity is not None and os.path.samestat(unix_identity, self.socket_path.lstat()):
                    self.socket_path.unlink()
            except OSError:
                pass

        try:
            try:
                class Server(HookAdmissionMixIn, LoopbackHTTPServer):
                    token = owner.token

                servers.append(Server((host, int(port)), Handler))
            except OSError as exc:
                errors.append(exc)
            unix_server = getattr(socketserver, "UnixStreamServer", None)
            if os.name != "nt" and unix_server is not None:

                class UnixServer(HookAdmissionMixIn, BoundedThreadingMixIn, unix_server):
                    daemon_threads = True
                    private_socket = True

                private = None
                try:
                    try:
                        private = UnixServer(str(self.socket_path), Handler)
                    except OSError as exc:
                        if exc.errno != errno.EADDRINUSE:
                            raise
                        previous = self.socket_path.lstat()
                        if not stat.S_ISSOCK(previous.st_mode) or previous.st_uid != os.getuid():
                            raise
                        # A second sensor must not replace a live listener. Only
                        # reclaim a same-user socket left behind by a stopped one.
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                            peer.settimeout(0.2)
                            try:
                                peer.connect(str(self.socket_path))
                            except ConnectionRefusedError:
                                if not os.path.samestat(previous, self.socket_path.lstat()):
                                    raise exc
                                self.socket_path.unlink()
                            else:
                                raise exc
                        private = UnixServer(str(self.socket_path), Handler)
                    unix_identity = self.socket_path.lstat()
                    self.socket_path.chmod(0o600)
                except OSError as exc:
                    errors.append(exc)
                    if private is not None:
                        private.server_close()
                        remove_bound_socket()
                        unix_identity = None
                else:
                    servers.append(private)
            if not servers:
                raise OSError("No hook listener could start: " + "; ".join(map(str, errors))) from errors[-1]
            for server in servers:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                threads.append((server, thread))
            stop.wait()
        finally:
            for server, _ in threads:
                server.shutdown()
            for server in servers:
                server.server_close()
            for _, thread in threads:
                thread.join()
            remove_bound_socket()


def private_status(config, *, expected_pid=None, timeout=5):
    """Read Linux status from the current UID and, when supplied, the service PID."""
    deadline = time.monotonic() + timeout

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("Sensor status deadline expired.")
        return value

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(remaining())
        peer.connect(str(Path(config["data_dir"]) / "sensor.sock"))
        credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII"))
        pid, uid, _ = struct.unpack("iII", credentials)
        if uid != os.geteuid():
            raise PermissionError("The sensor status socket belongs to another user.")
        if expected_pid is not None and pid != expected_pid:
            raise PermissionError("The sensor status socket belongs to another process.")

        def expire():
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        # HTTP parsing can perform many reads. Stop trickling responses at the
        # absolute deadline instead of resetting the budget for each read.
        timer = threading.Timer(remaining(), expire)
        timer.daemon = True
        connection = HTTPConnection("localhost", timeout=remaining())
        connection.sock = peer
        timer.start()
        try:
            peer.settimeout(remaining())
            connection.request("GET", "/v1/status")
            peer.settimeout(remaining())
            with connection.getresponse() as response:
                if response.status != 200:
                    raise ValueError(f"Sensor status returned HTTP {response.status}.")
                peer.settimeout(remaining())
                result = json.loads(response.read())
                if not isinstance(result, dict):
                    raise ValueError("Sensor status must be a JSON object.")
                remaining()
                return result
        except Exception as exc:
            if time.monotonic() >= deadline:
                raise TimeoutError("Sensor status deadline expired.") from exc
            raise
        finally:
            timer.cancel()
            connection.close()


def local_token(config):
    """The account token the loopback hook listener requires, if configured.

    Every local account can reach loopback TCP, so the per-user control token
    from the private sensor config authenticates callers. A sensor running as
    root or SYSTEM serves every account and cannot share that token with them.
    """
    from .telemetry import settings

    return settings(config).get("local_token") or None


def local_request(config, method, path, **kwargs):
    token = local_token(config)
    if token:
        kwargs["headers"] = {**(kwargs.get("headers") or {}), "Authorization": "Bearer " + token}
    sock = Path(config["data_dir"]) / "sensor.sock"
    transport = (
        httpx.HTTPTransport(uds=str(sock))
        if os.name != "nt" and sock.exists()
        else None
    )
    with httpx.Client(transport=transport, timeout=5, trust_env=False) as client:
        response = client.request(method, "http://" + config["listen"] + path, **kwargs)
        response.raise_for_status()
        return response.json()
