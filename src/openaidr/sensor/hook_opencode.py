"""Install a dependency-free OpenCode plugin without modifying user plugins."""

import json
import ipaddress
import os
from pathlib import Path
import shlex

from . import hook_runtime
from .settings_files import edit_settings
from .config import Config

MARKER = "// OpenAIDR OpenCode hook plugin v1\n"
PREFIX = "const openaidr = "


def telemetry_destination(config_path):
    """Use the configured loopback receiver without telemetry credentials."""
    from urllib.parse import urlsplit
    from .telemetry import settings

    if config_path is None or not Path(config_path).is_file():
        return None
    options = settings(Config.load(config_path))
    if not options["enabled"] or "opencode" in (options.get("disabled_agents") or []):
        return None
    endpoint = "http://" + options["listen"] + "/v1/logs"
    parsed = urlsplit(endpoint)
    if not ipaddress.ip_address(parsed.hostname).is_loopback or parsed.username or parsed.password:
        raise ValueError("OpenCode usage requires the loopback telemetry receiver")
    return {"endpoint": endpoint}


def render(config):
    return MARKER + PREFIX + json.dumps(config, ensure_ascii=True) + ";\n" + Path(__file__).with_suffix(".js").read_text()


def read(path):
    text = Path(path).read_text()
    if not text.startswith(MARKER + PREFIX):
        raise ValueError("not an OpenAIDR plugin")
    line = text[len(MARKER + PREFIX):].partition("\n")[0]
    config = json.loads(line.removesuffix(";"))
    if text != render(config):
        raise ValueError("plugin has changed")
    return config


def present(path):
    try:
        return Path(path).read_text().startswith(MARKER)
    except OSError:
        return False


def install(path, executable, config_path):
    from . import hooks

    path = Path(path)
    directory = hook_runtime.directory(path)

    def update(files):
        existing = files.text(path)
        if existing and not existing.startswith(MARKER):
            raise ValueError(f"{path}: an unrelated plugin already uses this path")
        commands = {event: hooks.command_line(executable, event, "opencode", config_path, health_dir=directory)
                    for event in hooks.managed_events("opencode")}
        config = {"commands": commands, "invocations": {event: shlex.split(command) for event, command in commands.items()},
                  "timeout": hooks.hook_timeout("PreToolUse", "opencode"),
                  "telemetry": telemetry_destination(config_path)}
        files.write(path, render(config))

    hook_runtime.register(config_path, directory)
    edit_settings([path], update)


def uninstall(path, config_path):
    path = Path(path)

    def update(files):
        if files.text(path).startswith(MARKER):
            files.delete(path)

    edit_settings([path], update)
    hook_runtime.cleanup(hook_runtime.directory(path), "opencode", config_path)


def available(path, config_path=None, *, match_config=False):
    from . import hooks

    try:
        config = read(path)
        if config["timeout"] != hooks.hook_timeout("PreToolUse", "opencode"):
            return False
        if match_config and config.get("telemetry") != telemetry_destination(config_path):
            return False
        for event in hooks.managed_events("opencode"):
            command = config["commands"][event]
            if config["invocations"][event] != shlex.split(command):
                return False
            handler = {"type": "command", "command": command, "timeout": config["timeout"]}
            if not hooks.available({"hooks": [handler]}, event, "opencode"):
                return False
            if match_config:
                parts, _ = hook_runtime.arguments(command, windows=os.name == "nt")
                if parts[1:] != hooks.command_args("", event, "opencode", config_path)[1:]:
                    return False
                if os.name != "nt":
                    runner = Path(shlex.split(command)[4])
                    if hook_runtime.posix_config(runner.read_text()).get("socket_path") != hooks.native_socket(config_path):
                        return False
        return True
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return False


def current(path, config_path):
    return available(path, config_path, match_config=True)


def executables(path):
    try:
        return {hook_runtime.arguments(command, windows=os.name == "nt")[0][0]
                for command in read(path)["commands"].values()}
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return set()
