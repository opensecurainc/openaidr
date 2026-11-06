"""Recoverable Windows state relocation, called by the signed update worker."""

import json
import os
from pathlib import Path
import stat

import yaml

from openaidr.core.files import atomic_write

# Release 1 teaches existing installations the migration protocol. Release 2
# changes packaging and defaults only after release 1 is on the older feeds.
LAYOUT = 2


def paths(environ=None):
    environ = os.environ if environ is None else environ
    local = Path(environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    return local / "OpenAIDR Sensor", local / "OpenAIDR" / "data", local / "OpenAIDR" / "migration"


def state_root(environ=None):
    legacy, current, _ = paths(environ)
    # The bridge release must also work after recovery relocated its state.
    if current.exists():
        if (legacy / "sensor.yaml").exists():
            raise ValueError("Both Windows configurations exist. No configuration was selected.")
        return current
    if legacy.exists() or LAYOUT == 1:
        return legacy
    return current


def plain_tree(path):
    """Never relocate state through a junction, symlink, or special file."""
    path = Path(path)
    for parent in (path, *path.parents):
        if parent.exists() or parent.is_symlink():
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Windows migration paths must not contain links.")
    if not path.exists():
        return
    for directory, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            item = Path(directory) / name
            info = item.lstat()
            if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                    or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))):
                raise ValueError("Windows migration state contains an unsupported file.")


def relocate_config(source, destination):
    """Rewrite only operational paths; never rewrite captured activity."""
    path = destination / "sensor.yaml"
    if not path.exists():
        return
    values = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(values, dict):
        raise ValueError("The saved Windows configuration must be a mapping.")
    for key in ("data_dir", "client_cert", "client_key", "ca_cert"):
        value = values.get(key)
        if not isinstance(value, str):
            continue
        try:
            relative = Path(value).relative_to(source)
        except ValueError:
            continue
        values[key] = str(destination / relative)
    atomic_write(path, yaml.safe_dump(values, sort_keys=False))


def preflight(*, environ=None):
    """Check support before the recovery worker removes the previous app."""
    from . import windows_task
    from .config import windows_base_dir

    legacy, current, recovery = paths(environ)
    for path in (legacy, current, recovery):
        plain_tree(path)
    if current.exists() and legacy.exists():
        raise ValueError("Both Windows data locations exist. No data was overwritten.")
    if windows_base_dir(environ) != legacy:
        raise ValueError("Automatic Windows folder migration requires the existing per-user state directory.")
    previous = windows_task.state()
    if previous["installed"]:
        if (previous.get("drift") or windows_task.configured_config() != legacy / "sensor.yaml"
                or not Path(previous["execute"]).is_relative_to(legacy / "runtime")):
            raise ValueError("The background task uses a custom configuration or runtime. Its data was kept.")
    return previous


def migrate(*, environ=None):
    """Move state only after the worker installed and verified the new app.

    The native worker owns the updater/window locks and a recovery schedule
    outside both state directories. This journal survives the directory rename
    and records user disablement before stopping the background task.
    """
    from . import windows_task, windows_runtime, hooks
    from .config import Config

    legacy, current, recovery = paths(environ)
    for path in (legacy, current, recovery):
        plain_tree(path)
    transaction = recovery / "desktop-update.json"
    if not transaction.is_file():
        raise ValueError("Start Windows folder migration through the app's update command.")
    pending = json.loads(transaction.read_text(encoding="utf-8")).get("pending") or {}
    if pending.get("install_started") is not True or pending.get("release", {}).get("layout") != 2:
        raise ValueError("The Windows update worker has not prepared this migration.")
    journal = recovery / "sensor-migration.json"
    if journal.exists():
        state = json.loads(journal.read_text(encoding="utf-8"))
    else:
        previous = preflight(environ=environ)
        state = {"task": previous, "moved": not legacy.exists(), "complete": False}
        atomic_write(journal, json.dumps(state))
    if state["complete"]:
        return
    previous = state["task"]
    if previous["installed"]:
        configured = windows_task.configured_config()
        task = windows_task.state()
        executable = Path(task.get("execute", ""))
        if (not task["installed"] or task.get("drift")
                or configured not in (legacy / "sensor.yaml", current / "sensor.yaml")
                or not any(executable.is_relative_to(root / "runtime") for root in (legacy, current))):
            raise ValueError("The background task changed during Windows migration.")
    try:
        if previous["installed"]:
            windows_task.stop()
            # A disabled Scheduled Task alone does not prove its process exited.
            windows_task._powershell(windows_task._stop_processes_script(executable))
        if not state["moved"]:
            if legacy.exists() and current.exists():
                raise ValueError("Both Windows data locations exist. No data was overwritten.")
            if legacy.exists():
                # Rename preserves SQLite databases, journals, credentials,
                # queue bytes, ACLs, and immutable runtime directories together.
                legacy.rename(current)
            elif not current.is_dir():
                raise ValueError("The Windows state directory is missing.")
            state["moved"] = True
            atomic_write(journal, json.dumps(state))
    except Exception:
        if previous["installed"] and legacy.exists():
            windows_task.restore_state(previous)
        # Once renamed, the old task action is invalid. The retained worker
        # must finish configuration and runtime validation before restarting it.
        raise
    relocate_config(legacy, current)
    config = Config.load(current / "sensor.yaml")
    bundle = current.parent / "app" / "runtime"
    selected = windows_runtime.select(bundle, current / "runtime")
    executable = windows_runtime.console(selected)
    if previous["installed"]:
        windows_task.relocate(legacy / "sensor.yaml", config.path, executable, previous)
    for agent in hooks.AGENTS:
        path = hooks.settings_path(agent, config)
        settings = {} if agent == "opencode" else hooks.load_settings(path)
        # The old executable disappeared with the rename, so availability
        # cannot identify the hooks we must retarget.
        owned = hooks.present(path, agent)
        if owned and not hooks.settings_disabled(settings, agent, path) and not hooks.opted_out(config, agent):
            hooks.install(path, str(executable), agent,
                          config_path=config.path, config_toml=hooks.codex_config_path(config))
    state["complete"] = True
    atomic_write(journal, json.dumps(state))


def main(*, check=False):
    if os.name != "nt":
        raise ValueError("Windows state migration requires Windows.")
    if check:
        preflight()
    else:
        migrate()
    return 0
