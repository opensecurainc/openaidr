"""Remove desktop-managed collection, with explicit managed-data cleanup."""

import json
from contextlib import ExitStack, nullcontext
import os
import plistlib
import re
import shutil
import stat
import time
from pathlib import Path

from openaidr.core.files import atomic_write
from . import hook_runtime, hooks, integrations, local_runtime, service
from .config import Config, configuration_lock, default_path, is_root

MARKER = "desktop-removal.json"


def marker(config):
    return config.path.parent / MARKER


def _job(label):
    result = service._run(["launchctl", "print", label], text=True, timeout=10)
    if result.returncode == 113:  # launchctl: service not found
        return None
    if result.returncode:
        raise ValueError("Cannot inspect the background sensor. Check your macOS login session and retry removal.")
    return result.stdout


def _process_start(pid):
    result = service._run(["/bin/ps", "-p", str(pid), "-o", "lstart="],
                          text=True, timeout=5, env={**os.environ, "LC_ALL": "C"})
    if result.returncode == 1 and not result.stdout.strip():
        return None
    if result.returncode or not result.stdout.strip():
        raise ValueError("Cannot inspect the background sensor process. Retry removal.")
    return result.stdout.strip()


def _read_saved(config):
    saved = json.loads(marker(config).read_text())
    if (not isinstance(saved, dict) or saved.get("state") not in ("pending", "complete")
            or not isinstance(saved.get("errors"), list) or any(not isinstance(error, str) for error in saved["errors"])):
        raise ValueError("The removal record is invalid.")
    return saved


def _preferences(saved):
    preferences = saved.get("preferences")
    if not isinstance(preferences, dict) or set(preferences) != {"hooks", "telemetry"}:
        return None
    if any(not isinstance(disabled, list) or any(agent not in hooks.AGENTS for agent in disabled)
           for disabled in preferences.values()):
        return None
    return preferences


def stop(config, saved):
    """Verify the user's registered service and wait for its process to exit."""
    for name in service.NAMES:
        _stop_one(config, saved, name)


def _stop_one(config, saved, name):
    path = Path.home() / "Library/LaunchAgents" / (name + ".plist")
    label = f"gui/{os.getuid()}/{name}"
    process_key = "sensor_process" if name == service.LEGACY_NAME else "openaidr_process"
    job = _job(label)
    if path.is_symlink():
        raise ValueError("The sensor service uses a symbolic link. Remove this customized service manually.")
    if path.exists():
        document = plistlib.loads(path.read_bytes())
        if document.get("Label") != name or service.config_argument(document.get("ProgramArguments")) != config.path.resolve():
            raise ValueError("The background service uses another configuration. Remove that service manually.")
    elif job is not None:
        raise ValueError("The loaded sensor has no service file. Remove this customized service manually.")
    process = saved.get(process_key)
    if not isinstance(process, dict) or not isinstance(process.get("pid"), int) or process["pid"] <= 1 or not isinstance(process.get("started"), str):
        process = None
    if job is not None:
        arguments = re.search(r"^\s*arguments = \{\n(.*?)^\s*\}", job, re.MULTILINE | re.DOTALL)
        if not arguments or service.config_argument([line.strip() for line in arguments[1].splitlines() if line.strip()]) != config.path.resolve():
            raise ValueError("The loaded sensor uses an unverified configuration. Remove this customized service manually.")
        match = re.search(r"^\s*pid = (\d+)\s*$", job, re.MULTILINE)
        if "state = running" in job and (not match or int(match[1]) <= 1):
            raise ValueError("Cannot verify the background sensor process. Retry removal.")
        if match:
            pid = int(match[1])
            started = _process_start(pid)
            process = {"pid": pid, "started": started} if started else None
            saved[process_key] = process
            atomic_write(marker(config), json.dumps(saved))
        service._run(["launchctl", "bootout", label], check=True, timeout=15)
    deadline = time.monotonic() + 30 if process else 0
    # launchd can forget the job before its child exits. A later retry must
    # wait for that process, without mistaking a reused PID for the sensor.
    while process and _process_start(process["pid"]) == process["started"]:
        if time.monotonic() >= deadline:
            raise ValueError("The background sensor is still stopping. Retry removal shortly.")
        time.sleep(0.1)
    if _job(label) is not None:
        raise ValueError("The background sensor remains registered. Retry removal.")
    path.unlink(missing_ok=True)
    saved.pop(process_key, None)


def remove_hooks(config, agent, *, path=None, config_toml=None):
    if agent == "codex" and path is None:
        errors = []
        for path, config_toml in hooks.codex_paths(config).items():
            try:
                remove_hooks(config, agent, path=path, config_toml=config_toml)
            except Exception as exc:
                errors.append(f"{path}: {exc}")
        # Removal stops automatic setup even when a profile needs manual repair.
        # The saved agent-wide preference is restored by resume().
        hooks.set_opt_out(config, agent, True)
        if errors:
            raise ValueError("; ".join(errors))
        return
    path = path or hooks.settings_path(agent, config)
    if not path.exists():
        hook_runtime.cleanup(hook_runtime.directory(path), agent, config.path)
        return
    # Another manually configured sensor can share the user's agent settings.
    # Leave its handlers untouched rather than removing all OpenAIDR hooks.
    if agent == "opencode":
        from . import hook_opencode

        commands = hook_opencode.read(path)["commands"].values() if hook_opencode.present(path) else []
    else:
        document = hooks.load_settings(path)
        events = document.get("openaidr" if agent == "antigravity" else "hooks")
        commands = [handler["command"] for event in (events if isinstance(events, dict) else {})
                    for group in hooks.groups(document, event, agent)
                    for handler in group.get("hooks", []) if hooks.our_handler(handler)]
    for command in commands:
        args, _ = hook_runtime.arguments(command, windows=False)
        target = Path(args[args.index("--config") + 1]) if "--config" in args else default_path()
        if target.expanduser().resolve() != config.path.resolve():
            raise ValueError(f"{path} contains hooks for another sensor configuration. Remove those hooks manually.")
    hooks.uninstall(path, agent, config_toml or hooks.codex_config_path(config), config_path=config.path)


def remove(config, progress=None):
    from .bridge import live_status

    if service.platform.system() != "Darwin" or is_root():
        raise ValueError("Desktop removal supports the current user's macOS installation only.")
    with configuration_lock(config.path):
        config = Config.load(config.path)
        try:
            saved = _read_saved(config)
        except (OSError, ValueError):
            saved = {}
        if _preferences(saved) is None:
            # Recovery cannot infer earlier choices from a damaged record.
            # Preserve the current opt-outs rather than silently enabling them.
            saved["preferences"] = {
                section: list((config.get(section) or {}).get("disabled_agents") or [])
                for section in ("hooks", "telemetry")
            }
        saved.update(state="pending", errors=[], retained_data=str(Path(config["data_dir"])))
        atomic_write(marker(config), json.dumps(saved))
        try:
            with progress.phase("services") if progress else nullcontext():
                stop(config, saved)
                if live_status(config):
                    raise ValueError("A manually started sensor still answers locally. Stop it, then retry removal.")
        except Exception as exc:
            saved["errors"].append(str(exc))
        try:
            local_runtime.cleanup(config)
        except Exception as exc:
            saved["errors"].append(f"Cannot stop the local runtime: {exc}")
        # Restore settings even after a shutdown failure, so new sessions stop
        # supplying activity while the user fixes the remaining service issue.
        with progress.phase("integrations") if progress else nullcontext():
            for agent in integrations.AGENTS:
                try:
                    result = integrations.remove(config, [agent], disconnect=True)["agents"][0]
                    if result["unresolved"]:
                        saved["errors"].append(f"{hooks.PRODUCTS[agent]} settings still export to OpenAIDR: {', '.join(result['unresolved'])}. Keep your edits and remove those exporters manually, then retry.")
                except Exception as exc:
                    saved["errors"].append(f"Cannot restore {hooks.PRODUCTS[agent]} telemetry: {exc}")
            for agent in hooks.AGENTS:
                try:
                    remove_hooks(config, agent)
                    hooks.set_opt_out(config, agent, True)
                except Exception as exc:
                    saved["errors"].append(f"Cannot remove {hooks.PRODUCTS[agent]} hooks: {exc}")
        if not saved["errors"]:
            saved["state"] = "complete"
        atomic_write(marker(config), json.dumps(saved))
        return {"desktop_removal": saved}


def resume(config):
    """Restore choices from before removal; native code clears the marker last."""
    if service.platform.system() != "Darwin" or is_root():
        raise ValueError("Desktop setup supports the current user's macOS installation only.")
    with configuration_lock(config.path):
        try:
            saved = _read_saved(config)
            preferences = _preferences(saved)
        except (OSError, ValueError):
            preferences = None
        if preferences is None:
            raise ValueError("The saved removal preferences are invalid. Retry removal before setting up again.")
        if saved.get("data_deletion_started") and not saved.get("data_deleted"):
            raise ValueError("Finish deleting local data before reinstalling.")
        config = Config.load(config.path)
        from .desktop_edition import enterprise_only

        if (not enterprise_only() and config.get("server_url") == local_runtime.ORIGIN
                and (local_runtime.directory(config) / "state.json").exists()):
            local_runtime.start(config, current_source=False)
        for section, disabled in preferences.items():
            values = dict(config.get(section) or {})
            values["disabled_agents"] = disabled
            config[section] = values
        config.save()
        return {"resumed": True}


def purge(config):
    """Delete managed data while keeping removal and locking barriers intact."""
    from .removal_progress import Progress

    progress = Progress(default_path().parent)
    with progress.phase("validation"):
        if service.platform.system() != "Darwin" or is_root():
            raise ValueError("Local data deletion supports the current user's macOS installation only.")
        root = default_path().parent
        if config.path != default_path() or root.resolve() != root.absolute() or config.path.is_symlink():
            raise ValueError("This installation uses a custom or linked folder. Quit OpenAIDR and remove its data manually.")
        original_root = root.lstat()
    with ExitStack() as stack:
        with progress.phase("configuration_lock"):
            stack.enter_context(configuration_lock(config.path))
        config = Config.load(config.path)
        saved = _read_saved(config)
        if saved["state"] != "complete" or saved["errors"]:
            raise ValueError("Finish removing collection before deleting local data.")
        # Never descend into a mounted volume inside the managed folder.
        with progress.phase("scan") as counts:
            counts.update(files=0, directories=0)
            def scan_error(exc):
                progress.operation, progress.path = "scandir", exc.filename or root
                raise exc
            for directory, folders, files in os.walk(root, followlinks=False, onerror=scan_error):
                counts["files"] += len(files)
                counts["directories"] += 1
                if os.path.ismount(directory) or any(os.path.ismount(Path(directory) / name) for name in folders):
                    raise ValueError("The local folder contains a mounted volume. Quit OpenAIDR and remove its data manually.")
        # Once cleanup starts, retries must still work after sensor.yaml is gone.
        if not saved.get("data_deletion_started"):
            data = Path(config["data_dir"])
            if not data.is_absolute() or not data.resolve().is_relative_to(root.resolve()):
                raise ValueError("The sensor uses a custom data folder outside OpenAIDR. Quit the app and remove the retained folders manually.")
            saved = remove(config, progress)["desktop_removal"]
            if saved["state"] != "complete":
                raise ValueError("Collection could not be stopped. Retry removal before deleting local data.")
        else:
            # Recheck services on every retry, including after partial deletion.
            with progress.phase("services"):
                stop(config, saved)
                from .bridge import live_status

                if live_status(config):
                    raise ValueError("A sensor is still running. Stop it before deleting local data.")
        with progress.phase("record"):
            progress.operation, progress.path = "write", marker(config)
            saved.update(data_deletion_started=True, data_deleted=False)
            atomic_write(marker(config), json.dumps(saved))
        keep = {MARKER, "sensor.yaml.lock", "desktop-updater.lock", "desktop-operation.lock"}
        with progress.phase("deletion"):
            if not saved.get("local_runtime_deleted"):
                local_runtime.cleanup(config, delete=True)
                # Keep credentials until Docker deletion succeeds. Persist success
                # before deleting files so partial filesystem cleanup is retryable.
                saved["local_runtime_deleted"] = True
                atomic_write(marker(config), json.dumps(saved))
            progress.operation = "open"
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                progress.operation = "fstat"
                identity = os.fstat(descriptor)
                if (identity.st_dev, identity.st_ino) != (original_root.st_dev, original_root.st_ino):
                    progress.operation = "identity"
                    raise OSError("The managed folder changed before deletion")
                progress.operation = "listdir"
                for name in os.listdir(descriptor):
                    if name in keep:
                        continue
                    progress.operation, progress.path = "stat", name
                    entry = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    if stat.S_ISDIR(entry.st_mode):
                        progress.operation = "rmtree"
                        shutil.rmtree(name, dir_fd=descriptor, onerror=progress.rmtree_error)
                    else:
                        progress.operation = "unlink"
                        os.unlink(name, dir_fd=descriptor)
                progress.operation, progress.path = "identity", root
                current = root.lstat()
                if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
                    raise OSError("The managed folder changed during deletion")
            finally:
                os.close(descriptor)
        with progress.phase("record"):
            progress.operation, progress.path = "write", marker(config)
            # Keep no enrollment or previous preferences in the durable stop marker.
            saved = {"state": "complete", "errors": [], "preferences": {"hooks": [], "telemetry": []},
                     "data_deletion_started": True, "data_deleted": True}
            atomic_write(marker(config), json.dumps(saved))
            return {"desktop_removal": saved}
