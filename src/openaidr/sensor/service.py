"""Native systemd, launchd, and per-user Windows Scheduled Task integration."""

import filecmp
import hashlib
import json
import os
import platform
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from .config import is_root, base_dir, default_data_dir

NAME = "openaidr"
LEGACY_NAME = "openaidr-sensor"
NAMES = (NAME, LEGACY_NAME)


def _run(*args, **kwargs):
    kwargs.setdefault("capture_output", True)
    return subprocess.run(*args, **kwargs)


def executable():
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve())
    # A public package also owns the short command name. Only trust this
    # installation's siblings, never an unrelated `openaidr` found on PATH.
    directory = Path(sys.executable).parent
    for name in NAMES:
        candidate = directory / (name + (".exe" if os.name == "nt" else ""))
        if candidate.is_file():
            return str(candidate)
    return shutil.which(LEGACY_NAME) or str(directory / NAME)


def staged_path():
    """Where a frozen standalone service is staged, outside the app bundle."""
    if platform.system() == "Darwin":
        directory = base_dir() / "bin"
    else:
        directory = default_data_dir() / "bin"
    return directory / (NAME + (".exe" if os.name == "nt" else ""))


def windows_runtime():
    """The one-directory runtime this frozen Windows sensor runs from, or None."""
    if os.name != "nt" or not getattr(sys, "frozen", False):
        return None
    from . import windows_runtime as runtime

    return runtime.bundled(sys.executable)


def staged_executable():
    """The executable the service runs, without staging anything.

    Hook commands point here. Copying is left to service install and
    restart. Desktop setup selects its bundled version exactly; standalone
    installation preserves a newer staged service.
    """
    if not getattr(sys, "frozen", False):
        return str(Path(executable()).resolve())
    if windows_runtime() is not None:
        from . import windows_runtime as runtime

        active = runtime.current(runtime.root())
        return str(runtime.console(active)) if active else str(Path(executable()).resolve())
    target = staged_path()
    legacy = target.with_name(LEGACY_NAME + target.suffix)
    if not target.exists() and legacy.exists():
        target = legacy
    return str(target.resolve()) if target.exists() else str(Path(executable()).resolve())


def hook_executable():
    """Stage a build-matched unpacked hook runtime without changing the service."""
    binary = staged_executable()
    if os.name == "nt" or not getattr(sys, "frozen", False) or not hasattr(sys, "_MEIPASS"):
        return binary
    bundle = Path(sys._MEIPASS) / "hook-client.tar"
    if not bundle.is_file():
        return binary
    from openaidr.build_info import validate

    with tarfile.open(bundle) as archive:
        bundled = validate(json.load(archive.extractfile("./build.json")))
    selected = _binary_build(Path(binary))
    if not selected:
        raise ValueError("Cannot verify the sensor build for hook installation")
    identity = hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest()
    directory = staged_path().parent / "hooks" / identity
    target = directory / "openaidr-sensor"
    if (directory / ".complete").is_file() and target.is_file():
        return str(target)
    if selected != bundled:
        # An older app cannot install its helper over a newer staged sensor.
        return binary
    directory.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = Path(tempfile.mkdtemp(prefix=".new-", dir=directory.parent))
    try:
        with tarfile.open(bundle) as archive:
            archive.extractall(temporary, filter="data")
        (temporary / ".complete").write_text(identity)
        try:
            os.rename(temporary, directory)
        except OSError:
            # A concurrent setup may have published this same immutable build.
            if not (directory / ".complete").is_file() or not target.is_file():
                raise
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    return str(target)


def stable_executable(*, match_version=False):
    """Copy frozen standalone service out of transient app/download locations."""
    source = Path(executable())
    if not getattr(sys, "frozen", False):
        return str(source.resolve())
    bundle = windows_runtime()
    if bundle is not None:
        from . import windows_runtime as runtime

        return str(runtime.console(runtime.select(bundle, runtime.root(), match_version=match_version)))
    target = staged_path()
    targets = (target, target.with_name(LEGACY_NAME + target.suffix))
    runtimes = {}
    runtime_digests = {}
    if platform.system() == "Darwin":
        from . import macos_runtime

        verified = {}
        for candidate in ((source,) if match_version else (source, *targets)):
            if candidate.is_file() and candidate not in runtimes:
                data = candidate.read_bytes()
                digest = hashlib.sha256(data).digest()
                if digest not in verified:
                    original = Path(sys.executable) if candidate == source else candidate
                    verified[digest] = macos_runtime.inspect(original, data)
                runtimes[candidate] = verified[digest]
                if runtimes[candidate] is not None:
                    runtime_digests[candidate] = digest
        if any(runtimes.values()):
            if target.parent.is_symlink() or any(path.is_symlink() for path in (Path(sys.executable), *targets)):
                raise ValueError("Cannot stage a sensor runtime through a symlink. Repair the installation first.")
    from openaidr import build_info
    from .bridge import keep_existing, order_key

    selected = source
    incoming = _binary_build(selected)
    runtime_builds = {runtime_digests[source]: incoming} if source in runtime_digests else {}
    if match_version and (target.parent.is_symlink() or any(path.is_symlink() for path in (source, *targets))):
        raise ValueError("Cannot stage a sensor through a symbolic link.")
    if match_version and not incoming:
        raise ValueError("Cannot verify the bundled sensor version.")
    installed = []
    for existing in (() if match_version else targets):
        if existing.is_file():
            digest = runtime_digests.get(existing)
            if existing.resolve() == selected.resolve():
                previous = incoming
            elif digest in runtime_builds:
                previous = runtime_builds[digest]
            else:
                previous = _binary_build(existing)
                if digest is not None:
                    runtime_builds[digest] = previous
            if not previous:
                raise ValueError(f"Cannot verify the staged executable {existing}. Repair it before replacing the service.")
            installed.append((existing, previous))
            if not incoming or keep_existing(previous.get("version", ""), incoming.get("version", ""), previous, incoming):
                selected, incoming = existing, previous
    # Choosing an existing artifact when order is unknown protects that path;
    # it does not authorize propagating its bytes over another staged artifact.
    for existing, previous in installed:
        if existing.resolve() == selected.resolve() or filecmp.cmp(existing, selected, shallow=False):
            continue
        old_version, new_version = previous.get("version", ""), (incoming or {}).get("version", "")
        old_order, new_order = order_key(old_version, previous), order_key(new_version, incoming)
        distinct_calendar_build = (
            (build_info.VERSION.fullmatch(old_version) or build_info.VERSION.fullmatch(new_version))
            and (old_version, previous.get("source_commit")) != (new_version, (incoming or {}).get("source_commit"))
        )
        if (old_order is None or new_order is None or old_order > new_order
                or old_order == new_order and distinct_calendar_build):
            raise ValueError(f"Cannot verify replacement order for {existing}. Keep both staged executables and repair the installation before migrating.")
    if runtimes.get(selected) is not None:
        macos_runtime.stage(runtimes[selected], target.parent)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for destination in targets:
        if selected.resolve() == destination.resolve():
            continue
        temporary = destination.with_suffix(".tmp")
        shutil.copy2(selected, temporary)
        temporary.chmod(0o755)
        os.replace(temporary, destination)
    return str(target.resolve())


def _binary_build(binary):
    try:
        result = _run([str(binary), "build-info"], text=True, timeout=5)
        if result.returncode == 0:
            document = json.loads(result.stdout)
            if isinstance(document, dict) and isinstance(document.get("version"), str):
                return document
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    try:
        result = _run([str(binary), "--version"], text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return {"version": result.stdout.strip().split()[-1]}
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def launchd_document(config, binary=None):
    return {
        "Label": NAME,
        "ProgramArguments": [
            binary or executable(),
            "run",
            "--config",
            str(config.path.resolve()),
        ],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 5,
        "ProcessType": "Background",
        "StandardOutPath": str(Path(config["data_dir"]) / "sensor.log"),
        "StandardErrorPath": str(Path(config["data_dir"]) / "sensor.err.log"),
    }


def enable_boot():
    """Enable Linux boot startup, elevating only the current user's linger request."""
    if platform.system() != "Linux":
        return False
    user = not is_root()
    if user:
        uid = str(os.getuid())
        query = ["loginctl", "show-user", uid, "--property=Linger", "--value"]
        state = _run(query, text=True, timeout=10)
        if state.returncode or state.stdout.strip() not in ("yes", "no"):
            raise RuntimeError(
                "Cannot check user lingering: "
                + (state.stderr.strip() or "systemd-logind is unavailable")
                + ". Use a systemd login session or run openaidr run under a supervisor."
            )
        if state.stdout.strip() != "yes":
            command = ["loginctl", "--no-ask-password", "enable-linger", uid]
            result = _run(command, text=True, timeout=10)
            if result.returncode:
                if not shutil.which("sudo"):
                    raise RuntimeError(
                        "Ask an administrator to run: loginctl enable-linger " + uid
                    )
                interactive = sys.stdin.isatty()
                print(
                    "Enabling startup at boot needs administrator permission for loginctl.",
                    file=sys.stderr,
                    flush=True,
                )
                result = _run(
                    ["sudo"] + ([] if interactive else ["-n"]) + command,
                    capture_output=not interactive,
                    text=True,
                    timeout=120 if interactive else 10,
                )
                if result.returncode:
                    raise RuntimeError(
                        "Cannot enable user lingering: "
                        + (result.stderr or "administrator permission was denied").strip()
                        + ". Ask an administrator to run: loginctl enable-linger " + uid
                    )
            state = _run(query, text=True, timeout=10)
            if state.returncode or state.stdout.strip() != "yes":
                raise RuntimeError("User lingering is not enabled after the request.")
    command = ["systemctl"] + (["--user"] if user else [])
    result = _run(command + ["enable", registered_name("Linux")], text=True, timeout=10)
    if result.returncode:
        raise RuntimeError("Cannot enable the sensor service: " + result.stderr.strip())
    state = _run(command + ["is-enabled", registered_name("Linux")], text=True, timeout=10)
    if state.returncode or state.stdout.strip() != "enabled":
        raise RuntimeError("The sensor service is not enabled at boot.")
    return True


def config_argument(arguments):
    if (
        not isinstance(arguments, list) or len(arguments) != 4
        or not all(isinstance(value, str) for value in arguments)
        or Path(arguments[0]).name not in NAMES
        or arguments[1:3] != ["run", "--config"] or not arguments[3]
    ):
        raise ValueError("Cannot determine the installed service's sensor config. Use manual setup for customized commands.")
    return Path(arguments[3]).expanduser().resolve()


def service_path(system, name=NAME):
    if system == "Linux":
        directory = Path("/etc/systemd/system") if is_root() else Path.home() / ".config/systemd/user"
        return directory / (name + ".service")
    directory = Path("/Library/LaunchDaemons") if is_root() else Path.home() / "Library/LaunchAgents"
    return directory / (name + ".plist")


def registered_name(system=None):
    system = system or platform.system()
    if system not in ("Linux", "Darwin"):
        return NAME
    found = [name for name in NAMES if service_path(system, name).exists()]
    if len(found) > 1:
        raise ValueError("Both OpenAIDR service names are installed. Remove the duplicate service before setup.")
    return found[0] if found else NAME


def _verify_absent_registration(system, name, *, timeout=None):
    """A missing file does not prove that the OS forgot a loaded service."""
    if system == "Darwin":
        domain = "system" if is_root() else "gui/" + str(os.getuid())
        result = _run(["launchctl", "print", domain + "/" + name], text=True, timeout=timeout)
        absent = result.returncode == 113
    else:
        command = ["systemctl"] + ([] if is_root() else ["--user"])
        result = _run(command + ["show", name, "--property=LoadState", "--property=FragmentPath", "--property=MainPID"], text=True, timeout=timeout)
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        absent = result.returncode in (0, 1) and values.get("LoadState") == "not-found" and values.get("FragmentPath") == "" and values.get("MainPID") == "0"
    if not absent:
        raise ValueError(f"Cannot verify that {name} is absent from the service manager. Remove the loaded or customized service manually before setup.")


def needs_migration():
    if platform.system() == "Windows":
        from . import windows_task
        return windows_task.state().get("legacy", False)
    return registered_name() == LEGACY_NAME


def _wait_for_exit(pid):
    if not pid:
        return
    deadline = time.monotonic() + 30
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("The OpenAIDR process is still stopping.")
        time.sleep(0.1)


def _stop_launchd(domain, name, *, pid=None, timeout=None):
    label = domain + "/" + name
    if pid is None:
        result = _run(["launchctl", "print", label], text=True, timeout=timeout)
        if result.returncode == 113:
            return
        if result.returncode:
            raise RuntimeError("Cannot inspect the replacement OpenAIDR service.")
        match = re.search(r"^\s*pid = (\d+)\s*$", result.stdout, re.MULTILINE)
        pid = int(match[1]) if match else 0
    result = _run(["launchctl", "bootout", label], timeout=timeout)
    if result.returncode not in (0, 113):
        raise RuntimeError("Cannot stop the OpenAIDR service.")
    _wait_for_exit(pid)


def _migrate_legacy(action, config, system, *, timeout=None, match_version=False):
    """Replace one verified registration, restoring it if the new one fails."""
    old_path, new_path = service_path(system, LEGACY_NAME), service_path(system)
    if old_path.is_symlink():
        raise ValueError("Automatic setup does not support symbolic service files.")
    identity = manage("identity", config, timeout=timeout, _name=LEGACY_NAME)
    if identity["config"] != config.path.resolve():
        raise ValueError("The legacy service uses another configuration. Remove it manually before setup.")
    from .bridge import app_version, keep_existing, recorded_service_build, recorded_service_version

    recorded = recorded_service_version(config)
    if not match_version and recorded and keep_existing(recorded, app_version(), recorded_service_build(config)):
        raise ValueError("The installed service is newer. Use the current OpenAIDR installation to migrate it.")
    running = manage("status", config, timeout=timeout, _name=LEGACY_NAME) == "running"
    start = running or action in ("start", "restart")
    previous = old_path.read_bytes()
    command = ["systemctl"] + ([] if is_root() else ["--user"])
    domain = "system" if is_root() else "gui/" + str(os.getuid())
    enabled = True
    if system == "Linux":
        result = _run(command + ["is-enabled", LEGACY_NAME], text=True, timeout=timeout)
        if result.stdout.strip() not in ("enabled", "disabled"):
            raise ValueError("Cannot migrate a masked or customized systemd service.")
        enabled = result.stdout.strip() == "enabled"
    else:
        result = _run(["launchctl", "print-disabled", domain], text=True, check=True, timeout=timeout)
        enabled = not re.search(r'"' + re.escape(LEGACY_NAME) + r'"\s*=>\s*true', result.stdout)
    try:
        if system == "Linux":
            _run(command + ["disable", "--now", LEGACY_NAME], check=True, timeout=timeout)
        else:
            _stop_launchd(domain, LEGACY_NAME, pid=identity["pid"], timeout=timeout)
            _run(["launchctl", "enable" if enabled or start else "disable", domain + "/" + NAME], check=True, timeout=timeout)
        manage("install", config, timeout=timeout, _name=NAME, _install_state=(enabled, start),
               **({"match_version": True} if match_version else {}))
        if system == "Darwin" and start and not enabled:
            _run(["launchctl", "disable", domain + "/" + NAME], check=True, timeout=timeout)
        old_path.unlink()
        if system == "Linux":
            _run(command + ["daemon-reload"], check=True, timeout=timeout)
    except Exception:
        # The old file stays available until replacement succeeds. Never start
        # it while the replacement might still be running.
        if system == "Linux":
            if new_path.exists():
                _run(command + ["disable", "--now", NAME], check=True, timeout=timeout)
            else:
                _verify_absent_registration(system, NAME, timeout=timeout)
        else:
            _stop_launchd(domain, NAME, timeout=timeout)
        new_path.unlink(missing_ok=True)
        old_path.write_bytes(previous)
        if system == "Linux":
            _run(command + ["daemon-reload"], check=True, timeout=timeout)
            _run(command + ["enable" if enabled else "disable", LEGACY_NAME], check=True, timeout=timeout)
            if running:
                _run(command + ["start", LEGACY_NAME], check=True, timeout=timeout)
        else:
            _run(["launchctl", "enable" if enabled or running else "disable", domain + "/" + LEGACY_NAME], check=True, timeout=timeout)
            if running:
                _run(["launchctl", "bootstrap", domain, str(old_path)], check=True, timeout=timeout)
                if not enabled:
                    _run(["launchctl", "disable", domain + "/" + LEGACY_NAME], check=True, timeout=timeout)
        raise


def manage(action, config, *, timeout=None, _name=None, _install_state=None, match_version=False):
    def run(*args, **kwargs):
        return _run(*args, timeout=timeout, **kwargs)

    system = platform.system()
    name = _name or (NAME if action == "uninstall" else registered_name(system))
    if _name is None and system in ("Linux", "Darwin") and action in ("install", "restart", "start"):
        for candidate in NAMES:
            if not service_path(system, candidate).exists():
                _verify_absent_registration(system, candidate, timeout=timeout)
    if _name is None and system in ("Linux", "Darwin") and action in ("install", "restart", "start") and name == LEGACY_NAME:
        return _migrate_legacy(action, config, system, timeout=timeout, match_version=match_version)
    if _name is None and system in ("Linux", "Darwin") and action == "uninstall":
        for installed in NAMES:
            if service_path(system, installed).exists():
                manage(action, config, timeout=timeout, _name=installed)
        return
    if match_version and action in ("install", "start", "restart"):
        binary = stable_executable(match_version=True)
    else:
        binary = stable_executable() if action == "install" else executable()
    if action == "install":
        Path(config["data_dir"]).mkdir(parents=True, exist_ok=True, mode=0o700)
    if system == "Linux":
        user = not is_root()
        path = service_path(system, name)
        command = ["systemctl"] + (["--user"] if user else [])
        if action == "install":
            path.parent.mkdir(parents=True, exist_ok=True)

            def quote(value):
                return (
                    '"'
                    + str(value)
                    .replace("\\", "\\\\")
                    .replace('"', '\\"')
                    .replace("%", "%%")
                    + '"'
                )

            path.write_text(
                "[Unit]\nDescription=OpenAIDR\nAfter=network-online.target\n\n[Service]\nExecStart="
                + quote(binary)
                + " run --config "
                + quote(config.path.resolve())
                + "\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy="
                + ("default.target" if user else "multi-user.target")
                + "\n"
            )
            run(command + ["daemon-reload"], check=True)
            if _install_state is None:
                run(command + ["enable", "--now", name], check=True)
            else:
                enabled, start = _install_state
                run(command + ["enable" if enabled else "disable", name], check=True)
                if start:
                    run(command + ["start", name], check=True)
        elif action == "uninstall":
            run(command + ["disable", "--now", name], check=False)
            path.unlink(missing_ok=True)
            run(command + ["daemon-reload"], check=True)
        elif action == "identity":
            result = run(
                command + ["show", name, "--all", "--property=LoadState",
                           "--property=FragmentPath", "--property=DropInPaths",
                           "--property=NeedDaemonReload", "--property=MainPID"],
                text=True,
            )
            properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
            if result.returncode or not {"LoadState", "FragmentPath", "DropInPaths", "NeedDaemonReload", "MainPID"} <= properties.keys():
                raise ValueError("Cannot verify the systemd service config. Check the systemd manager connection.")
            if properties["DropInPaths"]:
                raise ValueError("Automatic setup does not support systemd drop-ins. Use manual setup for this customized service.")
            if properties["NeedDaemonReload"] != "no":
                raise ValueError("The systemd service definition changed. Reload the systemd manager and retry setup.")
            fragment = properties["FragmentPath"]
            if properties["LoadState"] == "not-found" and not fragment and not path.exists():
                return {"config": None, "pid": 0}
            if properties["LoadState"] != "loaded" or not fragment or Path(fragment).resolve() != path.resolve():
                raise ValueError("Automatic setup cannot verify this systemd unit. Use manual setup for this customized service.")
            commands = re.findall(r"^ExecStart=(.*)$", path.read_text(), re.MULTILINE)
            if len(commands) != 1:
                raise ValueError("Cannot determine the installed service's sensor config.")
            saved = config_argument(shlex.split(commands[0].replace("%%", "%")))
            pid = int(properties["MainPID"])
            if pid:
                # daemon-reload does not replace an already running process.
                arguments = (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0")
                arguments = [os.fsdecode(arg) for arg in arguments if arg]
                if len(arguments) == 5 and re.fullmatch(r"python(?:\d+(?:\.\d+)*)?t?|pypy\d*", Path(arguments[0]).name):
                    arguments = arguments[1:]
                running = config_argument(arguments)
                if running != saved:
                    raise ValueError(
                        f"The running systemd service uses {running}, which differs from its unit. "
                        "Drain its queued activity, then uninstall and reinstall the service with the intended config."
                    )
            return {"config": saved, "pid": pid}
        elif action == "status":
            if not path.exists():
                return "not installed"
            result = run(command + ["is-active", name], capture_output=True, text=True)
            return "running" if result.returncode == 0 else "stopped"
        else:
            run(command + [action, name], check=True)
    elif system == "Darwin":
        root = is_root()
        path = service_path(system, name)
        domain = "system" if root else "gui/" + str(os.getuid())
        label = domain + "/" + name
        if action == "install":
            path.parent.mkdir(parents=True, exist_ok=True)
            document = launchd_document(config, binary)
            document["Label"] = name
            path.write_bytes(plistlib.dumps(document))
            run(["launchctl", "bootout", label], check=False, capture_output=True)
            if _install_state is None or _install_state[1]:
                run(["launchctl", "bootstrap", domain, str(path)], check=True)
        elif action == "uninstall":
            run(["launchctl", "bootout", label], check=False)
            path.unlink(missing_ok=True)
        elif action == "identity":
            if not path.exists():
                return {"config": None, "pid": 0}
            if path.is_symlink():
                raise ValueError("Automatic setup does not support symbolic service files.")
            document = plistlib.loads(path.read_bytes())
            if document.get("Label") != name:
                raise ValueError("Cannot verify the launchd service label.")
            saved = config_argument(document.get("ProgramArguments"))
            result = run(["launchctl", "print", label], text=True)
            pid = 0
            if result.returncode == 0:
                args = re.search(r"^\s*arguments = \{\n(.*?)^\s*\}", result.stdout, re.MULTILINE | re.DOTALL)
                if not args or config_argument([line.strip() for line in args[1].splitlines() if line.strip()]) != saved:
                    raise ValueError("Cannot verify the running launchd service config.")
                match = re.search(r"^\s*pid = (\d+)\s*$", result.stdout, re.MULTILINE)
                pid = int(match[1]) if match else 0
            elif result.returncode != 113:
                raise ValueError("Cannot inspect the launchd service.")
            return {"config": saved, "pid": pid}
        elif action == "status":
            if not path.exists():
                return "not installed"
            result = run(["launchctl", "print", label], capture_output=True, text=True)
            return (
                "running"
                if result.returncode == 0 and "state = running" in result.stdout
                else "stopped"
            )
        elif action == "stop":
            run(["launchctl", "bootout", label], check=True)
        elif action == "start":
            run(["launchctl", "bootstrap", domain, str(path)], check=True)
        else:
            run(["launchctl", "kickstart", "-k", label], check=True)
    elif system == "Windows":
        return windows_manage(action, config, binary=binary, timeout=timeout,
                              **({"match_version": True} if match_version else {}))
    else:
        raise ValueError("unsupported service platform: " + system)


def stop_and_wait(config):
    """Do not hand off enrollment while the old process can still queue events."""
    pid = None
    system = platform.system()
    if system == "Darwin":
        domain = "system" if is_root() else "gui/" + str(os.getuid())
        result = _run(["launchctl", "print", domain + "/" + registered_name(system)],
                      check=True, text=True, timeout=5)
        match = re.search(r"^\s*pid = (\d+)\s*$", result.stdout, re.MULTILINE)
        if not match or int(match[1]) <= 1:
            raise ValueError("Cannot verify the background sensor process. Refresh and try again.")
        pid = int(match[1])
    manage("stop", config, timeout=15)
    deadline = time.monotonic() + 30
    while True:
        if pid is not None:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
        elif system == "Windows":
            from . import windows_task

            # Stopping the task already waits for its process to exit.
            if not windows_task.state(timeout=15)["running"]:
                return
        elif manage("status", config, timeout=5) == "stopped":
            return
        if time.monotonic() >= deadline:
            raise ValueError("The background sensor is still stopping. Keep the current connection and try again shortly.")
        time.sleep(0.1)


def windows_manage(action, config, *, binary=None, timeout=None, match_version=False):
    """Manage the current user's logon Scheduled Task (see windows_task)."""
    from . import windows_task

    if action == "install":
        windows_task.register(binary or executable(), config.path, timeout=timeout)
    elif action == "uninstall":
        windows_task.unregister(timeout=timeout)
        if windows_runtime() is not None:
            from . import windows_runtime as runtime

            runtime.remove(runtime.root())
    elif action == "status":
        state = windows_task.state(timeout=timeout)
        if not state["installed"]:
            return "not installed"
        # After an upgrade the task still runs the previous runtime, and
        # restarting it there would keep the old sensor: register it again.
        expected = Path(windows_task.service_executable(staged_executable())[0])
        moved = windows_runtime() is not None and (
            os.path.normcase(str(expected)) != os.path.normcase(state.get("execute", ""))
        )
        if state["drift"] or moved:
            return "changed"
        return "running" if state["running"] else "stopped"
    elif action == "identity":
        return {"config": windows_task.configured_config(timeout=timeout), "pid": 0}
    elif action == "start":
        if (match_version and windows_runtime() is not None) or windows_task.state(timeout=timeout).get("legacy"):
            windows_task.register(binary if match_version else stable_executable(), config.path, timeout=timeout)
        windows_task.start(timeout=timeout)
    elif action == "stop":
        windows_task.stop(timeout=timeout)
    elif action == "restart":
        if windows_runtime() is not None:
            # Registration stops the task and starts it on the selected runtime.
            # Desktop setup has selected its bundled version exactly.
            was_running = windows_task.state(timeout=timeout).get("running", False)
            windows_task.register(binary if match_version else stable_executable(), config.path, timeout=timeout)
            if not was_running:
                windows_task.start(timeout=timeout)
        elif windows_task.state(timeout=timeout).get("legacy"):
            windows_task.register(binary if match_version else stable_executable(), config.path, timeout=timeout)
            windows_task.start(timeout=timeout)
        else:
            windows_task.restart(timeout=timeout)
    else:
        raise ValueError("unsupported service action: " + action)
