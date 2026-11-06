"""Per-user Windows Scheduled Task that runs the sensor without a console.

The sensor runs as the account that runs the coding agents, so it can read
that user's agent settings and per-user application registrations. A logon
Scheduled Task with limited rights needs no administrator approval, unlike a
Service Control Manager service, and a repeating trigger relaunches the
sensor within a few minutes if it exits.

The task runs ``openaidr-service.exe``, a windowless build of the
sensor, so no console window appears at logon or on restart. Its output goes
to ``sensor.log`` and ``sensor.err.log`` in the sensor data directory.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path, PureWindowsPath

TASK_PREFIX = "OpenAIDR"
LEGACY_TASK_PREFIX = "OpenAIDR Sensor"
SERVICE_EXECUTABLE = "openaidr-service.exe"
LEGACY_SERVICE_EXECUTABLE = "openaidr-sensor-service.exe"
COMMAND_TIMEOUT = 30
CREATE_NO_WINDOW = 0x08000000
# The task also relaunches the sensor on this interval when it is not running;
# MultipleInstances IgnoreNew makes the repetition a no-op while it runs.
RELAUNCH_MINUTES = 5


class TaskError(RuntimeError):
    """The Scheduled Task could not be inspected or changed."""


def _literal(value):
    value = str(value)
    if any(character in value for character in ("\x00", "\n", "\r")):
        raise TaskError("Windows task values cannot contain control characters.")
    return "'" + value.replace("'", "''") + "'"


def _powershell(script, *, timeout=None, check=True):
    command = [
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32",
                     "WindowsPowerShell", "v1.0", "powershell.exe"),
        "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'\n"
        # UTF-8 output keeps non-ASCII profile paths intact.
        + "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
        + script,
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout or COMMAND_TIMEOUT,
            creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except subprocess.TimeoutExpired as exc:
        raise TaskError("The Windows Task Scheduler did not respond in time.") from exc
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise TaskError("Windows Task Scheduler: " + (detail[-1] if detail else "command failed"))
    return result


# The task name carries the user SID so accounts on a shared machine each own
# their own task, and one user's task never controls another user's sensor.
_TASK_NAME = (
    "$taskName = " + _literal(TASK_PREFIX + " ")
    + " + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
)

# Query both names together so a legacy registration is never hidden, and
# refuse ambiguous dual installations instead of launching another collector.
_TASK_SELECT = (
    _TASK_NAME
    + "$legacyName = " + _literal(LEGACY_TASK_PREFIX + " ")
    + " + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
    + "$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue\n"
    + "$legacyTask = Get-ScheduledTask -TaskName $legacyName -ErrorAction SilentlyContinue\n"
    + "if ($null -ne $task -and $null -ne $legacyTask) { throw 'Both OpenAIDR task names are installed. Remove the duplicate task before setup.' }\n"
    + "if ($null -eq $task -and $null -ne $legacyTask) { $taskName = $legacyName; $task = $legacyTask }\n"
)


def _selection(name=None):
    if name is None:
        return _TASK_SELECT
    if name not in (TASK_PREFIX, LEGACY_TASK_PREFIX):
        raise TaskError("Unsupported OpenAIDR task name.")
    return (
        "$taskName = " + _literal(name + " ")
        + " + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
        + "$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue\n"
        + "$legacyName = " + _literal(LEGACY_TASK_PREFIX + " ")
        + " + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
    )


def service_executable(console_executable):
    """The windowless sensor next to a staged console sensor, or pythonw for source installs."""
    console = Path(console_executable)
    if getattr(sys, "frozen", False) or console.suffix.lower() == ".exe" and console.name != "python.exe":
        for name in (SERVICE_EXECUTABLE, LEGACY_SERVICE_EXECUTABLE):
            candidate = console.with_name(name)
            if candidate.is_file():
                return [str(candidate)]
        if getattr(sys, "frozen", False):
            raise TaskError(
                f"{SERVICE_EXECUTABLE} is missing beside {console}. Reinstall the OpenAIDR desktop app."
            )
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    interpreter = pythonw if pythonw.is_file() else Path(sys.executable)
    return [str(interpreter), "-m", "openaidr.sensor.windows_task"]


def task_arguments(console_executable, config_path):
    command = service_executable(console_executable)
    return command[0], subprocess.list2cmdline(
        command[1:] + ["run", "--config", str(Path(config_path).resolve())]
    )

def _stop_processes_script(executable):
    return (
        f"$folder = {_literal(Path(executable).parent)}\n"
        + "$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
        + "Get-CimInstance Win32_Process -Filter \"Name = '" + SERVICE_EXECUTABLE + "' OR Name = '" + LEGACY_SERVICE_EXECUTABLE + "'\" | "
        + "Where-Object { $_.ExecutablePath -and [System.IO.Path]::GetDirectoryName($_.ExecutablePath) -eq $folder -and "
        + "(Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction SilentlyContinue).Sid -eq $me } | "
        + "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; "
        + "Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue | Wait-Process -Timeout 30 -ErrorAction Stop }\n"
    )


def _wait_stopped_script(task):
    return (
        "$stopDeadline = (Get-Date).AddSeconds(30)\n"
        + f"while ($true) {{ $stopping = Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop | Where-Object {{ $_.TaskName -eq {task} }}; "
        + "if ($null -eq $stopping -or $stopping.State -ne 'Running') { break }; "
        + "if ((Get-Date) -ge $stopDeadline) { throw 'The OpenAIDR task is still stopping.' }; Start-Sleep -Milliseconds 200 }\n"
    )


def register(console_executable, config_path, *, timeout=None):
    """Create or replace the logon task for the current user, then start it."""
    program, arguments = task_arguments(console_executable, config_path)
    # Replacing a running task leaves the old process running, and
    # IgnoreNew would then skip the start, so stop it first.
    previous = state(timeout=timeout)
    legacy = previous.get("legacy", False)
    if legacy:
        if previous.get("drift") or configured_config(timeout=timeout) != Path(config_path).resolve():
            raise TaskError("The legacy task is customized or uses another configuration. Remove it manually before setup.")
    if previous["running"] and not legacy:
        stop(timeout=timeout)
    migrate = (
        "$legacyName = " + _literal(LEGACY_TASK_PREFIX + " ")
        + " + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
        + "$previous = $null\ntry {\n"
        + "$previous = Export-ScheduledTask -TaskName $legacyName\n"
        + "Disable-ScheduledTask -TaskName $legacyName | Out-Null\n"
        + "Stop-ScheduledTask -TaskName $legacyName\n"
        + _stop_processes_script(previous.get("execute", program))
        + _wait_stopped_script("$legacyName")
        + "Unregister-ScheduledTask -TaskName $legacyName -Confirm:$false\n"
    ) if legacy else ""
    restore = (
        "} catch {\n"
        + "Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue\n"
        + _stop_processes_script(program)
        + _wait_stopped_script("$taskName")
        + "Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue\n"
        + "if ($previous) { Register-ScheduledTask -TaskName $legacyName -Xml $previous -Force | Out-Null }\n"
        + ("Enable-ScheduledTask -TaskName $legacyName | Out-Null\nStart-ScheduledTask -TaskName $legacyName\n" if previous["running"] else "")
        + "throw\n}\n"
    ) if legacy else ""
    _powershell(
        _TASK_NAME + migrate
        + "$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name\n"
        + f"$action = New-ScheduledTaskAction -Execute {_literal(program)}"
        + (f" -Argument {_literal(arguments)}" if arguments else "")
        + f" -WorkingDirectory {_literal(Path(program).parent)}\n"
        + "$logon = New-ScheduledTaskTrigger -AtLogOn -User $identity\n"
        # Restart settings cover launch failures only; the repetition brings
        # back a sensor that exited while the user stays logged on.
        + f"$relaunch = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes({RELAUNCH_MINUTES}) "
        + f"-RepetitionInterval (New-TimeSpan -Minutes {RELAUNCH_MINUTES})\n"
        # An empty duration repeats indefinitely, whatever the default.
        + "$relaunch.Repetition.Duration = ''\n"
        + "$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited\n"
        + "$settings = New-ScheduledTaskSettingsSet -RestartCount 999 "
        + "-RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) "
        + "-MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
        + "-StartWhenAvailable\n"
        + ("$settings.Enabled = $false\n" if legacy and previous.get("state") == "Disabled" else "")
        + "Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($logon, $relaunch) "
        + "-Principal $principal -Settings $settings "
        + "-Description 'Collects coding agent activity and enforces OpenAIDR policy.' -Force | Out-Null\n"
        + ("Disable-ScheduledTask -TaskName $taskName | Out-Null\n" if legacy and previous.get("state") == "Disabled" else "")
        + ("Start-ScheduledTask -TaskName $taskName\n" if not legacy or previous["running"] else "")
        + restore,
        timeout=timeout,
    )


# Everything register() sets that decides who the sensor runs as and when,
# compared before the task is trusted, as ADR validates its task definition.
_DRIFT = (
    "$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
    "function Sid($name) { try { ([System.Security.Principal.NTAccount]$name).Translate("
    "[System.Security.Principal.SecurityIdentifier]).Value } catch { '' } }\n"
    "$drift = @()\n"
    "if (@($task.Actions).Count -ne 1) { $drift += 'actions' }\n"
    "$p = $task.Principal\n"
    "if ((Sid $p.UserId) -ne $sid -or [string]$p.LogonType -ne 'Interactive' -or "
    "[string]$p.RunLevel -ne 'Limited') { $drift += 'principal' }\n"
    "$triggers = @($task.Triggers)\n"
    # Each trigger must keep working: no end date, and the relaunch repeats
    # without a finite duration.
    "$logon = @($triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' -and $_.Enabled "
    "-and -not $_.EndBoundary })\n"
    "$relaunch = @($triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskTimeTrigger' -and "
    f"$_.Enabled -and -not $_.EndBoundary -and $_.Repetition.Interval -eq 'PT{RELAUNCH_MINUTES}M' "
    "-and -not $_.Repetition.Duration })\n"
    "if ($triggers.Count -ne 2 -or $logon.Count -ne 1 -or (Sid $logon[0].UserId) -ne $sid -or "
    "$relaunch.Count -ne 1) { $drift += 'triggers' }\n"
    "$s = $task.Settings\n"
    "if ([string]$s.MultipleInstances -ne 'IgnoreNew' -or [string]$s.ExecutionTimeLimit -ne 'PT0S' -or "
    "[int]$s.RestartCount -ne 999 -or [string]$s.RestartInterval -ne 'PT1M' -or "
    "-not $s.StartWhenAvailable -or "
    "$s.DisallowStartIfOnBatteries -or $s.StopIfGoingOnBatteries) { $drift += 'settings' }\n"
)


def _action_drift(value):
    """The action must run this sensor's own command line, as register() wrote it."""
    execute, arguments = value.get("execute", ""), value.get("arguments", "")
    windowless = PureWindowsPath(execute).name.lower() in (SERVICE_EXECUTABLE, LEGACY_SERVICE_EXECUTABLE)
    source = "-m openaidr.sensor.windows_task" in arguments
    return not ((windowless or source) and "run --config" in arguments)


def state(*, timeout=None, name=None):
    """Return ``installed``, ``running``, and for an installed task its
    ``state``, ``last_result``, ``execute``, ``arguments``, and ``drift``: the
    parts of its definition that differ from what register() creates."""
    result = _powershell(
        _selection(name)
        + "if ($null -eq $task) { '{\"installed\": false}'; exit 0 }\n"
        + "$info = Get-ScheduledTaskInfo -TaskName $taskName\n"
        + "$action = @($task.Actions)[0]\n"
        + _DRIFT
        + "[pscustomobject]@{ installed = $true; state = [string]$task.State; "
        + "last_result = [int64]$info.LastTaskResult; execute = [string]$action.Execute; "
        + "arguments = [string]$action.Arguments; legacy = ($taskName -eq $legacyName); drift = ($drift -join ',') } "
        + "| ConvertTo-Json -Compress\n",
        timeout=timeout,
    )
    try:
        value = json.loads(result.stdout.strip() or "{}")
    except json.JSONDecodeError as exc:
        raise TaskError("The Windows Task Scheduler returned an unreadable task state.") from exc
    if not isinstance(value, dict) or not isinstance(value.get("installed"), bool):
        raise TaskError("The Windows Task Scheduler returned an unreadable task state.")
    value["running"] = value.get("state") == "Running"
    if value["installed"]:
        drift = [part for part in str(value.get("drift") or "").split(",") if part]
        if _action_drift(value):
            drift.insert(0, "action")
        value["drift"] = drift
    return value


def status(*, timeout=None):
    """``changed`` means the task no longer matches what OpenAIDR registered;
    setup registers it again."""
    value = state(timeout=timeout)
    if not value["installed"]:
        return "not installed"
    if value["drift"]:
        return "changed"
    return "running" if value["running"] else "stopped"


def start(*, timeout=None):
    """Enable the task again after a stop, then run it now."""
    _powershell(
        _TASK_SELECT
        + "Enable-ScheduledTask -TaskName $taskName | Out-Null\n"
        + "Start-ScheduledTask -TaskName $taskName\n",
        timeout=timeout,
    )


def _terminate_leftovers(executable, *, timeout=None):
    """End windowless sensors this user still runs from the task's folder.

    A frozen one-file executable runs Python in a child process; stopping the
    task must not leave that child holding the receiver ports. The desktop app
    may have renamed a running copy aside in the same folder during an update.
    """
    _powershell(
        f"$folder = {_literal(Path(executable).parent)}\n"
        + "$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
        + "Get-CimInstance Win32_Process -Filter \"Name = '" + SERVICE_EXECUTABLE + "' OR Name = '" + LEGACY_SERVICE_EXECUTABLE + "'\" | "
        + "Where-Object { $_.ExecutablePath -and "
        + "[System.IO.Path]::GetDirectoryName($_.ExecutablePath) -eq $folder -and "
        + "(Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction SilentlyContinue).Sid -eq $me } | "
        + "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }\n",
        timeout=timeout, check=False,
    )


def stop(*, timeout=None, name=None):
    value = state(timeout=timeout, name=name)
    if not value["installed"]:
        raise TaskError("The OpenAIDR sensor task is not installed.")
    # Disabled first so neither the logon trigger nor the relaunch repetition
    # starts the sensor again until start or restart. (ADR has no repetition
    # trigger; it records the stop in a desired-state file its window honors.)
    _powershell(
        _selection(name)
        + "Disable-ScheduledTask -TaskName $taskName | Out-Null\n"
        + "Stop-ScheduledTask -TaskName $taskName\n",
        timeout=timeout,
    )
    if PureWindowsPath(value.get("execute", "")).name.lower() in (SERVICE_EXECUTABLE, LEGACY_SERVICE_EXECUTABLE):
        _terminate_leftovers(value["execute"], timeout=timeout)
    wait_stopped(timeout=timeout or COMMAND_TIMEOUT, name=name)


def wait_stopped(*, timeout=COMMAND_TIMEOUT, name=None):
    deadline = time.monotonic() + timeout
    while True:
        if not state(timeout=max(1, deadline - time.monotonic()), name=name)["running"]:
            return
        if time.monotonic() >= deadline:
            raise TaskError("The OpenAIDR sensor task is still stopping.")
        time.sleep(0.5)


def restart(*, timeout=None):
    stop(timeout=timeout)
    start(timeout=timeout)


def restore_state(previous):
    """Restore an unchanged task after migration stopped it but could not move state."""
    current = state()
    if (not current["installed"] or current.get("drift")
            or current.get("execute") != previous.get("execute")):
        raise TaskError("The background task changed during Windows migration.")
    if previous.get("state") != "Disabled":
        _powershell(
            _TASK_SELECT + "Enable-ScheduledTask -TaskName $taskName | Out-Null\n"
            + ("Start-ScheduledTask -TaskName $taskName\n" if previous.get("running") else "")
        )


def relocate(old_config, new_config, console, previous):
    """Retarget only our task action, preserving its triggers and disablement."""
    current = state()
    configured = configured_config()
    if (not current["installed"] or current.get("drift")
            or configured not in (Path(old_config), Path(new_config))):
        raise TaskError("The background task changed during Windows migration.")
    program, arguments = task_arguments(console, new_config)
    _powershell(
        _TASK_SELECT
        + f"$action = New-ScheduledTaskAction -Execute {_literal(program)} "
        + f"-Argument {_literal(arguments)} -WorkingDirectory {_literal(Path(program).parent)}\n"
        + "Set-ScheduledTask -TaskName $taskName -Action $action | Out-Null\n"
        + ("Disable-ScheduledTask -TaskName $taskName | Out-Null\n"
           if previous.get("state") == "Disabled" else "Enable-ScheduledTask -TaskName $taskName | Out-Null\n")
        + ("Start-ScheduledTask -TaskName $taskName\n" if previous.get("running") else "")
    )


def unregister(*, timeout=None):
    removed = False
    for name in (TASK_PREFIX, LEGACY_TASK_PREFIX):
        value = state(timeout=timeout, name=name)
        if not value["installed"]:
            continue
        if value.get("drift"):
            raise TaskError("The OpenAIDR task is customized. Remove it manually before uninstalling.")
        # Disable even a stopped task before deleting it, so its repeating
        # trigger cannot start a process between inspection and removal.
        stop(timeout=timeout, name=name)
        _powershell(
            _selection(name) + "Unregister-ScheduledTask -TaskName $taskName -Confirm:$false\n",
            timeout=timeout,
        )
        removed = True
    return removed


def configured_config(*, timeout=None):
    """The ``--config`` path the installed task passes to the sensor, if any."""
    value = state(timeout=timeout)
    if not value["installed"]:
        return None
    import shlex

    parts = shlex.split(value.get("arguments", ""), posix=False)
    for index, part in enumerate(parts[:-1]):
        if part == "--config":
            return Path(parts[index + 1].strip('"')).resolve()
    return None


def service_main(argv=None):
    """Entry point for the windowless sensor: log to files, then run the CLI."""
    argv = list(sys.argv[1:] if argv is None else argv)
    from .cli import main
    from .config import Config, default_path

    config_path = None
    for index, part in enumerate(argv[:-1]):
        if part == "--config":
            config_path = argv[index + 1]
    try:
        data_dir = Path(Config.load(config_path or default_path())["data_dir"])
    except Exception:
        data_dir = Path(config_path or default_path()).parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    out = open(data_dir / "sensor.log", "a", encoding="utf-8", buffering=1)
    err = open(data_dir / "sensor.err.log", "a", encoding="utf-8", buffering=1)
    sys.stdout, sys.stderr = out, err
    try:
        return main(argv)
    finally:
        out.flush()
        err.flush()


if __name__ == "__main__":
    raise SystemExit(service_main())
