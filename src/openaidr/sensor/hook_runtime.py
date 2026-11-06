"""Quiet native launchers and content-free hook execution measurements."""

import base64
from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import shlex
import subprocess
import threading
import time
import uuid

from .config import Config, configuration_lock, default_path
from openaidr.core.files import atomic_write
from openaidr.core.hook_protocol import PRODUCTS, ROUTES
from openaidr.core.protocol import AGENT_HOOK_TIMEOUT_SECONDS, HOOK_DECISION_TIMEOUT_SECONDS, HOOK_TIMEOUT_SECONDS

MARKER = "openaidr-hook-v1"
MAX_RECORDS = 4096
# Allow local delivery after the decision deadline, then leave time for quiet exit.
RESPONSE_RESERVE_NS = 100_000_000
EXIT_RESERVE_NS = (HOOK_TIMEOUT_SECONDS - HOOK_DECISION_TIMEOUT_SECONDS) * 1_000_000_000 - RESPONSE_RESERVE_NS
_job = None


def contain_descendants():
    """End this Windows process's descendants with it, however it ends.

    The process joins a kill-on-close job object, which its descendants inherit.
    The handle stays open for the process lifetime, so when the launcher ends a
    hung hook, even without taskkill, Windows ends every process the hook
    started, and none keeps the agent's output pipe open. Fails silently.
    """
    global _job
    if os.name != "nt" or _job is not None:
        return
    try:
        import ctypes
        from ctypes import wintypes

        class Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                        ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class Extended(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", Basic),
                        ("IoInfo", ctypes.c_uint64 * 6),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int,
                                                     ctypes.c_void_p, wintypes.DWORD)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return
        info = Extended()
        info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        # 9: JobObjectExtendedLimitInformation.
        if (kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))
                and kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess())):
            _job = job
        else:
            kernel32.CloseHandle(job)
    except Exception:
        pass

# Bound startup and forwarding in a worker process group. Cleanup and receipts
# stay detached so they cannot hold the native agent's output pipes open.
WATCHED = r'''
exec 2>/dev/null
umask 077
set -m
seconds=$1
shift
work() {
    set +m
    runtime=
    group=$$
    cleanup() {
        [ -n "$runtime" ] || return
        set -m
        # Detached in its own process group, so the watchdog's KILL cannot
        # stop it. Removing only after this worker's group is empty keeps a
        # dying sensor from recreating files after the removal; a group that
        # outlives the bound is removed anyway.
        (
            tries=0
            while kill -0 -- "-$group" 2>/dev/null && [ "$tries" -lt 100 ]; do
                /bin/sleep .05
                tries=$((tries + 1))
            done
            /bin/rm -rf -- "$runtime"
        ) 3<&- </dev/null >/dev/null 2>&1 &
    }
    trap cleanup EXIT
    trap 'exit 124' HUP INT TERM
    # Use the same precise clock for the deadline and latency measurement.
    # macOS date lacks nanoseconds; GNU date supports hosts without system Perl.
    # The watchdog also bounds either clock helper if it stalls.
    stamp=$(/usr/bin/env -i /usr/bin/perl -MTime::HiRes=time -e 'printf "%.0f", time()*1e9') || stamp=
    case "$stamp" in
        ''|*[!0-9]*) stamp=$(/bin/date +%s%N) || exit 125 ;;
    esac
    case "$stamp" in ''|*[!0-9]*) exit 125 ;; esac
    OPENAIDR_HOOK_STARTED_NS=$stamp
    OPENAIDR_HOOK_DEADLINE_NS=$((stamp + seconds * 1000000000 - @EXIT_RESERVE_NS@))
    OPENAIDR_HOOK_TIMEOUT_OWNER=sensor
    export OPENAIDR_HOOK_STARTED_NS OPENAIDR_HOOK_DEADLINE_NS OPENAIDR_HOOK_TIMEOUT_OWNER
    for base in "${TMPDIR:-}" "${TMP:-}" "${TEMP:-}" /tmp; do
        [ -n "$base" ] || continue
        runtime=$(/usr/bin/mktemp -d "$base/openaidr-hook.XXXXXXXX") && break
    done
    [ -n "$runtime" ] || exit 125
    # A background job lets the TERM trap run at once. Bash defers traps for a
    # foreground command, so a sensor slow to exit on TERM let the watchdog's
    # KILL end this worker before its cleanup ran and leaked the runtime.
    TMPDIR="$runtime" TMP="$runtime" TEMP="$runtime" OPENAIDR_HOOK_WRAPPED=1 "$@" <&3 &
    wait "$!"
}
export -f work
export seconds
/bin/bash -c 'work "$@"' "$0" "$@" <&3 &
child=$!
(
    # Leave headroom for returning the buffered native response.
    /bin/sleep "$((seconds - 1)).5"
    kill -TERM -- "-$child" 2>/dev/null
    /bin/sleep .05
    kill -KILL -- "-$child" 2>/dev/null
) 3<&- </dev/null >/dev/null 2>&1 &
watchdog=$!
wait "$child"
result=$?
kill -KILL -- "-$child" 2>/dev/null
kill -TERM -- "-$watchdog" 2>/dev/null
exit "$result"
'''.strip().replace("@EXIT_RESERVE_NS@", str(EXIT_RESERVE_NS))

# Buffer stdout until the worker completes successfully, including startup.
# Even an unavailable Bash executable is caught by the outer native shell.
POSIX = r'''
exec 2>/dev/null
umask 077
directory=$1 seconds=$2 agent=$3 event=$4
shift 4
exec 3<&0
OPENAIDR_HOOK_EXECUTION_ID=$(BASH_ENV= ENV= /bin/bash -c 'printf "%08x%08x%08x%08x" "$PPID" "$$" "$RANDOM" "$RANDOM"') || exit 0
export OPENAIDR_HOOK_EXECUTION_ID
output=$(BASH_ENV= ENV= /bin/bash -c @WATCHED@ "$0" "$seconds" "$@")
result=$?
trap '' PIPE
if [ "$result" -eq 0 ] && [ -n "$output" ]; then
    # A failed write must not leave buffered output for the detached reporter.
    (printf '%s\n' "$output") || result=$?
fi
(
    /bin/mkdir -p "$directory" || exit 0
    set -- "$directory"/*
    if [ "$#" -lt 4096 ] && [ -n "$OPENAIDR_HOOK_EXECUTION_ID" ]; then
        stamp=$(/bin/date -u +%s)
        set -C
        : > "$directory/$agent.$event.$stamp.$result.$OPENAIDR_HOOK_EXECUTION_ID.agent"
    fi
) 3<&- </dev/null >/dev/null 2>&1 &
exit 0
'''.strip().replace("@WATCHED@", shlex.quote(WATCHED))

# Reject syntax errors before the script can emit partial output. Keep native
# stdout connected directly so delivery receipts reflect the agent's pipe.
POSIX_BOOTSTRAP = r'''exec 2>/dev/null; [ -f "$1" ] && /bin/sh -n "$1" && /bin/sh "$1"; exit 0'''

# The launcher watchdog bounds this request, including startup. No event content is
# written to disk, and curl's default config and proxy environment are ignored.
SOCKET_REQUEST = r'''
hook_home=$(printf '%s' "$HOME" | /usr/bin/base64 | /usr/bin/tr -d '\n') || exit 1
response=$(/usr/bin/curl -q --silent --fail --proxy '' --noproxy '*' \
    --unix-socket "$1" \
    --max-filesize 4194304 --header 'Content-Type: application/json' \
    --header "X-OpenAIDR-Home: $hook_home" --header "X-OpenAIDR-Client-Pid: $$" \
    --data-binary @- --write-out '\n%{http_code}' \
    "http://localhost$2?event=$3&started=$OPENAIDR_HOOK_STARTED_NS&deadline=$OPENAIDR_HOOK_DEADLINE_NS&execution=$OPENAIDR_HOOK_EXECUTION_ID&timeout_owner=sensor") || exit $?
case "$response" in
    *'
200') printf '%s' "${response%????}" ;;
    '
204') ;;
    *) exit 1 ;;
esac
'''.strip()

WINDOWS = r"""
$ErrorActionPreference = 'Stop'
$result = 127
$output = ''
$process = $null
$execution = [Guid]::NewGuid().ToString('N')
$started = [DateTimeOffset]([Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime())
function detach($file, $arguments) {
    # Shell execution creates the process without inheriting this launcher's
    # handles: a redirected start inherits every inheritable handle, including
    # the agent's output pipe, and the agent would wait for the process to end.
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $file
    $info.Arguments = $arguments
    $info.UseShellExecute = $true
    $info.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    # Not the agent's working directory, which may be a stalled network path.
    $info.WorkingDirectory = $env:SystemRoot
    $child = [Diagnostics.Process]::Start($info)
    if ($null -ne $child) { $child.Dispose() }
}
try {
    # Drain both output pipes without waiting for pool growth. Stdin stays
    # on this thread and cannot queue behind those blocking readers.
    $workers = 0; $completion = 0
    [Threading.ThreadPool]::GetMinThreads([ref]$workers, [ref]$completion)
    $null = [Threading.ThreadPool]::SetMinThreads([Math]::Max(4, $workers), $completion)
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $hook.args[0]
    $info.Arguments = $hook.arguments
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.Encoding]::UTF8
    $info.StandardErrorEncoding = [Text.Encoding]::UTF8
    $info.EnvironmentVariables['OPENAIDR_HOOK_WRAPPED'] = '1'
    $info.EnvironmentVariables['PYTHONIOENCODING'] = 'utf-8'
    $info.EnvironmentVariables['OPENAIDR_HOOK_EXECUTION_ID'] = $execution
    $info.EnvironmentVariables['OPENAIDR_HOOK_TIMEOUT_OWNER'] = 'agent'
    $info.EnvironmentVariables['OPENAIDR_HOOK_STARTED_NS'] = [string]($started.ToUnixTimeMilliseconds() * 1000000L)
    $info.EnvironmentVariables['OPENAIDR_HOOK_DEADLINE_NS'] = [string](($started.ToUnixTimeMilliseconds() + $hook.seconds * 1000) * 1000000L)
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    $null = $process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    # stdin is already supplied by the agent. Synchronous forwarding avoids
    # scheduling it behind the two blocking pipe readers in the .NET pool.
    [Console]::OpenStandardInput().CopyTo($process.StandardInput.BaseStream)
    $process.StandardInput.BaseStream.Close()
    $process.WaitForExit()
    $result = $process.ExitCode
    if ($result -eq 0) {
        $stdout.Wait()
        $output = $stdout.Result
    }
} catch { $result = 1 }
finally {
    if ($null -ne $process) {
        try {
            if (-not $process.HasExited) {
                # Only exceptional local failures reach this cleanup. The
                # native agent terminates the process tree on hook timeout.
                try { detach "$env:SystemRoot\System32\taskkill.exe" "/PID $($process.Id) /T /F" } catch {}
                $process.Kill()
            }
        } catch {}
        $process.Dispose()
    }
}
try {
    if ([DateTimeOffset]::UtcNow -ge $started.AddSeconds($hook.seconds)) { $result = 124 }
    if ($result -eq 0 -and $output) {
        $outputBytes = [Text.Encoding]::UTF8.GetBytes($output)
        [Console]::OpenStandardOutput().Write($outputBytes, 0, $outputBytes.Length)
    }
} catch { $result = 1 }
# The outcome record is written by a detached process that inherits none of
# this launcher's handles, so a slow or unreachable measurement directory (for
# example a redirected profile on a network share) never keeps the agent
# waiting; only starting that process is on the agent's path.
try {
    $stamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $name = "$($hook.agent).$($hook.event).$stamp.$result.$execution.agent"
    # Typographic single quotes also end a PowerShell single-quoted string.
    $path = $hook.directory -replace "(['$([char]0x2018)-$([char]0x201B)])", '$1$1'
    $report = "`$ErrorActionPreference = 'SilentlyContinue'; `$p = '$path'; "
    $report += "[void][IO.Directory]::CreateDirectory(`$p); if ([IO.Directory]::GetFiles(`$p).Length -lt 4096) { "
    $report += "[IO.File]::Open([IO.Path]::Combine(`$p, '$name'), 'CreateNew', 'Write', 'None').Dispose() }"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($report))
    detach "$PSHOME\powershell.exe" "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded"
} catch {}
exit 0
""".strip()


def directory(settings_path):
    return Path(settings_path).parent / "openaidr-hook-health"


def registered_directories(config):
    path = Path(config["data_dir"]) / "hook-health-directories.json"
    try:
        paths = json.loads(path.read_text())
        return {Path(p) for p in paths if isinstance(p, str) and Path(p).is_absolute()} if isinstance(paths, list) else set()
    except (OSError, ValueError):
        return set()


def register(config_path, health_dir):
    if config_path is None:
        return
    config = Config.load(config_path)
    path = Path(config["data_dir"]) / "hook-health-directories.json"
    with configuration_lock(path):
        paths = registered_directories(config)
        paths.add(Path(health_dir).expanduser().absolute())
        atomic_write(path, json.dumps(sorted(str(p) for p in paths)))


# Names the native launchers give measurement files: agent, event, completion
# time, exit code, a unique execution identifier, and optional receipt version.
MEASUREMENT = re.compile(r"(" + "|".join(PRODUCTS) + r")\.([A-Za-z]+)\.(\d{1,12})\.(-?\d{1,10})\.([A-Za-z0-9]{6,64})(\.agent)?")


def unregister(config_path, health_dir):
    config = Config.load(config_path)
    path = Path(config["data_dir"]) / "hook-health-directories.json"
    with configuration_lock(path):
        paths = registered_directories(config)
        target = Path(health_dir).expanduser().absolute()
        if target in paths:
            paths.discard(target)
            atomic_write(path, json.dumps(sorted(str(p) for p in paths)))


def cleanup(health_dir, agent, config_path=None):
    """Remove one agent's launcher scripts and pending measurements after uninstall.

    Only files these launchers create are removed: measurement records named
    for this agent and Windows runners whose content hash and agent match.
    Unrelated files keep the directory in place. Pending measurements are
    content-free and are dropped rather than reported. The directory leaves
    the sensor's registry once it is gone. Best effort: a failure here never
    undoes or fails the uninstall that preceded it.
    """
    health_dir = Path(health_dir).expanduser().absolute()
    try:
        if health_dir.is_symlink():
            return
        launchers = health_dir / "launchers"
        if launchers.is_dir() and not launchers.is_symlink():
            for runner in launchers.glob("*.json"):
                try:
                    if runner.is_symlink() or not runner.is_file():
                        continue
                    text = runner.read_text(encoding="utf-8")
                    config = json.loads(text)
                    if (runner.stem == hashlib.sha256(text.encode()).hexdigest()
                            and config.get("marker") == MARKER and config.get("agent") == agent):
                        runner.unlink()
                except (OSError, ValueError, TypeError, AttributeError):
                    continue
            for runner in launchers.glob("*.ps1"):
                try:
                    if runner.is_symlink() or not runner.is_file():
                        continue
                    script = runner.read_text()
                    if (runner.stem == hashlib.sha256(script.encode()).hexdigest()
                            and windows_config(script).get("agent") == agent):
                        runner.unlink()
                except (OSError, ValueError, KeyError, TypeError):
                    continue
            for runner in launchers.glob("*/guardrail.sh"):
                try:
                    if runner.parent.is_symlink() or runner.is_symlink() or not runner.is_file():
                        continue
                    script = runner.read_text()
                    config = posix_config(script)
                    if (config.get("agent") == agent
                            and (runner == stable_posix_runner(config)
                                 or runner.parent.name == hashlib.sha256(script.encode()).hexdigest())):
                        runner.unlink()
                        runner.parent.rmdir()
                except (OSError, ValueError, KeyError, TypeError):
                    continue
            try:
                launchers.rmdir()
            except OSError:
                pass
        if health_dir.is_dir():
            with os.scandir(health_dir) as entries:
                for entry in entries:
                    match = MEASUREMENT.fullmatch(entry.name)
                    if match and match[1] == agent and entry.is_file(follow_symlinks=False):
                        try:
                            os.unlink(entry.path)
                        except OSError:
                            pass
            try:
                health_dir.rmdir()
            except OSError:
                pass
        if config_path is not None and not health_dir.exists():
            unregister(config_path, health_dir)
    except (OSError, ValueError):
        pass


def command(parts, health_dir, agent, event, *, windows=False, socket_path=None):
    seconds = AGENT_HOOK_TIMEOUT_SECONDS if windows else HOOK_TIMEOUT_SECONDS
    health_dir = Path(health_dir).expanduser().absolute()
    client = native_windows_client(parts) if windows else None
    if client is not None:
        explicit = "--config" in parts
        config_path = parts[parts.index("--config") + 1] if explicit else default_path()
        text = json.dumps(dict(marker=MARKER, args=parts, directory=str(health_dir),
                               agent=agent, event=event, seconds=seconds,
                               sensor_config=str(Path(config_path).absolute()),
                               explicit_config=explicit))
        runner = health_dir / "launchers" / (hashlib.sha256(text.encode()).hexdigest() + ".json")
        atomic_write(runner, text)
        return native_windows_command(client, runner)
    if not windows:
        config = dict(args=parts, directory=str(health_dir), seconds=seconds, agent=agent, event=event)
        if socket_path is not None:
            config["socket_path"] = str(socket_path)
        script = posix_script(config)
        # Stable commands follow app updates without changing agent trust.
        # Other agents keep an older session bound to the script it was given.
        runner = (stable_posix_runner(config)
                  or health_dir / "launchers" / hashlib.sha256(script.encode()).hexdigest() / "guardrail.sh")
        atomic_write(runner, script)
        return posix_launcher(runner, config)
    config = json.dumps(dict(args=parts, arguments=subprocess.list2cmdline(parts[1:]),
                             directory=str(health_dir), seconds=seconds, agent=agent, event=event))
    literal = config.replace("'", "''")
    script = f"# {MARKER}\n$hook = ConvertFrom-Json '{literal}'\n" + WINDOWS
    # Keep executable/config paths out of cmd.exe's 8191-character limit. The
    # immutable runner also preserves older agents' already-trusted commands.
    runner = health_dir / "launchers" / (hashlib.sha256(script.encode()).hexdigest() + ".ps1")
    command = windows_launcher(runner, health_dir, agent, event)
    atomic_write(runner, script)
    return command


def posix_script(config):
    parts = [config["directory"], str(config["seconds"]), config["agent"], config["event"], *config["args"]]
    body = POSIX
    if config.get("socket_path"):
        route = ROUTES[PRODUCTS[config["agent"]]]
        client = shlex.join(["/bin/sh", "-c", SOCKET_REQUEST, MARKER, config["socket_path"],
                             f"{route}/native", config["event"]])
        # Managed launches own a separate synchronous bridge. Keep its existing
        # CLI behavior, as well as an explicit runtime sensor-config override.
        select = ('\nif [ -z "${OPENAIDR_MANAGED_BRIDGE:-}" ] && '
                  '[ -z "${OPENAIDR_SENSOR_CONFIG:-}" ]; then\n'
                  f'    set -- {client}\nfi\n')
        body = body.replace("\noutput=$(", select + "output=$(", 1)
    return (f"#!/bin/sh\n# {MARKER}\n# {json.dumps(config)}\n"
            + shlex.join(["set", "--", *parts]) + "\n" + body + "\n")


def stable_posix_runner(config):
    if config.get("agent") in ("codex", "hermes"):
        return Path(config["directory"]) / "launchers" / f"{config['agent']}-{config['event']}" / "guardrail.sh"
    return None


def posix_launcher(runner, config):
    # Older sensors identify owned hooks by the sensor arguments at index 8.
    # Preserve that layout so upgrades and rollbacks replace, rather than append.
    parts = config["args"]
    if runner == stable_posix_runner(config):
        # Only the script uses the executable; keep it out of the trust identity.
        parts = ["openaidr", *parts[1:]]
    return shlex.join(["/bin/sh", "-c", POSIX_BOOTSTRAP, MARKER, str(runner),
                       str(config["seconds"]), config["agent"], config["event"], *parts])


def posix_config(script):
    prefix = f"#!/bin/sh\n# {MARKER}\n# "
    if not script.startswith(prefix):
        raise ValueError("invalid hook configuration")
    config = json.loads(script[len(prefix):].partition("\n")[0])
    parts = config["args"]
    if not isinstance(parts, list) or not all(isinstance(p, str) for p in parts):
        raise ValueError("invalid hook arguments")
    return config


def powershell_literal(text):
    # PowerShell also ends single-quoted strings at typographic single quotes.
    return "'" + re.sub("(['\u2018\u2019\u201a\u201b])", r"\1\1", str(text)) + "'"


def native_windows_client(parts):
    """Bundled helper beside the immutable sensor; source installs keep their launcher."""
    if len(parts) < 3 or parts[1] != "hook":
        return None
    sensor = Path(parts[0])
    if not sensor.is_absolute():
        return None
    client = sensor.with_name("openaidr-hook.exe")
    if os.name == "nt" and not re.fullmatch(r"[A-Za-z]:", ntpath.splitdrive(str(client))[0]):
        return None
    # These characters expand differently in cmd, Bash and PowerShell. Keep
    # the encoded legacy launcher for those unusual installation paths.
    if client.is_file() and not any(c in str(client) for c in '\"$`%\r\n'):
        return client
    return None


def native_windows_command(client, runner):
    path = str(client).replace("\\", "/")
    prefix = path[:3] if re.match(r"^[A-Za-z]:/", path) else "/"
    if not path.startswith(prefix):
        raise ValueError("absolute Windows hook executable required")
    # An unquoted drive prefix makes PowerShell invoke the path. Quoting the
    # remainder protects spaces and shell operators in all three hook shells.
    command = f'{prefix}"{path[len(prefix):]}" --openaidr-hook {str(runner).encode().hex()}'
    if len(command) > 7800:
        raise ValueError("hook path exceeds the Windows command length limit")
    return command


def windows_launcher(runner, health_dir, agent, event):
    """One PowerShell command line that every Windows hook shell runs alike.

    Claude Code runs hook commands with Git Bash, or PowerShell without it;
    Codex runs them with cmd.exe /C. The command holds no shell operators,
    backslashes, or user paths: a forward-slash executable and Base64 text
    mean the same to each shell. The Base64 text starts with "Iw" ("#"), never
    "/", so Git Bash does not convert it as a path. When PowerShell starts but
    cannot load the runner, the bootstrap records the failure in the
    measurement directory, never the working directory, and allows the action
    silently.
    """
    record = (f"[void][IO.Directory]::CreateDirectory($p)\n"
              f"if ([IO.Directory]::GetFiles($p).Length -lt {MAX_RECORDS}) {{\n"
              f"$n = '{agent}.{event}.' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + "
              "'.127.' + [guid]::NewGuid().ToString('N')\n"
              "[IO.File]::Open([IO.Path]::Combine($p, $n), 'CreateNew', 'Write', 'None').Dispose() }")
    bootstrap = (f"# {MARKER} {json.dumps(str(runner))}\n"
                 "$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\n"
                 f"trap {{ try {{ $p = {powershell_literal(health_dir)}\n{record} }} catch {{}}\nexit 0 }}\n"
                 f"& ([scriptblock]::Create([IO.File]::ReadAllText({powershell_literal(runner)})))\n")
    encoded = base64.b64encode(bootstrap.encode("utf-16-le")).decode()
    system = ntpath.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    executable = ntpath.join(system, "WindowsPowerShell", "v1.0", "powershell.exe").replace("\\", "/")
    # Bash expands $ and ` inside double quotes; cmd.exe expands %.
    if any(c in executable for c in '"$`%\r\n'):
        raise ValueError("system directory is not supported by the Windows hook shells")
    if not re.fullmatch(r"[A-Za-z0-9_./:-]+", executable):
        executable = f'"{executable}"'
    command = f"{executable} -NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}"
    # Codex passes the command to cmd.exe, which accepts 8191 characters.
    if len(command) > 7800:
        raise ValueError("hook measurement path exceeds the Windows command length limit")
    return command


def windows_runner(encoded):
    """The runner a launcher's encoded bootstrap loads, or None."""
    bootstrap = base64.b64decode(encoded, validate=True).decode("utf-16-le")
    prefix = f"# {MARKER} "
    if not bootstrap.startswith(prefix):
        return None
    return Path(json.loads(bootstrap[len(prefix):].partition("\n")[0]))


def arguments(command, *, windows=False):
    """Inspect launcher arguments without executing any hook or shell code."""
    native = windows and re.fullmatch(r'(?:[A-Za-z]:/|/)"[^"\r\n]+" --openaidr-hook ([0-9a-f]+)', command)
    if native:
        try:
            runner = Path(bytes.fromhex(native[1]).decode())
            if runner.is_symlink() or not runner.is_file():
                raise ValueError("invalid hook descriptor")
            text = runner.read_text(encoding="utf-8")
            config = json.loads(text)
            parts = config["args"]
            if not isinstance(parts, list) or not all(isinstance(p, str) for p in parts):
                raise ValueError("invalid hook arguments")
            client = native_windows_client(parts)
            valid = (config.get("marker") == MARKER
                     and config.get("seconds") == AGENT_HOOK_TIMEOUT_SECONDS
                     and runner.stem == hashlib.sha256(text.encode()).hexdigest()
                     and client is not None and command == native_windows_command(client, runner))
            return parts, valid
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return ["openaidr", "hook", "unavailable"], False
    launcher = windows and re.fullmatch(
        r'(?:"[^"\r\n]+"|[^"\s]+) -NoLogo -NoProfile -NonInteractive -EncodedCommand ([A-Za-z0-9+/=]+)', command)
    runner = launcher and windows_runner(launcher[1])
    if runner:
        try:
            script = runner.read_text()
            config = windows_config(script)
        except (OSError, ValueError, KeyError, TypeError):
            return ["openaidr", "hook", "unavailable"], False
        valid = runner.stem == hashlib.sha256(script.encode()).hexdigest()
        expected = windows_launcher(runner, Path(config["directory"]), config["agent"], config["event"])
        return config["args"], (valid and script.endswith(WINDOWS) and command == expected
                                and native_windows_client(config["args"]) is None)
    # Earlier cmd.exe command lines fail in Git Bash. They stay ours, so setup
    # replaces them in place, but are never reported as available.
    if windows and re.match(r'^"[^"\n]+\\cmd\.exe" /d /q /v:off /s /c ', command):
        encoded = re.search(r" -EncodedCommand ([A-Za-z0-9+/=]+) ", command)
        runner = encoded and windows_runner(encoded[1])
        if runner:
            try:
                return windows_config(runner.read_text())["args"], False
            except (OSError, ValueError, KeyError, TypeError):
                return ["openaidr", "hook", "unavailable"], False
    parts = shlex.split(command, posix=not windows)
    if (len(parts) >= 10 and parts[:2] == ["/bin/sh", "-c"] and parts[3] == MARKER
            and parts[2] == POSIX_BOOTSTRAP):
        runner = Path(parts[4])
        try:
            # A directory, FIFO, or symlink is not an installed launcher.
            if runner.is_symlink() or not runner.is_file():
                raise ValueError("invalid hook script")
            script = runner.read_text()
            config = posix_config(script)
            stable = runner == stable_posix_runner(config)
            valid = (runner.name == "guardrail.sh"
                     and (stable or runner.parent.name == hashlib.sha256(script.encode()).hexdigest())
                     and script == posix_script(config)
                     and command == posix_launcher(runner, config))
            return config["args"] if stable and valid else parts[8:], valid
        except (OSError, ValueError, KeyError, TypeError):
            return parts[8:], False
    if len(parts) >= 10 and parts[:2] == ["/bin/sh", "-c"] and parts[3] == MARKER:
        return parts[8:], False
    if len(parts) == 5 and parts[:4] == ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand"]:
        script = base64.b64decode(parts[4], validate=True).decode("utf-16-le")
        if script.startswith(f"# {MARKER}\n"):
            return windows_config(script)["args"], False
    return [part.strip('"') for part in parts] if windows else parts, False


def windows_config(script):
    prefix = f"# {MARKER}\n$hook = ConvertFrom-Json '"
    if not script.startswith(prefix):
        raise ValueError("invalid hook configuration")
    literal = script[len(prefix):].partition("\n")[0]
    if not literal.endswith("'"):
        raise ValueError("invalid hook configuration")
    config = json.loads(literal[:-1].replace("''", "'"))
    parts = config["args"]
    if not isinstance(parts, list) or not all(isinstance(p, str) for p in parts):
        raise ValueError("invalid hook arguments")
    return config


def measurement(sensor_id, product, event, execution_id, code, at, *, failure_reason=""):
    """One runtime record per run, including sensor-observed expiry."""
    hook = {"hook_event": event, "execution_id": execution_id,
            "outcome": "succeeded" if code == 0 else "failed"}
    if code is not None:
        hook["exit_code"] = code
    else:
        hook["failure_reason"] = failure_reason
    return {
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(
            ["hook-runtime", sensor_id, product, event, execution_id],
        ))),
        "time": at, "kind": "sensor", "agent": {"product": product},
        "source": {"collector": "hook-runtime"}, "hook": hook,
    }


def collect(health_dir, emit, *, sensor_id, complete=None):
    """Move completed measurements to the durable sensor spool, with replay IDs.

    Empty files are atomically created by the native shell, so a missing sensor
    executable can still be measured. No agent input or output is written here.
    """
    products = PRODUCTS
    try:
        with os.scandir(health_dir) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_RECORDS:
                    break
                match = MEASUREMENT.fullmatch(entry.name)
                if not match or not entry.is_file(follow_symlinks=False):
                    continue
                agent, event, stamp, code, execution_id, agent_owned = match.groups()
                try:
                    at = datetime.fromtimestamp(int(stamp) or entry.stat().st_mtime, timezone.utc).isoformat()
                except (OverflowError, OSError, ValueError):
                    continue
                record = {
                    "id": str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps([sensor_id, str(Path(entry.path).absolute())]))),
                    "time": at,
                    "kind": "sensor",
                    "agent": {"product": products[agent]},
                    "source": {"collector": "hook-runtime"},
                    "hook": {"hook_event": event, "exit_code": int(code),
                             "execution_id": execution_id,
                             "outcome": "failed" if int(code) else "succeeded"},
                }
                if agent_owned:
                    record = measurement(sensor_id, products[agent], event, execution_id, int(code), at)
                try:
                    emit(record)
                    if complete:
                        complete(record)
                except Exception:
                    # Retain the record for retry without interrupting heartbeats.
                    return
                Path(entry.path).unlink(missing_ok=True)
    except OSError:
        pass


class PendingDecisions:
    """Bounded, already-redacted decisions awaiting native output delivery.

    Missing receipts, restarts, expiry, and capacity loss leave delivery unknown.
    None of those cases may publish a decision as applied.
    """

    def __init__(self, emit, failed=None):
        self.emit = emit
        self.failed = failed
        self.lock = threading.Lock()
        self.entries = OrderedDict()
        self.receipts = OrderedDict()
        self.size = 0

    def stage(self, event):
        execution_id = event["hook"].get("execution_id")
        if not execution_id:
            return
        payload = json.dumps(event).encode()
        with self.lock:
            self._expire()
            if len(payload) > 4 << 20:
                return
            if execution_id in self.entries:
                self.size -= len(self.entries.pop(execution_id)[1])
            while self.entries and (self.size + len(payload) > 4 << 20 or len(self.entries) >= MAX_RECORDS):
                self.size -= len(self.entries.popitem(last=False)[1][1])
            self.entries[execution_id] = (time.monotonic(), payload)
            self.size += len(payload)

    def _expire(self):
        while self.entries and next(iter(self.entries.values()))[0] < time.monotonic() - 300:
            self.size -= len(self.entries.popitem(last=False)[1][1])
        while self.receipts and next(iter(self.receipts.values()))[0] < time.monotonic() - 300:
            self.receipts.popitem(last=False)

    def flush(self):
        """Pair early launcher exits with decisions that finished later."""
        with self.lock:
            self._expire()
            ready = [measurement for key, (_, measurement) in self.receipts.items() if key in self.entries]
            for key, (_, payload) in self.entries.items():
                if key in self.receipts:
                    continue
                event = json.loads(payload)
                hook = event["hook"]
                if hook.get("timeout_owner") in ("agent", "sensor") and hook.get("failure_reason") == "deadline_expired":
                    # Positive evidence: evaluation finished after the original
                    # delivery deadline. Missing receipts alone are not failure.
                    ready.append({"hook": {"execution_id": key, "outcome": "failed"}})
        for measurement in ready:
            self.complete(measurement)

    def record_receipt(self, measurement):
        """Queue evidence without blocking a local hook response on disk I/O."""
        execution_id = measurement["hook"].get("execution_id")
        if not execution_id:
            return
        with self.lock:
            self._expire()
            if execution_id not in self.receipts:
                while len(self.receipts) >= MAX_RECORDS:
                    self.receipts.popitem(last=False)
                self.receipts[execution_id] = (time.monotonic(), {"hook": dict(measurement["hook"])})

    def complete(self, measurement):
        execution_id = measurement["hook"].get("execution_id")
        self.record_receipt(measurement)
        with self.lock:
            entry = self.entries.get(execution_id)
            if entry is None:
                return
        event = json.loads(entry[1])
        succeeded = measurement["hook"]["outcome"] == "succeeded"
        timed_out = (measurement["hook"].get("exit_code") in (28, 124, 137)
                     or event["hook"].get("failure_reason") == "deadline_expired")
        event["hook"]["delivery"] = "delivered" if succeeded else "timed_out" if timed_out else "failed"
        if succeeded:
            self.emit(event)
        elif self.failed:
            self.failed(event)
        with self.lock:
            if self.entries.get(execution_id) is entry:
                self.size -= len(self.entries.pop(execution_id)[1])
                self.receipts.pop(execution_id, None)
