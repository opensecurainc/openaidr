"""WorkBuddy profile locations and Windows hook shell, shared by sensor setup."""

import os
from pathlib import Path
import shutil
import subprocess
import threading
import time

WINDOWS = os.name == "nt"
# A shell can be installed, removed, or blocked by application control after
# setup. Recheck at most this often while WorkBuddy hooks need one.
SHELL_RECHECK_SECONDS = 600
SHELL_PROBE_TIMEOUT_SECONDS = 10
_shell_lock = threading.Lock()
_shell_cache = None


def config_roots(home=None):
    """Return candidate profiles without reading or creating their directories."""
    override = os.environ.get("WORKBUDDY_CONFIG_DIR", "").strip()
    if override:
        return (Path(override).expanduser(),)
    home = Path(home) if home is not None else Path.home()
    return (home / ".workbuddy", home / ".workbuddy-ai")


def _windows_hook_shell():
    """The shell WorkBuddy 37.10 selects for a hook without a ``shell`` field.

    Git Bash beside Git comes first, then PowerShell 7, Windows PowerShell on
    ``PATH``, and the System32 copy. WorkBuddy uses the first one it finds and
    does not fall back when that one fails to start. Shell overrides set only
    in WorkBuddy's own environment are not visible here.
    """
    gits = [path for path in (r"C:\Program Files\Git\cmd\git.exe", r"C:\Program Files (x86)\Git\cmd\git.exe")
            if os.path.isfile(path)]
    found = shutil.which("git")
    for git in [*gits, *([found] if found else [])]:
        for relative in (("..", "bin", "bash.exe"), ("..", "usr", "bin", "bash.exe")):
            bash = os.path.normpath(os.path.join(os.path.dirname(git), *relative))
            if os.path.isfile(bash):
                return bash, "bash"
    bash = shutil.which("bash")
    folded = (bash or "").lower().replace("/", "\\")
    if bash and "\\git\\" in folded and not any(part in folded for part in ("\\system32\\", "\\syswow64\\")):
        return bash, "bash"
    for name in ("pwsh", "powershell"):
        found = shutil.which(name)
        if found:
            return found, "powershell"
    system = os.path.join(os.environ.get("SYSTEMROOT") or r"C:\Windows", "System32", "WindowsPowerShell",
                          "v1.0", "powershell.exe")
    return (system, "powershell") if os.path.isfile(system) else (None, None)


def _starts(executable, kind):
    args = ["-c", "exit 0"] if kind == "bash" else ["-NoProfile", "-NonInteractive", "-Command", "exit 0"]
    try:
        return subprocess.run(
            [executable, *args], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=SHELL_PROBE_TIMEOUT_SECONDS, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def hook_shell_unavailable():
    """True on Windows when WorkBuddy cannot start a shell for its hooks.

    WorkBuddy rejects the action when a hook's shell fails to start, so setup
    must not leave OpenAIDR hooks it cannot run. Results are cached briefly
    because status and heartbeats call this repeatedly.
    """
    global _shell_cache
    if not WINDOWS:
        return False
    with _shell_lock:
        now = time.monotonic()
        if _shell_cache is None or now - _shell_cache[0] >= SHELL_RECHECK_SECONDS:
            executable, kind = _windows_hook_shell()
            _shell_cache = (now, not (executable and _starts(executable, kind)))
        return _shell_cache[1]
