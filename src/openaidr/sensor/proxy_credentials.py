"""Proxy passwords in the operating system's credential store.

Passwords never enter ``sensor.yaml``, status output, logs, or command lines.
Desktop installs run the sensor as the signed-in user, so each store is the
user's own:

* macOS: the login keychain through ``/usr/bin/security`` (commands on stdin).
* Windows: Credential Manager (DPAPI-protected, per user).
* Linux: the Secret Service through ``secret-tool``, otherwise a credential
  encrypted with ``systemd-creds --user`` (systemd 256 or later).

System-wide (root or SYSTEM) installs support only proxies without a password.
"""

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .config import base_dir, is_root

SERVICE = "OpenAIDR sensor proxy"
LINUX_ATTRIBUTE = "openaidr-sensor-proxy"
TIMEOUT_SECONDS = 10
MAX_PASSWORD_BYTES = 1024


class CredentialStoreError(Exception):
    """The credential store is unavailable or rejected the operation."""


def _check_password(password):
    if not isinstance(password, str) or not password:
        raise ValueError("Enter the proxy password.")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES or any(ch in password for ch in "\r\n\0"):
        raise ValueError("The proxy password is too long or contains a line break.")


def _run(command, stdin=None):
    try:
        return subprocess.run(command, input=stdin, capture_output=True, text=True,
                              timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CredentialStoreError(f"{Path(command[0]).name} is unavailable") from exc


# macOS ---------------------------------------------------------------------

SECURITY = "/usr/bin/security"


def _quote(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _mac_get(account):
    result = _run([SECURITY, "find-generic-password", "-s", SERVICE, "-a", account, "-w"])
    if result.returncode == 44:  # errSecItemNotFound
        return None
    if result.returncode:
        raise CredentialStoreError("the login keychain could not be read")
    return result.stdout.rstrip("\n")


def _mac_set(account, password):
    # Interactive mode reads the command from stdin, so the password is never
    # visible in the process list. -U updates an existing item.
    command = (f"add-generic-password -U -s {_quote(SERVICE)} -a {_quote(account)} "
               f"-l {_quote(SERVICE)} -w {_quote(password)}\n")
    result = _run([SECURITY, "-i"], stdin=command)
    if result.returncode or "error" in result.stderr.lower():
        raise CredentialStoreError("the login keychain rejected the proxy password")


def _mac_delete(account):
    result = _run([SECURITY, "delete-generic-password", "-s", SERVICE, "-a", account])
    if result.returncode not in (0, 44):
        raise CredentialStoreError("the login keychain item could not be removed")


# Windows -------------------------------------------------------------------

def _windows_api():
    import ctypes
    from ctypes import wintypes

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
                    ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
                    ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
                    ("CredentialBlob", ctypes.c_void_p), ("Persist", wintypes.DWORD),
                    ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
                    ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.POINTER(ctypes.POINTER(CREDENTIAL))]
    advapi.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIAL), wintypes.DWORD]
    advapi.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    advapi.CredFree.argtypes = [ctypes.c_void_p]
    return ctypes, CREDENTIAL, advapi


_CRED_TYPE_GENERIC, _CRED_PERSIST_LOCAL_MACHINE, _ERROR_NOT_FOUND = 1, 2, 1168


def _windows_target(account):
    return f"{SERVICE}/{account}"


def _windows_get(account):
    ctypes, CREDENTIAL, advapi = _windows_api()
    pointer = ctypes.POINTER(CREDENTIAL)()
    if not advapi.CredReadW(_windows_target(account), _CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)):
        if ctypes.get_last_error() == _ERROR_NOT_FOUND:
            return None
        raise CredentialStoreError("Credential Manager could not be read")
    try:
        blob = ctypes.string_at(pointer.contents.CredentialBlob, pointer.contents.CredentialBlobSize)
        return blob.decode("utf-16-le")
    finally:
        advapi.CredFree(pointer)


def _windows_set(account, password):
    ctypes, CREDENTIAL, advapi = _windows_api()
    blob = password.encode("utf-16-le")
    buffer = ctypes.create_string_buffer(blob, len(blob))
    credential = CREDENTIAL(Type=_CRED_TYPE_GENERIC, TargetName=_windows_target(account),
                            CredentialBlobSize=len(blob),
                            CredentialBlob=ctypes.cast(buffer, ctypes.c_void_p),
                            Persist=_CRED_PERSIST_LOCAL_MACHINE,
                            UserName=account.rsplit("@", 1)[0])
    try:
        if not advapi.CredWriteW(ctypes.byref(credential), 0):
            raise CredentialStoreError("Credential Manager rejected the proxy password")
    finally:
        ctypes.memset(buffer, 0, len(blob))


def _windows_delete(account):
    ctypes, _, advapi = _windows_api()
    if not advapi.CredDeleteW(_windows_target(account), _CRED_TYPE_GENERIC, 0):
        if ctypes.get_last_error() != _ERROR_NOT_FOUND:
            raise CredentialStoreError("the Credential Manager item could not be removed")


# Linux ---------------------------------------------------------------------

def _linux_credential_file(account):
    digest = hashlib.sha256(account.encode("utf-8")).hexdigest()[:32]
    return base_dir() / "credentials" / f"proxy-{digest}.cred"


def _linux_name(account):
    return "openaidr-proxy-" + hashlib.sha256(account.encode("utf-8")).hexdigest()[:16]


def _secret_tool():
    return shutil.which("secret-tool")


def _systemd_creds():
    return shutil.which("systemd-creds")


def _linux_get(account):
    tool = _secret_tool()
    if tool:
        result = _run([tool, "lookup", "service", LINUX_ATTRIBUTE, "account", account])
        if result.returncode == 0 and result.stdout:
            return result.stdout.rstrip("\n")
    path = _linux_credential_file(account)
    if not path.exists():
        return None
    creds = _systemd_creds()
    if not creds:
        raise CredentialStoreError("systemd-creds is unavailable")
    result = _run([creds, "decrypt", "--user", f"--name={_linux_name(account)}", str(path), "-"])
    if result.returncode:
        raise CredentialStoreError("the encrypted proxy credential could not be read")
    return result.stdout


def _linux_set(account, password):
    tool = _secret_tool()
    if tool:
        result = _run([tool, "store", f"--label={SERVICE}", "service", LINUX_ATTRIBUTE,
                       "account", account], stdin=password)
        if result.returncode == 0:
            _linux_credential_file(account).unlink(missing_ok=True)
            return
    creds = _systemd_creds()
    if not creds:
        raise CredentialStoreError("No secure credential store is available. Install a Secret Service "
                                   "keyring or systemd 256 or later to save a proxy password.")
    path = _linux_credential_file(account)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    result = _run([creds, "encrypt", "--user", f"--name={_linux_name(account)}", "-", str(temporary)],
                  stdin=password)
    if result.returncode:
        temporary.unlink(missing_ok=True)
        raise CredentialStoreError("No secure credential store is available. Install a Secret Service "
                                   "keyring or systemd 256 or later to save a proxy password.")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _linux_delete(account):
    tool = _secret_tool()
    if tool:
        _run([tool, "clear", "service", LINUX_ATTRIBUTE, "account", account])
    _linux_credential_file(account).unlink(missing_ok=True)


# Public API ----------------------------------------------------------------

def _backend():
    if sys.platform == "darwin":
        return _mac_get, _mac_set, _mac_delete
    if os.name == "nt":
        return _windows_get, _windows_set, _windows_delete
    return _linux_get, _linux_set, _linux_delete


def get(account):
    """The saved password for ``account``, or ``None``."""
    return _backend()[0](account)


def set(account, password):  # noqa: A001 - mirrors get/delete
    if is_root():
        raise ValueError("Proxy passwords are not supported for system-wide installations. "
                         "Use a proxy that does not require a password.")
    _check_password(password)
    _backend()[1](account, password)


def delete(account):
    _backend()[2](account)
