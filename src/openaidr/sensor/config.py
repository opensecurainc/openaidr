import copy
import errno
import getpass
import hashlib
import os
import platform
from urllib.parse import urlsplit
from pathlib import Path
from uuid import UUID
import yaml
import threading
from contextlib import contextmanager

from openaidr.core.enrollment import validate_server_url
from openaidr.core.files import atomic_write, durable_directory

_config_lock = threading.RLock()
_locked_paths = set()
IDENTITY_FIELDS = (
    "connection_mode",
    "server_url",
    "sensor_id",
    "sensor_token",
    "tenant_id",
    "auth_mode",
    "ca_cert",
    "client_cert",
    "client_key",
    "credential_generation",
    "credential_expires_at",
    "credential_renew_after",
    "credential_activation_pending",
)


@contextmanager
def configuration_lock(path):
    """Serialize credential installation and config saves across local processes."""
    path = Path(path).expanduser().resolve()
    with _config_lock:
        if path in _locked_paths:
            yield
            return
        durable_directory(path.parent)
        fd = os.open(path.with_name(path.name + ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "nt":
                import msvcrt

                # Byte-range locks can extend past EOF. A priming write would
                # fail before locking if another process already owns byte 0.
                os.lseek(fd, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    # The CRT uses EACCES for a conflicting byte-range lock.
                    # Only normalize this call, never opening the lock file.
                    if exc.errno in (errno.EACCES, errno.EDEADLK):
                        raise BlockingIOError(errno.EAGAIN, "Configuration lock is busy") from exc
                    raise
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _locked_paths.add(path)
            try:
                yield
            finally:
                _locked_paths.remove(path)
        finally:
            os.close(fd)


def is_root():
    return (
        os.geteuid() == 0
        if hasattr(os, "geteuid")
        else os.environ.get("USERNAME", "").upper() == "SYSTEM"
    )


def base_dir():
    if platform.system() == "Darwin":
        return (
            Path("/Library/Application Support/OpenAIDR")
            if is_root()
            else Path.home() / "Library/Application Support/OpenAIDR"
        )
    if os.name == "nt":
        return windows_base_dir()
    return (
        Path("/etc/openaidr")
        if is_root()
        else Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
        / "openaidr"
    )


def windows_base_dir(environ=None):
    """Per-user state, like the per-user Scheduled Task that runs the sensor.

    The sensor runs as the account that runs the coding agents, so its
    configuration and queues live in that user's private local profile. A
    SYSTEM process keeps the machine-wide ProgramData location, and an existing
    per-machine configuration from older Windows installs is still honored
    when no per-user configuration exists.
    """
    environ = os.environ if environ is None else environ
    machine = Path(environ.get("ProgramData") or r"C:\ProgramData") / "OpenAIDR"
    if environ.get("USERNAME", "").upper() == "SYSTEM":
        return machine
    # App files and persistent state have separate children of OpenAIDR.
    # Existing state stays selected until the update worker relocates it.
    from .windows_layout import state_root

    user = state_root(environ)
    if not (user / "sensor.yaml").exists() and (machine / "sensor.yaml").exists():
        return machine
    return user


def default_path():
    return base_dir() / "sensor.yaml"


HOOK_PORT, TELEMETRY_PORT = 8377, 4318


def default_listen(port, environ=None, windows=None):
    """The default loopback listener for the hook or telemetry receiver.

    Every Windows user runs a sensor under their own Scheduled Task, all on
    one shared loopback, so each account gets its own pair of ports in
    20000-21999 (below the ephemeral range), stable across reinstalls.
    Elsewhere, and for SYSTEM, the fixed ports apply.
    """
    environ = os.environ if environ is None else environ
    windows = os.name == "nt" if windows is None else windows
    user = environ.get("USERNAME") or (getpass.getuser() if environ is os.environ else "")
    if not windows or user.upper() == "SYSTEM":
        return f"127.0.0.1:{port}"
    account = (environ.get("USERDOMAIN", "") + "\\" + user).lower()
    slot = int.from_bytes(hashlib.sha256(account.encode()).digest()[:4], "big") % 1000
    return f"127.0.0.1:{20000 + 2 * slot + (port == TELEMETRY_PORT)}"


def default_data_dir():
    if platform.system() == "Linux":
        return (
            Path("/var/lib/openaidr")
            if is_root()
            else Path(
                os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))
            )
            / "openaidr"
        )
    return base_dir() / "data"


def validate_device_auth(config):
    mode = config.get("auth_mode", "bearer")
    if mode not in ("bearer", "mtls"):
        raise ValueError("auth_mode must be bearer or mtls")
    if mode == "mtls":
        origin = validate_server_url(config.get("server_url", ""))
        parsed = urlsplit(origin)
        if parsed.scheme != "https":
            raise ValueError("mTLS requires an HTTPS server URL")
        if (
            parsed.username is not None
            or parsed.password is not None
            or "?" in origin
            or "#" in origin
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in origin)
        ):
            raise ValueError(
                "mTLS server URL must be an HTTPS origin without credentials"
            )
        for name in ("tenant_id", "sensor_id"):
            value = config.get(name)
            try:
                if not isinstance(value, str):
                    raise ValueError
                UUID(value)
            except ValueError:
                raise ValueError(f"mTLS requires a valid {name} UUID") from None
        for name in ("client_cert", "client_key"):
            if not isinstance(config.get(name), str) or not config[name].strip():
                raise ValueError(f"mTLS requires a {name} file path")


class Config(dict):
    def __init__(self, path=None, **values):
        super().__init__(
            listen=default_listen(HOOK_PORT),
            data_dir=str(default_data_dir()),
            host_kind="workstation",
            log_level="info",
            collectors={},
        )
        defaults = dict(self)
        self.update(values)
        for key in ("listen", "data_dir", "host_kind", "log_level"):
            if not self.get(key):
                self[key] = defaults[key]
        self.path = Path(path or default_path())
        self["server_url"] = (self.get("server_url") or "").rstrip("/")
        self._saved_identity = None

    @classmethod
    def load(cls, path=None):
        path = Path(path or default_path())
        values = yaml.safe_load(path.read_text()) if path.exists() else {}
        if values is not None and not isinstance(values, dict):
            raise ValueError("sensor config must be a mapping")
        config = cls(path, **(values or {}))
        config._saved_identity = {key: config.get(key) for key in IDENTITY_FIELDS}
        return config

    def save(self):
        with configuration_lock(self.path):
            current = Config.load(self.path) if self.path.exists() else None
            if (
                current is not None
                and self._saved_identity is not None
                and self._saved_identity
                == {key: self.get(key) for key in IDENTITY_FIELDS}
            ):
                # A setup/settings caller may have loaded the previous generation
                # before another process installed a certificate. Keep that identity.
                for key in IDENTITY_FIELDS:
                    if key in current:
                        self[key] = current[key]
                    else:
                        self.pop(key, None)
            atomic_write(self.path, yaml.safe_dump(dict(self), sort_keys=False))
            self._saved_identity = {key: self.get(key) for key in IDENTITY_FIELDS}

    def enrolled(self):
        if self.get("auth_mode", "bearer") != "bearer":
            try:
                validate_device_auth(self)
            except ValueError:
                return False
            return True
        return all(self.get(k) for k in ("server_url", "sensor_id", "sensor_token"))

    def validate(self):
        if self.get("server_url"):
            validate_server_url(self["server_url"])
        validate_device_auth(self)
        if self["host_kind"] not in ("workstation", "server"):
            raise ValueError("host_kind must be workstation or server")
        if self["log_level"] not in ("debug", "info", "warn", "error"):
            raise ValueError("log_level must be debug, info, warn, or error")


def capture_overrides(capture, overrides=None):
    result = copy.deepcopy(capture)
    for key, value in (overrides or {}).items():
        if key == "redact":
            result[key] = result.get(key, False) or bool(value)
        elif key == "max_text_bytes":
            if value and value > 0:
                result[key] = value
        elif value is not None:
            result[key] = result.get(key, False) and bool(value)
    return result
