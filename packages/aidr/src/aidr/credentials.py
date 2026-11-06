"""Private, standalone CLI credentials and recoverable service enrollment."""

import asyncio
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import httpx

from ._vendor.openaidr_api_client import free_tier
from ._vendor.openaidr_api_client.client import Connection, IntelligenceClient, TOKEN, Unavailable
from ._vendor.openaidr_api_client.contracts.capabilities import CAPABILITIES, Capabilities


ORIGIN = "https://api.opensecura.ai"
_LIMIT = 16 << 10


class CredentialError(ValueError):
    """A safe, actionable credential error that may be shown by the CLI."""


def default_path() -> Path:
    if sys.platform == "win32":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library/Application Support"
    else:
        root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "aidr/credentials.json"


def _private(info, *, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or (not directory and info.st_nlink != 1):
        raise CredentialError("Credentials require regular files in a private directory.")
    if os.name != "nt" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise CredentialError("Credentials and their directory must be accessible only to their owner.")


def _sync_directory(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _durable_directory(path):
    missing, parent = [], path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    _sync_directory(parent.parent)
    for entry in reversed(missing):
        entry.mkdir(mode=0o700, exist_ok=True)
        _sync_directory(entry.parent)


@contextmanager
def _locked(path):
    path = Path(path).expanduser().absolute()
    fd = None
    try:
        if path.is_symlink() or path.parent.is_symlink():
            raise CredentialError("Credential paths must not be symbolic links.")
        _durable_directory(path.parent)
        _private(path.parent.stat(follow_symlinks=False), directory=True)
        lock = path.with_name(path.name + ".lock")
        if lock.is_symlink():
            raise CredentialError("Credential paths must not be symbolic links.")
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        _private(os.fstat(fd))
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise CredentialError("Credentials are being updated by another process. Try again.") from None
        yield path
    except OSError:
        raise CredentialError("Could not access the credential store.") from None
    finally:
        if fd is not None:
            os.close(fd)


def _uuid(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError
    return value


def _free_connection(identity, ca_file=""):
    tenant = str(uuid5(NAMESPACE_URL, ORIGIN + "/free/" + UUID(identity["installation_id"]).hex))
    return Connection(identity["origin"], free_tier.credential(identity["installation_id"], identity["secret"]),
                      tenant, ca_file)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _read(path):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return {"version": 1, "free": None, "active": None, "pending_login": None}
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            _private(os.fstat(stream.fileno()))
            text = stream.read(_LIMIT + 1)
        if len(text) > _LIMIT:
            raise ValueError
        value = json.loads(text, object_pairs_hook=_unique_object)
        if (not isinstance(value, dict) or set(value) != {"version", "free", "active", "pending_login"}
                or type(value["version"]) is not int or value["version"] != 1):
            raise ValueError
        identity = value["free"]
        if identity is not None:
            if not isinstance(identity, dict) or set(identity) != {"origin", "installation_id", "device_id", "secret"}:
                raise ValueError
            _uuid(identity["installation_id"])
            _uuid(identity["device_id"])
            _free_connection(identity)
        active = value["active"]
        if active is not None:
            if not isinstance(active, dict) or set(active) != {"mode", "origin", "api_key", "tenant_id", "ca_file"}:
                raise ValueError
            if active["mode"] not in ("free", "api_key"):
                raise ValueError
            if not isinstance(active["ca_file"], str) or (active["ca_file"] and not Path(active["ca_file"]).is_absolute()):
                raise ValueError
            bound = Connection(active["origin"], active["api_key"], active["tenant_id"])
            if active["mode"] == "free" and (identity is None or bound != _free_connection(identity)):
                raise ValueError
        pending = value["pending_login"]
        if pending is not None:
            if not isinstance(pending, dict) or set(pending) != {"origin", "key_id", "tenant_id"}:
                raise ValueError
            _uuid(pending["tenant_id"])
            Connection(pending["origin"], "oasc_" + pending["key_id"] + "." + "a" * 43, pending["tenant_id"])
        return value
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise CredentialError("The saved credential state is invalid. It was not replaced.") from None


def _write(path, value):
    if path.is_symlink() or path.parent.is_symlink():
        raise CredentialError("Credential paths must not be symbolic links.")
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _active_connection(active):
    try:
        return Connection(active["origin"], active["api_key"], active["tenant_id"], active["ca_file"])
    except ValueError:
        raise CredentialError("The saved connection's trust bundle is unavailable. Restore it or log in again.") from None


def _ca_file(path):
    if not isinstance(path, str):
        raise CredentialError("The trust bundle must be a file path.")
    return str(Path(path).expanduser().absolute()) if path else ""


def _activate(value, connection, mode):
    value["active"] = {"mode": mode, "origin": connection.origin, "api_key": connection.api_key,
                       "tenant_id": connection.tenant_id, "ca_file": connection.ca_file}
    value["pending_login"] = None


def _result(connection, mode, verified):
    result = {"authenticated": True, "mode": mode, "base_url": connection.origin,
              "tenant_id": connection.tenant_id}
    if mode == "free":
        result["free"] = verified.model_dump(mode="json")
    else:
        result["capabilities"] = {name: verified.capabilities[name] for name in CAPABILITIES}
    return result


async def _verify(connection, mode, transport):
    client = IntelligenceClient.from_connection(connection, transport=transport)
    try:
        if mode == "free":
            return await free_tier.status(client)
        value = Capabilities.model_validate(await client.request("/v1/capabilities", None, _LIMIT, 10, method="GET"))
        if value.tenant_id != connection.tenant_id:
            raise CredentialError("Tenant differs")
        return value
    finally:
        await client.aclose()


def enroll_free(path, *, base_url=ORIGIN, ca_file="", transport=None):
    ca_file = _ca_file(ca_file)
    with _locked(path) as path:
        value = _read(path)
        identity = value["free"]
        if identity is None:
            identity = {"origin": base_url, "installation_id": str(uuid4()), "device_id": str(uuid4()),
                        "secret": secrets.token_urlsafe(32)}
            connection = _free_connection(identity, ca_file)
            value["free"] = identity
            _write(path, value)
        else:
            if identity["origin"] != base_url:
                raise CredentialError("The saved free identity belongs to another service. Use a separate --config.")
            connection = _free_connection(identity, ca_file)

        async def enroll():
            verified = await free_tier.enroll(connection.origin, identity["installation_id"], identity["device_id"],
                                              identity["secret"], ca_file=ca_file, transport=transport)
            if verified.tenant_id != connection.tenant_id:
                raise CredentialError("Tenant differs")
            return await _verify(connection, "free", transport)

        try:
            verified = asyncio.run(enroll())
        except (Unavailable, httpx.HTTPError, TimeoutError, ValueError, RecursionError):
            raise CredentialError("Could not verify free enrollment. Retry to recover the same account.") from None
        _activate(value, connection, "free")
        _write(path, value)
        return _result(connection, "free", verified)


async def _discover(connection, transport):
    async with asyncio.timeout(10):
        async with httpx.AsyncClient(verify=connection.verify(), transport=transport, trust_env=False,
                                    follow_redirects=False, timeout=10) as client:
            async with client.stream("GET", connection.origin + "/v1/capabilities",
                                     headers={"Authorization": "Bearer " + connection.api_key,
                                              "Accept-Encoding": "identity"}) as response:
                if (response.status_code not in (200, 401)
                        or response.headers.get("content-encoding", "identity") != "identity"):
                    raise Unavailable("API key verification unavailable")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > _LIMIT:
                        raise Unavailable("API key verification unavailable")
                value = json.loads(body)
                if response.status_code == 401:
                    if value == {"error": "tenant_assignment_required"}:
                        return None
                    raise Unavailable("API key rejected")
                return Capabilities.model_validate(value)


def login(path, api_key, *, base_url=ORIGIN, ca_file="", transport=None):
    if not isinstance(api_key, str) or not TOKEN.fullmatch(api_key.strip()):
        raise CredentialError("Enter a valid OpenSecura API key.")
    key = api_key.strip()
    ca_file = _ca_file(ca_file)
    connection = Connection(base_url, key, str(UUID(int=0)), ca_file)
    with _locked(path) as path:
        value = _read(path)
        try:
            verified = asyncio.run(_discover(connection, transport))
            if verified is None:
                pending = value["pending_login"]
                if pending is None or (pending["origin"], pending["key_id"]) != (base_url, key[5:37]):
                    pending = {"origin": base_url, "key_id": key[5:37], "tenant_id": str(uuid4())}
                    value["pending_login"] = pending
                    _write(path, value)
                connection = Connection(base_url, key, pending["tenant_id"], ca_file)
                verified = asyncio.run(_verify(connection, "api_key", transport))
            else:
                connection = Connection(base_url, key, verified.tenant_id, ca_file)
        except (Unavailable, httpx.HTTPError, TimeoutError, ValueError, RecursionError):
            raise CredentialError("Could not verify the API key. Check the key and connection, then retry.") from None
        _activate(value, connection, "api_key")
        _write(path, value)
        return _result(connection, "api_key", verified)


def load_connection(path) -> Connection:
    with _locked(path) as path:
        active = _read(path)["active"]
        if active is None:
            raise CredentialError("No active credentials. Run aidr enroll --free or aidr login first.")
        return _active_connection(active)


def status(path, *, transport=None):
    with _locked(path) as path:
        value = _read(path)
        active = value["active"]
        if active is None:
            return {"authenticated": False, "free_identity_retained": value["free"] is not None}
        connection = _active_connection(active)
        try:
            verified = asyncio.run(_verify(connection, active["mode"], transport))
        except (Unavailable, httpx.HTTPError, TimeoutError, ValueError, RecursionError):
            raise CredentialError("Could not verify the saved connection. Credentials were not changed.") from None
        return _result(connection, active["mode"], verified)


def logout(path):
    with _locked(path) as path:
        value = _read(path)
        if value["active"] is not None:
            value["active"] = None
            _write(path, value)
        return {"authenticated": False, "free_identity_retained": value["free"] is not None}
