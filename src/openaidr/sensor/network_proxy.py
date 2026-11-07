"""Manually configured HTTP(S) proxy for sensor traffic to the backend.

The ``network.proxy`` block in ``sensor.yaml`` holds only non-secret settings:

    network:
      proxy:
        mode: manual            # or direct
        url: http://proxy.example.com:3128
        bypass: [internal.example.com, "*.corp.example.com"]
        username: svc-openaidr  # optional; the password is in the OS credential store
        revision: 3             # changes on every save so pooled clients are rebuilt

Without the block, clients keep their historical behavior and honor the
HTTP(S)_PROXY/NO_PROXY environment. With it, the environment is ignored.
Loopback destinations never use the proxy. TLS to the destination is still
negotiated end to end through CONNECT, so server identity checks are unchanged.
"""

import ipaddress
import logging
import re
import time
from urllib.parse import quote, urlsplit

import httpx

from . import proxy_credentials

MODES = ("direct", "manual")
MAX_URL_LENGTH = 2048
MAX_BYPASS = 64
LOOPBACK = ("localhost", "127.0.0.1", "[::1]")
_HOST = re.compile(r"^(?:\*\.|\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
                   r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def validate_url(value):
    """Return the normalized proxy URL or raise ``ValueError`` with a user-facing message."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter a proxy URL.")
    value = value.strip()
    if len(value) > MAX_URL_LENGTH:
        raise ValueError("The proxy URL is too long.")
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError:
        raise ValueError("Enter a URL such as http://proxy.example.com:8080.") from None
    if url.scheme not in ("http", "https"):
        raise ValueError("Use an http:// or https:// proxy URL.")
    if url.username is not None or url.password is not None or "@" in url.netloc:
        raise ValueError("Enter the user name and password separately, not in the URL.")
    if not url.hostname:
        raise ValueError("Enter the proxy host name.")
    if url.path not in ("", "/") or url.query or url.fragment:
        raise ValueError("Remove the path from the proxy URL.")
    host = url.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"{url.scheme}://{host}" + (f":{port}" if port else "")


def validate_bypass(values):
    """Return normalized bypass entries: host names, ``*.domain``/``.domain`` or IP addresses."""
    if values is None:
        return []
    if isinstance(values, str):
        values = re.split(r"[\s,;]+", values)
    if not isinstance(values, (list, tuple)):
        raise ValueError("The bypass list must be a list of hosts.")
    entries = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError("The bypass list must be a list of hosts.")
        entry = value.strip().lower()
        if not entry:
            continue
        literal = entry[1:-1] if entry.startswith("[") and entry.endswith("]") else entry
        try:
            entry = str(ipaddress.ip_address(literal))
        except ValueError:
            if not _HOST.match(entry):
                raise ValueError(f"“{value.strip()}” is not a host name, domain, or IP address.") from None
            if entry.startswith("."):
                entry = "*" + entry
        if entry not in entries:
            entries.append(entry)
    if len(entries) > MAX_BYPASS:
        raise ValueError(f"Enter up to {MAX_BYPASS} bypass entries.")
    return entries


def validate(settings):
    """Validate a ``network.proxy`` mapping and return its normalized form."""
    if not isinstance(settings, dict):
        raise ValueError("network.proxy must be a mapping")
    mode = settings.get("mode")
    if mode not in MODES:
        raise ValueError("network.proxy.mode must be direct or manual")
    revision = settings.get("revision", 0)
    if type(revision) is not int or revision < 0:
        raise ValueError("network.proxy.revision must be a non-negative integer")
    if mode == "direct":
        return {"mode": "direct", "revision": revision}
    username = settings.get("username") or ""
    if not isinstance(username, str) or len(username) > 256 or any(ord(c) < 32 for c in username):
        raise ValueError("Enter a valid proxy user name.")
    normalized = {"mode": "manual", "url": validate_url(settings.get("url")),
                  "bypass": validate_bypass(settings.get("bypass")), "revision": revision}
    if username.strip():
        normalized["username"] = username.strip()
    return normalized


def configured(config):
    """The validated proxy settings, or ``None`` when the config has no proxy block."""
    network = config.get("network")
    if network is None or (isinstance(network, dict) and network.get("proxy") is None):
        return None
    if not isinstance(network, dict):
        raise ValueError("network must be a mapping")
    return validate(network["proxy"])


def account(settings):
    """Credential-store account for this proxy: the user and the proxy endpoint."""
    url = urlsplit(settings["url"])
    port = url.port or (443 if url.scheme == "https" else 80)
    return f"{settings['username']}@{url.hostname}:{port}"


def _direct_patterns(bypass):
    patterns = []
    for host in (*LOOPBACK, *bypass):
        if host.startswith("*."):
            patterns += [f"all://{host[2:]}", f"all://{host}"]
        else:
            try:
                if ipaddress.ip_address(host).version == 6:
                    host = f"[{host}]"
            except ValueError:
                pass
            patterns.append(f"all://{host}")
    return patterns


def bypasses(settings, url):
    """Whether ``url`` connects directly under these settings."""
    if settings is None or settings["mode"] == "direct":
        return True
    # Same rules as the client mounts from _direct_patterns: exact hosts, and
    # "*.domain" for the domain and its subdomains.
    host = (urlsplit(url).hostname or "").lower()
    for entry in (*LOOPBACK, *settings["bypass"]):
        entry = entry.strip("[]")
        if entry.startswith("*."):
            if host == entry[2:] or host.endswith(entry[1:]):
                return True
        elif host == entry:
            return True
    return False


def proxy(settings, password=None):
    """An ``httpx.Proxy`` for manual settings, using ``password`` or the stored one."""
    auth = None
    if settings.get("username"):
        if password is None:
            try:
                password = proxy_credentials.get(account(settings))
            except proxy_credentials.CredentialStoreError as exc:
                # The proxy then answers 407 and the status reports it. Never
                # fall back to plain-text storage or log the credential.
                logging.warning("proxy password unavailable: %s", exc)
        if password is not None:
            auth = (settings["username"], password)
    return httpx.Proxy(settings["url"], auth=auth)


def transport_options(config, verify, *, limits=None, asynchronous=False, password=None):
    """Extra httpx client options that route a client through the configured proxy.

    Returns ``{}`` when no proxy block is configured, preserving environment
    proxy behavior. ``password`` overrides the stored one for a connection test.
    """
    settings = configured(config)
    if settings is None:
        return {}
    options = {"trust_env": False}
    if settings["mode"] == "direct":
        return options
    transport = httpx.AsyncHTTPTransport if asynchronous else httpx.HTTPTransport
    kwargs = {"proxy": proxy(settings, password), "verify": verify}
    if limits is not None:
        kwargs["limits"] = limits
    options["mounts"] = {"all://": transport(**kwargs),
                         **{pattern: None for pattern in _direct_patterns(settings["bypass"])}}
    return options


def async_transport(config, origin, verify=True):
    """A proxied transport for clients with a fixed origin that otherwise ignore
    the environment (free and API-key modes), or ``None`` to keep them direct."""
    settings = configured(config)
    if settings is None or bypasses(settings, origin):
        return None
    return httpx.AsyncHTTPTransport(proxy=proxy(settings), verify=verify)


def route(config, url):
    """The proxy URL, with percent-encoded Basic credentials, that a separate
    process (the desktop updater) should use for ``url``; ``None`` for direct."""
    settings = configured(config)
    if settings is None or bypasses(settings, url):
        return None
    password = None
    if settings.get("username"):
        try:
            password = proxy_credentials.get(account(settings))
        except proxy_credentials.CredentialStoreError as exc:
            logging.warning("proxy password unavailable: %s", exc)
    if password is None:
        return settings["url"]
    scheme, rest = settings["url"].split("://", 1)
    return f"{scheme}://{quote(settings['username'], safe='')}:{quote(password, safe='')}@{rest}"


def public_status(config, *, check_password=True):
    """Settings for status displays. Never includes the password; reading the
    credential store to report ``password_saved`` is optional because status is
    polled frequently."""
    try:
        settings = configured(config)
    except ValueError as exc:
        return {"mode": "invalid", "error": str(exc)}
    if settings is None:
        return {"mode": "default"}
    status = {key: value for key, value in settings.items() if key != "revision"}
    if settings.get("username") and check_password:
        try:
            status["password_saved"] = proxy_credentials.get(account(settings)) is not None
        except proxy_credentials.CredentialStoreError:
            status["password_saved"] = False
    return status


def describe_error(exc):
    """A short, credential-free explanation of a proxied connection failure."""
    text = str(exc)
    if isinstance(exc, httpx.ProxyError):
        if "407" in text:
            return "proxy_auth_required", "The proxy requires a valid user name and password."
        return "proxy_refused", "The proxy refused the connection to the OpenAIDR server."
    cause = exc
    while cause is not None:
        if "CERTIFICATE_VERIFY_FAILED" in str(cause) or "certificate verify failed" in str(cause):
            return ("certificate_untrusted",
                    "The OpenAIDR server certificate is not trusted. If the proxy inspects TLS, "
                    "exempt the OpenAIDR server from inspection.")
        cause = cause.__cause__ or cause.__context__
    if isinstance(exc, httpx.TimeoutException):
        return "timeout", "The connection through the proxy timed out."
    if isinstance(exc, httpx.ConnectError):
        return "proxy_unreachable", "Could not connect to the proxy or the OpenAIDR server."
    if isinstance(exc, httpx.HTTPStatusError):
        return "server_error", f"The OpenAIDR server responded with HTTP {exc.response.status_code}."
    return "failed", "The connection test failed."


RELEASE_FEED = "https://releases.opensecura.ai/openaidr/rollout-v2.json"


def save(config, settings, password=None):
    """Validate and persist proxy settings; the password goes only to the credential store.

    A changed proxy endpoint or user name removes the previous stored password.
    Returns the normalized settings. The running service applies them on restart.
    """
    settings = validate({**settings, "revision": 0})
    previous = configured(config)
    if settings.get("username"):
        stored = password is None and proxy_credentials.get(account(settings)) is not None
        if password is None and not stored:
            raise ValueError("Enter the proxy password.")
        if password is not None:
            proxy_credentials.set(account(settings), password)
    if previous and previous.get("username") and (
            not settings.get("username") or account(previous) != account(settings)):
        try:
            proxy_credentials.delete(account(previous))
        except proxy_credentials.CredentialStoreError as exc:
            logging.warning("previous proxy password was not removed: %s", exc)
    settings["revision"] = (previous or {}).get("revision", 0) + 1
    network = dict(config.get("network") or {})
    network["proxy"] = settings
    config["network"] = network
    config.save()
    return settings


def clear(config):
    """Remove the proxy block and its stored password; clients use the environment again."""
    previous = configured(config)
    if previous and previous.get("username"):
        proxy_credentials.delete(account(previous))
    network = dict(config.get("network") or {})
    network.pop("proxy", None)
    if network:
        config["network"] = network
    else:
        config.pop("network", None)
    config.save()


def test_connection(config, settings, password=None, *, timeout=8):
    """Reach the OpenAIDR server (or the release feed before enrollment) through
    candidate settings without saving them. Any HTTP response proves the path."""
    from .tls import client_options

    settings = validate({**settings, "revision": 0})
    candidate = dict(config)
    candidate["network"] = {"proxy": settings}
    enrolled = bool(config.get("server_url")) and config.get("connection_mode") not in ("free", "api_key")
    target = config["server_url"] + "/ingest/v1/version" if enrolled else RELEASE_FEED
    if not enrolled:
        candidate.update(server_url="https://releases.opensecura.ai", auth_mode="bearer", sensor_token="")
    started = time.monotonic()
    try:
        options = client_options(candidate, proxy_password=password)
        with httpx.Client(timeout=timeout, follow_redirects=False, **options) as client:
            if enrolled:
                response = client.post(target, json={})
            else:
                response = client.head(target)
    except (httpx.HTTPError, ValueError, OSError) as exc:
        kind, message = describe_error(exc)
        return {"ok": False, "kind": kind, "message": message}
    elapsed = round((time.monotonic() - started) * 1000)
    if response.status_code >= 500:
        return {"ok": False, "kind": "server_error",
                "message": f"The server responded with HTTP {response.status_code}."}
    via = "directly" if bypasses(settings, target) else "through the proxy"
    what = "the OpenAIDR server" if enrolled else "the OpenAIDR update server"
    return {"ok": True, "kind": "reachable", "latency_ms": elapsed,
            "message": f"Reached {what} {via} in {elapsed} ms."}
