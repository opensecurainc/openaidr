"""Enrollment link format shared by the server and desktop sensor."""

import ipaddress
import re
from urllib.parse import parse_qs, urlsplit

TOKEN = re.compile(r"oaet_[A-Za-z0-9_-]{43}")


def enrollment_origin(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("Enrollment server URL is invalid")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Enrollment server URL is invalid")
    try:
        url = urlsplit(value)
        hostname = url.hostname
        _ = url.port
    except ValueError:
        raise ValueError("Enrollment server URL is invalid") from None
    if (
        url.scheme not in ("http", "https")
        or not hostname
        or url.username is not None
        or url.password is not None
        or url.path not in ("", "/")
        or "?" in value
        or "#" in value
        or any(c in url.netloc for c in "\\%")
    ):
        raise ValueError(
            "Enrollment server must be an HTTP(S) origin without credentials"
        )
    if url.scheme == "http":
        try:
            local = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            local = hostname.lower() == "localhost"
        if not local:
            raise ValueError("Enrollment links require HTTPS, except on localhost")
    return value.rstrip("/")


def make_enrollment_link(server, token):
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        raise ValueError("Invalid enrollment code")
    # URL fragments are not sent in browser HTTP requests or referrer headers.
    return enrollment_origin(server) + "/enroll#token=" + token


def parse_enrollment_link(value):
    if not isinstance(value, str) or len(value) > 8192:
        raise ValueError("Paste the enrollment link supplied by your administrator")
    value = value.strip()
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Invalid enrollment link")
    try:
        url = urlsplit(value)
        if url.path != "/enroll" or "?" in value:
            raise ValueError
        fields = parse_qs(url.fragment, strict_parsing=True, max_num_fields=1)
        token = fields["token"][0]
        if not TOKEN.fullmatch(token):
            raise ValueError
        origin = enrollment_origin(url._replace(path="", fragment="").geturl())
    except (ValueError, KeyError, IndexError):
        raise ValueError(
            "Invalid enrollment link. Use an HTTPS link from your administrator (localhost is allowed for development)."
        ) from None
    return origin, token


def validate_server_url(value):
    try:
        url = urlsplit(value)
        hostname = url.hostname
        _ = url.port
    except (TypeError, ValueError) as exc:
        raise ValueError("server URL is invalid") from exc
    if (
        url.scheme not in ("http", "https")
        or not hostname
        or url.username
        or url.password
    ):
        raise ValueError("server URL must be HTTP(S), with no embedded credentials")
    if url.path not in ("", "/") or url.query or url.fragment:
        raise ValueError(
            "server URL must be an origin without a path, query, or fragment"
        )
    if url.scheme == "http":
        try:
            loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            loopback = hostname.lower() == "localhost"
        if not loopback:
            raise ValueError(
                "HTTPS is required for remote servers; HTTP is allowed only on loopback"
            )
    return value.rstrip("/")
