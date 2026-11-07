"""Verified private-CA trust for enrolled sensors; never disables TLS checks."""

import re
import ssl
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .config import validate_device_auth
from . import network_proxy
from openaidr.core.enrollment import validate_server_url

MAX_CA_BYTES = 32 << 10
CERTIFICATE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----"
)


def validate_ca_certificate(pem):
    if not isinstance(pem, str):
        raise ValueError("CA certificate must be PEM text")
    if len(pem.encode("utf-8")) > MAX_CA_BYTES:
        raise ValueError("CA certificate must be at most 32 KiB")
    pem = pem.replace("\r\n", "\n").replace("\r", "\n")
    blocks = CERTIFICATE.findall(pem)
    if not blocks or CERTIFICATE.sub("", pem).strip():
        raise ValueError(
            "CA PEM must contain only public CERTIFICATE blocks; private keys are not accepted"
        )
    normalized = "\n".join(block.strip() for block in blocks) + "\n"
    try:
        # OpenSSL validates the encoded certificates and configures mandatory
        # chain validation and hostname/IP SAN verification.
        ssl.create_default_context(cadata=normalized)
    except (ssl.SSLError, ValueError) as exc:
        raise ValueError("CA certificate contains invalid certificate data") from exc
    return normalized


def read_ca_certificate(path):
    with Path(path).expanduser().open("rb") as stream:
        data = stream.read(MAX_CA_BYTES + 1)
    if len(data) > MAX_CA_BYTES:
        raise ValueError("CA certificate must be at most 32 KiB")
    try:
        pem = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("CA certificate must be ASCII PEM text") from exc
    return validate_ca_certificate(pem)


def verified_context(ca_cert=None, ca_certificate=None):
    if ca_certificate is not None:
        return ssl.create_default_context(
            cadata=validate_ca_certificate(ca_certificate)
        )
    if ca_cert:
        return ssl.create_default_context(cadata=read_ca_certificate(ca_cert))
    # Preserve HTTPX's normal public-root trust configuration.
    return True


def client_options(config, ca_certificate=None, *, limits=None, asynchronous=False, proxy_password=None):
    """Verified transport, exactly one device authentication method, and the
    configured proxy route (see ``network_proxy``)."""
    validate_server_url(config["server_url"])
    validate_device_auth(config)
    context = verified_context(config.get("ca_cert"), ca_certificate)
    headers = {}
    if config.get("auth_mode", "bearer") == "mtls":
        if context is True:
            # Keep HTTPX's public roots and SSL_CERT_FILE/SSL_CERT_DIR behavior.
            context = httpx.create_ssl_context()
        try:
            context.load_cert_chain(
                str(Path(config["client_cert"]).expanduser()),
                str(Path(config["client_key"]).expanduser()),
                password="",  # Services must never prompt for a key passphrase.
            )
        except (OSError, ValueError) as exc:
            raise ValueError("cannot load mTLS client certificate and key") from exc
    elif config.get("sensor_token"):
        headers["Authorization"] = "Bearer " + config["sensor_token"]
    options = {"verify": context, "headers": headers}
    options.update(network_proxy.transport_options(
        config, context, limits=limits, asynchronous=asynchronous, password=proxy_password))
    return options


def same_origin(first, second):
    def key(value):
        url = urlsplit(value)
        return (
            url.scheme.lower(),
            (url.hostname or "").lower(),
            url.port or (443 if url.scheme.lower() == "https" else 80),
        )

    return key(first) == key(second)
