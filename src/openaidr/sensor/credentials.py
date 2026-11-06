"""Opt-in device enrollment and credential rotation with durable retry state."""

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import stat
from uuid import UUID, uuid4
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import Config, configuration_lock
from openaidr.core.files import atomic_write, durable_directory, sync_directory
from openaidr.core.enrollment import validate_server_url
from .tls import same_origin, validate_ca_certificate


def identifier(value, name):
    try:
        return str(UUID(value))
    except (TypeError, ValueError, AttributeError):
        raise ValueError(name + " must be a trusted UUID") from None


def origin(value):
    value = validate_server_url(value)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or "?" in value
        or "#" in value
        or any(c.isspace() or ord(c) <= 32 or ord(c) == 127 for c in value)
    ):
        raise ValueError("device certificates require a canonical HTTPS origin")
    return value


def instant(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("certificate timestamps must have a timezone")
    return result


def copy_config(target, source):
    if target is source:
        return
    target.clear()
    target.update(source)
    target._saved_identity = source._saved_identity


# Owner and only access entry: the current user, inherited by everything created
# inside, with inheritance from the parent removed. Read back and verified,
# following the ADR Windows state directories.
WINDOWS_PRIVATE_DIRECTORY = r"""
trap { [Console]::Error.Write("$($_.Exception.GetType().Name): $($_.Exception.Message)"); exit 5 }
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sections = [System.Security.AccessControl.AccessControlSections]'Owner, Access'
$item = [System.IO.DirectoryInfo]::new($path)
if (-not $item.Exists -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { exit 3 }
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
# Owner and access rules only. The default, all sections, also writes the
# audit list, which needs SeSecurityPrivilege that standard users lack.
$acl.SetSecurityDescriptorSddlForm("O:${sid}D:P(A;OICI;FA;;;${sid})", $sections)
[System.IO.Directory]::SetAccessControl($item.FullName, $acl)
$verified = [System.IO.Directory]::GetAccessControl($item.FullName)
$rules = @($verified.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
$owner = $verified.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($owner -ne $sid -or
    -not $verified.AreAccessRulesProtected -or $rules.Count -ne 1 -or
    $rules[0].IdentityReference.Value -ne $sid -or $rules[0].IsInherited -or
    $rules[0].AccessControlType -ne 'Allow' -or $rules[0].FileSystemRights -ne 'FullControl') {
  # Identifies the mismatch without names: SIDs, flags, and rights only.
  $found = @($rules | ForEach-Object { "$($_.IdentityReference.Value) $($_.AccessControlType) $($_.FileSystemRights) inherited=$($_.IsInherited)" })
  [Console]::Out.Write("owner=$owner user=$sid protected=$($verified.AreAccessRulesProtected) rules=[$($found -join '; ')]")
  exit 4
}
"""


def restrict_windows_directory(path):
    """Limit a credential directory to the current Windows user, then verify it."""
    from .windows_task import TaskError, _literal, _powershell

    try:
        result = _powershell(
            f"$path = {_literal(path)}\n" + WINDOWS_PRIVATE_DIRECTORY, check=False
        )
    except TaskError as exc:
        raise ValueError("cannot restrict the credential directory: " + str(exc)) from None
    if result.returncode == 3:
        raise ValueError("credential directory must not be a link")
    if result.returncode == 4:
        raise ValueError(
            "credential directory must be private and owned by the service user; found "
            + result.stdout.strip()[:1000]
        )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise ValueError(
            "cannot restrict the credential directory to the service user: "
            + (detail[-1][:1000] if detail else f"PowerShell exited with {result.returncode}")
        )


def private_directory(path):
    path = Path(path).absolute()
    if path.is_symlink():
        raise ValueError("credential directory must not be a symlink")
    durable_directory(path)
    if os.name == "nt":
        restrict_windows_directory(path)
        return path
    info = path.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_mode & 0o077
        or info.st_uid != os.getuid()
    ):
        raise ValueError(
            "credential directory must be private and owned by the service user"
        )
    return path


def key_bytes(key):
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def pending_request(config, operation, server, tenant_id, sensor_id, token, metadata):
    directory = private_directory(Path(config["data_dir"]) / "credentials")
    path = directory / "pending.json"
    reference = hashlib.sha256(token.encode()).hexdigest() if token else ""
    binding = dict(
        operation=operation,
        server_url=server,
        tenant_id=tenant_id,
        sensor_id=sensor_id,
        credential_reference=reference,
    )
    if path.exists():
        if path.is_symlink() or (os.name != "nt" and path.stat().st_mode & 0o077):
            raise ValueError("pending credential request must be private")
        with path.open("rb") as stream:
            encoded = stream.read((64 << 10) + 1)
        if len(encoded) > 64 << 10:
            raise ValueError("invalid pending credential request")
        pending = json.loads(encoded)
        request_id = identifier(pending.get("request_id"), "pending request_id")
        if pending.get("body", {}).get("request_id") != request_id:
            raise ValueError("invalid pending credential request identity")
        installed = directory / request_id
        completed = (
            config.get("auth_mode") == "mtls"
            and config.get("credential_activation_pending") is False
            and pending.get("server_url") == config.get("server_url")
            and pending.get("tenant_id") == config.get("tenant_id")
            and config.get("client_key") == str(installed / "key.pem")
            and config.get("client_cert") == str(installed / "certificate.pem")
        )
        if completed:
            path.unlink()
            sync_directory(path.parent)
        elif all(pending.get(key) == value for key, value in binding.items()):
            return path, pending
        elif operation != "recover":
            raise ValueError(
                "another credential request is pending; retry its original operation or use explicit recovery"
            )
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenAIDR device")])
        )
        .sign(key, hashes.SHA256())
    )
    request_id = str(uuid4())
    body = dict(
        metadata,
        tenant_id=tenant_id,
        request_id=request_id,
        csr=csr.public_bytes(serialization.Encoding.PEM).decode(),
    )
    if sensor_id:
        body["sensor_id"] = sensor_id
    pending = dict(
        binding,
        request_id=request_id,
        body=body,
        private_key=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )
    atomic_write(path, json.dumps(pending))
    return path, pending


def validate_response(response, pending, generation):
    try:
        tenant_id = identifier(response["tenant_id"], "tenant_id")
        sensor_id = identifier(response["sensor_id"], "sensor_id")
        if (
            response["auth_mode"] != "mtls"
            or tenant_id != pending["tenant_id"]
            or (pending["sensor_id"] and sensor_id != pending["sensor_id"])
            or type(response["generation"]) is not int
            or response["generation"] <= generation
            or "sensor_token" in response
        ):
            raise ValueError("certificate response identity or generation mismatch")
        chain = validate_ca_certificate(response["certificate_chain"])
        certificates = x509.load_pem_x509_certificates(chain.encode())
        if len(certificates) != 2:
            raise ValueError("expected a device leaf and its tenant issuer")
        leaf, issuer = certificates
        key = serialization.load_pem_private_key(pending["private_key"].encode(), None)
        request = x509.load_pem_x509_csr(pending["body"]["csr"].encode())
        leaf.verify_directly_issued_by(issuer)
        issuer.verify_directly_issued_by(issuer)
        uri = f"urn:openaidr:tenant:{tenant_id}:sensor:{sensor_id}"
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        instant_now = datetime.now(timezone.utc)
        if (
            not isinstance(key, ec.EllipticCurvePrivateKey)
            or not isinstance(key.curve, ec.SECP256R1)
            or key_bytes(key.public_key()) != key_bytes(leaf.public_key())
            or key_bytes(key.public_key()) != key_bytes(request.public_key())
            or not request.is_signature_valid
            or leaf.public_bytes(serialization.Encoding.PEM).decode()
            != response["certificate"]
            or leaf.fingerprint(hashes.SHA256()).hex() != response["fingerprint"]
            or leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            or not issuer.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value.ca
            or not usage.digital_signature
            or usage.key_cert_sign
            or list(
                leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            )
            != [ExtendedKeyUsageOID.CLIENT_AUTH]
            or list(
                leaf.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
            )
            != [x509.UniformResourceIdentifier(uri)]
            or issuer.subject
            != x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME, "OpenAIDR devices " + tenant_id
                    )
                ]
            )
            or not (leaf.not_valid_before_utc <= instant_now < leaf.not_valid_after_utc)
            or not (
                issuer.not_valid_before_utc <= instant_now < issuer.not_valid_after_utc
            )
            or instant(response["expires_at"]) != leaf.not_valid_after_utc
            or instant(response["renew_after"])
            != leaf.not_valid_after_utc - timedelta(hours=48)
        ):
            raise ValueError("invalid device certificate identity, key or validity")
        return chain
    except (
        KeyError,
        TypeError,
        AttributeError,
        InvalidSignature,
        x509.ExtensionNotFound,
    ) as exc:
        raise ValueError("invalid device credential response") from exc


def activate(config, version="dev"):
    from .runtime import Client

    client = Client.from_config(config, version)
    try:
        request = dict(
            tenant_id=config["tenant_id"],
            sensor_id=config["sensor_id"],
            generation=config["credential_generation"],
        )
        result = client.post("credentials/activate", request)
    finally:
        client.close()
    leaf = x509.load_pem_x509_certificate(Path(config["client_cert"]).read_bytes())
    if (
        any(result.get(key) != value for key, value in request.items())
        or result.get("active") is not True
        or result.get("auth_mode") != "mtls"
        or result.get("fingerprint") != leaf.fingerprint(hashes.SHA256()).hex()
    ):
        raise ValueError("credential activation response identity mismatch")
    candidate = Config.load(config.path)
    candidate["credential_activation_pending"] = False
    candidate.save()
    copy_config(config, candidate)
    pending = Path(config["data_dir"]) / "credentials" / "pending.json"
    try:
        pending.unlink(missing_ok=True)
        sync_directory(pending.parent)
    except OSError:
        logging.warning(
            "credential activated; completed request cleanup will retry before the next rotation"
        )
    return result


def exchange(
    config,
    operation,
    *,
    server=None,
    tenant_id=None,
    token="",
    metadata=None,
    ca_certificate=None,
    version="dev",
):
    from .runtime import Client

    with configuration_lock(config.path):
        if config.path.exists():
            latest = Config.load(config.path)
            if operation != "enroll" and any(
                latest.get(key) != config.get(key)
                for key in ("server_url", "tenant_id", "sensor_id")
            ):
                raise ValueError("device identity changed; reload its configuration")
            config = latest
        else:
            config = Config(config.path, **copy.deepcopy(dict(config)))
        server = origin(server or config.get("server_url", ""))
        tenant_id = identifier(tenant_id or config.get("tenant_id"), "tenant_id")
        sensor_id = (
            ""
            if operation == "enroll"
            else identifier(config.get("sensor_id"), "sensor_id")
        )
        if operation != "enroll" and (
            not same_origin(server, config["server_url"])
            or tenant_id != config.get("tenant_id", tenant_id)
        ):
            raise ValueError(
                "credential operations must preserve the configured device identity"
            )
        if config.get("credential_activation_pending") and operation != "recover":
            if server != config["server_url"] or tenant_id != config["tenant_id"]:
                raise ValueError(
                    "pending activation belongs to the configured origin and tenant"
                )
            activate(config, version)
            return config, dict(
                sensor_id=config["sensor_id"],
                tenant_id=config["tenant_id"],
                auth_mode="mtls",
            )
        if operation == "enroll" and config.enrolled():
            raise ValueError(
                "already enrolled; use credential migration or recovery to preserve identity"
            )
        if operation in ("renew", "recover") and config.get("auth_mode") != "mtls":
            raise ValueError(
                "certificate renewal and recovery require an mTLS enrollment"
            )
        if operation == "migrate":
            if config.get("auth_mode", "bearer") != "bearer" or not config.enrolled():
                raise ValueError("migration requires an existing bearer enrollment")
            token = config["sensor_token"]
        if operation in ("enroll", "recover") and (
            not isinstance(token, str) or not token
        ):
            raise ValueError("a credential token is required")
        ca = validate_ca_certificate(ca_certificate) if ca_certificate else None
        trust = (
            config.get("ca_cert")
            if same_origin(config.get("server_url", ""), server)
            else None
        )
        path, pending = pending_request(
            config, operation, server, tenant_id, sensor_id, token, metadata or {}
        )
        body = dict(pending["body"])
        if operation in ("enroll", "recover"):
            body["enrollment_token" if operation == "enroll" else "recovery_token"] = (
                token
            )
        client = (
            Client.from_config(config, version)
            if operation == "renew"
            else Client(
                server,
                token=token if operation == "migrate" else "",
                version=version,
                ca_cert=trust,
                ca_certificate=ca,
            )
        )
        try:
            result = client.post(
                "enroll" if operation == "enroll" else "credentials/" + operation, body
            )
        finally:
            client.close()
        chain = validate_response(
            result, pending, config.get("credential_generation", 0)
        )
        directory = private_directory(path.parent / pending["request_id"])
        key_path, cert_path = directory / "key.pem", directory / "certificate.pem"
        atomic_write(key_path, pending["private_key"])
        atomic_write(cert_path, chain)
        candidate = (
            Config.load(config.path)
            if config.path.exists()
            else Config(config.path, **dict(config))
        )
        candidate.update(
            server_url=server,
            auth_mode="mtls",
            tenant_id=tenant_id,
            sensor_id=result["sensor_id"],
            client_key=str(key_path),
            client_cert=str(cert_path),
            credential_generation=result["generation"],
            credential_expires_at=result["expires_at"],
            credential_renew_after=result["renew_after"],
            credential_activation_pending=True,
        )
        candidate.pop("sensor_token", None)
        candidate.pop("connection_mode", None)
        if ca:
            trust_path = directory / "server-ca.pem"
            atomic_write(trust_path, ca)
            candidate["ca_cert"] = str(trust_path)
        elif trust:
            candidate["ca_cert"] = trust
        else:
            candidate.pop("ca_cert", None)
        if operation == "enroll":
            for name in ("host_kind", "label"):
                if name in (metadata or {}):
                    candidate[name] = metadata[name]
        candidate.validate()
        # Loading the installed pair verifies file readability and key matching
        # before the atomic config replacement retires local bearer use.
        proof = Client.from_config(candidate, version)
        proof.close()
        candidate.save()
        activate(candidate, version)
        return candidate, result


def enroll(
    config, server, token, tenant_id, metadata, *, ca_certificate=None, version="dev"
):
    candidate, result = exchange(
        config,
        "enroll",
        server=server,
        tenant_id=tenant_id,
        token=token,
        metadata=metadata,
        ca_certificate=ca_certificate,
        version=version,
    )
    copy_config(config, candidate)
    return result


def operate(config, operation, *, token="", tenant_id=None, version="dev"):
    if operation not in ("migrate", "renew", "recover"):
        raise ValueError("unknown credential operation")
    candidate, result = exchange(
        config, operation, token=token, tenant_id=tenant_id, version=version
    )
    copy_config(config, candidate)
    return result


def maintain(config, version="dev"):
    """Resume durable activation or renew near expiry without changing device IDs."""
    with configuration_lock(config.path):
        latest = Config.load(config.path) if config.path.exists() else config
        if any(
            latest.get(key) != config.get(key)
            for key in ("server_url", "tenant_id", "sensor_id", "auth_mode")
        ):
            raise ValueError(
                "running sensor identity changed; restart with the intended configuration"
            )
        changed = latest.get("credential_generation") != config.get(
            "credential_generation"
        )
        copy_config(config, latest)
        if config.get("credential_activation_pending"):
            activate(config, version)
            return True
        if config.get("credential_renew_after") and instant(
            config["credential_renew_after"]
        ) <= datetime.now(timezone.utc):
            operate(config, "renew", version=version)
            return True
        return changed
