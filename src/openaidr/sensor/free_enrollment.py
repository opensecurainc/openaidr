"""Persist a free installation before proving its hosted service connection."""

import asyncio
from dataclasses import dataclass, field
import json
from pathlib import Path
import secrets
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import httpx
from openaidr_api_client import free_tier
from openaidr_api_client.client import Connection, IntelligenceClient, Unavailable

from openaidr.core.files import atomic_write
from .config import IDENTITY_FIELDS, Config, configuration_lock

ORIGIN = "https://api.opensecura.ai"


@dataclass(frozen=True)
class Enrollment:
    installation_id: str
    device_id: str
    secret: str = field(repr=False)

    def __post_init__(self):
        for name in ("installation_id", "device_id"):
            if str(UUID(getattr(self, name))) != getattr(self, name):
                raise ValueError("Invalid free installation identity")
        free_tier.credential(self.installation_id, self.secret)

    @property
    def connection(self):
        tenant = str(uuid5(NAMESPACE_URL, ORIGIN + "/free/" + UUID(self.installation_id).hex))
        return Connection(ORIGIN, free_tier.credential(self.installation_id, self.secret), tenant)

    async def verify(self, *, transport=None):
        connection = self.connection
        value = await free_tier.enroll(ORIGIN, self.installation_id, self.device_id,
                                      self.secret, transport=transport)
        if value.tenant_id != connection.tenant_id:
            raise Unavailable("Free enrollment identity could not be verified")
        client = IntelligenceClient.from_connection(connection, transport=transport)
        try:
            return await free_tier.status(client)
        finally:
            await client.aclose()


def prepare(config):
    """Load or create one identity; never replace corrupt or enrolled state."""
    if config.enrolled() and config.get("connection_mode") != "free":
        raise ValueError("This device is connected to an organization. Keep its existing connection.")
    path = Path(config["data_dir"]) / "free-enrollment.json"
    try:
        with path.open(encoding="utf-8") as stream:
            saved = stream.read(2049)
        if len(saved) > 2048:
            raise ValueError
        value = json.loads(saved)
        if not isinstance(value, dict) or set(value) != {"installation_id", "device_id", "secret"}:
            raise ValueError
        enrollment = Enrollment(**value)
    except FileNotFoundError:
        if config.get("connection_mode") == "free":
            raise ValueError("The saved free installation identity is missing. Restore it before retrying.") from None
        enrollment = Enrollment(str(uuid4()), str(uuid4()), secrets.token_urlsafe(32))
        atomic_write(path, json.dumps(dict(installation_id=enrollment.installation_id,
            device_id=enrollment.device_id, secret=enrollment.secret)))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("The saved free installation identity is invalid. It was not replaced.") from None
    if config.get("connection_mode") == "free":
        connection = enrollment.connection
        if (config.get("server_url") != connection.origin or config.get("tenant_id") != connection.tenant_id
                or config.get("sensor_id") != enrollment.device_id or config.get("sensor_token") != connection.api_key):
            raise ValueError("The saved free installation does not match this device connection.")
    return enrollment


def connect(config, *, transport=None):
    """Serialize enrollment attempts and leave sensor configuration unmodified.

    The caller must hold this same configuration lock until it publishes the
    verified connection. A lost reply can then retry the same persisted identity.
    """
    with configuration_lock(config.path):
        config = Config.load(config.path)
        enrollment = prepare(config)
        try:
            status = asyncio.run(enrollment.verify(transport=transport))
        except Unavailable as exc:
            if exc.status_code == 429:
                raise ValueError("Free setup is rate limited. Wait and try again with the same installation.") from None
            raise ValueError("Could not verify free setup. Check your connection and try again.") from None
        except (httpx.HTTPError, TimeoutError):
            raise ValueError("Could not verify free setup. Check your connection and try again.") from None
        return enrollment, status


def activate(config, *, transport=None):
    """Publish only a proved identity, atomically with respect to setup writers."""
    with configuration_lock(config.path):
        config = Config.load(config.path)
        enrollment, status = connect(config, transport=transport)
        if config.get("connection_mode") != "free":
            candidate = Config(config.path, **{key: value for key, value in config.items() if key not in IDENTITY_FIELDS})
            candidate.update(connection_mode="free", auth_mode="bearer", server_url=enrollment.connection.origin,
                             sensor_id=enrollment.device_id, sensor_token=enrollment.connection.api_key,
                             tenant_id=enrollment.connection.tenant_id)
            candidate.validate()
            candidate.save()
        # The desktop response contains neither the enrollment secret nor the credential.
        return {"enrolled": True, "sensor_id": enrollment.device_id, "connection_mode": "free"}
