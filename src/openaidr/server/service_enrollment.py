"""Customer free enrollment preserves identity and binds only verified credentials."""

import asyncio
from dataclasses import dataclass, field, replace
import time
from uuid import NAMESPACE_URL, UUID, uuid5

import anyio
import httpx
from openaidr_api_client.client import Connection, IntelligenceClient, Unavailable

from openaidr.core.cloud_protection import project


def contracts():
    try:
        from openaidr_api_client import free_tier
    except ImportError:
        raise Unavailable("Customer enrollment SDK is unavailable") from None
    return free_tier


def prepare(cfg):
    """Capture persisted identity without binding a credential or changing cfg."""
    if not cfg.free_installation_id:
        return None
    installation, device = str(UUID(cfg.free_installation_id)), str(UUID(cfg.free_device_id))
    service = contracts()
    credential = service.credential(installation, cfg.free_secret)
    retained = f"oati_{UUID(installation).hex}.{cfg.free_secret}"
    if cfg.intelligence_api_key and cfg.intelligence_api_key not in (credential, retained):
        return None  # An explicit paid connection takes precedence.
    tenant = str(uuid5(NAMESPACE_URL, "https://api.opensecura.ai/free/" + UUID(installation).hex))
    if cfg.tenant_id and cfg.tenant_id != tenant:
        raise ValueError("Free installation does not match this workspace")
    connection = Connection(cfg.free_origin, credential, tenant, cfg.intelligence_ca_file)
    return Enrollment(installation, device, cfg.free_secret, connection)


def pending_config(cfg, enrollment):
    return replace(cfg, tenant_id=enrollment.connection.tenant_id, intelligence_origin="", intelligence_api_key="",
        intelligence_ca_file="", free_status=project(dict(state="connecting", checked_at=None)), free_failure="")


def status(cfg):
    return project(cfg.free_status) if prepare(cfg) is not None else None


@dataclass(frozen=True)
class Enrollment:
    installation_id: str
    device_id: str
    secret: str = field(repr=False)
    connection: Connection = field(repr=False)

    async def run_configured(self, cfg, stop):
        def current():
            candidate = prepare(cfg)
            return (candidate is not None and candidate.installation_id == self.installation_id
                and candidate.device_id == self.device_id and candidate.secret == self.secret
                and candidate.connection.origin == self.connection.origin
                and cfg.tenant_id == self.connection.tenant_id
                and cfg.intelligence_ca_file in ("", self.connection.ca_file))

        async def verified(connection):
            if not current():
                raise ValueError("Free configuration changed during enrollment")
            cfg.intelligence_origin, cfg.intelligence_api_key = connection.origin, connection.api_key
            cfg.intelligence_ca_file = connection.ca_file

        async def updated(value):
            if current():
                cfg.free_status = value

        await self.run(stop, on_verified=verified, on_status=updated)

    async def run(self, stop, *, on_verified, on_status, transport=None):
        """Prove identity before binding; retry failed initialization, never identity."""
        service = contracts()
        client = IntelligenceClient.from_connection(self.connection, transport=transport)
        enrolled, connected = False, False
        try:
            if not stop.is_set():
                await on_status(project(dict(state="connecting", checked_at=None)))
            while not stop.is_set():
                try:
                    if not enrolled:
                        value = await service.enroll(self.connection.origin, self.installation_id,
                            self.device_id, self.secret, ca_file=self.connection.ca_file, transport=transport)
                        if value.tenant_id != self.connection.tenant_id:
                            raise ValueError("Free enrollment tenant mismatch")
                        enrolled = True
                    if stop.is_set():
                        break
                    value = await service.status(client)
                    if stop.is_set():
                        break
                    if not connected:
                        try:
                            await on_verified(self.connection)
                        except Exception:
                            raise Unavailable("Free service initialization unavailable") from None
                        connected = True
                    if stop.is_set():
                        break
                    status = dict(schema_version=1, state="active" if value.status == "available" else value.status,
                        checked_at=time.time(), guardrail_available=value.guardrail_available,
                        guardrail_configured=value.guardrail_configured, credit_status=value.credit_status,
                        credits_per_usd=value.credits_per_usd, reset_at=value.reset_at)
                except Unavailable as error:
                    if error.status_code == 401:
                        enrolled = False
                    status = dict(state="unavailable", checked_at=time.time())
                except (httpx.HTTPError, TimeoutError, ValueError, KeyError, OSError):
                    status = dict(state="unavailable", checked_at=time.time())
                if stop.is_set():
                    break
                await on_status(project(status))
                try:
                    await asyncio.wait_for(stop.wait(), timeout=30)
                except TimeoutError:
                    pass
        finally:
            with anyio.CancelScope(shield=True):
                await client.aclose()
