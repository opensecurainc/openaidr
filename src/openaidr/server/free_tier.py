"""Local enrollment and content-free status for the hosted free allowance."""

import asyncio
from datetime import datetime, timezone
import re
import time
from uuid import UUID, uuid5, NAMESPACE_URL

import httpx

from openaidr.core.cloud_protection import project
from openaidr_api_client.client import Connection, IntelligenceClient, Unavailable


def configure(cfg):
    if not cfg.free_installation_id:
        return
    installation = UUID(cfg.free_installation_id).hex
    UUID(cfg.free_device_id)
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", cfg.free_secret):
        raise ValueError("Invalid free installation secret")
    tenant = str(uuid5(NAMESPACE_URL, "https://api.opensecura.ai/free/" + installation))
    if cfg.intelligence_api_key and cfg.intelligence_api_key != f"oati_{installation}.{cfg.free_secret}":
        # An explicit paid connection takes precedence over free enrollment.
        return
    if cfg.tenant_id and cfg.tenant_id != tenant:
        raise ValueError("Free installation does not match this workspace; preserve its existing credentials")
    cfg.tenant_id = tenant
    cfg.intelligence_origin = cfg.free_origin
    cfg.intelligence_api_key = f"oati_{installation}.{cfg.free_secret}"
    Connection.from_config(cfg)  # Exact HTTPS origin and existing trust checks.
    cfg.free_status = dict(state="connecting", checked_at=None)


def active(cfg):
    return matches_installation(cfg) and cfg.intelligence_api_key.startswith("oati_")


def matches_installation(cfg):
    if not getattr(cfg, "free_installation_id", ""):
        return False
    identity = f"{UUID(cfg.free_installation_id).hex}.{cfg.free_secret}"
    return cfg.intelligence_api_key in ("oati_" + identity, "oasc_" + identity)


def failed(cfg, error):
    if not active(cfg):
        return
    cause, exhausted = error, False
    for _ in range(5):
        if cause is None:
            break
        exhausted |= getattr(cause, "status_code", None) == 402
        cause = cause.__context__
    cfg.free_failure = "exhausted" if exhausted else "unavailable"
    cfg.free_status = {**cfg.free_status, "state": cfg.free_failure}


def succeeded(cfg):
    if active(cfg):
        cfg.free_failure = ""
        if cfg.free_status.get("guardrail_available"):
            cfg.free_status = {**cfg.free_status, "state": "active"}


def status(cfg):
    if not active(cfg):
        return None
    return project(cfg.free_status)


def validate(value, tenant):
    if not isinstance(value, dict) or value.get("tenant_id") != tenant or value.get("plan") != "free":
        raise ValueError("Invalid free allowance response")
    keys = ("allowance_nanos", "spent_nanos", "reserved_nanos", "remaining_nanos")
    if any(type(value.get(key)) is not int or not 0 <= value[key] <= 10**15 for key in keys):
        raise ValueError("Invalid free allowance amounts")
    if any(type(value.get(key)) is not bool for key in ("guardrail_available", "guardrail_configured")):
        raise ValueError("Invalid guardrail availability")
    if not isinstance(value.get("resets_at"), str):
        raise ValueError("Invalid free allowance reset")
    reset = datetime.fromisoformat(value["resets_at"])
    if reset.tzinfo is None:
        raise ValueError("Invalid free allowance reset")
    return {**{key: value[key] for key in keys}, "resets_at": reset.astimezone(timezone.utc).isoformat(),
            "guardrail_available": value["guardrail_available"], "guardrail_configured": value["guardrail_configured"]}


async def run(cfg, stop, *, transport=None):
    """Enrollment is idempotent. Retry status in the background, never in hooks."""
    connection = Connection.from_config(cfg)
    client = IntelligenceClient.from_connection(connection, transport=transport)
    enrolled = False
    try:
        while not stop.is_set():
            try:
                if not enrolled:
                    value = await client.request("/v1/free/enroll", {
                        "installation_id": cfg.free_installation_id, "device_id": cfg.free_device_id,
                        "secret": cfg.free_secret}, 4096, 10)
                    validate(value, connection.tenant_id)
                    enrolled = True
                value = validate(await client.request("/v1/free/status", None, 4096, 10, method="GET"), connection.tenant_id)
                if (value["guardrail_available"] and cfg.free_failure == "exhausted"
                        and (value["resets_at"] != cfg.free_status.get("resets_at")
                             or value["remaining_nanos"] > cfg.free_status.get("remaining_nanos", 0))):
                    cfg.free_failure = ""
                state = (cfg.free_failure or "active") if value["guardrail_available"] else "exhausted"
                if not value["guardrail_configured"]:
                    state = "unavailable"
                cfg.free_status = {**value, "checked_at": time.time(), "state": state}
            except Unavailable as error:
                if error.status_code == 401:
                    enrolled = False
                cfg.free_status = {**cfg.free_status, "state": "unavailable", "checked_at": time.time()}
            except (httpx.HTTPError, TimeoutError, ValueError, KeyError, OSError):
                cfg.free_status = {**cfg.free_status, "state": "unavailable", "checked_at": time.time()}
            try:
                await asyncio.wait_for(stop.wait(), timeout=30)
            except TimeoutError:
                pass
    finally:
        await client.aclose()
