"""Verify a manually supplied hosted service key before publishing its connection."""

import asyncio
import json
from uuid import uuid4

import httpx
from openaidr_api_client.client import Connection, TOKEN, Unavailable
from openaidr_api_client.contracts.capabilities import Capabilities

from .config import IDENTITY_FIELDS, Config, configuration_lock
from .free_enrollment import ORIGIN


def connection(config):
    if config.get("connection_mode") != "api_key" or config.get("server_url") != ORIGIN:
        raise ValueError("Invalid API key connection")
    return Connection(ORIGIN, config["sensor_token"], config["tenant_id"])


def status(client):
    try:
        value = Capabilities.model_validate(client.request("/v1/capabilities", None, 16 << 10, 10, method="GET"))
        if value.tenant_id != client.tenant_id:
            raise ValueError("Tenant differs")
        return value
    except ValueError:
        raise Unavailable("API key connection could not be verified") from None


async def verify(api_key, transport, tenant=None):
    # Discovery precedes tenant binding. Never follow redirects or use proxy environment variables.
    async with asyncio.timeout(10):
        async with httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False, timeout=10) as client:
            async with client.stream("GET", ORIGIN + "/v1/capabilities",
                    headers={"Authorization": "Bearer " + api_key, "Accept-Encoding": "identity"}) as response:
                if response.status_code == 403:
                    raise Unavailable("API key was rejected", status_code=response.status_code)
                if response.status_code not in (200, 401) or response.headers.get("content-encoding", "identity") != "identity":
                    raise Unavailable("API key verification unavailable")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 16 << 10:
                        raise ValueError("Response exceeds limit")
                if response.status_code == 401:
                    try:
                        assignment = json.loads(body) == {"error": "tenant_assignment_required"}
                    except (ValueError, RecursionError):
                        assignment = False
                    if assignment:
                        from openaidr.core.service_keys import claim
                        return await claim(Connection(ORIGIN, api_key, tenant or str(uuid4())), transport=transport)
                    raise Unavailable("API key was rejected", status_code=401)
    return Capabilities.model_validate(json.loads(body))


def activate(config, api_key, *, transport=None):
    if not isinstance(api_key, str) or not TOKEN.fullmatch(api_key.strip()):
        raise ValueError("Enter a valid OpenSecura API key.")
    api_key = api_key.strip()
    with configuration_lock(config.path):
        config = Config.load(config.path)
        if config.enrolled() and (config.get("connection_mode") != "api_key" or config.get("sensor_token") != api_key):
            raise ValueError("This device is already connected. Keep its existing connection.")
        try:
            verified = asyncio.run(verify(api_key, transport, config.get("tenant_id") if config.enrolled() else None))
            bound = Connection(ORIGIN, api_key, verified.tenant_id)
            if config.enrolled() and connection(config) != bound:
                raise ValueError("API key tenant changed")
        except Unavailable as exc:
            if exc.status_code in (401, 403):
                raise ValueError("The API key was rejected. Check the key and try again.") from None
            raise ValueError("Could not verify the API key. Check your connection and try again.") from None
        except (httpx.HTTPError, TimeoutError, ValueError, RecursionError):
            raise ValueError("Could not verify the API key. Check your connection and try again.") from None
        if not config.enrolled():
            candidate = Config(config.path, **{key: value for key, value in config.items() if key not in IDENTITY_FIELDS})
            candidate.update(connection_mode="api_key", auth_mode="bearer", server_url=bound.origin,
                             sensor_id=str(uuid4()), sensor_token=bound.api_key, tenant_id=bound.tenant_id)
            candidate.validate()
            candidate.save()
            config = candidate
        return {"enrolled": True, "sensor_id": config["sensor_id"], "connection_mode": "api_key"}
