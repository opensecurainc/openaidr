"""Claim a hosted service key before the pinned SDK uses its tenant binding."""

import asyncio
import json

import httpx
from openaidr_api_client.client import Unavailable
from openaidr_api_client.contracts.capabilities import Capabilities


async def claim(connection, previous=None, *, transport=None):
    if previous is not None and (previous.origin, previous.tenant_id) != (connection.origin, connection.tenant_id):
        raise ValueError("Key ownership proof must use the same service and tenant")
    headers = {"Authorization": "Bearer " + connection.api_key, "Accept-Encoding": "identity",
               "X-OpenSecura-Tenant-ID": connection.tenant_id}
    async with asyncio.timeout(10):
        async with httpx.AsyncClient(base_url=connection.origin, verify=connection.verify(), transport=transport,
                trust_env=False, follow_redirects=False, timeout=10) as client:
            async def request(path, *, proof=False):
                options = {"headers": {**headers, "Authorization": "Bearer " + previous.api_key},
                           "json": {"api_key": connection.api_key}} if proof else {"headers": headers}
                async with client.stream("POST" if proof else "GET", path, **options) as response:
                    if response.status_code != 200:
                        raise Unavailable("API key claim was rejected", status_code=response.status_code)
                    if response.headers.get("content-encoding", "identity") != "identity":
                        raise Unavailable("API key claim response is invalid")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > 16 << 10:
                            raise Unavailable("API key claim response exceeds limit")
                return json.loads(body)

            try:
                result = await request("/v1/capabilities")
            except Unavailable as error:
                if error.status_code not in (401, 403) or previous is None or previous.api_key == connection.api_key:
                    raise
                bound = await request("/v1/keys/claim", proof=True)
                if bound != {"tenant_id": connection.tenant_id, "key_id": connection.api_key[5:37]}:
                    raise Unavailable("API key claim response is invalid")
                result = await request("/v1/capabilities")
            value = Capabilities.model_validate(result)
            if value.tenant_id != connection.tenant_id:
                raise Unavailable("API key claim returned a different tenant")
            return value
