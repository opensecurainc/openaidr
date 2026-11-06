"""Workspace credentials for the hosted Intelligence endpoint."""

import asyncio
import json
from dataclasses import replace

from cryptography.fernet import Fernet, InvalidToken
from openaidr_api_client.client import Connection
from openaidr_api_client.clients.threat_intel import ThreatIntelClient

from openaidr_api_client.contracts.errors import APIError


ORIGINS = ("https://api.opensecura.ai",)


def switchable(cfg, connection):
    from .free_tier import matches_installation

    return bool(connection and not connection.ca_file and not matches_installation(cfg))


def selection(st, tenant, *, conn=None):
    rows = st.many("SELECT origin,version FROM tenant_intelligence_selection WHERE tenant_id=$1", tenant, conn=conn)
    return rows[0] if rows else {"origin": None, "version": 0}


def cipher(cfg):
    try:
        return Fernet(cfg.intelligence_keys_key.encode())
    except (ValueError, TypeError):
        raise APIError(503, "Saving Intelligence keys requires server encryption setup.") from None


def connection_for_origin(cfg, st, origin, *, conn=None):
    connection = Connection.from_config(cfg) if cfg is not None else None
    if st is not None and switchable(cfg, connection):
        if origin not in ORIGINS and origin != connection.origin:
            return None
        rows = st.many("SELECT encrypted_api_key FROM tenant_intelligence_keys WHERE tenant_id=$1 AND origin=$2",
                       connection.tenant_id, origin, conn=conn)
        if rows:
            try:
                tenant, bound_origin, key = json.loads(cipher(cfg).decrypt(rows[0]["encrypted_api_key"].encode()))
                if tenant != connection.tenant_id or bound_origin != origin:
                    raise ValueError()
                return replace(connection, origin=origin, api_key=key)
            except (InvalidToken, ValueError, TypeError):
                raise APIError(503, "The saved Intelligence credential is unavailable. Check server encryption setup.") from None
    return connection if connection and connection.origin == origin else None


def selected_connection(cfg, st=None, *, conn=None):
    connection = Connection.from_config(cfg) if cfg is not None else None
    if st is not None and switchable(cfg, connection):
        origin = selection(st, connection.tenant_id, conn=conn)["origin"] or connection.origin
        return connection_for_origin(cfg, st, origin, conn=conn)
    return connection


class WorkspaceThreatIntelClient:
    """Resolve each operation while keeping active requests and pools intact."""

    def __init__(self, st, cfg):
        self.st, self.cfg, self.tenant_id = st, cfg, cfg.tenant_id
        self.clients = {}

    async def client(self, *, run_sync=None):
        run_sync = run_sync or asyncio.to_thread
        connection = await run_sync(selected_connection, self.cfg, self.st)
        if connection not in self.clients:
            self.clients[connection] = ThreatIntelClient.from_connection(connection)
        return self.clients[connection]

    async def assess(self, tenant, actions, availability="available", *, run_sync=None):
        return await (await self.client(run_sync=run_sync)).assess(tenant, actions, availability)

    async def packages(self, queries):
        return await (await self.client()).packages(queries)

    async def aclose(self):
        for client in self.clients.values():
            await client.aclose()
