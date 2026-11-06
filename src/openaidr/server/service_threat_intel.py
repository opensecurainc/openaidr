"""Dormant URL/package adapters bound to one selected customer connection."""

import asyncio
from functools import partial

from openaidr_api_client.client import Unavailable
from openaidr_api_client.validation.web_risk import extract_urls

from .guardrail import calls
from .intelligence import selected_connection
from .service_operations import contracts


class Client:
    def __init__(self, connection, *, transport=None):
        try:
            from openaidr_api_client.contracts import service_threat_intel  # noqa: F401
        except ImportError:
            raise Unavailable("Customer service SDK is unavailable") from None
        from openaidr_api_client.clients.threat_intel import ThreatIntelClient

        self.connection, self.tenant_id = connection, connection.tenant_id
        self.cache_identity = connection.fingerprint()
        self.client = ThreatIntelClient.from_connection(connection, transport=transport)

    def _bind(self, operation, service):
        if operation.connection != self.connection or operation.service != service:
            raise Unavailable("Service operation connection or capability mismatch")

    async def assess(self, operation, actions, *, scope_id, run_sync, availability="available"):
        self._bind(operation, "url_reputation")
        if not extract_urls(actions)[0]:
            return await self.client.assess(operation.tenant, actions, availability, request_id=operation.id)

        async def received(value):
            operation.capture(value)

        try:
            await run_sync(calls.begin, operation, scope_id, actions, availability)
            failed = None
            try:
                result = await self.client.assess(operation.tenant, actions, availability,
                                                  request_id=operation.id, receipt=received)
                failed = None if "intelligence_unavailable" in result["reasons"] else result["status"] == "unavailable"
                return result
            finally:
                if operation.receipt is not None:
                    await asyncio.shield(run_sync(partial(calls.finish, operation, failed=failed)))
        except Exception:
            raise Unavailable("Intelligence assessment unavailable") from None

    async def packages(self, operation, queries, *, scope_id, run_sync, admit=None, record_receipt=True):
        self._bind(operation, "package_vulnerabilities")

        async def received(value):
            operation.capture(value)

        try:
            await run_sync(partial(calls.begin, operation, scope_id, queries, "", admit=admit))
            failed = None
            try:
                result = await self.client.packages(queries, request_id=operation.id, receipt=received)
                failed = all(item["status"] == "unavailable" for item in result)
                return result
            finally:
                if record_receipt and operation.receipt is not None:
                    await asyncio.shield(run_sync(partial(calls.finish, operation, failed=failed)))
        except Exception:
            raise Unavailable("Intelligence assessment unavailable") from None

    async def aclose(self):
        await self.client.aclose()


class WorkspaceClient:
    """Explicit customer selection with one immutable connection per request."""

    def __init__(self, st, cfg, *, transport=None):
        contracts()
        self.st, self.cfg, self.tenant_id = st, cfg, cfg.tenant_id
        self.transport, self.clients = transport, {}

    async def client(self, *, run_sync):
        connection = await run_sync(selected_connection, self.cfg, self.st)
        return self.bound(connection)

    def bound(self, connection):
        if connection is None or connection.tenant_id != self.tenant_id:
            raise Unavailable("Customer intelligence connection is unavailable")
        if connection not in self.clients:
            self.clients[connection] = Client(connection, transport=self.transport)
        return self.clients[connection]

    async def aclose(self):
        for client in self.clients.values():
            await client.aclose()
