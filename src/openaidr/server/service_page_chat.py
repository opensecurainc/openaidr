"""Dormant customer assistant and rule callers; active factories still use PageChat."""

from contextlib import aclosing

import anyio

from . import service_generation
from .httpx import APIError, require
from .page_chat import PageChat
from .service_operations import ServiceOperation, contracts


class CustomerPageChat(PageChat):
    def __init__(self, store=None, *, connection=None, connection_factory=None, transport=None):
        contracts()  # Reject the current SDK before creating any transport.
        super().__init__(store, connection=connection, connection_factory=connection_factory)
        self._transport = transport

    def generate(self, tenant, service, data, *, connection):
        require(service in ("assistant", "rule_generation"), "Queued summaries are unavailable.", 503)
        operation = ServiceOperation(self.store, tenant, service, connection)
        return service_generation.request(operation, data, transport=self._transport)

    async def _generation_stream(self, tenant, data, connection):
        operation = ServiceOperation(self.store, tenant, "assistant", connection)
        async with aclosing(service_generation.stream(operation, data, run_sync=anyio.to_thread.run_sync,
                                                      transport=self._transport)) as stream:
            async for event in stream:
                yield event

    def request_generation(self, path, data, call, *, connection):
        # Old queued callers have no durable customer request identity yet.
        raise APIError(503, "Queued summaries are unavailable.")
