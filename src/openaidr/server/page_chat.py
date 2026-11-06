"""Page chat has no data store, retrieval tools, or provider conversation state."""

from openaidr_api_client.validation.page_chat import (
    MAX_PAGE_CHARS as MAX_PAGE_CHARS,
    MAX_HISTORY_CHARS as MAX_HISTORY_CHARS,
    validate_input as validate_input,
    sse_events as sse_events,
    provider_errors as provider_errors,
)

import asyncio
import json
import threading
import time
from collections import deque
from contextlib import aclosing, contextmanager

import anyio
from starlette.responses import StreamingResponse

from openaidr_api_client.client import IntelligenceClient, SyncIntelligenceClient, Unavailable

from .httpx import APIError, require

_UNSELECTED = object()


class ChatResponse(StreamingResponse):
    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            # A failed downstream write may occur while the generator is paused
            # at yield. Close it explicitly so provider I/O and billing finish.
            with anyio.CancelScope(shield=True):
                await self.body_iterator.aclose()


class PageChat:
    def __init__(self, store=None, *, connection=None, connection_factory=None):
        self.store = store
        self._connection = connection
        self._connection_factory = connection_factory
        self._slots = threading.BoundedSemaphore(4)
        self._lock = threading.Lock()
        self._attempts = {}

    @property
    def connection(self):
        return self._connection_factory() if self._connection_factory else self._connection

    @connection.setter
    def connection(self, value):
        self._connection, self._connection_factory = value, None

    def configured(self, tenant):
        connection = self.connection
        return connection is not None and str(tenant) == connection.tenant_id

    def cache_identity(self, tenant, *, connection=_UNSELECTED):
        if connection is _UNSELECTED:
            connection = self.connection
        require(connection and str(tenant) == connection.tenant_id, "Assistant connection does not match this tenant", 503)
        return connection.fingerprint()

    @contextmanager
    def _admit(self, tenant, *, connection=_UNSELECTED):
        if connection is _UNSELECTED:
            connection = self.connection
        require(
            connection is not None and str(tenant) == connection.tenant_id,
            "OpenAIDR Assistant is not configured. Ask an administrator to enable it.",
            503,
        )
        require(
            self._slots.acquire(blocking=False),
            "OpenAIDR Assistant is busy. Try again shortly.",
            429,
        )
        try:
            with self._lock:
                cutoff = time.monotonic() - 60
                for ident, attempts in list(self._attempts.items()):
                    while attempts and attempts[0] <= cutoff:
                        attempts.popleft()
                    if not attempts:
                        del self._attempts[ident]
                attempts = self._attempts.setdefault(tenant, deque())
                require(
                    len(attempts) < 20,
                    "OpenAIDR Assistant limit reached. Try again in a minute.",
                    429,
                )
                attempts.append(time.monotonic())
            yield connection
        finally:
            self._slots.release()

    def answer(self, tenant, data):
        validate_input(data)
        with self._admit(tenant) as connection:
            return validate_result(self.generate(tenant, "assistant", data, connection=connection))

    def stream(self, tenant, data):
        # Invalid input still gets a normal HTTP error before streaming starts.
        validate_input(data)
        return self._stream(tenant, data)

    async def _stream(self, tenant, data):
        try:
            connection = await anyio.to_thread.run_sync(lambda: self.connection)
            # Acquire inside the generator so a disconnect before iteration
            # cannot leak a slot. Both response formats share the same budget.
            with self._admit(tenant, connection=connection), provider_errors():
                upstream = self._generation_stream(tenant, data, connection)
                async with aclosing(upstream) as stream:
                    async for event in stream:
                        yield stream_event(event["type"], **{k: v for k, v in event.items() if k != "type"})
        except APIError as exc:
            yield stream_event("error", message=exc.message)

    async def _generation_stream(self, tenant, data, connection):
        from openaidr_api_client.validation.page_chat import MODEL
        from .service_costs import Call

        call = await anyio.to_thread.run_sync(lambda: Call(self.store, tenant, "assistant", "openai", MODEL))
        failed = True
        try:
            async with aclosing(self._service_stream(data, call, connection)) as stream:
                async for event in stream:
                    if event["type"] == "done":
                        failed = False
                    yield event
        finally:
            with anyio.CancelScope(shield=True):
                await anyio.to_thread.run_sync(call.finish, failed)

    def generate(self, tenant, service, data, *, connection):
        from openaidr_api_client.validation.page_chat import MODEL
        from .service_costs import Call

        path = {"assistant": "/v1/assistant/respond", "rule_generation": "/v1/rules/draft"}[service]
        call = Call(self.store, tenant, "assistant", "openai", MODEL)
        failed = True
        try:
            with provider_errors():
                result = self.request_generation(path, data, call, connection=connection)
                if service == "assistant":
                    result = validate_result(result)
                else:
                    from openaidr_api_client.validation.rule_authoring import validate_result as validate_rule
                    result = validate_rule(data["intent"], result)
            failed = False
            return result
        finally:
            call.finish(failed)

    def request_generation(self, path, data, call, *, connection):
        require(connection and call.tenant == connection.tenant_id,
                "Assistant connection does not match this tenant", 503)
        deadline = time.monotonic() + 45
        with provider_errors():
            client = SyncIntelligenceClient.from_connection(connection)
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                value = client.request(path, {**data, "timeout_ms": max(1, int(remaining * 1000))}, 256 << 10, remaining)
                return service_result(value, call)
            finally:
                client.close()

    async def _service_stream(self, data, call, connection):
        deadline = time.monotonic() + 45
        require(connection and call.tenant == connection.tenant_id,
                "Assistant connection does not match this tenant", 503)
        client = IntelligenceClient.from_connection(connection)
        try:
            async with asyncio.timeout_at(deadline):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                async with client.client.stream("POST", "/v1/assistant/respond", timeout=remaining,
                    json={**data, "stream": True, "timeout_ms": max(1, int(remaining * 1000))}) as response:
                    if (response.status_code != 200 or response.headers.get("content-encoding", "identity") != "identity"
                            or response.headers.get("content-type", "").split(";", 1)[0] != "text/event-stream"):
                        raise Unavailable("Intelligence service unavailable")
                    size = 0
                    async for value in sse_events(response):
                        if isinstance(value, dict) and value.get("type") == "delta":
                            if set(value) != {"type", "text"} or not isinstance(value["text"], str):
                                raise ValueError("invalid text delta")
                            size += len(value["text"])
                            if size > 8000:
                                raise ValueError("answer too long")
                            yield value
                        else:
                            result = validate_result(service_result(value, call))
                            yield {"type": "done", **result}
                            return
                    raise ValueError("stream ended before completion")
        finally:
            with anyio.CancelScope(shield=True):
                await client.aclose()


def validate_result(result):
    if (not isinstance(result, dict) or set(result) != {"answer"} or not isinstance(result["answer"], str)
            or not result["answer"].strip() or len(result["answer"]) > 8000):
        raise ValueError("invalid answer")
    return result


def service_result(value, call):
    from .service_costs import validate_response_usage

    # Capture known provider usage even when the returned answer is malformed.
    if not isinstance(value, dict):
        raise ValueError("invalid generation response")
    if value.get("usage") is not None:
        call.payload = validate_response_usage(value["usage"])
    if value.get("status") == "completed":
        if set(value) != {"status", "result", "usage"} or value["usage"] is None or not isinstance(value["result"], dict):
            raise ValueError("invalid completed generation")
        return value["result"]
    if (set(value) != {"status", "code", "retry_after", "usage"} or value.get("status") != "error"
            or value["code"] not in ("timeout", "provider_unavailable", "invalid_response") or value["retry_after"] is not None):
        raise ValueError("invalid generation error")
    status = {"timeout": 504, "provider_unavailable": 503, "invalid_response": 502}[value["code"]]
    message = "OpenAIDR Assistant took too long. Please try again." if status == 504 else "OpenAIDR Assistant is unavailable. Please try again."
    raise APIError(status, message)


def stream_event(kind, **data):
    return "data: " + json.dumps({"type": kind, **data}) + "\n\n"
