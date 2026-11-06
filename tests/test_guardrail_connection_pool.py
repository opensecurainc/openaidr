"""Real HTTP/1.1 sockets prove reuse; no external provider or paid calls."""

import asyncio
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from openaidr.server.guardrail.clients import AsyncGuardrailClients
from openaidr_api_client.clients.guardrail import AsyncGuardrailClient
from openaidr_api_client.contracts.guardrail import JevError
from openaidr_api_client.client import Connection
from openaidr_api.providers.guardrail import parse_assessment
from uuid import NAMESPACE_URL, uuid5
from openaidr.server import model_keys
from types import SimpleNamespace
from test_risk import reply

TENANT_A = str(uuid5(NAMESPACE_URL, "pool-tenant-a"))
TENANT_B = str(uuid5(NAMESPACE_URL, "pool-tenant-b"))

def connection(tenant, name):
    return Connection("https://intelligence.test", "oati_" + uuid5(NAMESPACE_URL, name).hex + "." + "b" * 43, tenant)


@pytest.fixture
def provider():
    class Server(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 32

        def get_request(self):
            connection, address = super().get_request()
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self.lock:
                self.connections += 1
            return connection, address

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state = data["state"]
            with self.server.lock:
                self.server.requests.append((self.headers.get("Authorization"), state))
                self.server.active += 1
                self.server.peak = max(self.server.peak, self.server.active)
                if self.server.active == 8:
                    self.server.saturated.set()
            try:
                if state.get("block"):
                    self.server.entered.set()
                    self.server.gate.wait(3)
                payload = json.dumps({**parse_assessment(reply("none", 0)), "usage": {"model": None, "input_tokens": None, "output_tokens": None}}).encode()
                self.send_response(503 if state.get("error") else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with self.server.lock:
                    self.server.active -= 1

    server = Server(("127.0.0.1", 0), Handler)
    server.lock = threading.Lock()
    server.connections = server.active = server.peak = 0
    server.requests = []
    server.entered = threading.Event()
    server.saturated = threading.Event()
    server.gate = threading.Event()
    server.gate.set()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.gate.set()
        server.shutdown()
        server.server_close()
        thread.join(2)


def clients_for(provider, **bounds):
    created = []

    def factory(key):
        client = AsyncGuardrailClient(key)
        client.client.client.base_url = f"http://127.0.0.1:{provider.server_port}"
        created.append(client)
        return client

    return AsyncGuardrailClients(factory, **bounds), created


def test_500_assessments_reuse_tcp_and_concurrent_pool_stays_bounded(provider):
    async def exercise():
        clients, created = clients_for(provider)
        try:
            for index in range(500):
                result = await clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {"index": index})
                assert result["status"] == "scored"
            assert provider.connections == 1
            assert len(created) == 1
            await asyncio.gather(*(clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {"index": i}) for i in range(100)))
            assert provider.peak <= 8
            assert provider.connections <= 8
            assert len(provider.requests) == 600
        finally:
            await clients.aclose()
        assert created[0].client.client.is_closed

    asyncio.run(exercise())


def test_rotation_drains_old_request_and_tenant_headers_never_mix(provider):
    async def exercise():
        clients, created = clients_for(provider)
        provider.gate.clear()
        old = asyncio.create_task(clients.assess(TENANT_A, connection(TENANT_A, "old-key"), {"block": True}))
        assert await asyncio.to_thread(provider.entered.wait, 2)
        await clients.assess(TENANT_A, connection(TENANT_A, "new-key"), {"tag": "new"})
        await clients.assess(TENANT_B, connection(TENANT_B, "new-key"), {"tag": "other-tenant"})
        assert len(created) == 3
        assert not created[0].client.client.is_closed
        provider.gate.set()
        assert (await old)["status"] == "scored"
        await clients.assess(TENANT_A, connection(TENANT_A, "new-key"), {"tag": "reused"})
        assert len(created) == 3
        await clients.aclose()
        assert all(client.client.client.is_closed for client in created)
        assert provider.requests == [
            ("Bearer " + connection(TENANT_A, "old-key").api_key, {"block": True}), ("Bearer " + connection(TENANT_A, "new-key").api_key, {"tag": "new"}),
            ("Bearer " + connection(TENANT_A, "new-key").api_key, {"tag": "other-tenant"}), ("Bearer " + connection(TENANT_A, "new-key").api_key, {"tag": "reused"}),
        ]

    asyncio.run(exercise())


def test_deadline_cancellation_error_and_shutdown_do_not_leak_leases(provider):
    async def exercise():
        clients, created = clients_for(provider)
        provider.gate.clear()
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.05):
                await clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {"block": True})
        provider.gate.set()
        with pytest.raises(JevError):
            await clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {"error": True})
        await clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {"ok": True})
        assert len(created) == 1
        provider.entered.clear()
        provider.gate.clear()
        active = asyncio.create_task(clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {"block": True}))
        assert await asyncio.to_thread(provider.entered.wait, 2)
        closing = asyncio.create_task(clients.aclose())
        await asyncio.sleep(0)
        assert not closing.done()
        with pytest.raises(JevError):
            await clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {})
        provider.gate.set()
        await active
        await closing
        assert created[0].client.client.is_closed
        assert len(provider.requests) == 4

    asyncio.run(exercise())


def test_cache_evicts_idle_tenant_and_refuses_unbounded_active_generations(provider):
    async def exercise():
        clients, created = clients_for(provider, max_cached=1, max_live=2)
        await clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {})
        await clients.assess(TENANT_B, connection(TENANT_B, "key-b"), {})
        await clients.aclose()
        assert all(client.client.client.is_closed for client in created)
        clients, created = clients_for(provider, max_cached=1, max_live=1)
        provider.entered.clear()
        provider.gate.clear()
        active = asyncio.create_task(clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {"block": True}))
        assert await asyncio.to_thread(provider.entered.wait, 2)
        with pytest.raises(JevError):
            await clients.assess(TENANT_B, connection(TENANT_B, "key-b"), {})
        with pytest.raises(JevError):
            await clients.assess(TENANT_A, connection(TENANT_A, "rotated"), {})
        assert len(created) == 1
        provider.gate.set()
        await active
        await clients.aclose()
        assert created[0].client.client.is_closed

    asyncio.run(exercise())


def test_live_key_deletion_invalidates_idle_client_and_other_loop_is_refused(provider, monkeypatch):
    key = [connection(TENANT_A, "key-a")]
    monkeypatch.setattr(model_keys, "selected_connection", lambda *_args, **_kwargs: key[0])
    clients, created = clients_for(provider)

    async def exercise():
        adapter = model_keys.TenantAsyncGuardrailClient(None, TENANT_A, SimpleNamespace(), clients=clients)
        await adapter.assess({})
        key[0] = None
        with pytest.raises(JevError):
            await adapter.assess({})
        key[0] = connection(TENANT_A, "key-b")
        await adapter.assess({})
        await clients.aclose()
        assert all(client.client.client.is_closed for client in created)

    asyncio.run(exercise())
    with pytest.raises(JevError):
        asyncio.run(clients.assess(TENANT_A, connection(TENANT_A, "key-b"), {}))
    assert len(provider.requests) == 2


def test_saturated_transport_waiter_deadline_never_dispatches_or_leaks(provider):
    async def exercise():
        clients, created = clients_for(provider)
        provider.gate.clear()
        active = [asyncio.create_task(clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {"block": True})) for _ in range(8)]
        assert await asyncio.to_thread(provider.saturated.wait, 2)
        try:
            with pytest.raises(TimeoutError):
                async with asyncio.timeout(0.05):
                    await clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {"cancelled-waiter": True})
            assert len(provider.requests) == 8
        finally:
            provider.gate.set()
            await asyncio.gather(*active)
        await clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {"after": True})
        await clients.aclose()
        assert len(provider.requests) == 9
        assert provider.connections == 8
        assert created[0].client.client.is_closed

    asyncio.run(exercise())


def test_background_calls_reuse_one_loop_across_worker_threads(provider):
    from concurrent.futures import ThreadPoolExecutor
    from openaidr.server.guardrail.clients import BackgroundGuardrailClients

    created = []

    def factory(key):
        client = AsyncGuardrailClient(key)
        client.client.client.base_url = f"http://127.0.0.1:{provider.server_port}"
        created.append((client, threading.get_ident(), asyncio.get_running_loop()))
        return client

    clients = BackgroundGuardrailClients(factory)
    try:
        for i in range(500):
            assert clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {"index": i})["status"] == "scored"
        assert provider.connections == 1
        with ThreadPoolExecutor(max_workers=16) as workers:
            calls = [workers.submit(clients.assess, TENANT_A, connection(TENANT_A, "key-a"), {"index": i}) for i in range(100)]
            assert all(call.result()["status"] == "scored" for call in calls)
        assert provider.connections <= 8 and provider.peak <= 8
        assert len(created) == 1 and created[0][1] == clients._thread.ident
    finally:
        clients.close()
    assert created[0][0].client.client.is_closed
    assert not clients._thread.is_alive()
    with pytest.raises(JevError):
        clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {})


def test_background_admission_timeout_rotation_and_shutdown(provider):
    from concurrent.futures import ThreadPoolExecutor
    from openaidr.server.guardrail.clients import BackgroundGuardrailClients

    created = []

    def factory(key):
        client = AsyncGuardrailClient(key)
        client.client.client.base_url = f"http://127.0.0.1:{provider.server_port}"
        created.append(client)
        return client

    clients = BackgroundGuardrailClients(factory, max_pending=1, timeout=0.1)
    provider.gate.clear()
    with ThreadPoolExecutor(max_workers=1) as workers:
        blocked = workers.submit(clients.assess, TENANT_A, connection(TENANT_A, "old-key"), {"block": True})
        assert provider.entered.wait(2)
        with pytest.raises(JevError) as rejected:
            clients.assess(TENANT_B, connection(TENANT_B, "other-key"), {})
        assert rejected.value.code == "provider_unavailable"
        with pytest.raises(JevError) as expired:
            blocked.result()
        assert expired.value.code == "connection_failed"
    provider.gate.set()
    # Barrier on the provider loop: cancellation/done callbacks release the
    # real admission permit before another request may occupy it.
    async def settled():
        await asyncio.sleep(0)
        await asyncio.sleep(0)
    asyncio.run_coroutine_threadsafe(settled(), clients._loop).result(2)
    assert clients.assess(TENANT_A, connection(TENANT_A, "new-key"), {})["status"] == "scored"
    clients.invalidate(TENANT_A)
    clients.close()
    assert all(client.client.client.is_closed for client in created)
    assert not clients._thread.is_alive()
    assert [key for key, _ in provider.requests] == ["Bearer " + connection(TENANT_A, name).api_key for name in ("old-key", "new-key")]


def test_background_cancelled_before_dispatch_releases_submission(provider):
    from openaidr.server.guardrail.clients import BackgroundGuardrailClients

    def factory(key):
        client = AsyncGuardrailClient(key)
        client.client.client.base_url = f"http://127.0.0.1:{provider.server_port}"
        return client

    clients = BackgroundGuardrailClients(factory, max_pending=1, timeout=0.05)
    entered = threading.Event()
    gate = threading.Event()

    def busy():
        entered.set()
        gate.wait(2)
    clients._loop.call_soon_threadsafe(busy)
    assert entered.wait(2)
    with pytest.raises(JevError):
        clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {"never-dispatch": True})
    gate.set()
    async def barrier():
        await asyncio.sleep(0)
    asyncio.run_coroutine_threadsafe(barrier(), clients._loop).result(2)
    clients.timeout = 2
    assert clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {})["status"] == "scored"
    clients.close()
    assert len(provider.requests) == 1


def test_background_shutdown_drains_active_request_then_rejects_new_work(provider):
    import time
    from concurrent.futures import ThreadPoolExecutor
    from openaidr.server.guardrail.clients import BackgroundGuardrailClients

    made = []
    def factory(key):
        client = AsyncGuardrailClient(key)
        client.client.client.base_url = f"http://127.0.0.1:{provider.server_port}"
        made.append(client)
        return client

    clients = BackgroundGuardrailClients(factory)
    provider.gate.clear()
    with ThreadPoolExecutor(max_workers=2) as workers:
        active = workers.submit(clients.assess, TENANT_A, connection(TENANT_A, "key-a"), {"block": True})
        assert provider.entered.wait(2)
        closing = workers.submit(clients.close)
        limit = time.monotonic() + 2
        while not clients._closed and time.monotonic() < limit:
            time.sleep(0.005)
        assert clients._closed and not closing.done()
        with pytest.raises(JevError):
            clients.assess(TENANT_A, connection(TENANT_A, "key-a"), {})
        provider.gate.set()
        assert active.result()["status"] == "scored"
        closing.result()
    assert made[0].client.client.is_closed and not clients._thread.is_alive()
    assert len(provider.requests) == 1


def test_background_immediate_close_after_readiness_finishes_cleanup(monkeypatch):
    import time
    from concurrent.futures import ThreadPoolExecutor
    from openaidr.server.guardrail.clients import BackgroundGuardrailClients

    event_type = threading.Event
    ready, published, gate = event_type(), event_type(), event_type()
    original_set = ready.set
    first = True

    def make_event():
        nonlocal first
        if first:
            first = False
            return ready
        return event_type()

    def publish_and_pause():
        original_set()
        published.set()
        assert gate.wait(3)

    monkeypatch.setattr(threading, "Event", make_event)
    monkeypatch.setattr(ready, "set", publish_and_pause)
    clients = BackgroundGuardrailClients()
    assert published.wait(1)
    with ThreadPoolExecutor(max_workers=1) as workers:
        closing = workers.submit(clients.close)
        try:
            limit = time.monotonic() + 2
            while not clients._closed and time.monotonic() < limit:
                time.sleep(0.005)
            assert clients._closed
        finally:
            gate.set()
        closing.result(3)
    assert clients._clients._closed and not clients._thread.is_alive()
    clients.close()  # Repeated cleanup remains harmless.
