"""Bounded, event-loop-owned provider connections; credentials stay tenant scoped."""

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass

from openaidr_api_client.client import Connection


def _legacy_error(*args, **kwargs):
    from .scoring import JevError
    return JevError(*args, **kwargs)


def credential_digest(key):
    return key.fingerprint() if isinstance(key, Connection) else ""


@dataclass(eq=False)
class _Entry:
    tenant: str
    digest: str
    client: object
    users: int = 0
    retired: bool = False


class AsyncGuardrailClients:
    """One current generation per tenant; old leases drain without blocking callers.

    Every lease receives a freshly resolved key from the tenant adapter. The
    registry never chooses credentials, changes deadlines or retries a request.
    Retired/closing generations count toward the hard live-client bound.
    """

    def __init__(self, factory=None, *, max_cached=16, max_live=32, error_factory=None):
        if not 1 <= max_cached <= max_live:
            raise ValueError("Invalid provider cache bounds")
        self.factory = factory
        self.error = error_factory or _legacy_error
        self.max_cached, self.max_live = max_cached, max_live
        self._loop = None
        self._current = OrderedDict()
        self._live = set()
        self._closing = set()
        self._users = 0
        self._idle = None
        self._closed = False
        self.created = self.reused = self.rejected = self.close_errors = 0

    def _owned(self):
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
            self._idle = asyncio.Event()
            self._idle.set()
        elif self._loop is not loop:
            raise self.error("provider_unavailable")

    async def _close(self, entry):
        try:
            await entry.client.aclose()
        except Exception:
            # Never expose credentials/provider exception text or fail a lease
            # that has already delivered its assessment.
            self.close_errors += 1
        finally:
            self._live.discard(entry)

    def _retire(self, entry):
        entry.retired = True
        if self._current.get(entry.tenant) is entry:
            del self._current[entry.tenant]
        if not entry.users:
            task = asyncio.create_task(self._close(entry))
            self._closing.add(task)
            task.add_done_callback(self._closing.discard)

    def _lease(self, tenant, key):
        self._owned()
        if self._closed or not tenant or not isinstance(key, Connection):
            raise self.error("provider_unavailable")
        if key.tenant_id != str(tenant):
            raise self.error("provider_unavailable")
        digest = credential_digest(key)
        entry = self._current.get(tenant)
        if entry is not None and entry.digest != digest:
            self._retire(entry)
            entry = None
        if entry is None:
            if len(self._current) >= self.max_cached:
                # Do not evict an active tenant merely to admit another tenant.
                victim = next((item for item in self._current.values() if not item.users), None)
                if victim is None:
                    self.rejected += 1
                    raise self.error("provider_unavailable")
                self._retire(victim)
            if len(self._live) >= self.max_live:
                self.rejected += 1
                raise self.error("provider_unavailable")
            if self.factory is None:
                from openaidr_api_client.clients.guardrail import AsyncGuardrailClient
                client = AsyncGuardrailClient(key)
            else:
                client = self.factory(key)
            entry = _Entry(tenant, digest, client)
            self._current[tenant] = entry
            self._live.add(entry)
            self.created += 1
        else:
            self.reused += 1
        self._current.move_to_end(tenant)
        entry.users += 1
        self._users += 1
        self._idle.clear()
        return entry

    def _release(self, entry):
        entry.users -= 1
        self._users -= 1
        if entry.retired and not entry.users:
            self._retire(entry)
        if not self._users:
            self._idle.set()

    def invalidate(self, tenant):
        """A missing effective key closes idle credentials and drains old leases."""
        self._owned()
        entry = self._current.get(tenant)
        if entry is not None:
            self._retire(entry)

    async def assess(self, tenant, key, state, *, company_policy="", timeout=None, request_id=None):
        deadline = time.monotonic() + timeout if timeout is not None else None
        entry = self._lease(tenant, key)
        try:
            remaining = max(0, deadline - time.monotonic()) if deadline is not None else None
            return await entry.client.assess(state, company_policy=company_policy, timeout=remaining,
                                             **({"request_id": request_id} if request_id is not None else {}))
        finally:
            # No await: cancellation or a deadline cannot strand the lease or
            # wait for network cleanup. Cleanup remains lifespan owned.
            self._release(entry)

    async def aclose(self):
        self._owned()
        self._closed = True
        for entry in list(self._current.values()):
            self._retire(entry)
        await self._idle.wait()
        while self._closing:
            await asyncio.gather(*list(self._closing), return_exceptions=True)


class BackgroundGuardrailClients:
    """Synchronous facade; transports live only on one private provider loop.

    Thread-pool workers can change between ticks. They must not move an
    asyncio.Runner or its connections between threads. A persistent owned loop
    also preserves the asynchronous provider's whole-response timeout.
    """

    def __init__(self, factory=None, *, max_pending=32, timeout=None, error_factory=None):
        import threading

        if max_pending < 1 or (timeout is not None and timeout <= 0):
            raise ValueError("Invalid background provider bounds")
        if timeout is None:
            from .scoring import REQUEST_TIMEOUT
            timeout = REQUEST_TIMEOUT
        self.timeout = timeout
        self.error = error_factory or _legacy_error
        self._factory = factory
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._slots = threading.BoundedSemaphore(max_pending)
        self._closed = False
        self._shutdown = None
        self._thread = threading.Thread(target=self._run, name="openaidr-guardrail-provider", daemon=True)
        self._thread.start()
        if not self._ready.wait(5):
            self._closed = True
            raise RuntimeError("Background provider startup timed out")

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._clients = AsyncGuardrailClients(self._factory, error_factory=self.error)
        def started():
            # Publish readiness only from the running loop. A normal close
            # can then queue cleanup without a startup closed-check skipping it.
            if self._closed:  # Constructor timed out before the loop started.
                self._loop.stop()
            self._ready.set()
        self._loop.call_soon(started)
        try:
            self._loop.run_forever()
        finally:
            async def finish():
                pending = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                await self._clients.aclose()
                await self._loop.shutdown_asyncgens()
                await self._loop.shutdown_default_executor()
            self._loop.run_until_complete(finish())
            self._loop.close()

    def _call(self, operation):
        import threading
        from concurrent.futures import Future, InvalidStateError, TimeoutError as FutureTimeout

        if threading.current_thread() is self._thread:
            raise self.error("provider_unavailable")
        if not self._slots.acquire(blocking=False):
            raise self.error("provider_unavailable")
        result = Future()
        task = [None]

        def completed(running):
            # Done callbacks run even when a task is cancelled before its first
            # instruction. Release admission only when its actual task is done.
            self._slots.release()
            try:
                if running.cancelled():
                    result.cancel()
                else:
                    error = running.exception()
                    if not result.cancelled():
                        if error is None:
                            result.set_result(running.result())
                        else:
                            result.set_exception(error)
            except InvalidStateError:
                pass  # Caller deadline raced with this completion.

        def start():
            if result.cancelled():
                self._slots.release()
                return
            task[0] = self._loop.create_task(operation())
            task[0].add_done_callback(completed)

        def cancel(future):
            if future.cancelled():
                def stop():
                    if task[0] is not None:
                        task[0].cancel()
                self._loop.call_soon_threadsafe(stop)

        with self._lock:
            if self._closed:
                self._slots.release()
                raise self.error("provider_unavailable")
            result.add_done_callback(cancel)
            self._loop.call_soon_threadsafe(start)
        try:
            return result.result(timeout=self.timeout)
        except FutureTimeout:
            result.cancel()
            raise self.error("connection_failed", retryable=True) from None

    def assess(self, tenant, key, state, *, company_policy="", request_id=None):
        deadline = time.monotonic() + self.timeout
        return self._call(lambda: self._clients.assess(tenant, key, state, company_policy=company_policy,
                                                       timeout=max(0, deadline - time.monotonic()),
                                                       **({"request_id": request_id} if request_id is not None else {})))

    def invalidate(self, tenant):
        async def invalidate():
            self._clients.invalidate(tenant)
        self._call(invalidate)

    def close(self):
        import threading

        if threading.current_thread() is self._thread:
            raise RuntimeError("Provider loop cannot join itself")
        with self._lock:
            if not self._closed:
                self._closed = True
                self._shutdown = asyncio.run_coroutine_threadsafe(self._clients.aclose(), self._loop)
            shutdown = self._shutdown
        try:
            shutdown.result(timeout=self.timeout + 5)
        finally:
            if self._thread.is_alive():
                self._loop.call_soon_threadsafe(self._loop.stop)
                self._thread.join(5)
                if self._thread.is_alive():
                    raise RuntimeError("Background provider shutdown incomplete")
