"""Exercise tenant clients against the real API, mocking only provider transports."""

from contextlib import contextmanager, ExitStack
import inspect
from types import SimpleNamespace
from uuid import uuid4

import pytest
import httpx
from fastapi.testclient import TestClient

from openaidr_api.app import Config, create_app
from openaidr_api_client.client import Connection
from openaidr_api.threat_intel import keys


@contextmanager
def intelligence_service(monkeypatch, tmp_path, tenant, provider, *, origin="https://intelligence.test", **credentials):
    root = tmp_path / (tenant + "-" + uuid4().hex)
    root.mkdir(mode=0o700, exist_ok=True)
    database, token = root / "keys.sqlite3", root / "tenant.key"
    keys.initialize(database)
    # Retained tests use the original service; cloud integration uses the current one.
    if "actor" in inspect.signature(keys.issue).parameters:
        keys.issue(database, tenant, token, actor="tenant-adapter-test", source="provisioning")
    elif credentials.get("customer_mode"):
        keys.issue(database, tenant, token, customer=True)
    else:
        keys.issue(database, tenant, token)
    if credentials.get("customer_mode"):
        credentials.setdefault("credits_db", str(root / "credits.sqlite3"))
    connection = Connection(origin, token.read_text().strip(), tenant)

    async def upstream(request):
        response = provider(request)
        return await response if inspect.isawaitable(response) else response

    app = create_app(Config(str(database), **credentials), transport=httpx.MockTransport(upstream))
    requests = []
    original_sync = httpx.HTTPTransport.handle_request
    original_async = httpx.AsyncHTTPTransport.handle_async_request
    with TestClient(app) as client:
        patch = monkeypatch
        def check(request):
            assert str(request.url).startswith(connection.origin + "/v1/"), "Tenant bypassed the Intelligence API"
            requests.append(request)

        async def asynchronous(_transport, request):
            if request.url.host in {"127.0.0.1", "localhost"}:
                return await original_async(_transport, request)
            check(request)
            return await httpx.ASGITransport(app=app).handle_async_request(request)

        def synchronous(_transport, request):
            if request.url.host in {"127.0.0.1", "localhost"}:
                return original_sync(_transport, request)
            check(request)
            result = client.request(request.method, str(request.url), headers=request.headers, content=request.content)
            return httpx.Response(result.status_code, headers=result.headers, content=result.content, request=request)

        patch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", asynchronous)
        patch.setattr(httpx.HTTPTransport, "handle_request", synchronous)
        yield SimpleNamespace(connection=connection, requests=requests, app=app, database=database,
                              config=dict(tenant_id=tenant, intelligence_origin=connection.origin,
                                          intelligence_api_key=connection.api_key))


@pytest.fixture
def api_service(monkeypatch, tmp_path):
    with ExitStack() as stack:
        def configure(cfg, tenant, provider, **credentials):
            service = stack.enter_context(intelligence_service(monkeypatch, tmp_path, tenant, provider, **credentials))
            for name, value in service.config.items():
                setattr(cfg, name, value)
            return service
        yield configure
