"""Published HTTP boundaries for the tenant dashboard MCP service."""

import base64
import asyncio
import hashlib
import json
import socket
import subprocess
import sys
import threading
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
import httpx
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
import pytest
import uvicorn

from openaidr.server import auth, dashboard_mcp_auth as grants
from openaidr.server.app import create_app
from openaidr.server.config import Config
from openaidr.server.dashboard_mcp import MAX_BODY
from openaidr.server.store import new_id
from test_store import db, tenant  # noqa: F401


def setup(db, origin):
    item = tenant(db)
    user = db.create_user(item["id"], new_id() + "@example.test", "Operator", "unused", "owner")
    cookie = db.create_session(user["id"], item["id"])
    principal = db.get_session(cookie)
    cfg = Config(database_url=db.url, tenant_id=item["id"], public_url=origin, dashboard_mcp_enabled=True,
                 cost_processing=False, application_classification=False, osv_assessment=False)
    cfg.set_services("api")
    grants.update_settings(db, cfg, principal, {"revision": 0, "enabled": True, "allowed_scopes": list(grants.SCOPE_IDS)})
    client = grants.create_client(db, cfg, principal, {
        "name": "Investigation client", "redirect_uris": ["https://client.example.test/callback"], "scopes": list(grants.SCOPE_IDS),
    })["client"]
    app = create_app(cfg, db)
    return db, cfg, principal, client, cookie, app


@pytest.fixture
def system(db):
    db, cfg, principal, client, cookie, app = setup(db, "https://tenant.example.test")
    with TestClient(app, base_url=cfg.public_url, headers={auth.CSRF_HEADER: "1"}) as http:
        http.cookies.set(auth.cookie_name(secure=True), cookie)
        yield db, cfg, principal, client, http, app


def start(system, scopes=("overview:read",)):
    _, cfg, _, client, http, _ = system
    verifier = "b" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    result = http.get("/authorize", params={
        "client_id": client["id"], "redirect_uri": client["redirect_uris"][0], "response_type": "code",
        "scope": " ".join(scopes), "state": "client-state", "code_challenge": challenge,
        "code_challenge_method": "S256", "resource": cfg.public_url + "/mcp",
    }, follow_redirects=False)
    assert result.status_code == 302, result.text
    ident = result.headers["location"].rsplit("/", 1)[-1]
    path = "/api/v1/mcp/authorizations/" + ident
    assert http.get(path).status_code == 200
    result = http.post(path, json={"approve": True, "scopes": list(scopes)})
    assert result.status_code == 200, result.text
    code = parse_qs(urlsplit(result.json()["redirect_url"]).query)["code"][0]
    return {"client_id": client["id"], "redirect_uri": client["redirect_uris"][0], "grant_type": "authorization_code",
            "code": code, "code_verifier": verifier, "resource": cfg.public_url + "/mcp"}


def token(system, scopes=("overview:read",)):
    response = system[4].post("/token", data=start(system, scopes))
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def rpc(http, access, method="tools/list", arguments=None, name=None):
    params = {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"},
                        "io.modelcontextprotocol/clientCapabilities": {}}}
    headers = {"Authorization": "Bearer " + access, "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
    if name:
        params.update(name=name, arguments=arguments or {})
        headers["Mcp-Name"] = name
    return http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, headers=headers)


def test_oauth_resource_origin_and_csrf_are_enforced(system):
    _, cfg, _, _, http, _ = system
    metadata = http.get("/.well-known/oauth-authorization-server")
    assert metadata.status_code == 200
    assert metadata.json()["token_endpoint_auth_methods_supported"] == ["none"]
    assert "registration_endpoint" not in metadata.json()
    protected = http.get("/.well-known/oauth-protected-resource/mcp")
    assert protected.json()["resource"] == cfg.public_url + "/mcp"
    request = start(system)
    assert http.post("/token", data={**request, "resource": "https://attacker.example/mcp"}).status_code == 400
    assert http.post("/token", data=request, headers={"Origin": "https://attacker.example"}).status_code == 403
    assert http.post("/token", content="resource=a&resource=b", headers={"Content-Type": "application/x-www-form-urlencoded"}).status_code == 400
    assert http.post("/token", data=request).status_code == 200
    assert http.post("/api/v1/mcp/clients", json={}, headers={auth.CSRF_HEADER: ""}).status_code == 403
    assert http.post("/api/v1/mcp/clients", json={}, headers={"Origin": "https://attacker.example"}).status_code == 403


def test_real_protocol_filters_tools_and_rechecks_revocation(system):
    _, _, _, _, http, _ = system
    access = token(system)
    listing = rpc(http, access)
    assert listing.status_code == 200, listing.text
    tools = listing.json()["result"]["tools"]
    names = {tool["name"] for tool in tools}
    assert "get_overview" in names
    assert "update_finding" not in names and "propose_hook_mode" not in names
    read = rpc(http, access, "tools/call", {}, "get_overview")
    assert read.status_code == 200, read.text
    assert not read.json()["result"].get("isError", False), read.text
    rejected = rpc(http, access, "tools/call", {}, "propose_hook_mode")
    assert rejected.json()["result"]["isError"] is True
    granted = http.get("/api/v1/mcp/grants").json()["items"][0]
    assert http.delete("/api/v1/mcp/grants/" + granted["id"]).status_code == 200
    assert rpc(http, access).status_code == 401


def test_transport_has_no_cookie_fallback_and_bounds_requests(system):
    _, _, _, _, http, app = system
    missing = http.post("/mcp", json={})
    assert missing.status_code == 401
    assert "resource_metadata=" in missing.headers["www-authenticate"]
    access = token(system)
    assert rpc(http, "a-sensor-or-browser-token").status_code == 401
    assert http.post("/mcp", content=b"x" * (MAX_BODY + 1)).status_code == 413
    assert http.post("/mcp", content='{"jsonrpc":"2.0","id":1,"id":2}').status_code == 400
    assert http.post("/mcp", json={}, headers=[("Authorization", "Bearer " + access), ("Authorization", "Bearer other")]).status_code == 400
    unsupported = http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                            headers={"Authorization": "Bearer " + access, "Accept": "application/json, text/event-stream",
                                     "MCP-Protocol-Version": "2099-01-01", "Mcp-Method": "tools/list"})
    assert unsupported.status_code == 400 and "protocol" in unsupported.text.lower()
    for _ in range(120):
        app.state.dashboard_mcp.quota.take(("client", system[3]["id"]), 120)
    limited = rpc(http, access, "tools/call", {}, "get_overview")
    assert limited.json()["result"]["isError"] is True
    assert "rate_limited" in limited.text


def test_configuration_proposal_requires_browser_and_current_version(system):
    db, _, principal, _, http, _ = system
    access = token(system, ("configuration:propose", "guardrail:read"))
    response = rpc(http, access, "tools/call", {"request_id": new_id(), "expected_version": 0, "mode": "enforce"}, "propose_hook_mode")
    assert response.status_code == 200, response.text
    result = response.json()["result"]
    assert not result.get("isError", False), result
    proposal = result["structuredContent"]
    assert proposal["status"] == "pending"
    rejected = rpc(http, access, "tools/call", {"proposal_id": proposal["id"]}, "approve_change_proposal")
    assert rejected.json()["result"]["isError"] is True
    path = "/api/v1/mcp/changes/" + proposal["id"]
    displayed = http.get(path).json()
    assert displayed["before"] == {"mode": "shadow"} and displayed["after"] == {"mode": "enforce"}
    decision = http.post(path, json={"decision": "approve", "digest": displayed["digest"]})
    assert decision.status_code == 200, decision.text
    assert decision.json()["status"] == "applied"
    assert db.scalar("SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='mcp.change.applied'", principal["tenant"]["id"]) == 1


def test_disabled_deployment_does_not_publish_protocol(system):
    db, cfg, _, _, _, _ = system
    with TestClient(create_app(replace(cfg, dashboard_mcp_enabled=False), db), base_url=cfg.public_url) as http:
        assert http.post("/mcp", json={}).status_code == 404
        assert http.get("/.well-known/oauth-authorization-server").status_code == 404


def test_ingestion_startup_preserves_api_grants(system):
    db, cfg, _, _, http, _ = system
    access = token(system)
    worker = replace(cfg, dashboard_mcp_enabled=False)
    worker.set_services("ingest")
    create_app(worker, db)
    assert rpc(http, access).status_code == 200
    assert db.scalar("SELECT enabled FROM dashboard_mcp_settings WHERE tenant_id=$1", cfg.tenant_id)


def test_mcp_deployment_configuration_is_explicit():
    Config(database_url="postgresql://localhost/test").validate()
    for cfg in (Config(dashboard_mcp_enabled=True), Config(dashboard_mcp_enabled=True, tenant_id=new_id(), public_url="http://tenant.example")):
        with pytest.raises(ValueError, match="Dashboard MCP"):
            cfg.validate()


def test_public_client_revocation_needs_no_client_secret(system):
    _, _, _, client, http, _ = system
    credentials = http.post("/token", data=start(system)).json()
    result = http.post("/revoke", data={"client_id": client["id"], "token": credentials["refresh_token"]})
    assert result.status_code == 200, result.text
    assert rpc(http, credentials["access_token"]).status_code == 401
    assert http.post("/revoke", data={"client_id": client["id"], "token": "unknown-token"}).status_code == 200


def test_timed_out_refresh_rolls_back_and_can_be_retried(system, monkeypatch):
    from openaidr.server import dashboard_mcp

    _, cfg, _, registered, http, app = system
    credentials = http.post("/token", data=start(system)).json()
    request = {"client_id": registered["id"], "grant_type": "refresh_token",
               "refresh_token": credentials["refresh_token"], "resource": cfg.public_url + "/mcp"}
    provider = app.state.dashboard_mcp.provider
    mint = provider._mint
    completed = threading.Event()

    def slow_mint(*args, **kwargs):
        result = mint(*args, **kwargs)
        time.sleep(0.8)
        completed.set()
        return result

    with monkeypatch.context() as patch:
        patch.setattr(dashboard_mcp, "REQUEST_SECONDS", 0.5)
        patch.setattr(provider, "_mint", slow_mint)
        response = http.post("/token", data=request)
        assert response.status_code == 503, response.text
        assert completed.wait(2)
    retry = http.post("/token", data=request)
    assert retry.status_code == 200, retry.text
    assert rpc(http, retry.json()["access_token"]).status_code == 200


def test_sdk_client_can_discover_and_call_over_http(db):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    db, cfg, principal, registered, cookie, app = setup(db, origin)
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="on"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started
        with httpx.Client(base_url=origin, headers={auth.CSRF_HEADER: "1"}, cookies={auth.CONSOLE_COOKIE: cookie}) as browser:
            access = token((db, cfg, principal, registered, browser, app))

        async def use_client():
            async with httpx2.AsyncClient(headers={"Authorization": "Bearer " + access}) as http:
                async with Client(streamable_http_client(origin + "/mcp", http_client=http)) as client:
                    catalog = await client.list_tools()
                    assert "get_overview" in {tool.name for tool in catalog.tools}
                    result = await client.call_tool("get_overview", {})
                    assert not result.is_error
                    assert result.structured_content["source"]["path"] == "/api/v1/overview"
        asyncio.run(use_client())
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        assert not thread.is_alive()


def test_disabled_service_imports_without_optional_mcp_sdk(db):
    result = subprocess.run([sys.executable, "-c", """
import builtins
import sys
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name == 'mcp' or name.startswith('mcp.'):
        raise ModuleNotFoundError('optional MCP SDK intentionally unavailable')
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
from openaidr.server.app import create_app
from openaidr.server.config import Config
from openaidr.server.store import Store
store = Store(sys.argv[1])
app = create_app(Config(database_url=sys.argv[1]), store)
assert app.state.dashboard_mcp.app is None
store.close()
""", db.url], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr


def test_capacity_and_deadline_apply_before_slow_request_bodies(system, monkeypatch):
    from openaidr.server import dashboard_mcp

    monkeypatch.setattr(dashboard_mcp, "REQUEST_SECONDS", 0.5)
    app = system[-1]

    async def exercise():
        reached = 0
        all_reading = asyncio.Event()

        async def send_request():
            messages = []

            async def receive():
                nonlocal reached
                reached += 1
                if reached == 8:
                    all_reading.set()
                await asyncio.Event().wait()

            async def send(message):
                messages.append(message)

            scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                     "method": "POST", "scheme": "https", "path": "/mcp", "raw_path": b"/mcp",
                     "query_string": b"", "headers": [(b"host", b"tenant.example.test")],
                     "client": ("127.0.0.1", 4321), "server": ("tenant.example.test", 443)}
            await app(scope, receive, send)
            return next(message["status"] for message in messages if message["type"] == "http.response.start")

        slow = [asyncio.create_task(send_request()) for _ in range(8)]
        try:
            await asyncio.wait_for(all_reading.wait(), 2)
            assert await send_request() == 429
            assert reached == 8
            assert await asyncio.wait_for(asyncio.gather(*slow), 2) == [503] * 8
            assert not app.state.dashboard_mcp.slots.locked()
        finally:
            for task in slow:
                task.cancel()
            await asyncio.gather(*slow, return_exceptions=True)
    asyncio.run(exercise())


def test_detail_access_audit_records_target_without_evidence(system):
    db, cfg, principal, _, http, _ = system
    finding = new_id()
    db.execute("INSERT INTO findings(id,tenant_id,rule_id,category,severity,title,sensor_id,primary_event_id,first_event_at) "
               "VALUES($1,$2,'test','secret_exfiltration','high','Confidential retained title',$3,$4,clock_timestamp())",
               finding, cfg.tenant_id, new_id(), new_id())
    access = token(system, ("detections:read", "evidence:read"))
    result = rpc(http, access, "tools/call", {"id": finding}, "read_finding")
    assert not result.json()["result"].get("isError", False), result.text
    audit = db.one("SELECT details,actor_id FROM audit_log WHERE tenant_id=$1 AND action='mcp.tool.call'", cfg.tenant_id)
    assert audit["details"]["targets"]["path"] == "findings/" + finding
    assert audit["actor_id"] == principal["user"]["id"]
    assert "Confidential retained title" not in json.dumps(audit)
