import asyncio
from contextlib import contextmanager
import json
import socket
import threading
import time

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import httpx2
from mcp.server.mcpserver import MCPServer
import pytest
import uvicorn

from openaidr.server import (
    auth,
    knowledge_ingest,
    knowledge_mcp,
    knowledge_mcp_transport,
    knowledge_retrieval,
)
from openaidr.server.app import create_app
from openaidr.server.config import Config
from openaidr.server.httpx import APIError
from test_store import db, tenant
from test_knowledge_uploads import session
from test_knowledge_retrieval import functional_clock


@contextmanager
def serve(app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="on"))
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [sock]}, daemon=True
    )
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        assert not thread.is_alive()


@pytest.fixture
def remote():
    state = {
        "text": "Orbitctl refresh rebuilds production routing.",
        "auth": [],
        "fail": False,
    }
    server = MCPServer("Company wiki")

    @server.resource("wiki://operations", name="Operations", mime_type="text/plain")
    def operations():
        if state["fail"]:
            raise ValueError("remote private failure")
        return state["text"]

    @server.resource(
        "wiki://binary", name="Binary", mime_type="application/octet-stream"
    )
    def binary():
        return b"\x00\xff"

    app = server.streamable_http_app(json_response=True)

    async def check_auth(request, call_next):
        state["auth"].append(request.headers.get("authorization"))
        return await call_next(request)

    from starlette.middleware.base import BaseHTTPMiddleware

    app.add_middleware(BaseHTTPMiddleware, dispatch=check_auth)

    with serve(app) as origin:
        yield origin, state


def test_mcp_connect_select_refresh_revoke_and_tenant_authorization(
    db, remote, functional_clock
):
    origin, state = remote
    tid, other = tenant(db)["id"], tenant(db)["id"]
    cfg = Config(
        knowledge_mcp_key=Fernet.generate_key().decode(),
        knowledge_mcp_private_origins=origin,
    )
    cfg.set_services("api")
    token = "private-company-token"
    body = {
        "revision": 0,
        "name": "Company wiki",
        "endpoint": origin + "/mcp",
        "token": token,
    }
    with TestClient(create_app(cfg, db), headers={auth.CSRF_HEADER: "1"}) as client:
        assert client.post("/api/v1/knowledge/mcp", json=body).status_code == 401
        viewer, admin = session(db, tid, "viewer"), session(db, tid, "analyst")
        client.cookies.set(auth.CONSOLE_COOKIE, viewer)
        assert client.post("/api/v1/knowledge/mcp", json=body).status_code == 403
        client.cookies.set(auth.CONSOLE_COOKIE, admin)
        assert (
            client.post(
                "/api/v1/knowledge/mcp", json=body, headers={auth.CSRF_HEADER: ""}
            ).status_code
            == 403
        )
        created = client.post("/api/v1/knowledge/mcp", json=body)
        assert created.status_code == 200, created.text
        result = created.json()
        ident, revision = result["connection"]["connection_id"], result["revision"]
        path = "/api/v1/knowledge/mcp/" + ident
        assert result["connection"]["has_token"] and token not in created.text
        assert len(result["resources"]) == 2
        assert all(value == "Bearer " + token for value in state["auth"])
        stored = db.scalar(
            "SELECT encrypted_token FROM knowledge_mcp_connections WHERE tenant_id=$1",
            tid,
        )
        assert token not in stored
        assert token not in client.get("/api/v1/knowledge/mcp").text
        assert client.post(path + "/resources", json={}).status_code == 200
        assert client.post("/api/v1/knowledge/mcp/urn:uuid:" + ident + "/resources", json={}).status_code == 200
        imported = client.post(
            "/api/v1/knowledge/mcp/" + ident.upper() + "/sync",
            json={"revision": revision, "uris": ["wiki://operations"]},
        )
        assert imported.status_code == 200, imported.text
        revision = imported.json()["revision"]
        library = client.get("/api/v1/knowledge/library").json()
        source = library["sources"][0]
        assert source["source_type"] == "mcp" and source["fresh"]
        enabled = client.put(
            "/api/v1/knowledge/library", json={"revision": revision, "enabled": True}
        ).json()
        revision = enabled["revision"]
        evidence = knowledge_retrieval.retrieve(
            db, tid, {"kind": "command", "command": {"text": "orbitctl refresh"}}
        )
        assert source["source_id"] in {
            doc["source_id"] for doc in evidence["documents"]
        }
        assert (
            client.post(
                "/api/v1/knowledge/sources/" + source["source_id"] + "/verify",
                json={
                    "revision": revision,
                    "generation": source["generation"],
                    "source_version": source["source_version"],
                },
            ).status_code
            == 400
        )
        # An invalid selected resource must not publish any part of a batch.
        state["text"] = "Orbitctl refresh has new operational guidance."
        failed = client.post(
            path + "/sync",
            json={"revision": revision, "uris": ["wiki://operations", "wiki://binary"]},
        )
        assert failed.status_code == 415, failed.text
        assert client.get("/api/v1/knowledge/library").json()["revision"] == revision
        state["fail"] = True
        failed = client.post(
            path + "/sync", json={"revision": revision, "uris": ["wiki://operations"]}
        )
        assert failed.status_code == 502 and "remote private failure" not in failed.text
        assert client.get("/api/v1/knowledge/library").json()["revision"] == revision
        state["fail"] = False
        updated = client.post(
            path + "/sync", json={"revision": revision, "uris": ["wiki://operations"]}
        )
        assert updated.status_code == 200, updated.text
        revision = updated.json()["revision"]
        db.execute(
            "UPDATE knowledge_sources SET fresh_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1",
            tid,
        )
        expired = knowledge_retrieval.retrieve(
            db, tid, {"kind": "command", "command": {"text": "orbitctl refresh"}}
        )
        assert not expired["documents"]
        renewed = client.post(
            path + "/sync", json={"revision": revision, "uris": ["wiki://operations"]}
        )
        assert renewed.status_code == 200, renewed.text
        revision = renewed.json()["revision"]
        assert (
            client.get("/api/v1/knowledge/library").json()["sources"][0][
                "source_version"
            ]
            != source["source_version"]
        )
        assert (
            client.post(path + "/sync", json={"revision": 0, "uris": []}).status_code
            == 409
        )
        client.cookies.set(auth.CONSOLE_COOKIE, session(db, other, "analyst"))
        assert client.get("/api/v1/knowledge/mcp").json()["connections"] == []
        assert client.post(path + "/resources", json={}).status_code == 404
        assert (
            client.post(path + "/disconnect", json={"revision": 0}).status_code == 404
        )
        client.cookies.set(auth.CONSOLE_COOKIE, viewer)
        assert client.get("/api/v1/knowledge/mcp").status_code == 403
        assert client.post(path + "/resources", json={}).status_code == 403
        assert (
            client.post(
                path + "/sync", json={"revision": revision, "uris": []}
            ).status_code
            == 403
        )
        client.cookies.set(auth.CONSOLE_COOKIE, admin)
        removed = client.post(path + "/disconnect", json={"revision": revision})
        assert removed.status_code == 200, removed.text
        assert client.get("/api/v1/knowledge/mcp").json()["connections"] == []
        assert (
            client.get("/api/v1/knowledge/library").json()["sources"][0]["status"]
            == "revoked"
        )
        assert evidence["documents"]
        assert token not in json.dumps(db.list_audit(tid)[0], default=str)


def test_mcp_network_limits_credentials_and_redirects(db, remote):
    origin, _ = remote
    tid = tenant(db)["id"]
    for endpoint in [
        "file:///tmp/private",
        "http://127.0.0.1:1/mcp",
        "https://localhost/mcp",
        "https://169.254.169.254/latest/meta-data",
        "https://user:pass@example.com/mcp",
        "https://example.com/mcp?token=private",
    ]:
        with pytest.raises(APIError):
            knowledge_mcp_transport.run(endpoint, "", "")
    cfg = Config(knowledge_mcp_private_origins=origin)
    with pytest.raises(APIError, match="OPENAIDR_KNOWLEDGE_MCP_KEY"):
        knowledge_mcp.connect(
            db,
            cfg,
            tid,
            {
                "revision": 0,
                "name": "Wiki",
                "endpoint": origin + "/mcp",
                "token": "secret",
            },
        )
    cfg.knowledge_mcp_key = Fernet.generate_key().decode()
    connected = knowledge_mcp.connect(
        db,
        cfg,
        tid,
        {"revision": 0, "name": "Wiki", "endpoint": origin + "/mcp", "token": "secret"},
    )
    cfg.knowledge_mcp_key = Fernet.generate_key().decode()
    with pytest.raises(APIError, match="credential cannot be read"):
        knowledge_mcp.resources(db, cfg, tid, connected["connection"]["connection_id"])

    async def boundaries():
        url = httpx2.URL("https://example.com/mcp")
        transport = knowledge_mcp_transport.PinnedTransport(url, "93.184.216.34")
        try:
            with pytest.raises(APIError, match="redirects"):
                await transport.handle_async_request(
                    httpx2.Request("GET", "https://example.com/private")
                )
            with pytest.raises(APIError, match="exceeds"):
                async for _ in knowledge_mcp_transport.LimitedStream(
                    httpx2.ByteStream(b"x" * ((1 << 20) + 1))
                ):
                    pass
        finally:
            await transport.aclose()

    asyncio.run(boundaries())


def test_mcp_pins_hostname_and_rejects_private_dns_and_compression(monkeypatch):
    async def check():
        url = httpx2.URL("https://wiki.example.com/mcp")
        transport = knowledge_mcp_transport.PinnedTransport(url, "93.184.216.34")
        requests = []
        compressed = False

        async def remote(request):
            requests.append(request)
            return httpx2.Response(
                200,
                headers={"content-encoding": "gzip"} if compressed else {},
                stream=httpx2.ByteStream(b"{}"),
            )

        original = transport.transport
        transport.transport = httpx2.MockTransport(remote)
        await original.aclose()
        try:
            response = await transport.handle_async_request(
                httpx2.Request("POST", url, content=b"{}")
            )
            await response.aclose()
            assert requests[0].url.host == "93.184.216.34"
            assert requests[0].headers["Host"] == "wiki.example.com"
            assert requests[0].extensions["sni_hostname"] == "wiki.example.com"
            compressed = True
            with pytest.raises(APIError, match="compressed"):
                await transport.handle_async_request(
                    httpx2.Request("POST", url, content=b"{}")
                )
        finally:
            await transport.aclose()
        for ip in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "224.0.0.1", "0.0.0.0"):
            monkeypatch.setattr(
                socket,
                "getaddrinfo",
                lambda *args, **kwargs: [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))
                ],
            )
            with pytest.raises(APIError, match="address is not allowed"):
                await knowledge_mcp_transport._run(url, False, "", None)
            if ip in ("169.254.169.254", "224.0.0.1", "0.0.0.0"):
                with pytest.raises(APIError, match="address is not allowed"):
                    await knowledge_mcp_transport._run(url, True, "", None)

    asyncio.run(check())


def test_mcp_deadline_does_not_wait_for_a_stalled_dns_resolver(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    failures = []
    original = knowledge_mcp_transport.anyio.fail_after
    monkeypatch.setattr(
        knowledge_mcp_transport.anyio, "fail_after", lambda _: original(0.05)
    )

    def resolve(*args, **kwargs):
        entered.set()
        release.wait(5)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)

    def request():
        try:
            knowledge_mcp_transport.run("https://wiki.example.com/mcp", "", "")
        except APIError as error:
            failures.append(error.status)

    worker = threading.Thread(target=request, daemon=True)
    worker.start()
    try:
        assert entered.wait(1)
        worker.join(timeout=1)
        assert not worker.is_alive(), "DNS outlived the request deadline"
        assert failures == [502]
    finally:
        release.set()
        worker.join(timeout=5)


@pytest.fixture
def tool_remote():
    from mcp.types import ToolAnnotations
    from starlette.middleware.base import BaseHTTPMiddleware

    state = {"calls": [], "headers": [], "text": "Release guide", "fail": False}
    server = MCPServer("Tools and templates")

    @server.tool(annotations=ToolAnnotations(read_only_hint=True))
    def get_page(page_id: str) -> dict:
        state["calls"].append(("get_page", page_id))
        if state["fail"]:
            raise ValueError("private upstream failure")
        return {"title": state["text"], "body": "Production routing " + page_id}

    @server.tool()
    def search(query: str) -> str:
        state["calls"].append(("search", query))
        return "Search results: " + query

    @server.tool(annotations=ToolAnnotations(read_only_hint=False))
    def update_page() -> str:
        state["calls"].append(("update_page", ""))
        return "updated"

    @server.tool(annotations=ToolAnnotations(destructive_hint=True))
    def delete_page() -> str:
        state["calls"].append(("delete_page", ""))
        return "deleted"

    @server.resource("wiki://pages/{page_id}")
    def page(page_id: str) -> str:
        state["calls"].append(("template", page_id))
        return "Page " + page_id + ": " + state["text"]

    app = server.streamable_http_app(json_response=True)

    async def capture(request, call_next):
        state["headers"].append(dict(request.headers))
        return await call_next(request)

    app.add_middleware(BaseHTTPMiddleware, dispatch=capture)
    with serve(app) as origin:
        yield origin, state, server


def test_mcp_tool_and_template_imports_are_explicit_atomic_and_repeatable(db, tool_remote):
    import base64

    origin, state, server = tool_remote
    tid, other = tenant(db)["id"], tenant(db)["id"]
    cfg = Config(knowledge_mcp_key=Fernet.generate_key().decode(), knowledge_mcp_private_origins=origin)
    cfg.set_services("api")
    with TestClient(create_app(cfg, db), headers={auth.CSRF_HEADER: "1"}) as client:
        admin = session(db, tid, "analyst")
        client.cookies.set(auth.CONSOLE_COOKIE, admin)
        connected = client.post("/api/v1/knowledge/mcp", json={
            "revision": 0, "name": "Wiki tools", "endpoint": origin + "/mcp?tools=all",
            "auth": {"type": "basic", "username": "admin@example.com", "password": "private-api-token"},
        })
        assert connected.status_code == 200, connected.text
        result = connected.json()
        assert result["resources"] == []
        assert len(result["templates"]) == 1 and len(result["tools"]) == 4
        assert state["calls"] == [], "Discovery must never run tools or read template content"
        expected_auth = "Basic " + base64.b64encode(b"admin@example.com:private-api-token").decode()
        assert all(headers["authorization"] == expected_auth for headers in state["headers"])
        ident = result["connection"]["connection_id"]
        path = "/api/v1/knowledge/mcp/" + ident
        revision = result["revision"]
        tools = {item["name"]: item for item in result["tools"]}
        source = {"kind": "tool", "name": "get_page", "arguments": {"page_id": "123"}, "schema_hash": tools["get_page"]["schema_hash"]}
        template = {"kind": "template", "uri_template": "wiki://pages/{page_id}", "parameters": {"page_id": "456"}}
        for name in ("update_page", "delete_page"):
            assert not tools[name]["can_import"]
            denied = client.post(path + "/preview", json={"source": {**source, "name": name, "arguments": {}, "schema_hash": tools[name]["schema_hash"]}})
            assert denied.status_code == 400, denied.text
        stale = client.post(path + "/preview", json={"source": {**source, "schema_hash": "outdated"}})
        assert stale.status_code == 409
        assert state["calls"] == []
        # The server can change a tool after the user selected it.
        server.remove_tool("search")

        @server.tool(name="search", description="Changed search contract")
        def search(query: str) -> str:
            state["calls"].append(("search", query))
            return "Search results: " + query

        changed = client.post(path + "/preview", json={"source": {**source, "name": "search", "arguments": {"query": "routing"}, "schema_hash": tools["search"]["schema_hash"]}})
        assert changed.status_code == 409
        assert state["calls"] == []
        tools = {item["name"]: item for item in client.post(path + "/resources", json={}).json()["tools"]}
        preview = client.post(path + "/preview", json={"source": source})
        assert preview.status_code == 200, preview.text
        assert "Release guide" in preview.json()["document"]["text"]
        assert preview.json()["document"]["name"] == "Release guide"
        assert db.scalar("SELECT count(*) FROM knowledge_sources WHERE tenant_id=$1", tid) == 0
        assert knowledge_ingest.settings(db, tid)["revision"] == revision
        assert client.post(path + "/preview", json={"source": source}, headers={auth.CSRF_HEADER: ""}).status_code == 403
        client.cookies.set(auth.CONSOLE_COOKIE, session(db, tid, "viewer"))
        assert client.post(path + "/preview", json={"source": source}).status_code == 403
        client.cookies.set(auth.CONSOLE_COOKIE, session(db, other, "analyst"))
        assert client.post(path + "/preview", json={"source": source}).status_code == 404
        client.cookies.set(auth.CONSOLE_COOKIE, admin)
        imported = client.post(path + "/sync", json={"revision": revision, "imports": [source, template]})
        assert imported.status_code == 200, imported.text
        assert imported.json()["imported"] == 2
        revision = imported.json()["revision"]
        listed = client.get("/api/v1/knowledge/mcp").json()["connections"][0]
        assert listed["imports"] == [source, template]
        assert listed["auth_type"] == "basic"
        assert "private-api-token" not in json.dumps(listed)
        state["text"] = "Updated release guide"
        refreshed = client.post(path + "/sync", json={"revision": revision, "imports": listed["imports"]})
        assert refreshed.status_code == 200, refreshed.text
        revision = refreshed.json()["revision"]
        state["fail"] = True
        failed = client.post(path + "/sync", json={"revision": revision, "imports": [template, source]})
        assert failed.status_code == 502 and "private upstream" not in failed.text
        assert knowledge_ingest.settings(db, tid)["revision"] == revision
        assert client.get("/api/v1/knowledge/mcp").json()["connections"][0]["imports"] == [source, template]
        assert db.scalar("SELECT count(*) FROM knowledge_sources WHERE tenant_id=$1 AND status='current'", tid) == 2
        state["fail"] = False
        # Tools without annotations remain available through an explicit selection.
        search = {"kind": "tool", "name": "search", "arguments": {"query": "routing"}, "schema_hash": tools["search"]["schema_hash"]}
        assert client.post(path + "/preview", json={"source": search}).status_code == 200
        removed = client.post(path + "/sync", json={"revision": revision, "imports": []})
        assert removed.status_code == 200
        assert db.scalar("SELECT count(*) FROM knowledge_sources WHERE tenant_id=$1 AND status='current'", tid) == 0
        assert all(name not in ("update_page", "delete_page") for name, _ in state["calls"])
        assert "private-api-token" not in json.dumps(db.list_audit(tid)[0], default=str)
        encrypted = db.scalar("SELECT encrypted_token FROM knowledge_mcp_connections WHERE tenant_id=$1", tid)
        assert "private-api-token" not in encrypted


def test_mcp_custom_auth_and_import_validation(db, tool_remote):
    origin, state, _ = tool_remote
    tid = tenant(db)["id"]
    cfg = Config(knowledge_mcp_key=Fernet.generate_key().decode(), knowledge_mcp_private_origins=origin)
    body = {"revision": 0, "name": "Wiki", "endpoint": origin + "/mcp", "auth": {"type": "header", "name": "X-API-Key", "value": "private-key"}}
    connected = knowledge_mcp.connect(db, cfg, tid, body)
    assert all(headers["x-api-key"] == "private-key" for headers in state["headers"])
    for header in ("Host", "Content-Type", "Mcp-Session-Id", "Accept-Encoding", "Cookie", "Proxy-Authorization", "Bad\r\nHeader"):
        with pytest.raises(APIError):
            knowledge_mcp.connect(db, cfg, tid, {**body, "auth": {**body["auth"], "name": header}})
    for credentials in ({"type": "basic", "username": "bad:name", "password": "p"}, {"type": "bearer", "token": "bad\nvalue"}, {"type": "none", "token": "private"}):
        with pytest.raises(APIError):
            knowledge_mcp.connect(db, cfg, tid, {**body, "auth": credentials})
    tool = next(item for item in connected["tools"] if item["name"] == "get_page")
    source = {"kind": "tool", "name": "get_page", "arguments": {"page_id": "1"}, "schema_hash": tool["schema_hash"]}
    ident = connected["connection"]["connection_id"]
    for arguments in ([], {"token": "private"}, {"page_id": "x" * 33000}, {"page_id": float("nan")}):
        with pytest.raises(APIError):
            knowledge_mcp.preview(db, cfg, tid, ident, {"source": {**source, "arguments": arguments}})
    assert state["calls"] == []
    for query in ("api_key=abc", "password=abc", "access_token=abc", "Authorization=abc"):
        with pytest.raises(APIError):
            knowledge_mcp_transport.endpoint("https://example.com/mcp?" + query, "")
    assert str(knowledge_mcp_transport.endpoint("https://example.com/mcp?tools=all", "")[0]).endswith("?tools=all")


def test_mcp_legacy_credentials_and_selection_migrate(db, remote):
    from pathlib import Path

    origin, state = remote
    tid = tenant(db)["id"]
    cfg = Config(knowledge_mcp_key=Fernet.generate_key().decode(), knowledge_mcp_private_origins=origin)
    connected = knowledge_mcp.connect(db, cfg, tid, {"revision": 0, "name": "Legacy", "endpoint": origin + "/mcp", "token": "legacy-token"})
    ident = connected["connection"]["connection_id"]
    # Reconstruct the stored shape used before this migration.
    encrypted = Fernet(cfg.knowledge_mcp_key.encode()).encrypt(json.dumps([tid, ident, "legacy-token"]).encode()).decode()
    db.execute("UPDATE knowledge_mcp_connections SET encrypted_token=$2,resource_uris='[\"wiki://operations\"]' WHERE tenant_id=$1", tid, encrypted)
    db.execute("ALTER TABLE knowledge_mcp_connections DROP COLUMN auth_type, DROP COLUMN imports")
    migration = Path(knowledge_mcp.__file__).parent / "migrations/0047_mcp_imports.sql"
    with db.transaction() as conn:
        conn.execute(migration.read_text())
    connection = knowledge_mcp.list_connections(db, tid)["connections"][0]
    assert connection["auth_type"] == "bearer"
    assert connection["imports"] == [{"kind": "resource", "uri": "wiki://operations"}]
    result = knowledge_mcp.sync(db, cfg, tid, ident, {"revision": connected["revision"], "imports": connection["imports"]})
    assert result["imported"] == 1
    assert all(value == "Bearer legacy-token" for value in state["auth"])


@pytest.mark.parametrize("token", ["", "legacy-token"])
def test_mcp_legacy_writes_after_migration_keep_latest_selection(db, token):
    from openaidr.server.store import new_id

    server = MCPServer("Legacy wiki")

    @server.resource("wiki://a", mime_type="text/plain")
    def page_a():
        return "Original operations guide"

    @server.resource("wiki://b", mime_type="text/plain")
    def page_b():
        return "Replacement operations guide"

    tid, ident = tenant(db)["id"], new_id()
    with serve(server.streamable_http_app(json_response=True)) as origin:
        cfg = Config(knowledge_mcp_key=Fernet.generate_key().decode(), knowledge_mcp_private_origins=origin)
        encrypted = Fernet(cfg.knowledge_mcp_key.encode()).encrypt(json.dumps([tid, ident, token]).encode()).decode() if token else ""
        # Old replicas omit both new columns, including after migration or rollback.
        with db.transaction() as conn:
            knowledge_ingest._lock(db, tid, conn, 0)
            db.execute(
                "INSERT INTO knowledge_mcp_connections(tenant_id,connection_id,name,endpoint,encrypted_token) "
                "VALUES($1,$2,$3,$4,$5)", tid, ident, "Legacy", origin + "/mcp", encrypted, conn=conn,
            )
            knowledge_ingest._bump(db, tid, conn)
        for uris in (["wiki://a"], ["wiki://b"], []):
            previous_imports = db.scalar("SELECT imports FROM knowledge_mcp_connections WHERE connection_id=$1", ident)
            knowledge_mcp.sync(db, cfg, tid, ident, {
                "revision": knowledge_ingest.settings(db, tid)["revision"], "uris": uris,
            })
            # Reconstruct a legacy sync: corpus and resource_uris change, imports does not.
            db.execute(
                "UPDATE knowledge_mcp_connections SET imports=$2::jsonb WHERE connection_id=$1",
                ident, json.dumps(previous_imports),
            )
            listed = knowledge_mcp.list_connections(db, tid)
            connection = listed["connections"][0]
            assert connection["auth_type"] == ("bearer" if token else "none")
            assert connection["has_token"] == bool(token)
            assert connection["imports"] == [{"kind": "resource", "uri": uri} for uri in uris]
            refreshed = knowledge_mcp.sync(db, cfg, tid, ident, {
                "revision": listed["revision"], "imports": connection["imports"],
            })
            assert refreshed["imported"] == len(uris)
            assert {
                row["source_id"] for row in db.many(
                    "SELECT source_id FROM knowledge_sources WHERE tenant_id=$1 AND status='current'", tid,
                )
            } == {knowledge_mcp._source_id(ident, uri) for uri in uris}


def test_mcp_connects_to_a_tool_only_server():
    server = MCPServer("Tool only")
    calls = []

    @server.tool(structured_output=False)
    def read_wiki() -> str:
        calls.append(True)
        return "Operations guide"

    with serve(server.streamable_http_app(json_response=True)) as origin:
        catalog = knowledge_mcp_transport.run(origin + "/mcp", "", origin)
        assert not catalog["resources"] and not catalog["templates"]
        assert [item["name"] for item in catalog["tools"]] == ["read_wiki"]
        assert calls == []
        tool = catalog["tools"][0]
        documents = knowledge_mcp_transport.run(origin + "/mcp", "", origin, [{"kind": "tool", "name": tool["name"], "arguments": {}, "schema_hash": tool["schema_hash"]}])
        assert len(documents) == 1 and documents[0]["text"] == "Operations guide"
        assert calls == [True]
