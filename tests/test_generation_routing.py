"""Tenant permissions, caches and accounting across the shared HTTP boundary."""

from openaidr_api.providers import overview_summary as provider_overview, session_activity_summaries as provider_summaries

import asyncio
from contextlib import contextmanager
import copy
from dataclasses import replace
import json
import threading
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from openaidr_api.app import Config as APIConfig, create_app as create_api
from openaidr_api.threat_intel import keys
from openaidr.server import overview_summary, session_activity_summaries as summaries
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server.app import Service
from openaidr_api_client.client import Connection
from openaidr.server.page_chat import PageChat
from openaidr.server.service_costs import response_usage
from intelligence_service_fixtures import ProviderStream, event, overview_result, provider_answer
from test_rule_authoring import BASE, draft
from test_server_e2e import chat_system, system  # noqa: F401
from test_session_activity_summaries import summary_system, activity  # noqa: F401
from test_ordinary_session_detection import captured
from test_store import db  # noqa: F401


@contextmanager
def shared_service(tenant, tmp_path, monkeypatch, origin="https://local-intelligence.test"):
    database = tmp_path / "keys.sqlite3"
    keys.initialize(database)
    key_file = tmp_path / "tenant.key"
    keys.issue(database, tenant, key_file)
    credential = key_file.read_text().strip()
    remote = SimpleNamespace(connection=Connection(origin, credential, tenant),
        requests=[], origins={origin}, upstream=[], override=None, lost=False, status=200, stream=None, key_file=key_file,
        database=database, answer="Captured Jev evidence stays unchanged.", source_override=None)

    async def provider(request):
        if str(request.url) == "https://api.osv.dev/v1/querybatch":
            return httpx.Response(200, json={"results": [{}]})
        assert str(request.url) == "https://api.openai.com/v1/responses"
        assert request.headers["authorization"] == "Bearer service-only-provider-key"
        body = json.loads(request.content)
        remote.upstream.append(body)
        answer = remote.answer
        if body["instructions"] == provider_overview.INSTRUCTIONS:
            sources = json.loads(body["input"][0]["content"].split("\n", 1)[1])
            answer = json.dumps(overview_result(remote.source_override or sources[0]["id"]))
        elif body["instructions"] == provider_summaries.INSTRUCTIONS:
            answer = json.dumps({"summary": "Inspected the captured work."})
        elif body.get("text", {}).get("format", {}).get("name") == "fixed_rule_draft":
            answer = json.dumps({"status": "draft", **{k: v for k, v in draft().items() if k != "intent"}})
        result = provider_answer(answer)
        if body.get("stream"):
            return httpx.Response(200, stream=ProviderStream([
                event({"type": "response.output_text.delta", "delta": answer, "output_index": 0, "content_index": 0}),
                event({"type": "response.completed", "response": result}),
            ]))
        return httpx.Response(200, json=result)

    app = create_api(APIConfig(str(database), openai_key="service-only-provider-key"), transport=httpx.MockTransport(provider))

    async def boundary(_transport, request):
        assert str(request.url).startswith(tuple(value + "/v1/" for value in remote.origins)), "Selected tenant bypassed the service"
        if request.url.path != "/v1/credits":
            remote.requests.append(request)
        if remote.stream is not None:
            return httpx.Response(200, stream=remote.stream, headers={"Content-Type": "text/event-stream"})
        if remote.override is not None or remote.status != 200:
            return httpx.Response(remote.status, json=remote.override or {"error": "unavailable"})
        result = await httpx.ASGITransport(app=app).handle_async_request(request)
        if remote.lost:
            await result.aclose()
            raise httpx.ReadTimeout("service response lost")
        return result

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", boundary)
    with TestClient(app):
        yield remote
    assert not app.state.generation_admission.active


@pytest.fixture
def selected(chat_system, tmp_path, monkeypatch):
    client, st, app, tenant, user, direct, _, payload = chat_system
    with shared_service(tenant, tmp_path, monkeypatch) as remote:
        selected_config = replace(app.state.service.cfg, tenant_id=tenant,
                                  intelligence_origin=remote.connection.origin,
                                  intelligence_api_key=remote.connection.api_key)
        app.state.service.cfg = selected_config
        app.state.service.page_chat = Service(selected_config, st).page_chat
        yield SimpleNamespace(client=client, st=st, service=app.state.service, tenant=tenant,
                              user=user, direct=direct, payload=payload, remote=remote)
    assert not direct


def test_legacy_threat_connection_cannot_enable_model_requests(chat_system):
    _, st, app, tenant, _, sent, _, _ = chat_system
    config = replace(app.state.service.cfg, tenant_id=tenant, intelligence_origin="", intelligence_api_key="",
                     threat_intel_origin="https://legacy-intelligence.test",
                     threat_intel_api_key="oati_" + "a" * 32 + "." + "b" * 43)
    with pytest.raises(ValueError, match="Replace legacy"):
        Service(config, st)
    assert not sent


def test_workspace_switch_routes_existing_clients_and_persists_across_processes(selected, intelligence_environments):
    from contextlib import closing
    from openaidr.server import model_keys, remote_investigator, skill_llm
    from openaidr.server.intelligence import ORIGINS, WorkspaceThreatIntelClient
    from openaidr.server.store import Store

    s = selected
    test_origin, production = ORIGINS
    s.remote.origins.update(ORIGINS)
    s.service.cfg.intelligence_origin = test_origin
    from intelligence_service_fixtures import store_environment_key
    store_environment_key(s.st, s.service.cfg, production, s.service.cfg.intelligence_api_key)
    s.st.update_user(s.tenant, s.user["id"], role="owner")
    other_process = Store(s.st.url)
    runner = asyncio.Runner()
    threat = WorkspaceThreatIntelClient(other_process, s.service.cfg)
    pinned = remote_investigator.runtime(other_process, s.service.cfg)
    try:
        other_chat = Service(s.service.cfg, other_process).page_chat
        first_identity = other_chat.cache_identity(s.tenant)
        for version, origin in enumerate((test_origin, production, test_origin)):
            if version:
                switched = s.client.put("/api/v1/settings/intelligence", json={"origin": origin, "version": version - 1})
                assert switched.status_code == 200, switched.text
                assert switched.headers["cache-control"] == "no-store"
            response = s.client.get("/api/v1/settings/model-keys")
            assert response.json()["routing"]["origin"] == origin
            assert response.json()["routing"]["version"] == version
            checked = s.client.post("/api/v1/settings/intelligence/check", json={})
            assert checked.status_code == 200 and checked.json()["origin"] == origin
            assert s.client.post("/api/v1/chat", json=s.payload).status_code == 200
            assert str(s.remote.requests[-1].url) == origin + "/v1/assistant/respond"
            assert other_chat.connection.origin == origin
            assert (other_chat.cache_identity(s.tenant) == first_identity) is (origin == test_origin)
            assert model_keys.guardrail_credential(other_process, s.tenant, s.service.cfg).origin == origin
            assert skill_llm.model_connection(s.service.cfg, s.tenant, other_process).origin == origin
            with closing(remote_investigator.runtime(other_process, s.service.cfg)) as runtime:
                assert runtime.connection.origin == origin
                runtime.ready()
                assert str(s.remote.requests[-1].url) == origin + "/v1/investigations/runtime"
            assert pinned.connection.origin == test_origin

            results = runner.run(threat.packages([{"package": {"ecosystem": "npm", "name": "example"}, "version": "1.0.0"}]))
            assert results[0]["status"] == "complete"
            assert str(s.remote.requests[-1].url) == origin + "/v1/packages/check"
        assert s.st.scalar("SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='intelligence.service.select'", s.tenant) == 2
    finally:
        pinned.close()
        runner.run(threat.aclose())
        runner.close()
        other_process.close()


@pytest.mark.parametrize("streaming", [False, True])
def test_selected_assistant_needs_no_tenant_provider_key_and_preserves_rbac_usage(selected, streaming):
    s = selected
    assert not s.st.scalar("SELECT count(*) FROM tenant_model_keys WHERE tenant_id=$1", s.tenant)
    headers = {"Accept": "text/event-stream"} if streaming else {}
    result = s.client.post("/api/v1/chat", json=s.payload, headers=headers)
    assert result.status_code == 200, result.text
    expected = s.remote.answer
    if streaming:
        events = [json.loads(line[6:]) for line in result.text.splitlines() if line.startswith("data: ")]
        assert events == [{"type": "delta", "text": expected}, {"type": "done", "answer": expected}]
    else:
        assert result.json() == {"answer": expected}
    assert len(s.remote.upstream) == 1
    assert s.remote.requests[0].headers["authorization"] == "Bearer " + s.remote.connection.api_key
    body = json.loads(s.remote.requests[0].content)
    assert set(body) == {"page", "messages", "timeout_ms", *( ["stream"] if streaming else [])}
    usage = s.st.many("SELECT status,input_tokens,output_tokens FROM model_usage WHERE tenant_id=$1", s.tenant)
    assert usage == [{"status": "completed", "input_tokens": 123, "output_tokens": 10}]
    forbidden = {**s.payload, "page": {**s.payload["page"], "path": "/administration/users"}}
    s.st.update_user(s.tenant, s.user["id"], role="analyst")
    assert s.client.post("/api/v1/chat", json=forbidden, headers=headers).status_code == 403
    s.client.cookies.clear()
    assert s.client.post("/api/v1/chat", json=s.payload, headers=headers).status_code == 401
    assert len(s.remote.requests) == 1


def test_selected_failures_never_use_present_direct_keys_and_preserve_known_usage(selected):
    s = selected
    s.service.cfg.openai_api_key = "test-provider-key"
    s.st.execute("INSERT INTO tenant_model_keys(tenant_id,kind,api_key) VALUES($1,'detection','test-provider-key')", s.tenant)
    s.remote.status = 503
    assert s.client.post("/api/v1/chat", json=s.payload).status_code == 502
    assert not s.remote.upstream
    s.remote.status, s.remote.lost = 200, True
    assert s.client.post("/api/v1/chat", json=s.payload).status_code == 504
    assert len(s.remote.upstream) == 1
    s.remote.override = {"status": "completed", "result": {"answer": ""}, "usage": response_usage(provider_answer())}
    assert s.client.post("/api/v1/chat", json=s.payload).status_code == 502
    rows = s.st.many("SELECT status,input_tokens FROM model_usage WHERE tenant_id=$1 ORDER BY started_at", s.tenant)
    assert rows == [{"status": "error", "input_tokens": None}, {"status": "error", "input_tokens": None},
                    {"status": "error", "input_tokens": 123}]
    assert len(s.remote.requests) == 3 and not s.direct


def test_tenant_mismatch_cannot_use_shared_credential(selected):
    s = selected
    other = s.st.bootstrap_tenant("Other", "other-" + s.tenant[:8])["tenant"]["id"]
    user = s.st.create_user(other, "other@example.test", "Other", "unused", "viewer")
    s.client.cookies.set(CONSOLE_COOKIE, s.st.create_session(user["id"], other))
    assert s.client.post("/api/v1/chat", json=s.payload).status_code == 403
    assert not s.remote.requests
    assert not s.st.scalar("SELECT count(*) FROM model_usage WHERE tenant_id=$1", other)


@pytest.mark.parametrize("operation", ["answer", "stream", "overview", "rule"])
def test_generation_keeps_admitted_connection_when_selection_changes(selected, operation):
    s = selected
    first = s.remote.connection
    changed = replace(first, origin="https://other-intelligence.test")
    s.remote.origins.add(changed.origin)
    selections = []

    def select():
        connection = first if not selections else changed
        selections.append(connection)
        return connection

    s.service.page_chat._connection_factory = select
    if operation in ("answer", "stream"):
        headers = {"Accept": "text/event-stream"} if operation == "stream" else {}
        response = s.client.post("/api/v1/chat", json=s.payload, headers=headers)
    elif operation == "overview":
        response = s.client.post("/api/v1/overview/summary", json={})
    else:
        s.st.update_user(s.tenant, s.user["id"], role="analyst")
        response = s.client.post(BASE + "/generate", json={"intent": draft()["intent"]})
    assert response.status_code == 200, response.text
    assert selections == [first]
    assert len(s.remote.requests) == 1
    assert str(s.remote.requests[0].url).startswith(first.origin + "/v1/")
    if operation == "overview":
        assert s.client.get("/api/v1/overview/summary").json()["summary"] is None
        s.service.page_chat.connection = first
        assert s.client.get("/api/v1/overview/summary").json()["summary"] == response.json()


@pytest.mark.parametrize("streaming", [False, True])
def test_captured_unavailable_connection_does_not_reselect(selected, streaming):
    s = selected
    selections = []

    def select():
        value = None if not selections else s.remote.connection
        selections.append(value)
        return value

    s.service.page_chat._connection_factory = select
    response = s.client.post("/api/v1/chat", json=s.payload,
                             headers={"Accept": "text/event-stream"} if streaming else {})
    assert response.status_code == (200 if streaming else 503)
    if streaming:
        assert '"type": "error"' in response.text
    assert selections == [None]
    assert not s.remote.requests


def test_overview_cache_and_background_refresh_keep_permissions_and_connection_identity(selected):
    s = selected
    first = s.client.post("/api/v1/overview/summary", json={})
    assert first.status_code == 200, first.text
    assert s.client.get("/api/v1/overview/summary").json() == {"summary": first.json(), "stale": False}
    assert len(s.remote.requests) == 1
    source_paths = {source["path"] for source in first.json()["sources"]}
    assert "/administration/users" not in source_paths
    s.st.update_user(s.tenant, s.user["id"], role="owner")
    assert s.client.get("/api/v1/overview/summary").json()["summary"] is None
    s.st.execute("UPDATE overview_summaries SET refresh_after=now() WHERE tenant_id=$1", s.tenant)
    overview_summary.refresh_due(s.service, threading.Event())
    assert s.client.get("/api/v1/overview/summary").json()["summary"] is not None
    assert len(s.remote.requests) == 2
    old = s.remote.connection
    rotated = s.remote.key_file.with_name("rotated.key")
    keys.issue(s.remote.database, s.tenant, rotated)
    s.service.page_chat.connection = Connection(old.origin, rotated.read_text().strip(), s.tenant)
    assert s.client.get("/api/v1/overview/summary").json()["summary"] is None
    assert s.client.post("/api/v1/overview/summary", json={}).status_code == 200
    s.remote.source_override = "foreign-source"
    assert s.client.post("/api/v1/overview/summary", json={"refresh": True}).status_code == 502
    assert s.client.get("/api/v1/overview/summary").json()["summary"] is not None


def test_remote_rule_is_revalidated_and_still_needs_explicit_save_and_enable(selected):
    s = selected
    s.st.update_user(s.tenant, s.user["id"], role="analyst")
    original = s.st.get_policy(s.tenant)
    generated = s.client.post(BASE + "/generate", json={"intent": draft()["intent"]})
    assert generated.status_code == 200 and generated.json()["draft"] == draft()
    assert s.st.get_policy(s.tenant) == original
    value = generated.json()["draft"]
    assert s.client.post(BASE + "/preview", json={"version": original["version"], "draft": value, "rule_id": ""}).json()["passed"]
    saved = s.client.post(BASE + "/drafts", json={"version": original["version"], "draft": value})
    assert saved.status_code == 200 and saved.json()["policy"]["rules"][-1]["enabled"] is False
    bad = copy.deepcopy(value)
    bad["rule"]["enabled"] = True
    s.remote.override = {"status": "completed", "result": {"status": "draft", "draft": bad},
                         "usage": response_usage(provider_answer())}
    assert s.client.post(BASE + "/generate", json={"intent": value["intent"]}).status_code == 502
    bad["rule"].pop("enabled")
    bad["intent"] = "different intent"
    assert s.client.post(BASE + "/generate", json={"intent": value["intent"]}).status_code == 502
    assert len(s.remote.upstream) == 1


@pytest.mark.parametrize("origin", ["https://local-intelligence.test", "https://api.opensecura.ai"])
def test_session_worker_uses_selected_service_without_provider_key_and_scopes_cache(summary_system, tmp_path, monkeypatch, origin):
    s = summary_system
    s.cfg.openai_api_key = ""
    with shared_service(s.tenant["id"], tmp_path, monkeypatch, origin) as remote:
        s.app.state.service.page_chat = PageChat(s.db, connection=remote.connection)
        captured(s, (89, 70))
        assert activity(s)[0]["activity_summary"]["state"] == "pending"
        job = summaries.claim(s.db, s.tenant["id"])
        assert job["key_fingerprint"] == remote.connection.fingerprint()
        selections = []

        def select():
            value = remote.connection if not selections else replace(remote.connection, origin="https://other-intelligence.test")
            selections.append(value)
            return value

        s.app.state.service.page_chat._connection_factory = select
        summaries.generate(s.app.state.service, job)
        assert selections == [remote.connection]
        s.app.state.service.page_chat.connection = remote.connection
        assert activity(s, refresh=False)[0]["activity_summary"]["text"] == "Inspected the captured work."
        assert len(remote.requests) == 1
        assert s.db.scalar("SELECT count(*) FROM model_usage WHERE tenant_id=$1 AND status='completed'", s.tenant["id"]) == 1
        captured(s, (90,), device="foreign_sensor")
        assert activity(s, user="foreign")[0]["activity_summary"]["state"] == "unavailable"
        assert len(remote.requests) == 1
        old = remote.connection
        s.app.state.service.page_chat.connection = Connection("https://other-intelligence.test", old.api_key, old.tenant_id)
        assert activity(s, refresh=False)[0]["activity_summary"]["state"] == "pending"
        summaries.generate(s.app.state.service, job)
        assert activity(s, refresh=False)[0]["activity_summary"]["text"] is None
        assert len(remote.requests) == 1 and not s.provider["sent"]


def test_interrupted_remote_stream_closes_client_and_records_unknown_usage(selected):
    s = selected
    s.remote.stream = ProviderStream([event({"type": "delta", "text": "partial"})])
    reply = s.client.post("/api/v1/chat", json=s.payload, headers={"Accept": "text/event-stream"})
    events = [json.loads(line[6:]) for line in reply.text.splitlines() if line.startswith("data: ")]
    assert events[0] == {"type": "delta", "text": "partial"} and events[-1]["type"] == "error"
    assert s.remote.stream.closed
    assert s.st.many("SELECT status,input_tokens FROM model_usage WHERE tenant_id=$1", s.tenant) == [
        {"status": "error", "input_tokens": None}]


def test_cancelled_remote_stream_closes_provider_and_releases_admission(selected):
    s = selected
    s.remote.stream = ProviderStream([event({"type": "delta", "text": "partial"})], block=True)

    async def scenario():
        stream = s.service.page_chat.stream(s.tenant, s.payload)
        assert '"text": "partial"' in await anext(stream)
        await stream.aclose()

    asyncio.run(scenario())
    assert s.remote.stream.closed
    assert s.service.page_chat._slots.acquire(blocking=False)
    s.service.page_chat._slots.release()
    assert s.st.many("SELECT status,input_tokens FROM model_usage WHERE tenant_id=$1", s.tenant) == [
        {"status": "error", "input_tokens": None}]


def test_downstream_disconnect_closes_suspended_stream_and_finishes_accounting(selected):
    s = selected
    s.remote.stream = ProviderStream([event({"type": "delta", "text": "partial"})], block=True)
    request = s.client.build_request("POST", "/api/v1/chat", json=s.payload, headers={"Accept": "text/event-stream"})

    async def scenario():
        delivered, partial = False, False
        sent = []

        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": request.content}
            await asyncio.Event().wait()

        async def send(message):
            nonlocal partial
            sent.append(message)
            if b"partial" in message.get("body", b""):
                partial = True
                raise OSError("downstream disconnected")

        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"}, "http_version": "1.1",
                 "method": "POST", "path": "/api/v1/chat", "query_string": b"",
                 "headers": [(name.lower(), value) for name, value in request.headers.raw],
                 "scheme": "http", "server": ("testserver", 80), "client": ("127.0.0.1", 1234)}
        try:
            await asyncio.wait_for(s.client.app(scope, receive, send), 3)
        except Exception:
            assert partial
        assert partial, sent

    asyncio.run(scenario())
    assert s.remote.stream.closed
    assert s.st.many("SELECT status,input_tokens FROM model_usage WHERE tenant_id=$1", s.tenant) == [
        {"status": "error", "input_tokens": None}]
    for _ in range(4):
        assert s.service.page_chat._slots.acquire(blocking=False)
    assert not s.service.page_chat._slots.acquire(blocking=False)
    for _ in range(4):
        s.service.page_chat._slots.release()
