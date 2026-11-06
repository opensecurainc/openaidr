"""Real HTTP/SQL coverage for the Overview summary authorization boundary."""

import asyncio
from dataclasses import replace
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError

import httpx
import pytest
from fastapi.testclient import TestClient

from openaidr.server.app import create_app
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server.config import Config
from openaidr.server.overview_summary import SOURCES
from openaidr.server.permissions import page_allowed
from test_server_e2e import chat_system, system  # noqa: F401


def summary_reply(provider, citations=None, **item):
    provider["body"]["output"] = [{"type": "message", "role": "assistant", "content": [{
        "type": "output_text", "text": json.dumps({"items": [{
            "topic": "Findings", "headline": "0", "caption": "open or triaged findings",
            "text": "No open findings were reported.",
            "detail": "The captured aggregate reports zero open or triaged findings.",
            "tone": "neutral", "citations": citations or ["1"], **item,
        }]}),
    }]}]


def test_summary_collects_real_authorized_sources_and_excludes_credentials(chat_system):
    client, st, app, tenant, user, sent, provider, _ = chat_system
    # Retained tenant provider keys must not enter the authorized context.
    st.execute("INSERT INTO tenant_model_keys(tenant_id,kind,api_key) VALUES($1,'detection',$2)",
               tenant, "test-provider-key")
    st.execute("INSERT INTO tenant_company_policies(tenant_id,prompt) VALUES($1,$2)",
               tenant, "private policy content must not reach the summary provider")
    summary_reply(provider)
    for role in ("viewer", "admin", "analyst", "owner"):
        st.update_user(tenant, user["id"], role=role)
        assert client.get("/api/v1/overview/summary").json() == {"summary": None, "stale": True}
        result = client.post("/api/v1/overview/summary", json={})
        assert result.status_code == 200, result.text
        data = result.json()
        source_paths = {source["path"] for source in data["sources"]}
        expected = {path for path, *_ in SOURCES if page_allowed({"role": role}, path)}
        assert source_paths == expected
        assert "/costs/detections" not in source_paths
        assert ("/costs/openaidr" in source_paths) == (role != "analyst")
        # Every configured projection is exercised against an actual empty tenant.
        unavailable = [s["title"] for s in data["sources"] if s["status"] != "available"]
        assert unavailable == [], unavailable
        assert all(source["captured_at"] and source["scope"] for source in data["sources"])
        assert result.headers["cache-control"] == "no-store"
        assert sent[-1]["store"] is False and sent[-1]["tools"] == []
        payload = json.dumps(sent[-1])
        for private in ("Private tenant name", "Private user name", user["email"],
                        "test-provider-key", "private policy content"):
            assert private not in payload
        assert "CURRENT_PAGE" not in payload
        assert len(sent) == ("viewer", "admin", "analyst", "owner").index(role) + 1
        # A navigation reload reuses only the same tenant/role cache.
        cached = client.post("/api/v1/overview/summary", json={})
        assert cached.json() == data
        saved = client.get("/api/v1/overview/summary")
        assert saved.json() == {"summary": data, "stale": False}
        assert saved.headers["cache-control"] == "no-store"
        assert len(sent) == ("viewer", "admin", "analyst", "owner").index(role) + 1
    assert st.scalar("SELECT count(*) FROM model_usage WHERE tenant_id=$1 AND purpose='assistant' AND status='completed'", tenant) == 4
    other = st.bootstrap_tenant("Other tenant", "other-" + tenant[:8])["tenant"]["id"]
    other_user = st.create_user(other, "other@example.test", "Other", "unused", "owner")
    st.create_user(other, "second@example.test", "Second", "unused", "owner")
    client.cookies.set(CONSOLE_COOKIE, st.create_session(other_user["id"], other))
    assert client.get("/api/v1/overview/summary").status_code == 403
    assert client.post("/api/v1/overview/summary", json={}).status_code == 403
    assert len(sent) == 4
    assert st.scalar("SELECT count(*) FROM model_usage WHERE tenant_id=$1 AND purpose='assistant'", other) == 0


def test_summary_rejects_untrusted_requests_bad_citations_and_provider_failures(chat_system):
    client, st, app, tenant, user, sent, provider, _ = chat_system
    app.state.service.cfg.openai_api_key = "test-provider-key"
    st.update_user(tenant, user["id"], role="owner")  # Cost pages need a privileged role.
    cost_ids = [str(index) for index, source in enumerate(SOURCES, 1) if source[0].startswith("/costs/")]
    summary_reply(provider, ["not-an-authorized-source"])
    assert client.post("/api/v1/overview/summary", json={}).status_code == 502
    assert st.scalar("SELECT count(*) FROM model_usage WHERE tenant_id=$1 AND status='error'", tenant) == 1
    summary_reply(provider, headline="")  # The strip leads with the headline figure.
    assert client.post("/api/v1/overview/summary", json={}).status_code == 502
    # A cost figure without its window reads as a daily or monthly total.
    summary_reply(provider, cost_ids, topic="Costs", headline="$407.73", text="Agent costs are estimated at $407.73.")
    assert client.post("/api/v1/overview/summary", json={}).status_code == 502
    summary_reply(provider, cost_ids, topic="Costs", headline="$407.73", caption="agents, last 24 hours",
                  text="Agent costs are estimated at $407.73 over a 24-hour window.")
    assert client.post("/api/v1/overview/summary", json={}).status_code == 200
    assert len(sent) == 4  # The invalid results were not cached.
    for payload in ({"sources": []}, {"tenant": tenant}, {"refresh": "true"}):
        assert client.post("/api/v1/overview/summary", json=payload).status_code == 400
    provider["status"] = 503
    assert client.post("/api/v1/overview/summary", json={"refresh": True}).status_code == 503
    assert len(sent) == 5
    # Failed refresh does not replace the last successful cache entry.
    assert client.post("/api/v1/overview/summary", json={}).status_code == 200
    assert len(sent) == 5
    provider["status"] = 200
    assert client.post("/api/v1/overview/summary", json={"refresh": True}).status_code == 200
    assert len(sent) == 6
    client.cookies.clear()
    assert client.get("/api/v1/overview/summary").status_code == 401
    assert client.post("/api/v1/overview/summary", json={}).status_code == 401
    assert len(sent) == 6


def test_summary_marks_partial_sources_and_never_uses_client_content(chat_system, monkeypatch):
    from openaidr.server.httpx import APIError
    from openaidr.server.overview_summary import collect

    client, st, app, tenant, user, sent, provider, _ = chat_system
    app.state.service.cfg.openai_api_key = "test-provider-key"
    st.update_user(tenant, user["id"], role="owner")
    original = app.state.service.console
    reads = []

    def console(request, path):
        if request.method == "GET":
            reads.append((path, request.url.query))
        if path in ("inventory/skills", "credits") or path.startswith("costs/"):
            raise APIError(503, "private upstream diagnostic")
        return original(request, path)

    monkeypatch.setattr(app.state.service, "console", console)
    # Unavailable cost sources have no figure, so the Costs item needs no 24-hour window.
    cost_ids = [str(index) for index, source in enumerate(SOURCES, 1) if source[0].startswith("/costs/")]
    summary_reply(provider, cost_ids, topic="Costs", headline="Unavailable", caption="",
                  text="Cost data could not be read.")
    result = client.post("/api/v1/overview/summary", json={})
    assert result.status_code == 200
    missing = [s for s in result.json()["sources"] if s["status"] == "unavailable"]
    assert [s["title"] for s in missing] == ["AI Skills", "AI Agent Costs", "Credits & Usage"]
    assert missing[0]["facts"] == {}
    assert reads.count(("overview", "range=30d&view=risk")) == 1
    assert "private upstream diagnostic" not in json.dumps(sent)
    assert client.post("/api/v1/overview/summary", json={"sources": [{"facts": "malicious"}]}).status_code == 400
    # Projections count the bounded page and never forward observed identities.
    sources = collect({"role": "viewer"}, lambda endpoint: {
        "items": [{"name": "secret-user", "review_required": True, "approval_status": "monitoring", "status": "ok"}],
        "next_cursor": "private-cursor", "guardrail": {"configured": True, "masked": "sk-secret"},
    })
    apps = next(s for s in sources if s["title"] == "AI Apps")
    assert apps["facts"] == {"loaded_records": 1, "has_more": True, "approved": 0, "unapproved": 0, "monitoring": 1, "review_required": 1}
    assert all(secret not in json.dumps(sources) for secret in ("secret-user", "private-cursor", "sk-secret"))


def test_saved_summary_survives_restart_expiry_and_failure_but_not_key_rotation_or_retention(chat_system, monkeypatch):
    from openaidr.server import overview_summary

    client, st, app, tenant, user, sent, provider, _ = chat_system
    app.state.service.cfg.openai_api_key = "test-provider-key"
    summary_reply(provider)
    saved = client.post("/api/v1/overview/summary", json={}).json()
    app.state.service.overview_summary = overview_summary.OverviewSummary(st)
    assert client.get("/api/v1/overview/summary").json() == {"summary": saved, "stale": False}
    current_identity = st.scalar("SELECT key_fingerprint FROM overview_summaries WHERE tenant_id=$1", tenant)
    legacy_identity = app.state.service.page_chat.cache_identity(tenant)
    st.execute("UPDATE overview_summaries SET key_fingerprint=$2 WHERE tenant_id=$1", tenant, legacy_identity)
    provider["status"] = 503
    assert client.get("/api/v1/overview/summary").json() == {"summary": None, "stale": True}
    assert st.scalar("SELECT summary FROM overview_summaries WHERE tenant_id=$1", tenant) == saved
    st.execute("UPDATE overview_summaries SET key_fingerprint=$2 WHERE tenant_id=$1", tenant, current_identity)
    provider["status"] = 200
    st.execute("UPDATE overview_summaries SET generated_at=now()-interval '2 hours' WHERE tenant_id=$1", tenant)
    assert client.get("/api/v1/overview/summary").json() == {"summary": saved, "stale": True}
    assert len(sent) == 1  # Reading a saved summary does not generate or collect sources.
    provider["status"] = 503
    assert client.post("/api/v1/overview/summary", json={}).status_code == 503
    assert client.get("/api/v1/overview/summary").json() == {"summary": saved, "stale": True}
    app.state.service.page_chat.connection = replace(app.state.service.page_chat.connection, origin="https://rotated.test")
    assert client.get("/api/v1/overview/summary").json() == {"summary": None, "stale": True}
    app.state.service.page_chat.connection = replace(app.state.service.page_chat.connection, origin="https://intelligence.test")
    st.execute("UPDATE overview_summaries SET generated_at=now()-interval '8 days' WHERE tenant_id=$1", tenant)
    assert client.get("/api/v1/overview/summary").json() == {"summary": None, "stale": True}
    provider["status"] = 200
    assert client.post("/api/v1/overview/summary", json={}).status_code == 200
    assert client.get("/api/v1/overview/summary").json()["stale"] is False
    assert len(sent) == 3
    monkeypatch.setattr(overview_summary, "page_allowed", lambda user, path: path == "/")
    assert client.get("/api/v1/overview/summary").json() == {"summary": None, "stale": True}


def test_hourly_summaries_precede_login_scope_roles_and_retry_failures(chat_system):
    from openaidr.server.overview_summary import refresh_due

    client, st, app, tenant, user, sent, provider, _ = chat_system
    service = app.state.service
    service.cfg.openai_api_key = "test-provider-key"
    service.cfg.tenant_id = tenant
    summary_reply(provider)
    owner = st.create_user(tenant, "owner@example.test", "Owner", "unused", "owner")
    st.create_user(tenant, "second-viewer@example.test", "Viewer", "unused", "viewer")
    disabled = st.create_user(tenant, "disabled@example.test", "Disabled", "unused", "admin")
    st.update_user(tenant, disabled["id"], status="disabled")
    other = st.bootstrap_tenant("Other tenant", "other-" + tenant[:8])["tenant"]["id"]
    st.create_user(other, "other@example.test", "Other", "unused", "owner")
    st.execute("DELETE FROM auth_sessions WHERE tenant_id=$1", tenant)
    client.cookies.clear()
    stop = threading.Event()
    refresh_due(service, stop)
    assert len(sent) == 2  # Two active role sets, independent of user/session counts.
    assert st.scalar("SELECT count(*) FROM auth_sessions WHERE tenant_id=$1", tenant) == 0
    assert st.scalar("SELECT count(*) FROM overview_summaries WHERE tenant_id=$1", other) == 0
    assert client.get("/api/v1/overview/summary").status_code == 401
    client.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], tenant))
    saved = client.get("/api/v1/overview/summary").json()
    assert saved["summary"] and saved["stale"] is False
    assert all(page_allowed(user, source["path"]) for source in saved["summary"]["sources"])
    client.cookies.set(CONSOLE_COOKIE, st.create_session(owner["id"], tenant))
    owner_summary = client.get("/api/v1/overview/summary").json()["summary"]
    assert all(page_allowed(owner, source["path"]) for source in owner_summary["sources"])
    assert all(source["status"] == "available" for source in owner_summary["sources"])
    assert any(s["path"] == "/guardrail/live" for s in owner_summary["sources"])
    assert all(s["path"] != "/guardrail/live" for s in saved["summary"]["sources"])
    refresh_due(service, stop)
    assert len(sent) == 2  # Not due again until an hour after success.

    st.execute("UPDATE overview_summaries SET generated_at=now()-interval '61 minutes',refresh_after=now() WHERE tenant_id=$1", tenant)
    provider["status"] = 503
    refresh_due(service, stop)
    assert len(sent) == 4
    client.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], tenant))
    assert client.get("/api/v1/overview/summary").json() == {**saved, "stale": True}
    refresh_due(service, stop)
    assert len(sent) == 4  # Failed attempts wait five minutes before retrying.
    provider["status"] = 200
    st.execute("UPDATE overview_summaries SET refresh_after=now() WHERE tenant_id=$1", tenant)
    refresh_due(service, stop)
    assert len(sent) == 6
    latest = client.get("/api/v1/overview/summary").json()
    assert latest["stale"] is False and latest["summary"]["generated_at"] != saved["summary"]["generated_at"]
    assert st.scalar("SELECT bool_and(refresh_after > now()+interval '59 minutes') FROM overview_summaries WHERE tenant_id=$1", tenant)
    service.cfg.tenant_id = ""
    st.execute("UPDATE tenants SET status='suspended' WHERE id=$1", other)
    refresh_due(service, stop)
    assert len(sent) == 6  # Suspended tenants never get background summaries.
    st.execute("UPDATE tenants SET status='active' WHERE id=$1", other)
    service.page_chat.connection = None
    refresh_due(service, stop)
    assert len(sent) == 6  # Missing model keys do not schedule provider requests.


def test_scheduler_claim_is_shared_across_processes_and_recovers_after_expiry(chat_system):
    from openaidr.server.overview_summary import OverviewSummary

    _, st, app, tenant, user, _, _, _ = chat_system
    summaries = [app.state.service.overview_summary, OverviewSummary(st)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda summary: summary.claim_refresh(tenant, user), summaries))
    assert sorted(results) == [False, True]
    assert not summaries[0].claim_refresh(tenant, user)
    st.execute("UPDATE overview_summaries SET refresh_after=now() WHERE tenant_id=$1", tenant)
    assert summaries[1].claim_refresh(tenant, user)


def test_api_startup_warms_summary_before_login(chat_system):
    _, st, app, tenant, user, sent, provider, _ = chat_system
    summary_reply(provider)
    cfg = Config(database_url=app.state.service.cfg.database_url,
                 tenant_id=tenant, intelligence_origin=app.state.service.page_chat.connection.origin,
                 intelligence_api_key=app.state.service.page_chat.connection.api_key)
    cfg.set_services("api")
    st.execute("DELETE FROM auth_sessions WHERE tenant_id=$1", tenant)
    with TestClient(create_app(cfg, st)) as client:
        deadline = time.monotonic() + 10
        while not st.scalar("SELECT count(*) FROM overview_summaries WHERE tenant_id=$1 AND summary IS NOT NULL", tenant):
            assert time.monotonic() < deadline, "API startup did not generate a summary"
            time.sleep(0.02)
        assert len(sent) == 1
        assert st.scalar("SELECT count(*) FROM auth_sessions WHERE tenant_id=$1", tenant) == 0
        client.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], tenant))
        assert client.get("/api/v1/overview/summary").json()["summary"] is not None


@pytest.mark.parametrize("provider_status, expected_status", [(200, 200), (503, 503)])
def test_concurrent_summary_requests_share_generation_and_errors(chat_system, monkeypatch, provider_status, expected_status):
    client, st, app, tenant, user, sent, provider, _ = chat_system
    app.state.service.cfg.openai_api_key = "test-provider-key"
    summary_reply(provider)
    provider["status"] = provider_status
    entered, release = threading.Event(), threading.Event()
    upstream = httpx.AsyncHTTPTransport.handle_async_request

    async def slow_provider(transport, request):
        entered.set()
        assert await asyncio.to_thread(release.wait, 10)
        return await upstream(transport, request)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", slow_provider)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(client.post, "/api/v1/overview/summary", json={})
        try:
            assert entered.wait(10)
            # The saved read stays available even while generation is blocked.
            assert client.get("/api/v1/overview/summary").json() == {"summary": None, "stale": True}
            second = pool.submit(client.post, "/api/v1/overview/summary", json={"refresh": True})
            with pytest.raises(TimeoutError):
                second.result(timeout=0.2)
        finally:
            release.set()
        assert first.result(timeout=10).status_code == expected_status
        assert second.result(timeout=10).status_code == expected_status
    assert len(sent) == 1
    provider["status"] = 200
    assert client.post("/api/v1/overview/summary", json={"refresh": True}).status_code == 200
    assert len(sent) == 2
