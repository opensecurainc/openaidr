"""Session descriptions through authenticated HTTP, PostgreSQL, and a fake provider."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from datetime import datetime
import json
import threading
import time
from types import SimpleNamespace

from fastapi.testclient import TestClient
import httpx
from psycopg.types.json import Jsonb
import pytest
from openaidr_api_client.validation.page_chat import MODEL

from openaidr.core.event import new_id, now
from openaidr.server import auth, session_activity_summaries as summaries
from openaidr.server.app import create_app
from openaidr.server.config import Config
from test_inline_guardrail import browser
from test_ordinary_session_detection import captured
from test_risk_cases import refresh_activity
from test_session_aggregation import action, registered
from test_store import db as db, sensor, tenant


@pytest.fixture
def summary_system(db, monkeypatch, tmp_path):
    own, other = tenant(db), tenant(db)
    users = {name: db.create_user(scope["id"], name + "@example.test", name, "unused", role)
             for name, scope, role in (("admin", own, "analyst"), ("owner", own, "viewer"), ("foreign", other, "analyst"))}
    cfg = Config(database_url=db.url, public_url="http://testserver", openai_api_key="test-summary-key",
                 inline_guardrails=True, cost_processing=False)
    cfg.set_services("api,ingest")
    app = create_app(cfg, db)
    # Do not start lifespan workers: tests advance the real queue explicitly.
    client = TestClient(app)
    system = SimpleNamespace(db=db, app=app, cfg=cfg, client=client, users=users, tenant=own,
        sensors={"sensor": sensor(db, own["id"]), "foreign_sensor": sensor(db, other["id"])},
        headers={name: {"Cookie": auth.CONSOLE_COOKIE + "=" + db.create_session(user["id"], user["tenant_id"]),
                        auth.CSRF_HEADER: "1"} for name, user in users.items()})
    system.headers.update({name: {"Authorization": "Bearer " + token} for name, (_, token, _) in system.sensors.items()})
    provider = {"summary": "Requested authentication changes and ran the related tests.", "status": 200, "sent": []}

    def upstream(_transport, request):
        assert str(request.url) == "https://api.openai.com/v1/responses"
        assert request.headers["Authorization"] in ("Bearer test-summary-key", "Bearer rotated-test-key")
        provider["sent"].append(json.loads(request.content))
        if provider.get("wait"):
            provider["entered"].set()
            assert provider["wait"].wait(10)
        return httpx.Response(provider["status"], json={"status": "completed", "model": MODEL,
            "service_tier": "default", "usage": {"input_tokens": 100, "output_tokens": 20,
                "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}},
            "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text",
                "text": provider.get("answer", json.dumps({"summary": provider["summary"]}))}]}]}, request=request)

    from intelligence_fixture import intelligence_service
    from test_inline_guardrail import Provider
    from openaidr.server.page_chat import PageChat
    risk_provider = Provider()
    async def dispatch(request):
        if request.url.host == "api.typesafe.ai":
            return await risk_provider.handle(request)
        return await __import__("asyncio").to_thread(upstream, None, request)
    with intelligence_service(monkeypatch, tmp_path, own["id"], dispatch,
                              openai_key="test-summary-key", guardrail_key="test-risk-key") as api:
        for name, value in api.config.items():
            setattr(cfg, name, value)
        app.state.service.page_chat = PageChat(db, connection=api.connection)
        foreign_app = create_app(replace(cfg, tenant_id=other["id"], intelligence_origin="", intelligence_api_key=""), db)
        system.foreign_client = TestClient(foreign_app)
        system.provider, system.risk_provider = provider, risk_provider
        system.connection = api.connection
        system.key_db = api.database
        try:
            yield system
        finally:
            client.close()
            system.foreign_client.close()


def activity(system, *, refresh=True, user="admin", zone="UTC"):
    if refresh:
        system.db.execute("UPDATE risk_activity_snapshots SET refresh_after=now()")
        refresh_activity(system, zone=zone, user=user)
    response = browser(system, "GET", "risk-cases?view=activity&time_zone=" + zone, user=user)
    assert response.status_code == 200, response.text
    return response.json()["groups"]["sessions"]["items"]


def test_summary_queues_from_authorized_page_and_reuses_redacted_cached_result(summary_system):
    s = summary_system
    value = captured(s, (89, 70))
    private = "sk-proj-" + "a" * 50
    s.db.execute("UPDATE events SET body=jsonb_set(body,'{text}',$2) WHERE id=$1",
                 value.events[0]["id"], Jsonb("Please update authentication. API key: " + private))
    foreign = captured(s, (99,), device="foreign_sensor")
    rows = activity(s)
    assert rows[0]["activity_summary"] == {"state": "pending", "text": None, "through": None}
    assert not s.provider["sent"]
    job = summaries.claim(s.db)
    assert job["session_id"] == value.id and summaries.claim(s.db) is None
    summaries.generate(s.app.state.service, job)
    saved = activity(s, refresh=False)[0]["activity_summary"]
    assert saved["state"] == "ready" and saved["text"] == s.provider["summary"]
    assert datetime.fromisoformat(saved["through"]) == datetime.fromisoformat(rows[0]["last_activity_at"])
    assert summaries.claim(s.db) is None
    assert activity(s, refresh=False)[0]["activity_summary"] == saved
    payload = s.provider["sent"][0]
    assert payload["tools"] == [] and payload["store"] is False
    assert payload["max_output_tokens"] == 1024
    assert "authentication" in payload["input"][0]["content"]
    assert private not in json.dumps(payload)
    assert "peer@example.test" not in json.dumps(payload)
    assert s.db.scalar("SELECT count(*) FROM model_usage WHERE purpose='assistant' AND status='completed'") == 1
    assert s.db.scalar("SELECT count(*) FROM risk_cases") == 0
    assert s.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0
    assert s.client.get("/api/v1/risk-cases?view=activity").status_code == 401
    assert browser(s, "GET", "risk-cases?view=activity", user="owner").status_code == 403
    other = activity(s, user="foreign")
    assert other[0]["session_id"] == foreign.id and other[0]["activity_summary"]["text"] is None
    assert saved["text"] not in json.dumps(other)
    assert len(s.provider["sent"]) == 1
    s.db.execute("""UPDATE session_activity_summaries SET generated_at=now()-interval '25 hours',
        refresh_after=now() WHERE session_id=$1""", value.id)
    assert activity(s, refresh=False)[0]["activity_summary"]["state"] == "pending"
    summaries.generate(s.app.state.service, summaries.claim(s.db, s.tenant["id"]))
    assert activity(s, refresh=False)[0]["activity_summary"]["state"] == "ready"


def test_viewers_in_different_time_zones_keep_separate_cached_windows(summary_system):
    s = summary_system
    captured(s, (80,))
    for zone in ("UTC", "America/Los_Angeles"):
        assert activity(s, zone=zone)[0]["activity_summary"]["state"] == "pending"
        job = summaries.claim(s.db)
        assert job["time_zone"] == zone
        summaries.generate(s.app.state.service, job)
    for zone in ("UTC", "America/Los_Angeles"):
        assert activity(s, refresh=False, zone=zone)[0]["activity_summary"]["state"] == "ready"
    assert len(s.provider["sent"]) == 2
    assert summaries.claim(s.db) is None
    foreign = captured(s, (90,), device="foreign_sensor")
    activity(s, user="foreign")
    s.db.execute("UPDATE session_activity_summaries SET last_requested_at=now()-interval '25 hours' WHERE session_id=$1", foreign.id)
    assert summaries.claim(s.db, s.tenant["id"]) is None
    assert s.db.scalar("SELECT count(*) FROM session_activity_summaries WHERE session_id=$1", foreign.id) == 0
    assert summaries.claim(s.db, s.users["foreign"]["tenant_id"]) is None
    assert not s.db.scalar("SELECT count(*) FROM session_activity_summaries WHERE session_id=$1", foreign.id)


@pytest.mark.parametrize("change", ["evidence", "backfill", "key"])
def test_new_evidence_and_rotated_keys_cannot_receive_a_late_summary(summary_system, change):
    s = summary_system
    value = captured(s, (75,))
    activity(s)
    first = summaries.claim(s.db)
    s.provider.update(wait=threading.Event(), entered=threading.Event())
    with ThreadPoolExecutor() as pool:
        generating = pool.submit(summaries.generate, s.app.state.service, first)
        assert s.provider["entered"].wait(5)
        if change != "key":
            event = deepcopy(value.events[0])
            event.update(id=new_id(), text="Run the authentication tests.")
            if change == "evidence":
                event["time"] = now()
            event["evidence"].update(logical_id=event["id"], observation_id=event["id"])
            s.db.ingest_batch(value.sensor, [event])
        else:
            from openaidr_api.threat_intel import keys
            rotated = s.key_db.with_name("rotated.key")
            keys.issue(s.key_db, s.tenant["id"], rotated)
            s.app.state.service.page_chat.connection = replace(s.connection, api_key=rotated.read_text().strip())
        assert activity(s)[0]["activity_summary"]["state"] == "pending"
        s.provider["wait"].set()
        generating.result()
    assert activity(s, refresh=False)[0]["activity_summary"]["text"] is None
    s.db.execute("UPDATE session_activity_summaries SET refresh_after=now(),last_attempt_at=now()-interval '1 hour'")
    second = summaries.claim(s.db)
    assert (second["requested_through"] > first["requested_through"]) == (change == "evidence")
    summaries.generate(s.app.state.service, second)
    assert activity(s, refresh=False)[0]["activity_summary"]["state"] == "ready"
    if change != "key":
        assert "Run the authentication tests" in s.provider["sent"][-1]["input"][0]["content"]


@pytest.mark.parametrize("answer,status", [("not JSON", 200), ('{"summary":""}', 200), ('{"summary":null}', 200), ("{}", 503)])
def test_unavailable_summaries_do_not_retry_on_page_reads(summary_system, answer, status):
    s = summary_system
    captured(s, (None,))
    s.provider.update(answer=answer, status=status)
    activity(s)
    summaries.generate(s.app.state.service, summaries.claim(s.db))
    assert activity(s, refresh=False)[0]["activity_summary"] == {"state": "unavailable", "text": None, "through": None}
    assert summaries.claim(s.db) is None and len(s.provider["sent"]) == 1
    s.app.state.service.page_chat.connection = None
    assert activity(s, refresh=False)[0]["activity_summary"]["state"] == "unavailable"
    assert len(s.provider["sent"]) == 1


def test_bounded_capture_and_empty_evidence_do_not_invent_activity(summary_system):
    s = summary_system
    value = captured(s, (80,) * 50)
    for index, event in enumerate(value.events[:-1]):
        s.db.execute("UPDATE events SET body=jsonb_set(body,'{text}',$2) WHERE id=$1", event["id"],
                     Jsonb(("Initial authentication task. " if index == 0 else "Most recent captured task. " if index == 49 else "Read source. ") + "x" * 4000))
    activity(s)
    job = summaries.claim(s.db)
    evidence = summaries.collect(s.db, job)
    assert len(evidence) <= summaries.MAX_RECORDS
    payload = json.dumps(evidence, ensure_ascii=False)
    assert len(payload) <= summaries.MAX_INPUT_CHARS
    assert "Initial authentication task" in payload and "Most recent captured task" in payload
    s.db.execute("UPDATE events SET body=body-'text' WHERE session_id=$1", value.id)
    summaries.generate(s.app.state.service, job)
    assert not s.provider["sent"]
    assert activity(s, refresh=False)[0]["activity_summary"]["state"] == "unavailable"


def test_claims_are_unique_rate_limited_and_session_deletion_removes_summaries(summary_system):
    s = summary_system
    values = [captured(s, (score,)) for score in (90, 85, 80, 75)]
    activity(s)
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = [job for job in pool.map(lambda _: summaries.claim(s.db), range(4)) if job]
    while len(jobs) < 3:
        job = summaries.claim(s.db)
        assert job is not None
        jobs.append(job)
    assert len({job["session_id"] for job in jobs}) == 3
    assert summaries.claim(s.db) is None
    s.db.execute("UPDATE session_activity_summaries SET last_attempt_at=now()-interval '2 minutes'")
    assert summaries.claim(s.db) is not None
    s.db.execute("DELETE FROM agent_sessions WHERE id=$1", values[0].id)
    assert not s.db.scalar("SELECT count(*) FROM session_activity_summaries WHERE session_id=$1", values[0].id)


def test_managed_activity_uses_captured_target_content(summary_system, monkeypatch):
    s = summary_system
    provider = s.risk_provider
    s.settings = None
    s.provider = provider
    s.db.update_user(s.tenant["id"], s.users["admin"]["id"], role="owner")
    s.app.state.service.page_chat.connection = None
    with TestClient(s.app) as client:
        s.client = client
        registration = registered(s)
        action(s, registration, 75, finish=False)
        s.app.state.service.page_chat.connection = s.connection
        activity(s)
        deadline = time.monotonic() + 10
        while activity(s, refresh=False)[0]["activity_summary"]["state"] != "ready":
            assert time.monotonic() < deadline, "Background session summary did not complete"
            time.sleep(.05)
