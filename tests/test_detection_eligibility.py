"""Eligibility explanations through the tenant API and real PostgreSQL."""

from urllib.parse import urlencode

from psycopg.types.json import Jsonb

from openaidr.server import detection_history, ordinary_session_detection as ordinary
from openaidr.server.session_aggregation import SETTINGS
from test_detection_pipeline import pipeline
from test_inline_guardrail import browser, system as system
from test_ordinary_session_detection import captured, configure
from test_session_aggregation import action, close_session, deliver, finalized, registered
from test_store import db as db


def eligibility(system, *, user="admin", expected=200, **query):
    reply = browser(system, "GET", "detections/eligibility?" + urlencode(query), user=user)
    assert reply.status_code == expected, reply.text
    if expected == 200:
        assert reply.headers["cache-control"] == "no-store"
    return reply.json()


def test_availability_distinguishes_disabled_unknown_and_compatible_workers(system):
    configure(system, enabled=False)
    status = pipeline(system)["availability"]
    assert status["reason"] == "tenant_disabled" and status["scheduling_enabled"] is None
    settings = configure(system)
    assert pipeline(system)["availability"]["reason"] == "worker_unavailable"
    system.db.service_heartbeat("detect", "fixture", {"session_investigator": {"ready": True, "supported_models": ["gpt-6.1-sol"]}})
    assert pipeline(system)["availability"]["reason"] == "readiness_unknown"
    system.db.service_heartbeat("detect", "fixture", {"tenant_id": "", "session_detection_scheduling": False})
    assert pipeline(system)["availability"]["reason"] == "scheduling_disabled"
    system.db.service_heartbeat("detect", "fixture", {
        "tenant_id": "", "session_detection_scheduling": True,
        "session_investigator": {"ready": True, "supported_models": ["different-model"]},
    })
    assert pipeline(system)["availability"]["reason"] == "worker_unavailable"
    system.db.service_heartbeat("detect", "compatible", {
        "tenant_id": system.tenant["id"], "session_detection_scheduling": True,
        "session_investigator": {"ready": True, "supported_models": ["gpt-6.1-sol"]},
    })
    assert pipeline(system)["availability"]["reason"] == "ready"
    # The bound worker cannot serve another enabled tenant in the same database.
    assert pipeline(system, user="foreign")["availability"]["tenant_enabled"] is True
    reply = browser(system, "PUT", "response/session-detection", {key: settings[key] for key in SETTINGS}, user="foreign")
    assert reply.status_code == 200, reply.text
    foreign_status = pipeline(system, user="foreign")["availability"]
    assert foreign_status["scheduling_enabled"] is True and foreign_status["worker_ready"] is False
    system.db.execute("DELETE FROM service_heartbeats WHERE instance='fixture'")
    foreign_status = pipeline(system, user="foreign")["availability"]
    assert foreign_status["reason"] == "worker_unavailable" and foreign_status["scheduling_enabled"] is None
    system.db.service_heartbeat("detect", "fixture", {"tenant_id": "", "session_detection_scheduling": False})
    assert pipeline(system, user="foreign")["availability"]["reason"] == "scheduling_disabled"
    ready = {"session_detection_scheduling": True,
             "session_investigator": {"ready": True, "supported_models": ["gpt-6.1-sol"]}}
    system.db.service_heartbeat("detect", "fixture", ready)
    assert pipeline(system, user="foreign")["availability"]["reason"] == "readiness_unknown"
    assert pipeline(system, user="foreign")["availability"]["worker_ready"] is None
    assert pipeline(system)["availability"]["reason"] == "ready"
    system.db.service_heartbeat("detect", "fixture", {**ready, "tenant_id": ""})
    assert pipeline(system, user="foreign")["availability"]["reason"] == "ready"
    system.db.execute("UPDATE service_heartbeats SET last_seen_at=now()-interval '91 seconds'")
    assert pipeline(system)["availability"]["reason"] == "worker_unavailable"
    assert pipeline(system, user="foreign")["availability"]["reason"] == "worker_unavailable"
    assert system.db.scalar("SELECT count(*) FROM model_usage") == 0


def test_eligibility_is_tenant_scoped_paged_read_only_and_separates_history_identity(system):
    configure(system)
    high, low, unknown = captured(system), captured(system, (10,)), captured(system)
    foreign = captured(system, device="foreign_sensor")
    detection_history.save_owner(system.db, system.tenant["id"], high.id, system.users["owner"]["id"], system.users["admin"])
    for value in (high, low):
        ordinary.finalize(system.db, system.tenant["id"], value.id, scheduling_enabled=False)
    before = {table: system.db.scalar(f"SELECT count(*) FROM {table}") for table in (
        "session_snapshots", "session_investigation_jobs", "ordinary_session_input_dirty", "model_usage",
    )}
    first = eligibility(system, limit=1)
    rows, cursor = first["items"], first["next_cursor"]
    while cursor:
        result = eligibility(system, limit=1, cursor=cursor)
        rows += result["items"]
        cursor = result["next_cursor"]
    by_id = {r["id"]: r["eligibility"] for r in rows}
    assert set(by_id) == {high.id, low.id, unknown.id}
    assert by_id[high.id]["status"] == "eligible" and by_id[high.id]["reason"] == "scheduling_disabled"
    assert by_id[high.id]["owner"]["id"] == system.users["owner"]["id"] and by_id[high.id]["history_available"]
    assert by_id[low.id]["status"] == "not_selected" and by_id[low.id]["reason"] == "threshold_not_exceeded"
    assert by_id[low.id]["owner"] is None and not by_id[low.id]["history_available"]
    assert by_id[unknown.id]["status"] == "waiting"
    assert [r["id"] for r in eligibility(system, q=high.id)["items"]] == [high.id]
    assert [r["id"] for r in eligibility(system, q=system.users["owner"]["email"])["items"]] == [high.id]
    assert eligibility(system, q="%_")["items"] == []
    assert [r["id"] for r in eligibility(system, user="foreign")["items"]] == [foreign.id]
    eligibility(system, cursor=first["next_cursor"], q="changed", expected=400)
    eligibility(system, cursor=first["next_cursor"], user="foreign", expected=400)
    eligibility(system, range="24h", expected=400)
    eligibility(system, limit=101, expected=400)
    assert system.client.get("/api/v1/detections/eligibility").status_code == 401
    detail = browser(system, "GET", f"sessions/{high.id}/detection").json()
    assert detail["eligibility"] == by_id[high.id]
    assert before == {table: system.db.scalar(f"SELECT count(*) FROM {table}") for table in before}
    system.db.execute("UPDATE ordinary_session_detection SET next_evaluation_at=now()-interval '1 second' WHERE session_id=$1", high.id)
    assert eligibility(system, q=high.id)["items"][0]["eligibility"]["reason"] == "evaluation_pending"
    system.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", high.sensor["id"])
    assert eligibility(system, q=high.id)["items"][0]["eligibility"]["reason"] == "sensor_unavailable"


def test_stale_evidence_settings_and_history_window_never_claim_eligibility(system):
    configure(system)
    value = captured(system)
    state = ordinary.finalize(system.db, system.tenant["id"], value.id, scheduling_enabled=True, worker_ready=True)
    assert eligibility(system, q=value.id)["items"][0]["eligibility"]["reason"] == "queued"
    system.db.execute("UPDATE session_investigation_jobs SET state='inconclusive',completed_at=now() WHERE id=$1", state["routing"]["job_id"])
    assert eligibility(system, q=value.id)["items"][0]["eligibility"]["reason"] == "inconclusive"
    configure(system, risk_threshold="101")
    assert eligibility(system, q=value.id)["items"][0]["eligibility"]["reason"] == "evaluation_pending"
    ordinary.finalize(system.db, system.tenant["id"], value.id, scheduling_enabled=True, worker_ready=True)
    system.db.execute("INSERT INTO ordinary_session_input_dirty(tenant_id,session_id) VALUES($1,$2)", system.tenant["id"], value.id)
    assert eligibility(system, q=value.id)["items"][0]["eligibility"]["reason"] == "evaluation_pending"
    configure(system, enabled=False)
    assert eligibility(system, q=value.id)["items"][0]["eligibility"]["status"] == "disabled"
    configure(system, selection_policy="risk_budget")
    old = captured(system, (10,))
    system.db.execute("UPDATE agent_sessions SET last_event_at=now()-interval '8 days' WHERE id=$1", old.id)
    ordinary.finalize(system.db, system.tenant["id"], old.id, scheduling_enabled=True, worker_ready=True)
    assert eligibility(system, q=old.id)["items"][0]["eligibility"]["reason"] == "outside_history_window"
    urgent = captured(system, (99, 0), closed=False)
    system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", urgent.events[1]["id"], Jsonb({"status": "pending"}))
    state = ordinary.finalize(system.db, system.tenant["id"], urgent.id, scheduling_enabled=False)
    assert state["selection"]["reason"] == "urgent_risk" and state["counts"]["pending"] == 1
    assert eligibility(system, q=urgent.id)["items"][0]["eligibility"]["status"] == "eligible"


def test_managed_eligibility_matches_routing_and_requires_active_verified_owner(system):
    configure(system, risk_threshold="0")
    registration = registered(system)
    _, _, records, _ = action(system, registration, 90)
    deliver(system, registration, records)
    close_session(system, registration, len(records))
    finalized(system, registration, enabled=True, ready=False)
    row = eligibility(system)["items"][0]
    assert row["eligibility"]["reason"] == "worker_unavailable"
    assert row["eligibility"]["status"] == "eligible"
    system.db.execute("UPDATE session_finalizations SET failure_code='finalization_timeout',next_evaluation_at=now()-interval '1 second' WHERE registration_id=$1", registration["id"])
    assert eligibility(system)["items"][0]["eligibility"]["reason"] == "evaluation_failed"
    system.db.execute("UPDATE tenant_users SET status='disabled' WHERE id=$1", system.users["owner"]["id"])
    assert eligibility(system, user="admin")["items"][0]["eligibility"]["reason"] == "owner_unavailable"
    eligibility(system, user="owner", expected=403)
