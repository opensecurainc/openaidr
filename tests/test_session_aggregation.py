"""Session aggregation through real HTTP and PostgreSQL with external JEV transport mocked."""

from concurrent.futures import ThreadPoolExecutor
from copy import copy
from decimal import Decimal
import json
from pathlib import Path
from threading import Barrier

from psycopg.types.json import Jsonb
import pytest

from openaidr.core.event import new_id
from openaidr.server import session_aggregation as aggregation
from openaidr.server.auth import CONSOLE_COOKIE, CSRF_HEADER
from test_approvals import approval_settings, consume, decide, sensor_post
from test_inline_guardrail import Provider, browser, check, configure, event, payload, policy, system as system
from test_session_ownership import wait_for_blocker
from test_store import db as db


BOUNDARIES = ["prompt", "tool_call", "tool_output", "assistant_response"]


def detection_settings(system, **changes):
    value = {
        "selection_policy": "legacy",
        "enabled": True, "risk_threshold": "100", "idle_seconds": 60,
        "delivery_grace_seconds": 0, "gap_policy": "retain", "gap_wait_seconds": 0,
        "model": "gpt-6.1-sol", "max_runtime_seconds": 5,
        "max_tokens_per_attempt": 100, "max_cost_usd_per_attempt": "0.10",
        "max_attempts": 2, "max_concurrent": 1,
        "hourly_attempts": 2, "hourly_tokens": 200, "hourly_cost_usd": "0.20",
        "retry_delay_seconds": 0, **changes,
    }
    response = browser(system, "PUT", "response/session-detection", value)
    assert response.status_code == 200, response.text
    return response.json()


def registered(system, *, device="sensor", owner="owner", verified=True, protocol=True):
    if system.settings is None:
        configure(system)
    value = {"product": "codex-cli", "assessment_mode": "inline"}
    if protocol:
        value.update(delivery_protocol=1, delivery_epoch=new_id())
    result = sensor_post(system, "session-registrations", value, device=device, expected=201)
    result["external_id"] = "native-" + new_id()
    if protocol:
        result["delivery_epoch"] = value["delivery_epoch"]
    bound = sensor_post(
        system, f"session-registrations/{result['id']}/bind",
        {"external_id": result["external_id"]}, device=device,
    )
    if verified:
        response = browser(system, "POST", "session-registrations/confirm", {"token": bound["confirmation_token"]}, user=owner)
        assert response.status_code == 200, response.text
    return result


def receipt(kind, sequence, **fields):
    return {"record_id": new_id(), "sequence": sequence, "kind": kind, "gaps": [], **fields}


def deliver(system, registration, records, **options):
    return sensor_post(
        system, f"session-registrations/{registration['id']}/delivery",
        {"epoch_id": registration["delivery_epoch"], "records": records}, **options,
    )


def close_body(registration, sequence, **fields):
    return {
        "request_id": new_id(), "epoch_id": registration["delivery_epoch"],
        "final_sequence": sequence, "reason": "process_exit", "capabilities_version": 1,
        "boundaries": BOUNDARIES, "gaps": [], **fields,
    }


def close_session(system, registration, sequence, *, value=None, **options):
    return sensor_post(
        system, f"session-registrations/{registration['id']}/close",
        value or close_body(registration, sequence), **options,
    )


def status(system, registration, **options):
    return sensor_post(system, f"session-registrations/{registration['id']}/delivery-status", **options)


def finalized(system, registration, *, enabled=False, ready=False):
    return aggregation.finalize_one(
        system.db, registration["id"], scheduling_enabled=enabled, worker_ready=ready,
    )


def snapshot_page(system, snapshot_id, *, user="owner", limit=100, cursor="", expected=200):
    response = system.client.get(
        f"/api/v1/me/session-snapshots/{snapshot_id}",
        params={"limit": limit, "cursor": cursor}, headers=system.headers[user],
    )
    assert response.status_code == expected, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def action(system, registration, score=0, *, sequence=1, finish=True, gaps=None):
    system.provider.payload = Provider.scored(score)
    target = event(registration)
    value = payload(system, registration, target)
    result = check(system, value)
    records = [receipt(
        "target", sequence, event_id=target["id"], logical_id=result["logical_id"],
        action_commitment=result["action_commitment"], gaps=gaps or [],
    )]
    release = None
    if finish:
        outcome, release = finish_action(system, registration, result, sequence + 1)
        records.append(outcome)
    return value, result, records, release


def finish_action(system, registration, result, sequence):
    if result["decision"]["action"] == "block":
        observation = event(registration, "sensor", managed_outcome={
            "logical_id": result["logical_id"], "outcome": "not_executed", "reason": "blocked",
        })
        assert sensor_post(system, "events", {"events": [observation]})["accepted"] == 1
        return receipt("outcome", sequence, event_id=observation["id"], logical_id=result["logical_id"]), None
    if result["decision"]["action"] == "ask":
        decide(system, result["approval"]["id"])
    release = consume(system, result)
    reported = sensor_post(system, f"guardrail-releases/{release['id']}/outcome", {"outcome": "succeeded", "exit_code": 0})
    return receipt(
        "outcome", sequence, event_id=result["event_id"], logical_id=result["logical_id"],
        release_id=release["id"], outcome_audit_id=reported["outcome_audit_id"],
    ), release


def completed_session(system, *, score=0):
    registration = registered(system)
    _, _, records, _ = action(system, registration, score)
    deliver(system, registration, records)
    close_session(system, registration, len(records))
    return registration


def seed_queue(system, registration, snapshot):
    # Seed finalized historical metadata without repeating 100 provider calls.
    with system.db.transaction() as conn:
        system.db.execute(
            """CREATE TEMP TABLE queue_fixture ON COMMIT DROP AS
               SELECT gen_random_uuid() AS registration_id,gen_random_uuid() AS snapshot_id,
                      gen_random_uuid() AS job_id FROM generate_series(1,100)""", conn=conn,
        )
        system.db.execute(
            """INSERT INTO session_registrations
               SELECT (jsonb_populate_record(NULL::session_registrations,to_jsonb(r)||jsonb_build_object(
                   'id',q.registration_id,'external_id','queue-'||q.registration_id,
                   'delivery_epoch',q.registration_id))).*
               FROM session_registrations r CROSS JOIN queue_fixture q WHERE r.id=$1""", registration["id"], conn=conn,
        )
        system.db.execute(
            """INSERT INTO session_snapshots
               SELECT (jsonb_populate_record(NULL::session_snapshots,to_jsonb(s)||jsonb_build_object(
                   'id',q.snapshot_id,'registration_id',q.registration_id,
                   'epoch_id',q.registration_id,'item_count',0))).*
               FROM session_snapshots s CROSS JOIN queue_fixture q WHERE s.id=$1""", snapshot["snapshot_id"], conn=conn,
        )
        system.db.execute(
            """INSERT INTO session_finalizations
               SELECT (jsonb_populate_record(NULL::session_finalizations,to_jsonb(f)||jsonb_build_object(
                   'registration_id',q.registration_id,'snapshot_id',q.snapshot_id,
                   'status',f.status||jsonb_build_object('registration_id',q.registration_id,'snapshot_id',q.snapshot_id)))).*
               FROM session_finalizations f CROSS JOIN queue_fixture q WHERE f.registration_id=$1""", registration["id"], conn=conn,
        )
        system.db.execute(
            """INSERT INTO session_investigation_jobs
               SELECT (jsonb_populate_record(NULL::session_investigation_jobs,to_jsonb(j)||jsonb_build_object(
                   'id',q.job_id,'registration_id',q.registration_id,'snapshot_id',q.snapshot_id))).*
               FROM session_investigation_jobs j CROSS JOIN queue_fixture q WHERE j.snapshot_id=$1""", snapshot["snapshot_id"], conn=conn,
        )


def test_settings_default_on_with_limits_and_keep_detector_identity_for_routing_only_changes(system):
    defaults = browser(system, "GET", "response/session-detection").json()
    assert defaults["enabled"] is True and defaults["selection_policy"] == "risk_budget"
    assert defaults["max_concurrent"] == 1
    assert not {"model", "max_cost_usd_per_attempt", "hourly_cost_usd", "max_tokens_per_attempt", "hourly_tokens"}.intersection(defaults)
    retained = aggregation.get_settings(system.db, system.tenant["id"])
    assert retained["max_cost_usd_per_attempt"] == "2" and retained["hourly_cost_usd"] == "10"
    assert all(retained[key] is not None for key in aggregation.SETTINGS)
    assert browser(system, "PUT", "response/session-detection", {"enabled": True}).status_code == 200
    assert browser(system, "PUT", "response/session-detection", {"enabled": False}, user="owner").status_code == 403
    assert system.client.put(
        "/api/v1/response/session-detection", json={"enabled": False},
        headers={"Cookie": system.headers["admin"]["Cookie"]},
    ).status_code == 403
    current = detection_settings(system, risk_threshold="1000.25")
    routed = detection_settings(system, risk_threshold="0")
    assert routed["version"] > current["version"]
    assert routed["detector_config_version"] == current["detector_config_version"]
    changed = detection_settings(system, max_runtime_seconds=6)
    assert changed["detector_config_version"] > routed["detector_config_version"]
    assert browser(system, "GET", "response/session-detection", user="foreign").json()["enabled"] is True
    invalid = {key: value for key, value in changed.items() if key not in ("version", "detector_config_version", "updated_at")}
    for fields in ({"risk_threshold": "NaN"}, {"risk_threshold": "Infinity"}, {"risk_threshold": "1e999999999"}, {"max_tokens_per_attempt": True}, {"hourly_tokens": 99}, {"gap_wait_seconds": -1}):
        assert browser(system, "PUT", "response/session-detection", {**invalid, **fields}).status_code == 400


def test_administration_switch_preserves_limits_and_stops_admission(system):
    from test_ordinary_session_detection import captured, finalize

    user = system.db.create_user(system.tenant["id"], "it@example.test", "IT", "hash", ["it_admin"])
    system.headers["it"] = {"Cookie": CONSOLE_COOKIE + "=" + system.db.create_session(user["id"], user["tenant_id"]), CSRF_HEADER: "1"}
    path = "settings/session-detection"
    settings = browser(system, "GET", path, user="it").json()
    retained_settings = aggregation.get_settings(system.db, system.tenant["id"])
    assert settings["enabled"] and settings["availability"]["reason"] == "worker_unavailable"
    assert browser(system, "GET", "response/session-detection", user="it").status_code == 403
    assert browser(system, "GET", path, user="owner").status_code == 403
    assert system.client.get("/api/v1/" + path).status_code == 401
    payload = {"enabled": False, "version": settings["version"]}
    assert browser(system, "PUT", path, payload, user="owner").status_code == 403
    assert system.client.put("/api/v1/" + path, json=payload, headers={"Cookie": system.headers["it"]["Cookie"]}).status_code == 403
    assert browser(system, "PUT", path, {**payload, "hourly_cost_usd": "500"}, user="it").status_code == 400
    off = browser(system, "PUT", path, payload, user="it").json()
    assert not off["enabled"] and off["availability"]["reason"] == "tenant_disabled"
    assert all(off[key] == settings[key] for key in aggregation.SETTINGS if key != "enabled" and key in settings)
    retained_off = aggregation.get_settings(system.db, system.tenant["id"])
    assert all(retained_off[key] == retained_settings[key] for key in aggregation.SETTINGS if key != "enabled")
    assert browser(system, "GET", path, user="it").json()["enabled"] is False
    assert browser(system, "GET", path, user="foreign").json()["enabled"] is True
    assert browser(system, "PUT", path, payload, user="it").status_code == 409
    value = captured(system, (99,))
    assert finalize(system, value)["routing"]["status"] == "disabled"
    on = browser(system, "PUT", path, {"enabled": True, "version": off["version"]}, user="it").json()
    assert on["enabled"] and on["max_concurrent"] == 1
    # Once evidence grace has elapsed, default settings admit urgent activity.
    system.db.execute("UPDATE agent_sessions SET last_event_at=now()-interval '5 minutes',ended_at=now()-interval '5 minutes' WHERE id=$1", value.id)
    state = finalize(system, value)
    assert state["routing"]["status"] == "queued", state
    assert aggregation.claim_job(system.db, "default-worker", system.tenant["id"], worker_ready=True) is not None
    browser(system, "PUT", path, {"enabled": False, "version": on["version"]}, user="it")
    assert aggregation.claim_job(system.db, "off-worker", system.tenant["id"], worker_ready=True) is None
    assert system.db.scalar("SELECT count(*) FROM model_usage") == 0
    assert system.db.scalar("SELECT count(*) FROM audit_log WHERE action='session-detection.configure' AND actor_id=$1", user["id"]) == 3


def test_detection_defaults_migration_preserves_opt_out_and_partial_limits(system):
    st = system.db
    tenant = system.tenant["id"]
    foreign = system.users["foreign"]["tenant_id"]
    # Recreate the three pre-upgrade states: absent, explicit off with partial
    # limits, and an explicitly configured tenant.
    st.execute("DROP TRIGGER tenants_initialize_session_detection ON tenants")
    st.execute("DROP FUNCTION initialize_session_detection_settings()")
    st.execute("DELETE FROM tenant_session_detection_settings WHERE tenant_id=$1", foreign)
    st.execute("""UPDATE tenant_session_detection_settings SET enabled=false,
               max_tokens_per_attempt=NULL,hourly_tokens=100,max_cost_usd_per_attempt=NULL,hourly_cost_usd=0.5,
               delivery_grace_seconds=NULL,gap_wait_seconds=0,model=NULL WHERE tenant_id=$1""", tenant)
    configured = st.create_tenant("Configured", "configured")
    st.execute("INSERT INTO tenant_session_detection_settings(tenant_id,hourly_cost_usd) VALUES($1,25)", configured["id"])
    previous = aggregation.get_settings(st, configured["id"])
    migration = Path(__file__).parents[1] / "src/openaidr/server/migrations/0104_session_detection_defaults.sql"
    st.execute(migration.read_text())
    off = aggregation.get_settings(st, tenant)
    assert off["enabled"] is False
    assert off["hourly_tokens"] == off["max_tokens_per_attempt"] == 100
    assert off["hourly_cost_usd"] == off["max_cost_usd_per_attempt"] == "0.5"
    assert off["gap_wait_seconds"] == off["delivery_grace_seconds"] == 0
    assert aggregation.get_settings(st, configured["id"]) == previous
    assert aggregation.get_settings(st, foreign)["enabled"] is True
    created = st.create_tenant("New", "new-default")
    assert aggregation.get_settings(st, created["id"])["enabled"] is True
    actor = {"type": "user", "id": system.users["admin"]["id"], "name": "Admin"}
    assert aggregation.save_settings(st, tenant, {"enabled": True}, actor)["hourly_cost_usd"] == "0.5"


def test_canonical_sum_counts_blocked_attempts_once_across_aliases_and_derived_observations(system):
    detection_settings(system)
    registration = registered(system)
    records = []
    for score in (10.1, 20.2, 90.3):
        value, result, fresh, _ = action(system, registration, score, sequence=len(records) + 1, finish=False)
        records.extend(fresh)
        alias = check(system, {**value, "request_id": new_id()})
        assert alias["assessment"] == result["assessment"]
        outcome, _ = finish_action(system, registration, result, len(records) + 1)
        records.append(outcome)
    version = policy(system, "warn")
    revised = check(system, {**value, "request_id": new_id(), "policy_version": version})
    assert revised["assessment"] == result["assessment"]
    derived = event(registration, "file.write", file={"path": "/workspace/example.txt"})
    derived["evidence"]["logical_id"] = result["logical_id"]
    sensor_post(system, "events", {"events": [derived]})
    records.append(receipt("observation", len(records) + 1, event_id=derived["id"]))
    deliver(system, registration, records)
    close_session(system, registration, len(records))
    measured = finalized(system, registration)
    assert isinstance(measured["risk_total"], str)
    assert Decimal(measured["risk_total"]) == Decimal("120.6")
    assert Decimal(measured["risk_max"]) == Decimal("90.3")
    assert measured["counts"]["logical_targets"] == measured["counts"]["assessed"] == 3
    assert measured["counts"]["blocked"] == 1
    assert measured["coverage"]["status"] == "complete"
    assert len(system.provider.requests) == 3
    assert system.db.scalar("SELECT count(*) FROM model_usage") == 3


@pytest.mark.parametrize("assessment", ["zero", "unavailable", "missing", "invalid"])
def test_null_missing_and_invalid_assessments_never_become_measured_zero(system, assessment):
    detection_settings(system)
    registration = registered(system)
    if assessment == "missing":
        target = event(registration)
        sensor_post(system, "events", {"events": [target]})
        records = [receipt(
            "target", 1, event_id=target["id"], logical_id=target["evidence"]["logical_id"],
            action_commitment="hmac-sha256-v1:" + "a" * 64, gaps=["backend_unavailable"],
        )]
        observed = event(registration, "sensor", managed_outcome={
            "logical_id": target["evidence"]["logical_id"], "outcome": "succeeded", "reason": "backend_unavailable",
        })
        sensor_post(system, "events", {"events": [observed]})
        records.append(receipt("outcome", 2, event_id=observed["id"], logical_id=target["evidence"]["logical_id"], gaps=["backend_unavailable"]))
    else:
        if assessment == "unavailable":
            system.provider.status = 503
        _, result, records, _ = action(system, registration)
        if assessment == "invalid":
            system.db.execute(
                "UPDATE inline_guardrail_events SET assessment=assessment||$2 WHERE event_id=$1",
                result["event_id"], Jsonb({"score": True}),
            )
    deliver(system, registration, records)
    close_session(system, registration, 2)
    result = finalized(system, registration)
    assert result["counts"]["logical_targets"] == 1
    if assessment == "zero":
        assert Decimal(result["risk_total"]) == Decimal(result["risk_max"]) == 0
        assert result["counts"]["assessed"] == 1
        assert result["coverage"]["status"] == "complete"
    else:
        assert result["risk_total"] is None and result["risk_max"] is None
        assert result["counts"]["assessed"] == 0
        key = {"unavailable": "unavailable", "missing": "missing_assessments", "invalid": "invalid_assessments"}[assessment]
        assert result["counts"][key] == 1
        assert result["coverage"]["assessment"]["status"] == "incomplete"
        assert result["coverage"]["status"] == "incomplete"
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0


def test_dense_receipts_are_atomic_idempotent_and_close_retries_cannot_move_watermark_back(system):
    detection_settings(system)
    registration = registered(system)
    _, _, records, _ = action(system, registration, 10)
    deliver(system, registration, records[:1] * 101, expected=400)
    for invalid_sequence in (True, 0, 1 << 63):
        deliver(system, registration, [{**records[0], "sequence": invalid_sequence}], expected=400)
    missing = receipt("observation", 3, event_id=new_id())
    assert deliver(system, registration, [records[0], missing], expected=409)["error"]["code"] == "record_unavailable"
    assert system.db.scalar("SELECT count(*) FROM session_delivery_receipts") == 0
    assert deliver(system, registration, [records[1]])["accepted"] == 1
    old_close = close_body(registration, 2)
    close_session(system, registration, 2, value=old_close)
    partial = finalized(system, registration)
    assert partial["delivery"]["complete"] is False
    assert deliver(system, registration, [records[0]])["accepted"] == 1
    complete = finalized(system, registration)
    assert complete["delivery"]["complete"] is True
    assert complete["lifecycle"] == "closed"
    close_session(system, registration, 2)
    assert finalized(system, registration)["snapshot_id"] == complete["snapshot_id"]
    assert deliver(system, registration, records)["duplicates"] == 2
    assert finalized(system, registration)["snapshot_id"] == complete["snapshot_id"]
    changed = {**records[0], "gaps": ["backend_unavailable"]}
    deliver(system, registration, [changed], expected=409)
    deliver(system, registration, [{**records[0], "record_id": new_id()}], expected=409)
    late = event(registration, "response", text="Late observed response")
    sensor_post(system, "events", {"events": [late]})
    deliver(system, registration, [receipt("observation", 3, event_id=late["id"])])
    assert status(system, registration)["snapshot_current"] is False
    assert finalized(system, registration)["lifecycle"] == "active"
    close_session(system, registration, 3)
    latest = finalized(system, registration)
    replay = close_session(system, registration, 2, value=old_close)
    assert replay["duplicate"] is True
    assert replay["status"]["closing_sequence"] == 3
    assert latest["revision"] > complete["revision"]
    close_session(system, registration, 3, value={**old_close, "final_sequence": 3}, expected=409)


def test_receipts_and_snapshots_require_current_verified_owner_and_exact_sensor_scope(system):
    detection_settings(system, risk_threshold="0")
    registration = completed_session(system, score=10)
    current = finalized(system, registration, enabled=True, ready=True)
    for invalid_protocol in (
        {"delivery_protocol": 1}, {"delivery_epoch": new_id()},
        {"delivery_protocol": 2, "delivery_epoch": new_id()},
    ):
        rejected = system.client.post(
            "/ingest/v1/session-registrations", headers=system.headers["sensor"],
            json={"product": "codex-cli", "assessment_mode": "inline", **invalid_protocol},
        )
        assert rejected.status_code == 400, rejected.text
    sensor_post(system, f"session-registrations/{registration['id']}/delivery", {
        "epoch_id": new_id(), "records": [],
    }, expected=409)
    for device in ("peer_sensor", "foreign_sensor"):
        status(system, registration, device=device, expected=404)
        deliver(system, registration, [], device=device, expected=404)
    for user in ("admin", "foreign"):
        snapshot_page(system, current["snapshot_id"], user=user, expected=403 if user == "foreign" else 404)
    session_id = system.db.scalar("SELECT id FROM agent_sessions WHERE registration_id=$1", registration["id"])
    assert browser(system, "GET", f"me/sessions/{session_id}/detection", user="owner").status_code == 200
    assert browser(system, "GET", f"me/sessions/{session_id}/detection", user="admin").status_code == 404
    unverified = registered(system, verified=False)
    deliver(system, unverified, [], expected=403)
    legacy = registered(system, protocol=False)
    assert status(system, legacy)["coverage"]["status"] == "unknown"
    response = system.client.post(
        f"/ingest/v1/session-registrations/{legacy['id']}/delivery",
        json={"epoch_id": new_id(), "records": []}, headers=system.headers["sensor"],
    )
    assert response.status_code == 409, response.text
    foreign = registered(system, device="peer_sensor")
    foreign_event = event(foreign)
    sensor_post(system, "events", {"events": [foreign_event]}, device="peer_sensor")
    denied = system.client.post(
        f"/ingest/v1/session-registrations/{registration['id']}/delivery",
        json={"epoch_id": registration["delivery_epoch"], "records": [receipt("observation", 3, event_id=foreign_event["id"])]},
        headers=system.headers["sensor"],
    )
    assert denied.status_code in (403, 404), denied.text
    system.db.execute("UPDATE tenant_users SET status='disabled' WHERE id=$1", system.users["owner"]["id"])
    response = system.client.get(f"/api/v1/me/session-snapshots/{current['snapshot_id']}", headers=system.headers["owner"])
    assert response.status_code in (403, 404), response.text
    response = system.client.post(
        f"/ingest/v1/session-registrations/{registration['id']}/delivery-status", json={}, headers=system.headers["sensor"],
    )
    assert response.status_code in (403, 404), response.text
    assert aggregation.claim_job(system.db, "revoked-owner", system.tenant["id"], worker_ready=True) is None


def test_dense_prefix_cannot_hide_a_known_canonical_target_without_its_receipt(system):
    detection_settings(system)
    registration = registered(system)
    _, _, first, _ = action(system, registration, 10)
    _, _, omitted, _ = action(system, registration, 20, sequence=3)
    deliver(system, registration, first)
    close_session(system, registration, 2)
    incomplete = finalized(system, registration)
    assert incomplete["counts"]["logical_targets"] == 2
    assert incomplete["delivery"]["received"] == incomplete["delivery"]["expected"] == 2
    assert incomplete["delivery"]["complete"] is False
    assert incomplete["coverage"]["delivery"]["status"] == "incomplete"
    deliver(system, registration, omitted)
    close_session(system, registration, 4)
    completed = finalized(system, registration)
    assert completed["coverage"]["status"] == "complete"
    assert Decimal(completed["risk_total"]) == 30


def test_pending_approval_and_reported_outcomes_remain_distinct_until_reconciled(system):
    detection_settings(system)
    approval_settings(system)
    registration = registered(system)
    _, checked, records, _ = action(system, registration, 50, finish=False)
    deliver(system, registration, records)
    close_session(system, registration, 1)
    waiting = finalized(system, registration)
    assert waiting["counts"]["pending_approvals"] == 1
    assert waiting["lifecycle"] == "closing"
    assert waiting["snapshot_id"] is None
    decide(system, checked["approval"]["id"])
    approved = finalized(system, registration)
    assert approved["counts"]["pending_approvals"] == 0
    assert approved["counts"]["approved_unconsumed"] == 1
    assert approved["coverage"]["execution"]["status"] == "incomplete"
    release = consume(system, checked)
    unreported = finalized(system, registration)
    assert unreported["counts"]["unreported_outcomes"] == 1
    assert unreported["coverage"]["execution"]["status"] == "incomplete"
    path = f"guardrail-releases/{release['id']}/outcome"
    uncertain = sensor_post(system, path, {"outcome": "uncertain"})
    old_audit_id = uncertain["outcome_audit_id"]
    uncertainty = receipt(
        "outcome", 2, event_id=checked["event_id"], logical_id=checked["logical_id"],
        release_id=release["id"], outcome_audit_id=old_audit_id,
    )
    deliver(system, registration, [uncertainty])
    close_session(system, registration, 2)
    incomplete = finalized(system, registration)
    assert incomplete["counts"]["uncertain_outcomes"] == 1
    assert incomplete["coverage"]["execution"]["status"] == "incomplete"
    # Succeeded reports this native action's observed result. It makes no
    # assertion that all descendants stopped or that the host is quiescent.
    known = sensor_post(system, path, {"outcome": "succeeded", "exit_code": 0})
    assert known["outcome_audit_id"] != old_audit_id
    assert sensor_post(system, path, {"outcome": "succeeded", "exit_code": 0})["outcome_audit_id"] == known["outcome_audit_id"]
    deliver(system, registration, [receipt(
        "outcome", 3, event_id=checked["event_id"], logical_id=checked["logical_id"],
        release_id=release["id"], outcome_audit_id=known["outcome_audit_id"],
    )])
    assert deliver(system, registration, [uncertainty])["duplicates"] == 1
    close_session(system, registration, 3)
    completed = finalized(system, registration)
    assert completed["revision"] > incomplete["revision"]
    assert completed["counts"]["unreported_outcomes"] == completed["counts"]["uncertain_outcomes"] == 0
    assert completed["coverage"]["status"] == "complete"
    old = snapshot_page(system, incomplete["snapshot_id"])
    assert old["snapshot"]["counts"]["uncertain_outcomes"] == 1
    assert old_audit_id in json.dumps(old)
    assert known["outcome_audit_id"] not in json.dumps(old)


def test_snapshot_pages_survive_retention_and_remain_fixed_after_late_revision(system, monkeypatch):
    detection_settings(system)
    registration = registered(system)
    _, _, records, _ = action(system, registration, 10)
    observations = [event(registration, "response", text=f"retained-{index}:" + "x" * 1024 + f":tail-{index}") for index in range(128)]
    assert sensor_post(system, "events", {"events": observations})["accepted"] == len(observations)
    large = [
        event(registration, "response", text=f"large-{index}:" + "x" * size + f":large-tail-{index}")
        for index, size in enumerate((400 << 10, 400 << 10, 400 << 10, 1300 << 10))
    ]
    # Historical storage can contain bodies larger than present capture limits.
    system.db.ingest_batch(system.sensors["sensor"][0], large)
    observations.extend(large)
    nil = event(registration, "response", text="nil UUID observation retained")
    nil["id"] = "00000000-0000-0000-0000-000000000000"
    assert sensor_post(system, "events", {"events": [nil]})["accepted"] == 1
    records.extend(receipt("observation", index + 3, event_id=value["id"]) for index, value in enumerate(observations))
    for offset in range(0, len(records), 100):
        deliver(system, registration, records[offset:offset + 100])
    close_session(system, registration, len(records))
    transfers = []
    store_type = type(system.db)
    original_many = store_type.many

    def row_bytes(rows):
        return sum(len(json.dumps(row, ensure_ascii=False, default=str).encode()) for row in rows)

    def observe_real_fetch(store, *args, **kwargs):
        rows = original_many(store, *args, **kwargs)
        if rows and all("body" in row for row in rows):
            transfers.append((len(rows), row_bytes(rows)))
        return rows

    # Observe the actual database result boundary without changing SQL or data.
    monkeypatch.setattr(store_type, "many", observe_real_fetch)
    old = finalized(system, registration)
    assert old["coverage"]["status"] == "complete"
    default_page = system.client.get(
        f"/api/v1/me/session-snapshots/{old['snapshot_id']}", headers=system.headers["owner"],
    )
    assert default_page.status_code == 200, default_page.text
    assert len(default_page.json()["items"]) == 100
    first = snapshot_page(system, old["snapshot_id"], limit=7)
    assert len(first["items"]) == 7 and first["next_cursor"]
    assert default_page.json()["snapshot"]["item_count"] == first["snapshot"]["item_count"]

    def read_all(snapshot_id):
        items, cursor, oversized = [], "", 0
        while True:
            page = snapshot_page(system, snapshot_id, limit=500, cursor=cursor)
            size = row_bytes(page["items"])
            assert size <= 1 << 20 or len(page["items"]) == 1
            oversized += size > 1 << 20
            items.extend(page["items"])
            count = page["snapshot"]["item_count"]
            assert len(items) <= count
            cursor = page["next_cursor"]
            if not cursor:
                break
        assert len(items) == count
        assert len({item["ordinal"] for item in items}) == count
        assert oversized > 0
        retained = {item["source_id"]: item["body"]["text"] for item in items if item["kind"] == "observation" and "text" in item["body"]}
        for item in [*observations, nil]:
            assert retained[item["id"]] == item["text"]
        return items

    originals = read_all(old["snapshot_id"])
    original_json = json.dumps(originals)
    for index in range(128):
        assert f"retained-{index}:" in original_json and f":tail-{index}" in original_json
    session_id = system.db.scalar("SELECT id FROM agent_sessions WHERE registration_id=$1", registration["id"])
    system.db.execute("DELETE FROM events WHERE session_id=$1", session_id)
    assert deliver(system, registration, records[2:3])["duplicates"] == 1
    late = event(registration, "response", text="new revision only")
    sensor_post(system, "events", {"events": [late]})
    deliver(system, registration, [receipt("observation", len(records) + 1, event_id=late["id"])])
    close_session(system, registration, len(records) + 1)
    newest = finalized(system, registration)
    assert newest["revision"] > old["revision"]
    assert snapshot_page(system, old["snapshot_id"], limit=7) == first
    assert read_all(old["snapshot_id"]) == originals
    fresh = json.dumps(read_all(newest["snapshot_id"]))
    assert "new revision only" in fresh
    for index in range(128):
        assert f"retained-{index}:" in fresh and f":tail-{index}" in fresh
    snapshot_page(system, newest["snapshot_id"], cursor=first["next_cursor"], expected=400)
    assert transfers and any(size > 1 << 20 for _, size in transfers)
    assert all(size <= 1 << 20 or count == 1 for count, size in transfers), transfers


def test_finalizer_keeps_earlier_dirty_identity_that_commits_after_its_snapshot(system):
    detection_settings(system)
    registration = registered(system)
    _, first, first_records, _ = action(system, registration, 10)
    _, second, second_records, _ = action(system, registration, 20, sequence=3)
    deliver(system, registration, first_records + second_records)
    close_session(system, registration, 4)
    initial = finalized(system, registration)
    assert Decimal(initial["risk_total"]) == 30
    with ThreadPoolExecutor(max_workers=1) as pool:
        with system.db.transaction() as gate:
            system.db.execute(
                "UPDATE inline_guardrail_events SET assessment=assessment||$2 WHERE event_id=$1",
                first["event_id"], Jsonb({"score": 11}), conn=gate,
            )
            earlier = system.db.scalar("SELECT max(id) FROM session_input_dirty WHERE registration_id=$1", registration["id"], conn=gate)
            system.db.execute(
                "UPDATE inline_guardrail_events SET assessment=assessment||$2 WHERE event_id=$1",
                second["event_id"], Jsonb({"score": 22}),
            )
            later = system.db.scalar("SELECT max(id) FROM session_input_dirty WHERE registration_id=$1", registration["id"])
            assert later > earlier
            pending = pool.submit(finalized, system, registration)
            # The read snapshot must not wait for a child assessment lock.
            # The gate always exits before executor cleanup if this fails.
            snapshot = pending.result(timeout=3)
            assert Decimal(snapshot["risk_total"]) == 32
        assert system.db.scalar("SELECT count(*) FROM session_input_dirty WHERE id=$1", earlier) == 1
    assert status(system, registration)["snapshot_current"] is False
    latest = finalized(system, registration)
    assert Decimal(latest["risk_total"]) == 33
    assert latest["revision"] > snapshot["revision"]
    assert Decimal(snapshot_page(system, snapshot["snapshot_id"])["snapshot"]["risk_total"]) == 32


def test_strict_threshold_requires_both_worker_gates_and_reuses_snapshot_for_routing_changes(system):
    settings = detection_settings(system, risk_threshold="20")
    registration = completed_session(system, score=20)
    exact = finalized(system, registration, enabled=True, ready=True)
    assert exact["lifecycle"] == "closed" and exact["coverage"]["status"] == "complete"
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0
    updated = detection_settings(system, risk_threshold="19.9")
    assert updated["detector_config_version"] == settings["detector_config_version"]
    for enabled, ready in ((False, True), (True, False)):
        gated = finalized(system, registration, enabled=enabled, ready=ready)
        assert gated["snapshot_id"] == exact["snapshot_id"]
        assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0
    queued = finalized(system, registration, enabled=True, ready=True)
    assert queued["snapshot_id"] == exact["snapshot_id"]
    assert system.db.scalar("SELECT routing_reason FROM session_investigation_jobs") == "risk_threshold"
    assert finalized(system, registration, enabled=True, ready=True)["snapshot_id"] == queued["snapshot_id"]
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 1
    detection_settings(system, risk_threshold="19.9", max_runtime_seconds=6)
    changed = finalized(system, registration, enabled=True, ready=True)
    assert changed["snapshot_id"] == queued["snapshot_id"]
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 2
    assert system.db.scalar("SELECT count(DISTINCT detector_config_version) FROM session_investigation_jobs") == 2
    assert len(system.provider.requests) == system.db.scalar("SELECT count(*) FROM model_usage") == 1


@pytest.mark.parametrize("constraint", [
    {"max_concurrent": 1}, {"hourly_attempts": 1},
    {"hourly_tokens": 100}, {"hourly_cost_usd": "0.10"},
], ids=["concurrency", "attempts", "tokens", "cost"])
def test_concurrent_finalizers_and_claims_keep_one_job_and_atomic_tenant_budget(system, constraint):
    detection_settings(system, **{"risk_threshold": "0", "max_concurrent": 2, **constraint})
    first = completed_session(system, score=10)
    barrier = Barrier(2)

    def finalize():
        barrier.wait(timeout=5)
        return finalized(system, first, enabled=True, ready=True)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(finalize) for _ in range(2)]
        results = [future.result(timeout=5) for future in futures]
    assert results[0]["snapshot_id"] == results[1]["snapshot_id"]
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 1
    second = completed_session(system, score=10)
    finalized(system, second, enabled=True, ready=True)
    assert aggregation.claim_job(system.db, "unready", system.tenant["id"], worker_ready=False) is None
    barrier = Barrier(2)

    def claim(worker):
        barrier.wait(timeout=5)
        return aggregation.claim_job(system.db, worker, system.tenant["id"], worker_ready=True)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(claim, f"worker-{index}") for index in range(2)]
        claims = [future.result(timeout=5) for future in futures]
    assert sum(claim is not None for claim in claims) == 1
    attempt = system.db.one("SELECT state,reserved_tokens,reserved_cost_usd,actual_tokens,actual_cost_usd FROM session_investigation_attempts")
    assert attempt == {
        "state": "reserved", "reserved_tokens": 100, "reserved_cost_usd": Decimal("0.10"),
        "actual_tokens": None, "actual_cost_usd": None,
    }
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs WHERE state='running'") == 1
    assert system.db.scalar("SELECT count(*) FROM model_usage") == 2


def test_expired_worker_claims_fence_results_and_keep_reservations_separate_from_actual_usage(system):
    detection_settings(system, risk_threshold="0")
    registration = completed_session(system, score=10)
    finalized(system, registration, enabled=True, ready=True)
    first = aggregation.claim_job(system.db, "first", system.tenant["id"], worker_ready=True)
    assert first is not None
    with ThreadPoolExecutor(max_workers=1) as pool:
        with system.db.transaction() as gate:
            system.db.one("SELECT id FROM session_investigation_jobs WHERE id=$1 FOR UPDATE", first["job_id"], conn=gate)
            dispatch = pool.submit(aggregation.mark_dispatched, system.db, first["job_id"], first["claim_token"], first["attempt_id"])
            wait_for_blocker(system.db, gate.info.backend_pid)
            system.db.execute(
                "UPDATE session_investigation_jobs SET lease_deadline=clock_timestamp() WHERE id=$1",
                first["job_id"], conn=gate,
            )
            system.db.execute(
                "UPDATE session_investigation_attempts SET deadline_at=clock_timestamp() WHERE id=$1",
                first["attempt_id"], conn=gate,
            )
        assert dispatch.result(timeout=5) is False
    aggregation.expire_claims(system.db, system.tenant["id"])
    assert system.db.scalar("SELECT state FROM session_investigation_attempts WHERE id=$1", first["attempt_id"]) == "released"
    second = aggregation.claim_job(system.db, "second", system.tenant["id"], worker_ready=True)
    assert second["job_id"] == first["job_id"]
    assert second["attempt_id"] != first["attempt_id"] and second["claim_token"] != first["claim_token"]
    assert aggregation.mark_dispatched(system.db, first["job_id"], first["claim_token"], first["attempt_id"]) is False
    assert aggregation.finish_job(system.db, first["job_id"], first["claim_token"], first["attempt_id"], "completed", {"summary": "stale"}) is False
    assert aggregation.mark_dispatched(system.db, second["job_id"], second["claim_token"], second["attempt_id"]) is True
    system.db.execute(
        "UPDATE session_investigation_jobs SET lease_deadline=clock_timestamp() WHERE id=$1",
        second["job_id"],
    )
    system.db.execute(
        "UPDATE session_investigation_attempts SET deadline_at=clock_timestamp() WHERE id=$1",
        second["attempt_id"],
    )
    assert aggregation.expire_claims(system.db, system.tenant["id"]) == 1
    assert aggregation.claim_job(system.db, "third", system.tenant["id"], worker_ready=True) is None
    attempt = system.db.one(
        "SELECT state,reserved_tokens,reserved_cost_usd,actual_tokens,actual_cost_usd FROM session_investigation_attempts WHERE id=$1",
        second["attempt_id"],
    )
    assert attempt == {
        "state": "uncertain", "reserved_tokens": 100, "reserved_cost_usd": Decimal("0.10"),
        "actual_tokens": None, "actual_cost_usd": None,
    }
    terminal = system.db.one("SELECT state,result FROM session_investigation_jobs WHERE id=$1", second["job_id"])
    assert terminal["state"] == "inconclusive"
    assert aggregation.finish_job(
        system.db, second["job_id"], second["claim_token"], second["attempt_id"], "completed",
        {"summary": "late result", "actual_tokens": 25, "actual_cost_usd": "0.02"},
    ) is False
    assert system.db.one("SELECT state,result FROM session_investigation_jobs WHERE id=$1", second["job_id"]) == terminal
    assert system.db.one(
        "SELECT actual_tokens,actual_cost_usd FROM session_investigation_attempts WHERE id=$1", second["attempt_id"],
    ) == {"actual_tokens": 25, "actual_cost_usd": Decimal("0.02")}
    assert system.db.scalar("SELECT actual_tokens FROM session_investigation_attempts WHERE id=$1", first["attempt_id"]) is None
    assert len(system.provider.requests) == system.db.scalar("SELECT count(*) FROM model_usage") == 1


@pytest.mark.parametrize("source", ["receipt", "journal_lost"])
def test_explicit_gaps_need_selected_escalation_and_wait_before_routing(system, source):
    detection_settings(system, risk_threshold="1000")
    registration = registered(system)
    _, _, records, _ = action(system, registration, 10)
    expected_gaps = {"journal_lost"} if source == "journal_lost" else {"content_redacted", "backend_unavailable"}
    if source == "receipt":
        records.append(receipt("gap", 3, gaps=sorted(expected_gaps)))
    deliver(system, registration, records)
    close_session(system, registration, len(records), value=close_body(
        registration, len(records), reason="journal_lost" if source == "journal_lost" else "session_end",
    ))
    retained = finalized(system, registration, enabled=True, ready=True)
    assert retained["lifecycle"] == "incomplete"
    assert retained["coverage"]["status"] == "incomplete"
    assert expected_gaps <= set(retained["coverage"]["gaps"])
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0
    if source == "journal_lost":
        # A later well-formed manifest cannot restore lost capture history,
        # even when the measured risk would otherwise pass the normal route.
        close_session(system, registration, len(records))
        detection_settings(system, risk_threshold="0")
        retained = finalized(system, registration, enabled=True, ready=True)
        assert retained["coverage"]["status"] == "incomplete"
        assert "journal_lost" in retained["coverage"]["gaps"]
        assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0
    detection_settings(system, risk_threshold="1000", gap_policy="investigate", gap_wait_seconds=3600)
    waiting = finalized(system, registration, enabled=True, ready=True)
    assert waiting["snapshot_id"] == retained["snapshot_id"]
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0
    detection_settings(system, risk_threshold="1000", gap_policy="investigate", gap_wait_seconds=0)
    routed = finalized(system, registration, enabled=True, ready=True)
    assert routed["snapshot_id"] == retained["snapshot_id"]
    assert routed["coverage"]["status"] == "incomplete"
    assert routed["routing"]["reason"] == "persistent_gap"
    assert system.db.scalar("SELECT routing_reason FROM session_investigation_jobs") == "persistent_gap"
    assert Decimal(routed["risk_total"]) == 10
    assert len(system.provider.requests) == 1


def test_finalizer_evaluates_approval_expiry_after_waiting_for_registration_lock(system):
    detection_settings(system)
    approval_settings(system)
    registration = registered(system)
    _, checked, records, _ = action(system, registration, 50, finish=False)
    deliver(system, registration, records)
    close_session(system, registration, 1)
    assert finalized(system, registration)["counts"]["pending_approvals"] == 1
    with ThreadPoolExecutor(max_workers=1) as pool:
        with system.db.transaction() as gate:
            system.db.one("SELECT id FROM session_registrations WHERE id=$1 FOR UPDATE", registration["id"], conn=gate)
            system.db.execute(
                "UPDATE guardrail_approvals SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1",
                checked["approval"]["id"],
            )
            pending = pool.submit(finalized, system, registration)
            wait_for_blocker(system.db, gate.info.backend_pid)
            system.db.scalar(
                "SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM expires_at-clock_timestamp()))) FROM guardrail_approvals WHERE id=$1",
                checked["approval"]["id"], conn=gate,
            )
        expired = pending.result(timeout=5)
    assert expired["counts"]["pending_approvals"] == 0
    assert expired["snapshot_id"] is not None
    assert expired["lifecycle"] == "incomplete"
    assert expired["coverage"]["execution"]["status"] == "incomplete"
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0


def test_concurrent_close_and_last_receipt_preserve_complete_manifest(system):
    detection_settings(system)
    registration = registered(system)
    _, _, records, _ = action(system, registration, 10)
    deliver(system, registration, records[:1])
    barrier = Barrier(3)

    def submit_delivery():
        barrier.wait(timeout=5)
        return deliver(system, registration, records[1:])

    def submit_close():
        barrier.wait(timeout=5)
        return close_session(system, registration, 2)

    with ThreadPoolExecutor(max_workers=2) as pool:
        with system.db.transaction() as gate:
            system.db.one("SELECT id FROM session_registrations WHERE id=$1 FOR UPDATE", registration["id"], conn=gate)
            delivery = pool.submit(submit_delivery)
            closing = pool.submit(submit_close)
            barrier.wait(timeout=5)
            wait_for_blocker(system.db, gate.info.backend_pid)
        assert delivery.result(timeout=5)["accepted"] == 1
        assert closing.result(timeout=5)["duplicate"] is False
    completed = finalized(system, registration)
    assert completed["closing_sequence"] == completed["last_sequence"] == 2
    assert completed["coverage"]["status"] == "complete"
    assert completed["counts"]["logical_targets"] == 1


def test_ended_at_and_idle_deadline_never_manufacture_a_delivery_watermark(system):
    detection_settings(system, idle_seconds=1, gap_policy="investigate", gap_wait_seconds=1)
    registration = registered(system)
    _, _, records, _ = action(system, registration, 10)
    deliver(system, registration, records)
    system.db.execute("UPDATE agent_sessions SET ended_at=clock_timestamp() WHERE registration_id=$1", registration["id"])
    active = finalized(system, registration, enabled=True, ready=True)
    assert active["lifecycle"] == "active" and active["closing_sequence"] is None
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0
    system.db.scalar(
        "SELECT pg_sleep(GREATEST(0,2-EXTRACT(EPOCH FROM clock_timestamp()-last_activity_at))) FROM session_finalizations WHERE registration_id=$1",
        registration["id"],
    )
    idle = finalized(system, registration, enabled=True, ready=True)
    assert idle["lifecycle"] == "incomplete"
    assert idle["closing_sequence"] is None
    assert idle["coverage"]["status"] == "incomplete"
    assert "missing_watermark" in idle["coverage"]["gaps"]
    assert idle["delivery"]["complete"] is False
    assert Decimal(idle["risk_total"]) == 10
    assert idle["routing"]["status"] == "queued"
    assert idle["routing"]["reason"] == "persistent_gap"
    claim = aggregation.claim_job(system.db, "idle-worker", system.tenant["id"], worker_ready=True)
    assert claim is not None and claim["snapshot_id"] == idle["snapshot_id"]
    assert aggregation.mark_dispatched(system.db, claim["job_id"], claim["claim_token"], claim["attempt_id"]) is True


def test_new_revisions_supersede_queued_work_but_running_results_keep_original_snapshot(system):
    detection_settings(system, risk_threshold="0")
    registration = completed_session(system, score=10)
    first = finalized(system, registration, enabled=True, ready=True)
    late = event(registration, "response", text="Second closure")
    sensor_post(system, "events", {"events": [late]})
    deliver(system, registration, [receipt("observation", 3, event_id=late["id"])])
    close_session(system, registration, 3)
    second = finalized(system, registration, enabled=True, ready=True)
    assert second["snapshot_id"] != first["snapshot_id"]
    assert system.db.scalar("SELECT state FROM session_investigation_jobs WHERE snapshot_id=$1", first["snapshot_id"]) == "superseded"
    claim = aggregation.claim_job(system.db, "snapshot-worker", system.tenant["id"], worker_ready=True)
    assert claim["snapshot_id"] == second["snapshot_id"]
    assert aggregation.mark_dispatched(system.db, claim["job_id"], claim["claim_token"], claim["attempt_id"]) is True
    resumed = event(registration, "response", text="Resumed after worker claim")
    sensor_post(system, "events", {"events": [resumed]})
    deliver(system, registration, [receipt("observation", 4, event_id=resumed["id"])])
    active = finalized(system, registration, enabled=True, ready=True)
    assert active["lifecycle"] == "active" and active["snapshot_current"] is False
    assert aggregation.finish_job(
        system.db, claim["job_id"], claim["claim_token"], claim["attempt_id"], "completed",
        {"summary": "Investigation found password=review-secret", "finding_ids": [], "actual_tokens": 12, "actual_cost_usd": "0.01"},
    ) is True
    stored = system.db.one("SELECT state,snapshot_id,result FROM session_investigation_jobs WHERE id=$1", claim["job_id"])
    assert stored["state"] == "completed" and stored["snapshot_id"] == second["snapshot_id"]
    assert "review-secret" not in json.dumps(stored)
    assert stored["result"]["actual_tokens"] == 12
    assert "Resumed after worker claim" not in json.dumps(snapshot_page(system, second["snapshot_id"]))
    assert status(system, registration)["snapshot_current"] is False
    assert len(system.provider.requests) == 1


def test_finalization_timeout_preserves_inputs_and_bounded_queue_reconsiders_gates(system):
    detection_settings(system)
    first = completed_session(system, score=10)
    dirty_before = system.db.scalar("SELECT count(*) FROM session_input_dirty WHERE registration_id=$1", first["id"])
    expired = aggregation.finalize_one(system.db, first["id"], max_seconds=1e-9)
    assert expired["finalization_error"] == "finalization_timeout"
    assert expired["snapshot_current"] is False
    assert system.db.scalar("SELECT count(*) FROM session_snapshots") == 0
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0
    assert system.db.scalar("SELECT count(*) FROM session_input_dirty WHERE registration_id=$1", first["id"]) == dirty_before
    assert system.db.scalar("SELECT count(*) FROM session_delivery_receipts WHERE registration_id=$1", first["id"]) == 3
    assert aggregation.finalize_pending(system.db, system.tenant["id"], limit=1) == 0
    recovered = finalized(system, first)
    assert recovered["coverage"]["status"] == "complete" and recovered["snapshot_current"] is True
    second = completed_session(system, score=20)
    assert aggregation.finalize_pending(system.db, system.tenant["id"], limit=1) == 1
    assert status(system, second)["snapshot_current"] is True
    assert aggregation.finalize_pending(system.db, system.tenant["id"], limit=1) == 0
    detection_settings(system, risk_threshold="0")
    for _ in range(2):
        assert aggregation.finalize_pending(system.db, system.tenant["id"], limit=1) == 1
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0
    for count in (1, 2):
        assert aggregation.finalize_pending(system.db, system.tenant["id"], limit=1, scheduling_enabled=True, worker_ready=True) == 1
        assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == count
    assert aggregation.finalize_pending(system.db, system.tenant["id"], limit=1, scheduling_enabled=True, worker_ready=True) == 0
    assert system.db.scalar("SELECT count(*) FROM session_snapshots") == 2
    aggregation.finalize_one(system.db, first["id"], max_seconds=1e-9)
    failed = status(system, first)
    assert failed["snapshot_current"] is False
    assert failed["finalization_error"] == "finalization_timeout"
    claim = aggregation.claim_job(system.db, "healthy-snapshot", system.tenant["id"], worker_ready=True)
    assert claim is not None
    assert claim["snapshot_id"] == status(system, second)["snapshot_id"]
    aggregation.finalize_one(system.db, second["id"], max_seconds=1e-9)
    assert status(system, second)["finalization_error"] == "finalization_timeout"
    assert aggregation.mark_dispatched(system.db, claim["job_id"], claim["claim_token"], claim["attempt_id"]) is False
    recovered_again = finalized(system, first)
    assert recovered_again["snapshot_id"] == recovered["snapshot_id"]
    assert status(system, first)["finalization_error"] is None
    finalized(system, second)
    assert aggregation.mark_dispatched(system.db, claim["job_id"], claim["claim_token"], claim["attempt_id"]) is True
    assert len(system.provider.requests) == 2


def test_threshold_change_cannot_starve_eligible_work_behind_a_full_rejected_page(system):
    detection_settings(system, risk_threshold="0")
    low = completed_session(system, score=10)
    template = finalized(system, low, enabled=True, ready=True)
    seed_queue(system, low, template)
    high = completed_session(system, score=90)
    eligible = finalized(system, high, enabled=True, ready=True)
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs WHERE state='queued'") == 102
    detection_settings(system, risk_threshold="80")
    claim = None
    for _ in range(2):
        claim = aggregation.claim_job(system.db, "progress-worker", system.tenant["id"], worker_ready=True)
        if claim is not None:
            break
    assert claim is not None
    assert claim["snapshot_id"] == eligible["snapshot_id"]
    assert system.db.scalar("SELECT count(*) FROM session_investigation_attempts") == 1
    assert len(system.provider.requests) == 2


def test_busy_tenant_cannot_starve_eligible_work_for_another_tenant(system, monkeypatch, tmp_path):
    detection_settings(system, risk_threshold="0", max_runtime_seconds=600)
    registration = completed_session(system, score=10)
    template = finalized(system, registration, enabled=True, ready=True)
    seed_queue(system, registration, template)
    first = aggregation.claim_job(system.db, "busy-tenant", system.tenant["id"], worker_ready=True)
    assert first is not None
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs WHERE state='queued'") == 100
    other = copy(system)
    other.tenant = {"id": system.users["foreign"]["tenant_id"]}
    other.headers = {
        **system.headers, "admin": system.headers["foreign"], "owner": system.headers["foreign"],
        "sensor": system.headers["foreign_sensor"],
    }
    other.settings = None
    other.client, other.cfg = system.foreign_client, system.foreign_client.app.state.service.cfg
    from intelligence_fixture import intelligence_service
    with intelligence_service(monkeypatch, tmp_path, other.tenant["id"], system.provider.handle,
                              guardrail_key="test-provider-key") as api:
        for key, value in api.config.items():
            setattr(other.cfg, key, value)
        detection_settings(other, risk_threshold="0", max_runtime_seconds=600)
        other_registration = completed_session(other, score=10)
        eligible = finalized(other, other_registration, enabled=True, ready=True)
        claim = aggregation.claim_job(system.db, "global-worker", worker_ready=True)
        assert claim is not None and claim["snapshot_id"] == eligible["snapshot_id"]
        assert aggregation.claim_job(system.db, "capped-worker", other.tenant["id"], worker_ready=True) is None
        assert system.db.scalar("SELECT count(*) FROM session_investigation_attempts") == 2
        assert len(system.provider.requests) == 2


def test_settings_disable_serializes_with_dispatch_intent_and_stops_new_claims(system):
    detection_settings(system, risk_threshold="0")
    for _ in range(2):
        registration = completed_session(system, score=10)
        finalized(system, registration, enabled=True, ready=True)
    claim = aggregation.claim_job(system.db, "dispatch-worker", system.tenant["id"], worker_ready=True)
    assert claim is not None
    with ThreadPoolExecutor(max_workers=2) as pool:
        with system.db.transaction() as gate:
            system.db.one("SELECT id FROM session_investigation_jobs WHERE id=$1 FOR UPDATE", claim["job_id"], conn=gate)
            dispatch = pool.submit(aggregation.mark_dispatched, system.db, claim["job_id"], claim["claim_token"], claim["attempt_id"])
            wait_for_blocker(system.db, gate.info.backend_pid)
            dispatch_pid = system.db.scalar(
                "SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))", gate.info.backend_pid,
            )
            disable = pool.submit(browser, system, "PUT", "response/session-detection", {"enabled": False})
            wait_for_blocker(system.db, dispatch_pid)
            assert disable.done() is False
        assert dispatch.result(timeout=5) is True
        disabled = disable.result(timeout=5)
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["enabled"] is False
    assert system.db.scalar("SELECT state FROM session_investigation_attempts WHERE id=$1", claim["attempt_id"]) == "dispatched"
    assert aggregation.claim_job(system.db, "disabled-worker", system.tenant["id"], worker_ready=True) is None


def test_new_selection_settings_validate_nulls_and_preserve_explicit_legacy_configuration(system):
    initial = browser(system, "GET", "response/session-detection").json()
    assert initial["selection_policy"] == "risk_budget" and initial["history_days"] == 7
    assert initial["sample_percent"] == "0"
    legacy = detection_settings(system)
    assert legacy["selection_policy"] == "legacy"
    for name in aggregation.SELECTION_DEFAULTS:
        response = browser(system, "PUT", "response/session-detection", {"enabled": True, name: None})
        assert response.status_code == 400, (name, response.text)
    for value in ({"history_days": 91}, {"sample_percent": "2"}, {"sample_percent": "0.1"}, {"urgent_risk_threshold": 69}):
        assert browser(system, "PUT", "response/session-detection", {"enabled": True, **value}).status_code == 400
    assert detection_settings(system, sample_percent="0")["sample_percent"] == "0"
    assert browser(system, "GET", "response/session-detection").json()["selection_policy"] == "legacy"


@pytest.mark.parametrize("gap", [False, True])
def test_managed_close_enters_selection_without_a_telemetry_end_marker(system, gap):
    detection_settings(system, selection_policy="risk_budget", sample_percent="0",
                       session_high_risk_actions=1, delivery_grace_seconds=60, gap_wait_seconds=60)
    registration = registered(system)
    _, _, records, _ = action(system, registration, score=85,
                              gaps=["unsupported_boundary"] if gap else None)
    deliver(system, registration, records)
    active = finalized(system, registration, enabled=True, ready=True)
    assert active["routing"]["status"] == "waiting_coverage"
    assert aggregation.claim_job(system.db, "still-active", worker_ready=True) is None

    close_session(system, registration, len(records))
    if gap:
        waiting = finalized(system, registration, enabled=True, ready=True)
        assert waiting["routing"]["status"] == "waiting_coverage"
        assert aggregation.claim_job(system.db, "delivery-grace", worker_ready=True) is None
        detection_settings(system, selection_policy="risk_budget", sample_percent="0",
                           session_high_risk_actions=1, delivery_grace_seconds=0, gap_wait_seconds=0)
    state = finalized(system, registration, enabled=True, ready=True)
    assert state["lifecycle"] == ("incomplete" if gap else "closed")
    assert state["routing"]["status"] == "queued"
    assert state["routing"]["reason"] == "session_risk"
    assert state["selection"]["signals"]["population_sessions"] == 1
    assert system.db.scalar("SELECT ended_at FROM agent_sessions WHERE registration_id=$1",
                            registration["id"]) is None
    assert aggregation.claim_job(system.db, "managed-close", worker_ready=True)


def test_managed_urgent_investigation_captures_active_evidence_and_claims_independently(system):
    detection_settings(system, selection_policy="risk_budget", sample_percent="0")
    registration = registered(system)
    action(system, registration, score=99)
    state = finalized(system, registration, enabled=True, ready=True)
    assert state["routing"]["reason"] == "urgent_risk"
    assert state["coverage"]["status"] == "incomplete"
    assert state["coverage"]["active_session"]
    assert state["selection"]["signals"]["population_sessions"] == 0
    assert aggregation.claim_job(system.db, "managed-urgent", worker_ready=True)


def test_managed_session_outside_selection_history_stops_periodic_finalization(system):
    detection_settings(system, selection_policy="risk_budget", sample_percent="0")
    registration = completed_session(system, score=85)
    system.db.execute(
        """UPDATE agent_sessions SET started_at=now()-interval '9 days',
           last_event_at=now()-interval '8 days',ended_at=now()-interval '8 days'
           WHERE tenant_id=$1 AND registration_id=$2""",
        system.tenant["id"], registration["id"],
    )
    state = finalized(system, registration, enabled=True, ready=True)
    assert state["selection"]["signals"]["outside_history_window"]
    assert state["next_evaluation_at"] is None
    assert system.db.scalar("SELECT next_evaluation_at FROM session_finalizations WHERE registration_id=$1", registration["id"]) is None
    assert aggregation.finalize_pending(system.db, scheduling_enabled=True, worker_ready=True) == 0
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0
