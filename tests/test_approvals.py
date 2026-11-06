"""Durable owner approvals through real HTTP and PostgreSQL.

Only the external JEV HTTP transport is mocked.
"""

from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import replace
import json
from threading import Barrier, Event, Lock

from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb
import pytest

from openaidr.core.event import new_id
from openaidr.server.app import create_app
from test_inline_guardrail import (
    Provider,
    browser,
    check,
    configure,
    event,
    managed,
    payload,
    policy,
    system as system,
)
from test_session_ownership import wait_for_blocker
from test_store import db as db


def approval_settings(system, **changes):
    values = {
        "enabled": True, "ask_threshold": 40, "block_threshold": 80,
        "timeout_ms": 10000, "approvals_enabled": True,
        "approval_wait_seconds": 600, "approval_use_seconds": 300,
        **changes,
    }
    response = browser(system, "PUT", "response/guardrails", values)
    assert response.status_code == 200, response.text
    system.settings = response.json()
    return system.settings


def sensor_post(system, path, value=None, *, device="sensor", expected=200, client=None):
    target = getattr(system, "foreign_client", system.client) if device == "foreign_sensor" else system.client
    response = (client or target).post(
        "/ingest/v1/" + path, json={} if value is None else value,
        headers=system.headers.get(device, {}),
    )
    assert response.status_code == expected, response.text
    if path != "events":
        assert response.headers["cache-control"] == "no-store"
    return response.json()


def owner_request(system, method, approval_id, operation="", value=None, *, user="owner", expected=200, client=None):
    path = "/api/v1/me/approvals/" + approval_id + operation
    selected_client = client or (system.foreign_client if user == "foreign" else system.client)
    response = selected_client.request(method, path, json=value, headers=system.headers.get(user, {}))
    assert response.status_code == expected, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def decide(system, approval_id, decision="approve", **options):
    return owner_request(system, "POST", approval_id, "/decision", {"decision": decision}, **options)


def consume_body(result, request_id=None):
    return {"request_id": request_id or new_id(), "action_commitment": result["action_commitment"]}


def consume(system, result, value=None, *, expected=201, **options):
    return sensor_post(
        system, f"guardrail-checks/{result['id']}/consume",
        consume_body(result) if value is None else value, expected=expected, **options,
    )


def asked(system, *, target=None, context=None, registration=None):
    if system.settings is None:
        approval_settings(system)
    registration = registration or managed(system)
    system.provider.payload = Provider.scored(50)
    value = payload(system, registration, target, context)
    result = check(system, value)
    assert result["decision"]["action"] == "ask"
    assert result["approval"]["availability"] == "available"
    assert result["approval"]["status"] == "pending"
    return registration, value, result


def test_approval_settings_are_explicit_and_independent_of_model_scoring(system):
    configure(system)
    defaults = browser(system, "GET", "response/guardrails").json()
    assert defaults["approvals_enabled"] is False
    assert defaults["approval_wait_seconds"] is None and defaults["approval_use_seconds"] is None
    base = {"enabled": True, "ask_threshold": 40, "block_threshold": 80, "timeout_ms": 10000}
    for fields in (
        {"approvals_enabled": True},
        {"approvals_enabled": True, "approval_wait_seconds": True, "approval_use_seconds": 300},
        {"approvals_enabled": True, "approval_wait_seconds": 600, "approval_use_seconds": 0},
    ):
        assert browser(system, "PUT", "response/guardrails", {**base, **fields}).status_code == 400
    registration = managed(system)
    system.provider.payload = Provider.scored(50)
    value = payload(system, registration)
    disabled = check(system, value)
    assert disabled["decision"]["action"] == "ask"
    assert disabled["approval"] == {"availability": "disabled", "status": "unavailable"}
    assert consume(system, disabled, expected=409)["error"]["code"] == "approvals_disabled"
    assert system.db.scalar("SELECT count(*) FROM guardrail_approvals") == 0
    approval_settings(system)
    # A PR3-only settings writer must preserve explicit approval settings.
    configure(system)
    assert system.settings["approvals_enabled"] is True
    assert system.settings["approval_wait_seconds"] == 600
    assert system.settings["approval_use_seconds"] == 300
    policy(system, "ask")
    approval_settings(system, enabled=False)
    unavailable = check(system, payload(system, registration))
    assert unavailable["assessment"]["status"] == "unavailable"
    assert unavailable["assessment"]["score"] is None
    assert unavailable["decision"]["action"] == "ask"
    approved = decide(system, unavailable["approval"]["id"])
    assert approved["assessment"]["score"] is None
    assert consume(system, unavailable)["granted"] is True
    assert len(system.provider.requests) == 1


def test_allow_ask_block_require_explicit_single_release_and_preserve_assessment(system):
    approval_settings(system)
    registration = managed(system)
    for score, action in ((0, "allow"), (50, "ask"), (90, "block")):
        system.provider.payload = Provider.scored(score)
        result = check(system, payload(system, registration))
        assert result["decision"]["action"] == action
        original = system.db.scalar("SELECT assessment FROM inline_guardrail_events WHERE event_id=$1", result["event_id"])
        releases_before = system.db.scalar("SELECT count(*) FROM guardrail_releases")
        if action == "block":
            assert consume(system, result, expected=409)["error"]["code"] == "action_blocked"
            continue
        if action == "ask":
            approval_id = result["approval"]["id"]
            owner_request(system, "GET", approval_id)
            sensor_post(system, f"approvals/{approval_id}/status")
            assert consume(system, result, expected=409)["error"]["code"] == "approval_pending"
            approved = decide(system, approval_id)
            assert approved["status"] == "approved" and approved["release"] is None
            assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == releases_before
        receipt = consume(system, result)
        assert receipt["granted"] is True and receipt["replayed"] is False
        assert receipt["outcome"] is None and receipt["outcome_at"] is None
        assert receipt["approval_id"] == (result["approval"]["id"] if action == "ask" else None)
        assert system.db.scalar("SELECT assessment FROM inline_guardrail_events WHERE event_id=$1", result["event_id"]) == original
        assert system.db.scalar("SELECT decision FROM inline_guardrail_checks WHERE id=$1", result["id"])["action"] == action
    assert system.db.scalar("SELECT count(*) FROM guardrail_approvals") == 1
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 2
    assert len(system.provider.requests) == 3
    assert system.db.scalar("SELECT count(*) FROM model_usage") == 3


@pytest.mark.parametrize("phase", ["pending", "approved"])
def test_aliases_keep_expired_generation_and_only_fresh_check_renews_without_rescore(system, phase):
    _, value, first = asked(system)
    alias_payload = {**value, "request_id": new_id()}
    alias = check(system, alias_payload)
    approval_id = first["approval"]["id"]
    assert alias["approval"]["id"] == approval_id
    assert alias["approval"]["generation"] == first["approval"]["generation"] == 1
    if phase == "approved":
        decide(system, approval_id)
    column = "expires_at" if phase == "pending" else "approved_until"
    system.db.execute(f"UPDATE guardrail_approvals SET {column}=clock_timestamp() WHERE id=$1", approval_id)
    assert owner_request(system, "GET", approval_id)["status"] == "expired"
    for old_payload in (value, alias_payload):
        old = check(system, old_payload)
        assert old["approval"]["id"] == approval_id and old["approval"]["status"] == "expired"
    assert consume(system, alias, expected=409)["error"]["code"] == "approval_expired"
    renewed = check(system, {**value, "request_id": new_id()})
    assert renewed["approval"]["id"] != approval_id
    assert renewed["approval"]["generation"] == 2
    assert renewed["logical_id"] == first["logical_id"]
    assert renewed["assessment"] == first["assessment"]
    assert consume(system, renewed, expected=409)["error"]["code"] == "approval_pending"
    decide(system, renewed["approval"]["id"])
    assert consume(system, renewed)["granted"] is True
    assert len(system.provider.requests) == 1
    assert system.db.scalar("SELECT count(*) FROM inline_guardrail_events") == 1


@pytest.mark.parametrize("terminal", ["reject", "revoke"])
def test_owner_rejection_or_revocation_is_sticky_across_aliases_and_new_allow_policy(system, terminal):
    _, value, result = asked(system)
    approval_id = result["approval"]["id"]
    if terminal == "reject":
        assert decide(system, approval_id, "reject")["status"] == "rejected"
        assert decide(system, approval_id, "reject")["status"] == "rejected"
        assert decide(system, approval_id, "approve", expected=409)["error"]["code"] == "approval_decided"
    else:
        decide(system, approval_id)
        assert owner_request(system, "POST", approval_id, "/revoke", {})["status"] == "revoked"
        assert owner_request(system, "POST", approval_id, "/revoke", {})["status"] == "revoked"
    assert consume(system, result, expected=409)["error"]["code"] == "action_rejected"
    assert check(system, {**value, "request_id": new_id()}, expected=409)["error"]["code"] == "action_rejected"
    version = policy(system, "allow")
    revised = {**value, "request_id": new_id(), "policy_version": version}
    assert check(system, revised, expected=409)["error"]["code"] == "action_rejected"
    assert system.db.scalar("SELECT count(*) FROM guardrail_approvals") == 1
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0
    assert len(system.provider.requests) == 1


def test_only_verified_owner_can_review_or_decide_with_csrf_and_retained_api_only_preview(system):
    approval_settings(system)
    registration = managed(system, product="claude-code")
    target = event(registration, command={"text": "run-job password=approval-preview-secret"})
    target["evidence"]["password"] = "approval-metadata-secret"
    prompt = event(registration, "prompt", text="Intent visible only to the session owner")
    context = {"prior_events": [], "latest_prompt": prompt, "matched_tool_call": None, "gaps": ["parser_restart"]}
    _, _, result = asked(system, registration=registration, target=target, context=context)
    approval_id = result["approval"]["id"]
    for user in ("admin", "foreign"):
        owner_request(system, "GET", approval_id, user=user, expected=404)
        decide(system, approval_id, user=user, expected=404)
        owner_request(system, "POST", approval_id, "/revoke", {}, user=user, expected=404)
    owner_request(system, "GET", approval_id, user="anonymous", expected=401)
    path = f"/api/v1/me/approvals/{approval_id}/decision"
    assert system.client.post(path, json={"decision": "approve"}, headers={
        "Cookie": system.headers["owner"]["Cookie"],
    }).status_code == 403
    assert system.client.post(path, json={"decision": "approve"}, headers={
        **system.headers["owner"], "Origin": "https://foreign.example",
    }).status_code == 403
    nested = '{"decision":' + '[' * 1200 + 'null' + ']' * 1200 + '}'
    malformed = system.client.post(path, content=nested, headers={
        **system.headers["owner"], "Content-Type": "application/json",
    })
    assert malformed.status_code == 400 and malformed.headers["cache-control"] == "no-store"
    for device in ("peer_sensor", "foreign_sensor"):
        sensor_post(system, f"approvals/{approval_id}/status", device=device, expected=404)
        consume(system, result, device=device, expected=404)
    status = sensor_post(system, f"approvals/{approval_id}/status")
    assert not {"preview", "owner_user_id", "email", "assessment"} & status.keys()
    assert "Intent visible" not in json.dumps(status)
    system.db.execute("DELETE FROM events WHERE id=$1", result["event_id"])
    api_cfg = replace(system.cfg)
    api_cfg.set_services("api")
    with TestClient(create_app(api_cfg, system.db)) as api_only:
        detail = owner_request(system, "GET", approval_id, client=api_only)
        assert detail["client"]["product"] == "claude-code"
        assert detail["tenant"]["id"] == system.tenant["id"]
        assert detail["device"]["id"] == system.sensors["sensor"][0]["id"]
        assert detail["boundary"] == "tool_call"
        assert detail["preview_withheld"] is False
        assert detail["preview"]["target"]["id"] == target["id"]
        assert "Intent visible" in json.dumps(detail["preview"])
        assert "approval-preview-secret" not in json.dumps(detail)
        assert "approval-metadata-secret" not in json.dumps(detail)
        assert {"content_redacted", "parser_restart"} <= set(detail["gaps"])
        assert decide(system, approval_id, client=api_only)["status"] == "approved"
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0
    assert len(system.provider.requests) == 1


def test_blocked_api_only_approval_reads_preserve_auth_workers_and_bound_admission(system):
    _, _, result = asked(system)
    approval_id = result["approval"]["id"]
    start, overloaded = Event(), Event()
    count_lock = Lock()
    overload_count = 0
    request_count = 52
    api_cfg = replace(system.cfg)
    api_cfg.set_services("api")
    with TestClient(create_app(api_cfg, system.db)) as api_only:
        def read_approval():
            nonlocal overload_count
            assert start.wait(5), "request start gate was not released"
            response = api_only.get(
                f"/api/v1/me/approvals/{approval_id}", headers=system.headers["owner"],
            )
            if response.status_code == 503 and response.json()["error"]["code"] == "unavailable":
                with count_lock:
                    overload_count += 1
                    if overload_count >= request_count - system.cfg.ingest_concurrency:
                        overloaded.set()
            return response

        pending, auth_future = [], None
        with ThreadPoolExecutor(max_workers=request_count + 1) as pool:
            try:
                with system.db.transaction() as gate:
                    system.db.one("SELECT id FROM guardrail_approvals WHERE id=$1 FOR UPDATE", approval_id, conn=gate)
                    pending = [pool.submit(read_approval) for _ in range(request_count)]
                    start.set()
                    wait_for_blocker(system.db, gate.info.backend_pid)
                    assert overloaded.wait(5), "owner approval admission did not reject excess requests"
                    auth_future = pool.submit(
                        api_only.get, "/api/v1/auth/me", headers=system.headers["owner"],
                    )
                    response = auth_future.result(timeout=1)
                    assert response.status_code == 200, response.text
                    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0
            finally:
                # The gate is released before waiting for HTTP workers even
                # when admission or the unrelated auth request fails.
                start.set()
                workers = pending + ([auth_future] if auth_future else [])
                _, unfinished = wait(workers, timeout=15)
                assert not unfinished, "approval reads did not finish after gate release"
        responses = [future.result() for future in pending]
    assert all(response.status_code in (200, 503) for response in responses)
    assert all(response.headers["cache-control"] == "no-store" for response in responses)
    assert overload_count >= request_count - system.cfg.ingest_concurrency
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0
    assert len(system.provider.requests) == 1


def test_assistant_response_approval_withholds_held_text_and_context_copy(system):
    approval_settings(system)
    registration = managed(system)
    nonce = "held-response-" + new_id()
    target = event(registration, "response", text=nonce)
    context = {
        "prior_events": [event(registration, "response", text="Context copy: " + nonce)],
        "latest_prompt": event(registration, "prompt", text="Prompt copy: " + nonce),
        "matched_tool_call": None, "gaps": ["parser_restart"],
    }
    system.provider.payload = {
        **Provider.scored(50), "explanation": "Quoted response: " + nonce, "reason": nonce,
    }
    result = check(system, payload(system, registration, target, context))
    approval_id = result["approval"]["id"]
    # Today's provider parser discards these fields. Seed retained extensions
    # to verify that the owner DTO independently withholds free-form text.
    system.db.execute(
        "UPDATE inline_guardrail_events SET assessment=assessment||$2 WHERE event_id=$1",
        target["id"], Jsonb({"explanation": "Quoted response: " + nonce, "reason": nonce}),
    )
    system.db.execute(
        "UPDATE inline_guardrail_checks SET decision=decision||$2 WHERE id=$1",
        result["id"], Jsonb({"reason": nonce, "warnings": ["Quoted response: " + nonce]}),
    )
    detail = owner_request(system, "GET", approval_id)
    assert detail["boundary"] == "assistant_response"
    assert detail["preview"] is None and detail["preview_withheld"] is True
    assert nonce not in json.dumps(detail)
    assert detail["assessment"]["score"] == 50
    assert set(detail["assessment"]) <= {"status", "score", "category", "level"}
    assert detail["warnings"] == []
    assert "parser_restart" in detail["gaps"]
    assert consume(system, result, expected=409)["error"]["code"] == "approval_pending"
    approved = decide(system, approval_id)
    assert approved["status"] == "approved"
    assert approved["preview"] is None and approved["preview_withheld"] is True
    assert nonce not in json.dumps(approved)
    assert approved["reason"] == detail["reason"] and approved["warnings"] == []
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0
    stored = system.db.one("SELECT target_body,captured_context,assessment FROM inline_guardrail_events WHERE event_id=$1", target["id"])
    assert nonce in json.dumps(stored["target_body"])
    assert nonce in json.dumps(stored["captured_context"])
    assert nonce in json.dumps(stored["assessment"])


def test_concurrent_owner_choices_have_one_winner_and_never_release(system):
    _, _, result = asked(system)
    approval_id = result["approval"]["id"]
    start = Barrier(2)

    def submit(decision):
        start.wait(timeout=5)
        return system.client.post(
            f"/api/v1/me/approvals/{approval_id}/decision",
            json={"decision": decision}, headers=system.headers["owner"],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        with system.db.transaction() as gate:
            system.db.one("SELECT id FROM guardrail_approvals WHERE id=$1 FOR UPDATE", approval_id, conn=gate)
            pending = [pool.submit(submit, choice) for choice in ("approve", "reject")]
            wait_for_blocker(system.db, gate.info.backend_pid)
        responses = [future.result(5) for future in pending]
    assert sorted(response.status_code for response in responses) == [200, 409]
    winner = next(response.json() for response in responses if response.status_code == 200)
    loser = next(response.json() for response in responses if response.status_code == 409)
    assert loser["error"]["code"] == "approval_decided"
    assert system.db.one("SELECT decision,decided_by_user_id FROM guardrail_approvals WHERE id=$1", approval_id) == {
        "decision": winner["decision"], "decided_by_user_id": system.users["owner"]["id"],
    }
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0
    assert system.db.scalar("SELECT count(*) FROM audit_log WHERE action IN ('guardrail.approval.approve','guardrail.approval.reject')") == 1


@pytest.mark.parametrize("first", ["approve", "consume"])
def test_concurrent_approval_and_consumption_follow_the_committed_owner_choice(system, first):
    _, _, result = asked(system)
    approval_id = result["approval"]["id"]
    request = consume_body(result)

    def submit(operation):
        if operation == "approve":
            return system.client.post(
                f"/api/v1/me/approvals/{approval_id}/decision",
                json={"decision": "approve"}, headers=system.headers["owner"],
            )
        return system.client.post(
            f"/ingest/v1/guardrail-checks/{result['id']}/consume",
            json=request, headers=system.headers["sensor"],
        )

    second = "consume" if first == "approve" else "approve"
    with ThreadPoolExecutor(max_workers=2) as pool:
        with system.db.transaction() as gate:
            system.db.one("SELECT id FROM guardrail_approvals WHERE id=$1 FOR UPDATE", approval_id, conn=gate)
            first_future = pool.submit(submit, first)
            wait_for_blocker(system.db, gate.info.backend_pid)
            first_pid = system.db.scalar(
                "SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))",
                gate.info.backend_pid,
            )
            second_future = pool.submit(submit, second)
            # The first operation holds the sensor lock while it waits for
            # the approval row. The second must wait for that same operation.
            wait_for_blocker(system.db, first_pid)
        responses = {first: first_future.result(5), second: second_future.result(5)}
    approved = responses["approve"]
    assert approved.status_code == 200, approved.text
    assert approved.json()["release"] is None
    consumed = responses["consume"]
    if first == "approve":
        assert consumed.status_code == 201, consumed.text
        assert consumed.json()["granted"] is True
    else:
        assert consumed.status_code == 409, consumed.text
        assert consumed.json()["error"]["code"] == "approval_pending"
        assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0
        assert consume(system, result, request)["granted"] is True
    replay = consume(system, result, request, expected=200)
    assert replay["granted"] is False and replay["replayed"] is True
    assert replay["outcome"] is None
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 1
    assert system.db.scalar("SELECT count(*) FROM audit_log WHERE action='guardrail.release.consume'") == 1
    assert len(system.provider.requests) == 1


def test_consume_rechecks_policy_after_wait_and_persists_revocation_on_conflict(system):
    _, value, result = asked(system)
    approval_id = result["approval"]["id"]
    decide(system, approval_id)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with system.db.transaction() as gate:
            system.db.one("SELECT version FROM policies WHERE tenant_id=$1 FOR UPDATE", system.tenant["id"], conn=gate)
            pending = pool.submit(consume, system, result, expected=409)
            wait_for_blocker(system.db, gate.info.backend_pid)
            changed = system.db.one(
                "UPDATE policies SET version=version+1,rules=$2,ask_rule_ids='{}' WHERE tenant_id=$1 RETURNING version",
                system.tenant["id"], Jsonb([{
                    "id": "new-deny", "name": "New deny", "enabled": True,
                    "action": "deny", "match": {"kinds": ["command"]},
                }]), conn=gate,
            )["version"]
        assert pending.result(5)["error"]["code"] == "policy_changed"
    row = system.db.one("SELECT status,reason_code FROM guardrail_approvals WHERE id=$1", approval_id)
    assert row == {"status": "revoked", "reason_code": "policy_changed"}
    revised = check(system, {**value, "request_id": new_id(), "policy_version": changed})
    assert revised["decision"]["action"] == "block"
    assert consume(system, revised, expected=409)["error"]["code"] == "action_blocked"
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0
    assert len(system.provider.requests) == 1


@pytest.mark.parametrize("operation", ["decide", "consume"])
def test_approval_expiry_is_checked_after_real_row_wait_and_commits_on_conflict(system, operation):
    _, _, result = asked(system)
    approval_id = result["approval"]["id"]
    if operation == "consume":
        decide(system, approval_id)
    audit_before = system.db.scalar("SELECT count(*) FROM audit_log")
    with ThreadPoolExecutor(max_workers=1) as pool:
        with system.db.transaction() as gate:
            system.db.one("SELECT id FROM guardrail_approvals WHERE id=$1 FOR UPDATE", approval_id, conn=gate)
            pending = pool.submit(
                decide if operation == "decide" else consume,
                system, approval_id if operation == "decide" else result, expected=409,
            )
            wait_for_blocker(system.db, gate.info.backend_pid)
            column = "expires_at" if operation == "decide" else "approved_until"
            system.db.execute(
                f"UPDATE guardrail_approvals SET {column}=clock_timestamp() WHERE id=$1",
                approval_id, conn=gate,
            )
        assert pending.result(5)["error"]["code"] == "approval_expired"
    expired = system.db.one("SELECT status,decision FROM guardrail_approvals WHERE id=$1", approval_id)
    assert expired == {"status": "expired", "decision": None if operation == "decide" else "approve"}
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0
    assert system.db.scalar("SELECT count(*) FROM audit_log") > audit_before


@pytest.mark.parametrize("same_request", [False, True])
def test_concurrent_consumption_has_exactly_one_grant_and_one_release(system, same_request):
    _, _, result = asked(system)
    decide(system, result["approval"]["id"])
    first = consume_body(result)
    second = first if same_request else consume_body(result)
    start = Barrier(2)

    def submit(value):
        start.wait(timeout=5)
        return system.client.post(
            f"/ingest/v1/guardrail-checks/{result['id']}/consume",
            json=value, headers=system.headers["sensor"],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        with system.db.transaction() as gate:
            system.db.one("SELECT id FROM inline_guardrail_events WHERE event_id=$1 FOR UPDATE", result["event_id"], conn=gate)
            pending = [pool.submit(submit, value) for value in (first, second)]
            wait_for_blocker(system.db, gate.info.backend_pid)
        replies = [future.result(5) for future in pending]
    assert sorted(response.status_code for response in replies) == ([200, 201] if same_request else [201, 409])
    bodies = [response.json() for response in replies]
    assert sum(body.get("granted") is True for body in bodies) == 1
    if same_request:
        assert bodies[0]["id"] == bodies[1]["id"]
        assert sum(body["replayed"] is True for body in bodies) == 1
    else:
        assert next(body for body in bodies if "error" in body)["error"]["code"] == "action_already_consumed"
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 1
    assert len(system.provider.requests) == 1


@pytest.mark.parametrize("reconciled", ["succeeded", "not_executed"])
def test_lost_consume_response_never_regrants_and_outcomes_reconcile_once(system, reconciled):
    registration, value, result = asked(system)
    alias = check(system, {**value, "request_id": new_id()})
    decide(system, result["approval"]["id"])
    request = consume_body(result)
    first = consume(system, result, request)
    assert first["granted"] is True and first["outcome"] is None
    assert consume(system, alias, request, expected=409)["error"]["code"] == "payload_changed"
    # A changed policy cannot make a historical receipt a second grant or hide
    # an execution outcome that still needs reporting after a lost response.
    version = policy(system, "deny")
    approval_settings(system, approvals_enabled=False)
    with TestClient(create_app(replace(system.cfg, inline_guardrails=False), system.db)) as disabled:
        consume(system, result, request, expected=404, client=disabled)
        sensor_post(system, f"approvals/{result['approval']['id']}/status", expected=404, client=disabled)
        sensor_post(
            system, f"guardrail-releases/{first['id']}/outcome", {"outcome": "uncertain"},
            expected=404, client=disabled,
        )
    assert system.db.scalar("SELECT outcome FROM guardrail_releases WHERE id=$1", first["id"]) is None
    with TestClient(create_app(system.cfg, system.db)) as restarted:
        replay = consume(system, result, request, expected=200, client=restarted)
        assert replay["id"] == first["id"]
        assert replay["granted"] is False and replay["replayed"] is True
        assert replay["outcome"] is None
        changed = {**request, "action_commitment": "hmac-sha256-v1:" + "b" * 64}
        assert consume(system, result, changed, expected=409, client=restarted)["error"]["code"] == "payload_changed"
        path = f"guardrail-releases/{first['id']}/outcome"
        uncertain = sensor_post(system, path, {"outcome": "uncertain"}, client=restarted)
        assert uncertain["granted"] is False and uncertain["outcome"] == "uncertain"
        evidence = event(registration, "response", text="Execution reconciliation receipt")
        assert sensor_post(system, "events", {"events": [evidence]}, client=restarted)["accepted"] == 1
        report = {"outcome": reconciled, "exit_code": 0 if reconciled == "succeeded" else None, "evidence_ids": [evidence["id"]]}
        known = sensor_post(system, path, report, client=restarted)
        assert known["outcome"] == reconciled and known["granted"] is False
        for field in ("id", "registration_id", "check_id", "event_id", "logical_id", "approval_id", "action_commitment", "consumed_at"):
            assert known[field] == first[field]
        duplicate = sensor_post(system, path, report, client=restarted)
        assert duplicate["granted"] is False and duplicate["replayed"] is True
        for field in ("id", "outcome", "outcome_at", "outcome_details"):
            assert duplicate[field] == known[field]
        assert sensor_post(system, path, {"outcome": "failed", "exit_code": 1}, expected=409, client=restarted)["error"]["code"] == "outcome_conflict"
        historical = consume(system, result, request, expected=200, client=restarted)
        assert historical["granted"] is False and historical["replayed"] is True
        assert historical["outcome"] == reconciled and historical["outcome_at"] == known["outcome_at"]
        reviewed = owner_request(system, "GET", result["approval"]["id"], client=restarted)
        assert reviewed["release"]["id"] == first["id"] and reviewed["release"]["outcome"] == reconciled
    assert consume(system, result, expected=409)["error"]["code"] == "action_already_consumed"
    revised = {
        **value, "request_id": new_id(), "policy_version": version,
        "settings_version": system.settings["version"],
    }
    assert check(system, revised, expected=409)["error"]["code"] == "action_already_consumed"
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 1
    assert len(system.provider.requests) == 1


def test_outcome_references_are_scoped_and_cannot_accept_arbitrary_text(system):
    registration, _, result = asked(system)
    decide(system, result["approval"]["id"])
    release = consume(system, result)
    path = f"guardrail-releases/{release['id']}/outcome"
    other = managed(system)
    foreign_evidence = event(other, "response", text="Other session evidence")
    sensor_post(system, "events", {"events": [foreign_evidence]})
    sensor_post(system, path, {"outcome": "succeeded", "evidence_ids": [foreign_evidence["id"]]}, expected=403)
    sensor_post(system, path, {"outcome": "succeeded", "output": "unrestricted tool text"}, expected=400)
    for device in ("peer_sensor", "foreign_sensor"):
        sensor_post(system, path, {"outcome": "succeeded"}, device=device, expected=404)
    assert system.db.scalar("SELECT outcome FROM guardrail_releases WHERE id=$1", release["id"]) is None
    own = event(registration, "response", text="Own outcome evidence")
    sensor_post(system, "events", {"events": [own]})
    assert sensor_post(system, path, {"outcome": "failed", "exit_code": 2, "evidence_ids": [own["id"]]})["outcome"] == "failed"


@pytest.mark.parametrize("owner_state", ["disabled", "deleted"])
def test_revoked_owner_cannot_consume_or_reclaim_approval(system, owner_state):
    _, value, result = asked(system)
    approval_id = result["approval"]["id"]
    decide(system, approval_id)
    owner_id = system.users["owner"]["id"]
    if owner_state == "disabled":
        system.db.execute("UPDATE tenant_users SET status='disabled' WHERE id=$1", owner_id)
    else:
        system.db.delete_user(system.tenant["id"], owner_id)
    response = system.client.post(
        f"/ingest/v1/guardrail-checks/{result['id']}/consume",
        json=consume_body(result), headers=system.headers["sensor"],
    )
    assert response.status_code in (403, 404), response.text
    owner_request(system, "GET", approval_id, user="admin", expected=404)
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0
    assert system.db.scalar("SELECT verified_at IS NOT NULL FROM session_registrations WHERE id=$1", value["registration_id"])
    if owner_state == "deleted":
        assert system.db.scalar("SELECT owner_user_id FROM guardrail_approvals WHERE id=$1", approval_id) is None


@pytest.mark.parametrize("kind", ["command", "response"])
def test_retained_approval_projects_service_metadata_without_rewriting_evidence(system, kind):
    approval_settings(system)
    registration = managed(system)
    evidence = "captured model name and cost_usd are original user content"
    target = event(registration, kind, **({"command": {"text": "echo " + evidence}} if kind == "command" else {"text": evidence}))
    _, _, result = asked(system, target=target, registration=registration)
    approval_id = result["approval"]["id"]
    links = {"status": "matched", "checked": 1, "skipped": 0, "failed": 0,
             "matches": [{"url": "https://evidence.example/model-name", "threat_types": ["MALWARE"],
                          "source_ids": ["advisory-source:original"], "expires_at": "2026-11-01T00:00:00Z"}],
             "reasons": ["Captured provider names are evidence, not routing metadata"]}
    private = {"model": "private-service-model", "provider": "private-provider", "rubric_version": 99,
               "usage": {"input_tokens": 123}, "cost_usd": 7, "reason": evidence,
               "links": {**links, "provider": "private-link-routing", "model": "private-service-model", "cost_usd": 1}}
    system.db.execute("UPDATE inline_guardrail_events SET assessment=assessment||$2,model=$3,rubric_version=99 WHERE event_id=$1",
                      result["event_id"], Jsonb(private), private["model"])
    retained = system.db.one("SELECT target_body,captured_context,assessment,model,rubric_version FROM inline_guardrail_events WHERE event_id=$1", result["event_id"])
    for detail in (owner_request(system, "GET", approval_id), decide(system, approval_id)):
        assessment = detail["assessment"]
        assert not {"model", "provider", "rubric_version", "usage", "cost_usd"} & assessment.keys()
        assert assessment["score"] == 50 and "private-service-model" not in json.dumps(detail)
        if kind == "command":
            assert detail["preview"]["target"]["command"]["text"] == "echo " + evidence
            assert assessment["reason"] == evidence
            assert assessment["links"] == links
            assert "private-link-routing" not in json.dumps(detail)
        else:
            assert detail["preview"] is None and evidence not in json.dumps(detail)
    assert system.db.one("SELECT target_body,captured_context,assessment,model,rubric_version FROM inline_guardrail_events WHERE event_id=$1", result["event_id"]) == retained
