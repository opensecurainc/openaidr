"""Operator archives through real HTTP/PostgreSQL with external JEV mocked."""

from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import replace
from decimal import Decimal
import hashlib
import json
from threading import Event, Lock
from types import SimpleNamespace

from fastapi.testclient import TestClient

from openaidr.core.event import new_id
from openaidr.server import auth
from openaidr.server import session_aggregation as aggregation
from openaidr.server import session_investigator as investigator
from openaidr.server.app import create_app
from test_approvals import (
    approval_settings,
    consume,
    decide,
    owner_request,
    sensor_post,
)
from test_inline_guardrail import browser, check, event, system as system
from test_session_aggregation import (
    action,
    close_session,
    deliver,
    detection_settings,
    finalized,
    receipt,
    registered,
)
from test_session_investigator import (
    attempt,
    canonical,
    finding_result,
    finish_steps,
    measured,
    no_finding,
    prepared,
    proposal,
)
from test_session_ownership import wait_for_blocker
from test_store import db as db


PAGE_BYTES = 1 << 20


def operator(system):
    """A Security Analyst who is not the registered owner or an IT Admin."""
    user = system.db.create_user(
        system.tenant["id"],
        "archive-viewer@example.test",
        "Archive viewer",
        "hash",
        ["security_analyst"],
    )
    system.users["operator"] = user
    system.headers["operator"] = {
        auth.CSRF_HEADER: "1",
        "Cookie": auth.CONSOLE_COOKIE
        + "="
        + system.db.create_session(user["id"], user["tenant_id"]),
    }
    return user


def archive(system, path, *, params=None, user="operator", expected=200, client=None):
    selected_client = client or (system.foreign_client if user == "foreign" else system.client)
    response = selected_client.get(
        "/api/v1/" + path,
        params=params or {},
        headers=system.headers.get(user, {}),
    )
    assert response.status_code == expected, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def session_id(system, registration):
    return system.db.scalar(
        "SELECT id FROM agent_sessions WHERE registration_id=$1", registration["id"]
    )


def all_pages(system, path, **params):
    items, cursor, cursors = [], "", set()
    while True:
        page = archive(system, path, params={**params, "cursor": cursor})
        items.extend(page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            return items
        assert cursor not in cursors, "archive page did not advance"
        cursors.add(cursor)
        assert len(cursors) < 100, "fixture exceeded its bounded page count"


def test_report_queue_includes_every_outcome_without_duplicating_findings(system):
    operator(system)
    positive = report_with_history(system).value
    negative = attempt(system)
    prepared(system, negative)
    finish_steps(system, negative)
    investigator.publish_report(system.db, negative.claim)
    benign = attempt(system)
    prepared(system, benign)
    anchor = system.db.one(
        "SELECT ordinal,kind,source_id,body FROM session_snapshot_items WHERE snapshot_id=$1 AND kind='observation' AND source_id=$2",
        benign.claim["snapshot_id"], benign.value["target"]["id"],
    )
    benign_result = {**no_finding(), "verdict": "true_positive_non_malicious",
                     "evidence": [{"source": "target", "ordinal": anchor["ordinal"], "start": 0, "end": len(canonical(anchor))}]}
    benign_result["authorization"]["evidence_indices"] = [0]
    finish_steps(system, benign, lambda _: benign_result)
    investigator.publish_report(system.db, benign.claim)
    incomplete = attempt(system)
    investigator.stop_attempt(system.db, incomplete.claim, "runtime_unavailable", retryable=False)
    pending = attempt(system)

    items = all_pages(system, "session-investigations", limit=1)
    assert len(items) == 5
    by_id = {item["id"]: item for item in items}
    assert by_id[positive.claim["job_id"]]["outcome"] == "actionable_findings"
    assert by_id[negative.claim["job_id"]]["outcome"] == "no_actionable_findings"
    assert by_id[incomplete.claim["job_id"]]["outcome"] == "inconclusive"
    assert by_id[pending.claim["job_id"]]["outcome"] is None
    for value, verdict in ((positive, "true_positive"), (negative, "false_positive"),
                           (benign, "true_positive_non_malicious"), (incomplete, None), (pending, None)):
        assert by_id[value.claim["job_id"]]["verdict"] == verdict
        if verdict:
            selected = archive(system, "session-investigations", params={"outcome": verdict})
            assert [item["id"] for item in selected["items"]] == [value.claim["job_id"]]
            report = archive(system, f"session-investigations/{value.claim['job_id']}")["report"]
            assert report["verdict"] == verdict
    assert by_id[positive.claim["job_id"]]["report_attempt_id"] == positive.claim["attempt_id"]
    assert by_id[positive.claim["job_id"]]["subject"]["ownership_verified"]
    assert by_id[positive.claim["job_id"]]["snapshot_current"]
    assert by_id[positive.claim["job_id"]]["configuration_current"]
    counts = archive(system, "detections/pipeline")
    assert (counts["reports"], counts["actionable_reports"], counts["no_finding_reports"], counts["inconclusive_reports"]) == (4, 1, 2, 1)
    assert counts["pending_investigations"] == 1
    path = "/detections/reports/" + positive.claim["job_id"]
    system.headers["operator"].update({"X-OpenAIDR-CSRF": "1", "Origin": system.cfg.public_url})
    assert browser(system, "POST", "audit/page-views", {"path": path}, user="operator").status_code == 204
    assert browser(system, "POST", "audit/page-views", {"path": path}, user="foreign").status_code == 404
    for invalid in ("/detections/reports/:id", "/detections/reports/not-a-uuid", path + "?secret=hidden"):
        assert browser(system, "POST", "audit/page-views", {"path": invalid}, user="operator").status_code == 400
    page_audit = system.db.one("SELECT details FROM audit_log WHERE tenant_id=$1 AND action='dashboard.page.view' ORDER BY at DESC LIMIT 1", system.tenant["id"])
    assert page_audit["details"]["resource_id"] == positive.claim["job_id"]
    for outcome, value in (("actionable_findings", positive),
                           ("inconclusive", incomplete), ("pending", pending)):
        selected = archive(system, "session-investigations", params={"outcome": outcome})
        assert [item["id"] for item in selected["items"]] == [value.claim["job_id"]]
    negatives = archive(system, "session-investigations", params={"outcome": "no_actionable_findings"})
    assert {item["id"] for item in negatives["items"]} == {negative.claim["job_id"], benign.claim["job_id"]}
    assert archive(system, "session-investigations", user="foreign")["items"] == []
    archive(system, "session-investigations", user="anonymous", expected=401)
    archive(system, "session-investigations", params={"outcome": "safe"}, expected=400)
    first = archive(system, "session-investigations", params={"limit": 1})
    archive(system, "session-investigations", params={"cursor": first["next_cursor"], "outcome": "pending"}, expected=400)
    archive(system, "session-investigations", params={"cursor": first["next_cursor"]}, user="foreign", expected=400)


def test_report_queue_filters_by_session_and_marks_new_evidence_stale(system):
    operator(system)
    saved = report_with_history(system)
    path = "session-investigations"
    params = {"session_id": saved.session_id}
    before = archive(system, path, params=params)["items"]
    assert len(before) == 1 and before[0]["snapshot_current"]
    observed = event(saved.value.registration, "response", text="Evidence after report completion",
                     host={"user": "later-user", "hostname": "later-device"})
    sensor_post(system, "events", {"events": [observed]})
    after = archive(system, path, params=params)["items"]
    assert not after[0]["snapshot_current"]
    assert after[0]["summary"] == before[0]["summary"]
    assert after[0]["subject"] == before[0]["subject"]
    assert after[0]["subject"]["hostname"] != "later-device"
    assert archive(system, path, params={"session_id": new_id()})["items"] == []
    archive(system, path, params={"session_id": "invalid"}, expected=400)


def test_unstarted_terminal_investigation_has_an_explicit_inconclusive_report(system):
    from test_ordinary_session_detection import captured, configure, finalize

    operator(system)
    configure(system)
    value = captured(system)
    state = finalize(system, value)
    job_id = state["routing"]["job_id"]
    system.db.execute(
        "UPDATE session_investigation_jobs SET state='superseded',completed_at=clock_timestamp() WHERE id=$1", job_id,
    )
    data = archive(system, "session-investigations/" + job_id)
    assert data["report_generated_from_state"]
    assert data["report_attempt_id"] is None
    assert data["report"]["outcome"] == "inconclusive"
    assert data["report"]["scope"]["reviewed_sessions"] == []
    assert data["report"]["scope"]["target_sessions"][0]["session_id"] == value.id
    assert data["report"]["recommendations"] and data["report"]["limitations"]
    assert system.db.scalar("SELECT count(*) FROM model_usage") == 0


def test_ordinary_investigation_identity_requires_audited_analyst_assignment(system):
    from test_ordinary_session_detection import captured

    operator(system)
    value = captured(system)
    path = f"sessions/{value.id}/detection-owner"
    owner_id = system.users["owner"]["id"]
    assert archive(system, path)["owner"] is None
    for user in ("owner", "foreign"):
        response = browser(system, "PUT", path, {"owner_user_id": owner_id}, user=user)
        assert response.status_code in (403, 404), response.text
    rejected = browser(system, "PUT", path, {"owner_user_id": system.users["foreign"]["id"]})
    assert rejected.status_code == 404
    saved = browser(system, "PUT", path, {"owner_user_id": owner_id}, user="operator")
    assert saved.status_code == 200, saved.text
    assert saved.headers["cache-control"] == "no-store"
    assert saved.json()["owner"]["owner_user_id"] == owner_id
    assert saved.json()["owner"]["verified_at"]
    audit = system.db.one(
        "SELECT * FROM audit_log WHERE tenant_id=$1 AND target_id=$2 AND action='session-detection.owner-verify'",
        system.tenant["id"], value.id,
    )
    assert audit["actor_id"] == system.users["operator"]["id"]
    assert audit["details"]["owner_user_id"] == owner_id
    revoked = browser(system, "PUT", path, {"owner_user_id": None})
    assert revoked.status_code == 200 and revoked.json()["owner"] is None
    assert browser(system, "PUT", path, {"owner_user_id": owner_id}).status_code == 409
    assert browser(system, "PUT", path, {"owner_user_id": "not-a-user"}).status_code == 400
    assert browser(system, "GET", "sessions/invalid/detection-owner").status_code == 400
    assert system.db.scalar("SELECT count(*) FROM model_usage") == 0


def report_with_history(system):
    """Retained target and same-owner search/read receipts with real publication."""
    history = registered(system, device="peer_sensor")
    observed = event(
        history, "response", text="retained history <img src=x onerror=alert(1)>"
    )
    assert (
        sensor_post(system, "events", {"events": [observed]}, device="peer_sensor")[
            "accepted"
        ]
        == 1
    )
    history_id = session_id(system, history)
    value = attempt(system)
    step = prepared(system, value)
    search = investigator.read_tool(
        system.db, value.claim, step["id"], "search", "search_sessions", {}
    )
    assert history_id in json.dumps(search)
    read = investigator.read_tool(
        system.db,
        value.claim,
        step["id"],
        "history",
        "read_session",
        {"session_id": history_id, "snapshot_id": None, "cursor": ""},
    )
    assert read["items"]
    anchor = system.db.one(
        """SELECT ordinal,kind,source_id,body FROM session_snapshot_items
           WHERE snapshot_id=$1 AND kind='observation' AND source_id=$2""",
        value.claim["snapshot_id"],
        value.value["target"]["id"],
    )
    result = finding_result(value, anchor)
    result["findings"][0]["evidence"].append(
        {"source": "history", "read_id": read["read_id"], "item": 0}
    )
    finish_steps(system, value, lambda _: result)
    investigator.publish_report(system.db, value.claim)
    return SimpleNamespace(
        value=value,
        step=step,
        history=history,
        history_id=history_id,
        observed=observed,
        search=search,
        read=read,
        session_id=session_id(system, value.registration),
    )


def test_operator_archive_keeps_retained_scope_separate_from_current_owner_authority(
    system,
):
    viewer = operator(system)
    saved = report_with_history(system)
    value = saved.value
    paths = [
        f"sessions/{saved.session_id}/detection",
        f"sessions/{saved.session_id}/guardrail-actions",
        f"session-snapshots/{value.claim['snapshot_id']}",
        f"session-investigations/{value.claim['job_id']}",
        f"session-investigation-reads/{saved.search['read_id']}",
        f"session-investigation-reads/{saved.read['read_id']}",
    ]
    originals = {path: archive(system, path) for path in paths}
    for path in paths:
        archive(system, path, user="foreign", expected=404)
        archive(system, path, user="unauthenticated", expected=401)
    for suffix in (
        f"session-snapshots/{value.claim['snapshot_id']}",
        f"session-investigations/{value.claim['job_id']}",
        f"session-investigation-reads/{saved.read['read_id']}",
    ):
        archive(system, "me/" + suffix, expected=404)
    summary = originals[paths[0]]
    assert summary["registration"]["owner"]["id"] == system.users["owner"]["id"]
    assert summary["registration"]["owner_available"] is True
    assert (
        summary["session"]["device"]["reported_user"] != system.users["owner"]["email"]
    )
    assert "claim_token" not in json.dumps(originals)
    assert "confirmation_token" not in json.dumps(originals)

    retained = {}
    for captured in (saved.search, saved.read):
        path = f"session-investigation-reads/{captured['read_id']}"
        body = originals[path]
        persisted = system.db.one(
            "SELECT response,response_sha256 FROM session_investigation_reads WHERE id=$1",
            captured["read_id"],
        )
        assert body["response"] == persisted["response"]
        assert (
            hashlib.sha256(canonical(body["response"])).hexdigest()
            == body["response_sha256"]
        )
        retained[path] = body
    assert retained[paths[-2]]["session_id"] is None

    # Source availability continues to constrain live owner tools, while the
    # tenant operator inspects the immutable response actually delivered.
    system.db.execute("DELETE FROM events WHERE session_id=$1", saved.history_id)
    system.db.execute(
        "UPDATE sensors SET disabled=true WHERE id=$1",
        system.sensors["peer_sensor"][0]["id"],
    )
    archive(
        system,
        f"me/session-investigation-reads/{saved.search['read_id']}",
        user="owner",
        expected=404,
    )
    archive(
        system,
        f"me/session-investigations/{value.claim['job_id']}",
        user="owner",
        expected=404,
    )
    for path, original in retained.items():
        assert archive(system, path) == original
    assert archive(system, paths[3])["report"] == originals[paths[3]]["report"]

    system.db.execute(
        "UPDATE tenant_users SET status='disabled' WHERE id=$1",
        system.users["owner"]["id"],
    )
    system.db.execute(
        "UPDATE sensors SET disabled=true WHERE id=$1",
        system.sensors["sensor"][0]["id"],
    )
    summary = archive(system, paths[0])
    assert summary["registration"]["owner_available"] is False
    assert summary["session"]["device"]["sensor_disabled"] is True
    system.db.execute(
        "DELETE FROM tenant_users WHERE id=$1", system.users["owner"]["id"]
    )
    summary = archive(system, paths[0])
    assert summary["registration"]["owner"] is None
    assert (
        summary["registration"]["verified_at"]
        == originals[paths[0]]["registration"]["verified_at"]
    )
    for path, original in retained.items():
        assert archive(system, path) == original

    system.db.execute(
        "UPDATE tenant_users SET status='disabled' WHERE id=$1", viewer["id"]
    )
    denied = system.client.get(
        "/api/v1/" + paths[0], headers=system.headers["operator"]
    )
    assert denied.status_code in (401, 403)
    assert denied.headers["cache-control"] == "no-store"
    assert saved.session_id not in denied.text
    system.db.execute(
        "UPDATE tenant_users SET status='active' WHERE id=$1", viewer["id"]
    )
    deleted = browser(system, "DELETE", f"sensors/{system.sensors['sensor'][0]['id']}")
    assert deleted.status_code == 204, deleted.text
    assert archive(system, paths[0])["session"]["device"]["sensor_deleted_at"]
    for path, original in retained.items():
        assert archive(system, path) == original
    # Removing a sealed snapshot cascades its job, attempts and retained reads.
    # Operator access cannot recover rows removed by retention.
    system.db.execute(
        "DELETE FROM session_snapshots WHERE id=$1", value.claim["snapshot_id"]
    )
    for path in paths[2:]:
        archive(system, path, expected=404)
    archive(system, paths[0])
    archive(system, paths[1])


def test_action_pages_keep_aliases_generations_outcomes_and_missing_assessments_distinct(
    system,
):
    operator(system)
    approval_settings(system)
    detection_settings(system)
    registration = registered(system)
    value, first, records, _ = action(system, registration, 50, finish=False)
    assert check(system, value)["id"] == first["id"]
    alias = check(system, {**value, "request_id": new_id()})
    assert alias["approval"]["id"] == first["approval"]["id"]
    system.db.execute(
        "UPDATE guardrail_approvals SET expires_at=clock_timestamp() WHERE id=$1",
        first["approval"]["id"],
    )
    owner_request(system, "GET", first["approval"]["id"])
    renewed = check(system, {**value, "request_id": new_id()})
    assert renewed["approval"]["id"] != first["approval"]["id"]
    decide(system, renewed["approval"]["id"])
    release = consume(system, renewed)
    outcome = sensor_post(
        system, f"guardrail-releases/{release['id']}/outcome", {"outcome": "uncertain"}
    )
    records.append(
        receipt(
            "outcome",
            2,
            event_id=first["event_id"],
            logical_id=first["logical_id"],
            release_id=release["id"],
            outcome_audit_id=outcome["outcome_audit_id"],
        )
    )
    _, zero, extra, _ = action(system, registration, 0, sequence=3)
    records.extend(extra)
    system.provider.status = 503
    _, unavailable, extra, _ = action(system, registration, 0, sequence=5)
    records.extend(extra)
    system.provider.status = 200
    missing = event(registration)
    assert sensor_post(system, "events", {"events": [missing]})["accepted"] == 1
    records.append(
        receipt(
            "target",
            7,
            event_id=missing["id"],
            logical_id=missing["evidence"]["logical_id"],
            action_commitment="hmac-sha256-v1:" + "b" * 64,
            gaps=["backend_unavailable"],
        )
    )
    deliver(system, registration, records)
    close_session(system, registration, len(records))
    projection = finalized(system, registration)
    assert Decimal(projection["risk_total"]) == 50
    assert projection["counts"]["logical_targets"] == 4
    path = f"sessions/{session_id(system, registration)}/guardrail-actions"
    calls_before = len(system.provider.requests)
    usage_before = system.db.scalar("SELECT count(*) FROM model_usage")
    pages = all_pages(system, path, limit=1)
    assert len(pages) == 4 and len({row["logical_id"] for row in pages}) == 4
    actions = {row["logical_id"]: row for row in pages}
    asked = actions[first["logical_id"]]
    assert asked["decision_count"] == 3 and asked["approval_count"] == 2
    assert asked["latest_decision"]["decision"]["action"] == "ask"
    assert asked["latest_approval"]["status"] == "approved"
    assert (
        asked["release"]["id"] == release["id"]
        and asked["release"]["outcome"] == "uncertain"
    )
    assert asked["reported_outcome"]["payload"]["release_id"] == release["id"]
    assert actions[zero["logical_id"]]["assessment"]["value"]["score"] == 0
    assert actions[unavailable["logical_id"]]["assessment"]["status"] == "unavailable"
    missing_row = actions[missing["evidence"]["logical_id"]]
    assert missing_row["assessment"]["status"] == "missing"
    assert (
        missing_row["assessment"]["value"] is None and missing_row["action_id"] is None
    )
    assert missing_row["target_body"]["id"] == missing["id"]
    assert missing_row["release"] is None
    decisions = all_pages(
        system, path, limit=1, view="decisions", action_id=asked["action_id"]
    )
    approvals = all_pages(
        system, path, limit=1, view="approvals", action_id=asked["action_id"]
    )
    assert {row["id"] for row in decisions} == {first["id"], alias["id"], renewed["id"]}
    assert {row["generation"] for row in approvals} == {1, 2}
    assert len(system.provider.requests) == calls_before
    assert system.db.scalar("SELECT count(*) FROM model_usage") == usage_before

    cursor = archive(
        system,
        path,
        params={"limit": 1, "view": "decisions", "action_id": asked["action_id"]},
    )["next_cursor"]
    for params in (
        {"cursor": cursor},
        {"view": "approvals", "action_id": asked["action_id"], "cursor": cursor},
        {
            "view": "decisions",
            "action_id": actions[zero["logical_id"]]["action_id"],
            "cursor": cursor,
        },
    ):
        archive(system, path, params=params, expected=400)
    other = registered(system)
    action(system, other)
    other_path = f"sessions/{session_id(system, other)}/guardrail-actions"
    archive(
        system,
        other_path,
        params={"view": "decisions", "action_id": asked["action_id"]},
        expected=404,
    )
    action_cursor = archive(system, path, params={"limit": 1})["next_cursor"]
    archive(system, other_path, params={"cursor": action_cursor}, expected=400)
    archive(system, path, params={"cursor": cursor}, user="foreign", expected=404)


def test_snapshot_archive_preserves_full_bytes_and_cursors_after_retention_and_new_revision(
    system, monkeypatch
):
    operator(system)
    detection_settings(system)
    registration = registered(system)
    _, _, records, _ = action(system, registration, 0)
    observations = [
        event(
            registration,
            "response",
            text=f"observation-{index}:" + "漢" * size + f":tail-{index}",
        )
        for index, size in enumerate((140000, 140000, 140000, 450000))
    ]
    # Historical events may predate current envelope limits. Real storage is
    # used to verify complete transfer of one oversized retained item.
    system.db.ingest_batch(system.sensors["sensor"][0], observations)
    records.extend(
        receipt("observation", index + 3, event_id=item["id"])
        for index, item in enumerate(observations)
    )
    deliver(system, registration, records)
    close_session(system, registration, len(records))
    old = finalized(system, registration)
    transfers = []
    store_type = type(system.db)
    original_many = store_type.many

    def observe_fetch(store, *args, **kwargs):
        rows = original_many(store, *args, **kwargs)
        if rows and all("body" in row for row in rows):
            transfers.append((len(rows), len(canonical(rows))))
        return rows

    monkeypatch.setattr(store_type, "many", observe_fetch)
    path = f"session-snapshots/{old['snapshot_id']}"
    first = archive(system, path, params={"limit": 1})
    assert first["next_cursor"]
    assert (
        archive(system, path)["snapshot"]["item_count"]
        == first["snapshot"]["item_count"]
    )

    def read_all():
        items, cursor, oversized = [], "", 0
        while True:
            page = archive(system, path, params={"limit": 500, "cursor": cursor})
            size = len(canonical(page["items"]))
            assert size <= PAGE_BYTES or len(page["items"]) == 1
            oversized += size > PAGE_BYTES
            items.extend(page["items"])
            assert len(items) <= page["snapshot"]["item_count"]
            cursor = page["next_cursor"]
            if not cursor:
                assert len(items) == page["snapshot"]["item_count"]
                break
        assert oversized > 0
        assert len({item["ordinal"] for item in items}) == len(items)
        captured = {
            item["source_id"]: item["body"]
            for item in items
            if item["kind"] == "observation"
        }
        for item in observations:
            assert captured[item["id"]]["text"] == item["text"]
        return items

    original = read_all()
    system.db.execute(
        "DELETE FROM events WHERE session_id=$1", session_id(system, registration)
    )
    late = event(registration, "response", text="late revision only")
    assert sensor_post(system, "events", {"events": [late]})["accepted"] == 1
    deliver(
        system,
        registration,
        [receipt("observation", len(records) + 1, event_id=late["id"])],
    )
    close_session(system, registration, len(records) + 1)
    newest = finalized(system, registration)
    assert newest["revision"] > old["revision"]
    assert archive(system, path, params={"limit": 1}) == first
    assert read_all() == original
    archive(
        system,
        f"session-snapshots/{newest['snapshot_id']}",
        params={"cursor": first["next_cursor"]},
        expected=400,
    )
    archive(
        system,
        path,
        params={"cursor": first["next_cursor"]},
        user="foreign",
        expected=404,
    )
    assert transfers and any(size > PAGE_BYTES for _, size in transfers)
    assert all(size <= PAGE_BYTES or count == 1 for count, size in transfers)


def test_report_archive_marks_stale_content_and_configuration_without_inventing_usage(
    system,
):
    operator(system)
    saved = report_with_history(system)
    value = saved.value
    path = f"session-investigations/{value.claim['job_id']}"
    summary_path = f"sessions/{saved.session_id}/detection"
    report = archive(system, path, params={"attempt_id": value.claim["attempt_id"]})
    assert report["report_attempt_id"] == value.claim["attempt_id"]
    assert report["report"]["status"] == "finding"
    assert (
        report["snapshot_current"] is True and report["configuration_current"] is True
    )
    assert "usage" not in report and "usage_count" not in report
    assert not {"model", "runtime", "usage"}.intersection(report["report"])
    assert not {"model", "max_tokens_per_attempt", "max_cost_usd_per_attempt"}.intersection(report["configuration"])
    assert not {"runtime", "reserved_tokens", "actual_tokens", "reserved_cost_usd", "actual_cost_usd"}.intersection(report["attempts"][0])
    assert system.db.scalar("SELECT sum(cost_usd)>0 FROM model_usage WHERE investigation_job_id=$1", value.claim["job_id"])
    archive(system, path, params={"attempt_id": new_id()}, expected=404)

    current = aggregation.get_settings(system.db, system.tenant["id"])
    changed = {name: current[name] for name in aggregation.SETTINGS}
    changed["max_tokens_per_attempt"] += 1
    response = browser(system, "PUT", "response/session-detection", changed)
    assert response.status_code == 200, response.text
    summary = archive(system, summary_path)
    assert summary["projection"]["settings_changed"] is True
    assert summary["projection"]["snapshot_current"] is True
    revised = archive(system, path)
    assert (
        revised["configuration_current"] is False
        and revised["snapshot_current"] is True
    )
    assert revised["report"] == report["report"] and "usage" not in revised
    resumed = event(
        value.registration, "response", text="new live content after retained report"
    )
    assert sensor_post(system, "events", {"events": [resumed]})["accepted"] == 1
    dirty = archive(system, summary_path)
    assert (
        dirty["projection"]["dirty"] is True
        and dirty["projection"]["snapshot_current"] is False
    )
    assert archive(system, path)["snapshot_current"] is False
    assert archive(system, path)["report"] == report["report"]
    system.db.execute(
        "UPDATE session_finalizations SET failure_code='finalization_timeout' WHERE registration_id=$1",
        value.registration["id"],
    )
    assert (
        archive(system, summary_path)["projection"]["finalization_error"]
        == "finalization_timeout"
    )

    unknown = attempt(system)
    step = prepared(system, unknown)
    request = proposal(step)
    investigator.admit_call(system.db, unknown.claim, step["id"], request)
    assert (
        investigator.finish_call(
            system.db,
            unknown.claim,
            step["id"],
            measured(request["request_id"], cache_write_input_tokens=None),
        )
        is False
    )
    investigator.stop_attempt(system.db, unknown.claim, "usage_unknown")
    unpriced = archive(system, f"session-investigations/{unknown.claim['job_id']}")
    assert "usage" not in unpriced
    assert "actual_cost_usd" not in unpriced["attempts"][0]
    retained = system.db.one("SELECT * FROM session_investigation_attempts WHERE id=$1", unknown.claim["attempt_id"])
    assert retained["actual_cost_usd"] is None and retained["reserved_cost_usd"] > 0
    archive(
        system, path, params={"attempt_id": unknown.claim["attempt_id"]}, expected=404
    )

    costs = browser(system, "GET", "costs/detections", user="admin")
    assert costs.status_code == 410, costs.text
    usage_before = system.db.many(
        "SELECT id,input_tokens,output_tokens,cost_usd FROM model_usage ORDER BY id"
    )
    disabled = browser(system, "PUT", "response/session-detection", {"enabled": False})
    assert disabled.status_code == 200, disabled.text
    assert browser(system, "GET", "costs/detections", user="admin").status_code == 410
    assert (
        system.db.many(
            "SELECT id,input_tokens,output_tokens,cost_usd FROM model_usage ORDER BY id"
        )
        == usage_before
    )


def test_archive_unknown_projection_validation_and_resource_bound_cursors(system):
    operator(system)
    registration = registered(system)
    observed = event(
        registration, "prompt", text="No assessment or finalization exists"
    )
    sensor_post(system, "events", {"events": [observed]})
    sid = session_id(system, registration)
    path = f"sessions/{sid}/detection"
    result = archive(system, path)
    assert result["projection"]["available"] is False
    assert (
        result["projection"]["snapshot_current"] is False
        and result["detection"] is None
    )
    assert result["investigations"] == {"items": [], "next_cursor": ""}
    actions = archive(system, f"sessions/{sid}/guardrail-actions")
    assert actions["items"] == []
    legacy = event(
        {"external_id": "legacy-" + new_id(), "id": new_id(), "product": "codex-cli"},
        "prompt",
        text="Legacy captured prompt",
    )
    legacy["session"].pop("registration_id")
    sensor_post(system, "events", {"events": [legacy]})
    legacy_id = system.db.scalar(
        "SELECT session_id FROM events WHERE id=$1", legacy["id"]
    )
    legacy_summary = archive(system, f"sessions/{legacy_id}/detection")
    assert (
        legacy_summary["registration"] is None and legacy_summary["detection"] is None
    )
    assert legacy_summary["projection"]["available"] is False
    for suffix in ("detection", "guardrail-actions"):
        for params in (
            {"limit": 0},
            {"limit": 501},
            {"limit": "bad"},
            {"cursor": "not-a-cursor"},
        ):
            archive(system, f"sessions/{sid}/{suffix}", params=params, expected=400)
        archive(system, f"sessions/{new_id()}/{suffix}", expected=404)
        archive(system, f"sessions/not-a-uuid/{suffix}", expected=400)
    for params in (
        {"view": "invalid"},
        {"view": "decisions"},
        {"view": "approvals", "action_id": "not-a-uuid"},
    ):
        archive(
            system, f"sessions/{sid}/guardrail-actions", params=params, expected=400
        )
    for route in (
        "session-snapshots",
        "session-investigations",
        "session-investigation-reads",
    ):
        archive(system, route + "/not-a-uuid", expected=400)
        archive(system, route + "/" + new_id(), expected=404)
    # An operator read does not register evidence or trigger finalization.
    assert system.db.scalar("SELECT count(*) FROM session_finalizations") == 0
    assert system.db.scalar("SELECT count(*) FROM model_usage") == 0
    assert system.provider.requests == []


def test_api_only_archive_pressure_uses_private_workers_and_bounded_admission(system):
    operator(system)
    detection_settings(system)
    registration = registered(system)
    _, _, records, _ = action(system, registration)
    deliver(system, registration, records)
    close_session(system, registration, len(records))
    snapshot = finalized(system, registration)
    cfg = replace(
        system.cfg, inline_guardrails=False, intelligence_origin="", intelligence_api_key=""
    )
    cfg.set_services("api")
    start, overloaded, counter_lock = Event(), Event(), Lock()
    overload_count, request_count = 0, 52
    calls_before = len(system.provider.requests)
    with TestClient(create_app(cfg, system.db)) as api_only:
        assert api_only.app.state.service.inline_guardrail is None

        def read():
            nonlocal overload_count
            assert start.wait(5)
            response = api_only.get(
                f"/api/v1/session-snapshots/{snapshot['snapshot_id']}",
                headers=system.headers["operator"],
            )
            if (
                response.status_code == 503
                and response.json()["error"]["code"] == "unavailable"
            ):
                with counter_lock:
                    overload_count += 1
                    if overload_count >= request_count - cfg.ingest_concurrency:
                        overloaded.set()
            return response

        pending, auth_future = [], None
        with ThreadPoolExecutor(max_workers=request_count + 1) as pool:
            try:
                with system.db.transaction() as gate:
                    system.db.execute(
                        "LOCK TABLE session_snapshots IN ACCESS EXCLUSIVE MODE",
                        conn=gate,
                    )
                    pending = [pool.submit(read) for _ in range(request_count)]
                    start.set()
                    wait_for_blocker(system.db, gate.info.backend_pid)
                    assert overloaded.wait(3), (
                        "operator admission did not reject excess reads"
                    )
                    auth_future = pool.submit(
                        api_only.get,
                        "/api/v1/auth/me",
                        headers=system.headers["operator"],
                    )
                    response = auth_future.result(timeout=1)
                    assert response.status_code == 200, response.text
            finally:
                # Release the relation lock before joining blocked requests.
                start.set()
                workers = pending + ([auth_future] if auth_future else [])
                _, unfinished = wait(workers, timeout=15)
                assert not unfinished, (
                    "archive workers did not finish after relation unlock"
                )
        responses = [future.result() for future in pending]
    assert all(response.status_code in (200, 503) for response in responses)
    assert all(
        response.headers["cache-control"] == "no-store" for response in responses
    )
    assert overload_count >= request_count - cfg.ingest_concurrency
    assert len(system.provider.requests) == calls_before
