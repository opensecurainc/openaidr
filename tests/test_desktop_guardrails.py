"""Device-scoped guardrail summaries through HTTP and real PostgreSQL."""

from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from openaidr.server.store import new_id
from test_telemetry_dashboard import dashboard  # noqa: F401


ENDPOINT = "/ingest/v1/guardrails/summary"


def record(st, sensor, *, mode="shadow", decision="deny", status="evaluated",
           age=timedelta(hours=1), expired=True, product="claude-code"):
    stamp = st.scalar("SELECT now()") - age
    ident = new_id()
    st.execute(
        """INSERT INTO ordinary_hook_checks
           (id,tenant_id,sensor_id,request_id,payload_sha256,product,hook_event,session_id,
            mode,settings_version,policy_version,status,evaluated_decision,returned_decision,
            created_at,deadline_at,actions,reason)
           VALUES($1,$2,$3,$4,'test',$5,'PreToolUse','private-session',$6,1,1,$7,$8,$9,$10,$11,$12,$13)""",
        ident, sensor["tenant_id"], sensor["id"], new_id(), product, mode, status,
        decision if status == "evaluated" else None,
        ("allow" if mode == "shadow" else decision) if status == "evaluated" else None,
        stamp, stamp if expired else stamp + timedelta(days=2),
        Jsonb([{"kind": "command", "command": {"text": "PRIVATE-ACTION"}}]), "PRIVATE-REASON",
    )
    return ident


def test_guardrail_summary_binds_device_and_tenant_without_evidence(dashboard):
    st, _, client, sensor, token, foreign = dashboard
    headers = {"Authorization": "Bearer " + token}
    assert client.post(ENDPOINT, json={}).status_code == 401
    for body in ({"days": True}, {"days": 7}, {"days": "1"}, {"days": 31},
                 {"sensor_id": foreign["id"]}, {"tenant_id": foreign["tenant_id"]}):
        assert client.post(ENDPOINT, json=body, headers=headers).status_code == 400
    enrollment = st.create_enrollment_token(sensor["tenant_id"])
    peer, _, _ = st.enroll_sensor({"enrollment_token": enrollment["token"], "hostname": "peer"})
    own = record(st, sensor)
    record(st, peer, decision="ask")
    record(st, foreign, decision="warn")
    response = client.post(ENDPOINT, json={}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    data = response.json()
    assert data["days"] == 1 and data["mode"] == "shadow"
    assert data["summary"] == dict(completed=1, allow=0, warn=0, ask=0, deny=1, unavailable=0, pending=0)
    assert [row["id"] for row in data["recent"]] == [own]
    assert data["recent"][0]["returned_decision"] == "allow"
    assert set(data["recent"][0]) == {
        "id", "created_at", "product", "hook_event", "mode", "status",
        "evaluated_decision", "returned_decision",
    }
    assert all(value not in response.text for value in ("PRIVATE-ACTION", "PRIVATE-REASON", "private-session"))
    st.update_sensor(sensor["tenant_id"], sensor["id"], disabled=True)
    assert client.post(ENDPOINT, json={}, headers=headers).status_code == 403


def test_guardrail_summary_preserves_modes_failures_and_rolling_window(dashboard):
    st, _, client, sensor, token, _ = dashboard
    headers = {"Authorization": "Bearer " + token}

    def summary(days):
        response = client.post(ENDPOINT, json={"days": days}, headers=headers)
        assert response.status_code == 200, response.text
        return response.json()

    empty = summary(1)
    assert all(count == 0 for count in empty["summary"].values())
    assert empty["recent"] == empty["by_agent"] == []
    for mode in ("shadow", "enforce"):
        for decision in ("allow", "warn", "ask", "deny"):
            record(st, sensor, mode=mode, decision=decision)
    record(st, sensor, status="unavailable")
    expired = record(st, sensor, status="pending")
    pending = record(st, sensor, status="pending", expired=False)
    record(st, sensor, age=timedelta(days=2), product="codex-cli")
    record(st, sensor, age=timedelta(days=31))
    st.execute("INSERT INTO tenant_hook_settings(tenant_id,mode) VALUES($1,'enforce')", sensor["tenant_id"])
    day = summary(1)
    assert day["mode"] == "enforce"
    assert day["summary"] == dict(completed=8, allow=2, warn=2, ask=2, deny=2, unavailable=2, pending=1)
    assert day["by_mode"]["shadow"]["deny"] == day["by_mode"]["enforce"]["deny"] == 1
    assert day["by_mode"]["shadow"]["unavailable"] == 2
    assert day["by_mode"]["enforce"]["unavailable"] == 0
    assert {row["id"]: row["status"] for row in day["recent"]}[expired] == "unavailable"
    assert {row["id"]: row["status"] for row in day["recent"]}[pending] == "pending"
    assert [row["product"] for row in day["by_agent"]] == ["claude-code"]
    month = summary(30)
    assert month["summary"]["completed"] == 9
    assert len(month["by_agent"]) == 2
    for _ in range(21):
        record(st, sensor, age=timedelta(minutes=5), decision="allow")
    limited = summary(1)
    assert limited["summary"]["completed"] == 29
    assert len(limited["recent"]) == 20
    assert all(row["evaluated_decision"] == "allow" for row in limited["recent"])
    assert [row["created_at"] for row in limited["recent"]] == sorted(
        [row["created_at"] for row in limited["recent"]], reverse=True,
    )


def test_denial_review_pages_complete_window_and_preserves_decisions(dashboard):
    st, _, client, sensor, token, _ = dashboard
    headers = {"Authorization": "Bearer " + token}

    def call(action, data):
        result = client.post("/ingest/v1/guardrails/" + action, json=data, headers=headers)
        assert result.status_code == 200, result.text
        assert result.headers["cache-control"] == "no-store"
        return result.json()

    ids = {record(st, sensor, mode="enforce" if i % 2 else "shadow") for i in range(23)}
    old = record(st, sensor, age=timedelta(days=2))
    record(st, sensor, age=timedelta(days=31))
    for _ in range(21):
        record(st, sensor, decision="allow", age=timedelta(minutes=1))
    summary = call("summary", {})
    assert all(row["evaluated_decision"] == "allow" for row in summary["recent"])
    window = dict(days=1, until=summary["until"], cursor="")
    first = call("denials", window)
    assert len(first["items"]) == 20 and first["next_cursor"]
    assert "PRIVATE-ACTION" not in str(first)
    second = call("denials", {**window, "cursor": first["next_cursor"]})
    assert not second["next_cursor"] and len(second["items"]) == 3
    assert {row["id"] for row in first["items"] + second["items"]} == ids
    month = call("denials", {**window, "days": 30, "cursor": first["next_cursor"]})
    assert old in {row["id"] for row in month["items"]}
    check = first["items"][0]
    detail = call("check", {"id": check["id"]})
    assert detail["reason"] == "PRIVATE-REASON" and detail["actions"][0]["command"]["text"] == "PRIVATE-ACTION"
    for label, note in (("false_positive", "Expected cleanup <script>test</script>"), ("correct_denial", "")):
        saved = call("review", dict(id=check["id"], label=label, note=note))
        assert saved["label"] == label and saved["note"] == note and saved["reviewed_at"]
        loaded = call("check", {"id": check["id"]})
        assert loaded["label"] == label and loaded["note"] == note
        assert loaded["returned_decision"] == detail["returned_decision"] and loaded["reason"] == detail["reason"]
    assert call("summary", {})["summary"] == summary["summary"]
    assert call("denials", window)["items"][0]["label"] == "correct_denial"
    st.execute("DELETE FROM ordinary_hook_checks WHERE id=$1", check["id"])
    assert st.scalar("SELECT count(*) FROM ordinary_hook_reviews") == 0
    assert st.scalar("SELECT count(*) FROM ordinary_hook_review_revisions") == 0


def test_ask_inspection_pages_scoped_evidence_without_allowing_reviews(dashboard):
    st, _, client, sensor, token, foreign = dashboard
    peer, _, _ = st.enroll_sensor({"enrollment_token": st.create_enrollment_token(sensor["tenant_id"])["token"], "hostname": "peer"})
    headers = {"Authorization": "Bearer " + token}
    def post(action, data, authenticated=True):
        return client.post("/ingest/v1/guardrails/" + action, json=data, headers=headers if authenticated else {})
    ids = {record(st, sensor, decision="ask", mode="enforce" if i % 2 else "shadow") for i in range(23)}
    forbidden = [record(st, peer, decision="ask"), record(st, foreign, decision="ask"),
                 record(st, sensor, decision="allow"), record(st, sensor), record(st, sensor, status="unavailable")]
    summary = post("summary", {}).json()
    window = dict(days=1, until=summary["until"], cursor="", decision="ask", review_version=1)
    first = post("denials", window).json()
    second = post("denials", {**window, "cursor": first["next_cursor"]}).json()
    assert len(first["items"]) == 20 and len(second["items"]) == 3
    assert {row["id"] for row in first["items"] + second["items"]} == ids
    assert "PRIVATE-ACTION" not in str(first)
    ident = first["items"][0]["id"]
    detail = dict(id=ident, decision="ask", review_version=1)
    response = post("check", detail)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json()["actions"][0]["command"]["text"] == "PRIVATE-ACTION"
    assert response.json()["evidence"]["decision"]["evaluated_decision"] == "ask"
    assert post("check", {"id": ident}).status_code == 404
    assert post("review", dict(id=ident, label="false_positive", note="")).status_code == 404
    assert post("review", dict(id=ident, label="false_positive", note="", decision="ask")).status_code == 400
    for other in forbidden:
        assert post("check", {**detail, "id": other}).status_code == 404
    for action, data in (("check", detail), ("denials", window)):
        assert post(action, data, False).status_code == 401
        assert post(action, {**data, "decision": "allow"}).status_code == 400
        assert post(action, {**data, "sensor_id": peer["id"]}).status_code == 400


def test_denial_review_rejects_other_devices_tenants_and_invalid_feedback(dashboard):
    st, _, client, sensor, token, foreign = dashboard
    peer, _, _ = st.enroll_sensor({"enrollment_token": st.create_enrollment_token(sensor["tenant_id"])["token"], "hostname": "peer"})
    own = record(st, sensor)
    forbidden = [record(st, peer), record(st, foreign), record(st, sensor, decision="allow"),
                 record(st, sensor, status="unavailable"), new_id()]
    headers = {"Authorization": "Bearer " + token}

    def post(action, data, authenticated=True):
        return client.post("/ingest/v1/guardrails/" + action, json=data, headers=headers if authenticated else {})

    review = dict(id=own, label="false_positive", note="")
    for ident in forbidden:
        assert post("check", {"id": ident}).status_code == 404
        assert post("review", {**review, "id": ident}).status_code == 404
    summary = post("summary", {}).json()
    window = dict(days=1, until=summary["until"], cursor="")
    assert [row["id"] for row in post("denials", window).json()["items"]] == [own]
    for action, data in (("denials", window), ("check", {"id": own}), ("review", review)):
        assert post(action, data, False).status_code == 401
        assert post(action, {**data, "sensor_id": peer["id"]}).status_code == 400
    for changes in ({"label": "allow"}, {"label": None}, {"note": 1}, {"note": "x" * 2001}, {"note": "\0"}, {"id": "bad"}):
        assert post("review", {**review, **changes}).status_code == 400
    for changes in ({"days": True}, {"days": 7}, {"until": "bad"}, {"until": "2026-10-29"}, {"cursor": "bad"}):
        assert post("denials", {**window, **changes}).status_code == 400
    st.update_sensor(sensor["tenant_id"], sensor["id"], disabled=True)
    for action, data in (("denials", window), ("check", {"id": own}), ("review", review)):
        assert post(action, data).status_code == 403
    assert st.scalar("SELECT count(*) FROM ordinary_hook_reviews") == 0


def test_review_revisions_bind_evidence_retries_and_legacy_clients(dashboard):
    import hashlib
    import json
    import psycopg
    import pytest

    st, _, client, sensor, token, foreign = dashboard
    ident = record(st, sensor)
    headers = {"Authorization": "Bearer " + token}

    def post(action, data):
        return client.post("/ingest/v1/guardrails/" + action, json=data, headers=headers)

    detail = post("check", {"id": ident, "review_version": 1}).json()
    assert detail["review_revision"] == 0
    canonical = json.dumps(detail["evidence"], sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    assert detail["evidence_sha256"] == hashlib.sha256(canonical).hexdigest()
    assert {"assessment_input_not_retained", "policy_snapshot_not_retained"} <= set(detail["evidence"]["gaps"])
    assert detail["evidence"]["assessment_input"] is None
    request = {"id": ident, "review_version": 1, "label": "false_positive", "note": "Expected cleanup",
               "evidence_sha256": detail["evidence_sha256"], "expected_revision": 0, "request_id": new_id()}
    first = post("review", request)
    assert first.status_code == 200, first.text
    assert first.json()["review_revision"] == 1
    assert post("review", request).json() == first.json()
    assert post("review", {**request, "note": "Changed retry"}).status_code == 409
    assert post("review", {**request, "request_id": new_id()}).status_code == 409
    assert post("review", {**request, "request_id": new_id(), "expected_revision": 1,
                           "evidence_sha256": "0" * 64}).status_code == 409
    assert st.scalar("SELECT count(*) FROM ordinary_hook_review_revisions") == 1
    assert st.scalar("SELECT count(*) FROM ordinary_hook_review_evidence") == 1
    for table in ("ordinary_hook_review_evidence", "ordinary_hook_review_revisions"):
        with pytest.raises(psycopg.errors.CheckViolation):
            st.execute(f"UPDATE {table} SET check_id=check_id")

    second = post("review", {**request, "request_id": new_id(), "expected_revision": 1,
                             "label": "insufficient_context", "note": "Need the earlier prompt"})
    assert second.status_code == 200, second.text
    assert second.json()["review_revision"] == 2
    current = post("check", {"id": ident, "review_version": 1}).json()
    assert current["label"] == "insufficient_context" and current["review_revision"] == 2
    assert current["evidence_sha256"] == detail["evidence_sha256"]
    legacy = post("check", {"id": ident}).json()
    assert legacy["label"] is legacy["note"] is legacy["reviewed_at"] is None
    window = {"days": 1, "until": datetime.now(timezone.utc).isoformat(), "cursor": ""}
    assert post("denials", window).json()["items"][0]["label"] is None
    assert post("denials", {**window, "review_version": 1}).json()["items"][0]["label"] == "insufficient_context"
    assert post("review", request).json() == first.json()  # Retry cannot overwrite the newer label.
    legacy_save = post("review", {"id": ident, "label": "correct_denial", "note": "Confirmed"})
    assert legacy_save.status_code == 200, legacy_save.text
    assert set(legacy_save.json()) == {"id", "label", "note", "reviewed_at"}
    rows = st.many("SELECT * FROM ordinary_hook_review_revisions WHERE check_id=$1 ORDER BY revision", ident)
    assert [row["label"] for row in rows] == ["false_positive", "insufficient_context", "correct_denial"]
    assert [row["revision"] for row in rows] == [1, 2, 3]
    assert all(row["source_id"] == sensor["id"] for row in rows)
    assert rows[0]["evidence_sha256"] == rows[1]["evidence_sha256"] == detail["evidence_sha256"]
    assert rows[2]["evidence_sha256"] is None
    assert st.scalar("SELECT count(*) FROM ordinary_hook_review_evidence") == 1
    st.execute("DELETE FROM ordinary_hook_checks WHERE id=$1", ident)
    assert st.scalar("SELECT count(*) FROM ordinary_hook_review_revisions") == 0
    assert st.scalar("SELECT count(*) FROM ordinary_hook_review_evidence") == 0


def test_versioned_review_rejects_wrong_scope_and_competing_edits(dashboard):
    from concurrent.futures import ThreadPoolExecutor

    st, _, client, sensor, token, foreign = dashboard
    own = record(st, sensor)
    peer, _, _ = st.enroll_sensor({"enrollment_token": st.create_enrollment_token(sensor["tenant_id"])["token"], "hostname": "peer"})
    headers = {"Authorization": "Bearer " + token}

    def post(action, data):
        return client.post("/ingest/v1/guardrails/" + action, json=data, headers=headers)

    detail = post("check", {"id": own, "review_version": 1}).json()
    review = {"id": own, "label": "false_positive", "note": "", "review_version": 1,
              "evidence_sha256": detail["evidence_sha256"], "expected_revision": 0, "request_id": new_id()}
    for forbidden in (record(st, peer), record(st, foreign), record(st, sensor, decision="allow")):
        assert post("check", {"id": forbidden, "review_version": 1}).status_code == 404
        assert post("review", {**review, "id": forbidden}).status_code == 404
    for changes in ({"review_version": True}, {"review_version": 2}, {"expected_revision": True},
                    {"request_id": "bad"}, {"evidence_sha256": None}, {"label": "resolved"}):
        assert post("review", {**review, **changes}).status_code == 400
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda label: post("review", {**review, "label": label, "request_id": new_id()}),
                                ("correct_denial", "false_positive")))
    assert sorted(response.status_code for response in results) == [200, 409]
    assert st.scalar("SELECT count(*) FROM ordinary_hook_review_revisions") == 1
    st.update_sensor(sensor["tenant_id"], sensor["id"], disabled=True)
    assert post("review", review).status_code == 403


def test_feedback_migration_preserves_legacy_label_without_inventing_evidence(dashboard):
    st, _, _, sensor, _, _ = dashboard
    st.execute("DROP TABLE ordinary_hook_review_revisions,ordinary_hook_review_evidence")
    st.execute("DROP TRIGGER ordinary_hook_assessment_input_immutable ON ordinary_hook_checks")
    st.execute("DROP FUNCTION preserve_guardrail_feedback()")
    st.execute("ALTER TABLE ordinary_hook_checks DROP COLUMN assessment_input,DROP COLUMN assessment_input_sha256,DROP COLUMN assessment_context")
    st.execute("ALTER TABLE ordinary_hook_reviews DROP COLUMN revision")
    st.execute("DELETE FROM schema_migrations WHERE version=147")
    ident = record(st, sensor)
    st.execute("INSERT INTO ordinary_hook_reviews(check_id,label,note) VALUES($1,'false_positive','Legacy note')", ident)
    before = st.one("SELECT * FROM ordinary_hook_reviews WHERE check_id=$1", ident)
    st.migrate()
    current = st.one("SELECT * FROM ordinary_hook_reviews WHERE check_id=$1", ident)
    revision = st.one("SELECT * FROM ordinary_hook_review_revisions WHERE check_id=$1", ident)
    assert current == {**before, "revision": 1}
    assert revision["label"] == before["label"] and revision["note"] == before["note"]
    assert revision["reviewed_at"] == before["updated_at"] and revision["source_id"] == sensor["id"]
    assert revision["evidence_sha256"] is None and revision["request_id"] is None


def test_versioned_review_projects_private_metadata_and_binds_returned_evidence(dashboard):
    import hashlib
    import json

    st, _, client, sensor, token, _ = dashboard
    ident = record(st, sensor)
    action = {"kind": "command", "command": {"text": "Inspect customer model/provider accounting evidence"}}
    reason = "Preserve the customer's provider and model names exactly."
    assessment = {"status": "scored", "score": 95, "reason": reason, "model": "PRIVATE-MODEL-MARKER",
                  "provider": "PRIVATE-PROVIDER-MARKER", "usage": {"cost_usd": "PRIVATE-ACCOUNTING-MARKER"},
                  "rubric_version": "PRIVATE-PROFILE-MARKER", "links": {"status": "clean", "cost_usd": "PRIVATE-LINK-COST"}}
    settings = {"assessment_profile": {"model": "PRIVATE-PROFILE-MODEL", "rubric_version": "PRIVATE-RUBRIC"},
                "policy_snapshot": {"version": 1, "rules": [{"reason": reason}]}}
    st.execute("UPDATE ordinary_hook_checks SET actions=$2,reason=$3,assessment=$4,risk_settings=$5 WHERE id=$1",
               ident, Jsonb([action]), reason, Jsonb(assessment), Jsonb(settings))
    headers = {"Authorization": "Bearer " + token}
    detail = client.post("/ingest/v1/guardrails/check", json={"id": ident, "review_version": 1}, headers=headers)
    assert detail.status_code == 200, detail.text
    assert "PRIVATE-" not in detail.text
    evidence = detail.json()["evidence"]
    assert evidence["actions"] == [action] and evidence["assessment"]["reason"] == reason
    assert evidence["decision_basis"]["policy"]["rules"][0]["reason"] == reason
    assert "assessment_profile" not in evidence["decision_basis"]
    encoded = json.dumps(evidence, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    assert detail.json()["evidence_sha256"] == hashlib.sha256(encoded).hexdigest()
    request = {"id": ident, "review_version": 1, "label": "correct_denial", "note": "",
               "expected_revision": 0, "request_id": new_id(), "evidence_sha256": detail.json()["evidence_sha256"]}
    saved = client.post("/ingest/v1/guardrails/review", json=request, headers=headers)
    assert saved.status_code == 200, saved.text
    assert client.post("/ingest/v1/guardrails/review", json=request, headers=headers).json() == saved.json()
    assert st.scalar("SELECT evidence FROM ordinary_hook_review_evidence WHERE check_id=$1", ident) == evidence
    retained = st.one("SELECT assessment,risk_settings FROM ordinary_hook_checks WHERE id=$1", ident)
    assert retained["assessment"] == assessment and retained["risk_settings"] == settings
