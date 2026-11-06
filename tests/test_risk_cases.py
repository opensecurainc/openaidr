"""Risk case lifecycle through authenticated HTTP and real PostgreSQL."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

import pytest
from psycopg.errors import CheckViolation
from psycopg.types.json import Jsonb

from openaidr.core.event import new_id
from openaidr.server import auth, risk_activity
from test_inline_guardrail import browser, system as system
from test_ordinary_session_detection import captured, configure, finalize
from test_session_aggregation import action, close_session, deliver, finalized, registered
from test_store import db as db


def cases(system, query="", user="admin", expected=200):
    reply = browser(system, "GET", "risk-cases" + query, user=user)
    assert reply.status_code == expected, reply.text
    if expected == 200:
        assert reply.headers["cache-control"] == "no-store"
    return reply.json()


def refresh_activity(system, zone="UTC", user="admin"):
    tenant = system.users[user]["tenant_id"]
    risk_activity.request_snapshot(system.db, tenant, zone)
    while risk_activity.refresh_one(system.db, tenant):
        pass
    with system.db.transaction() as conn:
        assert system.db.scalar("""SELECT until IS NOT NULL FROM risk_activity_snapshots
            WHERE tenant_id=$1 AND time_zone=$2 FOR SHARE""", tenant, zone, conn=conn)


def investigate(system, scores=(90, 80), *, account="", device="sensor"):
    value = captured(system, scores, device=device)
    system.db.execute("UPDATE events SET body=jsonb_set(body,'{agent,account}',$2) WHERE session_id=$1",
                      value.id, Jsonb(account))
    state = finalize(system, value)
    return value, state["routing"]["job_id"]


def verdict(system, row, outcome, expected=200, user="admin", context=None):
    data = {"outcome": outcome, "version": row["version"]}
    if context is not None:
        data["review_context"] = context
    reply = browser(system, "PATCH", "risk-cases/" + row["id"], data, user=user)
    assert reply.status_code == expected, reply.text
    return reply.json()


def report_attempt(system, job_id, ordinal=1, report=None):
    attempt_id = new_id()
    report = report or {"title": "Retained result", "summary": "Captured evidence", "status": "finding",
                        "findings": [], "gaps": []}
    system.db.execute("""INSERT INTO session_investigation_attempts(id,tenant_id,job_id,ordinal,state,report,
        claim_token,worker_id,reserved_tokens,reserved_cost_usd,window_start,deadline_at)
        VALUES($1,$2,$3,$4,'completed',$5,$6,'test',1,0.01,now(),now()+interval '1 minute')""",
        attempt_id, system.tenant["id"], job_id, ordinal, Jsonb(report), new_id())
    system.db.execute("UPDATE session_investigation_jobs SET state='completed' WHERE id=$1", job_id)
    return attempt_id


def test_case_review_keeps_exact_attempts_and_rejects_changed_reports(system):
    configure(system)
    _, job_id = investigate(system)
    first = report_attempt(system, job_id)
    row = cases(system)["groups"]["sessions"]["items"][0]
    shown = cases(system, "/" + row["id"])
    saved = verdict(system, row, "fp", context=shown["review_context"])
    history = system.db.one("SELECT * FROM risk_case_review_revisions WHERE case_id=$1", row["id"])
    assert history["review_context"] == shown["review_context"]
    assert history["review_context"]["reports"][0]["attempt_id"] == first
    assert (history["revision"], history["case_version"], history["outcome"]) == (1, row["version"], "fp")
    assert history["reviewer_id"] == system.users["admin"]["id"] and history["reviewer_name"] == "Admin"
    assert history["reviewed_at"] and history["completeness"] == []
    with pytest.raises(CheckViolation, match="case review revisions are immutable"):
        system.db.execute("UPDATE risk_case_review_revisions SET outcome='tp' WHERE case_id=$1", row["id"])
    # A later attempt changes report selection without changing the case version.
    second = report_attempt(system, job_id, ordinal=2, report={"title": "Later report", "summary": "Partial result",
                            "status": "inconclusive", "gaps": ["Missing context"], "findings": []})
    verdict(system, saved["case"], "tp", context=saved["review_context"], expected=409)
    assert system.db.one("SELECT * FROM risk_case_review_revisions WHERE case_id=$1", row["id"]) == history
    current = cases(system, "/" + row["id"])
    assert current["review_context"]["reports"][0]["attempt_id"] == second
    # Even content changing under one attempt ID invalidates what was displayed.
    system.db.execute("UPDATE session_investigation_attempts SET report=jsonb_set(report,'{summary}','\"Changed output\"') WHERE id=$1", second)
    verdict(system, current["case"], "tp", context=current["review_context"], expected=409)
    current = cases(system, "/" + row["id"])
    confirmed = verdict(system, current["case"], "fp", context=current["review_context"])
    assert confirmed["case"]["version"] == current["case"]["version"] + 1
    revisions = system.db.many("SELECT * FROM risk_case_review_revisions WHERE case_id=$1 ORDER BY revision", row["id"])
    assert [item["revision"] for item in revisions] == [1, 2]
    assert revisions[0] == history
    assert revisions[1]["review_context"] == current["review_context"]
    assert revisions[1]["completeness"] == ["report_gaps"]
    # Reopening is its own workflow outcome, not a new benign or model label.
    verdict(system, confirmed["case"], "review", context=confirmed["review_context"])
    assert system.db.scalar("SELECT outcome FROM risk_case_review_revisions WHERE case_id=$1 AND revision=3", row["id"]) == "review"
    assert system.db.scalar("SELECT count(*) FROM findings") == 0


def test_case_review_marks_missing_and_partial_context_and_preserves_legacy_clients(system):
    configure(system)
    for _ in range(21):
        investigate(system)
    row = cases(system)["groups"]["users"]["items"][0]
    shown = cases(system, "/" + row["id"])
    assert shown["review_context"]["report_count"] == 21 and len(shown["review_context"]["reports"]) == 20
    saved = verdict(system, row, "fp", context=shown["review_context"])
    before = system.db.one("SELECT * FROM risk_case_review_revisions WHERE case_id=$1", row["id"])
    assert before["completeness"] == ["partial_case", "missing_report"]
    assert all(item["attempt_id"] is None and item["report_sha256"] is None for item in before["review_context"]["reports"])
    # Late completion of an already attached member does not rewrite a closed review.
    report_attempt(system, shown["reports"][0]["job_id"])
    assert system.db.one("SELECT * FROM risk_case_review_revisions WHERE case_id=$1", row["id"]) == before
    legacy = verdict(system, saved["case"], "tp")
    revision = system.db.one("SELECT * FROM risk_case_review_revisions WHERE case_id=$1 AND revision=2", row["id"])
    assert revision["review_context"] is None and revision["completeness"] == ["legacy_unbound"]
    verdict(system, legacy["case"], "tp")
    assert system.db.scalar("SELECT count(*) FROM risk_case_review_revisions WHERE case_id=$1", row["id"]) == 2
    system.db.execute("DELETE FROM risk_cases WHERE id=$1", row["id"])
    assert system.db.scalar("SELECT count(*) FROM risk_case_review_revisions WHERE case_id=$1", row["id"]) == 0


def test_case_review_validates_membership_tenant_and_concurrent_submissions(system):
    configure(system)
    _, job_id = investigate(system)
    report_attempt(system, job_id)
    row = cases(system)["groups"]["users"]["items"][0]
    shown = cases(system, "/" + row["id"])
    verdict(system, row, "tp", user="foreign", context=shown["review_context"], expected=404)
    forged = deepcopy(shown["review_context"])
    forged["reports"][0]["snapshot_id"] = new_id()
    verdict(system, row, "tp", context=forged, expected=409)
    forged["reports"] = []
    verdict(system, row, "tp", context=forged, expected=400)
    investigate(system)
    verdict(system, row, "tp", context=shown["review_context"], expected=409)
    current = cases(system, "/" + row["id"])
    analyst = system.db.create_user(system.tenant["id"], "second-analyst@example.test", "Second analyst", "hash", "owner")
    system.headers["analyst"] = {"Cookie": auth.CONSOLE_COOKIE + "=" + system.db.create_session(analyst["id"], system.tenant["id"]),
                                 auth.CSRF_HEADER: "1"}
    def save(submission):
        user, outcome = submission
        return browser(system, "PATCH", "risk-cases/" + row["id"], {
            "version": current["case"]["version"], "outcome": outcome,
            "review_context": current["review_context"],
        }, user=user).status_code
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(save, (("admin", "tp"), ("analyst", "fp")))) == [200, 409]
    assert system.db.scalar("SELECT count(*) FROM risk_case_review_revisions WHERE case_id=$1", row["id"]) == 1
    reviewer = system.db.one("SELECT reviewer_id,outcome FROM risk_case_review_revisions WHERE case_id=$1", row["id"])
    assert reviewer["reviewer_id"] == (system.users["admin"]["id"] if reviewer["outcome"] == "tp" else analyst["id"])
    assert system.db.scalar("SELECT count(*) FROM audit_log WHERE action='risk-case.outcome'") == 1


def test_risk_lists_use_current_tenant_detection_threshold(system):
    refresh_activity(system)
    snapshot = cases(system, "?view=activity")["activity_snapshot"]
    for threshold in (70, 82):
        settings = configure(system, selection_policy="risk_budget", action_risk_threshold=threshold)
        for view in ("activity", "cases"):
            data = cases(system, "?view=" + view)
            assert data["selection_policy"] == settings["selection_policy"]
            assert data["detection_threshold"] == settings["action_risk_threshold"]
            if view == "activity":
                assert data["activity_snapshot"] == snapshot
        assert cases(system, "?view=activity", user="foreign")["detection_threshold"] == 70
    configure(system, selection_policy="legacy", risk_threshold="250")
    for view in ("activity", "cases"):
        data = cases(system, "?view=" + view)
        assert data["selection_policy"] == "legacy"
        assert data["detection_threshold"] is None


def test_top_activity_includes_uninvestigated_sessions_and_reported_users(system):
    configure(system)
    values = [captured(system, scores, device=device) for scores, device in (
        ((65,), "sensor"), ((40,), "peer_sensor"), ((20,), "sensor"),
        ((0,), "peer_sensor"), ((None,), "sensor"), ((None, "90", -1, 101), "peer_sensor"),
        ((10,), "sensor"), ((9,), "peer_sensor"),
    )]
    for value in values:
        system.db.execute("UPDATE events SET body=jsonb_set(body,'{agent,account}',$2) WHERE session_id=$1",
                          value.id, Jsonb(""))
    for value in values[:2]:
        system.db.execute("UPDATE events SET body=jsonb_set(body,'{agent,account}',$2) WHERE session_id=$1",
                          value.id, Jsonb("person@example.test"))
    # A mixed-identity session remains visible, but is not attributed to a user.
    system.db.execute("UPDATE events SET body=jsonb_set(body,'{host,user}',$2) WHERE id=$1",
                      values[5].events[0]["id"], Jsonb("different-user"))
    for value in values:
        assert finalize(system, value)["routing"]["status"] == "below_threshold"
    old = captured(system, (100,))
    system.db.execute("UPDATE events SET time=now()-interval '40 days' WHERE session_id=$1", old.id)
    # A recently active session must not inherit a score from outside the window.
    old_event = deepcopy(values[4].events[0])
    old_event["id"] = new_id()
    old_event["evidence"]["observation_id"] = old_event["id"]
    system.db.ingest_batch(values[4].sensor, [old_event])
    system.db.execute("UPDATE events SET time=now()-interval '40 days',risk=$2 WHERE id=$1",
                      old_event["id"], Jsonb({"status": "scored", "score": 100}))
    foreign = captured(system, (99,), device="foreign_sensor")
    before = {table: system.db.scalar(f"SELECT count(*) FROM {table}") for table in (
        "risk_cases", "risk_case_jobs", "session_investigation_jobs", "session_snapshots", "model_usage",
    )}
    refresh_activity(system, "America/Los_Angeles")
    refresh_activity(system)
    refresh_activity(system, user="foreign")
    data = cases(system, "?view=activity&time_zone=America%2FLos_Angeles")
    assert data["view"] == "activity" and data["groups"]["sessions"]["total"] == 8
    assert [row["peak"] for row in data["groups"]["sessions"]["items"]] == [65, 40, 20, 10, 9]
    second = cases(system, "?view=activity&sessions_offset=5")
    assert [row["peak"] for row in second["groups"]["sessions"]["items"]] == [0, None, None]
    assert any(row["identity_kind"] == "mixed" for row in second["groups"]["sessions"]["items"])
    users = data["groups"]["users"]["items"]
    assert len(users) == 2
    assert users[0]["reported_user"] == "reported-user"
    assert users[0]["accounts"] == ["person@example.test"]
    assert (users[0]["peak"], users[0]["session_count"], users[0]["device_count"], users[0]["session_id"]) == (65, 4, 1, values[0].id)
    assert len({row["id"] for row in users if row["identity_kind"] == "os_user"}) == 2
    assert cases(system, "?view=activity&q=person")["groups"]["sessions"]["total"] == 2
    assert cases(system, "?view=activity&q=%25")["groups"]["sessions"]["total"] == 0
    assert all(sum(bin[key] for bin in data["charts"][kind]) == 0 for kind in ("sessions", "users") for key in ("review", "tp", "fp"))
    assert cases(system)["groups"]["sessions"]["total"] == 0
    assert cases(system, "?view=activity", user="foreign")["groups"]["sessions"]["items"][0]["session_id"] == foreign.id
    cases(system, "?view=activity", user="owner", expected=403)
    assert system.client.get("/api/v1/risk-cases?view=activity").status_code == 401
    for query in ("?view=invalid", "?view=activity&outcome=tp", "?view=activity&day=2026-10-21"):
        cases(system, query, expected=400)
    assert before == {table: system.db.scalar(f"SELECT count(*) FROM {table}") for table in before}


def test_top_activity_includes_managed_scores_without_investigation(system):
    configure(system, enabled=False)
    registration = registered(system)
    action(system, registration, 25)
    refresh_activity(system)
    data = cases(system, "?view=activity")
    assert data["groups"]["sessions"]["total"] == 1
    assert data["groups"]["sessions"]["items"][0]["peak"] == 25
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0


def test_activity_identity_conflicts_and_missing_fields(system):
    configure(system, risk_threshold="1")
    expected = {}
    for accounts, users, kind, reported_user in (
        (("same", None), ("same", "same"), "os_user", "same"),
        (("Alice", "alice"), ("os-user", "os-user"), "os_user", "os-user"),
        (("account-only@example.test", ""), (None, ""), "unknown", ""),
        (("müller", "müller"), ("first", "second"), "mixed", ""),
        (("", None), ("Zoë", "Zoë"), "os_user", "Zoë"),
    ):
        value = captured(system, (10, 20))
        for event, account, user, hostname in zip(value.events, accounts, users, (None, "host")):
            system.db.execute(
                "UPDATE events SET body=jsonb_set(jsonb_set(body,'{agent,account}',$2),'{host}',$3) WHERE id=$1",
                event["id"], Jsonb(account), Jsonb({"user": user, "hostname": hostname}),
            )
        expected[value.id] = (kind, reported_user, "host", 20)
        finalize(system, value)
    refresh_activity(system)
    data = cases(system, "?view=activity")
    assert data["groups"]["sessions"]["total"] == len(expected)
    assert {row["session_id"]: (row["identity_kind"], row["reported_user"], row["hostname"], row["peak"])
            for row in data["groups"]["sessions"]["items"]} == expected
    assert data["groups"]["users"]["total"] == 3
    assert {row["reported_user"]: row["accounts"] for row in data["groups"]["users"]["items"]} == {
        "same": ["same"], "os-user": ["Alice", "alice"], "Zoë": [],
    }
    investigated = cases(system)
    assert sorted((row["identity_kind"], row["reported_user"], row["peak"])
                  for row in investigated["groups"]["sessions"]["items"]) == sorted(
                      (kind, user, peak) for kind, user, _, peak in expected.values())
    assert {row["reported_user"]: row["accounts"] for row in investigated["groups"]["users"]["items"]} == {
        "same": ["same"], "os-user": ["Alice", "alice"], "Zoë": [],
    }


def test_case_identity_lifecycle_verdicts_and_tenant_authorization(system):
    configure(system)
    first, first_job = investigate(system, account="alice@example.test")
    investigate(system, (99, 80), account="alice@example.test", device="peer_sensor")
    investigate(system)
    investigate(system, device="peer_sensor")
    data = cases(system)
    sessions, users = (data["groups"][kind]["items"] for kind in ("sessions", "users"))
    assert data["groups"]["sessions"]["total"] == 4
    assert data["groups"]["users"]["total"] == 2
    account = next(row for row in users if row["peak"] == 99)
    assert account["reported_user"] == "reported-user" and account["accounts"] == ["alice@example.test"]
    assert account["session_count"] == 2 and account["device_count"] == 1
    assert len({row["id"] for row in users if row["identity_kind"] == "os_user"}) == 2
    assert sum(row["review"] for row in data["charts"]["users"]) == 2
    refresh_activity(system)
    activity = cases(system, "?view=activity")
    assert activity["groups"]["sessions"]["total"] == 4
    assert activity["charts"] == data["charts"]
    assert cases(system, user="foreign")["groups"]["sessions"]["total"] == 0
    cases(system, user="owner", expected=403)
    assert system.client.get("/api/v1/risk-cases").status_code == 401
    for route in (account["id"], account["id"] + "/download"):
        assert browser(system, "GET", "risk-cases/" + route, user="foreign").status_code == 404
        assert browser(system, "GET", "risk-cases/" + route, user="owner").status_code == 403
    verdict(system, account, "tp", expected=404, user="foreign")
    verdict(system, account, "tp", expected=403, user="owner")
    missing_csrf = system.client.patch("/api/v1/risk-cases/" + account["id"], json={"outcome": "tp", "version": account["version"]},
                                      headers={"Cookie": system.headers["admin"]["Cookie"]})
    assert missing_csrf.status_code == 403
    closed = verdict(system, account, "fp")["case"]
    assert closed["outcome"] == "fp" and closed["closed_at"] and closed["peak"] == account["peak"]
    updated_activity = cases(system, "?view=activity")
    assert updated_activity["activity_snapshot"] == activity["activity_snapshot"]
    assert updated_activity["groups"] == activity["groups"]
    assert sum(row["fp"] for row in updated_activity["charts"]["users"]) == 1
    verdict(system, account, "tp", expected=409)
    assert all(row["outcome"] == "review" for row in cases(system)["groups"]["sessions"]["items"])
    investigate(system, account="alice@example.test", device="peer_sensor")
    verdict(system, closed, "review", expected=409)
    new = next(row for row in cases(system)["groups"]["users"]["items"] if row["id"] not in {item["id"] for item in users})
    assert new["id"] != account["id"] and new["session_count"] == 1
    assert browser(system, "GET", "risk-cases/" + account["id"]).json()["case"]["session_count"] == 2
    assert system.db.scalar("SELECT count(*) FROM audit_log WHERE action='risk-case.outcome'") == 1
    # Re-finalizing the same investigation must not reopen a closed session case.
    session = next(row for row in sessions if browser(system, "GET", "risk-cases/" + row["id"]).json()["reports"][0]["job_id"] == first_job)
    verdict(system, session, "tp")
    finalize(system, first)
    assert system.db.scalar("SELECT count(*) FROM risk_case_jobs WHERE job_id=$1", first_job) == 2


def test_case_paging_search_charts_and_safe_complete_download(system):
    configure(system)
    for score in range(80, 87):
        investigate(system, (score, 80), account="person@example.test")
    data = cases(system, "?time_zone=America%2FLos_Angeles")
    rows = data["groups"]["sessions"]["items"]
    assert len(rows) == 5 and data["groups"]["sessions"]["total"] == 7
    assert [float(row["peak"]) for row in rows] == [86, 85, 84, 83, 82]
    second = cases(system, "?sessions_offset=5&time_zone=America%2FLos_Angeles")
    assert [float(row["peak"]) for row in second["groups"]["sessions"]["items"]] == [81, 80]
    closed = verdict(system, rows[0], "tp")["case"]
    filtered = cases(system, "?outcome=tp&q=person&time_zone=America%2FLos_Angeles")
    assert filtered["groups"]["sessions"]["total"] == 1
    assert sum(b["review"] + b["tp"] + b["fp"] for b in filtered["charts"]["sessions"]) == 7
    assert sum(b["tp"] for b in filtered["charts"]["sessions"]) == 1
    refresh_activity(system, "America/Los_Angeles")
    assert cases(system, "?view=activity&time_zone=America%2FLos_Angeles")["charts"] == filtered["charts"]
    day = next(b["day"] for b in filtered["charts"]["sessions"] if b["tp"])
    assert cases(system, "?day=" + day + "&time_zone=America%2FLos_Angeles")["groups"]["sessions"]["total"] == 7
    for query in ("?outcome=invalid", "?time_zone=invalid", "?day=wrong", "?sessions_offset=-1", "?q=" + "a" * 201):
        cases(system, query, expected=400)
    # Old open cases remain reachable, but do not inflate the 30-day chart.
    user_case = data["groups"]["users"]["items"][0]
    system.db.execute("UPDATE risk_cases SET opened_at=now()-interval '40 days' WHERE id=$1", user_case["id"])
    old = cases(system)
    assert old["groups"]["users"]["total"] == 1
    assert sum(b["review"] for b in old["charts"]["users"]) == 0
    refresh_activity(system)
    assert cases(system, "?view=activity")["charts"] == old["charts"]
    detail = browser(system, "GET", "risk-cases/" + closed["id"]).json()
    job = detail["reports"][0]
    report = {"title": "Jev evidence <script>alert(1)</script>", "summary": "retained & exact", "findings": [], "gaps": [],
              "model": "private-provider-model", "runtime": {"model": "private-provider-model"},
              "usage": {"actual_cost_usd": "1.23"},
              "evidence": [{"model": "customer-own-model", "text": "Jev evidence"}]}
    system.db.execute("""INSERT INTO session_investigation_attempts(id,tenant_id,job_id,ordinal,state,report,
        claim_token,worker_id,reserved_tokens,reserved_cost_usd,window_start,deadline_at)
        VALUES($1,$2,$3,1,'reserved',$4,$5,'test',1,0.01,now(),now()+interval '1 minute')""",
        new_id(), system.tenant["id"], job["job_id"], Jsonb(report), new_id())
    download = browser(system, "GET", "risk-cases/" + closed["id"] + "/download")
    assert download.status_code == 200, download.text
    assert download.headers["content-disposition"].startswith("attachment;")
    assert "<script>alert" not in download.text and "&lt;script&gt;alert" in download.text
    assert "Jev evidence" in download.text and "retained &amp; exact" in download.text
    assert job["snapshot_id"] in download.text
    assert "private-provider-model" not in download.text and "actual_cost_usd" not in download.text
    assert "customer-own-model" in download.text
    safe_report = cases(system, "/" + closed["id"])["reports"][0]["report"]
    assert safe_report["evidence"] == report["evidence"]
    assert not {"model", "runtime", "usage"}.intersection(safe_report)
    assert system.db.scalar("SELECT report FROM session_investigation_attempts WHERE job_id=$1", job["job_id"]) == report
    # A case without a retained investigation must disappear from both charts and lists.
    system.db.execute("DELETE FROM session_investigation_jobs WHERE id=$1", job["job_id"])
    retained = cases(system)
    assert retained["groups"]["sessions"]["total"] == 6
    assert sum(b["review"] for b in retained["charts"]["sessions"]) == 6
    assert sum(b["tp"] for b in retained["charts"]["sessions"]) == 0
    assert cases(system, "?view=activity")["charts"] == retained["charts"]


def test_mixed_identity_stays_unattributed_and_concurrent_verdict_is_not_lost(system):
    configure(system)
    value = captured(system)
    system.db.execute("UPDATE events SET body=jsonb_set(body,'{host,user}',$2) WHERE id=$1", value.events[0]["id"], Jsonb("different-user"))
    finalize(system, value)
    result = cases(system)
    row = result["groups"]["sessions"]["items"][0]
    assert row["identity_kind"] == "mixed" and row["reported_user"] == ""
    assert result["groups"]["users"]["total"] == 0
    def save(outcome):
        return browser(system, "PATCH", "risk-cases/" + row["id"], {"version": row["version"], "outcome": outcome}).status_code
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(save, ("tp", "fp"))) == [200, 409]
    # A newly created job for later evidence opens another session case.
    later = deepcopy(value.events[0])
    later["id"] = new_id()
    later["evidence"]["observation_id"] = later["id"]
    later["evidence"]["logical_id"] = new_id()
    system.db.ingest_batch(value.sensor, [later])
    system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", later["id"], Jsonb({"status": "scored", "score": 95}))
    finalize(system, value)
    assert cases(system)["groups"]["sessions"]["total"] == 2


def test_managed_jobs_and_historical_backfill_use_retained_snapshots(system):
    configure(system, risk_threshold="50")
    registration = registered(system)
    _, _, records, _ = action(system, registration, 95)
    deliver(system, registration, records)
    close_session(system, registration, len(records))
    finalized(system, registration, enabled=True, ready=True)
    before = cases(system)
    assert before["groups"]["sessions"]["total"] == 1
    row = before["groups"]["sessions"]["items"][0]
    assert row["peak"] == 95
    assert before["groups"]["users"]["total"] == 1
    # Exercise the migration's population path, then replay it idempotently.
    system.db.execute("DELETE FROM risk_cases")
    for _ in range(2):
        system.db.execute("SELECT attach_risk_cases(j) FROM session_investigation_jobs j ORDER BY created_at,id")
    restored = cases(system)
    assert restored["groups"]["sessions"]["total"] == restored["groups"]["users"]["total"] == 1
    assert restored["groups"]["sessions"]["items"][0]["opened_at"] == row["opened_at"]
    assert system.db.scalar("SELECT count(*) FROM risk_case_jobs") == 2


def test_activity_snapshots_stay_available_during_refresh_failure_and_recover(system):
    value = captured(system, (20,))
    # Readers can queue preparation and read case charts even when raw evidence is locked.
    with system.db.transaction() as locked:
        locked.execute("LOCK TABLE events IN ACCESS EXCLUSIVE MODE")
        pending = cases(system, "?view=activity")
        assert pending["groups"] is None and pending["activity_snapshot"]["state"] == "pending"
        assert risk_activity.refresh_one(system.db, system.tenant["id"])
        failed = cases(system, "?view=activity")
        assert failed["groups"] is None and failed["activity_snapshot"]["state"] == "unavailable"
    system.db.execute("UPDATE risk_activity_snapshots SET refresh_after=now() WHERE tenant_id=$1", system.tenant["id"])
    refresh_activity(system)
    saved = cases(system, "?view=activity")
    assert saved["activity_snapshot"]["state"] == "current"
    assert saved["activity_snapshot"]["refresh_interval_seconds"] == 900
    assert saved["groups"]["sessions"]["items"][0]["peak"] == 20
    assert system.db.scalar("""SELECT refresh_after-until=interval '15 minutes' FROM risk_activity_snapshots
        WHERE tenant_id=$1 AND time_zone='UTC'""", system.tenant["id"])
    system.db.execute("UPDATE risk_activity_snapshots SET until=until-interval '16 minutes' WHERE tenant_id=$1", system.tenant["id"])
    aged = cases(system, "?view=activity")
    assert aged["groups"] == saved["groups"]
    assert aged["activity_snapshot"]["state"] == "stale" and not aged["activity_snapshot"]["refresh_failed"]
    system.db.execute("UPDATE risk_activity_snapshots SET until=$2 WHERE tenant_id=$1",
                      system.tenant["id"], saved["activity_snapshot"]["until"])
    system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", value.events[0]["id"], Jsonb({"status": "scored", "score": 80}))
    assert cases(system, "?view=activity")["groups"] == saved["groups"]
    system.db.execute("UPDATE risk_activity_snapshots SET refresh_after=now() WHERE tenant_id=$1", system.tenant["id"])
    with system.db.transaction() as locked:
        locked.execute("LOCK TABLE events IN ACCESS EXCLUSIVE MODE")
        assert risk_activity.refresh_one(system.db, system.tenant["id"])
        stale = cases(system, "?view=activity&q=peer")
        assert stale["groups"] == saved["groups"]
        assert stale["activity_snapshot"]["until"] == saved["activity_snapshot"]["until"]
        assert stale["activity_snapshot"]["state"] == "stale" and stale["activity_snapshot"]["refresh_failed"]
    system.db.execute("UPDATE risk_activity_snapshots SET refresh_after=now() WHERE tenant_id=$1", system.tenant["id"])
    refresh_activity(system)
    recovered = cases(system, "?view=activity")
    assert recovered["activity_snapshot"]["state"] == "current"
    assert recovered["groups"]["sessions"]["items"][0]["peak"] == 80
    assert not risk_activity.refresh_one(system.db, system.tenant["id"])


def test_activity_snapshot_claims_and_authorization(system):
    own = captured(system, (60,))
    captured(system, (95,), device="foreign_sensor")
    cases(system, "?view=activity", user="owner", expected=403)
    assert system.db.scalar("SELECT count(*) FROM risk_activity_snapshots") == 0
    pending = cases(system, "?view=activity")
    assert pending["groups"] is None
    with ThreadPoolExecutor(2) as pool:
        assert sum(pool.map(lambda _: risk_activity.refresh_one(system.db, system.tenant["id"]), range(2))) == 1
    system.db.execute("UPDATE risk_activity_snapshots SET last_requested_at=now()-interval '2 minutes'")
    last_read = system.db.scalar("SELECT last_requested_at FROM risk_activity_snapshots")
    with system.db.transaction() as locked:
        locked.execute("SELECT 1 FROM risk_activity_snapshots FOR UPDATE")
        assert not risk_activity.refresh_one(system.db, system.tenant["id"])
        data = cases(system, "?view=activity")
        assert data["groups"]["sessions"]["total"] == 1
        assert data["groups"]["sessions"]["items"][0]["session_id"] == own.id
        assert system.db.scalar("SELECT last_requested_at FROM risk_activity_snapshots") == last_read
    cases(system, "?view=activity")
    assert system.db.scalar("SELECT last_requested_at FROM risk_activity_snapshots") > last_read
    assert cases(system, "?view=activity", user="foreign")["groups"] is None
    refresh_activity(system, user="foreign")
    assert cases(system, "?view=activity", user="foreign")["groups"]["sessions"]["items"][0]["peak"] == 95


def test_activity_snapshots_expire_and_renew_with_tenant_scoped_cleanup(system):
    captured(system, (60,))
    captured(system, (95,), device="foreign_sensor")
    refresh_activity(system)
    refresh_activity(system, user="foreign")
    system.db.execute("""UPDATE risk_activity_snapshots SET last_requested_at=now()-interval '31 minutes',
        refresh_after=now()-interval '1 minute',until=now()-interval '31 minutes'""")
    # Unread snapshots stay idle, even when their refresh is due.
    assert not risk_activity.refresh_one(system.db)
    stale = cases(system, "?view=activity")
    assert stale["activity_snapshot"]["state"] == "stale"
    assert stale["groups"]["sessions"]["items"][0]["peak"] == 60
    assert risk_activity.refresh_one(system.db)
    renewed = cases(system, "?view=activity")
    assert renewed["activity_snapshot"]["state"] == "current" and renewed["groups"] == stale["groups"]
    assert not risk_activity.refresh_one(system.db)
    system.db.execute("UPDATE risk_activity_snapshots SET last_requested_at=now()-interval '25 hours'")
    assert risk_activity.refresh_one(system.db, system.tenant["id"])
    assert not risk_activity.refresh_one(system.db, system.tenant["id"])
    assert system.db.scalar("SELECT count(*) FROM risk_activity_rows WHERE tenant_id=$1", system.tenant["id"]) == 0
    assert system.db.scalar("SELECT count(*) FROM risk_activity_snapshots") == 1
    assert system.db.scalar("SELECT count(*) FROM risk_activity_rows WHERE tenant_id=$1", system.users["foreign"]["tenant_id"]) > 0
    # Returning before cleanup renews the retained result, rather than deleting it.
    foreign = cases(system, "?view=activity", user="foreign")
    assert foreign["groups"]["sessions"]["items"][0]["peak"] == 95
    assert risk_activity.refresh_one(system.db, system.users["foreign"]["tenant_id"])
    # Returning after cleanup starts preparation again, never a false empty result.
    assert cases(system, "?view=activity")["groups"] is None
    refresh_activity(system)
    assert cases(system, "?view=activity")["groups"]["sessions"]["items"][0]["peak"] == 60


def test_activity_snapshot_capacity_is_atomic_and_reuses_idle_slots(system):
    captured(system, (60,))
    zones = ["UTC"] + [f"Etc/GMT{offset:+d}" for offset in range(-12, 13) if offset]
    for zone in zones[:risk_activity.MAX_SNAPSHOTS - 1]:
        assert cases(system, f"?view=activity&time_zone={zone.replace('+', '%2B')}")["groups"] is None
    with ThreadPoolExecutor(8) as pool:
        statuses = list(pool.map(lambda zone: browser(system, "GET",
            f"risk-cases?view=activity&time_zone={zone.replace('+', '%2B')}").status_code,
            zones[risk_activity.MAX_SNAPSHOTS - 1:]))
    assert set(statuses) <= {200, 429} and 200 in statuses
    stored = {row["time_zone"] for row in system.db.many("SELECT time_zone FROM risk_activity_snapshots WHERE tenant_id=$1",
                                                       system.tenant["id"])}
    assert len(stored) == risk_activity.MAX_SNAPSHOTS
    overflow = next(zone for zone in zones if zone not in stored)
    query = f"?view=activity&time_zone={overflow.replace('+', '%2B')}"
    with system.db.transaction() as claimed:
        system.db.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                          f"risk-activity:{system.tenant['id']}", conn=claimed)
        assert "busy" in cases(system, query, expected=429)["error"]["message"]
        assert cases(system, "?view=activity")["groups"] is None
    assert "16 time zones" in cases(system, query, expected=429)["error"]["message"]
    # A full tenant does not consume another tenant's slots or block saved reads.
    assert cases(system, query, user="foreign")["groups"] is None
    assert cases(system, "?view=activity")["groups"] is None
    refresh_activity(system)
    assert cases(system, "?view=activity")["groups"]["sessions"]["items"][0]["peak"] == 60
    system.db.execute("""UPDATE risk_activity_snapshots SET last_requested_at=now()-interval '31 minutes'
        WHERE tenant_id=$1 AND time_zone='UTC'""", system.tenant["id"])
    assert cases(system, query)["groups"] is None
    assert system.db.scalar("SELECT count(*) FROM risk_activity_snapshots WHERE tenant_id=$1", system.tenant["id"]) == risk_activity.MAX_SNAPSHOTS
    assert system.db.scalar("SELECT count(*) FROM risk_activity_rows WHERE tenant_id=$1 AND time_zone='UTC'", system.tenant["id"]) == 0
    assert not system.db.scalar("SELECT EXISTS(SELECT 1 FROM risk_activity_snapshots WHERE tenant_id=$1 AND time_zone='UTC')", system.tenant["id"])
    assert system.db.scalar("SELECT count(*) FROM risk_activity_snapshots WHERE tenant_id=$1", system.users["foreign"]["tenant_id"]) == 1


def test_os_user_migration_preserves_historical_groups_verdicts_and_report_links(system):
    migrations = Path(__file__).parents[1] / "src/openaidr/server/migrations"
    original = (migrations / "0099_risk_cases.sql").read_text()
    original_function = original[original.index("CREATE FUNCTION attach_risk_cases"):original.index("CREATE FUNCTION attach_new_risk_cases")]
    system.db.execute(original_function.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1))
    configure(system)
    investigate(system, account="shared@example.test")
    investigate(system, account="shared@example.test", device="peer_sensor")
    old = cases(system)
    historical = old["groups"]["users"]["items"][0]
    assert historical["identity_kind"] == "account" and historical["device_count"] == 2
    closed = verdict(system, historical, "fp")["case"]
    # Retain an open account group too; new investigations must not join it.
    investigate(system, account="shared@example.test")
    mixed = captured(system)
    system.db.execute("UPDATE events SET body=body #- '{agent,account}' WHERE id=$1", mixed.events[0]["id"])
    finalize(system, mixed)
    session_case = system.db.one("""SELECT c.* FROM risk_cases c JOIN risk_case_jobs cj ON cj.case_id=c.id
        JOIN session_investigation_jobs j ON j.id=cj.job_id WHERE c.kind='sessions' AND j.session_id=$1""", mixed.id)
    assert session_case["identity_kind"] == "mixed"
    verdict(system, session_case, "tp")
    before = system.db.many("SELECT id,kind,subject_key,outcome,opened_at,closed_at FROM risk_cases ORDER BY id")
    links = system.db.many("SELECT * FROM risk_case_jobs ORDER BY case_id,job_id")
    system.db.execute("ALTER TABLE risk_cases DROP COLUMN accounts")
    system.db.execute("DELETE FROM schema_migrations WHERE version=123")
    system.db.migrate()
    assert system.db.many("SELECT id,kind,subject_key,outcome,opened_at,closed_at FROM risk_cases ORDER BY id") == before
    assert system.db.many("SELECT * FROM risk_case_jobs ORDER BY case_id,job_id") == links
    corrected = browser(system, "GET", "risk-cases/" + str(session_case["id"])).json()["case"]
    assert (corrected["identity_kind"], corrected["reported_user"], corrected["outcome"]) == ("os_user", "reported-user", "tp")
    assert corrected["accounts"] == ["peer@example.test"]
    unchanged = browser(system, "GET", "risk-cases/" + closed["id"]).json()["case"]
    assert (unchanged["identity_kind"], unchanged["reported_user"], unchanged["outcome"], unchanged["device_count"]) == (
        "account", "shared@example.test", "fp", 2,
    )
    assert unchanged["accounts"] == ["shared@example.test"]
    verdict(system, closed, "review", expected=409)
    for device in ("sensor", "peer_sensor"):
        investigate(system, account="shared@example.test", device=device)
    current = cases(system)["groups"]["users"]["items"]
    device_users = [row for row in current if row["identity_kind"] == "os_user"]
    assert len(device_users) == 2 and len({row["id"] for row in device_users}) == 2
    assert all(row["session_count"] == row["device_count"] == 1 for row in device_users)
    assert all(row["reported_user"] == "reported-user" and row["accounts"] == ["shared@example.test"] for row in device_users)
    assert system.db.many("SELECT * FROM risk_case_jobs WHERE case_id=ANY($1) ORDER BY case_id,job_id",
                          [row["id"] for row in before]) == links
