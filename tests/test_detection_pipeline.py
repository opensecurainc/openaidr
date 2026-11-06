"""Pipeline counts through the authenticated API and real PostgreSQL."""

from datetime import timedelta

from psycopg.types.json import Jsonb

from test_inline_guardrail import browser, check, system as system
from test_session_aggregation import (
    action, close_session, completed_session, deliver, detection_settings,
    finalized, registered,
)
from test_store import db as db, new_id, now

METADATA = {"range", "since", "until", "selection_policy", "investigation_percent", "sample_percent", "history_days", "availability", "criteria"}


def pipeline(system, query="", user="admin"):
    reply = browser(system, "GET", "detections/pipeline" + query, user=user)
    assert reply.status_code == 200, reply.text
    assert reply.headers["cache-control"] == "no-store"
    return reply.json()


def test_pipeline_tracks_unique_actions_sessions_and_published_alerts(system):
    settings = detection_settings(system, risk_threshold="0", action_risk_threshold=65, urgent_risk_threshold=93)
    registration = registered(system)
    value, _, records, _ = action(system, registration, 90)
    check(system, {**value, "request_id": new_id()})
    _, _, more, _ = action(system, registration, 0, sequence=3)
    deliver(system, registration, records + more)
    close_session(system, registration, 4)
    snapshot = finalized(system, registration, enabled=True, ready=True)
    job_id = snapshot["routing"]["job_id"]

    below = completed_session(system, score=0)
    finalized(system, below, enabled=True, ready=True)
    initial = pipeline(system)
    assert initial["range"] == "30d"
    assert (initial["actions_scored"], initial["sessions_scored"]) == (3, 2)
    assert (initial["sessions_eligible"], initial["sessions_escalated"]) == (2, 1)
    assert (initial["sessions_inspected"], initial["sessions_with_alerts"], initial["alerts"]) == (0, 0, 0)
    assert (initial["reports"], initial["pending_investigations"], initial["sessions_selected"]) == (0, 1, 1)
    assert initial["selection_policy"] == "legacy"
    assert initial["criteria"] == {key: settings[key] for key in initial["criteria"]}
    assert initial["criteria"]["action_risk_threshold"] == 65
    assert initial["criteria"]["urgent_risk_threshold"] == 93

    # Multiple completed jobs/configurations and multiple findings still count
    # as one inspected session and one session with alerts.
    system.db.execute(
        "UPDATE session_investigation_jobs SET state='completed',completed_at=now() WHERE id=$1",
        job_id,
    )
    detection_settings(system, risk_threshold="0", max_runtime_seconds=6)
    revised = finalized(system, registration, enabled=True, ready=True)
    other_job = revised["routing"]["job_id"]
    assert other_job != job_id
    system.db.execute(
        "UPDATE session_investigation_jobs SET state='completed',completed_at=now() WHERE id=$1",
        other_job,
    )
    session_id = system.db.scalar("SELECT id FROM agent_sessions WHERE registration_id=$1", registration["id"])
    for index, status in enumerate(("open", "resolved", "false_positive")):
        system.db.execute(
            """INSERT INTO findings(id,tenant_id,rule_id,category,severity,title,status,
                   session_id,sensor_id,primary_event_id,first_event_at,investigation_job_id,
                   investigation_attempt_id,snapshot_id,finding_index,investigation_evidence)
               VALUES($1,$2,'codex-session-detection','secret_exfiltration','high','Fixture',$3,
                      $4,$5,$6,now(),$7,$8,$9,$10,'{}'::jsonb)""",
            new_id(), system.tenant["id"], status, session_id, system.sensors["sensor"][0]["id"],
            new_id(), job_id, new_id(), snapshot["snapshot_id"], index,
        )
    # Ordinary rule findings do not belong to the model pipeline.
    system.db.execute(
        """INSERT INTO findings(id,tenant_id,rule_id,category,severity,title,session_id,
               sensor_id,primary_event_id,first_event_at)
           VALUES($1,$2,'destructive-command','destructive_command','high','Rule fixture',$3,$4,$5,now())""",
        new_id(), system.tenant["id"], session_id, system.sensors["sensor"][0]["id"], new_id(),
    )
    result = pipeline(system)
    assert (result["actions_scored"], result["sessions_scored"]) == (3, 2)
    assert (result["sessions_inspected"], result["sessions_with_alerts"], result["alerts"]) == (1, 1, 3)
    assert (result["reports"], result["inconclusive_reports"], result["sessions_selected"]) == (2, 2, 1)
    assert result["actionable_reports"] == result["no_finding_reports"] == result["pending_investigations"] == 0
    assert len(browser(system, "GET", "findings").json()["items"]) == 4
    assert len(browser(system, "GET", "findings?source=policy").json()["items"]) == 1
    first = browser(system, "GET", "findings?source=incident&limit=1").json()
    incidents = first["items"]
    cursor = first["next_cursor"]
    while cursor:
        next_page = browser(system, "GET", f"findings?source=incident&limit=1&cursor={cursor}").json()
        incidents += next_page["items"]
        cursor = next_page["next_cursor"]
    assert len({finding["id"] for finding in incidents}) == 3
    assert all(finding["investigation_job_id"] == job_id for finding in incidents)
    assert len(browser(system, "GET", "findings?source=incident&status=open&severity=high").json()["items"]) == 1
    assert browser(system, "GET", "findings?source=incident", user="foreign").json()["items"] == []
    assert browser(system, "GET", "findings?source=policy", user="foreign").json()["items"] == []
    assert browser(system, "GET", "findings?source=invalid").status_code == 400
    assert system.client.get("/api/v1/findings?source=incident").status_code == 401
    assert (result["sessions_eligible"], result["sessions_escalated"]) == (2, 1)
    foreign = pipeline(system, user="foreign")
    assert foreign["criteria"]["action_risk_threshold"] == 70
    assert foreign["criteria"]["idle_seconds"] == 60
    assert all(foreign[key] == 0 for key in result if key not in METADATA)
    assert system.client.get("/api/v1/detections/pipeline").status_code == 401
    assert browser(system, "GET", "detections/pipeline?range=24h").status_code == 400
    system.db.execute(
        "UPDATE agent_sessions SET started_at=now()-interval '31 days' WHERE tenant_id=$1",
        system.tenant["id"],
    )
    short = pipeline(system)
    long = pipeline(system, "?range=90d")
    for key in result:
        if key not in METADATA:
            assert short[key] == 0
            assert long[key] == result[key]


def test_pipeline_ranges_follow_session_start_and_exclude_unmeasured_scores(system):
    detection_settings(system)
    for age in (6, 8, 29, 31, 89, 91, -1):
        registration = registered(system)
        action(system, registration, 0, finish=False)
        system.db.execute(
            "UPDATE agent_sessions SET started_at=$2 WHERE registration_id=$1",
            registration["id"], now() - timedelta(days=age),
        )
    broken = registered(system)
    for score in (None, "90", -1, 101):
        _, result, _, _ = action(system, broken, 0, finish=False)
        system.db.execute(
            "UPDATE inline_guardrail_events SET assessment=$2 WHERE event_id=$1",
            result["event_id"], Jsonb({"score": score}),
        )
    system.provider.status = 503
    action(system, broken, 0, finish=False)
    for days, count in ((7, 1), (30, 3), (90, 5)):
        result = pipeline(system, f"?range={days}d")
        assert (result["actions_scored"], result["sessions_scored"]) == (count, count)
        assert result["sessions_inspected"] == result["sessions_eligible"] == 0


def test_pipeline_keeps_gap_escalations_and_inconclusive_work_out_of_rate(system):
    detection_settings(system, risk_threshold="0", gap_policy="investigate")
    registration = registered(system)
    _, _, records, _ = action(system, registration, 90, gaps=["capture_disabled"])
    deliver(system, registration, records)
    close_session(system, registration, len(records))
    snapshot = finalized(system, registration, enabled=True, ready=True)
    assert snapshot["routing"]["reason"] == "persistent_gap"
    job = snapshot["routing"]["job_id"]
    for state in ("queued", "running", "inconclusive"):
        system.db.execute(
            "UPDATE session_investigation_jobs SET state=$2,completed_at=now() WHERE id=$1",
            job, state,
        )
        result = pipeline(system)
        assert result["sessions_inspected"] == result["sessions_escalated"] == result["sessions_eligible"] == 0
    system.db.execute("UPDATE session_investigation_jobs SET state='completed' WHERE id=$1", job)
    assert pipeline(system)["sessions_inspected"] == 1
