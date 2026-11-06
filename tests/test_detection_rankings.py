"""Score rankings through the tenant API and real PostgreSQL."""

from urllib.parse import urlencode

import pytest
from psycopg.types.json import Jsonb

from openaidr.server import detection_history, ordinary_session_detection as ordinary
from test_inline_guardrail import browser, system as system
from test_ordinary_session_detection import captured, configure
from test_session_aggregation import action, close_session, deliver, finalized, registered
from test_store import db as db


def rankings(system, *, user="admin", expected=200, **query):
    reply = browser(system, "GET", "detections/rankings?" + urlencode(query), user=user)
    assert reply.status_code == expected, reply.text
    if expected == 200:
        assert reply.headers["cache-control"] == "no-store"
    return reply.json()


def test_session_rankings_sort_peak_before_threshold_status_and_count_all_pages(system):
    configure(system, enabled=False, selection_policy="risk_budget", session_high_risk_actions=4)
    values = [captured(system, scores) for scores in (
        (70, 70, 70, 70), (95,), (70, 70, 70), (85,), (84,), (0,), (None,), (99,),
    )]
    for value in values:
        ordinary.finalize(system.db, system.tenant["id"], value.id)
    system.db.execute("INSERT INTO ordinary_session_input_dirty(tenant_id,session_id) VALUES($1,$2)", system.tenant["id"], values[-1].id)
    # The scheduler uses recent activity, even when the session started earlier.
    system.db.execute("UPDATE agent_sessions SET started_at=now()-interval '60 days' WHERE id=$1", values[1].id)
    old = captured(system, (100,))
    system.db.execute("UPDATE agent_sessions SET last_event_at=now()-interval '8 days' WHERE id=$1", old.id)
    foreign = captured(system, (100,), device="foreign_sensor")
    before = {table: system.db.scalar(f"SELECT count(*) FROM {table}") for table in (
        "session_snapshots", "session_investigation_jobs", "ordinary_session_input_dirty", "model_usage",
    )}
    result = rankings(system, limit=1)
    assert result["summary"] == {"total": 8, "meets": 2, "below": 4, "unknown": 2}
    assert result["criteria"]["session_high_risk_actions"] == 4
    assert result["items"][0]["id"] == values[1].id and result["items"][0]["peak"] == 95
    rows, cursor = result["items"], result["next_cursor"]
    while cursor:
        part = rankings(system, limit=2, cursor=cursor)
        assert part["summary"] == result["summary"]
        rows += part["items"]
        cursor = part["next_cursor"]
    assert [row["peak"] for row in rows] == [95, 85, 84, 70, 70, 0, None, None]
    assert [row["rank"] for row in rows] == list(range(1, 9))
    assert rows[1]["band"] == "below" and rows[3]["band"] == "meets"
    assert all(row["high_actions"] is None for row in rows[-2:])
    coverage = {row["id"]: row["score_coverage"] for row in rows}
    assert coverage[values[6].id] == {"status": "not_assessed", "assessed": 0, "targets": 1, "pending": 0}
    assert coverage[values[-1].id] == {"status": "updating", "assessed": None, "targets": None, "pending": None}
    filtered = rankings(system, band="meets")
    assert filtered["summary"] == result["summary"]
    assert [row["rank"] for row in filtered["items"]] == [1, 4]
    assert rankings(system, user="foreign")["items"][0]["id"] == foreign.id
    for query in ({"group": "invalid"}, {"band": "near"}, {"limit": 101},
                  {"cursor": result["next_cursor"], "group": "users"}):
        rankings(system, expected=400, **query)
    rankings(system, cursor=result["next_cursor"], user="foreign", expected=400)
    assert system.client.get("/api/v1/detections/rankings").status_code == 401
    assert before == {table: system.db.scalar(f"SELECT count(*) FROM {table}") for table in before}
    configure(system, enabled=False, selection_policy="risk_budget", action_risk_threshold=71)
    changed = rankings(system)
    assert changed["summary"]["unknown"] == 8
    assert all(row["score_coverage"]["status"] == "updating" for row in changed["items"])
    rankings(system, cursor=result["next_cursor"], expected=400)


def test_user_rankings_use_verified_owners_max_score_and_two_session_pattern(system):
    configure(system, enabled=False, selection_policy="risk_budget")
    first, second, single, unverified = [captured(system, scores) for scores in (
        (80, 70), (75,), (99, 90, 85), (100,),
    )]
    for value, user in ((first, "owner"), (second, "owner"), (single, "admin")):
        detection_history.save_owner(system.db, system.tenant["id"], value.id, system.users[user]["id"], system.users["admin"])
    for value in (first, second, single, unverified):
        ordinary.finalize(system.db, system.tenant["id"], value.id)
    result = rankings(system, group="users")
    assert result["summary"] == {"total": 2, "meets": 1, "below": 1, "unknown": 0}
    assert [(row["peak"], row["high_actions"], row["high_risk_sessions"], row["band"]) for row in result["items"]] == [
        (99, 3, 1, "below"), (80, 3, 2, "meets"),
    ]
    assert result["items"][0]["user_id"] == system.users["admin"]["id"]
    assert result["items"][1]["session_count"] == 2
    assert rankings(system, group="users", user="foreign")["summary"]["total"] == 0
    system.db.execute("INSERT INTO ordinary_session_input_dirty(tenant_id,session_id) VALUES($1,$2)", system.tenant["id"], second.id)
    pending = rankings(system, group="users")["items"][1]
    assert pending["band"] == "unknown" and pending["peak"] is None and pending["high_actions"] is None
    assert pending["score_coverage"] == {"status": "updating", "assessed": None, "targets": None, "pending": None}
    ordinary.finalize(system.db, system.tenant["id"], second.id)
    unscored = captured(system, (None,))
    detection_history.save_owner(system.db, system.tenant["id"], unscored.id, system.users["owner"]["id"], system.users["admin"])
    ordinary.finalize(system.db, system.tenant["id"], unscored.id)
    partial = rankings(system, group="users")["items"][1]
    assert partial["band"] == "unknown" and partial["peak"] is None
    assert partial["score_coverage"] == {"status": "partial", "assessed": 3, "targets": 4, "pending": 0}
    system.db.execute("UPDATE tenant_users SET status='disabled' WHERE id=$1", system.users["owner"]["id"])
    assert rankings(system, group="users", user="admin")["summary"]["total"] == 1
    rankings(system, user="owner", expected=403)
    system.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", first.sensor["id"])
    assert rankings(system, group="users", user="admin")["summary"]["total"] == 0
    assert rankings(system, user="admin")["summary"]["total"] == 0


def test_rankings_exclude_unverified_managed_sessions_and_explain_legacy_policy(system):
    configure(system, enabled=False, selection_policy="risk_budget")
    for verified in (True, False):
        registration = registered(system, verified=verified)
        if verified:
            _, _, records, _ = action(system, registration, 95)
            deliver(system, registration, records)
            close_session(system, registration, len(records))
            finalized(system, registration)
    result = rankings(system)
    assert result["summary"]["total"] == 1
    assert result["items"][0]["peak"] == 95 and result["items"][0]["band"] == "meets"
    assert result["items"][0]["score_coverage"] == {"status": "complete", "assessed": 1, "targets": 1, "pending": 0}
    configure(system, selection_policy="legacy")
    legacy = rankings(system)
    assert legacy["selection_policy"] == "legacy" and legacy["summary"] is None and legacy["items"] == []


@pytest.mark.parametrize(("scores", "pending", "status", "assessed"), [
    ((None, None), False, "not_assessed", 0),
    ((None, 0), True, "pending", 1),
    ((None, 0), False, "partial", 1),
    ((0, 90), False, "complete", 2),
])
def test_rankings_report_stored_score_coverage_without_model_calls(system, scores, pending, status, assessed):
    configure(system, enabled=False, selection_policy="risk_budget")
    for _ in range(2):
        value = captured(system, scores)
        if pending:
            system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", value.events[0]["id"], Jsonb({"status": "pending"}))
        detection_history.save_owner(system.db, system.tenant["id"], value.id, system.users["owner"]["id"], system.users["admin"])
        ordinary.finalize(system.db, system.tenant["id"], value.id)
    for group, multiplier in (("sessions", 1), ("users", 2)):
        rows = rankings(system, group=group)["items"]
        assert len(rows) == 2 // multiplier
        assert all(row["score_coverage"] == {
            "status": status, "assessed": assessed * multiplier,
            "targets": 2 * multiplier, "pending": int(pending) * multiplier,
        } for row in rows)
    assert system.db.scalar("SELECT count(*) FROM model_usage") == 0
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0
