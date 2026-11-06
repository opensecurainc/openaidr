
from openaidr_api.providers import guardrail as provider_scoring
from datetime import timedelta
from decimal import Decimal
from unittest.mock import Mock

import httpx
import pytest

from test_store import db, sensor, tenant
from test_risk import reply
from openaidr.server.model import public
from openaidr_api.providers.guardrail import JevClient, parse_assessment
from openaidr.server.guardrail.scoring import KINDS, JevError, RiskWorker
from openaidr.server.store import now, new_id


def event(kind="command", session="risk-session", at=None, **body):
    return {
        "id": new_id(),
        "time": (at or now()).isoformat(),
        "kind": kind,
        "agent": {"product": "claude-code"},
        "session": {"id": session},
        "command": {"text": "git status"},
        **body,
    }


def test_model_usage_records_each_provider_attempt_including_invalid_answers(db):
    from openaidr.server.guardrail.analytics import active
    from openaidr.server.model_costs import overview

    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    responses = [
        httpx.Response(200, json={**reply("none", 0), "usage": {"input_tokens": 2000, "output_tokens": 20}}),
        httpx.Response(429),
        httpx.Response(200, json={**reply("none", 0), "usage": {"input_tokens": 1000, "output_tokens": 10}}),
        httpx.Response(200, json={**reply(score=-1), "usage": {"input_tokens": 500, "output_tokens": 5}}),
        httpx.Response(200, json={**reply(), "usage": {"input_tokens": "bad", "output_tokens": 2}}),
        httpx.Response(200, json={**reply(), "model": "jev-unknown", "usage": {"input_tokens": 300, "output_tokens": 3}}),
        httpx.Response(200, json={**reply(), "model": "other-model", "usage": {"input_tokens": 300, "output_tokens": 3}}),
    ]
    provider = JevClient("test-key", httpx.MockTransport(lambda request: responses.pop(0)))
    worker = RiskWorker(db, provider, t["id"])
    try:
        for index in range(6):
            e = event()
            db.ingest_batch(s, [e])
            assert worker.tick()
            if index == 1:
                db.execute("UPDATE events SET risk_next_attempt_at=now()-interval '1 second' WHERE id=$1", e["id"])
                db.execute("UPDATE risk_provider_backoff SET retry_at=now()-interval '1 second'")
                worker.retry_at = 0
                assert worker.tick()
        assert not responses and not worker.tick()
    finally:
        provider.close()
    costs = overview(db, t["id"])["summary"]
    assert costs == {
        "calls": 7, "usage_calls": 5, "priced_calls": 3, "unpriced_calls": 4,
        "pending_calls": 0, "failed_calls": 3,
        "input_tokens": 4100, "output_tokens": 41, "tokens": 4141,
        "cost_usd": pytest.approx(0.000147),
    }
    assert db.scalar("SELECT count(*) FROM model_usage WHERE status='error' AND cost_usd IS NOT NULL") == 1
    assert db.scalar("SELECT count(*) FROM events WHERE risk ? 'usage'") == 0
    jev = active(db, t["id"])["jev"]
    assert (jev["calls"], jev["failed_calls"], jev["latency_samples"]) == (7, 3, 7)
    assert jev["priced_calls"] == 3 and float(jev["cost_usd"]) == pytest.approx(0.000147)
    assert db.scalar("SELECT count(*) FROM model_usage WHERE model='jev-1.13.0'") == 7


def test_model_usage_survives_stale_completions_and_keeps_original_prices(db, monkeypatch):
    from openaidr.server import model_costs

    t, foreign = tenant(db), tenant(db)
    s, _, _ = sensor(db, t["id"])
    e = event()
    db.ingest_batch(s, [e])
    first = db.claim_risk_event(t["id"])
    call = db.start_model_call(first, "jev-1.13.0")
    assert db.start_model_call(first, "jev-1.13.0") is None
    usage = {"model": "jev-1.13.0", "input_tokens": 2000, "output_tokens": 20}
    assert db.finish_model_call(foreign["id"], call, usage) == 0
    db.execute("UPDATE events SET risk_next_attempt_at=now()-interval '1 second' WHERE id=$1", e["id"])
    second = db.claim_risk_event(t["id"])
    next_call = db.start_model_call(second, "jev-1.13.0")
    assert db.finish_model_call(t["id"], next_call, usage) == 1
    assert db.finish_risk_event(second, parse_assessment(reply("none", 0))) == 1
    monkeypatch.setitem(model_costs.RATES, ("typesafe", "jev-1.13.0"), (Decimal("10"), Decimal("50")))
    assert db.finish_model_call(t["id"], call, usage) == 1
    assert db.finish_risk_event(first, parse_assessment(reply())) == 0
    assert db.finish_model_call(t["id"], call, {**usage, "input_tokens": 999999}) == 0
    assert db.scalar("SELECT sum(cost_usd) FROM model_usage") == Decimal("0.000168")
    assert db.scalar("SELECT count(*) FROM model_usage WHERE input_rate_usd=0.042") == 2
    db.execute("DELETE FROM events WHERE id=$1", e["id"])
    assert model_costs.overview(db, t["id"])["summary"]["calls"] == 2


def test_risk_queue_persistence_isolation_and_sensor_spoofing(db):
    a, b = tenant(db), tenant(db)
    sa, _, _ = sensor(db, a["id"])
    sb, _, _ = sensor(db, b["id"])
    ea, eb = event(risk={"status": "scored", "score": 0}), event()
    db.ingest_batch(sa, [ea])
    db.ingest_batch(sb, [eb])
    assert public(db.get_event(a["id"], ea["id"]))["risk"] is None
    first = db.claim_risk_event(a["id"])
    assert first["id"] == ea["id"] and first["risk_attempts"] == 1
    assert db.claim_risk_event(a["id"]) is None
    assessment = parse_assessment(reply())
    assert db.finish_risk_event(first, assessment) == 1
    assert public(db.get_event(a["id"], ea["id"]))["risk"] == assessment
    assert db.event_risks(a["id"], [ea["id"], eb["id"]]) == [
        {"id": ea["id"], "risk": assessment}
    ]
    assert db.ingest_batch(sa, [ea])["duplicates"] == 1
    assert db.claim_risk_event(a["id"]) is None
    assert db.claim_risk_event(b["id"])["id"] == eb["id"]


def test_risk_indexes_bound_arrivals_leases_and_current_usage(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    queued = [event(kind) for kind in KINDS]
    excluded = [event(kind) for kind in ("session.start", "session.end", "hook.decision", "sensor")]
    retry, pending, terminal, completed, exhausted, auth = [event() for _ in range(6)]
    db.ingest_batch(s, queued + excluded + [retry, pending, terminal, completed, exhausted, auth])
    db.execute("UPDATE events SET received_at=now()-interval '25 hours' WHERE id=$1", queued[0]["id"])
    for row, status, deadline, attempts, reason in (
        (retry, "error", "1 hour", 1, "connection_failed"),
        (pending, "pending", "1 minute", 1, None),
        (terminal, "error", None, 1, "provider_rejected"),
        (completed, "scored", None, 1, None),
        (exhausted, "error", "1 hour", 3, "connection_failed"),
        (auth, "error", "1 hour", 3, "authentication_failed"),
    ):
        db.execute(
            """UPDATE events SET risk=jsonb_build_object('status',$2::text,'reason',$5::text),
               risk_attempts=$4,risk_retry_attempts=$4,
               risk_next_attempt_at=CASE WHEN $3::text IS NULL THEN 'infinity'::timestamptz
                   ELSE now()+$3::interval END WHERE id=$1""",
            row["id"], status, deadline, attempts, reason,
        )
    predicate = db.scalar(
        "SELECT pg_get_expr(indpred,indrelid) FROM pg_index WHERE indexrelid='events_risk_leases_idx'::regclass"
    )
    indexed = db.many("SELECT id FROM events WHERE " + predicate)
    assert {row["id"] for row in indexed} == {pending["id"]}
    assert db.scalar("SELECT to_regclass('events_risk_pending_idx')") is None
    with db.transaction() as conn:
        conn.execute("SET LOCAL enable_seqscan=off")
        plan = db.many(
            """EXPLAIN SELECT id FROM events WHERE risk->>'status'='pending'
               AND risk_next_attempt_at<=now()
               AND (risk_retry_attempts>=3 OR received_at<now()-interval '24 hours')""",
            conn=conn,
        )
        arrivals = db.many(
            """EXPLAIN SELECT e.id FROM events e JOIN tenants t ON t.id=e.tenant_id
               WHERE t.status='active' AND e.received_at>=now()-interval '24 hours'
               AND NOT e.risk_body_omitted
               AND e.kind=ANY($1) AND e.risk_retry_attempts<3
               AND e.risk_next_attempt_at<=now()
               AND (e.risk IS NULL OR e.risk->>'status' IN ('pending','error'))""",
            list(KINDS), conn=conn,
        )
        usage = db.many(
            """EXPLAIN SELECT tenant_id,sum(attempts) FROM risk_assessment_usage
               WHERE window_start=$1 GROUP BY tenant_id""",
            now().replace(minute=0, second=0, microsecond=0), conn=conn,
        )
    assert any("Index Cond:" in row["QUERY PLAN"] and "risk_next_attempt_at" in row["QUERY PLAN"] for row in plan)
    arrival_indexes = db.many("SELECT relid::regclass::text AS name FROM pg_partition_tree('events_received_idx') WHERE isleaf")
    assert any(index["name"] in row["QUERY PLAN"] for index in arrival_indexes for row in arrivals)
    assert any("Index Cond:" in row["QUERY PLAN"] and "received_at" in row["QUERY PLAN"] for row in arrivals)
    assert any("risk_assessment_usage_window_idx" in row["QUERY PLAN"] for row in usage)
    assert any("Index Cond:" in row["QUERY PLAN"] and "window_start" in row["QUERY PLAN"] for row in usage)


@pytest.mark.parametrize("plan_mode", ["force_custom_plan", "force_generic_plan"])
def test_risk_claim_skips_ineligible_history(db, monkeypatch, plan_mode):
    from psycopg import sql

    # Exercise the upgrade over retained rows, then inheritance by a new tenant.
    db.execute("DROP INDEX IF EXISTS events_risk_candidates_idx")
    db.execute("DELETE FROM schema_migrations WHERE version=75")
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    db.execute("""INSERT INTO events
        (id,tenant_id,sensor_id,time,received_at,kind,product,body,risk,
         risk_retry_attempts,risk_next_attempt_at)
        SELECT md5('risk-history:'||n)::uuid,$1,$2,now(),
               now()-CASE WHEN n%8=7 THEN interval '25 hours' ELSE interval '1 hour' END,
               CASE WHEN n%8=5 THEN 'sensor' ELSE 'command' END,'claude-code',
               CASE WHEN n%8=3 THEN '{"source":{"hook_request_id":"retained"}}'::jsonb ELSE '{}'::jsonb END,
               CASE WHEN n%8=0 THEN '{"status":"scored"}'::jsonb
                    WHEN n%8=4 THEN '{"status":"error","hook_check_id":"retained"}'::jsonb
                    WHEN n%8 IN (1,2,6) THEN '{"status":"error"}'::jsonb END,
               CASE WHEN n%8=1 THEN 3 ELSE 0 END,
               CASE WHEN n%8=2 THEN 'infinity'::timestamptz
                    WHEN n%8=6 THEN now()+interval '1 hour' ELSE '-infinity'::timestamptz END
        FROM generate_series(1,24000) n""", t["id"], s["id"])
    db.migrate()
    other = tenant(db)
    peer, _, _ = sensor(db, other["id"])
    fresh, retry, expired_lease, foreign = [event() for _ in range(4)]
    db.ingest_batch(s, [fresh, retry, expired_lease])
    db.ingest_batch(peer, [foreign])
    for row, status in ((retry, "error"), (expired_lease, "pending")):
        db.execute("""UPDATE events SET risk=jsonb_build_object('status',$2::text),
            risk_retry_attempts=1,risk_next_attempt_at=now()-interval '1 second' WHERE id=$1""",
                   row["id"], status)
    db.execute("ANALYZE events")
    many, plans = db.many, []

    def explain_claim(query, *args, **kwargs):
        if "UPDATE events SET risk=" in query and "risk_assessment_usage" in query:
            conn = kwargs["conn"]
            with conn.transaction(force_rollback=True):
                conn.execute(sql.SQL("SET LOCAL plan_cache_mode={}").format(sql.Literal(plan_mode)))
                conn.execute("PREPARE risk_claim AS " + query)
                try:
                    plans.append(conn.execute(sql.SQL(
                        "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) EXECUTE risk_claim({})"
                    ).format(sql.SQL(",").join(sql.Literal(arg) for arg in args))).fetchone()["QUERY PLAN"][0])
                finally:
                    conn.execute("DEALLOCATE risk_claim")
        return many(query, *args, **kwargs)

    monkeypatch.setattr(db, "many", explain_claim)
    claimed = [db.claim_risk_event(t["id"])]
    assert claimed[0]["tenant_id"] == t["id"]
    claimed.extend(db.claim_risk_event() for _ in range(3))
    assert {row["id"] for row in claimed} == {row["id"] for row in (fresh, retry, expired_lease, foreign)}
    assert db.claim_risk_event() is None
    for plan in plans:
        nodes = [plan["Plan"]]
        for node in nodes:
            nodes.extend(node.get("Plans", []))
        scans = [node for node in nodes if "Scan" in node["Node Type"]
                 and node.get("Relation Name", "").startswith("events_") and node["Actual Loops"]]
        assert scans, plan
        assert sum((node["Actual Rows"] + node.get("Rows Removed by Filter", 0))
                   * node["Actual Loops"] for node in scans) < 20, plan
        assert sum(node.get("Shared Hit Blocks", 0) + node.get("Shared Read Blocks", 0)
                   for node in scans) < 150, plan


def test_risk_database_timeouts_preserve_scope_and_cancel_stalled_work(db, monkeypatch, request):
    import time
    import psycopg
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    from openaidr.server.guardrail import storage as risk

    original_timeout = db.scalar("SHOW statement_timeout")
    monkeypatch.setattr(risk, "DB_STATEMENT_TIMEOUT_MS", 100)
    monkeypatch.setattr(risk, "DB_LOCK_TIMEOUT_MS", 50)
    bounded = risk.risk_store(db)
    request.addfinalizer(bounded.close)
    params = conninfo_to_dict(bounded.url)
    assert params["connect_timeout"] == "5" and params["keepalives"] == "1"
    assert params["tcp_user_timeout"] == "10000"
    assert bounded.scalar("SELECT current_schema()") == db.scalar("SELECT current_schema()")
    assert bounded.scalar("SHOW statement_timeout") == "100ms"
    assert bounded.scalar("SHOW lock_timeout") == "50ms"
    started = time.monotonic()
    with pytest.raises(psycopg.errors.QueryCanceled):
        bounded.scalar("SELECT pg_sleep(5)")
    assert time.monotonic() - started < 2
    lock = int(new_id().replace("-", "")[-12:], 16)
    with db.transaction() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (lock,))
        with pytest.raises(psycopg.errors.LockNotAvailable):
            bounded.scalar("SELECT pg_advisory_xact_lock($1)", lock)
    assert bounded.scalar("SELECT 1") == 1
    assert db.scalar("SHOW statement_timeout") == original_timeout
    environment_params = conninfo_to_dict(db.url)
    monkeypatch.setenv("PGOPTIONS", environment_params.pop("options"))
    environment_store = type(db)(make_conninfo(**environment_params))
    request.addfinalizer(environment_store.close)
    environment_bounded = risk.risk_store(environment_store)
    request.addfinalizer(environment_bounded.close)
    assert environment_bounded.scalar("SELECT current_schema()") == db.scalar("SELECT current_schema()")


@pytest.mark.parametrize("plan_mode", ["force_custom_plan", "force_generic_plan"])
def test_pending_hook_cleanup_uses_identifier_indexes(db, monkeypatch, plan_mode):
    from psycopg import sql
    from psycopg.types.json import Jsonb

    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    # Same-sensor history defeats an index lookup that only constrains the tenant.
    db.execute("""INSERT INTO ordinary_hook_checks
        (id,tenant_id,sensor_id,request_id,payload_sha256,product,hook_event,session_id,
         mode,settings_version,policy_version,status,failure_reason)
        SELECT md5('check:'||n)::uuid,$1,$2,md5('request:'||n)::uuid,'hash','claude-code',
               'PreToolUse','history','shadow',1,1,'unavailable','provider_unavailable'
        FROM generate_series(1,6000) n""", t["id"], s["id"])
    check = db.one("SELECT id,request_id FROM ordinary_hook_checks WHERE id=md5('check:6000')::uuid")
    captured = [event(source={"hook_request_id": check["request_id"]}), event(),
                event(source={"hook_request_id": new_id()})]
    db.ingest_batch(s, captured)
    db.execute("""INSERT INTO events(id,tenant_id,sensor_id,time,kind,product,body,risk)
        SELECT md5('retained:'||n)::uuid,$1,$2,now(),'command','claude-code','{}',
               '{"status":"scored"}' FROM generate_series(1,6000) n""", t["id"], s["id"])
    for row in captured:
        risk = {"status": "pending"}
        if row is captured[1]:
            risk["hook_check_id"] = check["id"]
        db.execute("UPDATE events SET risk=$2,received_at=now()-interval '3 seconds' WHERE id=$1",
                   row["id"], Jsonb(risk))
    db.execute("ANALYZE ordinary_hook_checks")
    db.execute("ANALYZE events")
    execute, plans = db.execute, []

    def explain_cleanup(query, *args, **kwargs):
        if "UPDATE events" in query and "FROM ordinary_hook_checks" in query:
            with db.transaction() as conn:
                with conn.transaction(force_rollback=True):
                    conn.execute(sql.SQL("SET LOCAL plan_cache_mode={}").format(sql.Literal(plan_mode)))
                    conn.execute("PREPARE hook_cleanup AS " + query)
                    try:
                        plan = conn.execute(sql.SQL("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) EXECUTE hook_cleanup({})").format(
                            sql.SQL(",").join(sql.Literal(arg) for arg in args),
                        )).fetchone()["QUERY PLAN"][0]
                        plans.append(plan)
                    finally:
                        conn.execute("DEALLOCATE hook_cleanup")
        return execute(query, *args, **kwargs)

    monkeypatch.setattr(db, "execute", explain_cleanup)
    db.expire_risk_events(t["id"] if plan_mode == "force_custom_plan" else None)
    assert len(plans) == 1
    nodes, pending = [], [plans[0]["Plan"]]
    while pending:
        node = pending.pop()
        nodes.append(node)
        pending.extend(node.get("Plans", []))
    scans = [node for node in nodes if node.get("Relation Name") == "ordinary_hook_checks"
             and node.get("Actual Loops", 0)]
    assert scans, plans
    assert sum((node.get("Rows Removed by Filter", 0) + node["Actual Rows"])
               * node["Actual Loops"] for node in scans) <= 3, plans
    assert sum(node.get("Shared Hit Blocks", 0) + node.get("Shared Read Blocks", 0)
               for node in scans) < 50, plans
    event_scans = [node for node in nodes if node.get("Relation Name", "").startswith("events_")
                   and node.get("Actual Loops", 0)]
    assert event_scans, plans
    assert all(node["Actual Rows"] + node.get("Rows Removed by Filter", 0) <= 3
               for node in event_scans), plans
    expected = {"status": "error", "reason": "provider_unavailable", "hook_check_id": check["id"]}
    for row in captured[:2]:
        assert db.get_event(t["id"], row["id"])["risk"] == expected
    assert db.get_event(t["id"], captured[2]["id"])["risk"] == {
        "status": "error", "reason": "backend_unavailable",
    }


def test_pending_hook_cleanup_batches_preserve_results_scope_and_locked_rows(db, request):
    from psycopg.types.json import Jsonb
    from openaidr.server.guardrail.scoring import risk_store

    t, other = tenant(db), tenant(db)
    s, _, _ = sensor(db, t["id"])
    peer, _, _ = sensor(db, t["id"])
    foreign, _, _ = sensor(db, other["id"])
    scored = parse_assessment(reply("none", 0))
    checks = []
    for owner, device, status in ((t, s, "evaluated"), (t, s, "pending"),
                                  (t, s, "unavailable"), (t, peer, "evaluated"),
                                  (other, foreign, "evaluated")):
        checks.append(db.one("""INSERT INTO ordinary_hook_checks
            (id,tenant_id,sensor_id,request_id,payload_sha256,product,hook_event,session_id,
             mode,settings_version,policy_version,status,assessment,evaluated_decision,
             returned_decision,failure_reason)
            VALUES($1,$2,$3,$4,'hash','claude-code','PreToolUse','session','shadow',1,1,$5,$6,
                   CASE WHEN $5='evaluated' THEN 'allow' END,
                   CASE WHEN $5='evaluated' THEN 'allow' END,'provider_unavailable')
            RETURNING id,request_id""", new_id(), owner["id"], device["id"], new_id(), status, Jsonb(scored)))
    complete, pending, unavailable, peer_check, foreign_check = checks
    matched = {**scored, "hook_check_id": complete["id"]}
    missing = {"status": "error", "reason": "backend_unavailable"}
    cases = [
        ({"hook_request_id": complete["request_id"]}, {}, matched),
        ({}, {"hook_check_id": complete["id"]}, matched),
        ({"hook_request_id": pending["request_id"]}, {},
         {"status": "error", "reason": "timeout", "hook_check_id": pending["id"]}),
        ({}, {"hook_check_id": unavailable["id"]},
         {"status": "error", "reason": "provider_unavailable", "hook_check_id": unavailable["id"]}),
        ({"hook_request_id": "invalid"}, {"hook_check_id": complete["id"]}, matched),
        ({"hook_request_id": complete["request_id"]}, {"hook_check_id": "invalid"}, matched),
        ({"hook_request_id": peer_check["request_id"]}, {}, missing),
        ({}, {"hook_check_id": peer_check["id"]}, missing),
        ({"hook_request_id": foreign_check["request_id"]}, {}, missing),
        ({}, {"hook_check_id": foreign_check["id"]}, missing),
        ({"hook_request_id": new_id()}, {}, missing),
        ({"hook_request_id": complete["request_id"].upper()}, {}, missing),
        ({}, {"hook_check_id": complete["id"].upper()}, missing),
        ({"hook_request_id": complete["request_id"] + "\n"}, {}, missing),
        ({"hook_request_id": {"bad": "value"}}, {"hook_check_id": []}, missing),
        ({"hook_request_id": ""}, {"hook_check_id": None}, missing),
    ]
    cases += [({}, {"hook_check_id": complete["id"]}, matched)] * (103 - len(cases))
    captured = [event() for _ in cases]
    locked, fresh, finished = event(), event(), event()
    db.ingest_batch(s, [*captured, locked, fresh, finished])
    remote = event()
    db.ingest_batch(foreign, [remote])
    for row, (source, risk, _) in zip(captured, cases):
        db.execute("""UPDATE events SET body=body||jsonb_build_object('source',$2::jsonb),
            risk=$3,received_at=now()-interval '25 hours' WHERE id=$1""",
            row["id"], Jsonb(source), Jsonb({"status": "pending", **risk}))
    for row, check in ((locked, complete), (fresh, complete), (remote, foreign_check)):
        db.execute("UPDATE events SET risk=$2,received_at=now()-interval '25 hours' WHERE id=$1",
                   row["id"], Jsonb({"status": "pending", "hook_check_id": check["id"]}))
    db.execute("UPDATE events SET received_at=now()+interval '1 hour' WHERE id=$1", fresh["id"])
    db.execute("UPDATE events SET risk=$2 WHERE id=$1", finished["id"], Jsonb(matched))
    bounded = risk_store(db)
    request.addfinalizer(bounded.close)
    with db.transaction() as conn:
        conn.execute("SELECT id FROM events WHERE id=%s FOR UPDATE", (locked["id"],))
        bounded.expire_risk_events(t["id"])
        assert db.scalar("SELECT count(*) FROM events WHERE id=ANY($1::uuid[]) AND risk->>'status'<>'pending'",
                         [row["id"] for row in captured]) == 100
        bounded.expire_risk_events(t["id"])
        assert db.get_event(t["id"], locked["id"])["risk"]["status"] == "pending"
    bounded.expire_risk_events(t["id"])
    for row, (_, _, expected) in zip(captured, cases):
        assert db.get_event(t["id"], row["id"])["risk"] == expected
    assert db.get_event(t["id"], locked["id"])["risk"] == matched
    assert db.get_event(t["id"], fresh["id"])["risk"]["status"] == "pending"
    assert db.get_event(t["id"], finished["id"])["risk"] == matched
    assert db.get_event(other["id"], remote["id"])["risk"]["status"] == "pending"
    bounded.expire_risk_events()
    assert db.get_event(other["id"], remote["id"])["risk"] == {**scored, "hook_check_id": foreign_check["id"]}


def test_expired_claims_retry_without_stale_writes_and_stop_after_three(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    e = event()
    db.ingest_batch(s, [e])
    first = db.claim_risk_event(t["id"])
    db.execute(
        "UPDATE events SET risk_next_attempt_at=now()-interval '1 second' WHERE id=$1",
        e["id"],
    )
    second = db.claim_risk_event(t["id"])
    assert second["risk_attempts"] == 2
    assert db.finish_risk_event(first, parse_assessment(reply())) == 0
    db.finish_risk_event(
        second, {"status": "error", "reason": "connection_failed"}, True
    )
    assert db.claim_risk_event(t["id"]) is None
    db.execute(
        "UPDATE events SET risk_next_attempt_at=now()-interval '1 second' WHERE id=$1",
        e["id"],
    )
    assert db.claim_risk_event(t["id"])["risk_attempts"] == 3
    db.execute(
        "UPDATE events SET risk_next_attempt_at=now()-interval '1 second' WHERE id=$1",
        e["id"],
    )
    assert db.claim_risk_event(t["id"]) is None
    assert db.get_event(t["id"], e["id"])["risk"]["status"] == "error"


@pytest.mark.parametrize("attempts", [1, 2])
def test_interrupted_claims_become_terminal_after_aging_out(db, attempts):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    e = event()
    db.ingest_batch(s, [e])
    for _ in range(attempts):
        db.execute(
            "UPDATE events SET risk_next_attempt_at=now()-interval '1 second' WHERE id=$1",
            e["id"],
        )
        claim = db.claim_risk_event(t["id"])
    assert claim["risk_attempts"] == attempts
    db.execute(
        "UPDATE events SET received_at=now()-interval '25 hours' WHERE id=$1",
        e["id"],
    )
    assert db.claim_risk_event(t["id"]) is None
    assert db.get_event(t["id"], e["id"])["risk"]["status"] == "pending"

    db.execute(
        "UPDATE events SET risk_next_attempt_at=now()-interval '1 second' WHERE id=$1",
        e["id"],
    )
    assert db.claim_risk_event(t["id"]) is None
    assert db.get_event(t["id"], e["id"])["risk"] == {
        "status": "error", "reason": "assessment_expired"
    }
    assert db.scalar(
        "SELECT risk_next_attempt_at='infinity'::timestamptz FROM events WHERE id=$1",
        e["id"],
    )
    assert db.finish_risk_event(claim, parse_assessment(reply())) == 0


def test_context_retains_prompt_and_policy_decisions_but_excludes_other_sessions_and_future(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    start = now() - timedelta(minutes=1)
    prompt = event("prompt", at=start, text="Show working tree status")
    prior = [event(at=start + timedelta(seconds=i + 1)) for i in range(15)]
    decision = event("hook.decision", at=start + timedelta(seconds=18), hook={
        "hook_event": "PreToolUse", "decision": "allow", "rule_id": "test-policy",
        "reason": "Allowed by policy; password=hook-secret",
    })
    # A check no rule matched is recorded but is not session context.
    unmatched = event("hook.decision", at=start + timedelta(seconds=19), source={"collector": "hook"}, hook={
        "hook_event": "PreToolUse", "decision": "allow", "rule_id": "", "reason": "",
    })
    # The agent's own permission decision is evidence, even without a rule.
    native = event("hook.decision", at=start + timedelta(seconds=17), source="otlp",
                   hook={"decision": "allow"})
    target = event(at=start + timedelta(seconds=20))
    foreign = event(
        "prompt", session="other", at=start, text="private unrelated prompt"
    )
    future = event(
        "prompt", at=start + timedelta(seconds=21), text="future instruction"
    )
    db.ingest_batch(s, [prompt, *prior, native, decision, unmatched, target, foreign, future])
    context, latest = db.risk_context(db.get_event(t["id"], target["id"]))
    assert len(context) == 12
    assert latest["id"] == prompt["id"]
    assert {r["id"] for r in context}.isdisjoint(
        {foreign["id"], future["id"], target["id"]}
    )
    assert context[-1]["id"] == decision["id"]
    assert context[-2]["id"] == native["id"]

    def assess(request):
        import json

        payload = json.loads(request.content)
        evidence = payload["state"]["prior_events"][-1]
        assert evidence["kind"] == "hook.decision"
        assert evidence["hook"]["decision"] == "allow"
        assert evidence["hook"]["rule_id"] == "test-policy"
        assert "hook-secret" not in json.dumps(payload["state"])
        assert "not proof of user authorization" in payload["questions"]["category"]["instructions"]
        return httpx.Response(200, json=reply("none", 0))

    from openaidr.server.guardrail.scoring import assessment_state

    provider = JevClient("test-key", httpx.MockTransport(assess))
    try:
        provider.assess(assessment_state(db.get_event(t["id"], target["id"]), context, latest))
    finally:
        provider.close()
    assert db.get_event(t["id"], decision["id"])["risk"] is None


def test_scoring_bounds_large_stored_bodies_before_decoding(db):
    import json

    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    start = now() - timedelta(minutes=1)
    large = "\u4e2d" * 25_000
    prompt = event("prompt", at=start, text=large)
    prior = [event("tool.result", at=start + timedelta(seconds=i + 1), tool={"output": large}) for i in range(12)]
    target = event(at=start + timedelta(seconds=20))
    db.ingest_batch(s, [prompt, *prior, target])
    # Compressed storage size does not bound the JSON sent over the connection.
    assert db.scalar("SELECT pg_column_size(body)<64000 FROM events WHERE id=$1", prompt["id"])
    context, latest = db.risk_context(db.get_event(t["id"], target["id"]))
    assert len(context) == 12 and latest["id"] == prompt["id"]
    assert all(row["body"] == {"truncated": True} for row in [*context, latest])
    assert len(json.dumps([context, latest], default=str).encode()) < 10_000
    provider = Mock()
    provider.assess.return_value = parse_assessment(reply("none", 0))
    worker = RiskWorker(db, provider, t["id"])
    db.expire_risk_events(t["id"])
    provider.assess.assert_not_called()
    assert db.scalar("SELECT COALESCE(sum(attempts),0) FROM risk_assessment_usage") == 0
    stored = db.get_event(t["id"], prompt["id"])
    assert stored["risk"] == {
        "status": "unscored", "category": "unknown", "score": None,
        "level": None, "reason": "evidence_too_large",
    }
    assert stored["body"]["text"] == large
    assert worker.tick()
    provider.assess.assert_called_once()
    assert db.get_event(t["id"], target["id"])["risk"]["score"] == 0
    assert db.scalar("SELECT sum(attempts) FROM risk_assessment_usage") == 1


def test_oversized_backlog_cannot_starve_a_tenant_with_prior_provider_usage(db):
    a, b = tenant(db), tenant(db)
    sa, _, _ = sensor(db, a["id"])
    sb, _, _ = sensor(db, b["id"])
    first, second = event(), event()
    db.ingest_batch(sb, [first])
    provider = Mock()
    provider.assess.return_value = parse_assessment(reply("none", 0))
    worker = RiskWorker(db, provider)
    assert worker.tick()
    db.ingest_batch(sa, [event("tool.result", tool={"output": "x" * 64_000}) for _ in range(101)])
    db.ingest_batch(sb, [second])
    assert worker.tick()
    assert db.get_event(b["id"], second["id"])["risk"]["score"] == 0
    assert provider.assess.call_count == 2
    assert db.scalar("SELECT COALESCE(sum(attempts),0) FROM risk_assessment_usage WHERE tenant_id=$1", a["id"]) == 0
    assert db.scalar("SELECT count(*) FROM events WHERE tenant_id=$1 AND risk IS NULL", a["id"]) == 1
    assert db.scalar("SELECT count(*) FROM events WHERE tenant_id=$1 AND risk->>'reason'='evidence_too_large'", a["id"]) == 100


def test_ineligible_oversized_rows_do_not_receive_assessments_or_remain_queued(db):
    a, b = tenant(db), tenant(db)
    sa, _, _ = sensor(db, a["id"])
    sb, _, _ = sensor(db, b["id"])
    large = {"tool": {"output": "x" * 64_000}}
    unsupported, old, eligible = event("session.start", **large), event(**large), event(**large)
    inactive = event(**large)
    db.ingest_batch(sa, [unsupported, old, eligible])
    db.ingest_batch(sb, [inactive])
    db.execute("UPDATE events SET received_at=now()-interval '25 hours' WHERE id=$1", old["id"])
    db.execute("UPDATE tenants SET status='suspended' WHERE id=$1", b["id"])
    db.expire_risk_events()
    for owner, row in ((a, unsupported), (a, old), (b, inactive)):
        assert db.get_event(owner["id"], row["id"])["risk"] is None
    assert db.get_event(a["id"], eligible["id"])["risk"]["reason"] == "evidence_too_large"
    predicate = db.scalar("SELECT pg_get_expr(indpred,indrelid) FROM pg_index WHERE indexrelid='events_risk_oversized_idx'::regclass")
    assert db.scalar("SELECT count(*) FROM events WHERE " + predicate) == 0
    assert db.scalar("SELECT COALESCE(sum(attempts),0) FROM risk_assessment_usage") == 0


@pytest.mark.parametrize("mode", ["no_key", "detect_disabled", "initialization_failed"])
def test_abandoned_claims_expire_without_a_provider_worker(db, monkeypatch, mode):
    import time
    from fastapi.testclient import TestClient
    from openaidr.server.app import create_app
    from openaidr.server.config import Config

    a, b = tenant(db), tenant(db)
    sa, _, _ = sensor(db, a["id"])
    sb, _, _ = sensor(db, b["id"])
    abandoned, active, foreign = event(), event(), event()
    db.ingest_batch(sa, [abandoned, active])
    db.ingest_batch(sb, [foreign])
    assert db.claim_risk_event(a["id"])["id"] == abandoned["id"]
    assert db.claim_risk_event(a["id"])["id"] == active["id"]
    db.claim_risk_event(b["id"])
    db.execute("UPDATE events SET received_at=now()-interval '25 hours'")
    db.execute(
        "UPDATE events SET risk_next_attempt_at=now()-interval '1 second' WHERE id=ANY($1::uuid[])",
        [abandoned["id"], foreign["id"]],
    )
    cfg = Config(database_url=db.url, tenant_id=a["id"])
    cfg.set_services("ingest,api" if mode == "detect_disabled" else "ingest,api,detect")
    if mode == "initialization_failed":
        monkeypatch.setenv("HTTPS_PROXY", "unsupported://proxy.invalid")
    with TestClient(create_app(cfg, db)) as client:
        assert client.get("/healthz").status_code == 200
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = db.event_risks(a["id"], [abandoned["id"]])[0]["risk"]
            if result["status"] == "error":
                break
            time.sleep(0.02)
        assert result == {"status": "error", "reason": "assessment_expired"}
        assert db.get_event(a["id"], active["id"])["risk"]["status"] == "pending"
        assert db.get_event(b["id"], foreign["id"])["risk"]["status"] == "pending"


def test_worker_recovers_stored_work_and_leaves_old_or_control_events_unscored(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    old, control, eligible = (
        event(),
        event("session.start"),
        event("response", text="Done"),
    )
    db.ingest_batch(s, [old, control, eligible])
    db.execute(
        "UPDATE events SET received_at=now()-interval '2 days' WHERE id=$1", old["id"]
    )
    client = Mock()
    client.assess.return_value = parse_assessment(reply("none", 0))
    assert RiskWorker(db, client, t["id"]).tick()
    assert not RiskWorker(db, client, t["id"]).tick()
    client.assess.assert_called_once()
    assert public(db.get_event(t["id"], eligible["id"]))["risk"]["score"] == 0
    assert db.get_event(t["id"], old["id"])["risk"] is None


@pytest.mark.parametrize("services", ["detect", "ingest,api,detect"])
@pytest.mark.parametrize("key_source", ["server", "tenant"])
def test_detection_reuses_stored_scores_without_background_model_calls(db, monkeypatch, services, key_source):
    import threading
    from fastapi.testclient import TestClient
    from psycopg.types.json import Jsonb
    from openaidr.server.app import create_app
    from openaidr.server.config import Config
    from openaidr.server.guardrail import storage as risk

    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    reconciled = threading.Event()
    stores = []
    original_risk_store = risk.risk_store

    def tracked_store(original, **kwargs):
        bounded = original_risk_store(original, **kwargs)
        expire = bounded.expire_risk_events
        def reconcile(tenant_id=None):
            result = expire(tenant_id)
            reconciled.set()
            return result
        bounded.expire_risk_events = reconcile
        stores.append(bounded)
        return bounded

    from unittest.mock import AsyncMock
    provider = Mock(assess=AsyncMock(return_value=parse_assessment(reply("none", 0))), aclose=AsyncMock())
    monkeypatch.setattr(provider_scoring, "AsyncJevClient", lambda key: provider)
    monkeypatch.setattr(risk, "risk_store", tracked_store)
    cfg = Config(database_url=db.url, tenant_id=t["id"],
                 cost_processing=False, database_diagnostics=False)
    if key_source == "tenant":
        db.execute("INSERT INTO tenant_model_keys(tenant_id,kind,api_key) VALUES($1,'guardrail','guardrail-test-key')", t["id"])
    cfg.set_services(services)
    app = create_app(cfg, db)
    for _ in range(2):
        reconciled.clear()
        unscored, scored, expired, active = event(), event(), event(), event()
        db.ingest_batch(s, [unscored, scored, expired, active])
        assessment = {"status": "scored", "score": 90, "hook_check_id": new_id()}
        db.execute("UPDATE events SET risk=$2 WHERE id=$1", scored["id"], Jsonb(assessment))
        db.execute("""UPDATE events SET risk='{"status":"pending"}',risk_attempts=1,
                   risk_next_attempt_at=now()+interval '60 seconds' WHERE id=ANY($1::uuid[])""",
                   [expired["id"], active["id"]])
        db.execute("UPDATE events SET risk_next_attempt_at=now()-interval '1 second' WHERE id=$1", expired["id"])
        with TestClient(app) as client:
            assert client.get("/healthz").status_code == 200
            assert reconciled.wait(5)
        assert db.get_event(t["id"], unscored["id"])["risk"] is None
        assert db.get_event(t["id"], scored["id"])["risk"] == assessment
        assert db.get_event(t["id"], expired["id"])["risk"] == {"status": "error", "reason": "assessment_expired"}
        assert db.get_event(t["id"], active["id"])["risk"] == {"status": "pending"}
    provider.assess.assert_not_awaited()
    assert db.scalar("SELECT count(*) FROM model_usage") == 0
    assert len(stores) == (6 if cfg.enabled("api") else 4)
    assert all(pool.closed for bounded in stores for pool in bounded.pools.values())
    assert db.scalar("SELECT 1") == 1


@pytest.mark.parametrize("name,value", [
    ("HTTPS_PROXY", "unsupported://proxy-credential@proxy.invalid"),
    ("SSL_CERT_FILE", "/nonexistent/jev-test-ca.pem"),
])
def test_unconfigured_service_ignores_legacy_provider_environment(db, monkeypatch, caplog, name, value):
    from fastapi.testclient import TestClient
    from openaidr.server.app import create_app
    from openaidr.server.config import Config
    from openaidr.server.model_keys import TenantGuardrailClient

    monkeypatch.setenv(name, value)
    t = tenant(db)
    cfg = Config(database_url=db.url, tenant_id=t["id"])
    cfg.set_services("ingest,api,detect")
    with TestClient(create_app(cfg, db)) as client:
        assert client.get("/healthz").status_code == 200
    with pytest.raises(JevError, match="provider_unavailable"):
        TenantGuardrailClient(db, t["id"], cfg).assess({})
    assert "proxy-credential" not in caplog.text and "test-key" not in caplog.text
    assert "proxy-credential" not in caplog.text and value not in caplog.text


def test_provider_backoff_survives_restart_and_applies_to_replicas(db):
    a, b = tenant(db), tenant(db)
    sa, _, _ = sensor(db, a["id"])
    sb, _, _ = sensor(db, b["id"])
    first, second, other = event(), event(), event()
    db.ingest_batch(sa, [first, second])
    db.ingest_batch(sb, [other])
    failed, healthy = Mock(), Mock()
    failed.assess.side_effect = JevError("provider_unavailable", True, 120)
    healthy.assess.return_value = parse_assessment(reply("none", 0))
    replica = RiskWorker(db, healthy, b["id"])
    assert RiskWorker(db, failed, a["id"]).tick()
    assert not replica.tick()
    assert not RiskWorker(db, healthy, a["id"]).tick()
    healthy.assess.assert_not_called()
    assert db.get_event(a["id"], second["id"])["risk"] is None
    assert db.get_event(b["id"], other["id"])["risk"] is None

    db.execute("UPDATE risk_provider_backoff SET retry_at=now()-interval '1 second'")
    assert replica.tick()
    assert db.get_event(b["id"], other["id"])["risk"]["score"] == 0
    healthy.assess.assert_called_once()


@pytest.mark.parametrize(
    "status,reason", [(422, "provider_rejected"), (200, "invalid_response")]
)
def test_terminal_errors_do_not_pause_unrelated_assessments(db, status, reason):
    a, b = tenant(db), tenant(db)
    sa, _, _ = sensor(db, a["id"])
    sb, _, _ = sensor(db, b["id"])
    first, second, other = event(), event(), event()
    db.ingest_batch(sa, [first, second])
    db.ingest_batch(sb, [other])
    handler = Mock(side_effect=[
        httpx.Response(status, json={}),
        httpx.Response(200, json=reply("none", 0)),
        httpx.Response(200, json=reply("none", 0)),
    ])
    client = JevClient("test-key", httpx.MockTransport(handler))
    try:
        worker = RiskWorker(db, client, a["id"])
        assert worker.tick()
        failed = db.get_event(a["id"], first["id"])["risk"]
        assert failed.pop("knowledge")["enabled"] is False
        assert failed == {
            "status": "error", "reason": reason
        }
        assert db.scalar("SELECT count(*) FROM risk_provider_backoff") == 0
        assert worker.tick()
        assert RiskWorker(db, client, b["id"]).tick()
        assert db.get_event(a["id"], second["id"])["risk"]["score"] == 0
        assert db.get_event(b["id"], other["id"])["risk"]["score"] == 0
        assert handler.call_count == 3
    finally:
        client.close()


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("prior_attempts", [0, 2])
def test_authentication_failures_suspend_until_restart_and_preserve_queue(db, status, prior_attempts):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    first, second = event(), event()
    db.ingest_batch(s, [first, second])
    if prior_attempts:
        db.execute(
            """UPDATE events SET risk_attempts=$2,risk_retry_attempts=$2,
               risk='{"status":"error","reason":"connection_failed"}'::jsonb
               WHERE id=$1""", first["id"], prior_attempts,
        )
    rejected = Mock(return_value=httpx.Response(status, text="private-provider-body"))
    client = JevClient("invalid-key", httpx.MockTransport(rejected))
    try:
        worker = RiskWorker(db, client, t["id"])
        assert worker.tick()
        failed = db.get_event(t["id"], first["id"])["risk"]
        assert failed.pop("knowledge")["enabled"] is False
        assert failed == {
            "status": "error", "reason": "authentication_failed"
        }
        db.execute("UPDATE risk_provider_backoff SET retry_at=now()-interval '1 second'")
        db.execute("UPDATE events SET risk_next_attempt_at=now()-interval '1 second' WHERE id=$1", first["id"])
        worker.retry_at = 0
        for _ in range(3):
            assert not worker.tick()
        rejected.assert_called_once()
        assert db.get_event(t["id"], second["id"])["risk"] is None
        assert db.scalar("SELECT sum(risk_attempts) FROM events") == prior_attempts + 1
    finally:
        client.close()

    corrected = JevClient(
        "corrected-key",
        httpx.MockTransport(lambda request: httpx.Response(200, json=reply("none", 0))),
    )
    try:
        restarted = RiskWorker(db, corrected, t["id"])
        assert restarted.tick()
        assert db.get_event(t["id"], first["id"])["risk"]["score"] == 0
        assert db.scalar("SELECT risk_attempts FROM events WHERE id=$1", first["id"]) == prior_attempts + 2
        assert restarted.tick()
        assert db.get_event(t["id"], second["id"])["risk"]["score"] == 0
        assert db.scalar("SELECT attempts FROM risk_assessment_usage WHERE sensor_id=$1", s["id"]) == 3
    finally:
        corrected.close()


def test_authentication_attempts_do_not_exhaust_transient_retries(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    e = event()
    db.ingest_batch(s, [e])
    responses = Mock(side_effect=[
        httpx.Response(401), httpx.Response(403), httpx.Response(401),
        httpx.Response(503), httpx.Response(200, json=reply("none", 0)),
    ])
    client = JevClient("test-key", httpx.MockTransport(responses))
    try:
        for attempt in range(5):
            db.execute("DELETE FROM risk_provider_backoff")
            db.execute("UPDATE events SET risk_next_attempt_at=now()-interval '1 second'")
            assert RiskWorker(db, client, t["id"]).tick()
        assert responses.call_count == 5
        assert db.get_event(t["id"], e["id"])["risk"]["score"] == 0
        assert db.scalar("SELECT risk_attempts FROM events") == 5
        assert db.scalar("SELECT risk_retry_attempts FROM events") == 2
        assert db.scalar("SELECT attempts FROM risk_assessment_usage") == 5
    finally:
        client.close()


@pytest.mark.parametrize("status", [401, 403])
def test_stale_key_does_not_pause_valid_replicas_or_other_tenants(db, status):
    a, b = tenant(db), tenant(db)
    sa, _, _ = sensor(db, a["id"])
    sb, _, _ = sensor(db, b["id"])
    failed, same_tenant, other_tenant = event(), event(), event()
    db.ingest_batch(sa, [failed, same_tenant])
    db.ingest_batch(sb, [other_tenant])
    rejected = Mock(return_value=httpx.Response(status, headers={"Retry-After": "3600"}))
    stale = JevClient("stale-key", httpx.MockTransport(rejected))
    healthy = Mock()
    healthy.assess.return_value = parse_assessment(reply("none", 0))
    try:
        worker = RiskWorker(db, stale, a["id"])
        assert worker.tick()
        assert db.scalar("SELECT count(*) FROM risk_provider_backoff") == 0
        assert RiskWorker(db, healthy, a["id"]).tick()
        assert RiskWorker(db, healthy, b["id"]).tick()
        assert db.get_event(a["id"], same_tenant["id"])["risk"]["score"] == 0
        assert db.get_event(b["id"], other_tenant["id"])["risk"]["score"] == 0
        assert not worker.tick()
        rejected.assert_called_once()
        assert db.scalar("SELECT risk_retry_attempts FROM events WHERE id=$1", failed["id"]) == 0
        assert db.scalar("SELECT sum(attempts) FROM risk_assessment_usage") == 3
    finally:
        stale.close()


@pytest.mark.parametrize("completed", [False, True])
@pytest.mark.parametrize("existing_backoff", [False, True])
def test_stale_provider_failures_cannot_create_or_extend_shared_backoff(db, completed, existing_backoff):
    a, b = tenant(db), tenant(db)
    sa, _, _ = sensor(db, a["id"])
    sb, _, _ = sensor(db, b["id"])
    original, unrelated = event(), event()
    db.ingest_batch(sa, [original])
    db.ingest_batch(sb, [unrelated])
    first = db.claim_risk_event(a["id"])
    db.execute("UPDATE events SET risk_next_attempt_at=now()-interval '1 second' WHERE id=$1", original["id"])
    reclaimed = db.claim_risk_event(a["id"])
    if completed:
        assert db.finish_risk_event(reclaimed, parse_assessment(reply("none", 0))) == 1
    if existing_backoff:
        db.execute("INSERT INTO risk_provider_backoff(provider,retry_at) VALUES('jev',now()-interval '1 second')")
    previous = db.many("SELECT * FROM risk_provider_backoff")
    latest_risk = db.get_event(a["id"], original["id"])["risk"]
    assert db.finish_risk_event(
        first, {"status": "error", "reason": "provider_unavailable"}, 3600, provider_delay=3600,
    ) == 0
    assert db.many("SELECT * FROM risk_provider_backoff") == previous
    assert db.get_event(a["id"], original["id"])["risk"] == latest_risk
    assert db.claim_risk_event(b["id"])["id"] == unrelated["id"]


def test_concurrent_provider_failures_keep_the_longest_pause(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    db.ingest_batch(s, [event(), event()])
    first, second = db.claim_risk_event(), db.claim_risk_event()
    failed = {"status": "error", "reason": "provider_unavailable"}
    db.finish_risk_event(first, failed, 120, provider_delay=120)
    deadline = db.scalar("SELECT retry_at FROM risk_provider_backoff WHERE provider='jev'")
    db.finish_risk_event(second, failed, 30, provider_delay=30)
    assert db.scalar("SELECT retry_at FROM risk_provider_backoff WHERE provider='jev'") == deadline


def test_usage_fairness_does_not_limit_sensors_or_tenants(db):
    a, b = tenant(db), tenant(db)
    sa, _, _ = sensor(db, a["id"])
    sa2, _, _ = sensor(db, a["id"])
    sa3, _, _ = sensor(db, a["id"])
    sb, _, _ = sensor(db, b["id"])
    flood = [event() for _ in range(10)]
    second_sensor, third_sensor, other_tenant = event(), event(), event()
    db.ingest_batch(sa, flood)
    db.ingest_batch(sa2, [second_sensor])
    db.ingest_batch(sa3, [third_sensor])
    db.ingest_batch(sb, [other_tenant])
    provider = Mock()
    provider.assess.return_value = parse_assessment(reply("none", 0))

    def tick():
        # A fresh worker on every call also verifies restart persistence.
        return RiskWorker(db, provider).tick()

    assert tick()
    assert db.get_event(a["id"], flood[0]["id"])["risk"]["status"] == "scored"
    assert tick()
    assert db.get_event(b["id"], other_tenant["id"])["risk"]["status"] == "scored"
    assert tick()
    assert db.get_event(a["id"], second_sensor["id"])["risk"]["status"] == "scored"
    for _ in range(10):
        assert tick()
    assert not tick()
    assert db.get_event(a["id"], flood[1]["id"])["risk"]["status"] == "scored"
    assert db.get_event(a["id"], third_sensor["id"])["risk"]["status"] == "scored"
    assert provider.assess.call_count == 13


def test_concurrent_claims_dispatch_each_event_once_without_an_hourly_cap(db):
    from concurrent.futures import ThreadPoolExecutor

    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    db.ingest_batch(s, [event() for _ in range(10)])
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(pool.map(
            lambda _: db.claim_risk_event(), range(10)
        ))
    assert len({row["id"] for row in claims}) == 10
    assert db.scalar("SELECT sum(risk_attempts) FROM events") == 10
    assert db.scalar("SELECT attempts FROM risk_assessment_usage WHERE sensor_id=$1", s["id"]) == 10


def test_usage_counts_do_not_prevent_retries(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    db.ingest_batch(s, [event()])
    row = db.claim_risk_event()
    db.finish_risk_event(row, {"status": "error", "reason": "connection_failed"}, 30)
    db.execute("UPDATE events SET risk_next_attempt_at=now()-interval '1 second'")
    provider = Mock()
    provider.assess.return_value = parse_assessment(reply("none", 0))
    assert RiskWorker(db, provider).tick()
    provider.assess.assert_called_once()
    assert db.scalar("SELECT risk_attempts FROM events") == 2


def test_material_assessments_become_detections_with_event_evidence(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    call = event(
        kind="tool.call",
        tool={"name": "Bash", "call_id": "toolu_1"},
        host={"hostname": "host", "os": "linux", "arch": "amd64", "user": "alice"},
        agent={"product": "claude-code", "account": "panhu@opensecura.ai"},
    )
    db.ingest_batch(s, [call])
    row = db.claim_risk_event(t["id"])
    assert row["id"] == call["id"]
    assert db.finish_risk_event(row, parse_assessment(reply())) == 1
    items, cursor = db.list_findings(t["id"])
    assert cursor == "" and len(items) == 1
    finding = items[0]
    assert finding["rule_id"] == "jev-risk-detection"
    assert finding["category"] == "secret_exfiltration"
    assert finding["severity"] == "critical"
    assert finding["status"] == "open"
    assert finding["title"] == "Secret exfiltration risk in a tool call"
    assert finding["primary_event_id"] == call["id"]
    assert finding["event_ids"] == [call["id"]]
    assert finding["session_id"] == row["session_id"]
    assert finding["sensor_id"] == s["id"]
    assert finding["hostname"] == "host" and finding["username"] == "alice"
    assert finding["product"] == "claude-code"
    assert finding["account"] == "panhu@opensecura.ai"
    assert db.rule_finding_counts(t["id"]) == {"jev-risk-detection": 1}
    # A repeated terminal write and a repeated detection insert stay inert.
    assert db.finish_risk_event(row, parse_assessment(reply())) == 0
    assert db.record_risk_detection(row, parse_assessment(reply())) is False
    assert db.rule_finding_counts(t["id"]) == {"jev-risk-detection": 1}


def test_worker_creates_detections_for_material_tool_assessments(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    call = event(
        kind="tool.call",
        tool={"name": "Bash", "call_id": "toolu_1"},
        host={"hostname": "host", "user": "alice"},
    )
    db.ingest_batch(s, [call])
    client = Mock()
    client.assess.return_value = parse_assessment(reply())
    assert RiskWorker(db, client, t["id"]).tick()
    client.assess.assert_called_once()
    items, _ = db.list_findings(t["id"])
    assert [finding["rule_id"] for finding in items] == ["jev-risk-detection"]
    assert items[0]["primary_event_id"] == call["id"]


def test_advisory_and_response_assessments_keep_scores_without_detections(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    low = event(kind="prompt")
    db.ingest_batch(s, [low])
    row = db.claim_risk_event(t["id"])
    assert row["id"] == low["id"]
    low_result = parse_assessment(reply("excessive_agency", 1.0))
    assert low_result["level"] == "low"
    assert db.finish_risk_event(row, low_result) == 1
    response = event(kind="response")
    db.ingest_batch(s, [response])
    row = db.claim_risk_event(t["id"])
    assert row["id"] == response["id"]
    assert db.finish_risk_event(row, parse_assessment(reply())) == 1
    assert db.rule_finding_counts(t["id"]) == {}
    assert db.event_risks(t["id"], [low["id"]])[0]["risk"]["level"] == "low"
    assert db.event_risks(t["id"], [response["id"]])[0]["risk"]["status"] == "scored"


def test_disabled_detection_rule_stops_new_detections_only(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    db.set_rule_enabled(t["id"], "jev-risk-detection", False)
    muted = event(kind="tool.result")
    db.ingest_batch(s, [muted])
    row = db.claim_risk_event(t["id"])
    assert row["id"] == muted["id"]
    assert db.finish_risk_event(row, parse_assessment(reply())) == 1
    assert db.rule_finding_counts(t["id"]) == {}
    assert db.event_risks(t["id"], [muted["id"]])[0]["risk"]["status"] == "scored"
    db.set_rule_enabled(t["id"], "jev-risk-detection", True)
    detected = event(kind="tool.result")
    db.ingest_batch(s, [detected])
    row = db.claim_risk_event(t["id"])
    assert row["id"] == detected["id"]
    assert db.finish_risk_event(row, parse_assessment(reply())) == 1
    assert db.rule_finding_counts(t["id"]) == {"jev-risk-detection": 1}
