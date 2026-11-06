from datetime import timedelta
from decimal import Decimal

import pytest

from test_store import db, sensor, tenant
from openaidr.server.guardrail import analytics as guardrail
from openaidr.server.store import new_id, now


def decision(action, rule_id="", rule_name="", e2e=12.0, session="s1", **hook):
    return {
        "id": new_id(),
        "time": (now() - timedelta(minutes=1)).isoformat(),
        "kind": "hook.decision",
        "agent": {"product": "claude-code", "account": "alice@example.com"},
        "session": {"id": session},
        "source": {"collector": "hook"},
        "command": {"text": "ls"},
        "hook": {
            "hook_event": "PreToolUse",
            "decision": action,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "reason": "",
            "latency_ms": 0.5,
            "e2e_ms": e2e,
            **hook,
        },
    }


def test_history_reads_decision_fields_without_event_heap_access(db, monkeypatch):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    event = decision("allow")
    db.ingest_batch(s, [event])
    db.execute("""INSERT INTO events(id,tenant_id,sensor_id,time,kind,product,body)
        SELECT md5('decision-report-'||n)::uuid,e.tenant_id,e.sensor_id,e.time,e.kind,e.product,e.body
        FROM events e CROSS JOIN generate_series(1,1999) n WHERE e.id=$1""", event["id"])
    db.execute("ANALYZE guardrail_decision_events")
    plans, many = [], db.many
    def capture_query(query, *args, **kwargs):
        if "WITH decisions AS MATERIALIZED" in query:
            plans.append(db.scalar("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + query,
                                   *args, conn=kwargs["conn"])[0]["Plan"])
        return many(query, *args, **kwargs)
    monkeypatch.setattr(db, "many", capture_query)
    result = guardrail.history(db, t["id"], "30d", "endpoints")
    assert result["totals"]["total"] == result["totals"]["allow"] == 2000
    assert result["totals"]["e2e_p95"] == 12
    assert result["rules"][0]["total"] == 2000
    assert len(plans) == 2
    for plan in plans:
        pending = [plan]
        while pending:
            node = pending.pop()
            if node.get("Relation Name", "").startswith("events_"):
                assert node.get("Shared Hit Blocks", 0) + node.get("Shared Read Blocks", 0) == 0, plan
            pending.extend(node.get("Plans", []))


@pytest.mark.parametrize("range_name", ["1h", "30d"])
def test_history_reads_delivery_evidence_in_bulk(db, monkeypatch, range_name):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    db.execute(
        """INSERT INTO ordinary_hook_checks
           (id,tenant_id,sensor_id,request_id,payload_sha256,product,hook_event,session_id,
            mode,settings_version,policy_version,status,evaluated_decision,returned_decision,created_at)
           SELECT md5('history-check-'||n)::uuid,$1,$2,md5('history-request-'||n)::uuid,
                  'fixture','claude-code','PreToolUse','session','enforce',1,1,
                  'evaluated','allow','allow',now()-interval '1 minute'
           FROM generate_series(1,2000) n""",
        t["id"], s["id"],
    )
    # Old event timestamps remain valid delivery evidence for a current check.
    receipt = {"id": new_id(), "time": (now() - timedelta(days=2)).isoformat(),
               "kind": "sensor", "agent": {"product": "claude-code"},
               "source": {"collector": "hook-delivery", "hook_request_id": new_id()},
               "hook": {"delivery_status": "delivered", "delivered_decision": "allow"}}
    db.ingest_batch(s, [receipt])
    db.execute(
        """INSERT INTO events(id,tenant_id,sensor_id,agent_id,session_id,time,kind,product,body)
           SELECT md5('history-receipt-'||n)::uuid,e.tenant_id,e.sensor_id,e.agent_id,e.session_id,
                  e.time,e.kind,e.product,e.body||jsonb_build_object(
                      'source',jsonb_build_object('collector','hook-delivery',
                          'hook_request_id',md5('history-request-'||n)::uuid),
                      'hook',jsonb_build_object('delivered_decision','allow','delivery_status',
                          CASE WHEN n%2=0 THEN 'delivered' ELSE 'timed_out' END))
           FROM events e CROSS JOIN generate_series(1,2000) n WHERE e.id=$1""",
        receipt["id"],
    )
    db.execute("ANALYZE ordinary_hook_checks")
    db.execute("ANALYZE events")
    db.execute("ANALYZE hook_delivery_events")
    with db.transaction() as conn:
        conn.execute("SET plan_cache_mode=force_generic_plan")
        conn.prepare_threshold = 0
    plans, many = [], db.many

    def capture_query(query, *args, **kwargs):
        if "samples AS MATERIALIZED" in query:
            plans.append(db.scalar("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + query,
                                   *args, conn=kwargs["conn"])[0]["Plan"])
        return many(query, *args, **kwargs)

    monkeypatch.setattr(db, "many", capture_query)
    original_indexscan = db.scalar("SHOW enable_indexscan")
    result = guardrail.history(db, t["id"], range_name)
    assert db.scalar("SHOW enable_indexscan") == original_indexscan
    assert db.scalar("SHOW plan_cache_mode") == "force_generic_plan"
    assert db.scalar("""SELECT count(*) FROM pg_prepared_statements
        WHERE ltrim(statement,chr(10)||' ') LIKE 'WITH decisions%'
          AND statement LIKE '%selected_checks AS MATERIALIZED%'
          AND custom_plans>0 AND generic_plans=0""") == 1
    assert result["totals"]["attempted"] == 2000
    assert result["totals"]["failed"] == 1000
    assert result["totals"]["unconfirmed"] == 0
    # Retired event partitions must stop contributing before asynchronous key cleanup.
    db.execute("UPDATE telemetry_partition_days SET retired_at=now() WHERE tenant_id=$1", t["id"])
    assert guardrail.history(db, t["id"], range_name)["totals"]["unconfirmed"] == 2000
    plan = plans[0]
    event_blocks = receipt_blocks = 0
    pending = [plan]
    while pending:
        node = pending.pop()
        blocks = node.get("Shared Hit Blocks", 0) + node.get("Shared Read Blocks", 0)
        if node.get("Relation Name", "").startswith("events_"):
            event_blocks += blocks
        elif node.get("Relation Name") == "hook_delivery_events":
            receipt_blocks += blocks
        pending.extend(node.get("Plans", []))
    # Compact index probes are cheap; repeated reads of wide event heaps are not.
    assert event_blocks < 2000, plan
    assert 0 < receipt_blocks < 10000, plan


@pytest.mark.parametrize("launcher_first", [False, True])
def test_timeout_and_launcher_receipt_count_one_failed_run(db, tmp_path, launcher_first):
    from openaidr.sensor import hook_runtime

    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    execution = new_id().replace("-", "")
    at = now()
    failure = hook_runtime.measurement(s["id"], "codex-cli", "PreToolUse", execution,
                                       None, at.isoformat(), failure_reason="deadline_expired")
    (tmp_path / f"codex.PreToolUse.{int(at.timestamp())}.22.{execution}.agent").touch()
    receipts = []
    hook_runtime.collect(tmp_path, receipts.append, sensor_id=s["id"])
    events = [failure, receipts[0]]
    if launcher_first:
        events.reverse()
    assert db.ingest_batch(s, events) == {"accepted": 1, "duplicates": 1}
    assert db.ingest_batch(s, events) == {"accepted": 0, "duplicates": 2}
    assert guardrail.stats(db, t["id"], "1h")["executions"] == {"total": 1, "failed": 1}


def test_stats_rates_latency_rules_and_scope(db):
    t, other = tenant(db), tenant(db)
    s, _, _ = sensor(db, t["id"])
    so, _, _ = sensor(db, other["id"])
    rule = {"id": "push", "name": "Approve pushes", "action": "ask", "enabled": True,
            "match": {"command_regex": "git push"}}
    db.save_policy(t["id"], [rule])
    legacy = decision("deny", "rm", "Block rm")
    del legacy["hook"]["latency_ms"], legacy["hook"]["e2e_ms"]
    native = decision("reject")
    native["source"] = "otlp"
    malformed = decision("allow", e2e="slow")
    # Valid JSON, but beyond float8: must not fail the query or a percentile.
    oversized = decision("allow", e2e=10**400)
    def execution(outcome):
        return {"id": new_id(), "time": (now() - timedelta(minutes=1)).isoformat(),
                "kind": "sensor", "agent": {"product": "codex-cli"},
                "source": {"collector": "hook-runtime"}, "hook": {"outcome": outcome}}

    old_execution = execution("failed")
    old_execution["time"] = (now() - timedelta(hours=2)).isoformat()
    unrelated = execution("failed")
    unrelated["source"] = {"collector": "sensor"}
    db.ingest_batch(s, [
        *(decision("allow", e2e=float(i)) for i in range(1, 9)),
        decision("ask", "push", "Old name", e2e=40.0),
        # Codex enforces an ask rule as a deny.
        decision("ask", "push", "Old name", e2e=60.0, enforced="deny"),
        decision("deny", "rm", "Block rm", e2e=5.0),
        legacy, native, malformed, oversized,
        execution("succeeded"), execution("succeeded"), execution("failed"),
        execution("invalid"), old_execution, unrelated,
    ])
    db.ingest_batch(so, [decision("deny", "rm", "Block rm") for _ in range(5)])
    db.ingest_batch(so, [execution("failed")])

    result = guardrail.stats(db, t["id"], "1h")
    totals = result["totals"]
    assert result["executions"] == {"total": 3, "failed": 1}
    assert sum(b["executions"]["total"] for b in result["series"]) == 3
    assert sum(b["executions"]["failed"] for b in result["series"]) == 1
    assert guardrail.stats(db, other["id"], "1h")["executions"] == {"total": 1, "failed": 1}
    assert guardrail.stats(db, tenant(db)["id"], "1h")["executions"] == {"total": 0, "failed": 0}
    assert (totals["total"], totals["allow"], totals["ask"], totals["deny"]) == (13, 10, 2, 1)
    assert totals["legacy"] == 1
    # The malformed latency is left out of percentiles, not the counts.
    assert totals["e2e_p50"] == pytest.approx(5.0)
    assert totals["policy_p99"] == pytest.approx(0.5)
    assert len(result["series"]) == 60 and sum(b["total"] for b in result["series"]) == 13
    rules = {r["rule_id"]: r for r in result["rules"]}
    assert set(rules) == {"", "push", "rm"}
    assert rules[""]["allow"] == 10
    push = rules["push"]
    assert (push["rule_name"], push["action"], push["in_policy"]) == ("Approve pushes", "ask", True)
    assert (push["ask"], push["deny"]) == (2, 0)
    assert rules["rm"]["in_policy"] is False and rules["rm"]["rule_name"] == "Block rm"
    assert guardrail.stats(db, other["id"], "1h")["totals"]["deny"] == 5
    with pytest.raises(ValueError):
        guardrail.stats(db, t["id"], "90d")


def test_stats_use_evaluated_decisions_in_both_modes_and_exclude_failures(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    records = []
    for mode in ("shadow", "enforce"):
        for action in guardrail.DECISIONS:
            returned = "allow" if mode == "shadow" else action
            records.append(decision(
                returned, action, action.title(), mode=mode,
                evaluated_decision=action, returned_decision=returned,
            ))
    records.extend([
        decision("deny", "ask", "Ask", mode="enforce",
                 evaluated_decision="ask", returned_decision="ask"),
        decision("allow", e2e=9999, failure_reason="backend_unavailable"),
        decision("allow", e2e=9999, failure_reason="deadline_expired"),
        decision("allow", e2e=9999, mode="shadow"),
        decision("allow", e2e=9999, evaluated_decision="invalid"),
        decision("allow", e2e=9999, evaluated_decision=None),
    ])
    db.ingest_batch(s, records)

    result = guardrail.stats(db, t["id"], "1h")
    expected = {"total": 9, "allow": 2, "warn": 2, "ask": 3, "deny": 2}
    assert {key: result["totals"][key] for key in expected} == expected
    assert result["totals"]["legacy"] == 0
    assert result["totals"]["e2e_p99"] == 12
    for key, count in expected.items():
        assert sum(bucket[key] for bucket in result["series"]) == count
    for rule in result["rules"]:
        action = rule["rule_id"]
        assert rule["action"] == action
        assert rule["total"] == rule[action] == expected[action]
    assert len(result["rules"]) == 4


@pytest.mark.parametrize("range_name", guardrail.RANGES)
def test_execution_series_uses_the_selected_window_without_decisions(db, range_name):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    duration, interval = guardrail.RANGES[range_name]
    end = now()
    start = end - duration
    records = [
        (start + timedelta(seconds=interval * 1.5), "failed"),
        (start + timedelta(seconds=interval * 1.5), "succeeded"),
        (end - timedelta(seconds=interval / 2), "succeeded"),
        (start - timedelta(seconds=interval), "failed"),
        (end + timedelta(seconds=interval), "failed"),
    ]
    db.ingest_batch(s, [
        {"id": new_id(), "time": at.isoformat(), "kind": "sensor",
         "agent": {"product": "codex-cli"}, "source": {"collector": "hook-runtime"},
         "hook": {"outcome": outcome}}
        for at, outcome in records
    ])
    result = guardrail.stats(db, t["id"], range_name)
    series = result["series"]
    assert result["totals"]["total"] == 0
    assert result["executions"] == {"total": 3, "failed": 1}
    assert len(series) == int(duration.total_seconds() // interval)
    assert series[1]["executions"] == {"total": 2, "failed": 1}
    assert series[-1]["executions"] == {"total": 1, "failed": 0}
    assert all(b["executions"] == {"total": 0, "failed": 0} for b in series[2:-1])
    assert series[0]["executions"] == {"total": 0, "failed": 0}
    assert series[0]["start"] == result["since"]
    assert series[-1]["start"] + timedelta(seconds=interval) == result["until"]


def test_active_counts_live_sessions_users_actions_and_labels(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])

    # Hook and transcript events carry only the OS user, as in production.
    def event(kind, session, user="alice", at=None, **body):
        return {"id": new_id(), "time": (at or now()).isoformat(), "kind": kind,
                "agent": {"product": "codex-cli"}, "host": {"user": user},
                "session": {"id": session}, "source": {"collector": "hook"}, **body}

    def codex(record, user="alice"):
        record.update(agent={"product": "codex-cli"}, host={"user": user})
        return record

    # Native telemetry of the same session: the account, no content.
    def native(kind, session, **body):
        record = event(kind, session, **body)
        record.update(source="otlp", agent={"product": "codex-cli", "account": "alice@example.com"})
        return record

    duplicate_prompt = native("prompt", "a", prompt={"length": 13})
    duplicate_call = native("command", "a", command={"text": "make"}, tool={"name": "Bash", "call_id": "c1"})
    native_only = native("prompt", "n", prompt={"length": 4})
    # Hooks alone (transcripts off, the default) report decisions, not actions,
    # so every native action of such a session is the only record of it.
    hook_only = [
        native("prompt", "h", prompt={"length": 9}),
        native("command", "h", command={"text": "ls"}, tool={"name": "Bash", "call_id": "h1"}),
        native("command", "h", command={"text": "pwd"}),
        native("tool.result", "h", tool={"name": "Bash"}),
    ]
    db.ingest_batch(s, [
        event("prompt", "a", text="fix the build"),
        event("command", "a", command={"text": "make"}, tool={"name": "Bash", "call_id": "c1"}),
        event("tool.result", "a", tool={"name": "Bash", "call_id": "c1", "output": "ok"}),
        codex(decision("allow", session="a")),
        duplicate_prompt, duplicate_call, native_only, *hook_only,
        dict(codex(decision("allow", session="h")), tool={"name": "Bash", "call_id": "h1"}),
        event("prompt", "b", user="bob", text="hi"),
        event("session.end", "b", user="bob"),
        event("prompt", "c", user="carol", text="deploy"),
        codex(decision("ask", "push", session="c", enforced="deny"), "carol"),
        # Backfilled from an old transcript: arrives now, happened yesterday.
        event("prompt", "old", user="dave", at=now() - timedelta(days=1), text="old work"),
    ])
    db.execute(
        "INSERT INTO telemetry_exports(id,tenant_id,sensor_id,signal,batch_id,payload_sha256,record_count,service_names,payload)"
        " VALUES($1,$2,$3,'logs',$4,'x',0,'{}','{}'::jsonb)",
        new_id(), t["id"], s["id"], new_id(),
    )
    export = db.scalar("SELECT id FROM telemetry_exports WHERE tenant_id=$1", t["id"])
    db.execute(
        "UPDATE events SET export_id=$1 WHERE id = ANY($2::uuid[])",
        export, [duplicate_prompt["id"], duplicate_call["id"], native_only["id"]]
        + [e["id"] for e in hook_only],
    )
    row = guardrail.active(db, t["id"])
    # Sessions a, c, h, and n; alice counts once across a, h, and n although
    # hook events name only her OS user; the backfilled session is history.
    assert (row["sessions"], row["users"]) == (4, 2)
    # Prompts of a, b (since ended), c, h, and n count; the native prompt and
    # call of session a repeat collector events and do not; session h's native
    # actions count, including the call whose id its hook decision shares.
    assert (row["prompts"], row["tool_calls"], row["tool_results"]) == (5, 3, 2)
    assert (row["decisions"], row["allow"], row["deny"], row["ask"]) == (3, 2, 1, 0)
    assert guardrail.active(db, tenant(db)["id"])["sessions"] == 0


def test_active_guardrail_metrics_include_retries_without_exposing_provider_prices(db):
    t, other = tenant(db), tenant(db)
    s, _, _ = sensor(db, t["id"])
    event_id = new_id()

    def call(attempt, *, duration=100, cost="0.001", status="completed",
             minutes=1, tid=None, model="jev1.13", provider="typesafe", purpose="detection"):
        started = now() - timedelta(minutes=minutes)
        db.execute(
            """INSERT INTO model_usage(id,tenant_id,sensor_id,event_id,attempt,
                   purpose,provider,model,started_at,completed_at,status,cost_usd)
               VALUES($1,$2,$3,$4,$5,$12,$6,$7,$8,$9,$10,$11)""",
            new_id(), tid or t["id"], s["id"], event_id, attempt,
            provider, model, started,
            started + timedelta(milliseconds=duration) if duration is not None else None,
            status, Decimal(cost) if cost is not None else None, purpose,
        )

    call(1, duration=100, cost="0.002", status="error")
    call(2, duration=200, cost="0.003", purpose="guardrail")  # A retry is another billed attempt.
    call(3, duration=300, cost=None)
    call(4, duration=None, cost=None, status="pending")
    call(5, duration=9000, minutes=6)
    call(6, duration=9000, tid=other["id"])
    call(7, duration=9000, model="another-model")
    call(8, duration=9000, provider="another-provider")
    jev = guardrail.active(db, t["id"])["jev"]
    assert (jev["calls"], jev["pending_calls"], jev["failed_calls"]) == (4, 1, 1)
    assert "priced_calls" not in jev and "cost_usd" not in jev
    assert jev["latency_samples"] == 3
    assert jev["latency_p95_ms"] == pytest.approx(290)
    for attempt, status in enumerate(("pending", "completed", "error"), 9):
        call(attempt, purpose="verification", model="jev-1.13.0", status=status,
             duration=None if status == "pending" else 100)
    assert guardrail.active(db, t["id"])["jev"] == jev
    empty = guardrail.active(db, tenant(db)["id"])["jev"]
    assert empty["calls"] == empty["latency_samples"] == 0
    assert "cost_usd" not in empty and empty["latency_p95_ms"] is None
    db.execute("UPDATE model_usage SET cost_usd=NULL WHERE tenant_id=$1", t["id"])
    assert guardrail.active(db, t["id"])["jev"] == jev
    db.execute("UPDATE model_usage SET cost_usd=0 WHERE tenant_id=$1", t["id"])
    assert guardrail.active(db, t["id"])["jev"] == jev
