"""Ordinary risk escalation through PostgreSQL and the authenticated report API."""

from copy import deepcopy
from importlib.resources import files
from types import SimpleNamespace

from psycopg.types.json import Jsonb
import pytest

from openaidr.core.event import new_id
from openaidr.server import detection_history, detection_selection, ordinary_session_detection as ordinary
from openaidr.server import session_aggregation as aggregation, session_investigator as investigator, session_ownership
from test_detection_pipeline import pipeline
from test_inline_guardrail import browser, system as system
from test_session_aggregation import detection_settings, registered
from test_session_investigator import RUNTIME, TOOLS, finding_result, finish_steps
from test_session_ownership import event
from test_store import db as db


def configure(system, **changes):
    return detection_settings(system, **{
        "risk_threshold": "100", "max_runtime_seconds": 120, "max_tokens_per_attempt": 200000,
        "max_cost_usd_per_attempt": "10", "hourly_tokens": 400000, "hourly_cost_usd": "20",
        **changes,
    })


def captured(system, scores=(80, 40), *, closed=True, device="sensor"):
    native = new_id()
    events = [event(native) for _ in scores]
    if closed:
        events.append(event(native, kind="session.end"))
    sensor = system.sensors[device][0]
    system.db.ingest_batch(sensor, events)
    for value, score in zip(events, scores):
        system.db.execute(
            "UPDATE events SET risk=$3 WHERE tenant_id=$1 AND id=$2",
            sensor["tenant_id"], value["id"], Jsonb({"status": "scored", "score": score}),
        )
    session_id = system.db.scalar("SELECT id FROM agent_sessions WHERE tenant_id=$1 AND external_id=$2",
                                  sensor["tenant_id"], native)
    return SimpleNamespace(id=session_id, events=events, native=native, sensor=sensor)


def finalize(system, value, **options):
    return ordinary.finalize(system.db, value.sensor["tenant_id"], value.id, scheduling_enabled=True,
                             worker_ready=True, supported_models=["gpt-6.1-sol"], **options)


def test_routing_uses_unique_measured_scores_and_reuses_the_job(system):
    configure(system)
    high = captured(system)
    duplicate = deepcopy(high.events[0])
    duplicate["id"] = new_id()
    duplicate["evidence"]["observation_id"] = duplicate["id"]
    system.db.ingest_batch(high.sensor, [duplicate])
    system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", duplicate["id"], Jsonb({"status": "scored", "score": 80}))
    first = finalize(system, high)
    assert first["risk_total"] == "120" and first["counts"]["assessed"] == 2
    assert first["routing"]["status"] == "queued"
    assert finalize(system, high)["routing"]["job_id"] == first["routing"]["job_id"]
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 1
    for scores in ((40, 60), (0,), (None, "90", -1, 101)):
        low = captured(system, scores)
        result = finalize(system, low)
        assert result["routing"]["status"] == "below_threshold"
        assert result["snapshot_id"] is None
    result = pipeline(system)
    assert result["actions_scored"] == 5
    assert result["sessions_eligible"] == 3
    assert result["sessions_escalated"] == 1
    assert pipeline(system, user="foreign")["actions_scored"] == 0
    assert system.db.scalar("SELECT count(*) FROM model_usage") == 0


def test_ordinary_report_keeps_evidence_gaps_and_is_tenant_scoped(system):
    configure(system)
    value = captured(system)
    state = finalize(system, value)
    claim = aggregation.claim_job(system.db, "ordinary-test", system.tenant["id"], worker_ready=True)
    assert claim is not None
    attempt = SimpleNamespace(claim=claim, result={"logical_id": value.events[0]["evidence"]["logical_id"]})
    investigator.prepare_attempt(system.db, claim, RUNTIME)
    step = investigator.next_step(system.db, claim)
    assert not step["history_allowed"]
    assert investigator.read_tool(system.db, claim, step["id"], "forbidden-history", "search_sessions", {}) == {
        "error": {"code": "record_unavailable"}}
    anchor = system.db.one(
        "SELECT ordinal,kind,source_id,body FROM session_snapshot_items WHERE snapshot_id=$1 AND source_id=$2 AND kind='observation'",
        state["snapshot_id"], value.events[0]["id"],
    )
    report = finding_result(attempt, anchor)
    report["findings"][0]["action_outcomes"] = []
    finish_steps(system, attempt, lambda _: report)
    assert investigator.publish_report(system.db, claim)
    job_id = claim["job_id"]
    response = browser(system, "GET", "session-investigations/" + job_id, user="admin")
    assert response.status_code == 200, response.text
    assert response.json()["session_id"] == value.id
    assert response.json()["report"]["source_coverage"]["status"] == "incomplete"
    assert "unverified_history" in response.json()["report"]["gaps"]
    assert browser(system, "GET", "session-investigations/" + job_id, user="foreign").status_code == 404
    assert browser(system, "GET", "me/session-investigations/" + job_id, user="owner").status_code == 404
    summary = browser(system, "GET", f"sessions/{value.id}/detection").json()
    assert summary["registration"] is None
    assert summary["detection"]["risk_total"] == "120"
    assert summary["investigations"]["items"][0]["id"] == job_id
    assert summary["investigations"]["items"][0]["snapshot_current"]
    assert browser(system, "GET", "session-snapshots/" + state["snapshot_id"]).status_code == 200
    findings = browser(system, "GET", "findings?source=incident").json()["items"]
    assert len(findings) == 1 and findings[0]["session_id"] == value.id
    assert pipeline(system)["sessions_inspected"] == pipeline(system)["sessions_with_alerts"] == 1
    assert aggregation.claim_job(system.db, "repeat-test", system.tenant["id"], worker_ready=True) is None


@pytest.mark.parametrize("verified", [False, True])
def test_history_tool_admission_requires_verified_session_ownership(system, verified):
    from test_session_investigator import proposal

    configure(system)
    value = captured(system)
    if verified:
        detection_history.save_owner(system.db, system.tenant["id"], value.id,
                                     system.users["owner"]["id"], system.users["admin"])
    finalize(system, value)
    claim = aggregation.claim_job(system.db, "history-tools", system.tenant["id"], worker_ready=True)
    investigator.prepare_attempt(system.db, claim, RUNTIME)
    step = investigator.next_step(system.db, claim)
    assert step["history_allowed"] is verified
    request = proposal(step)
    request["request"]["tools"] = deepcopy(TOOLS)
    if verified:
        admitted = investigator.admit_call(system.db, claim, step["id"], request)
        assert admitted["max_output_tokens"] > 0
        assert system.db.scalar("SELECT count(*) FROM model_usage") == 1
    else:
        with pytest.raises(investigator.InvestigationStopped) as stopped:
            investigator.admit_call(system.db, claim, step["id"], request)
        assert stopped.value.code == "invalid_request"
        assert system.db.scalar("SELECT count(*) FROM model_usage") == 0


def test_late_evidence_supersedes_unstarted_work_and_pending_scores_delay_routing(system):
    configure(system)
    value = captured(system)
    before = finalize(system, value)
    late = event(value.native)
    system.db.ingest_batch(value.sensor, [late])
    system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", late["id"], Jsonb({"status": "pending"}))
    assert aggregation.claim_job(system.db, "late-test", worker_ready=True) is None
    pending = finalize(system, value)
    assert pending["routing"]["status"] == "waiting_coverage"
    assert system.db.scalar("SELECT state FROM session_investigation_jobs WHERE id=$1", before["routing"]["job_id"]) == "superseded"
    assert system.db.scalar("SELECT count(*) FROM session_snapshot_items WHERE snapshot_id=$1", before["snapshot_id"]) == 5
    system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", late["id"], Jsonb({"status": "scored", "score": 90}))
    system.db.execute("UPDATE agent_sessions SET ended_at=last_event_at WHERE id=$1", value.id)
    after = finalize(system, value)
    assert after["risk_total"] == "210"
    assert after["snapshot_id"] != before["snapshot_id"]
    assert after["routing"]["job_id"] != before["routing"]["job_id"]


def test_snapshot_policy_lookup_is_bounded_and_preserves_reference_scope(system, monkeypatch):
    configure(system, risk_threshold="0")
    policy = {"revision": 3, "prompt": "Retained company policy"}
    checks = {}
    for device, count in (("sensor", 20000), ("peer_sensor", 1), ("foreign_sensor", 1)):
        sensor = system.sensors[device][0]
        checks[device] = new_id()[:-1] + "a"
        system.db.execute(
            """INSERT INTO ordinary_hook_checks(id,tenant_id,sensor_id,request_id,payload_sha256,
                   product,hook_event,session_id,mode,settings_version,policy_version,status,risk_settings)
               SELECT CASE WHEN n=1 THEN $5::uuid ELSE gen_random_uuid() END,
                   $1,$2,gen_random_uuid(),'test','codex-cli','PreToolUse',
                   'test','shadow',1,1,'unavailable',$3 FROM generate_series(1,$4) n""",
            sensor["tenant_id"], sensor["id"], Jsonb({"company_policy": policy}), count, checks[device],
        )
    system.db.execute("ANALYZE ordinary_hook_checks")
    references = [checks["sensor"], checks["peer_sensor"], checks["foreign_sensor"],
                  "invalid", "", checks["sensor"].upper(), None, 42]
    value = captured(system, (80,) * len(references))
    for target, reference in zip(value.events, references):
        system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", target["id"],
                          Jsonb({"status": "scored", "score": 80, "hook_check_id": reference}))
    queries, execute = [], system.db.execute

    def capture_copy(query, *args, **kwargs):
        if query.startswith("INSERT INTO session_snapshot_items"):
            queries.append((query, args))
        return execute(query, *args, **kwargs)

    monkeypatch.setattr(system.db, "execute", capture_copy)
    state = finalize(system, value)
    items = system.db.many(
        "SELECT kind,source_id,body FROM session_snapshot_items WHERE snapshot_id=$1 ORDER BY ordinal",
        state["snapshot_id"],
    )
    assessments = {item["source_id"]: item["body"] for item in items if item["kind"] == "event_assessment"}
    assert len(items) == 2 * len(references) + 1
    for index, target in enumerate(value.events[:-1]):
        assert assessments[target["id"]]["company_policy"] == (policy if index == 0 else None)
        assert assessments[target["id"]]["risk"]["hook_check_id"] == references[index]
    assert system.db.scalar("SELECT count(*) FROM ordinary_session_input_dirty WHERE session_id=$1", value.id) == 0

    query, args = queries[0]
    # Inspect the actual evidence read without inserting into the sealed snapshot again.
    query = query[query.index("SELECT "):]
    plan = system.db.scalar("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + query, *args)[0]["Plan"]
    scans, pending = [], [plan]
    while pending:
        node = pending.pop()
        pending.extend(node.get("Plans", []))
        if node.get("Relation Name") == "ordinary_hook_checks":
            scans.append(node)
    assert scans and sum(node.get("Shared Hit Blocks", 0) + node.get("Shared Read Blocks", 0)
                         for node in scans) < 100, scans


@pytest.mark.parametrize("revoke", ["sensor", "tenant", "settings"])
def test_revocation_prevents_ordinary_dispatch(system, revoke):
    configure(system)
    value = captured(system)
    finalize(system, value)
    claim = aggregation.claim_job(system.db, "revoke-test", worker_ready=True)
    assert claim
    if revoke == "sensor":
        system.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", value.sensor["id"])
    elif revoke == "tenant":
        system.db.execute("UPDATE tenants SET status='suspended' WHERE id=$1", system.tenant["id"])
    else:
        configure(system, enabled=False)
    with pytest.raises(investigator.InvestigationStopped):
        investigator.prepare_attempt(system.db, claim, RUNTIME)
    assert system.db.scalar("SELECT count(*) FROM model_usage") == 0


def test_idle_grace_and_disabled_worker_do_not_dispatch(system):
    configure(system, delivery_grace_seconds=10, gap_wait_seconds=10)
    value = captured(system, closed=False)
    assert finalize(system, value)["snapshot_id"] is None
    system.db.execute("UPDATE agent_sessions SET last_event_at=now()-interval '2 minutes' WHERE id=$1", value.id)
    system.db.execute("UPDATE ordinary_session_detection SET state=jsonb_set(state,'{last_received_at}',to_jsonb((now()-interval '1 minute')::text)) WHERE session_id=$1", value.id)
    result = ordinary.finalize(system.db, system.tenant["id"], value.id, scheduling_enabled=False)
    assert result["routing"]["reason"] == "scheduling_disabled"
    assert result["snapshot_id"]
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0
    assert finalize(system, value)["routing"]["status"] == "queued"


def test_changed_idle_setting_rechecks_queued_sessions_before_admission(system):
    configure(system, idle_seconds=60)
    value = captured(system, closed=False)
    system.db.execute("UPDATE agent_sessions SET last_event_at=now()-interval '2 minutes' WHERE id=$1", value.id)
    before = finalize(system, value)
    assert before["routing"]["status"] == "queued"
    configure(system, idle_seconds=600)
    assert aggregation.claim_job(system.db, "idle-test", worker_ready=True) is None
    assert finalize(system, value)["routing"]["status"] == "waiting_coverage"
    assert aggregation.claim_job(system.db, "idle-test", worker_ready=True) is None
    configure(system, idle_seconds=60)
    after = finalize(system, value)
    assert after["routing"]["job_id"] == before["routing"]["job_id"]
    assert aggregation.claim_job(system.db, "idle-test", worker_ready=True) is not None


def test_committing_older_wakeup_after_snapshot_cannot_lose_late_scores(system):
    configure(system)
    system.db.execute("INSERT INTO tenant_telemetry_retention(tenant_id,mode) VALUES($1,'90')", system.tenant["id"])
    value = captured(system)
    before = finalize(system, value)
    with system.db.transaction() as writer:
        # The wakeup sequence is allocated before the snapshot but commits
        # after it, reproducing a delivery/scoring race without thread timing.
        system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", value.events[0]["id"],
                          Jsonb({"status": "scored", "score": 100}), conn=writer)
        first = finalize(system, value)
        assert first["risk_total"] == "120"
        assert first["snapshot_id"] == before["snapshot_id"]
    assert aggregation.claim_job(system.db, "late-score", worker_ready=True) is None
    second = finalize(system, value)
    assert second["risk_total"] == "140"
    assert second["snapshot_id"] != first["snapshot_id"]


def test_timer_reevaluation_reuses_evidence_but_rechecks_ranking(system, monkeypatch):
    configure(system, selection_policy="risk_budget", investigation_percent="50")
    system.db.execute("INSERT INTO tenant_telemetry_retention(tenant_id,mode) VALUES($1,'90')", system.tenant["id"])
    target, competitor = captured(system, (85, 80)), captured(system, (90, 90))
    finalize(system, target)
    finalize(system, competitor)
    before = finalize(system, target)
    assert before["routing"]["status"] == "below_threshold"
    queries, execute = [], system.db._execute

    def observe(conn, query, args, mode):
        queries.append(query)
        return execute(conn, query, args, mode)

    monkeypatch.setattr(system.db, "_execute", observe)
    after = finalize(system, target)
    assert after["risk_total"] == before["risk_total"]
    assert after["coverage"] == before["coverage"]
    assert after["routing"]["status"] == "below_threshold"
    assert not any(query.startswith("WITH actions AS") or query.startswith("SELECT DISTINCT gap") for query in queries)
    assert sum(query.startswith("WITH population AS") for query in queries) == 1
    # A different session changes the ranking without dirtying the target.
    for value in competitor.events[:-1]:
        system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", value["id"], Jsonb({"status": "scored", "score": 40}))
    finalize(system, competitor)
    queries.clear()
    selected = finalize(system, target)
    assert selected["routing"]["reason"] == "session_risk"
    assert selected["routing"]["status"] == "queued"
    assert not any(query.startswith("WITH actions AS") or query.startswith("SELECT DISTINCT gap") for query in queries)


@pytest.mark.parametrize("change", ["risk", "event", "settings", "legacy"])
def test_evidence_summary_invalidates_on_new_inputs_and_old_state(system, monkeypatch, change):
    configure(system)
    system.db.execute("INSERT INTO tenant_telemetry_retention(tenant_id,mode) VALUES($1,'90')", system.tenant["id"])
    value = captured(system)
    before = finalize(system, value)
    if change == "risk":
        system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", value.events[0]["id"], Jsonb({"status": "scored", "score": 95}))
    elif change == "event":
        added = event(value.native)
        system.db.ingest_batch(value.sensor, [added])
        system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", added["id"], Jsonb({"status": "scored", "score": 70}))
    elif change == "settings":
        configure(system, action_risk_threshold=90)
    else:
        system.db.execute("UPDATE ordinary_session_detection SET state=state-'evidence_summary' WHERE session_id=$1", value.id)
    queries, execute = [], system.db._execute

    def observe(conn, query, args, mode):
        queries.append(query)
        return execute(conn, query, args, mode)

    monkeypatch.setattr(system.db, "_execute", observe)
    result = finalize(system, value)
    assert result["risk_total"] == {"risk": "135", "event": "190"}.get(change, before["risk_total"])
    assert result["evidence_summary"]["high_actions"] == {"risk": 1, "event": 2, "settings": 0, "legacy": 1}[change]
    assert sum(query.startswith("WITH actions AS") for query in queries) == 1
    assert sum(query.startswith("SELECT DISTINCT gap") for query in queries) == 1
    assert system.db.scalar("SELECT count(*) FROM ordinary_session_input_dirty WHERE session_id=$1", value.id) == 0


@pytest.mark.parametrize("during_snapshot", [False, True])
def test_evidence_summary_invalidates_after_partition_retirement(system, monkeypatch, during_snapshot):
    from openaidr.server import telemetry_retention
    from openaidr.server.store import now

    configure(system)
    value = captured(system)
    system.db.execute("UPDATE events SET risk=$2 WHERE session_id=$1 AND risk IS NULL", value.id,
                      Jsonb({"status": "scored", "score": 0}))
    before = finalize(system, value)
    tenant = system.tenant["id"]
    system.db.set_detect_cursor(tenant, {"time": now(), "id": "ffffffff-ffff-ffff-ffff-ffffffffffff"})
    day = system.db.scalar("SELECT storage_day FROM events WHERE id=$1", value.events[0]["id"])

    def retire():
        system.db.execute("INSERT INTO tenant_telemetry_retention(tenant_id,mode) VALUES($1,'7')", tenant)
        with system.db.transaction() as conn:
            assert telemetry_retention._drop(system.db, tenant, day, conn)
        assert system.db.scalar("SELECT count(*) FROM ordinary_session_input_dirty WHERE session_id=$1", value.id) == 0

    if during_snapshot:
        scalar = system.db.scalar

        def retire_after_snapshot(query, *args, **kwargs):
            result = scalar(query, *args, **kwargs)
            if query.startswith("SELECT pg_try_advisory_xact_lock") and args == ("ordinary-session-detection:" + value.id,):
                retire()
            return result

        monkeypatch.setattr(system.db, "scalar", retire_after_snapshot)
    else:
        retire()
    after = finalize(system, value)
    assert before["risk_total"] == "120"
    assert after["risk_total"] is None and after["counts"]["logical_targets"] == 0
    assert after["snapshot_id"] is None
    assert (after["evidence_summary"]["retired_at"] is None) == during_snapshot
    assert system.db.scalar("SELECT state FROM session_investigation_jobs WHERE id=$1", before["routing"]["job_id"]) == "superseded"


def test_cached_batch_ranks_once_against_the_complete_tenant_population(system, monkeypatch):
    configure(system, selection_policy="risk_budget", investigation_percent="50")
    tenant = system.tenant["id"]
    system.db.execute("INSERT INTO tenant_telemetry_retention(tenant_id,mode) VALUES($1,'90')", tenant)
    targets = [captured(system, scores) for scores in ((85, 80), (90, 90), (96,))]
    outside_batch = captured(system, (0,))
    captured(system, (99,), device="foreign_sensor")
    for value in [*targets, outside_batch]:
        finalize(system, value)
    for value in targets:
        finalize(system, value)
    ids = [value.id for value in targets]
    system.db.execute("""UPDATE ordinary_session_detection SET next_evaluation_at=now()-interval '1 minute',
        updated_at=now()-interval '1 minute' WHERE session_id=ANY($1::uuid[])""", ids)
    system.db.execute("UPDATE ordinary_session_detection SET next_evaluation_at=NULL WHERE session_id=$1", outside_batch.id)
    settings = aggregation.get_settings(system.db, tenant)
    with system.db.transaction() as conn:
        expected = {ident: detection_selection.select(system.db, tenant, ident, settings, conn) for ident in ids}
    signal_times = system.db.many("SELECT session_id,updated_at FROM session_detection_signals WHERE tenant_id=$1 ORDER BY session_id", tenant)
    queries, execute = [], system.db._execute

    def observe(conn, query, args, mode):
        queries.append(query)
        return execute(conn, query, args, mode)

    monkeypatch.setattr(system.db, "_execute", observe)
    assert ordinary.finalize_pending(system.db, tenant, scheduling_enabled=True, worker_ready=True,
                                     supported_models=["gpt-6.1-sol"]) == len(targets)
    rows = system.db.many("SELECT session_id,state FROM ordinary_session_detection WHERE session_id=ANY($1::uuid[])", ids)
    assert {row["session_id"]: row["state"]["selection"] for row in rows} == expected
    assert all(row["state"]["selection"]["signals"]["population_sessions"] == 4 for row in rows)
    assert sum(query.startswith("WITH population AS") for query in queries) == 1
    assert not any(query.startswith("WITH actions AS") or query.startswith("SELECT DISTINCT gap") for query in queries)
    assert system.db.many("SELECT session_id,updated_at FROM session_detection_signals WHERE tenant_id=$1 ORDER BY session_id", tenant) == signal_times


def test_cached_batches_keep_global_worker_tenants_separate(system, monkeypatch):
    configure(system, selection_policy="risk_budget", investigation_percent="100")
    tenant, foreign = system.tenant["id"], system.users["foreign"]["tenant_id"]
    settings = aggregation.get_settings(system.db, tenant)
    aggregation.save_settings(system.db, foreign, {key: settings[key] for key in aggregation.SETTINGS}, {})
    groups = {}
    for scope, device, age in ((tenant, "sensor", 2), (foreign, "foreign_sensor", 1)):
        system.db.execute("INSERT INTO tenant_telemetry_retention(tenant_id,mode) VALUES($1,'90')", scope)
        values = [captured(system, (96,), device=device), captured(system, (97,), device=device)]
        for value in values:
            finalize(system, value)
        groups[scope] = {value.id for value in values}
        system.db.execute("""UPDATE ordinary_session_detection SET next_evaluation_at=now()-interval '1 minute',
            updated_at=now()-$2*interval '1 minute' WHERE tenant_id=$1""", scope, age)
    rankings, many = [], system.db.many

    def observe(query, *args, **kwargs):
        if query.startswith("WITH population AS"):
            rankings.append((args[0], set(args[8])))
        return many(query, *args, **kwargs)

    monkeypatch.setattr(system.db, "many", observe)
    assert ordinary.finalize_pending(system.db, scheduling_enabled=True, worker_ready=True,
                                     supported_models=["gpt-6.1-sol"]) == 4
    assert rankings == [(tenant, groups[tenant]), (foreign, groups[foreign])]
    for row in system.db.many("SELECT tenant_id,session_id,state FROM ordinary_session_detection"):
        assert row["session_id"] in groups[row["tenant_id"]]
        assert row["state"]["selection"]["signals"]["population_sessions"] == 2
        assert row["state"]["routing"]["status"] == "queued"


def test_cached_batch_preserves_late_risk_wakeups(system, monkeypatch):
    configure(system, selection_policy="risk_budget", investigation_percent="100")
    tenant = system.tenant["id"]
    system.db.execute("INSERT INTO tenant_telemetry_retention(tenant_id,mode) VALUES($1,'90')", tenant)
    targets = [captured(system, (80, 80)), captured(system, (85, 85))]
    for value in targets:
        finalize(system, value)
    for value in targets:
        finalize(system, value)
    ids = [value.id for value in targets]
    system.db.execute("""UPDATE ordinary_session_detection SET next_evaluation_at=now()-interval '1 minute',
        updated_at=now()-interval '1 minute' WHERE session_id=ANY($1::uuid[])""", ids)
    execute = system.db._execute
    changed = False

    def late_risk(conn, query, args, mode):
        nonlocal changed
        result = execute(conn, query, args, mode)
        if query.startswith("WITH population AS") and not changed:
            changed = True
            system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", targets[0].events[0]["id"],
                              Jsonb({"status": "scored", "score": 100}))
        return result

    monkeypatch.setattr(system.db, "_execute", late_risk)
    assert ordinary.finalize_pending(system.db, tenant, scheduling_enabled=True, worker_ready=True,
                                     supported_models=["gpt-6.1-sol"]) == 2
    assert changed
    state = system.db.one("SELECT * FROM ordinary_session_detection WHERE session_id=$1", ids[0])
    assert state["state"]["risk_total"] == "160"
    assert system.db.scalar("SELECT count(*) FROM ordinary_session_input_dirty WHERE session_id=$1", ids[0]) == 1
    # Claim validation rejects the stale snapshot before another provider call.
    job = system.db.one("SELECT * FROM session_investigation_jobs WHERE id=$1", state["state"]["routing"]["job_id"])
    with system.db.transaction() as conn:
        assert not ordinary.current(system.db, job, aggregation.get_settings(system.db, tenant, conn), conn)
    refreshed = finalize(system, targets[0])
    assert refreshed["risk_total"] == "180"
    assert refreshed["snapshot_id"] != state["snapshot_id"]


def test_cached_batch_isolates_a_revoked_sensor_with_a_savepoint(system, monkeypatch):
    configure(system, selection_policy="risk_budget", investigation_percent="100")
    tenant = system.tenant["id"]
    system.db.execute("INSERT INTO tenant_telemetry_retention(tenant_id,mode) VALUES($1,'90')", tenant)
    revoked, allowed = captured(system, (96,)), captured(system, (97,), device="peer_sensor")
    for value in (revoked, allowed):
        finalize(system, value)
    ids = [revoked.id, allowed.id]
    system.db.execute("""UPDATE ordinary_session_detection SET next_evaluation_at=now()-interval '1 minute',
        updated_at=now()-interval '1 minute' WHERE session_id=ANY($1::uuid[])""", ids)
    before = system.db.one("SELECT * FROM ordinary_session_detection WHERE session_id=$1", revoked.id)
    execute = system.db._execute
    changed = False

    def revoke_after_ranking(conn, query, args, mode):
        nonlocal changed
        result = execute(conn, query, args, mode)
        if query.startswith("WITH population AS") and not changed:
            changed = True
            system.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", revoked.sensor["id"])
        return result

    monkeypatch.setattr(system.db, "_execute", revoke_after_ranking)
    assert ordinary.finalize_pending(system.db, tenant, scheduling_enabled=True, worker_ready=True,
                                     supported_models=["gpt-6.1-sol"]) == 2
    assert changed
    assert system.db.one("SELECT * FROM ordinary_session_detection WHERE session_id=$1", revoked.id) == before
    assert system.db.scalar("SELECT updated_at>$2 FROM ordinary_session_detection WHERE session_id=$1", allowed.id, before["updated_at"])


@pytest.mark.parametrize("after_first", [False, True])
def test_exhausted_batch_budget_preserves_individual_progress(system, monkeypatch, after_first):
    import time

    configure(system, selection_policy="risk_budget", investigation_percent="100")
    tenant = system.tenant["id"]
    system.db.execute("INSERT INTO tenant_telemetry_retention(tenant_id,mode) VALUES($1,'90')", tenant)
    targets = [captured(system, (96,)), captured(system, (97,))]
    for value in targets:
        finalize(system, value)
    ids = sorted(value.id for value in targets)
    system.db.execute("""UPDATE ordinary_session_detection SET next_evaluation_at=now()-interval '1 minute',
        updated_at=now()-interval '1 minute' WHERE session_id=ANY($1::uuid[])""", ids)
    previous = system.db.many("SELECT session_id,updated_at FROM ordinary_session_detection WHERE tenant_id=$1", tenant)
    offset = 0
    clock = SimpleNamespace(monotonic=lambda: time.monotonic() + offset)
    monkeypatch.setattr(ordinary, "time", clock)
    monkeypatch.setattr(aggregation, "time", clock)
    run = ordinary.finalize
    individual = []
    advanced = False

    def consume_budget(st, tenant_id, session_id, **options):
        nonlocal offset, advanced
        shared = options.get("_conn") is not None
        if not shared:
            individual.append(session_id)
        if shared and not advanced and not after_first:
            offset += 16
            advanced = True
        result = run(st, tenant_id, session_id, **options)
        if shared and not advanced:
            offset += 16
            advanced = True
        return result

    monkeypatch.setattr(ordinary, "finalize", consume_budget)
    assert ordinary.finalize_pending(system.db, tenant, scheduling_enabled=True, worker_ready=True,
                                     supported_models=["gpt-6.1-sol"]) == 2
    assert advanced
    assert set(individual) == set(ids[1:] if after_first else ids)
    for row in previous:
        assert system.db.scalar("SELECT updated_at>$2 FROM ordinary_session_detection WHERE session_id=$1",
                                row["session_id"], row["updated_at"])


def test_contended_authority_leaves_work_pending_for_retry(system):
    configure(system)
    value = captured(system)
    options = {"scheduling_enabled": True, "worker_ready": True, "supported_models": ["gpt-6.1-sol"]}
    with system.db.transaction() as writer:
        system.db.one("SELECT id FROM sensors WHERE id=$1 FOR UPDATE", value.sensor["id"], conn=writer)
        assert ordinary.finalize_pending(system.db, **options) == 1
        assert system.db.scalar("SELECT count(*) FROM ordinary_session_detection") == 0
        assert system.db.scalar("SELECT count(*) FROM ordinary_session_input_dirty") > 0
    assert ordinary.finalize_pending(system.db, **options) == 1
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs WHERE state='queued'") == 1
    assert system.db.scalar("SELECT count(*) FROM ordinary_session_input_dirty") == 0


def test_ordinary_claims_share_tenant_concurrency_and_hourly_budgets(system):
    configure(system, hourly_attempts=1)
    first, second = captured(system), captured(system)
    finalize(system, first)
    finalize(system, second)
    claim = aggregation.claim_job(system.db, "first-worker", worker_ready=True)
    assert claim
    assert aggregation.claim_job(system.db, "second-worker", worker_ready=True) is None
    investigator.prepare_attempt(system.db, claim, RUNTIME)
    finish_steps(system, SimpleNamespace(claim=claim))
    report = investigator.publish_report(system.db, claim)
    assert report["report_status"] == "inconclusive"
    assert aggregation.claim_job(system.db, "after-completion", worker_ready=True) is None
    assert system.db.scalar("SELECT count(*) FROM session_investigation_attempts") == 1


def bind_owner(system, session, owner="owner"):
    return detection_history.save_owner(system.db, system.tenant["id"], session.id,
                                        system.users[owner]["id"], system.users["admin"])


def test_risk_budget_prioritizes_peak_and_distinct_actions_over_busy_low_scores(system):
    configure(system, selection_policy="risk_budget", sample_percent="0")
    busy = captured(system, (20,) * 10)
    moderate = captured(system, (75, 75))
    strongest = captured(system, (90, 85))
    assert finalize(system, busy)["routing"]["status"] == "below_threshold"
    assert finalize(system, moderate)["routing"]["status"] == "below_threshold"
    state = finalize(system, strongest)
    assert state["routing"]["reason"] == "session_risk"
    assert state["selection"]["signals"]["population_sessions"] == 3
    assert state["selection"]["signals"]["risk_slots"] == 1
    assert state["selection"]["signals"]["high_risk_actions"] == 2
    assert aggregation.claim_job(system.db, "selected", worker_ready=True)


def test_urgent_active_session_bypasses_budget_and_reuses_same_evidence(system):
    configure(system, selection_policy="risk_budget", sample_percent="0")
    value = captured(system, (99,), closed=False)
    first = finalize(system, value)
    assert first["routing"]["reason"] == "urgent_risk"
    assert first["coverage"]["status"] == "incomplete"
    assert finalize(system, value)["routing"]["job_id"] == first["routing"]["job_id"]
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 1
    assert aggregation.claim_job(system.db, "urgent", worker_ready=True)


def test_user_pattern_groups_recent_verified_history_and_serializes_user_work(system):
    configure(system, selection_policy="risk_budget", sample_percent="0", max_concurrent=2)
    sessions = [captured(system, (75,)) for _ in range(3)]
    for session in sessions:
        bind_owner(system, session)
    assert finalize(system, sessions[0])["routing"]["status"] == "below_threshold"
    assert finalize(system, sessions[1])["routing"]["status"] == "below_threshold"
    result = finalize(system, sessions[2])
    assert result["routing"]["reason"] == "user_pattern"
    assert result["selection"]["signals"]["user_sessions"] == 3
    claim = aggregation.claim_job(system.db, "pattern", worker_ready=True)
    assert claim
    urgent = captured(system, (100,))
    bind_owner(system, urgent)
    finalize(system, urgent)
    assert aggregation.claim_job(system.db, "same-user", worker_ready=True) is None


def test_selection_never_samples_low_or_unscored_sessions_with_stale_settings(system):
    configure(system, selection_policy="risk_budget", investigation_percent="100")
    # Simulate settings saved by an older backend before the removal migration.
    system.db.execute("ALTER TABLE tenant_session_detection_settings DROP CONSTRAINT investigation_sampling_removed")
    system.db.execute("UPDATE tenant_session_detection_settings SET sample_percent=100 WHERE tenant_id=$1", system.tenant["id"])
    values = [captured(system, scores) for scores in ((None,), (20, 30), (85,))]
    for value in values:
        state = finalize(system, value)
        assert state["routing"]["status"] == "below_threshold"
        assert state["routing"]["job_id"] is None
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 0
    assert system.db.scalar("SELECT count(*) FROM risk_cases") == 0
    assert aggregation.claim_job(system.db, "no-sampling", worker_ready=True) is None
    high = finalize(system, captured(system, (85, 80)))
    assert high["routing"]["reason"] == "session_risk"
    assert high["selection"]["signals"]["risk_slots"] == 4
    value = values[0]
    system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", value.events[0]["id"], Jsonb({"status": "scored", "score": 99}))
    second = finalize(system, value)
    assert second["routing"]["reason"] == "urgent_risk"
    assert aggregation.claim_job(system.db, "new-risk", worker_ready=True)


@pytest.mark.parametrize("state", ["queued", "reserved", "expired", "stopped", "failed"])
def test_historical_sample_jobs_cannot_start_dispatch_or_retry(system, state):
    configure(system, selection_policy="risk_budget")
    value = captured(system, (85, 80))
    routed = finalize(system, value)
    claim = aggregation.claim_job(system.db, "old-worker", worker_ready=True) if state != "queued" else None
    if state == "failed":
        assert aggregation.mark_dispatched(system.db, claim["job_id"], claim["claim_token"], claim["attempt_id"])
    # Represent a sampling job left by an older worker, even with eligible scores.
    system.db.execute("UPDATE session_investigation_jobs SET routing_reason='sample' WHERE id=$1", routed["routing"]["job_id"])
    if state == "reserved":
        assert claim
        assert not aggregation.mark_dispatched(system.db, claim["job_id"], claim["claim_token"], claim["attempt_id"])
    elif state == "expired":
        system.db.execute("UPDATE session_investigation_jobs SET lease_deadline=now()-interval '1 second' WHERE id=$1", claim["job_id"])
        aggregation.expire_claims(system.db, system.tenant["id"])
    elif state == "stopped":
        investigator.stop_attempt(system.db, claim, "runtime_unavailable", retryable=True)
    elif state == "failed":
        assert aggregation.finish_job(system.db, claim["job_id"], claim["claim_token"], claim["attempt_id"],
                                      "failed", {"actual_tokens": 0, "actual_cost_usd": "0"})
    if state in ("expired", "stopped", "failed"):
        assert system.db.scalar("SELECT state FROM session_investigation_jobs WHERE id=$1", claim["job_id"]) == "inconclusive"
    if state != "reserved":
        assert aggregation.claim_job(system.db, "new-worker", worker_ready=True) is None
    assert system.db.scalar("SELECT count(*) FROM model_usage") == 0


def test_sampling_removal_migration_preserves_settings_and_history(system):
    configure(system, selection_policy="risk_budget", investigation_percent="100")
    jobs = [finalize(system, captured(system, (85, 80)))["routing"]["job_id"] for _ in range(3)]
    system.db.execute("UPDATE session_investigation_jobs SET routing_reason='sample' WHERE id=ANY($1::uuid[])", jobs[:2])
    system.db.execute("UPDATE session_investigation_jobs SET state='inconclusive',completed_at=now(),result=$2 WHERE id=$1",
                      jobs[1], Jsonb({"summary": "Historical report"}))
    system.db.execute("ALTER TABLE tenant_session_detection_settings DROP CONSTRAINT investigation_sampling_removed")
    system.db.execute("ALTER TABLE tenant_session_detection_settings ALTER COLUMN sample_percent SET DEFAULT 0.1")
    system.db.execute("UPDATE tenant_session_detection_settings SET sample_percent=0.1,enabled=false WHERE tenant_id=$1", system.tenant["id"])
    before = aggregation.get_settings(system.db, system.tenant["id"])
    history = system.db.one("SELECT * FROM session_investigation_jobs WHERE id=$1", jobs[1])
    cases = system.db.many("SELECT * FROM risk_cases ORDER BY id")
    migration = files("openaidr.server").joinpath("migrations/0125_remove_investigation_sampling.sql")
    system.db.execute(migration.read_text())
    after = aggregation.get_settings(system.db, system.tenant["id"])
    assert after == {**before, "sample_percent": "0", "version": before["version"] + 1, "updated_at": after["updated_at"]}
    assert system.db.scalar("SELECT state FROM session_investigation_jobs WHERE id=$1", jobs[0]) == "superseded"
    assert system.db.scalar("SELECT state FROM session_investigation_jobs WHERE id=$1", jobs[2]) == "queued"
    assert system.db.one("SELECT * FROM session_investigation_jobs WHERE id=$1", jobs[1]) == history
    assert system.db.many("SELECT * FROM risk_cases ORDER BY id") == cases
    created = system.db.create_tenant("No sampling", "no-sampling")
    assert aggregation.get_settings(system.db, created["id"])["sample_percent"] == "0"


@pytest.mark.parametrize("managed", [False, True])
def test_sampling_removal_reselects_eligible_sessions_without_new_evidence(system, managed):
    from test_session_aggregation import completed_session, finalized

    configure(system, selection_policy="risk_budget", investigation_percent="100", session_high_risk_actions=1)
    value = completed_session(system, score=85) if managed else captured(system, (85,))
    before = finalized(system, value, enabled=True, ready=True) if managed else finalize(system, value)
    old_job = before["routing"]["job_id"]
    system.db.execute("UPDATE session_investigation_jobs SET routing_reason='sample' WHERE id=$1", old_job)
    system.db.execute("ALTER TABLE tenant_session_detection_settings DROP CONSTRAINT investigation_sampling_removed")
    system.db.execute("UPDATE tenant_session_detection_settings SET sample_percent=0.1 WHERE tenant_id=$1", system.tenant["id"])
    migration = files("openaidr.server").joinpath("migrations/0125_remove_investigation_sampling.sql")
    system.db.execute(migration.read_text())
    after = finalized(system, value, enabled=True, ready=True) if managed else finalize(system, value)
    assert after["routing"]["status"] == "queued"
    assert after["routing"]["reason"] == "session_risk"
    assert after["routing"]["job_id"] != old_job
    assert after["snapshot_id"] != before["snapshot_id"]
    assert system.db.scalar("SELECT state FROM session_investigation_jobs WHERE id=$1", old_job) == "superseded"
    assert aggregation.claim_job(system.db, "risk-after-upgrade", worker_ready=True)["job_id"] == after["routing"]["job_id"]


def test_history_is_scoped_to_attested_user_and_revocation_blocks_replays(system):
    configure(system)
    target, sibling, unrelated = captured(system), captured(system), captured(system)
    bind_owner(system, target)
    bind_owner(system, sibling)
    bind_owner(system, unrelated, "admin")
    finalize(system, target)
    claim = aggregation.claim_job(system.db, "history", worker_ready=True)
    investigator.prepare_attempt(system.db, claim, RUNTIME)
    step = investigator.next_step(system.db, claim)
    assert step["history_allowed"]
    search = investigator.read_tool(system.db, claim, step["id"], "history-search", "search_sessions", {})
    assert {row["id"] for row in search["sessions"]} == {target.id, sibling.id}
    denied = investigator.read_tool(system.db, claim, step["id"], "other-user", "read_session", {"session_id": unrelated.id})
    assert denied == {"error": {"code": "record_unavailable"}}
    read = investigator.read_tool(system.db, claim, step["id"], "sibling", "read_session", {"session_id": sibling.id})
    assert read["items"]
    detection_history.save_owner(system.db, system.tenant["id"], sibling.id, None, system.users["admin"])
    assert investigator.read_tool(system.db, claim, step["id"], "sibling", "read_session", {"session_id": sibling.id}) == {"error": {"code": "record_unavailable"}}
    assert investigator.read_tool(system.db, claim, step["id"], "history-search", "search_sessions", {}) == {"error": {"code": "record_unavailable"}}


@pytest.mark.parametrize("historical_sample", [False, True])
def test_selection_budget_counts_previous_distinct_sessions_and_preserves_urgent_exception(system, historical_sample):
    configure(system, selection_policy="risk_budget", sample_percent="0", hourly_attempts=10,
              hourly_tokens=2000000, hourly_cost_usd="100", max_concurrent=2)
    first = captured(system, (80, 80))
    finalize(system, first)
    claim = aggregation.claim_job(system.db, "first-selection", worker_ready=True)
    assert claim
    investigator.prepare_attempt(system.db, claim, RUNTIME)
    finish_steps(system, SimpleNamespace(claim=claim))
    investigator.publish_report(system.db, claim)
    if historical_sample:
        system.db.execute("UPDATE session_investigation_jobs SET routing_reason='sample' WHERE id=$1", claim["job_id"])
    # A newly arrived, higher ranked session cannot spend a second slot from
    # the same one-session budget just because the ranking changed.
    second = captured(system, (90, 90))
    assert finalize(system, second)["routing"]["reason"] == "session_risk"
    assert aggregation.claim_job(system.db, "replacement", worker_ready=True) is None
    urgent = captured(system, (99,))
    finalize(system, urgent)
    urgent_claim = aggregation.claim_job(system.db, "urgent-exception", worker_ready=True)
    assert urgent_claim and urgent_claim["snapshot_id"] != claim["snapshot_id"]


def test_completed_review_does_not_repeat_for_benign_addition_but_new_risk_is_eligible(system):
    configure(system, selection_policy="risk_budget", sample_percent="0", hourly_attempts=10,
              hourly_tokens=2000000, hourly_cost_usd="100")
    value = captured(system, (99,))
    first = finalize(system, value)
    claim = aggregation.claim_job(system.db, "review", worker_ready=True)
    investigator.prepare_attempt(system.db, claim, RUNTIME)
    finish_steps(system, SimpleNamespace(claim=claim))
    report = investigator.publish_report(system.db, claim)
    assert report["report_status"] == "inconclusive"
    benign = event(value.native)
    system.db.ingest_batch(value.sensor, [benign])
    system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", benign["id"], Jsonb({"status": "scored", "score": 1}))
    after = finalize(system, value)
    assert after["selection"]["reviewed_evidence"]
    assert system.db.scalar("SELECT count(*) FROM session_investigation_jobs") == 1
    system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", benign["id"], Jsonb({"status": "scored", "score": 90}))
    changed = finalize(system, value)
    assert changed["snapshot_id"] != first["snapshot_id"]
    assert aggregation.claim_job(system.db, "new-risk", worker_ready=True)


def test_deleted_verified_owner_cannot_turn_job_into_unowned_investigation(system):
    configure(system)
    value = captured(system)
    bind_owner(system, value)
    finalize(system, value)
    claim = aggregation.claim_job(system.db, "verified-owner", worker_ready=True)
    system.db.execute("DELETE FROM tenant_users WHERE tenant_id=$1 AND id=$2", system.tenant["id"], system.users["owner"]["id"])
    assert system.db.scalar("SELECT owner_user_id FROM session_investigation_jobs WHERE id=$1", claim["job_id"]) is None
    with pytest.raises(investigator.InvestigationStopped):
        investigator.prepare_attempt(system.db, claim, RUNTIME)


@pytest.mark.parametrize("unavailable", ["legacy", "disabled_owner", "deleted_owner"])
def test_non_investigable_registered_session_cannot_stall_ordinary_selection(system, unavailable):
    configure(system, selection_policy="risk_budget", sample_percent="0")
    if unavailable == "legacy":
        registration = session_ownership.reserve(system.db, system.sensors["sensor"][0], "codex-cli")
        registration["external_id"] = new_id()
        bound = session_ownership.bind(system.db, system.sensors["sensor"][0], registration["id"], registration["external_id"])
        response = browser(system, "POST", "session-registrations/confirm", {"token": bound["confirmation_token"]}, user="owner")
        assert response.status_code == 200
    else:
        registration = registered(system)
    system.db.ingest_batch(system.sensors["sensor"][0], [event(registration["external_id"], registration["id"], kind="session.end")])
    if unavailable == "disabled_owner":
        system.db.execute("UPDATE tenant_users SET status='disabled' WHERE id=$1", system.users["owner"]["id"])
    elif unavailable == "deleted_owner":
        system.db.execute("DELETE FROM tenant_users WHERE id=$1", system.users["owner"]["id"])
    target = captured(system, (85, 80))
    state = finalize(system, target)
    assert state["selection"]["signals"]["population_sessions"] == 1
    assert state["selection"]["signals"]["pending_signals"] == 0
    assert state["routing"]["reason"] == "session_risk"
    assert aggregation.claim_job(system.db, "no-stall", worker_ready=True)


@pytest.mark.parametrize("concentrated", [False, True])
def test_selection_pending_lookup_is_bounded_and_tenant_scoped(system, monkeypatch, concentrated):
    configure(system, selection_policy="risk_budget", investigation_percent="100")
    target = captured(system, (85, 80))
    assert finalize(system, target)["routing"]["reason"] == "session_risk"
    foreign_tenant = system.users["foreign"]["tenant_id"]
    system.db.execute(
        """INSERT INTO agent_sessions(id,tenant_id,agent_id,sensor_id,external_id,product,
                   started_at,last_event_at,ended_at)
           SELECT gen_random_uuid(),s.tenant_id,s.agent_id,s.sensor_id,'history-'||n,s.product,
               s.started_at,s.last_event_at,s.ended_at
           FROM agent_sessions s CROSS JOIN generate_series(1,500) n WHERE s.id=$1""", target.id,
    )
    system.db.execute(
        """INSERT INTO session_detection_signals(session_id,tenant_id,action_risk_threshold,
                   peak,high_actions,evidence_signature)
           SELECT id,tenant_id,70,0,0,'' FROM agent_sessions WHERE tenant_id=$1 AND id<>$2""",
        system.tenant["id"], target.id,
    )
    system.db.execute(
        """INSERT INTO ordinary_session_input_dirty(tenant_id,session_id,created_at)
           SELECT $1,CASE WHEN $2 THEN $3::uuid ELSE gen_random_uuid() END,
               clock_timestamp()-interval '1 day' FROM generate_series(1,20000)""",
        system.tenant["id"], concentrated, target.id,
    )
    for table in ("agent_sessions", "session_detection_signals", "ordinary_session_input_dirty"):
        system.db.execute("ANALYZE " + table)
    settings = aggregation.get_settings(system.db, system.tenant["id"])
    queries, many = [], system.db.many

    def capture_query(query, *args, **kwargs):
        if query.startswith("WITH population AS"):
            queries.append((query, args))
        return many(query, *args, **kwargs)

    monkeypatch.setattr(system.db, "many", capture_query)
    with system.db.transaction() as conn:
        result = detection_selection.select(system.db, system.tenant["id"], target.id, settings, conn)
        assert result["reason"] == "session_risk"
        assert result["signals"]["pending_signals"] == 0
        query, args = queries[0]
        plan = system.db.scalar("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + query, *args, conn=conn)[0]["Plan"]
    nodes, pending = [], [plan]
    while pending:
        node = pending.pop()
        nodes.append(node)
        pending.extend(node.get("Plans", []))
    scans = [node for node in nodes if node.get("Relation Name") == "ordinary_session_input_dirty"]
    assert scans and all(node["Actual Loops"] <= 1 for node in scans), scans
    assert sum(node.get("Shared Hit Blocks", 0) + node.get("Shared Read Blocks", 0)
               for node in scans) < 500, scans

    # A foreign wakeup cannot stall selection, even if it names this session.
    # A new wakeup for this tenant must still defer non-urgent selection.
    for tenant_id, expected in ((foreign_tenant, "session_risk"), (system.tenant["id"], None)):
        system.db.execute(
            "INSERT INTO ordinary_session_input_dirty(tenant_id,session_id) VALUES($1,$2)", tenant_id, target.id,
        )
        with system.db.transaction() as conn:
            result = detection_selection.select(system.db, system.tenant["id"], target.id, settings, conn)
        assert result["reason"] == expected
        assert result["signals"]["pending_signals"] == int(expected is None)
