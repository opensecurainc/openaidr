"""Investigator evidence, authority, accounting, and publication against PostgreSQL."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from decimal import Decimal
from datetime import datetime
from functools import partial
import hashlib
import json
from threading import Barrier
import time
from types import SimpleNamespace

import pytest

from openaidr_api_client.contracts.investigation_runtime import READ_ARGUMENTS, REPORT_FIELDS
from openaidr.core.event import new_id
from openaidr.server import session_aggregation as aggregation
from openaidr.server import session_investigator as investigator
from openaidr.server.config import Config
from test_approvals import approval_settings, sensor_post
from test_inline_guardrail import browser, event, managed, system as system
from test_session_aggregation import (
    action, close_session, deliver, detection_settings, finalized, receipt, registered,
)
from test_session_ownership import wait_for_blocker
from test_store import db as db


MODEL = "gpt-6.1-sol"
TOOLS = [{"type": "function", "name": name, "strict": False, "parameters": schema}
         for name, schema in READ_ARGUMENTS.items()]
RUNTIME = {"version": "0.160.0", "executable_sha256": "a" * 64,
           "platform": "fixture", "protocol_version": 1}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def attempt(system, *, extra_text=None, score=90, gaps=None, **settings):
    approval_settings(system)
    detection_settings(system, **{
        "risk_threshold": "0", "max_runtime_seconds": 120,
        "max_tokens_per_attempt": 200000, "max_cost_usd_per_attempt": "10",
        "hourly_tokens": 2000000, "hourly_cost_usd": "100", "hourly_attempts": 20,
        **settings,
    })
    registration = registered(system)
    value, result, records, _ = action(system, registration, score, gaps=gaps)
    if extra_text is not None:
        observation = event(registration, "response", text=extra_text)
        system.db.ingest_batch(system.sensors["sensor"][0], [observation])
        records.append(receipt("observation", len(records) + 1, event_id=observation["id"]))
    deliver(system, registration, records)
    close_session(system, registration, len(records))
    snapshot = finalized(system, registration, enabled=True, ready=True)
    claim = aggregation.claim_job(system.db, "fixture-investigator", system.tenant["id"], worker_ready=True)
    assert claim is not None
    return SimpleNamespace(registration=registration, value=value, result=result,
                           records=records, snapshot=snapshot, claim=claim)


@pytest.mark.parametrize("fallback", ["", "different-fallback-key"])
def test_missing_service_ignores_retained_provider_keys_and_starts_no_native_work(system, fallback):
    from openaidr.server.remote_investigator import runtime

    cfg = Config(database_url=system.db.url, openai_api_key=fallback)
    system.db.execute("INSERT INTO tenant_model_keys(tenant_id,kind,api_key) VALUES($1,'detection','retained-provider-key')",
                      system.tenant["id"])
    async def run():
        worker = investigator.Investigator(system.db, lambda: runtime(system.db, cfg))
        try:
            value = attempt(system)
            await worker.run_claim(value.claim)
            assert system.db.scalar("SELECT count(*) FROM model_usage WHERE investigation_attempt_id=$1", value.claim["attempt_id"]) == 0
        finally:
            await worker.aclose()
    asyncio.run(run())


def prepared(system, value, **bounds):
    investigator.prepare_attempt(system.db, value.claim, RUNTIME, **bounds)
    step = investigator.next_step(system.db, value.claim)
    assert step is not None
    return step


def proposal(step, *, input_tokens=1000, output_tokens=128, nonce=None):
    return {
        "request_id": new_id(), "input_tokens": input_tokens,
        "requested_output_tokens": output_tokens,
        "request": {
            "model": MODEL, "service_tier": "default", "store": False,
            "truncation": "disabled", "stream": True,
            "input": [{"role": "user", "content": canonical(step["context"]).decode() + (nonce or "")}],
            "instructions": "Investigate only the supplied captured evidence.",
            "tools": TOOLS if step["history_allowed"] else [],
            "text": {"format": {"type": "json_schema", "name": "investigation",
                                 "strict": True, "schema": REPORT_FIELDS}},
        },
    }


def measured(request_id, **changes):
    return {
        "request_id": request_id, "status": "completed", "error_code": "",
        "usage": {"response_id": "response-" + request_id, "model": MODEL,
                  "service_tier": "default", "input_tokens": 1000,
                  "output_tokens": 20, "cached_input_tokens": 0,
                  "cache_write_input_tokens": 0, "reasoning_output_tokens": 10,
                  **changes},
    }


def no_finding():
    return {
        "status": "no_finding", "verdict": "false_positive", "title": "Review of captured activity",
        "summary": "Synthetic benign evidence.",
        "conclusion": "No actionable issue was established in the reviewed snapshot.",
        "confidence": "medium", "timeline": [], "evidence": [],
        "authorization": {"assessment": "The available request is consistent with the activity.",
                          "policy_basis": "", "policy_quote": "", "policy_revision": 0,
                          "evidence_indices": []},
        "impact": {"observed": "No harmful impact was established.", "potential": "None established."},
        "recommendations": [], "alternative_explanations": [], "limitations": [],
        "findings": [], "gaps": [],
    }


def finish_steps(system, value, result_for=None):
    completed = []
    for _ in range(100):
        step = investigator.next_step(system.db, value.claim)
        if step is None:
            return completed
        request = proposal(step)
        admitted = investigator.admit_call(system.db, value.claim, step["id"], request)
        final_body = {**request["request"], "max_output_tokens": admitted["max_output_tokens"]}
        assert admitted["request_sha256"] == hashlib.sha256(canonical(final_body)).hexdigest()
        assert investigator.finish_call(system.db, value.claim, step["id"], measured(request["request_id"])) is True
        output = result_for(step) if result_for else no_finding()
        investigator.complete_step(system.db, value.claim, step["id"], json.dumps(output))
        completed.append(step)
    pytest.fail("investigation did not complete its bounded step plan")


def owner_job(system, job_id, *, user="owner", expected=200):
    response = browser(system, "GET", f"me/session-investigations/{job_id}", user=user)
    assert response.status_code == expected, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()


@pytest.mark.parametrize("deadline", [False, True], ids=["complete", "expired-during-preparation"])
def test_manifest_covers_every_utf8_byte_and_keeps_late_revision_separate(system, deadline):
    text = "retained-start:" + "é漢🧪" * 7000 + ":retained-tail"
    value = attempt(system, extra_text=text, **({"max_runtime_seconds": 1} if deadline else {}))
    if deadline:
        started = time.monotonic()
        with pytest.raises(investigator.InvestigationStopped) as stopped:
            prepared(system, value, fragment_bytes=4, chunk_bytes=4)
        assert stopped.value.code == "claim_expired"
        assert time.monotonic() - started < 5
        assert system.db.scalar("SELECT plan_sealed_at FROM session_investigation_attempts WHERE id=$1", value.claim["attempt_id"]) is None
        assert system.db.scalar("SELECT count(*) FROM session_investigation_requests WHERE attempt_id=$1", value.claim["attempt_id"]) == 0
        assert system.db.scalar("SELECT count(*) FROM model_usage WHERE investigation_attempt_id=$1", value.claim["attempt_id"]) == 0
        return
    first = prepared(system, value, fragment_bytes=8192, chunk_bytes=16384)
    originals = system.db.many(
        "SELECT ordinal,kind,source_id,body FROM session_snapshot_items WHERE snapshot_id=$1 ORDER BY ordinal",
        value.claim["snapshot_id"],
    )
    by_ordinal = {row["ordinal"]: canonical(row) for row in originals}
    chunks = system.db.many(
        "SELECT input_manifest FROM session_investigation_steps WHERE attempt_id=$1 AND kind='chunk' ORDER BY ordinal",
        value.claim["attempt_id"],
    )
    positions = {key: 0 for key in by_ordinal}
    assert len(chunks) > 1
    for chunk in chunks:
        fragments = chunk["input_manifest"]["fragments"]
        assert sum(part["end"] - part["start"] for part in fragments) <= 16384
        for part in fragments:
            raw = by_ordinal[part["ordinal"]]
            assert part["start"] == positions[part["ordinal"]]
            assert 0 < part["end"] - part["start"] <= 8192
            assert part["total_bytes"] == len(raw)
            assert part["sha256"] == hashlib.sha256(raw).hexdigest()
            raw[part["start"]:part["end"]].decode("utf-8")
            positions[part["ordinal"]] = part["end"]
    assert positions == {key: len(raw) for key, raw in by_ordinal.items()}
    delivered_ranges = {key: [] for key in by_ordinal}

    def inspect_prompt(step):
        evidence = step["context"]["evidence"]
        for part in evidence.get("fragments", []):
            raw = by_ordinal[part["ordinal"]]
            assert part["text"].encode() == raw[part["start"]:part["end"]]
            delivered_ranges[part["ordinal"]].append((part["start"], part["end"]))
        return no_finding()

    request = proposal(first)
    investigator.admit_call(system.db, value.claim, first["id"], request)
    assert investigator.finish_call(system.db, value.claim, first["id"], measured(request["request_id"])) is True
    investigator.complete_step(system.db, value.claim, first["id"], json.dumps(inspect_prompt(first)))
    # A started investigation keeps the old sealed source while late evidence
    # creates a separate revision and a separately eligible job.
    late = event(value.registration, "response", text="late revision only")
    sensor_post(system, "events", {"events": [late]})
    deliver(system, value.registration, [receipt("observation", len(value.records) + 1, event_id=late["id"])])
    close_session(system, value.registration, len(value.records) + 1)
    newer = finalized(system, value.registration, enabled=True, ready=True)
    assert newer["snapshot_id"] != value.claim["snapshot_id"]
    assert system.db.many(
        "SELECT ordinal,kind,source_id,body FROM session_snapshot_items WHERE snapshot_id=$1 ORDER BY ordinal",
        value.claim["snapshot_id"],
    ) == originals
    finish_steps(system, value, inspect_prompt)
    for ordinal, ranges in delivered_ranges.items():
        assert ranges[0][0] == 0 and ranges[-1][1] == len(by_ordinal[ordinal])
        assert all(left[1] == right[0] for left, right in zip(ranges, ranges[1:]))
    steps = system.db.many("SELECT id,state,input_manifest FROM session_investigation_steps WHERE attempt_id=$1", value.claim["attempt_id"])
    tree = {row["id"]: row["input_manifest"].get("children", []) for row in steps}
    parents = set(tree) - {child for children in tree.values() for child in children}
    assert len(parents) == 1 and all(row["state"] == "completed" for row in steps)
    pending, visited = list(parents), set()
    while pending:
        child = pending.pop()
        assert child not in visited
        visited.add(child)
        pending.extend(tree[child])
    assert visited == set(tree)
    investigator.publish_report(system.db, value.claim)
    report = owner_job(system, value.claim["job_id"])
    assert report["report"]["status"] == "no_finding"
    assert report["snapshot_id"] == value.claim["snapshot_id"]
    assert value.claim["claim_token"] not in json.dumps(report)
    assert "late revision only" not in json.dumps(report)


def test_admission_commits_exact_request_and_deduplicates_native_retries(system):
    value = attempt(system)
    step = prepared(system, value)
    request = proposal(step)
    admitted = investigator.admit_call(system.db, value.claim, step["id"], request)
    row = system.db.one(
        "SELECT r.*,u.purpose,u.event_id,u.investigation_attempt_id FROM session_investigation_requests r JOIN model_usage u ON u.id=r.usage_id WHERE r.id=$1",
        request["request_id"],
    )
    assert row["state"] == "dispatched" and row["purpose"] == "detection"
    assert row["event_id"] is None and row["investigation_attempt_id"] == value.claim["attempt_id"]
    assert row["reserved_tokens"] == request["input_tokens"] + admitted["max_output_tokens"]
    body = {**request["request"], "max_output_tokens": admitted["max_output_tokens"]}
    assert row["request_sha256"] == hashlib.sha256(canonical(body)).hexdigest()
    assert investigator.finish_call(system.db, value.claim, step["id"], measured(request["request_id"])) is True
    for replay in (request, {**request, "request_id": new_id()}):
        with pytest.raises(investigator.InvestigationStopped):
            investigator.admit_call(system.db, value.claim, step["id"], replay)
    assert system.db.scalar("SELECT count(*) FROM session_investigation_requests") == 1


@pytest.mark.parametrize("missing", [None, "cache_write_input_tokens", "output_tokens", "measured-zero", "over-bound-input"])
def test_usage_preserves_cache_cost_nulls_and_allows_only_matching_late_values(system, missing):
    value = attempt(system)
    step = prepared(system, value)
    request = proposal(step)
    investigator.admit_call(system.db, value.claim, step["id"], request)
    complete = measured(request["request_id"], cached_input_tokens=400, cache_write_input_tokens=200)
    zero = missing == "measured-zero"
    over_bound = missing == "over-bound-input"
    if zero:
        complete["usage"].update(input_tokens=0, output_tokens=0, cached_input_tokens=0,
                                 cache_write_input_tokens=0, reasoning_output_tokens=0)
    elif over_bound:
        complete["usage"]["input_tokens"] = 1001
    unknown = missing is not None and not (zero or over_bound)
    report = deepcopy(complete)
    if unknown:
        report["usage"][missing] = None
    assert investigator.finish_call(system.db, value.claim, step["id"], report) is (not unknown and not over_bound)
    usage = system.db.one("SELECT * FROM model_usage WHERE investigation_request_id=$1", request["request_id"])
    assert usage["input_tokens"] == (0 if zero else 1001 if over_bound else 1000)
    assert usage["cached_input_tokens"] == (0 if zero else 400)
    known_cost = Decimal("0") if zero else Decimal("0.001542") if over_bound else Decimal("0.00154")
    assert usage["cost_usd"] == (None if unknown else known_cost)
    assert system.db.scalar("SELECT actual_tokens FROM session_investigation_attempts WHERE id=$1", value.claim["attempt_id"]) is None
    if unknown or over_bound:
        with pytest.raises(investigator.InvestigationStopped):
            investigator.admit_call(system.db, value.claim, step["id"], proposal(step, nonce="ignore false finish"))
        with pytest.raises(investigator.InvestigationStopped):
            investigator.complete_step(system.db, value.claim, step["id"], json.dumps(no_finding()))
        investigator.stop_attempt(system.db, value.claim, "provider_contract_violation" if over_bound else "usage_unknown")
        assert investigator.finish_call(system.db, value.claim, step["id"], complete) is False
        usage = system.db.one("SELECT * FROM model_usage WHERE investigation_request_id=$1", request["request_id"])
        assert usage["cost_usd"] == known_cost
    changed = deepcopy(complete)
    changed["usage"]["output_tokens"] = 21
    assert investigator.finish_call(system.db, value.claim, step["id"], changed) is False
    assert system.db.scalar("SELECT output_tokens FROM model_usage WHERE investigation_request_id=$1", request["request_id"]) == (0 if zero else 20)


def test_read_tools_keep_same_owner_versions_and_deny_foreign_scope(system):
    for route in ("session-investigations", "session-investigation-reads"):
        invalid = browser(system, "GET", f"me/{route}/invalid-id")
        assert invalid.status_code == 400
        assert invalid.headers["cache-control"] == "no-store"
    approval_settings(system)
    configured = browser(system, "PUT", "response/guardrails", {
        "enabled": True, "ask_threshold": 40, "block_threshold": 80, "timeout_ms": 10000,
    }, user="foreign")
    assert configured.status_code == 200, configured.text
    sources = {}
    for label, owner, device, verified in (
        ("owned", "owner", "peer_sensor", True),
        ("legacy", "owner", "sensor", True),
        ("other-user", "admin", "sensor", True),
        ("other-tenant", "foreign", "foreign_sensor", True),
        ("unverified", "owner", "sensor", False),
    ):
        registration = (
            managed(system, mode="legacy", owner=owner, device=device) if label == "legacy" else
            registered(system, owner=owner, device=device, verified=verified)
        )
        observation = event(registration, "response", text=f"private-{label}-" + new_id())
        if label == "owned":
            observation["text"] += "漢" * 16000 + ":retained-history-tail"
            system.db.ingest_batch(system.sensors[device][0], [observation])
        else:
            sensor_post(system, "events", {"events": [observation]}, device=device)
        session_id = system.db.scalar("SELECT id FROM agent_sessions WHERE registration_id=$1", registration["id"])
        sources[label] = (session_id, observation)
    value = attempt(system)
    step = prepared(system, value)
    listed = investigator.read_tool(system.db, value.claim, step["id"], "search", "search_sessions", {})
    assert sources["owned"][0] in json.dumps(listed)
    assert sources["legacy"][0] in json.dumps(listed)
    for label in ("other-user", "other-tenant", "unverified"):
        assert sources[label][0] not in json.dumps(listed)
    stored_search = system.db.one(
        "SELECT response::text AS response,response_sha256,status FROM session_investigation_reads WHERE id=$1",
        listed["read_id"],
    )
    assert investigator.read_tool(system.db, value.claim, step["id"], "search", "search_sessions", {}) == listed
    retained_search = browser(system, "GET", f"me/session-investigation-reads/{listed['read_id']}", user="owner")
    assert retained_search.status_code == 200 and retained_search.json() == listed
    for label, (session_id, observation) in sources.items():
        result = investigator.read_tool(
            system.db, value.claim, step["id"], "read-" + label, "read_session",
            {"session_id": session_id, "snapshot_id": None, "cursor": ""},
        )
        if label not in ("owned", "legacy"):
            assert result == {"error": {"code": "record_unavailable"}}
            assert observation["text"] not in json.dumps(result)
            continue
        assert result["version"]["kind"] == "live"
        assert len(canonical(result)) <= 32 << 10
        prefix = observation["text"].split("漢", 1)[0]
        assert prefix in json.dumps(result)
        system.db.execute("DELETE FROM events WHERE id=$1", observation["id"])
        if label == "owned":
            assert result["next_cursor"]
            missing = investigator.read_tool(
                system.db, value.claim, step["id"], "changed-continuation", "read_session",
                {"session_id": session_id, "snapshot_id": None, "cursor": result["next_cursor"]},
            )
            assert missing == {"error": {"code": "record_unavailable"}}
        retained = browser(system, "GET", f"me/session-investigation-reads/{result['read_id']}", user="owner")
        assert retained.status_code == 200, retained.text
        assert retained.headers["cache-control"] == "no-store"
        assert prefix in retained.text
        for user in ("admin", "foreign"):
            assert browser(system, "GET", f"me/session-investigation-reads/{result['read_id']}", user=user).status_code == 404
    system.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", system.sensors["peer_sensor"][0]["id"])
    fresh = investigator.read_tool(system.db, value.claim, step["id"], "fresh-search", "search_sessions", {})
    assert sources["owned"][0] not in json.dumps(fresh)
    assert investigator.read_tool(system.db, value.claim, step["id"], "search", "search_sessions", {}) == {"error": {"code": "record_unavailable"}}
    assert browser(system, "GET", f"me/session-investigation-reads/{listed['read_id']}", user="owner").status_code == 404
    assert system.db.one(
        "SELECT response::text AS response,response_sha256,status FROM session_investigation_reads WHERE id=$1",
        listed["read_id"],
    ) == stored_search
    system.db.execute("UPDATE sensors SET disabled=false WHERE id=$1", system.sensors["peer_sensor"][0]["id"])
    assert investigator.read_tool(system.db, value.claim, step["id"], "search", "search_sessions", {}) == listed


@pytest.mark.parametrize("bound", ["tokens", "cost", "context"])
def test_concurrent_request_admission_obeys_remaining_budget_before_inference(system, bound):
    settings = {
        "tokens": {"max_tokens_per_attempt": 1100},
        "cost": {"max_cost_usd_per_attempt": "0.00260"},
        "context": {"max_tokens_per_attempt": 2000000, "hourly_tokens": 4000000,
                    "max_cost_usd_per_attempt": "100", "hourly_cost_usd": "1000"},
    }[bound]
    value = attempt(system, **settings)
    step = prepared(system, value)
    barrier = Barrier(2)

    def admit(index):
        request = proposal(step, nonce=f"\nRequest {index}", input_tokens=1050001 if bound == "context" else 1000)
        barrier.wait(timeout=5)
        try:
            return investigator.admit_call(system.db, value.claim, step["id"], request)
        except investigator.InvestigationStopped:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        values = list(pool.map(admit, range(2)))
    admitted = [value for value in values if value is not None]
    if bound == "context":
        assert admitted == []
        assert system.db.scalar("SELECT count(*) FROM session_investigation_requests") == 0
        assert system.db.scalar("SELECT count(*) FROM model_usage WHERE investigation_attempt_id=$1", value.claim["attempt_id"]) == 0
        allowed = investigator.admit_call(system.db, value.claim, step["id"], proposal(step, input_tokens=1049999))
        assert allowed["max_output_tokens"] == 1
        return
    assert len(admitted) == 1
    assert admitted[0]["max_output_tokens"] == (100 if bound == "tokens" else 10)
    assert system.db.scalar("SELECT count(*) FROM session_investigation_requests") == 1
    assert system.db.scalar("SELECT count(*) FROM model_usage WHERE investigation_attempt_id=$1", value.claim["attempt_id"]) == 1
    with pytest.raises(investigator.InvestigationStopped):
        investigator.admit_call(system.db, value.claim, step["id"], proposal(step, nonce="third input"))
    assert system.db.scalar("SELECT count(*) FROM session_investigation_requests") == 1


def finding_result(value, anchor):
    reference = {"source": "target", "ordinal": anchor["ordinal"], "start": 0, "end": len(canonical(anchor))}
    return {
        **no_finding(), "title": "Attempt outside the stated task",
        "conclusion": "The evidence supports an attempted unauthorized action.",
        "timeline": [{"description": "The requested action was blocked.", "evidence_indices": [0]}],
        "evidence": [reference],
        "status": "finding", "verdict": "true_positive", "summary": "A blocked attempt was observed.", "gaps": [],
        "findings": [{
            "category": "unauthorized_actions", "severity": "high", "title": "Captured blocked attempt",
            "tags": [], "confidence": "medium", "authorization": {
                "assessment": "The attempted action exceeded the captured task.",
                "policy_basis": "", "policy_quote": "", "policy_revision": 0, "evidence_indices": [0],
            }, "alternative_explanations": ["The request might omit prior context; password=review-secret."],
            "explanation": "Attempted operation, password=review-secret; execution was blocked.",
            "severity_rationale": "Sensitive operation outside the stated task; password=review-secret.",
            "timeline": [{"description": "The operation was requested, password=review-secret.",
                          "evidence_indices": [0]}],
            "impact": {"observed": "Execution was blocked; password=review-secret.",
                       "potential": "The attempted operation could expose data; password=review-secret."},
            "recommended_actions": [{"priority": "high", "action": "Review the request, password=review-secret.",
                                     "rationale": "Confirm whether it was intended, password=review-secret."}],
            "uncertainties": ["The user's intent is unresolved; password=review-secret."],
            "evidence": [{"source": "target", "ordinal": anchor["ordinal"],
                          "start": 0, "end": len(canonical(anchor))}],
            "action_outcomes": [{"logical_id": value.result["logical_id"],
                                 "execution": "not_executed", "authorization": "not_recorded"}],
        }],
    }


@pytest.mark.parametrize("variant", [
    "valid", "reduced", "invented-history", "false-success", "invalid-timeline", "missing-report", "disabled-rule",
    "invented-report-history", "invalid-report-timeline", "missing-conclusion",
    "false-human-rejection", "primary-category-tag", "duplicate-tags", "secondary-tag",
    "benign-verdict-with-finding", "missing-verdict",
])
def test_publication_validates_actual_evidence_and_outcomes_and_is_atomic(system, variant):
    value = attempt(system, extra_text="synthetic background context " * 400 if variant == "reduced" else None)
    step = prepared(system, value, **({"fragment_bytes": 8192, "chunk_bytes": 8192} if variant == "reduced" else {}))
    anchor = system.db.one(
        "SELECT ordinal,kind,source_id,body FROM session_snapshot_items WHERE snapshot_id=$1 AND kind='observation' AND source_id=$2",
        value.claim["snapshot_id"], value.value["target"]["id"],
    )
    output = finding_result(value, anchor)
    if variant == "invented-history":
        output["findings"][0]["evidence"].append({"source": "history", "read_id": new_id(), "item": 0})
    elif variant == "false-success":
        output["findings"][0]["action_outcomes"][0]["execution"] = "succeeded"
    elif variant == "false-human-rejection":
        output["findings"][0]["action_outcomes"][0]["authorization"] = "rejected"
    elif variant == "primary-category-tag":
        output["findings"][0]["tags"] = [output["findings"][0]["category"]]
    elif variant in ("duplicate-tags", "secondary-tag"):
        output["findings"][0]["tags"] = ["data_exposure"] * (2 if variant == "duplicate-tags" else 1)
    elif variant == "invalid-timeline":
        output["findings"][0]["timeline"][0]["evidence_indices"] = [1]
    elif variant == "missing-report":
        del output["findings"][0]["impact"]
    elif variant == "invented-report-history":
        output["evidence"].append({"source": "history", "read_id": new_id(), "item": 0})
    elif variant == "invalid-report-timeline":
        output["timeline"][0]["evidence_indices"] = [1]
    elif variant == "missing-conclusion":
        del output["conclusion"]
    elif variant == "missing-verdict":
        del output["verdict"]
    elif variant == "benign-verdict-with-finding":
        output["verdict"] = "true_positive_non_malicious"
    if variant in ("invented-history", "false-success", "invalid-timeline", "missing-report",
                   "invented-report-history", "invalid-report-timeline", "missing-conclusion",
                   "false-human-rejection", "primary-category-tag", "duplicate-tags",
                   "benign-verdict-with-finding", "missing-verdict"):
        request = proposal(step)
        investigator.admit_call(system.db, value.claim, step["id"], request)
        investigator.finish_call(system.db, value.claim, step["id"], measured(request["request_id"]))
        with pytest.raises(investigator.InvestigationStopped):
            investigator.complete_step(system.db, value.claim, step["id"], json.dumps(output))
        assert system.db.scalar("SELECT count(*) FROM findings WHERE investigation_job_id=$1", value.claim["job_id"]) == 0
        return
    def result_for(step):
        if variant != "reduced":
            return output
        evidence = step["context"]["evidence"]
        if step["kind"] == "reduce":
            return next((child["result"] for child in evidence["children"] if child["result"]["findings"]), no_finding())
        return output if any(part["ordinal"] == anchor["ordinal"] for part in evidence["fragments"]) else no_finding()

    completed = finish_steps(system, value, result_for)
    if variant == "reduced":
        assert any(step["kind"] == "reduce" for step in completed)
    if variant == "disabled-rule":
        disabled = browser(system, "PATCH", "detections/rules/codex-session-detection", {"enabled": False})
        assert disabled.status_code == 200, disabled.text
        assert disabled.json()["enabled"] is False
    barrier = Barrier(2)

    def publish():
        barrier.wait(timeout=5)
        try:
            return investigator.publish_report(system.db, value.claim)
        except investigator.InvestigationStopped:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: publish(), range(2)))
    assert any(result is not None for result in results)
    findings = system.db.many("SELECT * FROM findings WHERE investigation_job_id=$1", value.claim["job_id"])
    assert len(findings) == (0 if variant == "disabled-rule" else 1)
    if findings:
        assert findings[0]["primary_event_id"] == value.value["target"]["id"]
        assert findings[0]["snapshot_id"] == value.claim["snapshot_id"]
    assert "review-secret" not in json.dumps(findings, default=str)
    system.db.execute("DELETE FROM events WHERE id=$1", value.value["target"]["id"])
    report = owner_job(system, value.claim["job_id"])
    assert report["report"]["status"] == "finding"
    assert report["report"]["schema_version"] == 4
    assert report["report"]["outcome"] == "actionable_findings"
    assert report["report"]["verdict"] == "true_positive"
    assert report["report"]["scope"]["reviewed_sessions"][0]["snapshot_id"] == value.claim["snapshot_id"]
    assert report["report"]["scope"]["subject"]["ownership_verified"] is True
    incident = report["report"]["findings"][0]
    assert incident["timeline"][0]["evidence_indices"] == [0]
    assert incident["impact"]["observed"].startswith("Execution was blocked")
    assert incident["recommended_actions"] and incident["uncertainties"]
    assert "review-secret" not in json.dumps(report)
    assert "usage" not in report and "model" not in report["report"]
    assert "runtime" not in report["attempts"][0]
    for user in ("admin", "foreign"):
        owner_job(system, value.claim["job_id"], user=user, expected=404)


@pytest.mark.parametrize("operation", [
    "read", "publish", "history-sensor-publish", "search-history-replay",
    "search-history-read", "search-history-publish", "search-history-report",
])
def test_owner_revocation_committing_during_lock_wait_stops_reads_and_publication(system, operation):
    approval_settings(system)
    search_source = operation.startswith("search-history-")
    history = stored_search = report_before = None
    if operation == "history-sensor-publish" or search_source:
        source = registered(system, device="peer_sensor")
        observation = event(source, "response", text="Cited history from another owned sensor.")
        sensor_post(system, "events", {"events": [observation]}, device="peer_sensor")
        session_id = system.db.scalar("SELECT id FROM agent_sessions WHERE registration_id=$1", source["id"])
    value = attempt(system)
    step = prepared(system, value)
    if operation == "history-sensor-publish" or search_source:
        if search_source:
            history = investigator.read_tool(system.db, value.claim, step["id"], "cited-search", "search_sessions", {})
            assert session_id in json.dumps(history)
            assert investigator.read_tool(system.db, value.claim, step["id"], "cited-search", "search_sessions", {}) == history
            allowed = browser(system, "GET", f"me/session-investigation-reads/{history['read_id']}", user="owner")
            assert allowed.status_code == 200 and allowed.json() == history
            stored_search = system.db.one(
                "SELECT response::text AS response,response_sha256,status FROM session_investigation_reads WHERE id=$1",
                history["read_id"],
            )
            if operation in ("search-history-publish", "search-history-report"):
                output = {**no_finding(), "summary": "Search returned historical session " + session_id}
                finish_steps(system, value, lambda _: output)
            if operation == "search-history-report":
                investigator.publish_report(system.db, value.claim)
                report_before = owner_job(system, value.claim["job_id"])
                assert session_id in json.dumps(report_before)
        else:
            history = investigator.read_tool(system.db, value.claim, step["id"], "cited-history", "read_session", {
                "session_id": session_id, "snapshot_id": None, "cursor": "",
            })
            anchor = system.db.one(
                "SELECT ordinal,kind,source_id,body FROM session_snapshot_items WHERE snapshot_id=$1 AND kind='observation' AND source_id=$2",
                value.claim["snapshot_id"], value.value["target"]["id"],
            )
            output = finding_result(value, anchor)
            output["findings"][0]["evidence"].append({"source": "history", "read_id": history["read_id"], "item": 0})
            finish_steps(system, value, lambda _: output)
    elif operation == "publish":
        finish_steps(system, value)
    else:
        investigator.read_tool(system.db, value.claim, step["id"], "late-search", "search_sessions", {})

    def work():
        if operation == "search-history-replay":
            return investigator.read_tool(system.db, value.claim, step["id"], "cited-search", "search_sessions", {})
        if operation == "search-history-read":
            return browser(system, "GET", f"me/session-investigation-reads/{history['read_id']}", user="owner")
        if operation == "search-history-report":
            return browser(system, "GET", f"me/session-investigations/{value.claim['job_id']}", user="owner")
        if operation != "read":
            return investigator.publish_report(system.db, value.claim)
        return investigator.read_tool(system.db, value.claim, step["id"], "late-search", "search_sessions", {})

    with ThreadPoolExecutor(max_workers=1) as pool:
        with system.db.transaction() as gate:
            if operation == "history-sensor-publish" or search_source:
                system.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", system.sensors["peer_sensor"][0]["id"], conn=gate)
            else:
                system.db.execute("UPDATE tenant_users SET status='disabled' WHERE id=$1", system.users["owner"]["id"], conn=gate)
            blocking_pid = system.db.scalar("SELECT pg_backend_pid()", conn=gate)
            pending = pool.submit(work)
            wait_for_blocker(system.db, blocking_pid)
        if operation == "search-history-replay":
            assert pending.result(timeout=5) == {"error": {"code": "record_unavailable"}}
        elif operation in ("search-history-read", "search-history-report"):
            denied = pending.result(timeout=5)
            assert denied.status_code == 404 and session_id not in denied.text
        else:
            with pytest.raises(investigator.InvestigationStopped):
                pending.result(timeout=5)
    assert system.db.scalar("SELECT count(*) FROM findings WHERE investigation_job_id=$1", value.claim["job_id"]) == 0
    state = system.db.scalar("SELECT state FROM session_investigation_jobs WHERE id=$1", value.claim["job_id"])
    assert (state == "completed") is (operation == "search-history-report")
    if search_source:
        assert system.db.one(
            "SELECT response::text AS response,response_sha256,status FROM session_investigation_reads WHERE id=$1",
            history["read_id"],
        ) == stored_search
        assert browser(system, "GET", f"me/session-investigation-reads/{history['read_id']}", user="owner").status_code == 404
        system.db.execute("UPDATE sensors SET disabled=false WHERE id=$1", system.sensors["peer_sensor"][0]["id"])
        recovered = browser(system, "GET", f"me/session-investigation-reads/{history['read_id']}", user="owner")
        assert recovered.status_code == 200 and recovered.json() == history
        if operation == "search-history-report":
            assert owner_job(system, value.claim["job_id"]) == report_before


def test_expired_dispatch_fences_late_result_but_preserves_original_usage(system):
    value = attempt(system)
    step = prepared(system, value)
    original = value.claim
    stopped = investigator.stop_attempt(system.db, original, "runtime_unavailable", retryable=True)
    assert stopped["state"] == "queued"
    value.claim = aggregation.claim_job(system.db, "startup-retry", system.tenant["id"], worker_ready=True)
    assert value.claim is not None and value.claim["attempt_id"] != original["attempt_id"]
    with pytest.raises(investigator.InvestigationStopped):
        investigator.admit_call(system.db, original, step["id"], proposal(step))
    assert system.db.scalar("SELECT count(*) FROM model_usage WHERE investigation_attempt_id=$1", original["attempt_id"]) == 0
    step = prepared(system, value)
    request = proposal(step)
    investigator.admit_call(system.db, value.claim, step["id"], request)
    system.db.execute("UPDATE session_investigation_attempts SET deadline_at=clock_timestamp()-interval '1 second' WHERE id=$1", value.claim["attempt_id"])
    aggregation.expire_claims(system.db, system.tenant["id"])
    assert investigator.finish_call(system.db, value.claim, step["id"], measured(request["request_id"])) is False
    with pytest.raises(investigator.InvestigationStopped):
        investigator.complete_step(system.db, value.claim, step["id"], json.dumps(no_finding()))
    with pytest.raises(investigator.InvestigationStopped):
        investigator.admit_call(system.db, value.claim, step["id"], proposal(step, nonce="late retry"))
    assert aggregation.claim_job(system.db, "replacement", system.tenant["id"], worker_ready=True) is None
    assert system.db.scalar("SELECT state FROM session_investigation_jobs WHERE id=$1", value.claim["job_id"]) == "inconclusive"
    assert system.db.scalar("SELECT actual_tokens FROM session_investigation_attempts WHERE id=$1", value.claim["attempt_id"]) == 1020
    assert system.db.scalar("SELECT count(*) FROM session_investigation_requests") == 1
    assert system.db.scalar("SELECT count(*) FROM findings WHERE investigation_job_id=$1", value.claim["job_id"]) == 0


@pytest.mark.parametrize("conclusion", ["no_finding", "benign", "finding"])
def test_capture_gaps_cannot_be_removed_by_a_clean_model_conclusion(system, conclusion):
    value = attempt(system, gaps=["capture_disabled"], gap_policy="investigate")
    prepared(system, value)
    anchor = system.db.one(
        "SELECT ordinal,kind,source_id,body FROM session_snapshot_items WHERE snapshot_id=$1 AND kind='observation' AND source_id=$2",
        value.claim["snapshot_id"], value.value["target"]["id"],
    )
    result = finding_result(value, anchor) if conclusion in ("finding", "benign") else no_finding()
    if conclusion == "benign":
        result.update(status="no_finding", verdict="true_positive_non_malicious", findings=[])
        result["authorization"]["evidence_indices"] = [0]
    finish_steps(system, value, lambda _: result)
    investigator.publish_report(system.db, value.claim)
    report = owner_job(system, value.claim["job_id"])["report"]
    assert report["status"] == ("finding" if conclusion == "finding" else "inconclusive")
    assert report["coverage"]["status"] == "complete"
    assert report["source_coverage"]["status"] == "incomplete"
    if conclusion != "finding":
        assert report["outcome"] == "inconclusive" and report["confidence"] == "low"
        assert report["verdict"] is None
        assert report["title"] == "Investigation incomplete: missing evidence"
        assert report["summary"].startswith("Some activity records are missing")
    assert "capture_disabled" in report["gaps"]
    assert system.db.scalar("SELECT count(*) FROM findings WHERE investigation_job_id=$1", value.claim["job_id"]) == (1 if conclusion == "finding" else 0)


@pytest.mark.parametrize("verdict", [None, "true_positive", "true_positive_non_malicious"])
def test_negative_verdict_rejects_conflicting_classification_and_uncited_benign_context(system, verdict):
    value = attempt(system)
    step = prepared(system, value)
    request = proposal(step)
    investigator.admit_call(system.db, value.claim, step["id"], request)
    investigator.finish_call(system.db, value.claim, step["id"], measured(request["request_id"]))
    output = {**no_finding(), "verdict": verdict}
    with pytest.raises(investigator.InvestigationStopped, match="invalid_result"):
        investigator.complete_step(system.db, value.claim, step["id"], json.dumps(output))
    assert system.db.scalar("SELECT report FROM session_investigation_attempts WHERE id=$1", value.claim["attempt_id"]) is None


@pytest.mark.parametrize("variant", ["captured", "missing", "invented-quote", "wrong-revision", "uncited-policy"])
def test_acceptable_use_requires_the_policy_applied_to_cited_evidence(system, variant):
    original = "Company policy prohibits running personal cryptocurrency mining jobs."
    if variant != "missing":
        response = browser(system, "PUT", "response/company-policy", {"revision": 0, "prompt": original})
        assert response.status_code == 200, response.text
    value = attempt(system)
    # A later policy edit is never applied retroactively to the sealed evidence.
    current = browser(system, "GET", "response/company-policy").json()
    updated = browser(system, "PUT", "response/company-policy", {
        "revision": current["revision"], "prompt": "Personal cryptocurrency mining is now permitted.",
    })
    assert updated.status_code == 200, updated.text
    step = prepared(system, value)
    policies = step["context"]["company_policies"]
    assert [policy["prompt"] for policy in policies] == ([] if variant == "missing" else [original])
    anchor = system.db.one(
        "SELECT ordinal,kind,source_id,body FROM session_snapshot_items WHERE snapshot_id=$1 AND kind=$2 ORDER BY ordinal LIMIT 1",
        value.claim["snapshot_id"], "observation" if variant == "uncited-policy" else "assessment",
    )
    result = finding_result(value, anchor)
    finding = result["findings"][0]
    finding["category"] = "acceptable_use"
    finding["authorization"].update(
        policy_basis="The cited operation is within the policy's scope.",
        policy_quote="Personal topics are forbidden." if variant == "invented-quote" else "prohibits running personal cryptocurrency mining jobs",
        policy_revision=99 if variant == "wrong-revision" else 1,
    )
    if variant != "captured":
        with pytest.raises(investigator.InvestigationStopped, match="invalid_result"):
            finish_steps(system, value, lambda _: result)
        assert system.db.scalar("SELECT count(*) FROM findings WHERE investigation_job_id=$1", value.claim["job_id"]) == 0
        return
    finish_steps(system, value, lambda _: result)
    investigator.publish_report(system.db, value.claim)
    report = owner_job(system, value.claim["job_id"])["report"]
    assert report["company_policies"][0]["prompt"] == original
    assert report["company_policies"][0]["revision"] == 1
    assert report["findings"][0]["category"] == "acceptable_use"


def test_review_scope_keeps_history_as_context_and_rejects_future_evidence(system):
    approval_settings(system)
    history = registered(system, device="peer_sensor")
    previous = event(history, "response", text="Past work in the same project.")
    sensor_post(system, "events", {"events": [previous]}, device="peer_sensor")
    history_id = system.db.scalar("SELECT id FROM agent_sessions WHERE registration_id=$1", history["id"])
    value = attempt(system)
    step = prepared(system, value)
    future = event(history, "response", text="Future evidence must not enter this investigation.")
    future["time"] = previous["time"]  # A backdated event still arrived after the job cutoff.
    sensor_post(system, "events", {"events": [future]}, device="peer_sensor")
    new_session = registered(system, device="peer_sensor")
    sensor_post(system, "events", {"events": [event(new_session, "response", text="A new session")]}, device="peer_sensor")
    new_id_value = system.db.scalar("SELECT id FROM agent_sessions WHERE registration_id=$1", new_session["id"])
    searched = investigator.read_tool(system.db, value.claim, step["id"], "search-context", "search_sessions", {})
    assert history_id in json.dumps(searched) and new_id_value not in json.dumps(searched)
    assert investigator.read_tool(system.db, value.claim, step["id"], "future-session", "read_session", {
        "session_id": new_id_value,
    }) == {"error": {"code": "record_unavailable"}}
    first = investigator.read_tool(system.db, value.claim, step["id"], "context", "read_session", {"session_id": history_id})
    assert "Past work" in json.dumps(first) and "Future evidence" not in json.dumps(first)
    next_page = investigator.read_tool(system.db, value.claim, step["id"], "context-end", "read_session", {
        "session_id": history_id, "cursor": first["next_cursor"],
    })
    assert next_page["items"] == []
    finish_steps(system, value)
    investigator.publish_report(system.db, value.claim)
    report = owner_job(system, value.claim["job_id"])["report"]
    assert report["outcome"] == "no_actionable_findings"
    assert report["scope"]["reviewed_sessions"][0]["snapshot_id"] == value.claim["snapshot_id"]
    assert {item["session_id"] for item in report["scope"]["context_sessions"]} == {history_id}
    assert all(item["review_status"] == "context_only" for item in report["scope"]["context_sessions"])
    assert history_id not in json.dumps(report["scope"]["reviewed_sessions"])


def test_interrupted_attempt_has_detailed_inconclusive_report(system):
    value = attempt(system)
    prepared(system, value)
    investigator.stop_attempt(system.db, value.claim, "runtime_unavailable")
    report = owner_job(system, value.claim["job_id"])["report"]
    assert report["outcome"] == "inconclusive"
    assert report["reason"] == "runtime_unavailable"
    assert report["title"] and report["conclusion"] and report["summary"]
    assert report["scope"]["reviewed_sessions"] == []
    assert report["scope"]["target_sessions"][0]["snapshot_id"] == value.claim["snapshot_id"]
    assert report["recommendations"][0]["priority"] == "normal"
    assert report["coverage"]["status"] == "incomplete" and report["limitations"]


def test_report_scope_uses_sealed_evidence_when_late_events_change_session_metadata(system):
    value = attempt(system)
    captured = system.db.one(
        "SELECT min((body->>'time')::timestamptz) AS first,max((body->>'time')::timestamptz) AS last "
        "FROM session_snapshot_items WHERE snapshot_id=$1 AND kind='observation'",
        value.claim["snapshot_id"],
    )
    prepared(system, value)
    finish_steps(system, value)
    late = event(value.registration, "response", text="Late context belongs to another revision.",
                 host={"user": "late-user", "hostname": "late-device"})
    late["session"]["cwd"] = "/late-project"
    sensor_post(system, "events", {"events": [late]})
    investigator.publish_report(system.db, value.claim)
    report = owner_job(system, value.claim["job_id"])["report"]
    target = report["scope"]["reviewed_sessions"][0]
    assert datetime.fromisoformat(target["started_at"].replace("Z", "+00:00")) == captured["first"]
    assert datetime.fromisoformat(target["ended_at"].replace("Z", "+00:00")) == captured["last"]
    assert "/late-project" not in report["scope"]["projects"]
    assert report["scope"]["subject"]["reported_user"] != "late-user"
    assert "late-device" not in json.dumps(report["scope"]["devices"])


def test_legacy_step_replays_its_persisted_prompt_identity(system):
    from openaidr.server.investigation_bridge import Bridge
    from openaidr_api_client.client import Connection
    from openaidr_api_client.contracts import investigations as wire
    from openaidr_api_client.contracts.investigation_runtime import PROMPT_VERSION

    value = attempt(system)
    metadata = {**RUNTIME, "version": wire.native.VERSION}
    investigator.prepare_attempt(system.db, value.claim, metadata)
    step = investigator.next_step(system.db, value.claim)
    connection = Connection("https://fixture.invalid", "oati_" + "a" * 32 + "." + "b" * 43,
                            system.tenant["id"])
    bridge = Bridge(system.db, value.claim, connection, wire.profile(metadata))
    request = bridge.prepare_binding()
    bridge.attach(dict(id=new_id(), state="waiting_step", revision=1, attempt_id=request["attempt_id"],
                       deadline_at=request["deadline_at"], runtime_profile_sha256=request["runtime_profile_sha256"]))
    outgoing = bridge.step_message(step)
    assert outgoing["prompt_version"] == PROMPT_VERSION == 4
    assert bridge.step_message(step) == outgoing
    assert system.db.scalar("SELECT count(*) FROM session_investigation_remote_messages WHERE attempt_id=$1",
                            value.claim["attempt_id"]) == 1


def remote_exchange(system, tmp_path, *, protocol_version=1, connection=None):
    """Real tenant controller plus service persistence, without a native/provider process."""
    from openaidr_api.investigations.store import Store
    from openaidr.server.investigation_bridge import Bridge
    from openaidr_api_client.client import Connection
    from openaidr_api_client.contracts import investigations as wire

    value = attempt(system)
    native_metadata = {**RUNTIME, "version": wire.native.VERSION}
    investigator.prepare_attempt(system.db, value.claim, native_metadata)
    step = investigator.next_step(system.db, value.claim)
    connection = connection or Connection("https://fixture.invalid", "oati_" + "a" * 32 + "." + "b" * 43,
                            system.tenant["id"])
    assert protocol_version == 1
    profile = wire.profile({**native_metadata, "protocol_version": 1})
    bridge = Bridge(system.db, value.claim, connection, profile)
    store = Store(tmp_path / "jobs.sqlite3")
    body = bridge.prepare_binding()
    created, fresh = store.create(connection.tenant_id, body, profile, protocol_version=protocol_version)
    assert fresh
    ident = bridge.attach(created)
    outgoing = bridge.step_message(step)
    accepted = store.exchange(connection.tenant_id, ident, outgoing, protocol_version=protocol_version)
    bridge.acknowledge(outgoing, accepted["ack"])
    worker = store.claim("fixture-worker", wire.digest(profile))
    assert store.take_step(connection.tenant_id, ident, worker["generation"])["step_id"] == step["id"]
    callbacks = dict(tool_callback=partial(investigator.read_tool, system.db, value.claim, step["id"]),
                     call_admission=partial(investigator.admit_call, system.db, value.claim, step["id"]),
                     call_finish=partial(investigator.finish_call, system.db, value.claim, step["id"]))
    return SimpleNamespace(value=value, step=step, connection=connection, profile=profile, bridge=bridge,
                           store=store, job=ident, generation=worker["generation"], callbacks=callbacks,
                           body=body, wire=wire, exchange=partial(store.exchange, protocol_version=protocol_version),
                           cancel=partial(store.cancel, protocol_version=protocol_version),
                           status=partial(store.status, protocol_version=protocol_version))


def remote_operation(remote, kind, payload):
    return remote.store.operation(remote.connection.tenant_id, remote.job, remote.generation, kind, payload)


def remote_reply(remote, operation):
    message = remote.bridge.reply(operation, **remote.callbacks)
    delivered = remote.exchange(remote.connection.tenant_id, remote.job, message)
    remote.bridge.acknowledge(message, delivered["ack"])
    return remote.store.take_reply(remote.connection.tenant_id, remote.job, remote.generation,
                                   operation["operation_id"])


@pytest.mark.parametrize("fault", ["before_receipt", "after_receipt"])
def test_remote_admission_and_transport_receipt_commit_together(system, tmp_path, monkeypatch, fault):
    remote = remote_exchange(system, tmp_path)
    counted = proposal(remote.step)
    operation = remote_operation(remote, "admit_call", counted)
    save = remote.bridge._save

    def crash(conn, value, **kw):
        if fault == "after_receipt":
            save(conn, value, **kw)
        raise RuntimeError("injected process loss before commit")

    monkeypatch.setattr(remote.bridge, "_save", crash)
    with pytest.raises(RuntimeError):
        remote.bridge.reply(operation, **remote.callbacks)
    assert system.db.scalar("SELECT count(*) FROM session_investigation_requests") == 0
    assert system.db.scalar("SELECT count(*) FROM model_usage WHERE purpose='detection'") == 0
    assert system.db.scalar("SELECT count(*) FROM session_investigation_remote_messages WHERE kind='reply'") == 0
    monkeypatch.setattr(remote.bridge, "_save", save)
    with ThreadPoolExecutor(2) as pool:
        replies = list(pool.map(lambda _: remote.bridge.reply(operation, **remote.callbacks), range(2)))
    assert replies[0] == replies[1]
    reply = replies[0]
    assert reply["outcome"]["ok"]
    assert system.db.scalar("SELECT count(*) FROM session_investigation_requests") == 1
    # The response is already durable, so a retry cannot call the ordinary
    # duplicate-rejecting admission helper again.
    def forbidden(*args, **kwargs):
        pytest.fail("replayed admission")
    callbacks = {**remote.callbacks, "call_admission": forbidden}
    assert remote.bridge.reply(operation, **callbacks) == reply
    remote.exchange(remote.connection.tenant_id, remote.job, reply)  # Lose this HTTP response.
    recovered = remote.exchange(remote.connection.tenant_id, remote.job,
                                     {"type": "poll", "ack_for": reply["message_id"]})
    remote.bridge.acknowledge(reply, recovered["ack"])
    grant = remote.store.take_reply(remote.connection.tenant_id, remote.job, remote.generation,
                                    operation["operation_id"])["value"]
    row = system.db.one("SELECT * FROM session_investigation_requests WHERE id=$1", counted["request_id"])
    assert row["input_tokens_counted"] == counted["input_tokens"]
    assert row["request_sha256"] == grant["request_sha256"]
    # A deterministic provider boundary can run only after the committed permit.
    assert remote_reply(remote, remote_operation(remote, "finish_call", measured(counted["request_id"])))["value"]
    assert system.db.scalar("SELECT count(*) FROM model_usage WHERE investigation_request_id=$1", counted["request_id"]) == 1
    with pytest.raises(investigator.InvestigationStopped, match="request_replayed"):
        investigator.admit_call(system.db, remote.value.claim, remote.step["id"], counted)


def test_remote_completion_and_publication_are_atomic_with_recoverable_acknowledgements(system, tmp_path, monkeypatch):
    from openaidr.server.investigation_bridge import Bridge

    remote = remote_exchange(system, tmp_path)
    counted = proposal(remote.step)
    assert remote_reply(remote, remote_operation(remote, "admit_call", counted))["ok"]
    assert remote_reply(remote, remote_operation(remote, "finish_call", measured(counted["request_id"])))["value"]
    remote.store.complete_step(remote.connection.tenant_id, remote.job, remote.generation, json.dumps(no_finding()))
    result = remote.exchange(remote.connection.tenant_id, remote.job, {"type": "poll", "ack_for": None})["step_result"]
    callback = partial(investigator.complete_step, system.db, remote.value.claim, remote.step["id"])
    save = remote.bridge._save

    def crash(conn, value, **kw):
        saved = save(conn, value, **kw)
        if value["type"] in ("step_ack", "finish"):
            raise RuntimeError("injected loss after effect and receipt")
        return saved

    monkeypatch.setattr(remote.bridge, "_save", crash)
    with pytest.raises(RuntimeError):
        remote.bridge.accept_step(remote.step["id"], result, callback)
    assert system.db.scalar("SELECT state FROM session_investigation_steps WHERE id=$1", remote.step["id"]) == "prepared"
    monkeypatch.setattr(remote.bridge, "_save", save)
    ack = remote.bridge.accept_step(remote.step["id"], result, callback)
    reopened = Bridge(system.db, remote.value.claim, remote.connection, remote.profile)
    assert reopened.recovery()["messages"] == [ack]
    assert reopened.accept_step(remote.step["id"], result, lambda *a, **k: pytest.fail("completed twice")) == ack
    delivered = remote.exchange(remote.connection.tenant_id, remote.job, ack)
    reopened.acknowledge(ack, delivered["ack"])
    assert investigator.next_step(system.db, remote.value.claim) is None
    publish = partial(investigator.publish_report, system.db, remote.value.claim)
    monkeypatch.setattr(remote.bridge, "_save", crash)
    with pytest.raises(RuntimeError):
        remote.bridge.finish(publish)
    assert system.db.scalar("SELECT state FROM session_investigation_jobs WHERE id=$1", remote.value.claim["job_id"]) == "running"
    assert system.db.scalar("SELECT report FROM session_investigation_attempts WHERE id=$1", remote.value.claim["attempt_id"]) is None
    monkeypatch.setattr(remote.bridge, "_save", save)
    report, finish = remote.bridge.finish(publish)
    assert report["report_status"] == "no_finding"
    assert reopened.finish(lambda **k: pytest.fail("published twice")) == (report, finish)
    assert reopened.recovery()["messages"] == [finish]
    delivered = remote.exchange(remote.connection.tenant_id, remote.job, finish)
    reopened.acknowledge(finish, delivered["ack"])
    assert delivered["state"] == "completed" and reopened.recovery()["messages"] == []


def test_remote_history_requires_delivery_ack_and_rechecks_scope_for_cached_reads(system, tmp_path):
    approval_settings(system)
    history = registered(system, device="peer_sensor")
    previous = event(history, "response", text="History that was captured before the immutable cutoff.")
    sensor_post(system, "events", {"events": [previous]}, device="peer_sensor")
    source = system.db.scalar("SELECT id FROM agent_sessions WHERE registration_id=$1", history["id"])
    remote = remote_exchange(system, tmp_path)
    future = event(history, "response", text="Future evidence must remain excluded.")
    future["time"] = previous["time"]
    sensor_post(system, "events", {"events": [future]}, device="peer_sensor")
    operation = remote_operation(remote, "read_tool", {
        "call_id": "history-read", "name": "read_session", "arguments": {"session_id": source},
    })
    reply = remote.bridge.reply(operation, **remote.callbacks)
    assert "History that was captured" in json.dumps(reply) and "Future evidence" not in json.dumps(reply)
    read_id = reply["outcome"]["value"]["read_id"]
    assert system.db.scalar("SELECT message FROM session_investigation_remote_messages WHERE id=$1", reply["message_id"]) is None
    text = no_finding()
    text["evidence"] = [{"source": "history", "read_id": read_id, "item": 0}]
    result = dict(step_id=remote.step["id"], text=json.dumps(text), runtime=remote.profile,
                  result_sha256=remote.wire.digest(json.dumps(text)))
    with pytest.raises(investigator.InvestigationStopped, match="incomplete_coverage"):
        remote.bridge.verify_result(remote.step["id"], result)
    delivered = remote.exchange(remote.connection.tenant_id, remote.job, reply)
    remote.bridge.acknowledge(reply, delivered["ack"])
    assert remote.bridge.verify_result(remote.step["id"], result) == result["text"]
    assert remote.bridge.reply(operation, **remote.callbacks) == reply
    system.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", system.sensors["peer_sensor"][0]["id"])
    with pytest.raises(investigator.InvestigationStopped, match="scope_unavailable"):
        remote.bridge.reply(operation, **remote.callbacks)
    # Acknowledgement is a historical fact; recording it again grants no new read.
    remote.bridge.acknowledge(reply, delivered["ack"])
    assert remote.bridge.recovery()["messages"] == []


def test_remote_revocation_blocks_grant_replay_and_keeps_late_accounting(system, tmp_path):
    remote = remote_exchange(system, tmp_path)
    counted = proposal(remote.step)
    operation = remote_operation(remote, "admit_call", counted)
    reply = remote.bridge.reply(operation, **remote.callbacks)
    delivered = remote.exchange(remote.connection.tenant_id, remote.job, reply)
    remote.bridge.acknowledge(reply, delivered["ack"])
    remote.store.take_reply(remote.connection.tenant_id, remote.job, remote.generation, operation["operation_id"])
    detection_settings(system, enabled=False)
    with pytest.raises(investigator.InvestigationStopped, match="settings_changed"):
        remote.bridge.reply(operation, **remote.callbacks)
    remote.cancel(remote.connection.tenant_id, remote.job, {"message_id": new_id(), "code": "settings_changed"})
    unknown = remote_operation(remote, "finish_call", measured(counted["request_id"], output_tokens=None))
    assert remote_reply(remote, unknown)["value"] is False
    assert system.db.scalar("SELECT cost_usd FROM model_usage WHERE investigation_request_id=$1", counted["request_id"]) is None
    known = remote_operation(remote, "finish_call", measured(counted["request_id"]))
    assert remote_reply(remote, known)["value"] is False
    assert system.db.scalar("SELECT cost_usd FROM model_usage WHERE investigation_request_id=$1", counted["request_id"]) > 0
    assert system.db.scalar("SELECT count(*) FROM model_usage WHERE investigation_request_id=$1", counted["request_id"]) == 1
    assert remote.status(remote.connection.tenant_id, remote.job)["state"] == "cancelled"


def test_remote_binding_pins_origin_profile_deadline_and_owning_tenant(system, tmp_path):
    from dataclasses import replace
    from openaidr.server.investigation_bridge import Bridge

    remote = remote_exchange(system, tmp_path)
    assert remote.bridge.prepare_binding() == remote.body
    assert remote.bridge.recovery()["create_request"] == remote.body
    with pytest.raises(investigator.InvestigationStopped, match="scope_unavailable"):
        Bridge(system.db, remote.value.claim, replace(remote.connection, tenant_id=new_id()), remote.profile)
    with pytest.raises(investigator.InvestigationStopped, match="scope_unavailable"):
        Bridge(system.db, remote.value.claim, remote.connection, remote.profile,
               benchmark_owner_tenant_id=remote.connection.tenant_id)  # Ordinary schema cannot claim benchmark authority.
    moved = Bridge(system.db, remote.value.claim, replace(remote.connection, origin="https://other.invalid"), remote.profile)
    with pytest.raises(investigator.InvestigationStopped, match="runtime_unavailable"):
        moved.prepare_binding()
    rebound = Bridge(system.db, remote.value.claim, remote.connection, {**remote.profile, "executable_sha256": "f" * 64})
    with pytest.raises(investigator.InvestigationStopped, match="runtime_unavailable"):
        rebound.prepare_binding()
    assert system.db.scalar("SELECT count(*) FROM session_investigation_remote_bindings") == 1
