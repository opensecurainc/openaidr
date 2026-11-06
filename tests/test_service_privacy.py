"""Customer service metadata stays separate from literal captured evidence."""

import hashlib
import json

from psycopg.types.json import Jsonb

from openaidr.core.event import new_id
from openaidr.server.model import public_record
from test_inline_guardrail import browser, system as system
from test_store import db as db


def test_event_projection_preserves_native_models_and_evidence_keys():
    evidence = {"model": "customer-model", "usage": {"input_tokens": 91},
                "provider": "customer-provider", "cost_usd": "quoted evidence"}
    row = {"body": {"agent": {"model": "customer-model"}, "tool": {"input": evidence}},
           "risk": {"status": "scored", "score": 80, "model": "private-service-model",
                    "usage": {"input_tokens": 10}, "knowledge": {"title": "private-service-model"}}}
    result = public_record(row, "event")
    assert result["agent"] == row["body"]["agent"]
    assert result["tool"]["input"] == evidence
    assert result["risk"] == {"status": "scored", "score": 80, "knowledge": row["risk"]["knowledge"]}
    assert row["risk"]["model"] == "private-service-model"


def test_audit_projection_hides_only_known_service_configuration(system):
    tenant, actor = system.tenant["id"], {"type": "user", "id": system.users["admin"]["id"]}
    private = {"model": "private-service-model", "budget_usd": "7.00"}
    for action, details in (
        ("skill_scanning.llm.configure", {"mode": "automatic", **private}),
        ("session-detection.configure", {"enabled": True, "risk_threshold": "70", **private,
                                         "max_tokens_per_attempt": 99, "hourly_cost_usd": "9"}),
        ("policy.update", {"reason": "private-service-model", "match": private}),
    ):
        system.db.audit(tenant, actor, action, details=details)
    reply = browser(system, "GET", "audit")
    assert reply.status_code == 200, reply.text
    items = {item["action"]: item["details"] for item in reply.json()["items"]}
    assert items["skill_scanning.llm.configure"] == {"mode": "automatic"}
    assert items["session-detection.configure"] == {"enabled": True, "risk_threshold": "70"}
    assert items["policy.update"] == {"reason": "private-service-model", "match": private}
    assert system.db.scalar("SELECT details->>'model' FROM audit_log WHERE action='skill_scanning.llm.configure'") == private["model"]
    assert browser(system, "GET", "audit", user="foreign").json()["items"] == []
    assert system.client.get("/api/v1/audit").status_code == 401


def test_historical_partial_read_projects_metadata_with_distinct_integrity(system):
    from openaidr.server import session_investigator as inv
    from test_session_investigator import attempt, canonical, prepared
    from test_session_operator import archive, operator, session_id

    operator(system)
    prior = attempt(system, extra_text="Captured Jev model and model/provider keys stay exact")
    source = system.db.one("""SELECT ordinal,kind,source_id,body FROM session_snapshot_items
        WHERE snapshot_id=$1 AND kind='assessment' ORDER BY ordinal LIMIT 1""", prior.claim["snapshot_id"])
    inv.stop_attempt(system.db, prior.claim, "cancelled", retryable=False)
    current = attempt(system)
    step = prepared(system, current)
    raw = canonical(source)
    start = raw.index(b'"model"') + 3
    end = min(len(raw), start + 37)
    ident = new_id()
    fragment = {"ordinal": source["ordinal"], "source_id": source["source_id"],
                "start": start, "end": end, "total_bytes": len(raw), "text": raw[start:end].decode()}
    retained = {"read_id": ident, "next_cursor": "", "session_id": session_id(system, prior.registration),
                "version": {"kind": "snapshot", "snapshot_id": prior.claim["snapshot_id"]},
                "items": [fragment], "coverage": {"scope": "returned_page"}}
    digest = hashlib.sha256(canonical(retained)).hexdigest()
    system.db.execute("""INSERT INTO session_investigation_reads
        (id,attempt_id,step_id,tool_call_id,tool_name,arguments,status,session_id,source_snapshot_id,response,response_sha256)
        VALUES($1,$2,$3,'historical-metadata','read_session','{}','delivered',$4,$5,$6,$7)""",
        ident, current.claim["attempt_id"], step["id"], retained["session_id"], prior.claim["snapshot_id"], Jsonb(retained), digest)
    path = "session-investigation-reads/" + ident
    result = archive(system, path)
    projected = result["response"]["items"][0]
    assert result["retained_response_sha256"] == digest
    assert result["response_sha256"] == hashlib.sha256(canonical(result["response"])).hexdigest()
    assert result["response_sha256"] != digest
    assert projected["retained_source_range"] == {
        "start": start, "end": end, "total_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    assert projected["start"] == 0 and projected["end"] == len(projected["text"].encode())
    assert projected["sha256"] == hashlib.sha256(projected["text"].encode()).hexdigest()
    safe = json.loads(projected["text"])
    assert not {"model", "rubric_version"}.intersection(safe["body"])
    assert not {"model", "usage", "rubric_version"}.intersection(safe["body"]["assessment"])
    assert safe["body"]["target_body"] == source["body"]["target_body"]
    assert safe["body"]["captured_context"] == source["body"]["captured_context"]
    assert archive(system, "me/" + path, user="owner")["items"] == [projected]
    for user in ("foreign", "anonymous"):
        archive(system, path, user=user, expected=401 if user == "anonymous" else 404)
    archive(system, "me/" + path, expected=404)
    snapshot = archive(system, "session-snapshots/" + prior.claim["snapshot_id"])
    item = next(item for item in snapshot["items"] if item["kind"] == "assessment")
    assert item["body"] == safe["body"]
    assert item["retained_source_sha256"] == hashlib.sha256(raw).hexdigest()
    stored = system.db.one("SELECT response,response_sha256 FROM session_investigation_reads WHERE id=$1", ident)
    assert stored == {"response": retained, "response_sha256": digest}
    assert system.db.scalar("SELECT body FROM session_snapshot_items WHERE snapshot_id=$1 AND ordinal=$2",
                            prior.claim["snapshot_id"], source["ordinal"]) == source["body"]


def test_risk_polling_excludes_historical_service_identity(system):
    from test_session_investigator import attempt

    value = attempt(system)
    event_id = value.value["target"]["id"]
    risk = {"status": "scored", "score": 20, "model": "private-service-model",
            "usage": {"input_tokens": 100}, "company_policy": {"prompt": "Exact policy model/provider"}}
    system.db.execute("UPDATE events SET risk=$2 WHERE id=$1", event_id, Jsonb(risk))
    response = browser(system, "GET", "events/risks?ids=" + event_id)
    assert response.status_code == 200, response.text
    result = response.json()["items"][0]["risk"]
    assert result == {key: risk[key] for key in ("status", "score", "company_policy")}
    assert browser(system, "GET", "events/risks?ids=" + event_id, user="foreign").json()["items"] == []
    assert system.db.scalar("SELECT risk FROM events WHERE id=$1", event_id) == risk
