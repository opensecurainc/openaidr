"""Pinned native Codex with real receiver storage and synthetic provider transport."""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil

import httpx
import pytest
from fastapi.testclient import TestClient

from openaidr_api.runtimes import investigator as codex_investigator
from openaidr.server.guardrail import scoring as risk
from openaidr.server import session_investigator
from openaidr.server.app import create_app
from openaidr_api.runtimes.investigator import Runtime
from openaidr.server.config import Config
from test_inline_guardrail import system as system
from test_session_investigator import MODEL, attempt, canonical, finding_result, no_finding
from test_store import db as db


class FragmentedStream(httpx.SyncByteStream):
    def __init__(self, data):
        self.data = data

    def __iter__(self):
        for offset in range(0, len(self.data), 97):
            yield self.data[offset:offset + 97]


class NativeProvider:
    def __init__(self, system, value, mode, marker):
        self.system, self.value, self.mode, self.marker = system, value, mode, marker
        self.counted, self.inferred = [], []
        self.session_id = value.session_id if mode == "ordinary" else system.db.scalar(
            "SELECT id FROM agent_sessions WHERE registration_id=$1", value.registration["id"],
        )

    def handle(self, request):
        assert request.url.host == "api.openai.com" and request.url.scheme == "https"
        assert request.method == "POST"
        body = json.loads(request.content)
        if request.url.path == "/v1/responses/input_tokens":
            self.counted.append(body)
            return httpx.Response(200, json={
                "object": "response.input_tokens",
                "input_tokens": True if self.mode == "invalid-count" else 1000,
            })
        assert request.url.path == "/v1/responses"
        assert self.mode not in ("token-budget", "invalid-count"), "inference was dispatched despite failed preflight/admission"
        assert self.counted
        for key in ("model", "input", "instructions", "tools", "text", "reasoning"):
            assert body.get(key) == self.counted[-1].get(key), key
        assert body["model"] == MODEL and body["service_tier"] == "default"
        assert body["store"] is False and body["truncation"] == "disabled"
        assert type(body["max_output_tokens"]) is int and body["max_output_tokens"] > 0
        assert not body.get("previous_response_id") and not body.get("conversation")
        assert {tool["name"] for tool in body["tools"]} == (set() if self.mode == "ordinary" else {"search_sessions", "read_session"})
        assert all(item.get("type") != "additional_tools" for item in body["input"])
        # This query is made from the fake provider boundary, after actual
        # admission has committed and before any inference response is returned.
        digest = hashlib.sha256(canonical(body)).hexdigest()
        dispatch = self.system.db.one(
            "SELECT r.state,r.request_sha256,u.purpose,u.investigation_attempt_id FROM session_investigation_requests r JOIN model_usage u ON u.id=r.usage_id WHERE r.attempt_id=$1 AND r.request_sha256=$2",
            self.value.claim["attempt_id"], digest,
        )
        assert dispatch["state"] == "dispatched" and dispatch["purpose"] == "detection"
        assert dispatch["investigation_attempt_id"] == self.value.claim["attempt_id"]
        self.inferred.append(body)
        number = len(self.inferred)
        if number == 1 and self.mode in ("read", "forged-tool"):
            item = {
                "id": "fixture-call", "type": "function_call", "call_id": "fixture-read",
                "name": "exec_command" if self.mode == "forged-tool" else "read_session",
                "arguments": json.dumps(
                    {"cmd": "touch " + str(self.marker)} if self.mode == "forged-tool" else
                    {"session_id": self.session_id, "snapshot_id": None, "cursor": ""}
                ),
            }
        elif number == 1 and self.mode == "hosted-tool":
            item = {"id": "fixture-hosted", "type": "web_search_call", "status": "completed",
                    "action": {"type": "search", "query": "untrusted fixture instruction"}}
        else:
            result = no_finding()
            if self.mode == "incident":
                anchor = self.system.db.one(
                    "SELECT ordinal,kind,source_id,body FROM session_snapshot_items WHERE snapshot_id=$1 AND kind='observation' AND source_id=$2",
                    self.value.claim["snapshot_id"], self.value.value["target"]["id"],
                )
                result = finding_result(self.value, anchor)
            item = {"id": "fixture-message-" + str(number), "type": "message", "role": "assistant",
                    "status": "completed", "content": [{"type": "output_text", "text": json.dumps(result), "annotations": []}]}
        response = {
            "id": "fixture-response-" + str(number), "object": "response", "status": "completed",
            "model": MODEL, "service_tier": "default", "output": [item],
            "usage": {"input_tokens": 1000, "output_tokens": 20, "total_tokens": 1020,
                      "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                      "output_tokens_details": {"reasoning_tokens": 10}},
        }
        if self.mode == "missing-cache-write":
            del response["usage"]["input_tokens_details"]["cache_write_tokens"]
        events = [
            {"type": "response.created", "response": {**response, "status": "in_progress", "output": []}},
            {"type": "response.output_item.added", "output_index": 0, "item": item},
            {"type": "response.output_item.done", "output_index": 0, "item": item},
            {"type": "response.completed", "response": response},
        ]
        if self.mode == "forged-fragments":
            fragments = []
            for index, (name, arguments) in enumerate((
                ("read_session", {"session_id": self.session_id, "snapshot_id": None, "cursor": ""}),
                ("exec_command", {"cmd": "touch " + str(self.marker)}),
            )):
                forged = {"id": "forged-item-" + str(index), "type": "function_call",
                          "call_id": "forged-call-" + str(index), "name": name,
                          "arguments": json.dumps(arguments)}
                fragments.extend([
                    {"type": "response.output_item.added", "output_index": index, "item": forged},
                    {"type": "response.output_item.done", "output_index": index, "item": forged},
                ])
            events[1:1] = fragments
        data = "".join("event: " + row["type"] + "\ndata: " + json.dumps(row) + "\n\n" for row in events)
        return httpx.Response(200, stream=FragmentedStream(data.encode()), headers={"content-type": "text/event-stream"})


def runtime_config(system):
    binary = os.environ.get("OPENAIDR_TEST_CODEX_BINARY") or shutil.which("codex")
    if not binary:
        pytest.skip("pinned Codex 0.160.0 executable is not installed")
    cfg = Config(
        database_url=system.db.url, openai_api_key="synthetic-provider-key",
        session_investigator_binary=str(Path(binary).resolve()),
    )
    probe = Runtime(cfg)
    try:
        readiness = probe.ready(MODEL)
        if not readiness["ready"]:
            pytest.skip("pinned native investigator unavailable: " + readiness["reason"])
        assert "0.160.0" in readiness["version"]
        assert len(readiness["executable_sha256"]) == 64
    finally:
        probe.close()
    return cfg


@pytest.mark.parametrize("mode", ["read", "incident", "forged-tool", "hosted-tool", "forged-fragments", "missing-cache-write", "ordinary"])
def test_native_runtime_uses_only_scoped_reads_and_committed_inference(system, tmp_path, mode):
    from test_remote_investigator import execute, outcome_diagnostics, service

    if mode == "ordinary":
        from types import SimpleNamespace
        from openaidr.server.session_aggregation import claim_job
        from test_ordinary_session_detection import captured, configure, finalize

        configure(system)
        captured_session = captured(system)
        finalize(system, captured_session)
        value = SimpleNamespace(session_id=captured_session.id,
                                claim=claim_job(system.db, "ordinary-native", worker_ready=True))
    else:
        value = attempt(system)
    marker = tmp_path / "forbidden-effect"
    provider = NativeProvider(system, value, mode, marker)
    with service(system, tmp_path, provider) as (_, connection, transport, created, _):
        result = execute(system, value.claim, connection, transport)
    assert created and not marker.exists()
    assert provider.counted and provider.inferred
    reads = system.db.many("SELECT * FROM session_investigation_reads WHERE attempt_id=$1", value.claim["attempt_id"])
    if mode == "read":
        assert result["report_status"] == "no_finding", outcome_diagnostics(system, value.claim, result)
        assert any(row["tool_name"] == "read_session" and row["status"] == "delivered" for row in reads)
        assert len(provider.inferred) >= 2
    elif mode == "incident":
        assert result["report_status"] == "finding", outcome_diagnostics(system, value.claim, result)
        report = system.db.scalar("SELECT report FROM session_investigation_attempts WHERE id=$1", value.claim["attempt_id"])
        assert report["schema_version"] == 4
        assert report["findings"][0]["timeline"][0]["evidence_indices"] == [0]
        assert report["findings"][0]["recommended_actions"]
        assert "review-secret" not in json.dumps(report)
    elif mode == "forged-fragments":
        assert result["report_status"] == "no_finding", outcome_diagnostics(system, value.claim, result)
        assert reads == [] and len(provider.inferred) == 1
    else:
        assert result["report_status"] == "inconclusive"
        assert reads == []
        assert len(provider.inferred) == 1
    usage = system.db.many("SELECT * FROM model_usage WHERE investigation_attempt_id=$1", value.claim["attempt_id"])
    assert len(usage) == len(provider.inferred)
    assert all(row["purpose"] == "detection" and row["input_tokens"] == 1000 and row["output_tokens"] == 20 for row in usage)
    if mode == "missing-cache-write":
        assert usage[0]["cache_write_input_tokens"] is None
        assert usage[0]["cost_usd"] is None
    assert system.db.scalar("SELECT count(*) FROM findings WHERE investigation_job_id=$1", value.claim["job_id"]) == (1 if mode == "incident" else 0)


@pytest.mark.parametrize("mode", ["token-budget", "invalid-count"])
def test_native_preflight_and_budget_rejection_make_no_inference_call(system, tmp_path, mode):
    from test_remote_investigator import execute, service

    value = attempt(system, **({"max_tokens_per_attempt": 100} if mode == "token-budget" else {}))
    provider = NativeProvider(system, value, mode, tmp_path / "forbidden-effect")
    with service(system, tmp_path, provider) as (_, connection, transport, _, _):
        result = execute(system, value.claim, connection, transport)
    assert result["report_status"] == "inconclusive"
    assert provider.counted and provider.inferred == []
    assert system.db.scalar("SELECT count(*) FROM session_investigation_requests WHERE attempt_id=$1", value.claim["attempt_id"]) == 0
    assert system.db.scalar("SELECT count(*) FROM model_usage WHERE investigation_attempt_id=$1", value.claim["attempt_id"]) == 0


def test_tenant_startup_never_dispatches_native_work_without_an_api(system, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from openaidr.server.app import create_app
    from openaidr.server.guardrail import storage as risk

    value = attempt(system)
    assert session_investigator.stop_attempt(system.db, value.claim, "runtime_unavailable", retryable=True)["state"] == "queued"
    cfg = runtime_config(system)
    stores = []
    make_store = risk.risk_store

    def tracked_store(original, **options):
        bounded = make_store(original, **options)
        stores.append(bounded)
        return bounded

    monkeypatch.setattr(risk, "risk_store", tracked_store)
    monkeypatch.setattr(codex_investigator, "Runtime", lambda *args, **kwargs:
                        pytest.fail("Tenant startup invoked the native provider runtime"))
    for scheduling, key in ((False, "synthetic-key"), (True, ""), (True, "synthetic-key")):
        disabled = replace(cfg, tenant_id=system.tenant["id"], cost_processing=False,
                           session_detection_scheduling=scheduling, openai_api_key=key)
        disabled.set_services("api,detect")
        with TestClient(create_app(disabled, system.db)) as client:
            assert client.get("/healthz").status_code == 200
            assert system.db.scalar("SELECT state FROM session_investigation_jobs WHERE id=$1", value.claim["job_id"]) == "queued"
        assert all(pool.closed for bounded in stores for pool in bounded.pools.values())
        stores.clear()
    assert system.db.scalar("SELECT 1") == 1
