"""WorkBuddy's verified native usage contract through setup and accounting."""

import copy
from datetime import datetime, timezone
import json

from fastapi.testclient import TestClient
import pytest

from openaidr.core.agent_usage import extract
from openaidr.core.telemetry import attributes, decode_export, encode_export, records
from openaidr.core.workbuddy_telemetry import USAGE_EVENT, request_logs
from openaidr.sensor import hooks, integrations
from openaidr.sensor.telemetry import Telemetry
from openaidr.server import agent_projects
from openaidr.server.agent_cost_usage import overview, process_pending
from openaidr.server.app import create_app
from test_copilot_telemetry import wire
from test_telemetry_sensor import config
from test_telemetry_server import backend  # noqa: F401


def native_export():
    # Contract from WorkBuddy AI 5.9.4 / @genie/agent-cli 2.165.0:
    # emitCliModelUsageEvent, emitCliExecutionEvent, exportPendingOtelObservations.
    end = int(datetime.now(timezone.utc).timestamp() * 1e9)
    usage = wire({
        "codebuddy.stage.modelRequestId": "request-1", "codebuddy.stage.model": "native-model",
        "codebuddy.stage.inputTokens": 100, "codebuddy.stage.outputTokens": 20,
        "codebuddy.stage.totalTokens": 120, "codebuddy.stage.credit": 99,
        "codebuddy.stage.cacheReadTokens": 0, "codebuddy.stage.cacheWriteTokens": 0,
        "codebuddy.stage.elapsedMs": 250, "cost_usd": 99,
        "input.value": "private-prompt", "output.value": "private-output",
        "llm.prompt.0.content": "private-system", "gen_ai.input.messages": "private-messages",
    })
    parent = {
        "traceId": "11" * 16, "spanId": "22" * 8, "name": "codebuddy_code.interaction",
        "startTimeUnixNano": str(end - 1_000_000_000), "endTimeUnixNano": str(end),
        "attributes": wire({"workbuddy.session.id": "session-1", "workbuddy.project.id": "project-1",
                            "workbuddy.reasoning_effort": "high", "unexpected": "private-extra"}),
        "events": [{"name": USAGE_EVENT, "timeUnixNano": str(end), "attributes": usage}],
    }
    spans = [parent]
    for name in (USAGE_EVENT, "codebuddy_code.cli.model_request", "codebuddy_code.cli.model_stream"):
        spans.append({**parent, "name": name, "spanId": "33" * 8, "attributes": usage, "events": []})
    return {"resourceSpans": [{
        "resource": {"attributes": wire({"service.name": "workbuddy", "private.resource": "private-resource"})},
        "scopeSpans": [{"scope": {"name": "codebuddy_code"}, "spans": spans}],
    }]}


@pytest.mark.parametrize("media", ["application/json", "application/x-protobuf"])
def test_usage_events_and_deferred_spans_deduplicate_without_content(tmp_path, media):
    telemetry = Telemetry(config(tmp_path))
    try:
        body = encode_export("traces", native_export(), media)
        for _ in range(2):
            telemetry.accept("traces", body, media)
        batch = telemetry.queue.next()
        assert batch["signal"] == "logs"
        data = decode_export("logs", batch["body"], batch["content_type"])
        assert "private-" not in json.dumps(data) and "credit" not in json.dumps(data)
        events = list(extract({"id": "batch", "sensor_id": "sensor", "payload": data,
                               "received_at": datetime.now(timezone.utc)}))
        assert len(events) == 2 and events[0]["key"] == events[1]["key"]
        assert events[0]["scope"][-1] == "session-1" and events[1]["scope"][-1] == ""
        assert events[0]["model"] == "native-model" and events[0]["reasoning_effort"] == "high"
        assert events[0]["usage"]["tokens"] == 120 and events[0]["usage"]["cost"] is None
        assert tuple(telemetry.queue.db.execute("SELECT count(*),sum(tokens) FROM usage_calls").fetchone()) == (1, 120)
        assert telemetry.queue.db.execute("SELECT application FROM usage_apps").fetchone()[0] == "workbuddy"
    finally:
        telemetry.close()


@pytest.mark.parametrize("change", ["codebuddy", "missing_id", "missing_input", "fractional", "negative", "nan",
                                    "cache_read", "cache_write", "invalid_cache", "streaming_missing_cache"])
def test_unidentified_or_ambiguous_usage_never_fabricates_counts(change):
    data = native_export()
    resource = data["resourceSpans"][0]
    parent = resource["scopeSpans"][0]["spans"][0]
    resource["scopeSpans"][0]["spans"] = [parent]
    event = parent["events"][0]
    values = attributes(event["attributes"])
    if change == "codebuddy":
        resource["resource"]["attributes"] = wire({"service.name": "codebuddy_code"})
    elif change == "missing_id":
        values.pop("codebuddy.stage.modelRequestId")
    elif change == "missing_input":
        values.pop("codebuddy.stage.inputTokens")
        # Parent totals cannot fill a missing per-request counter.
        parent["attributes"] += wire({"codebuddy.stage.inputTokens": 100})
    elif change == "streaming_missing_cache":
        values.pop("codebuddy.stage.cacheReadTokens")
        values.pop("codebuddy.stage.cacheWriteTokens")
    elif change == "fractional":
        values["codebuddy.stage.inputTokens"] = "1.5"
    elif change in {"negative", "nan"}:
        values["codebuddy.stage.inputTokens"] = -1 if change == "negative" else "NaN"
    else:
        values["codebuddy.stage.cacheWriteTokens" if change == "cache_write" else "codebuddy.stage.cacheReadTokens"] = (
            "invalid" if change == "invalid_cache" else 50
        )
    event["attributes"] = wire(values)
    clean = request_logs(data)
    if change in {"codebuddy", "missing_id"}:
        assert clean == {"resourceLogs": []}
    else:
        assert len(list(records("logs", clean))) == 1  # Keep request metadata, not invented zero usage.
        if "cache" in change:
            retained = attributes(next(records("logs", clean))[2]["attributes"])
            assert retained["workbuddy.usage.unavailable"] == "cache_breakdown"
            assert "input_token_count" not in retained and "output_token_count" not in retained
    assert list(extract({"id": "batch", "sensor_id": "sensor", "payload": clean,
                         "received_at": datetime.now(timezone.utc)})) == []


@pytest.mark.parametrize("cache", [None, 60])
def test_workbuddy_usage_reaches_only_its_tenant_once(backend, tmp_path, cache):
    st, cfg, sensor, token, other, other_token, _ = backend
    telemetry = Telemetry(config(tmp_path))
    try:
        original = native_export()
        # Ordinary streaming omits cache details; nonzero splits are ambiguous.
        ambiguous = copy.deepcopy(original["resourceSpans"][0]["scopeSpans"][0]["spans"][1])
        ambiguous["attributes"] = wire({"codebuddy.stage.modelRequestId": "request-2",
            "codebuddy.stage.inputTokens": 100, "codebuddy.stage.outputTokens": 20,
            **({"codebuddy.stage.cacheReadTokens": cache} if cache is not None else {})})
        original["resourceSpans"][0]["scopeSpans"][0]["spans"].append(ambiguous)
        telemetry.accept("traces", encode_export("traces", original, "application/x-protobuf"), "application/x-protobuf")
        batch = telemetry.queue.next()
        queued = decode_export("logs", batch["body"], batch["content_type"])
        assert tuple(telemetry.queue.db.execute("SELECT count(*),sum(tokens) FROM usage_calls").fetchone()) == (1, 120)
        with TestClient(create_app(cfg, st)) as client:
            for credential, expected in ((token, 200), (token, 200), (other_token, 403)):
                response = client.post("/otlp/v1/logs", content=batch["body"], headers={
                    "Authorization": "Bearer " + credential, "Content-Type": batch["content_type"],
                })
                assert response.status_code == expected, response.text
        persisted = st.one("SELECT payload FROM telemetry_exports WHERE tenant_id=$1", sensor["tenant_id"])["payload"]
        for payload in (queued, persisted):
            retained = [attributes(item["attributes"]) for _, _, item in records("logs", payload)]
            incomplete = next(item for item in retained if item["request_id"] == "request-2")
            assert incomplete["workbuddy.usage.unavailable"] == "cache_breakdown"
            assert not any(key in incomplete for key in
                           ("input_token_count", "output_token_count", "cached_token_count", "cache_write_token_count"))
            assert "private-" not in json.dumps(payload)
        assert process_pending(st)["failed"] == 0
        assert agent_projects.process_pending(st) == 1
        attribution = st.one("SELECT pending,retry_at FROM agent_project_sessions WHERE tenant_id=$1 AND product='workbuddy'",
                             sensor["tenant_id"])
        assert attribution == {"pending": False, "retry_at": None}
        assert agent_projects.process_pending(st) == 0
        result = overview(st, sensor["tenant_id"])
        assert result["processing"]["pending_project_sessions"] == 0
        summary = result["summary"]
        assert summary["calls"] == 1 and summary["tokens"] == 120
        assert summary["unpriced_calls"] == 1 and summary["cost_usd"] is None
        assert overview(st, other["tenant_id"])["summary"]["calls"] == 0
    finally:
        telemetry.close()

def test_workbuddy_profile_detection_does_not_enable_automatic_configuration(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKBUDDY_CONFIG_DIR", str(tmp_path / "custom-profile"))
    monkeypatch.setattr(integrations.shutil, "which", lambda _: None)
    assert not integrations.detect(tmp_path, directories=())["workbuddy_available"]
    (tmp_path / "custom-profile").mkdir()
    assert integrations.detect(tmp_path, directories=())["workbuddy_available"]
    assert "workbuddy" not in integrations.AGENTS and "workbuddy" in hooks.AGENTS
    monkeypatch.delenv("WORKBUDDY_CONFIG_DIR")
    for name in (".workbuddy", ".workbuddy-ai"):
        root = tmp_path / name
        root.mkdir()
        assert integrations.detect(tmp_path, directories=())["workbuddy_available"]
        root.rmdir()
