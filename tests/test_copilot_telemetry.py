"""Copilot's native OTLP spans through durable usage accounting."""

import copy
from datetime import datetime, timezone
import json

from fastapi.testclient import TestClient
import pytest

from openaidr.core.agent_usage import extract
from openaidr.core.copilot_telemetry import request_logs
from openaidr.core.telemetry import attributes, decode_export, encode_export, records
from openaidr.sensor.telemetry import Telemetry
from openaidr.server.agent_cost_usage import overview, process_pending
from openaidr.server.app import create_app
from test_telemetry_sensor import config
from test_telemetry_server import backend  # noqa: F401


def wire(values):
    return [{"key": key, "value": {"intValue" if type(value) is int else "stringValue": str(value)}}
            for key, value in values.items()]


def native_export():
    end = int(datetime.now(timezone.utc).timestamp() * 1e9)
    chat = {
        "traceId": "11" * 16, "spanId": "22" * 8, "name": "chat model",
        "startTimeUnixNano": str(end - 2_000_000_000), "endTimeUnixNano": str(end),
        "attributes": wire({
            "gen_ai.operation.name": "chat", "gen_ai.conversation.id": "native-session",
            "gen_ai.response.model": "gpt-6.1-sol", "gen_ai.response.id": "response-id",
            "gen_ai.usage.input_tokens": 100, "gen_ai.usage.output_tokens": 20,
            "gen_ai.usage.cache_read.input_tokens": 60,
            "gen_ai.usage.cache_creation.input_tokens": 10,
            "github.copilot.cost": 3, "github.copilot.nano_aiu": 500,
            "gen_ai.input.messages": "private-prompt", "gen_ai.output.messages": "private-response",
            "gen_ai.system_instructions": "private-system", "unexpected.attribute": "private-extra",
            "cost_usd": 99,
        }),
        "events": [{"name": "private-event"}],
    }
    parent = copy.deepcopy(chat)
    parent["attributes"] = wire({"gen_ai.operation.name": "invoke_agent", "gen_ai.usage.input_tokens": 100})
    tool = copy.deepcopy(chat)
    tool["attributes"] = wire({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.call.result": "private-output"})
    return {"resourceSpans": [{
        "resource": {"attributes": wire({"service.name": "github-copilot", "service.version": "1.0",
                                          "unexpected.resource": "private-resource"})},
        "scopeSpans": [{"scope": {"name": "github.copilot"}, "spans": [parent, chat, tool]}],
    }]}


@pytest.mark.parametrize("media", ["application/json", "application/x-protobuf"])
def test_copilot_usage_survives_filtering_and_retries_without_raw_traces(tmp_path, media):
    telemetry = Telemetry(config(tmp_path))
    try:
        original = native_export()
        body = encode_export("traces", original, media)
        for _ in range(2):
            telemetry.accept("traces", body, media)
        batch = telemetry.queue.next()
        assert batch["signal"] == "logs"
        data = decode_export("logs", batch["body"], batch["content_type"])
        assert "private-" not in json.dumps(data)
        assert "resourceSpans" not in data
        retained = list(records("logs", data))
        assert len(retained) == 1
        assert attributes(retained[0][2]["attributes"])["duration_ms"] == 2000
        events = list(extract({"id": "batch", "sensor_id": "sensor", "payload": data,
                               "received_at": datetime.now(timezone.utc)}))
        assert len(events) == 1
        assert events[0]["scope"][-1] == "native-session"
        assert events[0]["usage"] == {
            "tokens": 120, "input_tokens": 30, "output_tokens": 20,
            "cache_read_tokens": 60, "cache_write_tokens": 10, "cost": None, "source": "unpriced",
        }
        assert tuple(telemetry.queue.db.execute("SELECT count(*),sum(tokens) FROM usage_calls").fetchone()) == (1, 120)
        assert telemetry.queue.db.execute("SELECT application FROM usage_apps").fetchone()[0] == "copilot"
        # The aggregate parent and metrics must never create extra request usage.
        metrics = {"resourceMetrics": [{
            "resource": {"attributes": wire({"service.name": "github-copilot"})},
            "scopeMetrics": [{"metrics": [{"name": "gen_ai.client.token.usage",
                                             "gauge": {"dataPoints": [{"asInt": "120"}]}}]}],
        }]}
        telemetry.accept("metrics", encode_export("metrics", metrics, media), media)
        assert telemetry.queue.db.execute("SELECT count(*) FROM usage_calls").fetchone()[0] == 1
    finally:
        telemetry.close()


@pytest.mark.parametrize("change", ["other_agent", "parent", "missing_id", "zero_id", "unfinished", "backwards"])
def test_only_identified_completed_copilot_requests_are_converted(change):
    data = native_export()
    resource = data["resourceSpans"][0]
    scope = resource["scopeSpans"][0]
    chat = scope["spans"][1]
    scope["spans"] = [chat]
    if change == "other_agent":
        resource["resource"]["attributes"] = wire({"service.name": "codex-cli"})
        scope["scope"] = {"name": "codex"}
    elif change == "parent":
        chat["attributes"] = wire({"gen_ai.operation.name": "invoke_agent"})
    elif change == "missing_id":
        del chat["spanId"]
    elif change == "zero_id":
        chat["traceId"] = "0" * 32
    elif change == "unfinished":
        del chat["endTimeUnixNano"]
    else:
        chat["endTimeUnixNano"] = str(int(chat["startTimeUnixNano"]) - 1)
    assert request_logs(data) == {"resourceLogs": []}


def test_copilot_usage_reaches_tenant_accounting_once(backend, tmp_path):
    st, cfg, sensor, token, other, other_token, _ = backend
    telemetry = Telemetry(config(tmp_path))
    try:
        telemetry.accept("traces", encode_export("traces", native_export(), "application/x-protobuf"),
                         "application/x-protobuf")
        batch = telemetry.queue.next()
        with TestClient(create_app(cfg, st)) as client:
            # Native exporters can retry without an OpenAIDR batch header.
            for _ in range(2):
                result = client.post("/otlp/v1/logs", content=batch["body"], headers={
                    "Authorization": "Bearer " + token, "Content-Type": batch["content_type"],
                })
                assert result.status_code == 200, result.text
            rejected = client.post("/otlp/v1/logs", content=batch["body"], headers={
                "Authorization": "Bearer " + other_token, "Content-Type": batch["content_type"],
            })
            assert rejected.status_code == 403
        assert process_pending(st)["failed"] == 0
        summary = overview(st, sensor["tenant_id"])["summary"]
        assert summary["calls"] == 1
        assert summary["tokens"] == 120
        assert summary["unpriced_calls"] == 1
        assert summary["cost_usd"] is None
        assert overview(st, other["tenant_id"])["summary"]["calls"] == 0
    finally:
        telemetry.close()
