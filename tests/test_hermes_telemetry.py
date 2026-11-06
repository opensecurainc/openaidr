"""Hermes plugin exports through local and tenant request accounting."""

import copy
from datetime import datetime, timedelta, timezone
import json

from fastapi.testclient import TestClient
import pytest

from openaidr.core.agent_usage import extract
from openaidr.core.event import new_id
from openaidr.core.hermes_telemetry import request_logs
from openaidr.core.telemetry import attributes, decode_export, encode_export, records
from openaidr.sensor.telemetry import Telemetry
from openaidr.server import agent_projects
from openaidr.server.agent_cost_usage import overview, process_pending
from openaidr.server.app import create_app
from test_copilot_telemetry import wire
from test_telemetry_sensor import config
from test_telemetry_server import backend  # noqa: F401


def native_export():
    # hermes_otel v1.18.2 uses api.* for individual requests and llm.* for
    # the enclosing conversation loop. Both carry token totals.
    end = int(datetime.now(timezone.utc).timestamp() * 1e9)
    request = {
        "traceId": "11" * 16, "spanId": "22" * 8, "name": "api.test-model",
        "startTimeUnixNano": str(end - 2_000_000_000), "endTimeUnixNano": str(end),
        "attributes": wire({
            "gen_ai.operation.name": "chat", "session.id": "hermes-session",
            "gen_ai.request.model": "test-model", "gen_ai.provider.name": "test-provider",
            "gen_ai.usage.input_tokens": 100, "gen_ai.usage.output_tokens": 20,
            "gen_ai.usage.cache_read.input_tokens": 60, "gen_ai.usage.cache_creation.input_tokens": 10,
            "llm.token_count.prompt": 100, "llm.token_count.completion": 20,
            "gen_ai.usage.reasoning.output_tokens": 5,
            "gen_ai.input.messages": "private-prompt", "gen_ai.output.messages": "private-response",
            "input.value": "private-system", "output.value": "private-output",
            "unexpected.attribute": "private-extra", "hermes.cost.usage": "99", "cost_usd": "99",
        }),
        "events": [{"name": "private-event"}],
    }
    spans = []
    for name in ("agent", "llm.test-model", "api.test-model", "tool.terminal"):
        span = copy.deepcopy(request)
        span["name"] = name
        spans.append(span)
    return {"resourceSpans": [{
        "resource": {"attributes": wire({"service.name": "custom-profile",
                                          "unexpected.resource": "private-resource"})},
        "scopeSpans": [{"scope": {"name": "hermes-otel-plugin"}, "spans": spans}],
    }]}


@pytest.mark.parametrize("media", ["application/json", "application/x-protobuf"])
@pytest.mark.parametrize("legacy", [False, True])
def test_hermes_requests_keep_usage_once_without_content_or_parent_totals(tmp_path, media, legacy):
    telemetry = Telemetry(config(tmp_path))
    try:
        original = native_export()
        if legacy:
            for span in original["resourceSpans"][0]["scopeSpans"][0]["spans"]:
                for item in span["attributes"]:
                    item["key"] = {
                        "gen_ai.usage.cache_read.input_tokens": "llm.token_count.prompt_details.cache_read",
                        "gen_ai.usage.cache_creation.input_tokens": "llm.token_count.prompt_details.cache_write",
                    }.get(item["key"], item["key"])
                span["attributes"] = [item for item in span["attributes"] if item["key"] not in
                                      ("gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens")]
        body = encode_export("traces", original, media)
        for _ in range(2):
            telemetry.accept("traces", body, media)
        batch = telemetry.queue.next()
        assert batch["signal"] == "logs"
        data = decode_export("logs", batch["body"], batch["content_type"])
        assert "private-" not in json.dumps(data)
        assert "resourceSpans" not in data
        resource, _, item = next(records("logs", data))
        assert attributes(resource["attributes"])["service.name"] == "hermes-agent"
        assert attributes(item["attributes"])["duration_ms"] == 2000
        events = list(extract({"id": "batch", "sensor_id": "sensor", "payload": data,
                               "received_at": datetime.now(timezone.utc)}))
        assert len(events) == 1
        assert events[0]["scope"][-1] == "hermes-session"
        assert events[0]["usage"] == {
            "tokens": 120, "input_tokens": 30, "output_tokens": 20, "cache_read_tokens": 60,
            "cache_write_tokens": 10, "cost": None, "source": "unpriced",
        }
        assert tuple(telemetry.queue.db.execute("SELECT count(*),sum(tokens) FROM usage_calls").fetchone()) == (1, 120)
        assert telemetry.queue.db.execute("SELECT application FROM usage_apps").fetchone()[0] == "hermes"
    finally:
        telemetry.close()


@pytest.mark.parametrize("change", ["other_scope", "parent", "missing_id", "zero_id", "unfinished", "backwards", "operation"])
def test_only_identified_completed_hermes_api_spans_are_converted(change):
    data = native_export()
    scope = data["resourceSpans"][0]["scopeSpans"][0]
    request = scope["spans"][2]
    scope["spans"] = [request]
    if change == "other_scope":
        scope["scope"]["name"] = "some-other-plugin"
    elif change == "parent":
        request["name"] = "llm.test-model"
    elif change == "missing_id":
        del request["spanId"]
    elif change == "zero_id":
        request["traceId"] = "0" * 32
    elif change == "unfinished":
        del request["endTimeUnixNano"]
    elif change == "backwards":
        request["endTimeUnixNano"] = str(int(request["startTimeUnixNano"]) - 1)
    else:
        request["attributes"] = wire({"gen_ai.operation.name": "invoke_agent"})
    assert request_logs(data) == {"resourceLogs": []}


def test_hermes_usage_reaches_only_the_enrolled_tenant_once(backend, tmp_path):
    st, cfg, sensor, token, other, other_token, _ = backend
    telemetry = Telemetry(config(tmp_path))
    try:
        telemetry.accept("traces", encode_export("traces", native_export(), "application/x-protobuf"),
                         "application/x-protobuf")
        batch = telemetry.queue.next()
        with TestClient(create_app(cfg, st)) as client:
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
        assert summary["calls"] == 1 and summary["tokens"] == 120
        assert summary["unpriced_calls"] == 1 and summary["cost_usd"] is None
        assert overview(st, other["tenant_id"])["summary"]["calls"] == 0
        # Late hook metadata attributes the request without replaying usage.
        for product, directory in (("codex-cli", "unrelated"), ("hermes-agent", "hermes-project")):
            st.ingest_batch(sensor, [{
                "id": new_id(), "time": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                "kind": "session.start", "agent": {"product": product},
                "session": {"id": "hermes-session", "cwd": "/work/" + directory},
            }])
        assert agent_projects.process_pending(st) > 0
        attributed = overview(st, sensor["tenant_id"])
        assert attributed["summary"] == summary
        assert attributed["by_project"][0]["name"] == "hermes-project"
    finally:
        telemetry.close()
