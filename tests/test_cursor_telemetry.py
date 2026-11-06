"""Cursor Enterprise exports, reported identities, and request deduplication."""

import copy
from datetime import datetime, timezone
import json

from fastapi.testclient import TestClient
import pytest

from openaidr.core.agent_usage import extract
from openaidr.core.telemetry import attributes, encode_export, records, scrub_export
from openaidr.server.agent_costs import extract as attributed
from openaidr.server.agent_cost_usage import overview, process_pending
from openaidr.server.app import create_app
from test_telemetry_dashboard import cost_payload
from test_telemetry_server import backend  # noqa: F401


def native_export(event_id="customer-telemetry:v1:request-1", *, user="member@example.test", team=123):
    data = cost_payload("cursor", datetime.now(timezone.utc), [("cursor.api.request", {
        "cursor.event.id": event_id, "cursor.usage_event.id": "usage-1", "cursor.conversation.id": "chat-1",
        "cursor.request.id": "request-1", "cursor.model.name": "reported-model",
        "cursor.api.request.input_tokens": 30, "cursor.api.request.output_tokens": 20,
        "cursor.api.request.cache_read_tokens": 60, "cursor.api.request.cache_creation_tokens": 10,
        "cost_usd": 99,
    })])
    resource = data["resourceLogs"][0]["resource"]["attributes"]
    resource.append({"key": "cursor.team.id", "value": {"intValue": str(team)}})
    if user:
        resource.append({"key": "cursor.user.email", "value": {"stringValue": user}})
    return data


def envelope(data, **overrides):
    return {"id": "batch", "sensor_id": "dedicated-source", "payload": data,
            "received_at": datetime.now(timezone.utc), "username": "collector-operator", **overrides}


@pytest.mark.parametrize("event_name", ["eventName", "body", "attribute"])
def test_cursor_native_usage_and_identity_survive_local_filtering(event_name):
    data = native_export()
    item = next(records("logs", data))[2]
    if event_name == "body":
        item.pop("eventName")
        item["body"] = {"stringValue": "api_request"}
    elif event_name == "attribute":
        item["attributes"].append({"key": "event.name", "value": {"stringValue": item.pop("eventName")}})
    clean = scrub_export("logs", data)
    event, = attributed(envelope(clean))
    assert event["name"] == "cursor.api_request"
    assert event["user"] == "member@example.test"
    assert event["model"] == "reported-model"
    assert event["scope"][-1] == "chat-1"
    assert event["usage"] == {"tokens": 120, "input_tokens": 30, "output_tokens": 20,
                              "cache_read_tokens": 60, "cache_write_tokens": 10,
                              "cost": None, "source": "unpriced"}
    assert event["key"] == next(extract(envelope(data, id="retry", sensor_id="replacement-source")))["key"]
    other_team = next(extract(envelope(native_export(team=456))))
    assert event["key"] != other_team["key"]


@pytest.mark.parametrize("identity, expected", [
    ({}, "Unattributed"), ({"cursor.user.account_id": "user_123"}, "user_123"),
    ({"cursor.user.account_id": "user_123", "cursor.user.email": "member@example.test"}, "member@example.test"),
])
def test_cursor_never_attributes_unowned_requests_to_collector_operator(identity, expected):
    data = native_export(user="")
    data["resourceLogs"][0]["resource"]["attributes"].extend(
        {"key": key, "value": {"stringValue": value}} for key, value in identity.items()
    )
    assert next(attributed(envelope(data)))["user"] == expected


@pytest.mark.parametrize("field,value", [
    ("cursor.event.id", None), ("cursor.event.id", ""), ("cursor.team.id", None),
    ("cursor.team.id", "invalid"), ("cursor.api.request.input_tokens", "-1"),
    ("cursor.api.request.output_tokens", "0.5"), ("cursor.api.request.cache_read_tokens", None),
    ("cursor.api.request.cache_creation_tokens", "secret-token-value"),
])
def test_cursor_malformed_usage_or_identity_is_not_counted(field, value):
    data = native_export()
    resource, _, item = next(records("logs", data))
    target = resource if field == "cursor.team.id" else item
    target["attributes"] = [entry for entry in target["attributes"] if entry["key"] != field]
    if value is not None:
        target["attributes"].append({"key": field, "value": {"stringValue": value}})
    assert list(extract(envelope(data))) == []


@pytest.mark.parametrize("event_name,direction,control", [
    ("user_message", "", "prompt_text"), ("assistant_message", "", "response_text"),
    ("tool_io", "arguments", "tool_input"), ("tool_io", "result", "tool_output"),
])
@pytest.mark.parametrize("enabled", [False, True])
def test_cursor_relay_content_respects_native_and_managed_capture(event_name, direction, control, enabled):
    data = native_export()
    item = next(records("logs", data))[2]
    item["eventName"] = "cursor.conversation." + event_name
    item["body"] = {"stringValue": "private-message-or-tool-content"}
    item["attributes"].append({"key": "cursor.conversation.tool_io.direction", "value": {"stringValue": direction}})
    for native_enabled, capture in ((enabled, None), (True, {control: enabled})):
        clean = scrub_export("logs", data, capture_prompts=native_enabled, capture_tool_details=native_enabled, capture=capture)
        body = next(records("logs", clean))[2]["body"]["stringValue"]
        assert body == ("private-message-or-tool-content" if enabled else "[REDACTED]")


@pytest.mark.parametrize("direction", [
    {"stringValue": "unknown"}, {"arrayValue": {"values": [{"stringValue": "arguments"}]}},
])
def test_cursor_relay_unknown_tool_direction_does_not_release_content(direction):
    data = native_export()
    item = next(records("logs", data))[2]
    item["eventName"] = "cursor.conversation.tool_io"
    item["body"] = {"stringValue": "private-tool-content"}
    item["attributes"].append({"key": "cursor.conversation.tool_io.direction", "value": direction})
    clean = scrub_export("logs", data, capture_tool_details=True, capture={"tool_input": True, "tool_output": True})
    assert next(records("logs", clean))[2]["body"] == {"stringValue": "[REDACTED]"}


def test_cursor_enterprise_delivery_preserves_evidence_and_counts_retries_once(backend):
    st, cfg, sensor, token, other, other_token, _ = backend
    payload = native_export()
    unowned = native_export("customer-telemetry:v1:request-2", user="")
    second_user = native_export("customer-telemetry:v1:request-3", user="second@example.test")
    correction = copy.deepcopy(payload)
    item = next(records("logs", correction))[2]
    item["eventName"] = "cursor.api.correction"
    item["body"] = {"stringValue": "api_correction_not_billed_errored"}
    item["attributes"] = [entry for entry in item["attributes"] if entry["key"] == "cursor.usage_event.id"]
    item["attributes"].append({"key": "cursor.event.id", "value": {"stringValue": "correction-1"}})
    metrics = {"resourceMetrics": [{"resource": payload["resourceLogs"][0]["resource"], "scopeMetrics": [{
        "metrics": [{"name": "cursor.cost.usage", "unit": "USD", "sum": {
            "aggregationTemporality": 1, "isMonotonic": True,
            "dataPoints": [{"asDouble": 0.25, "timeUnixNano": str(int(datetime.now(timezone.utc).timestamp() * 1e9))}],
        }}],
    }]}]}
    with TestClient(create_app(cfg, st)) as client:
        for media in ("application/json", "application/x-protobuf"):
            body = encode_export("logs", payload, media)
            for bearer, expected in (("invalid", 401), (other_token, 403), (token, 200)):
                result = client.post("/otlp/v1/logs", content=body, headers={
                    "Content-Type": media, "Authorization": "Bearer " + bearer,
                })
                assert result.status_code == expected, result.text
        # Rebatching and another observation cannot manufacture new requests.
        combined = {"resourceLogs": payload["resourceLogs"] + unowned["resourceLogs"] + second_user["resourceLogs"]}
        for signal, data in (("logs", combined), ("logs", correction), ("metrics", metrics)):
            result = client.post("/otlp/v1/" + signal, content=encode_export(signal, data, "application/x-protobuf"), headers={
                "Content-Type": "application/x-protobuf", "Authorization": "Bearer " + token,
            })
            assert result.status_code == 200, result.text
    assert process_pending(st)["failed"] == 0
    data = overview(st, sensor["tenant_id"])
    assert data["summary"]["calls"] == 3
    assert data["summary"]["tokens"] == 360
    assert data["summary"]["unpriced_calls"] == 3
    assert data["summary"]["cost_usd"] is None
    assert {row["name"] for row in data["by_user"]} == {"member@example.test", "second@example.test", "Unattributed"}
    assert "PRIVATE-PROMPT" not in json.dumps(data)
    assert overview(st, other["tenant_id"])["summary"]["calls"] == 0
    # Native metrics and correction records remain available for reconciliation.
    assert st.scalar("SELECT count(*) FROM telemetry_exports WHERE tenant_id=$1 AND signal='metrics'", sensor["tenant_id"]) == 1
    retained = st.one("SELECT payload FROM telemetry_exports WHERE tenant_id=$1 AND signal='metrics'", sensor["tenant_id"])
    assert retained["payload"] == metrics
    assert attributes(next(records("logs", payload))[2]["attributes"])["cost_usd"] == "99"
