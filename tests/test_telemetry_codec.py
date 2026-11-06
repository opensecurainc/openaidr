"""OTLP wire and privacy regression tests shared by both receivers."""

import gzip
import json

import pytest
from google.rpc.status_pb2 import Status
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
)
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
    ExportMetricsServiceRequest,
)

from openaidr.core.telemetry import (
    TelemetryError,
    attributes,
    count_records,
    decode_export,
    encode_export,
    error_bytes,
    response_bytes,
    scrub_export,
)


def attr(key, value):
    return {"key": key, "value": {"stringValue": value}}


def logs():
    return {
        "resourceLogs": [
            {
                "resource": {"attributes": [attr("service.name", "claude-code")]},
                "scopeLogs": [
                    {
                        "scope": {"name": "claude-code"},
                        "logRecords": [
                            {
                                "timeUnixNano": "1700000000123456789",
                                "severityNumber": 9,
                                "eventName": "claude_code.user_prompt",
                                "body": {"stringValue": "private prompt text"},
                                "traceId": "a" * 32,
                                "spanId": "b" * 16,
                                "attributes": [
                                    attr("event.name", "user_prompt"),
                                    attr("prompt", "private prompt text"),
                                    attr("session.id", "s-1"),
                                    attr("note", "password=hunter22"),
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }


@pytest.mark.parametrize("media", ["application/json", "application/x-protobuf"])
@pytest.mark.parametrize("encoding", ["", "gzip"])
def test_logs_roundtrip(media, encoding):
    data = logs()
    wire = encode_export("logs", data, media)
    if encoding:
        wire = gzip.compress(wire)
    result = decode_export("logs", wire, media + "; charset=utf-8", encoding)
    assert result == data
    assert count_records("logs", result) == 1
    assert response_bytes("logs", media) == (
        b"{}" if media == "application/json" else b""
    )


def test_real_generated_protobuf_and_hex_json_ids():
    request = ExportTraceServiceRequest()
    span = request.resource_spans.add().scope_spans.add().spans.add()
    span.name = "codex.tool_call"
    span.trace_id = bytes.fromhex("12" * 16)
    span.span_id = bytes.fromhex("34" * 8)
    span.parent_span_id = bytes.fromhex("56" * 8)
    span.start_time_unix_nano = 1700000000000000000
    span.end_time_unix_nano = 1700000001000000000
    result = decode_export(
        "traces", request.SerializeToString(), "application/x-protobuf"
    )
    item = result["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    assert item["traceId"] == "12" * 16 and item["parentSpanId"] == "56" * 8
    assert (
        encode_export("traces", result, "application/x-protobuf")
        == request.SerializeToString()
    )
    assert count_records("traces", result) == 1


def test_metrics_keep_integer_precision_and_temporality():
    request = ExportMetricsServiceRequest()
    metric = request.resource_metrics.add().scope_metrics.add().metrics.add()
    metric.name = "claude_code.token.usage"
    metric.sum.aggregation_temporality = 1
    metric.sum.is_monotonic = True
    metric.sum.data_points.add(
        as_int=9007199254740993, time_unix_nano=1700000000000000000
    )
    data = decode_export(
        "metrics", request.SerializeToString(), "application/x-protobuf"
    )
    record = data["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]
    assert record["sum"]["dataPoints"][0]["asInt"] == "9007199254740993"
    assert record["sum"]["aggregationTemporality"] == 1
    assert scrub_export("metrics", data) == data
    assert count_records("metrics", data) == 1


def test_unknown_fields_ignored_and_invalid_body_rejected():
    data = logs()
    data["futureField"] = True
    assert (
        decode_export("logs", json.dumps(data).encode(), "application/json") == logs()
    )
    for data in (
        b"[]",
        b"{",
        b'{"resourceLogs":"bad"}',
        b'{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":"bad"}]}]}]}',
    ):
        with pytest.raises(TelemetryError):
            decode_export("logs", data, "application/json")
    with pytest.raises(TelemetryError):
        decode_export("logs", b"not protobuf", "application/x-protobuf")
    with pytest.raises(TelemetryError):
        decode_export(
            "traces",
            b'{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"hello"}]}]}]}',
            "application/json",
        )
    with pytest.raises(TelemetryError) as error:
        decode_export("logs", b"{}", "text/plain")
    assert error.value.status == 415
    with pytest.raises(TelemetryError):
        decode_export("logs", b"bad gzip", "application/json", "gzip")


def test_compressed_and_wire_limits(monkeypatch):
    monkeypatch.setattr("openaidr.core.telemetry.MAX_BODY_BYTES", 100)
    for body, encoding in [(b" " * 101, ""), (gzip.compress(b" " * 1000), "gzip")]:
        with pytest.raises(TelemetryError) as error:
            decode_export("logs", body, "application/json", encoding)
        assert error.value.status == 413


def test_malformed_nested_json_and_deflate_are_client_errors():
    nested = b'{"unknown":' + b"[" * 1200 + b"0" + b"]" * 1200 + b"}"
    with pytest.raises(TelemetryError) as error:
        decode_export("logs", nested, "application/json")
    assert error.value.status == 400
    corrupt = bytearray(gzip.compress(b"{}"))
    corrupt[10] = 7  # Reserved DEFLATE block type after a valid gzip header.
    with pytest.raises(TelemetryError) as error:
        decode_export("logs", bytes(corrupt), "application/json", "gzip")
    assert error.value.status == 400


def test_content_policy_and_secret_redaction():
    original = logs()
    clean = scrub_export("logs", original)
    record = clean["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    assert record["body"]["stringValue"] == "[REDACTED]"
    attrs = attributes(record["attributes"])
    assert attrs["prompt"] == "[REDACTED]" and attrs["session.id"] == "s-1"
    assert "hunter22" not in attrs["note"]
    assert (
        original["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"][
            "stringValue"
        ]
        == "private prompt text"
    )
    assert "private prompt text" in json.dumps(
        scrub_export("logs", original, capture_prompts=True)
    )


def test_numeric_usage_counters_survive_without_exposing_token_credentials():
    data = logs()
    record = data["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    valid = [
        {"key": "input_token_count", "value": {"intValue": "1000"}},
        {"key": "output_token_count", "value": {"stringValue": "200"}},
        {"key": "cached_token_count", "value": {"doubleValue": 100.0}},
        {"key": "cache_write_token_count", "value": {"intValue": "0"}},
        {"key": "reasoning_token_count", "value": {"intValue": "50"}},
    ]
    record["attributes"] = valid + [attr("access_token", "123456"), attr("input_token_count_extra", "123456")]
    cleaned = scrub_export("logs", data)
    attrs = attributes(cleaned["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"])
    assert [attrs[item["key"]] for item in valid] == ["1000", "200", "100", "0", "50"]
    assert attrs["access_token"] == attrs["input_token_count_extra"] == "[REDACTED]"
    for wire in ({"stringValue": "credential-secret"}, {"intValue": "-1"},
                 {"doubleValue": 1.5}, {"boolValue": True},
                 {"intValue": str(2**53)}, {"arrayValue": {"values": [{"stringValue": "secret"}]}}):
        record["attributes"] = [{"key": "input_token_count", "value": wire}]
        cleaned = scrub_export("logs", data)
        assert attributes(cleaned["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"])["input_token_count"] == "[REDACTED]"


def test_tool_content_and_nested_keys():
    data = logs()
    record = data["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    record.update(
        eventName="codex.tool_result", body={"stringValue": "codex.tool_result"}
    )
    record["attributes"] = [
        attr("arguments", json.dumps({"command": "echo hi", "password": "never-send"})),
        attr("output", "output contents"),
    ]
    clean = scrub_export("logs", data)
    assert "echo hi" not in json.dumps(clean) and "output contents" not in json.dumps(
        clean
    )
    clean = scrub_export("logs", data, capture_tool_details=True)
    assert "echo hi" in json.dumps(clean) and "never-send" not in json.dumps(clean)


def test_otlp_error_encoding():
    assert (
        json.loads(error_bytes(16, "sensor token required", "application/json"))["code"]
        == 16
    )
    message = Status.FromString(error_bytes(8, "queue full", "application/x-protobuf"))
    assert message.code == 8 and message.message == "queue full"


def test_flatten_records_gives_one_row_per_record_or_point():
    from openaidr.core.telemetry import flatten_records

    resource = {
        "attributes": [
            {"key": "service.name", "value": {"stringValue": "codex-cli"}},
            {"key": "host.name", "value": {"stringValue": "devbox"}},
        ]
    }
    logs = {
        "resourceLogs": [
            {
                "resource": resource,
                "scopeLogs": [
                    {
                        "scope": {"name": "openaidr.demo.codex"},
                        "logRecords": [
                            {
                                "timeUnixNano": "1700000000123456789",
                                "severityText": "INFO",
                                "eventName": "codex.tool_result",
                                "body": {"stringValue": "codex.tool_result"},
                                "attributes": [
                                    {
                                        "key": "tool_name",
                                        "value": {"stringValue": "exec_command"},
                                    },
                                    {"key": "success", "value": {"boolValue": True}},
                                    {"key": "duration_ms", "value": {"intValue": "42"}},
                                ],
                            },
                            {
                                "body": {
                                    "kvlistValue": {
                                        "values": [
                                            {
                                                "key": "nested",
                                                "value": {"stringValue": "x"},
                                            }
                                        ]
                                    }
                                }
                            },
                        ],
                    }
                ],
            }
        ]
    }
    rows = flatten_records("logs", logs)
    assert [row["kind"] for row in rows] == ["log", "log"]
    assert rows[0]["time"] == "2023-11-14T22:13:20.123456Z"
    assert rows[0]["service"] == "codex-cli" and rows[0]["host"] == "devbox"
    assert rows[0]["scope"] == "openaidr.demo.codex"
    assert rows[0]["event_name"] == "codex.tool_result"
    assert rows[0]["attributes"] == {
        "tool_name": "exec_command",
        "success": True,
        "duration_ms": "42",
    }
    assert rows[1]["time"] is None and rows[1]["body"] == {"nested": "x"}

    metrics = {
        "resourceMetrics": [
            {
                "resource": resource,
                "scopeMetrics": [
                    {
                        "metrics": [
                            {
                                "name": "codex.api_request",
                                "unit": "{request}",
                                "sum": {
                                    "aggregationTemporality": 1,
                                    "isMonotonic": True,
                                    "dataPoints": [
                                        {
                                            "timeUnixNano": "1700000000000000000",
                                            "asInt": "1",
                                        },
                                        {
                                            "timeUnixNano": "1700000001000000000",
                                            "asInt": "2",
                                        },
                                    ],
                                },
                            },
                            {
                                "name": "codex.api_request.duration_ms",
                                "histogram": {
                                    "dataPoints": [
                                        {
                                            "count": "1",
                                            "sum": 220.0,
                                            "explicitBounds": [500],
                                        }
                                    ]
                                },
                            },
                        ]
                    }
                ],
            }
        ]
    }
    rows = flatten_records("metrics", metrics)
    assert [(row["name"], row["metric_type"], row["value"]) for row in rows] == [
        ("codex.api_request", "sum", 1),
        ("codex.api_request", "sum", 2),
        ("codex.api_request.duration_ms", "histogram", {"count": "1", "sum": 220.0}),
    ]
    assert rows[0]["monotonic"] is True and rows[0]["unit"] == "{request}"

    traces = {
        "resourceSpans": [
            {
                "resource": resource,
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "name": "openaidr.demo.turn",
                                "traceId": "abc",
                                "spanId": "def",
                                "startTimeUnixNano": "1700000000000000000",
                                "endTimeUnixNano": "1700000000250000000",
                                "status": {"code": 2, "message": "boom"},
                                "events": [{"name": "exception"}],
                            }
                        ]
                    }
                ],
            }
        ]
    }
    rows = flatten_records("traces", traces)
    assert rows[0]["kind"] == "span" and rows[0]["duration_ms"] == 250
    assert rows[0]["status"] == 2 and rows[0]["status_message"] == "boom"
    assert rows[0]["event_count"] == 1 and rows[0]["trace_id"] == "abc"
    assert flatten_records("logs", {}) == []
