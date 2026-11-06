"""OTLP/HTTP codecs shared by the local service and tenant receiver.

The generated OpenTelemetry messages validate the wire schema. OTLP JSON uses
hexadecimal trace/span IDs, unlike generic protobuf JSON's base64 byte fields.
"""

from __future__ import annotations

import base64
import copy
import gzip
import io
import json
import re
import zlib

from google.protobuf.json_format import MessageToDict, ParseDict, ParseError
from google.protobuf.message import DecodeError
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
    ExportLogsServiceResponse,
)
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
    ExportMetricsServiceRequest,
    ExportMetricsServiceResponse,
)
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)

from openaidr.core.redact import is_secret_key, redact_string

MAX_BODY_BYTES = 8 << 20
CAPTURE_GAPS_ATTRIBUTE = "openaidr.capture.gaps"
SIGNALS = {
    "logs": (
        ExportLogsServiceRequest,
        ExportLogsServiceResponse,
        "resourceLogs",
        "scopeLogs",
        "logRecords",
    ),
    "metrics": (
        ExportMetricsServiceRequest,
        ExportMetricsServiceResponse,
        "resourceMetrics",
        "scopeMetrics",
        "metrics",
    ),
    "traces": (
        ExportTraceServiceRequest,
        ExportTraceServiceResponse,
        "resourceSpans",
        "scopeSpans",
        "spans",
    ),
}
_ID_LENGTH = {
    "traceId": 32,
    "trace_id": 32,
    "spanId": 16,
    "span_id": 16,
    "parentSpanId": 16,
    "parent_span_id": 16,
}


class TelemetryError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = self.status_code = status


def media_type(content_type: str) -> str:
    value = content_type.split(";", 1)[0].strip().lower()
    if value not in ("application/json", "application/x-protobuf"):
        raise TelemetryError("use application/json or application/x-protobuf", 415)
    return value


def _classes(signal):
    if signal not in SIGNALS:
        raise TelemetryError("unknown OTLP signal", 404)
    return SIGNALS[signal]


def _convert_ids(value, to_protobuf=False):
    if isinstance(value, list):
        return [_convert_ids(item, to_protobuf) for item in value]
    if not isinstance(value, dict):
        return value
    out = {}
    for key, item in value.items():
        if key in _ID_LENGTH:
            if not isinstance(item, str):
                raise TelemetryError("invalid " + key)
            try:
                if to_protobuf:
                    if item and (
                        len(item) != _ID_LENGTH[key]
                        or not re.fullmatch(r"[0-9a-fA-F]+", item)
                    ):
                        raise ValueError()
                    item = base64.b64encode(bytes.fromhex(item)).decode()
                else:
                    raw = base64.b64decode(item, validate=True)
                    if raw and len(raw) * 2 != _ID_LENGTH[key]:
                        raise ValueError()
                    item = raw.hex()
            except (ValueError, TypeError) as exc:
                raise TelemetryError("invalid " + key) from exc
            out[key] = item
        else:
            out[key] = _convert_ids(item, to_protobuf)
    return out


def _message_dict(message):
    return _convert_ids(MessageToDict(message, use_integers_for_enums=True))


def _parse_dict(payload, message):
    if not isinstance(payload, dict):
        raise TelemetryError("OTLP export must be an object")
    try:
        ParseDict(_convert_ids(payload, True), message, ignore_unknown_fields=True)
    except (ParseError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise TelemetryError("invalid OTLP payload") from exc
    return message


def decode_export(
    signal: str, body: bytes, content_type: str, content_encoding: str = ""
) -> dict:
    request, *_ = _classes(signal)
    media = media_type(content_type)
    if len(body) > MAX_BODY_BYTES:
        raise TelemetryError("OTLP export exceeds size limit", 413)
    encoding = content_encoding.strip().lower()
    if encoding not in ("", "identity", "gzip"):
        raise TelemetryError("unsupported content encoding", 415)
    if encoding == "gzip":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                body = stream.read(MAX_BODY_BYTES + 1)
        except (OSError, EOFError, zlib.error) as exc:
            raise TelemetryError("invalid gzip body") from exc
        if len(body) > MAX_BODY_BYTES:
            raise TelemetryError("decompressed OTLP export exceeds size limit", 413)
    message = request()
    if media == "application/json":
        try:

            def invalid_constant(value):
                raise ValueError("non-JSON numeric constant")

            payload = json.loads(body, parse_constant=invalid_constant)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise TelemetryError("invalid OTLP JSON") from exc
        _parse_dict(payload, message)
    else:
        try:
            message.ParseFromString(body)
        except DecodeError as exc:
            raise TelemetryError("invalid OTLP protobuf") from exc
    return _message_dict(message)


def encode_export(
    signal: str, payload: dict, content_type: str = "application/json"
) -> bytes:
    request, *_ = _classes(signal)
    message = _parse_dict(payload, request())
    if media_type(content_type) == "application/json":
        return json.dumps(
            _message_dict(message), separators=(",", ":"), ensure_ascii=False
        ).encode()
    return message.SerializeToString()


def response_bytes(signal: str, content_type: str) -> bytes:
    _, response, *_ = _classes(signal)
    return (
        b"{}"
        if media_type(content_type) == "application/json"
        else response().SerializeToString()
    )


def records(signal: str, payload: dict):
    _, _, resources, scopes, items = _classes(signal)
    for resource in payload.get(resources, []):
        for scope in resource.get(scopes, []):
            for item in scope.get(items, []):
                yield resource.get("resource", {}), scope.get("scope", {}), item


def count_records(signal: str, payload: dict) -> int:
    if signal != "metrics":
        return sum(1 for _ in records(signal, payload))
    return sum(
        len(metric.get(kind, {}).get("dataPoints", []))
        for _, _, metric in records(signal, payload)
        for kind in ("gauge", "sum", "histogram", "exponentialHistogram", "summary")
    )


def attributes(values: list | None) -> dict:
    def unwrap(value):
        if "arrayValue" in value:
            return [unwrap(item) for item in value["arrayValue"].get("values", [])]
        if "kvlistValue" in value:
            return attributes(value["kvlistValue"].get("values", []))
        for key in (
            "stringValue",
            "boolValue",
            "intValue",
            "doubleValue",
            "bytesValue",
        ):
            if key in value:
                return value[key]
        return None

    return {
        item["key"]: unwrap(item.get("value", {}))
        for item in values or []
        if "key" in item
    }


_PROMPTS = {
    "prompt",
    "user_prompt",
    "response",
    "response.model_output",
    "system_prompt",
    "system_prompt_preview",
    "user_system_prompt",
    "new_context",
    "gen_ai.prompt",
    "gen_ai.completion",
    "gen_ai.input.messages",
    "gen_ai.output.messages",
}
_TOOL_CONTENT = {
    "tool_input",
    "tool_parameters",
    "tool_output",
    "tool.output",
    "output",
    "arguments",
    "command",
    "cmd",
    "bash_command",
    "full_command",
    "input",
    "cursor.grok_bot.shell.command",
    "cursor.grok_bot.shell.blocked_reason",
    "cursor.grok_bot.shell.classification_reasons",
    "cursor.grok_bot.browser.url",
    "cursor.grok_bot.browser.page_title",
}
_RAW_CONTENT = {
    "api_request_body",
    "api_response_body",
    "request_body",
    "response_body",
    "body_ref",
}
_REDACTED = "[REDACTED]"
_TOKEN_COUNTERS = {
    "estimate.input_tokens", "estimate.output_tokens",
    "input_token_count", "output_token_count", "cached_token_count",
    "cache_write_token_count", "reasoning_token_count",
    "cursor.api.request.input_tokens", "cursor.api.request.output_tokens",
    "cursor.api.request.cache_read_tokens", "cursor.api.request.cache_creation_tokens",
}


def scrub_export(
    signal: str,
    payload: dict,
    capture_prompts: bool = False,
    capture_tool_details: bool = False,
    *,
    capture: dict | None = None,
) -> dict:
    """Apply local collection choices and secret redaction before durable storage.

    Resource metadata, counters, histograms and trace IDs remain intact. Raw API
    bodies are never forwarded by this endpoint application.
    """
    _classes(signal)
    gaps = set()
    blocked = (
        _RAW_CONTENT
        | (set() if capture_prompts else _PROMPTS)
        | (set() if capture_tool_details else _TOOL_CONTENT)
    )
    if capture is not None:
        responses = {
            "response",
            "response.model_output",
            "gen_ai.completion",
            "gen_ai.output.messages",
        }
        outputs = {"tool_output", "tool.output", "output"}
        if not capture.get("prompt_text"):
            blocked |= _PROMPTS - responses
        if not capture.get("response_text"):
            blocked |= responses
        if not capture.get("tool_output"):
            blocked |= outputs
        if not capture.get("tool_input"):
            blocked |= (_TOOL_CONTENT - outputs) | {
                "path",
                "file_path",
                "file.path",
                "cwd",
                "url",
                "host",
                "tool.input",
                "tool.arguments",
                "tool_parameters",
            }

    def clean_text(text):
        # Some exporters put tool arguments in a JSON-encoded string attribute.
        structured = False
        if text.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, (dict, list)):
                    text = json.dumps(
                        clean_json(parsed), ensure_ascii=False, separators=(",", ":")
                    )
                    structured = True
            except (ValueError, RecursionError):
                pass
        if not structured:
            text, reasons = redact_string(text)
            if reasons:
                gaps.add("content_redacted")
        if capture is not None:
            limit = capture.get("max_text_bytes", 16384)
            if len(text.encode()) > limit:
                text = text.encode()[:limit].decode("utf-8", errors="ignore")
                gaps.add("content_truncated")
        return text

    def sensitive(key):
        key = key.lower()
        if key in blocked:
            gaps.add("capture_disabled")
            return True
        if is_secret_key(key):
            gaps.add("content_redacted")
            return True
        return False

    def clean_json(value):
        if isinstance(value, dict):
            return {
                key: _REDACTED if sensitive(key) else clean_json(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [clean_json(item) for item in value]
        return clean_text(value) if isinstance(value, str) else value

    def clean_wire(value):
        if isinstance(value, list):
            return [clean_wire(item) for item in value]
        if not isinstance(value, dict):
            return value
        # These exact OTLP fields are counts, although their names match the
        # credential redactor. Never exempt text or nested values under them.
        if value.get("key") in _TOKEN_COUNTERS:
            wire = value.get("value")
            if isinstance(wire, dict) and len(wire) == 1:
                raw = next((wire[key] for key in ("intValue", "doubleValue", "stringValue") if key in wire), None)
                if isinstance(raw, str) and re.fullmatch(r"[0-9]{1,16}", raw):
                    raw = int(raw)
                if type(raw) in (int, float) and 0 <= raw <= 2**53 - 1 and raw == int(raw):
                    return {"key": value["key"], "value": {"intValue": str(int(raw))}}
        if "key" in value and "value" in value and sensitive(value["key"]):
            return {**value, "value": {"stringValue": _REDACTED}}
        return {
            key: clean_text(item)
            if key == "stringValue" and isinstance(item, str)
            else clean_wire(item)
            for key, item in value.items()
        }

    result = clean_wire(copy.deepcopy(payload))
    if signal == "logs":
        for resource, scope, item in records(signal, result):
            attrs = attributes(item.get("attributes"))
            event_name = str(
                attrs.get("event.name", "")
                or item.get("eventName", "")
                or item.get("body", {}).get("stringValue", "")
            )
            suffix = event_name.split(".")[-1]
            cursor_gate = {
                "cursor.conversation.user_message": ("prompt_text", capture_prompts),
                "cursor.conversation.assistant_message": ("response_text", capture_prompts),
            }.get(event_name)
            if event_name == "cursor.conversation.tool_io":
                direction = attrs.get("cursor.conversation.tool_io.direction")
                control = {"arguments": "tool_input", "result": "tool_output"}.get(
                    direction if isinstance(direction, str) else ""
                )
                cursor_gate = (control, capture_tool_details and control is not None)
            if cursor_gate is not None and (
                not cursor_gate[1] or capture is not None and not capture.get(cursor_gate[0])
            ):
                item["body"] = {"stringValue": _REDACTED}
                gaps.add("capture_disabled")
            permitted = capture_prompts
            if capture is not None:
                permitted = capture_prompts and bool(
                    capture.get(
                        "response_text"
                        if suffix == "assistant_response"
                        else "prompt_text"
                    )
                )
            if (
                suffix in _RAW_CONTENT
                or suffix in {"user_prompt", "assistant_response"}
                and not permitted
                or capture is not None
                and suffix in {"tool_result", "tool_output"}
                and not (capture_tool_details and capture.get("tool_output"))
                or capture is not None
                and suffix in {"tool_call", "tool_decision"}
                and not (capture_tool_details and capture.get("tool_input"))
            ):
                # Structured event metadata stays available without its contents.
                if item.get("body", {}).get("stringValue") != event_name or item.get(
                    "body", {}
                ).get("stringValue") not in {
                    "user_prompt",
                    "assistant_response",
                    "codex.user_prompt",
                    "claude_code.user_prompt",
                    "claude_code.assistant_response",
                }:
                    item["body"] = {"stringValue": _REDACTED}
                    gaps.add("capture_disabled")
    if capture is not None and gaps:
        marker = {
            "key": CAPTURE_GAPS_ATTRIBUTE,
            "value": {
                "arrayValue": {
                    "values": [{"stringValue": gap} for gap in sorted(gaps)]
                },
            },
        }
        for _, _, item in records(signal, result):
            targets = [item]
            if signal == "metrics":
                targets = [
                    point
                    for kind in (
                        "gauge",
                        "sum",
                        "histogram",
                        "exponentialHistogram",
                        "summary",
                    )
                    for point in item.get(kind, {}).get("dataPoints", [])
                ]
            for target in targets:
                target.setdefault("attributes", []).append(copy.deepcopy(marker))
    return result


def error_bytes(code: int, message: str, content_type: str) -> bytes:
    """Encode an OTLP failure using google.rpc.Status canonical status codes."""
    from google.rpc.status_pb2 import Status

    status = Status(code=code, message=message)
    if media_type(content_type) == "application/json":
        return json.dumps(
            {"code": code, "message": message}, separators=(",", ":")
        ).encode()
    return status.SerializeToString()


def _iso(unix_nano) -> str | None:
    """Render an OTLP unix-nanosecond timestamp as UTC ISO 8601 with microseconds."""
    try:
        number = int(unix_nano)
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    from datetime import datetime, timezone

    try:
        moment = datetime.fromtimestamp(number // 1_000_000_000, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return (
        moment.replace(microsecond=(number % 1_000_000_000) // 1000)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _any_value(value) -> object:
    """Unwrap one OTLP AnyValue, such as a log body, into plain JSON."""
    if not isinstance(value, dict):
        return value
    return attributes([{"key": "v", "value": value}]).get("v")


def flatten_records(signal: str, payload: dict) -> list[dict]:
    """One investigation row per log record, span, or metric data point.

    The rows are derived views over the canonical payload for reading in the
    console; they do not replace the stored export. Attribute values are
    unwrapped from OTLP wire form. Nothing here redacts: the sensor applied its
    content gates before the export left the device.
    """
    rows = []
    for resource, scope, item in records(signal, payload):
        resource_attributes = attributes(resource.get("attributes"))
        common = {
            "service": resource_attributes.get("service.name") or "(unknown)",
            "host": resource_attributes.get("host.name"),
            "scope": scope.get("name") or None,
        }
        if signal == "logs":
            attrs = attributes(item.get("attributes"))
            rows.append(
                {
                    **common,
                    "kind": "log",
                    "time": _iso(item.get("timeUnixNano")),
                    "observed_time": _iso(item.get("observedTimeUnixNano")),
                    "event_name": attrs.get("event.name")
                    or item.get("eventName")
                    or None,
                    "severity": item.get("severityText")
                    or (
                        str(item["severityNumber"])
                        if item.get("severityNumber") is not None
                        else None
                    ),
                    "body": _any_value(item.get("body")),
                    "trace_id": item.get("traceId") or None,
                    "span_id": item.get("spanId") or None,
                    "attributes": attrs,
                }
            )
        elif signal == "traces":
            start, end = item.get("startTimeUnixNano"), item.get("endTimeUnixNano")
            try:
                duration_ms = round((int(end) - int(start)) / 1_000_000, 3)
            except (TypeError, ValueError):
                duration_ms = None
            status = item.get("status") or {}
            rows.append(
                {
                    **common,
                    "kind": "span",
                    "time": _iso(start),
                    "end_time": _iso(end),
                    "duration_ms": duration_ms,
                    "name": item.get("name") or None,
                    "span_kind": item.get("kind"),
                    "trace_id": item.get("traceId") or None,
                    "span_id": item.get("spanId") or None,
                    "parent_span_id": item.get("parentSpanId") or None,
                    "status": status.get("code"),
                    "status_message": status.get("message") or None,
                    "event_count": len(item.get("events", []) or []),
                    "attributes": attributes(item.get("attributes")),
                }
            )
        else:
            for kind in (
                "gauge",
                "sum",
                "histogram",
                "exponentialHistogram",
                "summary",
            ):
                if kind not in item:
                    continue
                for point in item[kind].get("dataPoints", []) or []:
                    if kind in ("gauge", "sum"):
                        value = point.get("asInt", point.get("asDouble"))
                        try:
                            value = int(value) if "asInt" in point else value
                        except (TypeError, ValueError):
                            pass
                    else:
                        value = {
                            key: point.get(key)
                            for key in ("count", "sum", "min", "max")
                            if key in point
                        }
                    rows.append(
                        {
                            **common,
                            "kind": "metric",
                            "time": _iso(point.get("timeUnixNano")),
                            "start_time": _iso(point.get("startTimeUnixNano")),
                            "name": item.get("name") or None,
                            "unit": item.get("unit") or None,
                            "metric_type": kind,
                            "temporality": item[kind].get("aggregationTemporality"),
                            "monotonic": item[kind].get("isMonotonic"),
                            "value": value,
                            "attributes": attributes(point.get("attributes")),
                        }
                    )
    return rows
