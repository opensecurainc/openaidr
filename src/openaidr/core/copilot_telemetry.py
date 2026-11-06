"""Retain Copilot request accounting without retaining its trace payloads."""

import re

from .telemetry import attributes, records


RESOURCE_FIELDS = {
    "service.name", "service.version", "host.name", "os.user", "process.user.name",
    "user.name", "enduser.pseudo.id", "project.name", "process.cwd",
}
REQUEST_FIELDS = {
    "gen_ai.provider.name", "gen_ai.request.model", "gen_ai.response.model",
    "gen_ai.response.id", "gen_ai.response.time_to_first_chunk", "error.type",
    "github.copilot.cost", "github.copilot.nano_aiu", "github.copilot.server_duration",
    "github.copilot.initiator", "enduser.pseudo.id",
}
FIELDS = {
    "gen_ai.conversation.id": "session.id",
    "github.copilot.turn_id": "turn.id",
    "gen_ai.usage.input_tokens": "input_token_count",
    "gen_ai.usage.output_tokens": "output_token_count",
    "gen_ai.usage.cache_read.input_tokens": "cached_token_count",
    "gen_ai.usage.cache_creation.input_tokens": "cache_write_token_count",
}


def _metadata(values, permitted, aliases=None):
    result = []
    for attribute in values:
        key, value = attribute.get("key"), attribute.get("value", {})
        if key in permitted and len(value) == 1 and next(iter(value)) in {
            "stringValue", "intValue", "doubleValue", "boolValue",
        }:
            result.append({"key": (aliases or {}).get(key, key), "value": dict(value)})
    return result


def request_logs(payload):
    """Convert completed chat spans only; parent totals would double count usage.

    Use a metadata allowlist even when upstream content capture is enabled.
    Normal sensor filtering and redaction still apply to the resulting logs.
    """
    output = {"resourceLogs": []}
    for resource, scope, span in records("traces", payload):
        resource_attrs = attributes(resource.get("attributes"))
        if (resource_attrs.get("service.name") != "github-copilot"
                and scope.get("name") != "github.copilot"):
            continue
        attrs = attributes(span.get("attributes"))
        if attrs.get("gen_ai.operation.name") != "chat":
            continue
        trace, ident = span.get("traceId", ""), span.get("spanId", "")
        if not (re.fullmatch(r"[0-9a-fA-F]{32}", trace) and int(trace, 16)
                and re.fullmatch(r"[0-9a-fA-F]{16}", ident) and int(ident, 16)):
            continue
        try:
            start, end = int(span.get("startTimeUnixNano", 0)), int(span.get("endTimeUnixNano", 0))
        except (TypeError, ValueError):
            continue
        if not 0 < start <= end <= 2**64 - 1:
            continue
        retained = _metadata(span.get("attributes", []), REQUEST_FIELDS | FIELDS.keys(), FIELDS)
        retained.extend([
            {"key": "request_id", "value": {"stringValue": trace.lower() + ":" + ident.lower()}},
            {"key": "duration_ms", "value": {"doubleValue": (end - start) / 1_000_000}},
        ])
        output["resourceLogs"].append({
            "resource": {"attributes": _metadata(resource.get("attributes", []), RESOURCE_FIELDS)},
            "scopeLogs": [{
                "scope": {"name": "openaidr.copilot"},
                "logRecords": [{
                    "timeUnixNano": str(end),
                    "eventName": "copilot.api_request",
                    "body": {"stringValue": "copilot.api_request"},
                    "attributes": retained,
                }],
            }],
        })
    return output
