"""Convert hermes_otel API spans to content-free request accounting logs."""

import re

from .telemetry import attributes, records


FIELDS = {
    "session.id": ("session.id", "gen_ai.conversation.id", "session_id"),
    "gen_ai.request.model": ("gen_ai.request.model", "llm.model_name"),
    "gen_ai.response.model": ("gen_ai.response.model",),
    "gen_ai.provider.name": ("gen_ai.provider.name", "llm.provider"),
    "gen_ai.response.id": ("gen_ai.response.id",),
    "input_token_count": ("gen_ai.usage.input_tokens", "llm.token_count.prompt"),
    "output_token_count": ("gen_ai.usage.output_tokens", "llm.token_count.completion"),
    "cached_token_count": ("gen_ai.usage.cache_read.input_tokens", "gen_ai.usage.cache_read_input_tokens",
                           "llm.token_count.prompt_details.cache_read"),
    "cache_write_token_count": ("gen_ai.usage.cache_creation.input_tokens", "gen_ai.usage.cache_creation_input_tokens",
                                "llm.token_count.prompt_details.cache_write"),
    "gen_ai.usage.reasoning.output_tokens": ("gen_ai.usage.reasoning.output_tokens",
                                            "llm.token_count.completion_details.reasoning"),
    "gen_ai.request.reasoning_effort": ("gen_ai.request.reasoning_effort",),
    "error.type": ("error.type",),
}


def request_logs(payload):
    """Keep one API attempt, never its parent totals, content, or span events.

    Instrumentation scope identifies the plugin even when users customize its
    service name for a profile. Normalize that service for stable attribution.
    Costs are left unpriced: the plugin's cost attributes are estimates.
    """
    output = {"resourceLogs": []}
    for resource, scope, span in records("traces", payload):
        if scope.get("name") != "hermes-otel-plugin" or not str(span.get("name", "")).startswith("api."):
            continue
        attrs = attributes(span.get("attributes"))
        if attrs.get("gen_ai.operation.name") not in (None, "chat"):
            continue
        trace, ident = span.get("traceId", ""), span.get("spanId", "")
        if not (isinstance(trace, str) and re.fullmatch(r"[0-9a-fA-F]{32}", trace) and int(trace, 16)
                and isinstance(ident, str) and re.fullmatch(r"[0-9a-fA-F]{16}", ident) and int(ident, 16)):
            continue
        try:
            start, end = int(span.get("startTimeUnixNano", 0)), int(span.get("endTimeUnixNano", 0))
        except (TypeError, ValueError):
            continue
        if not 0 < start <= end <= 2**64 - 1:
            continue
        native = {item["key"]: item.get("value", {}) for item in span.get("attributes", [])}
        retained = []
        for key, aliases in FIELDS.items():
            value = next((native[name] for name in aliases if name in native), {})
            if len(value) == 1 and next(iter(value)) in {"stringValue", "intValue", "doubleValue", "boolValue"}:
                retained.append({"key": key, "value": dict(value)})
        retained.extend([
            {"key": "request_id", "value": {"stringValue": trace.lower() + ":" + ident.lower()}},
            {"key": "duration_ms", "value": {"doubleValue": (end - start) / 1_000_000}},
        ])
        output["resourceLogs"].append({
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "hermes-agent"}}]},
            "scopeLogs": [{
                "scope": {"name": "openaidr.hermes"},
                "logRecords": [{"timeUnixNano": str(end), "eventName": "hermes.api_request",
                                "body": {"stringValue": "hermes.api_request"}, "attributes": retained}],
            }],
        })
    return output
