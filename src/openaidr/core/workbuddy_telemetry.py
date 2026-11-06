"""Keep only native WorkBuddy per-request accounting from OTLP traces."""

from .telemetry import attributes, records
from .agent_usage import token


USAGE_EVENT = "codebuddy_code.cli.model_request.usage"
FIELDS = {
    "request_id": ("codebuddy.stage.modelRequestId",),
    "model": ("codebuddy.stage.model", "codebuddy.stage.responseModel", "codebuddy.stage.requestedModel"),
    "input_token_count": ("codebuddy.stage.inputTokens",),
    "output_token_count": ("codebuddy.stage.outputTokens",),
    "cached_token_count": ("codebuddy.stage.cacheReadTokens",),
    "cache_write_token_count": ("codebuddy.stage.cacheWriteTokens",),
    "duration_ms": ("codebuddy.stage.elapsedMs",),
    "session.id": ("workbuddy.session.id", "conversation.id"),
    "workbuddy.project.id": ("workbuddy.project.id",),
    "gen_ai.request.reasoning_effort": ("workbuddy.reasoning_effort",),
}


def request_logs(payload):
    """Normalize usage events and their deferred standalone-span representation.

    WorkBuddy shares its CLI emitter with CodeBuddy. Require an explicit
    service name so CodeBuddy exports cannot become WorkBuddy usage.
    Never retain raw spans, content aliases, credits, or request/stream totals.
    """
    output = {"resourceLogs": []}
    for resource, _, span in records("traces", payload):
        if attributes(resource.get("attributes")).get("service.name") != "workbuddy":
            continue
        inherited = [entry for entry in span.get("attributes", []) if entry.get("key") in
                     {"workbuddy.session.id", "conversation.id", "workbuddy.project.id", "workbuddy.reasoning_effort"}]
        observations = list(span.get("events", []))
        if span.get("name") == USAGE_EVENT:
            observations.append({**span, "timeUnixNano": span.get("endTimeUnixNano")})
        for item in observations:
            if item.get("name") != USAGE_EVENT:
                continue
            native = {entry["key"]: entry.get("value", {}) for entry in [*inherited, *item.get("attributes", [])]}
            request_id = native.get("codebuddy.stage.modelRequestId", {}).get("stringValue")
            if not isinstance(request_id, str) or not request_id.strip():
                continue
            try:
                timestamp = int(item.get("timeUnixNano", 0))
            except (ValueError, TypeError):
                continue
            if not 0 < timestamp <= 2**64 - 1:
                continue
            values = attributes(item.get("attributes"))
            ambiguous_cache = any(token(values, key) != 0 for key in
                                  ("codebuddy.stage.cacheReadTokens", "codebuddy.stage.cacheWriteTokens"))
            retained = []
            for key, aliases in FIELDS.items():
                # Native events erase whether input came from prompt_tokens
                # (inclusive) or input_tokens (potentially exclusive). Keep the
                # request but leave missing or ambiguous counts unavailable.
                if ambiguous_cache and key in {"input_token_count", "output_token_count", "cached_token_count", "cache_write_token_count"}:
                    continue
                value = next((native[name] for name in aliases if name in native), {})
                if len(value) == 1 and next(iter(value)) in {"stringValue", "intValue", "doubleValue", "boolValue"}:
                    retained.append({"key": key, "value": dict(value)})
            if ambiguous_cache:
                retained.append({"key": "workbuddy.usage.unavailable", "value": {"stringValue": "cache_breakdown"}})
            output["resourceLogs"].append({
                "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "workbuddy"}}]},
                "scopeLogs": [{
                    "scope": {"name": "openaidr.workbuddy"},
                    "logRecords": [{"timeUnixNano": str(timestamp), "eventName": "workbuddy.api_request",
                                    "body": {"stringValue": "workbuddy.api_request"}, "attributes": retained}],
                }],
            })
    return output
