"""Dormant generation wire adapters. Current routes do not import this module."""

import asyncio
import json
import time

import anyio
from openaidr_api_client.client import IntelligenceClient, SyncIntelligenceClient, Unavailable
from openaidr_api_client.contracts.errors import APIError
from openaidr_api_client.validation import page_chat, overview_summary, rule_authoring, session_activity_summaries

from .service_operations import contracts


SERVICES = {
    "assistant": ("assistant/respond", "assistant.1", "ServiceAssistantRequest", "ServiceAssistantResponse"),
    "overview_summaries": ("summaries/generate", "overview-summaries.1", "ServiceOverviewRequest", "ServiceSummaryResponse"),
    "session_summaries": ("summaries/generate", "session-summaries.1", "ServiceSessionSummaryRequest", "ServiceSummaryResponse"),
    "rule_generation": ("rules/draft", "rule-generation.1", "ServiceRuleRequest", "ServiceRuleResponse"),
}


class GenerationFailed(APIError):
    """A validated service error, distinct from an unusable or missing reply."""


def prepare(operation, data, *, streaming=False):
    models = contracts()
    path, profile, request_name, response_name = SERVICES[operation.service]
    request_model, response_model = getattr(models, request_name), getattr(models, response_name)
    if streaming and operation.service != "assistant":
        raise ValueError("Only assistant responses support streaming")
    if operation.service == "assistant":
        page_chat.validate_input(data)
    payload = {**data, "timeout_ms": 45000}
    if operation.service == "assistant":
        payload["stream"] = streaming
    payload = request_model.model_validate(payload).model_dump()
    return "/v1/services/" + path, profile, response_model, payload


def result(operation, value, profile, schema, data):
    if not isinstance(value, dict):
        raise ValueError("Invalid generation response")
    # Preserve known accounting even when the task result cannot be used.
    operation.capture(value.get("billing"))
    parsed = schema.model_validate(value).root
    if parsed.profile != profile:
        raise ValueError("Generation profile mismatch")
    if parsed.status == "error":
        status = {"timeout": 504, "provider_unavailable": 503, "invalid_response": 502}[parsed.code]
        message = "OpenAIDR Assistant took too long. Please try again." if status == 504 else "OpenAIDR Assistant is unavailable. Please try again."
        raise GenerationFailed(status, message)
    answer = parsed.result.model_dump()
    if operation.service == "assistant":
        if not answer["answer"].strip():
            raise ValueError("Invalid assistant answer")
        return answer
    if operation.service == "overview_summaries":
        return overview_summary.validate_answer(json.dumps(answer), data["sources"])
    if operation.service == "session_summaries":
        return session_activity_summaries.validate_answer(json.dumps(answer))
    return rule_authoring.validate_result(data["intent"], answer)


def request(operation, data, *, transport=None, record_receipt=True):
    path, profile, schema, payload = prepare(operation, data)
    deadline = time.monotonic() + 45
    try:
        with page_chat.provider_errors():
            client = SyncIntelligenceClient.from_connection(operation.connection, transport=transport)
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                payload["timeout_ms"] = max(1, int(remaining * 1000))
                value = client.request(path, payload, 256 << 10, remaining, request_id=operation.id)
                return result(operation, value, profile, schema, payload)
            finally:
                client.close()
    finally:
        if record_receipt:
            operation.finish()


async def stream(operation, data, *, run_sync, transport=None):
    path, profile, schema, payload = prepare(operation, data, streaming=True)
    deadline = time.monotonic() + 45
    client = IntelligenceClient.from_connection(operation.connection, transport=transport)
    try:
        with page_chat.provider_errors():
            async with asyncio.timeout_at(deadline):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                payload["timeout_ms"] = max(1, int(remaining * 1000))
                async with client.client.stream("POST", path, timeout=remaining, json=payload,
                                                headers={"Idempotency-Key": operation.id}) as response:
                    if (response.status_code != 200 or response.headers.get("content-encoding", "identity") != "identity"
                            or response.headers.get("content-type", "").split(";", 1)[0] != "text/event-stream"):
                        raise Unavailable("Intelligence service unavailable")
                    size = 0
                    async for value in page_chat.sse_events(response):
                        if isinstance(value, dict) and value.get("type") == "delta":
                            if set(value) != {"type", "text"} or not isinstance(value["text"], str):
                                raise ValueError("Invalid text delta")
                            size += len(value["text"])
                            if size > 8000:
                                raise ValueError("Answer too long")
                            yield value
                        else:
                            answer = result(operation, value, profile, schema, payload)
                            yield {"type": "done", **answer}
                            return
                    raise ValueError("Stream ended before completion")
    finally:
        with anyio.CancelScope(shield=True):
            try:
                await client.aclose()
            finally:
                await run_sync(operation.finish)
