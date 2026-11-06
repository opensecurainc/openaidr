"""Shared redacted evidence projection, independent of execution protocols."""

import json

from openaidr.core.redact import redact_value

MAX_EVENT_BYTES = 8_000
MAX_STATE_BYTES = 24_000


def event_evidence(row):
    """Send only relevant evidence, redacted before truncation, never raw exports."""
    body = row.get("body") or {}
    evidence = {"kind": row["kind"]}
    for key in ("text", "command", "file", "network", "tool", "hook", "truncated", "redacted"):
        if key in body:
            evidence[key] = body[key]
    session = body.get("session") or {}
    if session.get("cwd"):
        evidence["cwd"] = session["cwd"]
    # Redact nested values as text too. Keep a valid outer state even when a
    # very large command or tool payload must be cut down.
    text = json.dumps(redact_value(evidence), ensure_ascii=False, default=str)
    encoded = text.encode()
    if len(encoded) > MAX_EVENT_BYTES:
        return {
            "kind": row["kind"],
            "truncated": True,
            # The prefix is itself JSON text, so wrapping it can double escaping.
            "content": encoded[: MAX_EVENT_BYTES // 2].decode("utf-8", errors="ignore"),
        }
    return json.loads(text)


def assessment_state(row, context, prompt):
    state = {
        "target_event": event_evidence(row),
        "latest_prompt": event_evidence(prompt) if prompt else None,
        "prior_events": [],
        "context_limited": True,
    }
    for item in reversed(context):
        if prompt and prompt.get("id") and item.get("id") == prompt["id"]:
            continue
        state["prior_events"].insert(0, event_evidence(item))
        if len(json.dumps(state, ensure_ascii=False).encode()) > MAX_STATE_BYTES:
            state["prior_events"].pop(0)
            break
    return state
