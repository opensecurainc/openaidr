"""Shared accounting rules for native per-request usage logs."""

from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json

from .telemetry import attributes, records
from .reasoning import reasoning_effort


UNKNOWN = "Unattributed"
PRICE_DATE = "2026-10-23"
# Free for ChatGPT sign-ins from the announcement; not an API token rate.
# https://x.com/thsottiaux/status/2107368734981517634
AUTO_REVIEW_FREE_SINCE = datetime(2026, 10, 6, 7, 13, 54, tzinfo=timezone.utc)
# USD per million tokens: input, cache read, cache write, output. Snapshot of
# https://developers.openai.com/api/docs/pricing and linked model pages, 2026-10-23.
# Match exact models only. Unknown models or unsupported tiers stay unpriced.
OPENAI_RATES = {
    "gpt-6-astra": ("10", "1", "12.5", "50"),
    "gpt-6.1-sol": ("2", "0.1", "2.5", "10"),
    "gpt-6-sol": ("2", "0.2", "2.5", "10"),
    "gpt-6-luna": ("0.1", "0.01", "0.125", "0.5"),
    "gpt-5.6-sol": ("4", "0.4", "5", "20"),
    "gpt-5.6-luna": ("0.2", "0.02", "0.25", "1.2"),
}


def text(attrs, *keys):
    return next(
        (
            attrs[k].strip()[:1024]
            for k in keys
            if isinstance(attrs.get(k), str) and attrs[k].strip()
        ),
        "",
    )


def number(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        result = Decimal(str(value))
        return result if result.is_finite() and 0 <= result <= 2**53 - 1 else None
    except (InvalidOperation, ValueError):
        return None


def token(attrs, *keys, optional=False):
    value = next((attrs[k] for k in keys if k in attrs), 0 if optional else None)
    parsed = number(value)
    return int(parsed) if parsed is not None and parsed == int(parsed) else None


def event_time(item, attrs, received):
    raw = item.get("timeUnixNano")
    if raw:
        # OTLP timestamps exceed the safe integer range used for usage counters.
        try:
            nano = int(raw)
            if 0 < nano <= 18446744073709551615:
                return datetime.fromtimestamp(nano / 1e9, timezone.utc), str(nano)
        except (TypeError, ValueError, OverflowError, OSError):
            pass
    raw = attrs.get("event.timestamp")
    if isinstance(raw, str):
        try:
            value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if value.tzinfo:
                return value.astimezone(timezone.utc), raw
        except (ValueError, OverflowError, OSError):
            pass
    raw = item.get("observedTimeUnixNano")
    if raw:
        try:
            nano = int(raw)
            if 0 < nano <= 18446744073709551615:
                return datetime.fromtimestamp(nano / 1e9, timezone.utc), str(nano)
        except (TypeError, ValueError, OverflowError, OSError):
            pass
    return received, ""


def usage(attrs, kind, *, when=None):
    codex = kind.startswith("codex.")
    cursor = kind == "cursor.api_request"
    if cursor:
        attrs = {**attrs, **{
            target: attrs.get("cursor.api.request." + source)
            for source, target in (
                ("input_tokens", "input_token_count"), ("output_tokens", "output_token_count"),
                ("cache_read_tokens", "cached_token_count"), ("cache_creation_tokens", "cache_write_token_count"),
            )
        }}
    inclusive_input = codex or kind in ("copilot.api_request", "hermes.api_request", "workbuddy.api_request")
    input_count = token(attrs, "input_token_count", "input_tokens")
    output = token(attrs, "output_token_count", "output_tokens")
    optional_cache = not cursor and kind != "workbuddy.api_request"
    cached = token(attrs, "cached_token_count", "cache_read_tokens", optional=optional_cache)
    written = token(
        attrs, "cache_write_token_count", "cache_creation_tokens", optional=optional_cache
    )
    valid = all(v is not None for v in (input_count, output, cached, written))
    if valid and inclusive_input and cached + written > input_count:
        valid = False
    if kind == "workbuddy.api_request" and (cached != 0 or written != 0):
        valid = False  # Native events do not identify cache inclusivity.
    # Copilot reports a multiplier; Cursor reports USD only as aggregate
    # metrics. Hermes plugin costs are estimates; WorkBuddy credits are not USD.
    native_unpriced = cursor or kind in ("copilot.api_request", "hermes.api_request", "workbuddy.api_request")
    cost = None if native_unpriced else number(attrs.get("cost_usd_micros"))
    if not native_unpriced:
        cost = cost / 1_000_000 if cost is not None else number(attrs.get("cost_usd"))
    if kind == "opencode.api_request" and cost == 0:
        cost = None  # OpenCode also returns zero when its model prices are missing.
    source = "reported" if cost is not None else "unpriced"
    model = text(attrs, "model", "gen_ai.response.model", "gen_ai.request.model")
    if (
        cost is None and valid and codex and model == "codex-auto-review"
        and text(attrs, "auth_mode").lower() == "chatgpt"
        and when is not None and when >= AUTO_REVIEW_FREE_SINCE
    ):
        cost = Decimal(0)
        source = "calculated"
    if cost is None and valid and codex and model in OPENAI_RATES:
        tier = text(attrs, "service_tier")
        multiplier = {
            "": 1,
            "default": 1,
            "auto": 1,
            "standard": 1,
            "priority": 2,
            "fast": 2,
            "ultrafast": 6 if model in {"gpt-6-astra", "gpt-6.1-sol"} else None,
            "flex": Decimal("0.5"),
            "batch": Decimal("0.5"),
        }.get(tier)
        if multiplier is not None:
            rates = [Decimal(rate) for rate in OPENAI_RATES[model]]
            if input_count > 272_000:
                rates = [
                    r * (Decimal("1.5") if i == 3 else 2) for i, r in enumerate(rates)
                ]
            cost = (
                sum(
                    n * r
                    for n, r in zip(
                        (input_count - cached - written, cached, written, output), rates
                    )
                )
                * multiplier
                / 1_000_000
            )
            source = "calculated"
    if not valid and cost is None:
        return None
    return {
        "cost": cost,
        "source": source,
        "tokens": (input_count + output + (0 if inclusive_input else cached + written))
        if valid
        else 0,
        "input_tokens": (input_count - (cached + written if inclusive_input else 0))
        if valid
        else 0,
        "output_tokens": output if valid else 0,
        "cache_read_tokens": cached if valid else 0,
        "cache_write_tokens": written if valid else 0,
    }


def extract(export):
    """Parse an export once into cost and correlation metadata."""
    occurrences = defaultdict(int)
    received = export["received_at"]
    if isinstance(received, str):
        received = datetime.fromisoformat(received.replace("Z", "+00:00"))
    for index, (resource, _, item) in enumerate(records("logs", export["payload"])):
        attrs = {
            **attributes(resource.get("attributes")),
            **attributes(item.get("attributes")),
        }
        service = text(attrs, "service.name")
        # Codex's eventName can be a tracing source location. Its event.name
        # attribute carries the semantic name, as in the telemetry record view.
        name = (
            text(attrs, "event.name")
            or item.get("eventName")
            or text(item.get("body") or {}, "stringValue")
        )
        if service == "cursor" and name == "cursor.api.request":
            name = "cursor.api_request"
        if name in {"api_request", "tool_result", "user_prompt"}:
            if service in {"claude-code", "claude-code-desktop", "claude_code"}:
                name = "claude_code." + name
            elif service == "cowork":
                name = "cowork." + name
            elif service == "cursor" and name == "api_request":
                name = "cursor.api_request"
        cursor = name == "cursor.api_request"
        if name == "opencode.api_request" and (service != "opencode" or not text(attrs, "request_id")):
            continue
        if cursor:
            team = token(attrs, "cursor.team.id")
            event_id = attrs.get("cursor.event.id")
            if service != "cursor" or team is None or not isinstance(event_id, str) or not event_id.strip():
                continue
        if name == "hermes.api_request" and service != "hermes-agent":
            continue
        if name == "workbuddy.api_request" and (service != "workbuddy" or not text(attrs, "request_id")):
            continue
        is_usage = name in {"claude_code.api_request", "cowork.api_request", "codex.api_request", "copilot.api_request", "cursor.api_request", "hermes.api_request", "opencode.api_request", "workbuddy.api_request"} or (
            name == "codex.sse_event"
            and attrs.get("event.kind") == "response.completed"
        )
        if not is_usage and name not in {
            "claude_code.tool_result",
            "cowork.tool_result",
            "codex.tool_result",
            "claude_code.user_prompt",
            "cowork.user_prompt",
            "codex.user_prompt",
        }:
            continue
        when, stamp = event_time(item, attrs, received)
        scope = (
            str(export["sensor_id"]),
            service,
            text(attrs, "cursor.conversation.id") if cursor else text(attrs, "session.id", "conversation.id", "thread.id"),
        )
        request_id = (
            text(attrs, "request_id", "response_id", "gen_ai.response.id")
            if is_usage
            else ""
        )
        if cursor:
            # Cursor event IDs survive retries and rebatching. Include its
            # team ID, and let the tenant ledger deduplicate collector rotation.
            identity = ("cursor", team, event_id)
        elif name == "workbuddy.api_request":
            # Deferred native events may lack session metadata. The model
            # request ID survives that change, batching, and delivery retries.
            identity = (str(export["sensor_id"]), service, request_id)
        elif request_id:
            identity = (*scope, name, request_id) if name in ("copilot.api_request", "hermes.api_request", "opencode.api_request") else (name.split(".")[0], request_id)
            if service == "cowork" and text(attrs, "openaidr.cowork.account"):
                identity = (*identity, text(attrs, "openaidr.cowork.account"))
        elif stamp:
            fingerprint = hashlib.sha256(
                json.dumps(attrs, sort_keys=True).encode()
            ).hexdigest()
            identity = (*scope, name, stamp, fingerprint)
            occurrences[identity] += 1
            identity = (*identity, occurrences[identity])
        else:
            identity = (str(export["id"]), index)
        measured = usage(attrs, name, when=when if stamp else None) if is_usage else None
        if is_usage and measured is None:
            continue
        yield {
            "key": hashlib.sha256(json.dumps(identity).encode()).hexdigest(),
            "export_record": index,
            "time": when,
            "name": name,
            "scope": scope,
            "turn": text(attrs, "cursor.request.id") if cursor else text(attrs, "prompt.id", "turn.id", "turn_id"),
            "model": (text(attrs, "cursor.model.name") if cursor else text(
                attrs, "model", "gen_ai.response.model", "gen_ai.request.model"
            ))
            or UNKNOWN,
            "reasoning_effort": reasoning_effort(attrs) or "unknown",
            "attributes": attrs,
            "usage": measured,
            "demo": attrs.get("openaidr.demo") in (True, "true"),
        }
