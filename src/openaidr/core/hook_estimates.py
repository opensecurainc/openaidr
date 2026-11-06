"""Value observed hook text at list price, separate from measured model usage."""

from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal
import json
import re

from .agent_usage import OPENAI_RATES, token
from .telemetry import attributes, records

METHOD = "utf8_bytes_div4_v1"
EVENT = "openaidr.hook_usage_estimate"
PRODUCTS = {"github-copilot", "cursor"}
PRICE_DATE = "2026-11-02"
# Standard input/output USD per million, without caching or service modifiers.
# https://platform.claude.com/docs/en/about-claude/pricing
RATES = {
    **{name: (rates[0], rates[3]) for name, rates in OPENAI_RATES.items()},
    **{f"claude-opus-{version}": ("5", "25") for version in ("4-5", "4-6", "4-7", "4-8", "5")},
    **{f"claude-sonnet-{version}": ("3", "15") for version in ("4", "4-5", "4-6")},
    "claude-opus-5-5": ("4", "20"),
    "claude-sonnet-5": ("2", "10"),
    "claude-sonnet-5-5": ("2", "10"),
    "claude-haiku-4-5": ("1", "5"),
    "claude-fable-5-1": ("10", "50"),
}
COVERAGE = (
    "Partial estimate of captured hook text, using one token per four UTF-8 bytes. "
    "Includes submitted prompts, tool arguments/results and available responses, each once. "
    "Hidden or repeated context, reasoning, cache use, images and uncaptured text are unknown. "
    "Text can be blocked or unused. This is neither cumulative model usage nor billed spend. "
    "Keep separate from native OTel totals."
)


def model_name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9 ._:/-]{1,128}", value):
        return "unknown"
    return value.strip() or "unknown"


def price(model, incoming, outgoing):
    name = model.lower().replace(" ", "-")
    if name.startswith("claude-"):
        name = re.sub(r"-\d{8}$", "", name.replace(".", "-"))
    rates = RATES.get(name)
    if rates is None:
        return None
    return (Decimal(str(rates[0])) * incoming + Decimal(str(rates[1])) * outgoing) / 1_000_000


def estimate(event, assumed_models=None):
    """Accept only already captured/redacted events. Never read transcripts."""
    product = event.get("agent", {}).get("product")
    source = event.get("source", {})
    if product not in PRODUCTS or source.get("collector") != "hook":
        return None
    kind, tool = event.get("kind"), event.get("tool", {})
    direction = "input"
    if kind in ("prompt", "response"):
        value = event.get("text")
        direction = "output" if kind == "response" else "input"
    elif kind == "tool.result":
        value = tool.get("output")
    elif "input" in tool:
        value = tool["input"]
        direction = "output"
        if value is not None and not isinstance(value, str):
            value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    else:
        return None
    if not isinstance(value, str) or not value:
        return None
    # Redaction already bounds normal hook text; also cap structured tool data.
    raw = value.encode("utf-8", errors="replace")
    size = min(len(raw), 65536)
    count = (size + 3) // 4
    model = model_name(event.get("agent", {}).get("model"))
    model_source = "hook" if model != "unknown" else "unknown"
    if model_source == "unknown":
        model = model_name((assumed_models or {}).get(product))
        model_source = "configured" if model != "unknown" else "unknown"
    # One native tool call can emit several mapped actions with the same input.
    ident = source.get("hook_request_id") or event.get("id")
    if not isinstance(ident, str) or not ident or len(ident) > 128:
        return None
    try:
        observed = datetime.fromisoformat(event["time"].replace("Z", "+00:00"))
        if observed.tzinfo is None:
            return None
    except (KeyError, ValueError, TypeError, AttributeError):
        return None
    return dict(observation_id=ident, application=product, observed_at=observed,
                model=model, model_source=model_source,
                estimated_input_tokens=count if direction == "input" else 0,
                estimated_output_tokens=count if direction == "output" else 0,
                modified=bool(event.get("redacted") or event.get("truncated") or len(raw) > size))


def payload(items):
    return {"resourceLogs": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": item["application"]}}]},
        "scopeLogs": [{"scope": {"name": "openaidr.hook_estimates"}, "logRecords": [{
            "eventName": EVENT, "timeUnixNano": str(int(item["observed_at"].timestamp() * 1e9)),
            "attributes": [{"key": key, "value": {"stringValue": str(value)}} for key, value in {
                "estimate.method": METHOD, "estimate.id": item["observation_id"],
                "estimate.model": item["model"], "estimate.model_source": item["model_source"],
                "estimate.input_tokens": item["estimated_input_tokens"],
                "estimate.output_tokens": item["estimated_output_tokens"],
                "estimate.modified": int(item["modified"]),
            }.items()],
        }]}],
    } for item in items]}


def observations(export):
    received = export["received_at"]
    if isinstance(received, str):
        received = datetime.fromisoformat(received.replace("Z", "+00:00"))
    for resource, _, item in records("logs", export["payload"]):
        app = attributes(resource.get("attributes")).get("service.name")
        if app not in PRODUCTS or item.get("eventName") != EVENT:
            continue
        attrs = attributes(item.get("attributes"))
        ident, source = attrs.get("estimate.id"), attrs.get("estimate.model_source")
        if (attrs.get("estimate.method") != METHOD or source not in ("hook", "configured", "unknown")
                or not isinstance(ident, str) or not ident or len(ident) > 128):
            continue
        incoming, outgoing = token(attrs, "estimate.input_tokens"), token(attrs, "estimate.output_tokens")
        if incoming is None or outgoing is None or not 0 < incoming + outgoing <= 16384:
            continue
        try:
            observed = datetime.fromtimestamp(int(item["timeUnixNano"]) / 1e9, timezone.utc)
        except (KeyError, ValueError, TypeError, OverflowError, OSError):
            continue
        if not -300 <= (received - observed).total_seconds() <= 30 * 86400:
            continue
        model = model_name(attrs.get("estimate.model")) if source != "unknown" else "unknown"
        yield dict(application=app, observation_id=ident, observed_at=observed,
                   model=model, model_source=source, estimated_input_tokens=incoming,
                   estimated_output_tokens=outgoing, modified=attrs.get("estimate.modified") == "1",
                   estimated_cost_usd=price(model, incoming, outgoing))


def report(rows):
    def empty():
        return dict(observations=0, priced_observations=0, assumed_model_observations=0,
                    modified_observations=0, estimated_input_tokens=0, estimated_output_tokens=0,
                    estimated_cost_usd=None)

    groups, summary = defaultdict(empty), empty()
    for row in rows:
        for target in (summary, groups[(row["application"], row["model"], row["model_source"])]):
            for field in target:
                if field == "estimated_cost_usd":
                    if row[field] is not None:
                        target[field] = (target[field] or Decimal(0)) + Decimal(str(row[field]))
                else:
                    target[field] += row[field]

    def serial(values):
        return dict(values, estimated_tokens=values["estimated_input_tokens"] + values["estimated_output_tokens"],
                    estimated_cost_usd=str(values["estimated_cost_usd"]) if values["estimated_cost_usd"] is not None else None)

    return dict(source="hook_estimate", method=METHOD, price_date=PRICE_DATE,
                cost_kind="observed_text_list_price_estimate", coverage=COVERAGE,
                summary=serial(summary), items=[dict(application=app, model=model, model_source=source, **serial(values))
                    for (app, model, source), values in sorted(groups.items())])
