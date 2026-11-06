"""Cumulative Antigravity CLI observations, separate from model requests."""

from datetime import datetime, timezone
from decimal import Decimal

from .agent_usage import number, text, token
from .telemetry import attributes, records


def observations(export):
    received = export["received_at"]
    if isinstance(received, str):
        received = datetime.fromisoformat(received.replace("Z", "+00:00"))
    for resource, _, item in records("logs", export["payload"]):
        if attributes(resource.get("attributes")).get("service.name") != "antigravity-cli":
            continue
        if item.get("eventName") != "antigravity.session_usage":
            continue
        attrs = attributes(item.get("attributes"))
        session = text(attrs, "session.id")
        if not session or len(session) > 256:
            continue
        try:
            stamp = int(item["timeUnixNano"])
            observed = datetime.fromtimestamp(stamp / 1e9, timezone.utc)
        except (KeyError, ValueError, TypeError, OverflowError, OSError):
            continue
        age = (received - observed).total_seconds()
        if stamp <= 0 or not -300 <= age <= 30 * 86400:
            continue
        incoming = token(attrs, "session.input_tokens")
        outgoing = token(attrs, "session.output_tokens")
        cost = number(attrs.get("session.estimated_cost_usd"))
        if cost is not None and cost > Decimal("1000000000"):
            cost = None
        if incoming is None and outgoing is None and cost is None:
            continue
        yield dict(session_id=session, observed_at=observed, observation_ns=stamp,
                   input_tokens=incoming, output_tokens=outgoing,
                   estimated_cost_usd=str(cost) if cost is not None else None)


def report(items):
    """No total: observations cover overlapping lifetimes, not a spend window."""
    return dict(source="antigravity_cli_statusline", cost_kind="list_price_estimate",
                coverage="Latest observed conversation totals; includes earlier activity and subagent cost. Not a daily spend report or invoice.",
                items=items)
