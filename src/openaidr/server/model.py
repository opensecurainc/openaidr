"""JSON domain helpers; database results remain ordinary dictionaries."""

from openaidr_api_client.contracts.detection import (
    DETECTION_CATEGORIES as DETECTION_CATEGORIES,
    SEVERITIES as SEVERITIES,
)

try:
    from openaidr_api_client.contracts.service_guardrail import CATEGORIES as CATEGORIES
except ModuleNotFoundError as error:
    if error.name != "openaidr_api_client.contracts.service_guardrail":
        raise
    from openaidr_api_client.contracts.guardrail import CATEGORIES as CATEGORIES

from datetime import datetime, timezone, timedelta
from uuid import UUID

ROLES = ("viewer", "analyst", "admin", "owner")
STATUSES = ("open", "triaged", "resolved", "false_positive")
ONLINE_WINDOW = timedelta(seconds=90)


def role_rank(role):
    return ROLES.index(role) if role in ROLES else -1


def sensor_status(row, now=None):
    now = now or datetime.now(timezone.utc)
    return (
        "disabled"
        if row["disabled"]
        else "online"
        if row.get("last_heartbeat_at") and now - row["last_heartbeat_at"] <= ONLINE_WINDOW
        else "offline"
    )


def finish(row, kind):
    now = datetime.now(timezone.utc)
    if kind == "sensor":
        from .device_identity import presentation

        presentation(row)
        row["user"] = row.get("username", "")
        row["collectors"] = row.get("collectors") or []
        row["status"] = sensor_status(row, now)
        from .sensor_health import assess

        row["health"] = assess(row)
    if kind in ("agent", "finding"):
        row["host"] = {
            key: row.get("username" if key == "user" else key, "")
            for key in ("hostname", "os", "arch", "user")
        }
    if kind == "agent":
        row["models"] = row.get("models") or []
        row["status"] = (
            "active" if now - row["last_seen"] <= timedelta(days=1) else "idle"
        )
    if kind == "finding":
        row["assignee"] = (
            {"id": row["assignee_id"], "name": row.get("assignee_name") or ""}
            if row.get("assignee_id")
            else None
        )
        row.setdefault("rule_name", "")
    if kind == "note":
        row["author"] = {"id": row["author_id"], "name": row.get("author_name", "")}
    if kind == "action":
        row["created_by"] = {
            "id": row["created_by"],
            "name": row.get("created_by_name", ""),
        }
    if kind == "audit":
        row["actor"] = {"id": row["actor_id"], "name": row.get("actor_name", "")}
    return row


def public(value):
    """Encode JSON values without interpreting captured keys as record fields."""
    if isinstance(value, list):
        return [public(item) for item in value]
    if isinstance(value, dict):
        return {key: public(item) for key, item in value.items()}
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, UUID):
        return str(value)
    return value


def public_record(row, kind):
    """Project a known database record, preserving all nested JSON evidence."""
    if kind == "event":
        from .customer_views import guardrail_assessment

        return public({
            **row["body"],
            **{key: row.get(key) for key in (
                "id", "tenant_id", "sensor_id", "agent_id", "session_id",
                "received_at", "kind", "time",
            )},
            "risk": guardrail_assessment(row.get("risk")),
        })
    if kind == "audit":
        from .customer_views import audit_details

        row = {**row, "details": audit_details(row.get("action"), row.get("details") or {})}
    hidden = {"password_hash", "token_hash", "username"}
    if kind != "telemetry_export":
        hidden.add("tenant_id")
    hidden.update({
        "sensor": ("health_report", "health_reported_at"),
        "agent": ("hostname", "os", "arch"),
        "finding": ("hostname", "os", "arch", "assignee_id", "assignee_name", "primary_event_id"),
        "note": ("author_id", "author_name"),
        "action": ("created_by_name",),
        "audit": ("actor_type", "actor_id", "actor_name"),
    }.get(kind, ()))
    return public({key: item for key, item in row.items() if key not in hidden})
