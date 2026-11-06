"""Allowlisted cloud protection state for sensor status and desktop notices."""

from datetime import datetime, timezone
import math
import time

FIELDS = {"schema_version", "state", "checked_at", "guardrail_configured", "guardrail_available",
          "credit_status", "credits_per_usd", "reset_at"}
LEGACY_AMOUNTS = {"allowance_nanos", "spent_nanos", "reserved_nanos", "remaining_nanos"}
LEGACY_FIELDS = LEGACY_AMOUNTS | {"state", "checked_at", "guardrail_configured", "guardrail_available", "resets_at"}
CREDIT_STATES = ("disabled", "unconfigured", "active", "exhausted", "unavailable", None)


def project(value, *, at=None):
    if value is None:
        return None
    unavailable = dict(schema_version=1, state="unavailable", checked_at=None,
                       guardrail_configured=False, guardrail_available=False,
                       credit_status="unavailable", credits_per_usd="100", reset_at=None)
    if not isinstance(value, dict):
        return unavailable
    if set(value) == {"state", "checked_at"} and value["state"] in ("connecting", "exhausted", "unavailable"):
        # Existing enrollment has no successful availability response yet.
        value = {**unavailable, **value, "credit_status": None}
    elif set(value) == LEGACY_FIELDS:
        # Validate the retained legacy wire shape before discarding its private counters.
        if any(type(value[key]) is not int or not 0 <= value[key] <= 10**15 for key in LEGACY_AMOUNTS):
            return unavailable
        if not isinstance(value["resets_at"], str):
            return unavailable
        value = dict(schema_version=1, state=value["state"], checked_at=value["checked_at"],
                     guardrail_configured=value["guardrail_configured"], guardrail_available=value["guardrail_available"],
                     credit_status=None, credits_per_usd="100", reset_at=value["resets_at"])
    if set(value) != FIELDS:
        return unavailable
    checked = value["checked_at"]
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["state"] not in ("connecting", "active", "exhausted", "unavailable")
            or value["credits_per_usd"] != "100" or value["credit_status"] not in CREDIT_STATES
            or type(value["guardrail_configured"]) is not bool or type(value["guardrail_available"]) is not bool
            or checked is not None and (type(checked) not in (int, float) or checked < 0 or type(checked) is float and not math.isfinite(checked))):
        return unavailable
    result = dict(value)
    if value["reset_at"] is not None:
        try:
            reset = datetime.fromisoformat(value["reset_at"])
            if reset.tzinfo is None:
                return unavailable
            result["reset_at"] = reset.astimezone(timezone.utc).isoformat()
        except (TypeError, ValueError, OverflowError):
            return unavailable
    now = time.time() if at is None else at
    stale = checked is None or checked > now + 30 or now - checked > 180
    if (value["state"] == "active" and (stale or not value["guardrail_available"]
            or not value["guardrail_configured"] or value["credit_status"] not in (None, "disabled", "active"))
            or checked is not None and stale):
        result["state"] = "unavailable"
    if result["state"] != "active":
        result["guardrail_available"] = False
    return result
