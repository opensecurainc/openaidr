"""Bounded heartbeat diagnostics, separate from connection liveness."""

from datetime import datetime, timezone

from .httpx import APIError, require

STALL_SECONDS = 300


def validate_report(value):
    try:
        return _validate_report(value)
    except APIError:
        # Optional diagnostics must never interrupt liveness, policy updates,
        # or administrative commands. Invalid reports replace old health too.
        return None


def _validate_report(value):
    if value is None:
        return None
    require(isinstance(value, dict), "health_report must be an object or null")
    # Future reporters must still be able to heartbeat against an older server.
    if type(value.get("version")) is not int or value["version"] != 1:
        return None

    def integer(data, key):
        result = data.get(key)
        require(type(result) is int and 0 <= result <= 9007199254740991,
                f"health_report {key} must be a nonnegative safe integer")
        return result

    def flag(data, key):
        result = data.get(key)
        require(type(result) is bool, f"health_report {key} must be a boolean")
        return result

    def upload(name):
        data = value.get(name)
        require(isinstance(data, dict), f"health_report {name} must be an object")
        stamp = data.get("last_success_at")
        if stamp is not None:
            require(isinstance(stamp, str) and len(stamp) <= 64,
                    "health_report last_success_at must be a timestamp or null")
            try:
                parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                require(parsed.tzinfo is not None, "health_report timestamp needs a timezone")
                stamp = parsed.astimezone(timezone.utc).isoformat()
            except (ValueError, OverflowError):
                require(False, "health_report last_success_at is invalid")
        result = dict(upload_failed=flag(data, "upload_failed"),
                      stalled_for_s=integer(data, "stalled_for_s"), last_success_at=stamp)
        if name == "activity":
            result["dropped"] = integer(data, "dropped")
        else:
            result.update(enabled=flag(data, "enabled"), listening=flag(data, "listening"))
        return result

    # Store only these fields. Exception text, paths, URLs, and credentials do not
    # belong in a fleet health report, including unknown extension fields.
    return dict(version=1, activity=upload("activity"), telemetry=upload("telemetry"),
                collectors_failed=integer(value, "collectors_failed"))


def assess(row):
    report = row.get("health_report")
    reported_at = row.get("health_reported_at")
    current = bool(report and reported_at and reported_at == row.get("last_heartbeat_at"))
    reasons = []

    def reason(code, message):
        reasons.append(dict(code=code, message=message))

    if row["status"] == "disabled":
        status = "disabled"
    elif row["status"] == "offline" or not current:
        status = "unknown"
    else:
        activity, telemetry = report["activity"], report["telemetry"]
        for name, details, depth in (
            ("activity", activity, row.get("queue_depth")),
            ("telemetry", telemetry, row.get("telemetry_queue_depth")),
        ):
            if name == "telemetry" and not details["enabled"]:
                continue
            if details["upload_failed"]:
                reason(name + "_upload_failed", name.capitalize() + " uploads are failing")
            if depth and details["stalled_for_s"] >= STALL_SECONDS:
                reason(name + "_stalled", name.capitalize() + " queue has made no progress for at least 5 minutes")
        if activity["dropped"]:
            reason("activity_dropped", "Activity records were dropped during this sensor session")
        if telemetry["enabled"] and not telemetry["listening"]:
            reason("telemetry_not_listening", "Telemetry receiver is not listening")
        if report["collectors_failed"]:
            reason("collector_failed", "Activity collection is failing")
        status = "needs_attention" if reasons else "healthy"
    return dict(status=status, reasons=reasons, reported_at=reported_at if current else None,
                stale=row["status"] != "online", report=report if current else None)
