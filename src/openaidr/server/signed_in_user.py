"""Best-effort endpoint login evidence, independent of heartbeat liveness."""

from datetime import datetime, timedelta, timezone


def parse(value):
    if not isinstance(value, dict):
        return None
    name, stamp = value.get("name"), value.get("signed_in_at")
    if not isinstance(name, str) or not name.strip() or len(name) > 256 or not name.isprintable():
        return None
    if not isinstance(stamp, str) or len(stamp) > 64:
        return None
    try:
        stamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return None
        stamp = stamp.astimezone(timezone.utc)
        if not datetime(1970, 1, 1, tzinfo=timezone.utc) < stamp <= datetime.now(timezone.utc) + timedelta(minutes=5):
            return None
    except (ValueError, OverflowError):
        return None
    return name, stamp
