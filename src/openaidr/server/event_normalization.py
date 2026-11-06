"""Consistent receiver defaults for ordinary and inline captured events."""

from .httpx import require


def normalize_host(event, sensor, *, defaults=None):
    """Fill omitted host values, retaining a prior stored observation's defaults."""
    host = event.setdefault("host", {})
    require(isinstance(host, dict), "event host must be an object")
    for key in ("hostname", "os", "arch", "user"):
        if not host.get(key):
            host[key] = (
                defaults[key]
                if defaults is not None and key in defaults
                else sensor.get(
                    key, sensor.get("username", "") if key == "user" else ""
                )
            )
    return event
