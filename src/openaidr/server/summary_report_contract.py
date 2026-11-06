"""Public aggregate report format, without the cloud receiver."""

import hashlib
import json
import re
from datetime import datetime, timedelta
from uuid import UUID

from .httpx import require
from .store import valid_uuid

PATH = "/reporting/v1/summary-reports"
MAX_BYTES = 16 << 10
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
VERSION = re.compile(r"20[0-9]{2}\.[1-9][0-9]?\.[1-9][0-9]?\+[0-9a-f]{7,40}")
COUNTS = {
    "checks": ("total", "pending", "evaluated", "unavailable", "shadow", "enforce"),
    "evaluated_decisions": ("allow", "warn", "ask", "deny"),
    "returned_decisions": ("allow", "warn", "ask", "deny"),
    "delivery": ("delivered", "timed_out", "failed", "unconfirmed"),
    "delivered_decisions": ("allow", "warn", "ask", "deny"),
    "findings": ("total", "info", "low", "medium", "high", "critical", "marked_false_positive"),
    "investigations": ("total", "finding", "no_finding", "inconclusive", "unknown",
                       "source_complete", "source_incomplete", "source_unknown"),
    "latency_samples": ("policy", "e2e"),
}
LATENCIES = tuple(f"{kind}_{pct}" for kind in ("policy", "e2e") for pct in ("p50", "p95", "p99"))


def encoded(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(payload):
    return hashlib.sha256(encoded(payload)).hexdigest()


def validate(payload):
    """Reject extra fields at every level. No free text or arbitrary metric labels."""
    require(isinstance(payload, dict) and set(payload) == {
        "schema_version", "report_id", "tenant_id", "generated_at", "window_start", "window_end",
        "backend_version", "counts", "latency_ms",
    }, "invalid summary report fields")
    require(type(payload["schema_version"]) is int and payload["schema_version"] == 1,
            "unsupported summary report version")
    require(all(isinstance(payload[k], str) and valid_uuid(payload[k]) and str(UUID(payload[k])) == payload[k]
                for k in ("report_id", "tenant_id")), "invalid report identity")
    times = []
    for key in ("window_start", "window_end", "generated_at"):
        value = payload[key]
        require(isinstance(value, str) and len(value) <= 32 and value.endswith("+00:00"), "UTC timestamp required")
        try:
            times.append(datetime.fromisoformat(value))
        except ValueError:
            require(False, "invalid timestamp")
    require(times[1] - times[0] == timedelta(days=1) and times[1] == times[2], "invalid report window")
    version = payload["backend_version"]
    require(version is None or isinstance(version, str) and VERSION.fullmatch(version), "invalid backend version")
    counts = payload["counts"]
    require(isinstance(counts, dict) and set(counts) == set(COUNTS), "invalid count groups")
    for group, keys in COUNTS.items():
        values = counts[group]
        require(isinstance(values, dict) and set(values) == set(keys), "invalid count fields")
        require(all(type(v) is int and 0 <= v <= 2**53 - 1 for v in values.values()), "invalid count")
    latency = payload["latency_ms"]
    require(isinstance(latency, dict) and set(latency) == set(LATENCIES), "invalid latency fields")
    require(all(v is None or type(v) in (int, float) and 0 <= v <= 3_600_000
                for v in latency.values()), "invalid latency")
    require(len(encoded(payload)) <= MAX_BYTES, "summary report too large", 413)
