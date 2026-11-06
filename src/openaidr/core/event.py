"""Append-only JSON event contract shared by sensors and servers.

Events remain dictionaries so unknown fields survive rolling upgrades.
"""

import secrets
import re
import time
import uuid
from datetime import datetime, timezone

from openaidr_common.event import EVIDENCE_GAPS as EVIDENCE_GAPS, PRODUCTS as PRODUCTS

SCHEMA_VERSION = 1
KINDS = (
    "session.start",
    "session.end",
    "prompt",
    "response",
    "tool.call",
    "tool.result",
    "command",
    "file.read",
    "file.write",
    "network",
    "hook.decision",
    "sensor",
)


def validate_evidence(evidence) -> str:
    if (
        not isinstance(evidence, dict)
        or type(evidence.get("version")) is not int
        or evidence["version"] != 1
    ):
        return "invalid evidence version"
    for key in ("logical_id", "observation_id", "stream_id"):
        value = evidence.get(key)
        if not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z0-9_.:-]{1,128}", value
        ):
            return "invalid evidence." + key
    for key in ("sequence", "part"):
        value = evidence.get(key)
        if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
            return "invalid evidence." + key
    gaps = evidence.get("gaps")
    if (
        not isinstance(gaps, list)
        or len(gaps) > 32
        or any(not isinstance(gap, str) or gap not in EVIDENCE_GAPS for gap in gaps)
    ):
        return "invalid evidence.gaps"
    return ""


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_id() -> str:
    """RFC 9562 UUIDv7, including on Python versions before uuid.uuid7."""
    bits = ((time.time_ns() // 1_000_000) & ((1 << 48) - 1)) << 80
    bits |= 7 << 76 | secrets.randbits(12) << 64 | 2 << 62 | secrets.randbits(62)
    return str(uuid.UUID(int=bits))


def validate_event(event: dict) -> str:
    if not isinstance(event, dict):
        return "invalid event"
    if not event.get("id"):
        return "missing id"
    if "evidence" in event:
        reason = validate_evidence(event["evidence"])
        if reason:
            return reason
    if not event.get("time") or str(event["time"]).startswith("0001-01-01"):
        return "missing time"
    if not event.get("kind"):
        return "missing kind"
    kind = event["kind"]
    if kind not in KINDS:
        return "unknown kind"
    if not isinstance(event.get("agent"), dict) or not event["agent"].get("product"):
        return "missing agent.product"
    if "account" in event["agent"] and not isinstance(event["agent"]["account"], str):
        return "agent.account must be a string"
    session = event.get("session")
    if isinstance(session, dict) and "registration_id" in session:
        registration_id = session["registration_id"]
        if not isinstance(registration_id, str):
            return "invalid session.registration_id"
        try:
            if str(uuid.UUID(registration_id)) != registration_id.lower():
                return "invalid session.registration_id"
        except ValueError:
            return "invalid session.registration_id"
        if (
            not isinstance(session.get("id"), str) or not 1 <= len(session["id"]) <= 256
            or any(ord(char) < 32 or ord(char) == 127 for char in session["id"])
        ):
            return "invalid registered session.id"
    if kind != "sensor" and (
        not isinstance(event.get("session"), dict) or not event["session"].get("id")
    ):
        return "missing session.id"
    for kinds, field, key, reason in [
        (("command",), "command", "text", "command event without command.text"),
        (("file.read", "file.write"), "file", "path", "file event without file.path"),
        (("network",), "network", "url", "network event without network.url"),
    ]:
        if kind in kinds and (
            not isinstance(event.get(field), dict) or not event[field].get(key)
        ):
            return reason
    return ""
