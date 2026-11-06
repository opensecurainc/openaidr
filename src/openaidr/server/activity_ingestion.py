"""Acknowledge activity only after normal storage or lossless retention commits."""

import base64
import copy
import hashlib
import re
import uuid

import psycopg

from openaidr.core.event import validate_event
from openaidr.core.protocol import default_sensor_config
from . import ingest_evidence
from .event_normalization import normalize_host
from .httpx import parse_time, require


def _validation(event):
    if reason := ingest_evidence.storage_issue(event):
        return reason
    if not isinstance(event, dict):
        return "invalid_event"
    for name in ("agent", "host", "session", "source", "tool", "command", "file", "network", "hook", "export"):
        if name in event and not isinstance(event[name], dict):
            return "invalid_event_structure"
    for name, fields in (
        ("agent", ("product", "version", "model", "account")),
        ("host", ("hostname", "os", "arch", "user")),
        ("session", ("id", "cwd", "git_branch", "registration_id", "parent_id")),
        ("command", ("text",)), ("file", ("path",)), ("network", ("host",)),
        ("tool", ("name", "call_id")), ("source", ("hook_request_id",)),
    ):
        if any(key in event.get(name, {}) and not isinstance(event[name][key], str) for key in fields):
            return "invalid_event_text"
    if reason := validate_event(event):
        return reason
    if not isinstance(event.get("id"), str):
        return "invalid_event_id"
    try:
        uuid.UUID(event["id"])
    except ValueError:
        return "invalid_event_id"
    for field in ("time", "observed_at"):
        if field == "observed_at" and not event.get(field):
            continue
        try:
            if not isinstance(event[field], str) or parse_time(event[field]).tzinfo is None:
                return "invalid_event_time"
        except (ValueError, TypeError, AttributeError, KeyError):
            return "invalid_event_time"
    return ""


def _retain(st, sensor, event, reason, index, conn):
    digest = hashlib.sha256(ingest_evidence.encode(event)).hexdigest()
    code = reason if re.fullmatch(r"[a-z_]{1,64}", reason) else "invalid_event"
    retained = ingest_evidence.retain(st, sensor, "events", "sha256:" + digest, event, code, conn=conn)
    ident = event.get("id", "") if isinstance(event, dict) else ""
    if not isinstance(ident, str) or len(ident) > 128 or ingest_evidence.text_issue(ident):
        ident = ""
    return {"index": index, "id": ident, "reason": reason, "retained_id": retained["id"]}


def receive(st, sensor, raw):
    require(len(raw) <= 8 << 20, "request body too large", 413)
    try:
        data = ingest_evidence.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        # Preserve the bytes without guessing an encoding or editing characters.
        data = {"wire_base64": base64.b64encode(raw).decode("ascii")}
        invalid = "invalid_json"
    else:
        invalid = "" if isinstance(data, dict) else "invalid_batch"
        if not invalid:
            require(not data.get("sensor_id") or data["sensor_id"] == sensor["id"],
                    "batch sensor_id does not match the token", 403)
            if not isinstance(data.get("events", []), list):
                invalid = "invalid_batch"
    if invalid:
        with st.transaction() as conn:
            rejected = _retain(st, sensor, data, invalid, None, conn)
        return {"accepted": 0, "duplicates": 0, "rejected": [rejected]}
    events = data.get("events", [])
    require(len(events) <= default_sensor_config()["batch_max_events"], "batch exceeds batch_max_events", 413)
    valid, indices, rejected = [], [], []
    with st.transaction() as conn:
        for index, event in enumerate(events):
            if reason := _validation(event):
                rejected.append(_retain(st, sensor, event, reason, index, conn))
                continue
            normalized = copy.deepcopy(event)
            normalize_host(normalized, sensor)
            valid.append(normalized)
            indices.append(index)
        try:
            with conn.transaction():
                result = st.ingest_batch(sensor, valid, conn) if valid else {"accepted": 0, "duplicates": 0}
        except (psycopg.DataError, psycopg.errors.ProgramLimitExceeded):
            # Roll back the complete normal batch before isolating a less common
            # PostgreSQL data restriction. Capacity, locks, and outages propagate.
            result = {"accepted": 0, "duplicates": 0, "rejected": []}
            for position, event in enumerate(valid):
                try:
                    with conn.transaction():
                        item = st.ingest_batch(sensor, [event], conn)
                except (psycopg.DataError, psycopg.errors.ProgramLimitExceeded):
                    index = indices[position]
                    rejected.append(_retain(st, sensor, events[index], "database_data_error", index, conn))
                else:
                    result["accepted"] += item["accepted"]
                    result["duplicates"] += item["duplicates"]
                    result["rejected"].extend({**record, "index": position} for record in item.get("rejected", []))
        for record in result.get("rejected", []):
            index = indices[record["index"]]
            rejected.append(_retain(st, sensor, events[index], record["reason"], index, conn))
    return {"accepted": result["accepted"], "duplicates": result["duplicates"],
            "rejected": sorted(rejected, key=lambda item: item["index"])}
