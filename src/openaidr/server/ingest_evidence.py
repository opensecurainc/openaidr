"""Lossless retention for evidence that cannot enter PostgreSQL text or JSONB."""

import base64
from dataclasses import dataclass
from decimal import Decimal
import hashlib
import json
import math
import re

from .store import Conflict, new_id

SOURCES = ("events", "hook-checks", "otlp-logs", "otlp-metrics", "otlp-traces")
ENCODING = "json-ascii-v1"
MAX_BYTES = 64 << 20
FIELDS = "id,sensor_id,source,record_key,encoding,reason,status,payload_sha256,received_at"


@dataclass(frozen=True)
class Number:
    """A JSON number whose original token cannot be represented by Python safely."""

    token: str


def loads(raw):
    def integer(token):
        return int(token) if len(token.lstrip("-")) <= 4300 else Number(token)

    def floating(token):
        value = float(token)
        nonzero = any(char in "123456789" for char in re.split("[eE]", token, maxsplit=1)[0])
        return value if math.isfinite(value) and (value != 0 or not nonzero) else Number(token)

    return json.loads(raw, parse_int=integer, parse_float=floating)


def text_issue(value):
    if "\x00" in value:
        return "nul_character"
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return "unpaired_surrogate"
    return ""


def storage_issue(value):
    """Check keys as well as values; do not modify source evidence or identities."""
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 64:
            return "nesting_limit"
        if isinstance(item, str):
            if reason := text_issue(item):
                return reason
        elif isinstance(item, Number):
            return "unsupported_number"
        elif isinstance(item, float) and not math.isfinite(item):
            return "nonfinite_number"
        elif isinstance(item, int) and item.bit_length() > 435411:
            return "numeric_range"
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    return "nonstring_key"
                pending.extend(((key, depth + 1), (child, depth + 1)))
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif item is not None and not isinstance(item, (int, float, bool)):
            return "unsupported_type"
    return ""


def encode(value):
    """ASCII JSON preserves NUL, lone surrogates, and literal backslash escapes.

    Nonfinite numbers retain Python JSON's explicit NaN/Infinity tokens. The
    download is an octet stream, not a claim that those tokens are standard JSON.
    Number tokens retain values the ordinary JSON decoder would lose or reject.
    """
    parts, pending, size = [], [value], 0
    while pending:
        item = pending.pop()
        if isinstance(item, tuple):
            part = item[0]
        elif isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise ValueError("retained object keys must be strings")
            pending.append(("}",))
            for index, key in reversed(list(enumerate(sorted(item)))):
                pending.extend((item[key], (json.dumps(key, ensure_ascii=True) + ":",)))
                if index:
                    pending.append((",",))
            part = "{"
        elif isinstance(item, list):
            pending.append(("]",))
            for index, child in reversed(list(enumerate(item))):
                pending.append(child)
                if index:
                    pending.append((",",))
            part = "["
        elif isinstance(item, Number):
            if not re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", item.token):
                raise ValueError("invalid retained number")
            part = item.token
        elif isinstance(item, int) and not isinstance(item, bool) and item.bit_length() > 14000:
            part = str(Decimal(item))
        else:
            part = json.dumps(item, ensure_ascii=True, separators=(",", ":"))
        size += len(part)
        if size > MAX_BYTES:
            raise ValueError("retained evidence exceeds the storage limit")
        parts.append(part)
    return "".join(parts).encode("ascii")


def retain(st, sensor, source, record_key, value, reason, *, conn=None):
    """Call after the source's capture/redaction rules, inside its transaction."""
    if source not in SOURCES or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", record_key):
        raise ValueError("invalid retained evidence identity")
    if not re.fullmatch(r"[a-z_]{1,64}", reason):
        raise ValueError("invalid retained evidence reason")
    if conn is None:
        with st.transaction() as connection:
            return retain(st, sensor, source, record_key, value, reason, conn=connection)
    raw = encode(value)
    digest = hashlib.sha256(raw).hexdigest()
    rows = st.many(
        f"""INSERT INTO retained_ingest_evidence
            (id,tenant_id,sensor_id,source,record_key,encoding,reason,payload,payload_sha256)
            SELECT $1,$2,id,$4,$5,$6,$7,$8,$9 FROM sensors WHERE id=$3 AND tenant_id=$2
            ON CONFLICT(tenant_id,sensor_id,source,record_key) DO UPDATE
              SET record_key=retained_ingest_evidence.record_key
              WHERE retained_ingest_evidence.payload_sha256=EXCLUDED.payload_sha256
            RETURNING {FIELDS}""",
        new_id(), sensor["tenant_id"], sensor["id"], source, record_key, ENCODING,
        reason, raw, digest, conn=conn,
    )
    if not rows:
        raise Conflict("retained evidence identity does not match its source or payload")
    return rows[0]


def listing(st, tenant, page):
    return st._page(FIELDS, "retained_ingest_evidence", ["tenant_id=$1"], [tenant], page, "received_at")


def read(st, tenant, ident):
    return st.one(f"SELECT {FIELDS},payload FROM retained_ingest_evidence WHERE tenant_id=$1 AND id=$2",
                  tenant, ident)


def public(row):
    return {**{key: value for key, value in row.items() if key != "payload"},
            "payload_base64": base64.b64encode(row["payload"]).decode("ascii")}


def cleanup(st, tenant, conn):
    """Use the tenant's existing age policy and completed pressure-cleanup cutoff."""
    return st.execute("""DELETE FROM retained_ingest_evidence WHERE id IN (
        SELECT e.id FROM retained_ingest_evidence e JOIN tenant_telemetry_retention r USING(tenant_id)
        WHERE e.tenant_id=$1 AND (
            (r.mode IN ('7','30','90') AND e.received_at<clock_timestamp()-
                (CASE WHEN r.mode IN ('7','30','90') THEN r.mode::int ELSE 0 END)*interval '1 day')
            OR (r.cleanup_threshold_percent IS NOT NULL
                AND (e.received_at AT TIME ZONE 'UTC')::date<=r.last_deleted_day))
        ORDER BY e.received_at,e.id LIMIT 10)
        """, tenant, conn=conn)
