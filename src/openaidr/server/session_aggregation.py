"""Managed delivery receipts, immutable session snapshots and bounded job admission."""

import base64
import hashlib
import json
import math
import re
import time
import uuid
from contextlib import nullcontext
from datetime import timedelta
from decimal import Decimal, InvalidOperation

from psycopg.errors import QueryCanceled, SerializationFailure
from psycopg.types.json import Jsonb

from openaidr.core.event import EVIDENCE_GAPS, validate_evidence
from openaidr_api_client.contracts.detection import SESSION_GAPS as GAPS
from . import session_ownership
from .httpx import APIError, require
from openaidr.core.redact import redact_value
from .store import NotFound, new_id


DECIMALS = ("risk_threshold", "max_cost_usd_per_attempt", "hourly_cost_usd", "investigation_percent", "sample_percent")
INTEGERS = (
    "idle_seconds",
    "delivery_grace_seconds",
    "gap_wait_seconds",
    "max_runtime_seconds",
    "max_tokens_per_attempt",
    "max_attempts",
    "max_concurrent",
    "hourly_attempts",
    "hourly_tokens",
    "retry_delay_seconds",
    "history_days",
    "action_risk_threshold",
    "urgent_risk_threshold",
    "session_high_risk_actions",
    "user_high_risk_actions",
)
SETTINGS = ("enabled", *DECIMALS, *INTEGERS, "gap_policy", "model", "selection_policy")
SELECTION_DEFAULTS = {
    "selection_policy": "risk_budget", "history_days": 7,
    "investigation_percent": "1", "sample_percent": "0",
    "action_risk_threshold": 70, "urgent_risk_threshold": 95,
    "session_high_risk_actions": 2, "user_high_risk_actions": 3,
}
DETECTOR_FIELDS = (
    "model",
    "max_runtime_seconds",
    "max_tokens_per_attempt",
    "max_cost_usd_per_attempt",
    "history_days",
)
BOUNDARIES = frozenset(("prompt", "tool_call", "tool_output", "assistant_response"))
OUTCOMES = frozenset(("succeeded", "failed", "not_executed", "uncertain"))
OUTCOME_REASONS = frozenset(
    ("blocked", "rejected", "expired", "cancelled", "backend_unavailable", "reconciled")
)
_PAGE_BYTES = 1 << 20


def _uuid(value, label="id"):
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise APIError(400, "invalid " + label) from None


def _json(value):
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise APIError(400, "invalid session detection JSON") from None


def _body(payload, fields, required=()):
    require(
        isinstance(payload, dict)
        and set(payload) <= set(fields)
        and set(required) <= set(payload),
        "invalid session detection request",
    )


def _decimal(value, name, *, positive=False):
    try:
        require(type(value) in (str, int, float, Decimal), "invalid " + name)
        result = Decimal(str(value))
        require(
            result.is_finite() and (result > 0 if positive else result >= 0),
            "invalid " + name,
        )
        require(abs(result.as_tuple().exponent) <= 64, "invalid " + name)
        require(result.adjusted() <= 64, "invalid " + name)
        require(len(str(result)) <= 80, "invalid " + name)
        return result
    except InvalidOperation:
        raise APIError(400, "invalid " + name) from None


def _settings_view(row):
    return {
        key: str(value) if key in DECIMALS and value is not None else value
        for key, value in row.items()
    }


def get_settings(st, tenant_id, conn=None):
    rows = st.many(
        "SELECT "
        + ",".join(SETTINGS)
        + ",version,detector_config_version,updated_at FROM tenant_session_detection_settings WHERE tenant_id=$1",
        tenant_id,
        conn=conn,
    )
    if rows:
        return _settings_view(rows[0])
    return {
        **dict.fromkeys(SETTINGS),
        **SELECTION_DEFAULTS,
        "enabled": False,
        "version": 0,
        "detector_config_version": 0,
        "updated_at": None,
    }


def _validate_settings(values):
    for name in DECIMALS:
        if name not in values:
            continue
        if values[name] is not None:
            values[name] = _decimal(
                values[name], name, positive=name not in ("risk_threshold", "sample_percent")
            )
    for name in INTEGERS:
        if name not in values:
            continue
        value = values[name]
        minimum = (
            0
            if name
            in ("delivery_grace_seconds", "gap_wait_seconds", "retry_delay_seconds")
            else 1
        )
        maximum = (
            1 << (63 if name in ("hourly_tokens", "max_tokens_per_attempt") else 31)
        ) - 1
        require(
            value is None or (type(value) is int and minimum <= value <= maximum),
            "invalid " + name,
        )
    require(
        values["selection_policy"] in ("legacy", "risk_budget"), "invalid selection_policy",
    )
    require(type(values["history_days"]) is int and 1 <= values["history_days"] <= 90, "invalid history_days")
    require(all(isinstance(values[key], Decimal) for key in ("sample_percent", "investigation_percent"))
            and 0 <= values["sample_percent"] <= values["investigation_percent"] <= 100,
            "invalid investigation percentages")
    require(values["sample_percent"] == 0, "Random investigation sampling has been removed; sample_percent must be 0")
    require(all(type(values[key]) is int for key in ("action_risk_threshold", "urgent_risk_threshold", "session_high_risk_actions", "user_high_risk_actions"))
            and 1 <= values["action_risk_threshold"] <= values["urgent_risk_threshold"] <= 100,
            "invalid action risk thresholds")
    require(
        values["gap_policy"] is None
        or values["gap_policy"] in ("retain", "investigate"),
        "invalid gap_policy",
    )
    if "model" in values:
        require(
            values["model"] is None
            or (
                isinstance(values["model"], str)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", values["model"])
            ),
            "invalid model",
        )
    require(
        not values["enabled"] or all(value is not None for value in values.values()),
        "explicit detection settings are required before enablement",
    )
    for larger, smaller in (
        ("gap_wait_seconds", "delivery_grace_seconds"),
        ("hourly_tokens", "max_tokens_per_attempt"),
        ("hourly_cost_usd", "max_cost_usd_per_attempt"),
    ):
        if larger not in values:
            continue
        require(
            values[larger] is None
            or values[smaller] is None
            or values[larger] >= values[smaller],
            larger + " is below " + smaller,
        )


def _persist_settings(st, tenant_id, values, actor, detector_changed, conn, *, audit_values=None):
    fields = tuple(values)
    placeholders = ",".join("$" + str(index + 2) for index in range(len(fields)))
    updates = ",".join(name + "=EXCLUDED." + name for name in fields)
    row = st.one(
        "INSERT INTO tenant_session_detection_settings(tenant_id,"
        + ",".join(fields)
        + ") VALUES($1,"
        + placeholders
        + ") "
        "ON CONFLICT(tenant_id) DO UPDATE SET "
        + updates
        + ",version=tenant_session_detection_settings.version+1,"
        "detector_config_version=tenant_session_detection_settings.detector_config_version+$"
        + str(len(fields) + 2)
        + ",updated_at=clock_timestamp() RETURNING *",
        tenant_id,
        *(values[name] for name in fields),
        int(detector_changed),
        conn=conn,
    )
    st.execute(
        "INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5,'session-detection.configure','session-detection',$2,$6)",
        new_id(),
        tenant_id,
        actor.get("type", "user"),
        actor.get("id", ""),
        actor.get("name", ""),
        Jsonb(
            {
                "version": row["version"],
                "detector_config_version": row["detector_config_version"],
                **_settings_view(values if audit_values is None else audit_values),
            }
        ),
        conn=conn,
    )
    return row


def save_settings(st, tenant_id, payload, actor, *, expected_version=None, conn=None):
    _body(payload, SETTINGS, ("enabled",))
    require(type(payload["enabled"]) is bool, "enabled must be a boolean")
    with nullcontext(conn) if conn is not None else st.transaction() as conn:
        st.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "session-detection-settings:" + tenant_id,
            conn=conn,
        )
        previous = get_settings(st, tenant_id, conn)
        protocol = st.scalar("SELECT job_protocol_version FROM tenant_session_detection_settings WHERE tenant_id=$1", tenant_id, conn=conn)
        require(protocol in (None, 1) or payload == {"enabled": False},
                "Investigation settings require the complete-job contract", 409)
        require(expected_version is None or previous["version"] == expected_version,
                "Investigation settings changed. Refresh and try again.", 409)
        values = {name: payload.get(name, previous[name]) for name in SETTINGS}
        _validate_settings(values)
        detector_changed = any(
            values[key]
            != (
                Decimal(previous[key])
                if key in DECIMALS and previous[key] is not None
                else previous[key]
            )
            for key in DETECTOR_FIELDS
        )
        row = _persist_settings(st, tenant_id, values, actor, detector_changed, conn)
        row.pop("tenant_id")
        return _settings_view(row)


def _authorize(
    st,
    sensor,
    registration_id,
    conn,
    *,
    owner_user_id=None,
    protocol=False,
    snapshot=False,
):
    row = session_ownership.authorize_inline(
        st,
        sensor,
        _uuid(registration_id, "registration id"),
        conn,
        owner_user_id,
        snapshot=snapshot,
    )
    if protocol and row["delivery_protocol"] != 1:
        raise APIError(
            409, "session has no managed delivery protocol", "delivery_unavailable"
        )
    return row


def _gaps(value):
    require(
        isinstance(value, list)
        and len(value) <= 32
        and all(isinstance(item, str) and item in GAPS for item in value),
        "invalid delivery gaps",
    )
    return value


def _event_body(st, sensor, registration_id, event_id, conn):
    rows = st.many(
        """SELECT e.body FROM events e JOIN agent_sessions s ON s.tenant_id=e.tenant_id AND s.id=e.session_id
           WHERE e.tenant_id=$1 AND e.sensor_id=$2 AND s.registration_id=$3 AND e.id=$4
           UNION ALL SELECT target_body AS body FROM inline_guardrail_events
           WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3 AND event_id=$4 LIMIT 1""",
        sensor["tenant_id"],
        sensor["id"],
        registration_id,
        event_id,
        conn=conn,
    )
    if not rows:
        foreign = st.scalar(
            "SELECT EXISTS(SELECT 1 FROM events WHERE id=$1 UNION ALL SELECT 1 FROM inline_guardrail_events WHERE event_id=$1)",
            event_id,
            conn=conn,
        )
        raise APIError(
            403 if foreign else 409,
            "delivery evidence is unavailable",
            "record_unavailable",
        )
    return rows[0]["body"]


def _capture(body):
    result = redact_value(body)
    if not isinstance(body, dict):
        return result
    metadata = body.get("evidence")
    if not validate_evidence(metadata):
        for key in (
            "version",
            "logical_id",
            "observation_id",
            "stream_id",
            "sequence",
            "part",
            "gaps",
        ):
            result.setdefault("evidence", {})[key] = metadata[key]
        if result != body:
            result["evidence"]["gaps"] = sorted(
                set(metadata["gaps"]) | {"content_redacted"}
            )
    return result


def _record(st, sensor, registration, item, conn):
    _body(
        item,
        (
            "record_id",
            "sequence",
            "kind",
            "event_id",
            "logical_id",
            "action_commitment",
            "release_id",
            "outcome_audit_id",
            "gaps",
        ),
        ("record_id", "sequence", "kind", "gaps"),
    )
    item = dict(item)
    item["record_id"] = _uuid(item["record_id"], "record id")
    require(
        type(item["sequence"]) is int and 1 <= item["sequence"] <= (1 << 63) - 1,
        "invalid delivery sequence",
    )
    require(
        item["kind"] in ("target", "observation", "outcome", "gap"),
        "invalid delivery kind",
    )
    _gaps(item["gaps"])
    for field in ("event_id", "release_id", "outcome_audit_id"):
        if field in item:
            item[field] = _uuid(item[field], field)
    if "logical_id" in item:
        require(
            isinstance(item["logical_id"], str)
            and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", item["logical_id"]),
            "invalid logical_id",
        )
    prior = st.many(
        "SELECT payload_sha256,captured_body FROM session_delivery_receipts WHERE registration_id=$1 AND record_id=$2",
        registration["id"],
        item["record_id"],
        conn=conn,
    )
    if prior:
        if prior[0]["payload_sha256"] != hashlib.sha256(_json(item)).hexdigest():
            raise APIError(
                409,
                "delivery identity already binds different content",
                "payload_changed",
            )
        # Acknowledged references remain replayable after ordinary retention.
        return item, prior[0]["captured_body"]
    captured = None
    if item["kind"] in ("target", "observation"):
        require(
            "event_id" in item and not ({"release_id", "outcome_audit_id"} & set(item)),
            "invalid evidence receipt",
        )
        captured = _event_body(st, sensor, registration["id"], item["event_id"], conn)
        if item["kind"] == "target":
            require(
                "logical_id" in item
                and isinstance(item.get("action_commitment"), str)
                and re.fullmatch(
                    r"hmac-sha256-v1:[0-9a-f]{64}", item["action_commitment"]
                ),
                "invalid target binding",
            )
            if (
                validate_evidence(captured.get("evidence"))
                or captured["evidence"]["logical_id"] != item["logical_id"]
            ):
                raise APIError(
                    409, "target logical identity does not match", "payload_changed"
                )
            assessed = st.many(
                "SELECT event_id,action_commitment FROM inline_guardrail_events WHERE registration_id=$1 AND logical_id=$2",
                registration["id"],
                item["logical_id"],
                conn=conn,
            )
            if assessed and (
                assessed[0]["event_id"] != item["event_id"]
                or assessed[0]["action_commitment"] != item["action_commitment"]
            ):
                raise APIError(
                    409, "target assessment binding does not match", "payload_changed"
                )
        else:
            require(
                "action_commitment" not in item and "logical_id" not in item,
                "invalid observation receipt",
            )
    elif item["kind"] == "outcome":
        require(
            "logical_id" in item and "action_commitment" not in item,
            "invalid outcome receipt",
        )
        if "release_id" in item:
            require("outcome_audit_id" in item, "invalid release outcome reference")
            rows = st.many(
                """SELECT a.details,e.event_id FROM audit_log a JOIN guardrail_releases r ON r.id::text=a.target_id AND r.tenant_id=a.tenant_id
                   JOIN inline_guardrail_events e ON e.id=r.guardrail_event_id
                   WHERE a.tenant_id=$1 AND r.sensor_id=$2 AND r.registration_id=$3 AND r.id=$4
                     AND a.id=$5 AND a.action='guardrail.release.outcome' AND e.logical_id=$6""",
                sensor["tenant_id"],
                sensor["id"],
                registration["id"],
                item["release_id"],
                item["outcome_audit_id"],
                item["logical_id"],
                conn=conn,
            )
            require(rows, "outcome evidence is unavailable", 403)
            require(
                "event_id" not in item or item["event_id"] == rows[0]["event_id"],
                "outcome event does not match",
                403,
            )
            captured = rows[0]["details"]
        else:
            require(
                "event_id" in item and "outcome_audit_id" not in item,
                "invalid observed outcome reference",
            )
            body = _event_body(st, sensor, registration["id"], item["event_id"], conn)
            outcome = body.get("managed_outcome")
            _body(
                outcome,
                ("logical_id", "outcome", "exit_code", "reason"),
                ("logical_id", "outcome", "reason"),
            )
            require(
                body["kind"] == "sensor"
                and outcome["logical_id"] == item["logical_id"]
                and isinstance(outcome["outcome"], str)
                and outcome["outcome"] in OUTCOMES
                and isinstance(outcome["reason"], str)
                and outcome["reason"] in OUTCOME_REASONS,
                "invalid observed outcome",
            )
            require(
                outcome.get("exit_code") is None
                or (
                    type(outcome["exit_code"]) is int
                    and -(1 << 31) <= outcome["exit_code"] < 1 << 31
                ),
                "invalid outcome exit_code",
            )
            require(
                outcome["outcome"] not in ("succeeded", "failed")
                or (
                    outcome["reason"] == "backend_unavailable"
                    and "backend_unavailable" in item["gaps"]
                ),
                "an executed outage outcome must retain its gap",
            )
            captured = outcome
    else:
        require(
            set(item) == {"record_id", "sequence", "kind", "gaps"} and item["gaps"],
            "invalid gap receipt",
        )
    return item, _capture(captured) if captured and item["kind"] in (
        "target",
        "observation",
    ) else captured


def _insert_receipt(st, sensor, registration, payload, captured, conn):
    digest = hashlib.sha256(_json(payload)).hexdigest()
    rows = st.many(
        """SELECT * FROM session_delivery_receipts WHERE registration_id=$1
           AND (record_id=$2 OR ($3::bigint IS NOT NULL AND sequence=$3)
                OR ($4='target' AND kind='target' AND logical_id=$5))""",
        registration["id"],
        payload["record_id"],
        payload.get("sequence"),
        payload["kind"],
        payload.get("logical_id"),
        conn=conn,
    )
    if rows:
        if (
            len(rows) != 1
            or rows[0]["record_id"] != payload["record_id"]
            or rows[0]["payload_sha256"] != digest
        ):
            raise APIError(
                409,
                "delivery identity already binds different content",
                "payload_changed",
            )
        return rows[0]["id"], True
    row = st.one(
        """INSERT INTO session_delivery_receipts(id,tenant_id,sensor_id,registration_id,epoch_id,record_id,sequence,kind,
                   logical_id,event_id,release_id,payload_sha256,payload,captured_body)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id""",
        new_id(),
        sensor["tenant_id"],
        sensor["id"],
        registration["id"],
        registration["delivery_epoch"],
        payload["record_id"],
        payload.get("sequence"),
        payload["kind"],
        payload.get("logical_id"),
        payload.get("event_id"),
        payload.get("release_id"),
        digest,
        Jsonb(payload),
        Jsonb(captured),
        conn=conn,
    )
    return row["id"], False


def receive(st, sensor, registration_id, payload):
    _body(payload, ("epoch_id", "records"), ("epoch_id", "records"))
    require(len(_json(payload)) <= 64 << 10, "delivery request is too large", 413)
    require(
        isinstance(payload["records"], list) and len(payload["records"]) <= 100,
        "invalid delivery batch",
    )
    with st.transaction() as conn:
        registration = _authorize(st, sensor, registration_id, conn, protocol=True)
        if _uuid(payload["epoch_id"], "epoch") != registration["delivery_epoch"]:
            raise APIError(409, "delivery epoch does not match", "epoch_changed")
        accepted = duplicates = 0
        for raw in payload["records"]:
            item, captured = _record(st, sensor, registration, raw, conn)
            _, duplicate = _insert_receipt(
                st, sensor, registration, item, captured, conn
            )
            duplicates += duplicate
            accepted += not duplicate
        return {
            "accepted": accepted,
            "duplicates": duplicates,
            "status": _state(st, registration, conn),
        }, 200


def close(st, sensor, registration_id, payload):
    fields = (
        "request_id",
        "epoch_id",
        "final_sequence",
        "reason",
        "capabilities_version",
        "boundaries",
        "gaps",
    )
    _body(payload, fields, fields)
    require(
        type(payload["final_sequence"]) is int
        and 0 <= payload["final_sequence"] <= (1 << 63) - 1,
        "invalid closing sequence",
    )
    require(
        payload["reason"]
        in ("session_end", "process_exit", "user_stop", "client_error", "journal_lost"),
        "invalid close reason",
    )
    require(
        type(payload["capabilities_version"]) is int
        and payload["capabilities_version"] == 1,
        "unsupported capabilities version",
    )
    require(
        isinstance(payload["boundaries"], list)
        and len(payload["boundaries"]) <= 4
        and all(
            isinstance(value, str) and value in BOUNDARIES
            for value in payload["boundaries"]
        ),
        "invalid boundaries",
    )
    require(
        len(set(payload["boundaries"])) == len(payload["boundaries"]),
        "duplicate boundary",
    )
    _gaps(payload["gaps"])
    with st.transaction() as conn:
        registration = _authorize(st, sensor, registration_id, conn, protocol=True)
        if _uuid(payload["epoch_id"], "epoch") != registration["delivery_epoch"]:
            raise APIError(409, "delivery epoch does not match", "epoch_changed")
        item = {
            **payload,
            "record_id": _uuid(payload["request_id"], "request id"),
            "kind": "close",
        }
        item.pop("request_id")
        item["epoch_id"] = registration["delivery_epoch"]
        previous = st.scalar(
            "SELECT max((payload->>'final_sequence')::bigint) FROM session_delivery_receipts WHERE registration_id=$1 AND kind='close'",
            registration["id"],
            conn=conn,
        )
        duplicate = st.scalar(
            "SELECT EXISTS(SELECT 1 FROM session_delivery_receipts WHERE registration_id=$1 AND record_id=$2)",
            registration["id"],
            item["record_id"],
            conn=conn,
        )
        if (
            not duplicate
            and previous is not None
            and payload["final_sequence"] < previous
        ):
            raise APIError(
                409, "closing watermark cannot move backwards", "stale_close"
            )
        ident, duplicate = _insert_receipt(st, sensor, registration, item, None, conn)
        return {
            "duplicate": duplicate,
            "close_id": ident,
            "status": _state(st, registration, conn),
        }, 200


def _stored(value):
    return json.loads(json.dumps(value, default=str, allow_nan=False))


def _page_groups(rows):
    """Keep a single oversized record intact without combining it with others."""
    group, size = [], 2
    for row in rows:
        if group and size + row["byte_size"] + 1 > _PAGE_BYTES:
            yield group
            group, size = [], 2
        size += row["byte_size"] + bool(group)
        group.append(row["id"])
    if group:
        yield group


def _rows(st, query, registration, conn, *extra):
    """Read fixed source queries by indexed UUID, bounding transferred body bytes."""
    after = None
    while True:
        # The first page includes the valid nil UUID. Later pages use an
        # exclusive indexed bound. Both query operators are internal constants.
        page = query.format(after=">=" if after is None else ">")
        args = (
            registration["id"],
            registration["tenant_id"],
            after if after is not None else str(uuid.UUID(int=0)),
            *extra,
        )
        metadata = st.many(
            f"SELECT p.id,octet_length(to_jsonb(p)::text) AS byte_size FROM ({page}) p ORDER BY p.id",
            *args,
            conn=conn,
        )
        if not metadata:
            return
        for keys in _page_groups(metadata):
            rows = st.many(
                f"SELECT p.* FROM ({page}) p WHERE p.id=ANY(${len(args) + 1}::uuid[]) ORDER BY p.id",
                *args,
                keys,
                conn=conn,
            )
            for row in rows:
                if isinstance(st, _FinalizationStore):
                    st.check()
                yield row
        after = metadata[-1]["id"]


def _observations(st, registration, previous_snapshot, conn):
    # Prefer the immutable copy acknowledged by a receipt. SQL removes duplicate
    # source IDs before transferring/redacting large bodies a second time.
    sources = (
        (
            """SELECT d.id,d.captured_body AS body,d.event_id FROM session_delivery_receipts d
            WHERE d.registration_id=$1 AND d.tenant_id=$2 AND d.id{after}$3 AND d.kind IN ('target','observation')
              AND NOT EXISTS(SELECT 1 FROM session_delivery_receipts old WHERE old.registration_id=$1
                             AND old.event_id=d.event_id AND old.kind IN ('target','observation') AND old.id<d.id)
            ORDER BY d.id LIMIT 250""",
            (),
            True,
        ),
        (
            """SELECT e.event_id AS id,e.target_body AS body FROM inline_guardrail_events e
            WHERE e.registration_id=$1 AND e.tenant_id=$2 AND e.event_id{after}$3
              AND NOT EXISTS(SELECT 1 FROM session_delivery_receipts d WHERE d.registration_id=$1
                             AND d.event_id=e.event_id AND d.kind IN ('target','observation'))
            ORDER BY e.event_id LIMIT 250""",
            (),
            False,
        ),
        (
            """SELECT e.id,e.body FROM events e JOIN agent_sessions s ON s.id=e.session_id AND s.tenant_id=e.tenant_id
            WHERE s.registration_id=$1 AND e.tenant_id=$2 AND e.id{after}$3
              AND NOT EXISTS(SELECT 1 FROM session_delivery_receipts d WHERE d.registration_id=$1
                             AND d.event_id=e.id AND d.kind IN ('target','observation'))
              AND NOT EXISTS(SELECT 1 FROM inline_guardrail_events g WHERE g.registration_id=$1 AND g.event_id=e.id)
            ORDER BY e.id LIMIT 250""",
            (),
            False,
        ),
        (
            """SELECT i.source_id AS id,i.body FROM session_snapshot_items i JOIN session_snapshots s ON s.id=i.snapshot_id
            WHERE s.registration_id=$1 AND s.tenant_id=$2 AND i.source_id{after}$3 AND i.snapshot_id=$4
              AND i.kind='observation'
              AND NOT EXISTS(SELECT 1 FROM session_delivery_receipts d WHERE d.registration_id=$1
                             AND d.event_id=i.source_id AND d.kind IN ('target','observation'))
              AND NOT EXISTS(SELECT 1 FROM inline_guardrail_events g WHERE g.registration_id=$1 AND g.event_id=i.source_id)
              AND NOT EXISTS(SELECT 1 FROM events e JOIN agent_sessions a ON a.id=e.session_id
                             WHERE e.id=i.source_id AND a.registration_id=$1 AND e.tenant_id=$2)
            ORDER BY i.source_id LIMIT 250""",
            (previous_snapshot,),
            True,
        ),
    )
    for query, args, sanitized in sources:
        for row in _rows(st, query, registration, conn, *args):
            yield row.get("event_id", row["id"]), row["body"], sanitized


def _content_gaps(st, registration, previous_snapshot, conn):
    gaps = set()

    def inspect(body, sanitized=False):
        if not isinstance(body, dict):
            gaps.add("unknown_evidence")
            return
        safe = body if sanitized else _capture(body)
        evidence = safe.get("evidence")
        if validate_evidence(evidence):
            gaps.add(
                "legacy_evidence" if "evidence" not in body else "unknown_evidence"
            )
        else:
            gaps.update(evidence["gaps"])

    for _, body, sanitized in _observations(st, registration, previous_snapshot, conn):
        inspect(body, sanitized)
    # Context remains context, and contributes no independent score or event.
    for row in _rows(
        st,
        """SELECT id,captured_context FROM inline_guardrail_events
            WHERE registration_id=$1 AND tenant_id=$2 AND id{after}$3 ORDER BY id LIMIT 250""",
        registration,
        conn,
    ):
        context = row["captured_context"]
        gaps.update(context.get("gaps", []))
        for name in ("latest_prompt", "matched_tool_call"):
            if context.get(name) is not None:
                inspect(context[name])
        for body in context.get("prior_events", []):
            inspect(body)
    return gaps


def _aggregate(st, registration, now, conn, action_threshold=70):
    return st.one(
        """WITH targets AS (
               SELECT logical_id FROM inline_guardrail_events WHERE registration_id=$1 AND tenant_id=$2
               UNION SELECT logical_id FROM session_delivery_receipts WHERE registration_id=$1 AND tenant_id=$2 AND kind='target'
           ), measured AS (
               SELECT t.logical_id,e.id,e.status,e.deadline_at,
                      CASE WHEN e.status='scored' AND jsonb_typeof(e.assessment->'score')='number'
                           THEN CASE WHEN (e.assessment->>'score')::numeric BETWEEN 0 AND 100
                                     THEN (e.assessment->>'score')::numeric END END AS score,
                      EXISTS(SELECT 1 FROM inline_guardrail_checks c WHERE c.guardrail_event_id=e.id AND c.decision->>'action'='block') AS blocked,
                      EXISTS(SELECT 1 FROM guardrail_approvals a WHERE a.guardrail_event_id=e.id
                             AND a.status='pending' AND a.expires_at>$3) AS approval_pending,
                      EXISTS(SELECT 1 FROM guardrail_approvals a WHERE a.guardrail_event_id=e.id
                             AND a.status='approved' AND a.approved_until>$3
                             AND NOT EXISTS(SELECT 1 FROM guardrail_releases r WHERE r.guardrail_event_id=e.id)) AS approved_unconsumed,
                      r.outcome AS release_outcome,r.id AS release_id,r.outcome_audit_id,
                      reported.captured_body->>'outcome' AS reported_outcome,
                      reported.payload->>'outcome_audit_id' AS reported_audit_id
               FROM targets t LEFT JOIN inline_guardrail_events e
                 ON e.registration_id=$1 AND e.tenant_id=$2 AND e.logical_id=t.logical_id
               LEFT JOIN guardrail_releases r ON r.guardrail_event_id=e.id
               LEFT JOIN LATERAL (
                   SELECT d.captured_body,d.payload FROM session_delivery_receipts d
                   WHERE d.registration_id=$1 AND d.tenant_id=$2 AND d.kind='outcome' AND d.logical_id=t.logical_id
                   ORDER BY d.sequence DESC LIMIT 1
               ) reported ON true
           ), effective AS (
               SELECT *,CASE WHEN release_id IS NULL THEN reported_outcome
                             WHEN outcome_audit_id::text=reported_audit_id THEN release_outcome END AS outcome
               FROM measured
           ) SELECT count(*) AS logical_targets,count(score) AS assessed,sum(score) AS risk_total,max(score) AS risk_max,
                    count(*) FILTER(WHERE score>=$4) AS high_actions,
                    md5(COALESCE(string_agg(logical_id||':'||score::text,',' ORDER BY logical_id) FILTER(WHERE score>=$4),'')) AS selection_signature,
                    count(*) FILTER(WHERE status='unavailable' OR (status='pending' AND deadline_at<=$3)) AS unavailable,
                    count(*) FILTER(WHERE status='pending' AND deadline_at>$3) AS pending,
                    count(*) FILTER(WHERE id IS NULL) AS missing_assessments,
                    count(*) FILTER(WHERE status='scored' AND score IS NULL) AS invalid_assessments,
                    count(*) FILTER(WHERE blocked) AS blocked,
                    count(*) FILTER(WHERE approval_pending) AS pending_approvals,
                    count(*) FILTER(WHERE approved_unconsumed) AS approved_unconsumed,
                    count(*) FILTER(WHERE outcome IS NULL) AS unreported_outcomes,
                    count(*) FILTER(WHERE outcome='uncertain') AS uncertain_outcomes
             FROM effective""",
        registration["id"],
        registration["tenant_id"],
        now,
        action_threshold,
        conn=conn,
    )


def _latest_close(st, registration, conn):
    rows = st.many(
        """SELECT * FROM (
                SELECT DISTINCT ON (payload-'record_id') * FROM session_delivery_receipts
                WHERE registration_id=$1 AND tenant_id=$2 AND kind='close'
                ORDER BY payload-'record_id',received_at,id
            ) controls ORDER BY (payload->>'final_sequence')::bigint DESC,received_at DESC,id DESC LIMIT 1""",
        registration["id"],
        registration["tenant_id"],
        conn=conn,
    )
    return rows[0] if rows else None


def _state(st, registration, conn, *, previous=None, settings=None, scan_content=False):
    now = st.scalar("SELECT clock_timestamp()", conn=conn)
    if previous is None:
        rows = st.many(
            "SELECT * FROM session_finalizations WHERE registration_id=$1 AND tenant_id=$2",
            registration["id"],
            registration["tenant_id"],
            conn=conn,
        )
        previous = rows[0] if rows else {}
    settings = settings or get_settings(st, registration["tenant_id"], conn)
    dirty = st.scalar(
        "SELECT EXISTS(SELECT 1 FROM session_input_dirty WHERE registration_id=$1)",
        registration["id"],
        conn=conn,
    )
    closing = _latest_close(st, registration, conn)
    watermark = closing["payload"]["final_sequence"] if closing else None
    receipt = st.one(
        """SELECT count(*) AS received,min(sequence) AS first,max(sequence) AS last,
                               max(received_at) AS last_received
                        FROM session_delivery_receipts WHERE registration_id=$1 AND tenant_id=$2 AND kind<>'close'""",
        registration["id"],
        registration["tenant_id"],
        conn=conn,
    )
    last_activity = st.scalar(
        """SELECT max(activity) FROM (
                  SELECT max(received_at) AS activity FROM events WHERE tenant_id=$2 AND session_id=$3
                  UNION ALL SELECT max(created_at) FROM inline_guardrail_events WHERE registration_id=$1 AND tenant_id=$2
                  UNION ALL SELECT max(received_at) FROM session_delivery_receipts WHERE registration_id=$1 AND tenant_id=$2 AND kind<>'close'
                  UNION ALL SELECT $4::timestamptz
              ) activity""",
        registration["id"],
        registration["tenant_id"],
        registration.get("session_id"),
        previous.get("last_activity_at") or registration["verified_at"],
        conn=conn,
    )
    declared_gaps = {
        row["gap"]
        for row in st.many(
            """SELECT DISTINCT g.gap FROM session_delivery_receipts d
                    CROSS JOIN LATERAL jsonb_array_elements_text((d.payload->'gaps') ||
                        CASE WHEN d.kind='close' AND d.payload->>'reason'='journal_lost'
                             THEN '["journal_lost"]'::jsonb ELSE '[]'::jsonb END) g(gap)
                    WHERE d.registration_id=$1 AND d.tenant_id=$2""",
            registration["id"],
            registration["tenant_id"],
            conn=conn,
        )
    }
    counts = _aggregate(st, registration, now, conn, settings["action_risk_threshold"])
    risk_total, risk_max = counts.pop("risk_total"), counts.pop("risk_max")
    signature, high_actions = counts.pop("selection_signature"), counts.pop("high_actions")
    counts["observations"] = st.scalar(
        """SELECT count(*) FROM (
                  SELECT e.id FROM events e JOIN agent_sessions s ON s.id=e.session_id AND s.tenant_id=e.tenant_id
                    WHERE e.tenant_id=$2 AND s.registration_id=$1
                  UNION SELECT event_id FROM inline_guardrail_events WHERE registration_id=$1 AND tenant_id=$2
                  UNION SELECT event_id FROM session_delivery_receipts WHERE registration_id=$1 AND tenant_id=$2 AND kind IN ('target','observation')
                  UNION SELECT source_id FROM session_snapshot_items WHERE snapshot_id=$3 AND kind='observation'
              ) observations""",
        registration["id"],
        registration["tenant_id"],
        previous.get("snapshot_id"),
        conn=conn,
    )
    if scan_content:
        content = _content_gaps(st, registration, previous.get("snapshot_id"), conn)
    else:
        content = set(
            previous.get("status", {})
            .get("coverage", {})
            .get("content", {})
            .get("reasons", [])
        )
        if dirty or not previous.get("status"):
            content.add("unfinalized_evidence")
    content.update(declared_gaps & EVIDENCE_GAPS)
    delivery = set(declared_gaps)
    dense = (
        watermark is not None
        and receipt["received"] == watermark
        and (watermark == 0 or receipt["first"] == 1 and receipt["last"] == watermark)
    )
    if registration["delivery_protocol"] != 1:
        delivery.add("unknown_delivery_protocol")
    if watermark is None:
        delivery.add("missing_watermark")
    elif not dense:
        delivery.add(
            "missing_receipts"
            if (receipt["last"] or 0) <= watermark
            else "records_after_close"
        )
    missing_targets = st.scalar(
        """SELECT count(*) FROM inline_guardrail_events e WHERE e.registration_id=$1 AND e.tenant_id=$2
                   AND NOT EXISTS(SELECT 1 FROM session_delivery_receipts d WHERE d.registration_id=e.registration_id
                                  AND d.logical_id=e.logical_id AND d.kind='target')""",
        registration["id"],
        registration["tenant_id"],
        conn=conn,
    )
    if missing_targets:
        delivery.add("missing_target_receipts")
    if closing and set(closing["payload"]["boundaries"]) != BOUNDARIES:
        delivery.add("unsupported_boundary")
    assessment = {
        name
        for name in (
            "unavailable",
            "pending",
            "missing_assessments",
            "invalid_assessments",
        )
        if counts[name]
    }
    execution = {
        name
        for name in (
            "pending_approvals",
            "approved_unconsumed",
            "unreported_outcomes",
            "uncertain_outcomes",
        )
        if counts[name]
    }
    if "backend_unavailable" in declared_gaps:
        execution.add("backend_unavailable")
    coverage = {}
    for name, reasons in (
        ("delivery", delivery),
        ("content", content),
        ("assessment", assessment),
        ("execution", execution),
    ):
        coverage[name] = {
            "status": "incomplete" if reasons else "complete",
            "reasons": sorted(reasons),
        }
    if registration["delivery_protocol"] is None:
        coverage["delivery"]["status"] = "unknown"
    unknown_content = {"unknown_evidence", "legacy_evidence", "unfinalized_evidence"}
    if content & unknown_content:
        coverage["content"]["status"] = (
            "unknown" if content <= unknown_content else "incomplete"
        )
    coverage["gaps"] = sorted(delivery | content | assessment | execution)
    coverage["scope"] = "declared_managed_records"
    coverage["status"] = "incomplete" if coverage["gaps"] else "complete"
    if registration["delivery_protocol"] is None:
        coverage["status"] = "unknown"
    next_times = []
    waiting = counts["pending_approvals"] or counts["pending"]
    for row in st.many(
        """SELECT deadline_at AS deadline FROM inline_guardrail_events WHERE registration_id=$1 AND tenant_id=$2 AND status='pending' AND deadline_at>$3
                    UNION ALL SELECT expires_at FROM guardrail_approvals WHERE registration_id=$1 AND tenant_id=$2 AND status='pending' AND expires_at>$3
                    UNION ALL SELECT approved_until FROM guardrail_approvals WHERE registration_id=$1 AND tenant_id=$2 AND status='approved' AND approved_until>$3
                      AND NOT EXISTS(SELECT 1 FROM guardrail_releases r WHERE r.guardrail_event_id=guardrail_approvals.guardrail_event_id)""",
        registration["id"],
        registration["tenant_id"],
        now,
        conn=conn,
    ):
        next_times.append(row["deadline"])
    resumed = closing and (receipt["last"] or 0) > watermark
    lifecycle = "active"
    if closing and not resumed:
        lifecycle = "closing"
        if not waiting and coverage["status"] == "complete":
            lifecycle = "closed"
        elif not waiting and settings["delivery_grace_seconds"] is not None:
            deadline = closing["received_at"] + timedelta(
                seconds=settings["delivery_grace_seconds"]
            )
            if now >= deadline:
                lifecycle = "incomplete"
            else:
                next_times.append(deadline)
    elif not waiting and settings["idle_seconds"] is not None:
        deadline = last_activity + timedelta(seconds=settings["idle_seconds"])
        if now >= deadline:
            lifecycle = "incomplete"
        else:
            next_times.append(deadline)
    current = bool(
        previous.get("snapshot_id")
        and previous.get("status", {}).get("snapshot_current")
        and not previous.get("failure_code")
        and lifecycle in ("closed", "incomplete")
        and not dirty
        and previous.get("lifecycle") == lifecycle
        and previous.get("status", {}).get("counts") == counts
        and (
            previous.get("next_evaluation_at") is None
            or previous["next_evaluation_at"] > now
        )
    )
    routing = previous.get("status", {}).get(
        "routing",
        {
            "status": "disabled",
            "reason": "tenant_disabled",
            "job_id": None,
            "settings_version": settings["version"],
            "detector_config_version": settings["detector_config_version"],
        },
    )
    if routing.get("job_id"):
        jobs = st.many(
            "SELECT state FROM session_investigation_jobs WHERE id=$1 AND tenant_id=$2 AND registration_id=$3",
            routing["job_id"],
            registration["tenant_id"],
            registration["id"],
            conn=conn,
        )
        if jobs:
            routing = {**routing, "status": jobs[0]["state"]}
    return {
        "registration_id": registration["id"],
        "protocol": registration["delivery_protocol"],
        "epoch_id": registration["delivery_epoch"],
        "lifecycle": lifecycle,
        "last_sequence": receipt["last"] or 0,
        "closing_sequence": watermark,
        "closing_at": closing["received_at"] if closing else None,
        "last_activity_at": last_activity,
        "next_evaluation_at": min(next_times) if next_times else None,
        "delivery": {
            "received": receipt["received"],
            "expected": watermark,
            "complete": not delivery,
            "gaps": sorted(delivery),
        },
        "counts": counts,
        "risk_total": str(risk_total) if risk_total is not None else None,
        "risk_max": str(risk_max) if risk_max is not None else None,
        "selection_signature": signature,
        "high_risk_actions": high_actions,
        "coverage": coverage,
        "revision": previous.get("revision", 0),
        "snapshot_id": previous.get("snapshot_id"),
        "snapshot_current": current,
        "finalization_error": previous.get("failure_code") or None,
        "routing": routing,
    }


def status(st, sensor, registration_id):
    with st.transaction() as conn:
        return _state(st, _authorize(st, sensor, registration_id, conn), conn)


def _owner_registration(st, tenant_id, user_id, registration_id, conn):
    row = st.one(
        """SELECT sensor_id FROM session_registrations WHERE tenant_id=$1 AND owner_user_id=$2
                    AND id=$3 AND verified_at IS NOT NULL""",
        tenant_id,
        user_id,
        _uuid(registration_id),
        conn=conn,
    )
    return _authorize(
        st,
        {"tenant_id": tenant_id, "id": row["sensor_id"]},
        registration_id,
        conn,
        owner_user_id=user_id,
    )


def owner_status(st, tenant_id, user_id, registration_id):
    with st.transaction() as conn:
        return _state(
            st, _owner_registration(st, tenant_id, user_id, registration_id, conn), conn
        )


def owner_session_status(st, tenant_id, user_id, session_id):
    with st.transaction() as conn:
        registration_id = st.scalar(
            """SELECT r.id FROM agent_sessions s JOIN session_registrations r
                    ON r.id=s.registration_id AND r.tenant_id=s.tenant_id
                    WHERE s.tenant_id=$1 AND s.id=$2 AND r.owner_user_id=$3 AND r.verified_at IS NOT NULL""",
            tenant_id,
            _uuid(session_id),
            user_id,
            conn=conn,
        )
        return _state(
            st, _owner_registration(st, tenant_id, user_id, registration_id, conn), conn
        )


def _snapshot_sources(st, registration, previous_snapshot, conn):
    for ident, body, sanitized in _observations(
        st, registration, previous_snapshot, conn
    ):
        yield "observation", ident, body if sanitized else _capture(body)
    for kind, table in (
        ("assessment", "inline_guardrail_events"),
        ("check", "inline_guardrail_checks"),
        ("approval", "guardrail_approvals"),
        ("release", "guardrail_releases"),
        ("delivery", "session_delivery_receipts"),
    ):
        # Table names are internal constants, never caller input. Snapshot the
        # full permitted evidence, but never copy a live execution fence.
        query = f"""SELECT id,to_jsonb(s)-'claim_token'-'payload_sha256' AS body FROM {table} s
                    WHERE registration_id=$1 AND tenant_id=$2 AND id{{after}}$3 ORDER BY id LIMIT 250"""
        for row in _rows(st, query, registration, conn):
            if kind == "delivery":
                # Receiver validation permits only typed metadata and already
                # sanitized captured bodies. Keep that exact acknowledged copy.
                yield kind, row["id"], row["body"]
                continue
            safe = redact_value(row["body"])
            if kind == "assessment":
                safe["target_body"] = _capture(row["body"]["target_body"])
                context = row["body"]["captured_context"]
                safe["captured_context"] = {
                    **redact_value(context),
                    "prior_events": [
                        _capture(body) for body in context.get("prior_events", [])
                    ],
                    **{
                        key: _capture(context[key]) if context.get(key) else None
                        for key in ("latest_prompt", "matched_tool_call")
                    },
                }
            yield kind, row["id"], safe
    for row in _rows(
        st,
        """SELECT a.id,to_jsonb(a) AS body FROM audit_log a
                    JOIN guardrail_releases r ON r.id::text=a.target_id AND r.tenant_id=a.tenant_id
                    WHERE r.registration_id=$1 AND a.tenant_id=$2 AND a.id{after}$3 AND a.action='guardrail.release.outcome'
                    ORDER BY a.id LIMIT 250""",
        registration,
        conn,
    ):
        yield "outcome", row["id"], redact_value(row["body"])


def _copy_snapshot(st, registration, previous_snapshot, snapshot_id, conn):
    batch, size, position, count = [], 2, 0, 0

    def flush():
        nonlocal position, count, batch, size
        if not batch:
            return
        count += st.execute(
            """INSERT INTO session_snapshot_items(snapshot_id,ordinal,kind,source_id,body)
                    SELECT $1,$2+n,item->>'kind',(item->>'source_id')::uuid,item->'body'
                    FROM jsonb_array_elements($3::jsonb) WITH ORDINALITY AS input(item,n)
                    ON CONFLICT(snapshot_id,kind,source_id) DO NOTHING""",
            snapshot_id,
            position,
            Jsonb(batch, dumps=_json),
            conn=conn,
        )
        position += len(batch)
        batch, size = [], 2

    for kind, ident, body in _snapshot_sources(
        st, registration, previous_snapshot, conn
    ):
        item = {"kind": kind, "source_id": ident, "body": body}
        item_size = len(_json(item))
        if batch and size + item_size + 1 > _PAGE_BYTES:
            flush()
        size += item_size + bool(batch)
        batch.append(item)
        if len(batch) >= 100 or size >= _PAGE_BYTES:
            flush()
    flush()
    st.execute(
        "UPDATE session_snapshots SET item_count=$2,sealed_at=clock_timestamp() WHERE id=$1",
        snapshot_id,
        count,
        conn=conn,
    )


def _check_job_protocol(protocol_version):
    require(type(protocol_version) is int and protocol_version in (1, 4), "invalid investigation job protocol")
    if protocol_version == 4:
        from .investigation_submissions import _contracts

        _contracts()


def _job_settings(st, tenant_id, conn, protocol_version):
    if protocol_version == 4:
        from .investigation_settings import read

        return read(st, tenant_id, conn)
    return get_settings(st, tenant_id, conn)


def _jobs_allowed(st, tenant_id, conn, protocol_version=1):
    return st.scalar("SELECT job_protocol_version FROM tenant_session_detection_settings WHERE tenant_id=$1 FOR SHARE",
                     tenant_id, conn=conn) == protocol_version


def _route(
    st,
    registration,
    state,
    settings,
    conn,
    *,
    scheduling_enabled,
    worker_ready,
    supported_models=None,
    protocol_version=1,
):
    routing = {
        "status": "disabled",
        "reason": "tenant_disabled",
        "job_id": None,
        "settings_version": settings["version"],
        "detector_config_version": settings["detector_config_version"],
    }
    reason = None
    if not settings["enabled"]:
        return routing
    if (
        state["lifecycle"] not in ("closed", "incomplete")
        or not state["snapshot_current"]
    ):
        return {**routing, "status": "waiting_coverage", "reason": "session_active"}
    if settings["selection_policy"] == "risk_budget":
        from . import detection_selection

        # Selection must see this managed close before the final routing status
        # is stored. Both updates commit with the snapshot in one transaction.
        st.execute("UPDATE session_finalizations SET lifecycle=$2,status=$3 WHERE registration_id=$1",
                   registration["id"], state["lifecycle"], Jsonb(_stored(state)), conn=conn)
        selected = detection_selection.select(st, registration["tenant_id"], registration["session_id"], settings, conn)
        if detection_selection.reviewed(st, registration["tenant_id"], registration["session_id"], state["selection_signature"], settings, conn):
            selected["reason"] = None
            selected["reviewed_evidence"] = True
        state["selection"] = selected
        reason = selected["reason"]
        if reason is None:
            # Changed evidence/settings provide their own wakeup. An expired
            # history window or completed inspection must not pin retention.
            finished = selected.get("reviewed_evidence") or selected["signals"].get("outside_history_window")
            state["next_evaluation_at"] = None if finished else st.scalar("SELECT now()+interval '60 seconds'", conn=conn)
            return {**routing, "status": "below_threshold", "reason": "outside_selection_budget"}
    elif state["lifecycle"] == "closed" and state["coverage"]["status"] == "complete":
        if state["risk_total"] is not None and Decimal(state["risk_total"]) > Decimal(
            settings["risk_threshold"]
        ):
            reason = "risk_threshold"
        else:
            return {
                **routing,
                "status": "below_threshold",
                "reason": "threshold_not_exceeded",
            }
    elif settings["gap_policy"] == "investigate":
        closed_at = state["closing_at"]
        if closed_at is None:
            closed_at = state["last_activity_at"] + timedelta(
                seconds=settings["idle_seconds"]
            )
        deadline = closed_at + timedelta(seconds=settings["gap_wait_seconds"])
        if st.scalar("SELECT clock_timestamp()", conn=conn) >= deadline:
            reason = "persistent_gap"
        else:
            state["next_evaluation_at"] = min(
                value
                for value in (state["next_evaluation_at"], deadline)
                if value is not None
            )
    if reason is None:
        return {
            **routing,
            "status": "waiting_coverage",
            "reason": "coverage_incomplete",
        }
    if not scheduling_enabled:
        return {**routing, "reason": "scheduling_disabled"}
    if not _jobs_allowed(st, registration["tenant_id"], conn, protocol_version) or not worker_ready or (
        protocol_version == 1 and supported_models is not None and settings["model"] not in supported_models
    ):
        return {**routing, "status": "waiting_worker", "reason": "worker_unavailable"}
    row = st.one(
        """INSERT INTO session_investigation_jobs(id,tenant_id,sensor_id,registration_id,owner_user_id,
                       snapshot_id,detector_config_version,settings_version,configuration,routing_reason,protocol_version)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                ON CONFLICT(snapshot_id,detector_config_version) DO UPDATE SET id=session_investigation_jobs.id
                RETURNING id,state,routing_reason,protocol_version""",
        new_id(),
        registration["tenant_id"],
        registration["sensor_id"],
        registration["id"],
        registration["owner_user_id"],
        state["snapshot_id"],
        settings["detector_config_version"],
        settings["version"],
        Jsonb(_stored(settings)),
        reason,
        protocol_version,
        conn=conn,
    )
    require(row["protocol_version"] == protocol_version, "retained investigation contract conflict", 409)
    return {
        **routing,
        "status": row["state"],
        "reason": row["routing_reason"],
        "job_id": row["id"],
    }


_MATERIAL_STATE = (
    "lifecycle",
    "closing_sequence",
    "last_sequence",
    "delivery",
    "counts",
    "risk_total",
    "risk_max",
    "selection_signature",
    "coverage",
)


class _FinalizationLimit(Exception):
    pass


class _FinalizationStore:
    """Share one total deadline across SQL, Python redaction and copy pages."""

    def __init__(self, st, deadline):
        self.st, self.deadline = st, deadline
        self._benchmark_all_sessions = getattr(st, "_benchmark_all_sessions", False)

    def check(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise _FinalizationLimit
        return remaining

    def __getattr__(self, name):
        if name not in ("one", "many", "scalar", "execute"):
            raise AttributeError(name)

        def run(query, *args, conn):
            remaining = self.check()
            conn.execute(
                "SELECT set_config('statement_timeout',%s,true)",
                (str(max(1, math.ceil(remaining * 1000))),),
            )
            result = getattr(self.st, name)(query, *args, conn=conn)
            if time.monotonic() >= self.deadline:
                raise _FinalizationLimit
            return result

        return run


def _finalize(
    st,
    registration_id,
    *,
    scheduling_enabled,
    worker_ready,
    deadline,
    supported_models=None,
    protocol_version=1,
):
    with st.transaction() as conn:
        st.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ", conn=conn)
        st = _FinalizationStore(st, deadline)
        scope = st.one(
            "SELECT tenant_id,sensor_id FROM session_registrations WHERE id=$1",
            registration_id,
            conn=conn,
        )
        registration = _authorize(
            st,
            {"tenant_id": scope["tenant_id"], "id": scope["sensor_id"]},
            registration_id,
            conn,
            snapshot=True,
        )
        st.execute(
            "INSERT INTO session_finalizations(registration_id,tenant_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
            registration_id,
            registration["tenant_id"],
            conn=conn,
        )
        previous = st.one(
            "SELECT * FROM session_finalizations WHERE registration_id=$1 FOR UPDATE",
            registration_id,
            conn=conn,
        )
        settings = _job_settings(st, registration["tenant_id"], conn, protocol_version)
        state = _state(st, registration, conn, previous=previous, settings=settings)
        from . import detection_selection

        detection_selection.record(st, registration["tenant_id"], registration["session_id"], settings,
                                   state["risk_max"], state["high_risk_actions"], state["selection_signature"], conn)
        urgent = bool(settings["enabled"] and settings["selection_policy"] == "risk_budget"
                      and state["risk_max"] is not None
                      and Decimal(state["risk_max"]) >= settings["urgent_risk_threshold"])
        closing_candidate = (
            state["closing_sequence"] is not None
            and state["last_sequence"] <= state["closing_sequence"]
            and not state["counts"]["pending_approvals"]
            and not state["counts"]["pending"]
        )
        if closing_candidate or state["lifecycle"] == "incomplete":
            state = _state(
                st,
                registration,
                conn,
                previous=previous,
                settings=settings,
                scan_content=True,
            )
        if urgent and state["lifecycle"] not in ("closed", "incomplete"):
            state["lifecycle"] = "incomplete"
            state["coverage"]["status"] = "incomplete"
            state["coverage"]["active_session"] = True
        state["finalization_error"] = None
        # REPEATABLE READ deletes only rows visible to this snapshot. An older
        # identity committed later survives, unlike a MAX(id) watermark.
        dirty = st.execute(
            "DELETE FROM session_input_dirty WHERE registration_id=$1",
            registration_id,
            conn=conn,
        )
        changed = any(
            previous["status"].get(key) != _stored(state[key])
            for key in _MATERIAL_STATE
        )
        input_version = previous["input_version"] + int(bool(dirty or changed))
        snapshot_version = st.scalar(
            "SELECT COALESCE((SELECT input_version FROM session_snapshots WHERE id=$1),0)",
            previous["snapshot_id"],
            conn=conn,
        )
        finalizable = state["lifecycle"] in ("closed", "incomplete")
        if finalizable and (
            not previous["snapshot_id"] or input_version != snapshot_version
        ):
            snapshot_id = new_id()
            revision = previous["revision"] + 1
            st.execute(
                """INSERT INTO session_snapshots(id,tenant_id,sensor_id,registration_id,owner_user_id,revision,input_version,
                         epoch_id,closing_sequence,lifecycle,coverage,counts,risk_total,risk_max,selection_signature)
                    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)""",
                snapshot_id,
                registration["tenant_id"],
                registration["sensor_id"],
                registration_id,
                registration["owner_user_id"],
                revision,
                max(1, input_version),
                registration["delivery_epoch"],
                state["closing_sequence"],
                state["lifecycle"],
                Jsonb(state["coverage"]),
                Jsonb(state["counts"]),
                Decimal(state["risk_total"])
                if state["risk_total"] is not None
                else None,
                Decimal(state["risk_max"]) if state["risk_max"] is not None else None,
                state["selection_signature"],
                conn=conn,
            )
            _copy_snapshot(st, registration, previous["snapshot_id"], snapshot_id, conn)
            state.update(snapshot_id=snapshot_id, revision=revision)
            snapshot_version = input_version
        state["snapshot_current"] = bool(
            finalizable and state["snapshot_id"] and input_version == snapshot_version
        )
        if dirty or changed:
            st.execute(
                """UPDATE session_investigation_jobs SET state='superseded',completed_at=clock_timestamp()
                         WHERE registration_id=$1 AND state='queued' AND ($2::uuid IS NULL OR snapshot_id<>$2 OR NOT $3)""",
                registration_id,
                state["snapshot_id"],
                state["snapshot_current"],
                conn=conn,
            )
        state["routing"] = _route(
            st,
            registration,
            state,
            settings,
            conn,
            scheduling_enabled=scheduling_enabled,
            worker_ready=worker_ready,
            supported_models=supported_models,
            protocol_version=protocol_version,
        )
        st.execute(
            """UPDATE session_finalizations SET input_version=$2,revision=$3,snapshot_id=$4,lifecycle=$5,
                     last_activity_at=$6,next_evaluation_at=$7,closing_sequence=$8,status=$9,settings_version=$10,
                     failure_code='',updated_at=clock_timestamp()
                     WHERE registration_id=$1""",
            registration_id,
            input_version,
            state["revision"],
            state["snapshot_id"],
            state["lifecycle"],
            state["last_activity_at"],
            state["next_evaluation_at"],
            state["closing_sequence"],
            Jsonb(_stored(state)),
            settings["version"],
            conn=conn,
        )
        return state


def _finalization_failure(st, registration_id):
    # Failure reporting must not wait behind the lock that exhausted the copy
    # deadline. Dirty rows were rolled back and remain authoritative either way.
    result = {
        "registration_id": registration_id,
        "snapshot_current": False,
        "finalization_error": "finalization_timeout",
    }
    try:
        with st.transaction() as conn:
            st.execute("SET LOCAL statement_timeout='1s'", conn=conn)
            rows = st.many(
                """INSERT INTO session_finalizations(registration_id,tenant_id,failure_code,next_evaluation_at)
                         SELECT id,tenant_id,'finalization_timeout',clock_timestamp()+interval '5 seconds'
                         FROM session_registrations WHERE id=$1
                         ON CONFLICT(registration_id) DO UPDATE SET failure_code='finalization_timeout',
                             next_evaluation_at=clock_timestamp()+interval '5 seconds',updated_at=clock_timestamp()
                         RETURNING status""",
                registration_id,
                conn=conn,
            )
            if rows:
                result = {**rows[0]["status"], **result}
    except QueryCanceled:
        pass
    return result


def finalize_one(
    st,
    registration_id,
    *,
    scheduling_enabled=False,
    worker_ready=False,
    max_seconds=15,
    supported_models=None,
    protocol_version=1,
):
    _check_job_protocol(protocol_version)
    registration_id = _uuid(registration_id)
    require(
        type(max_seconds) in (int, float)
        and math.isfinite(max_seconds)
        and max_seconds > 0,
        "invalid finalization limit",
    )
    deadline = time.monotonic() + max_seconds
    for attempt in range(3):
        try:
            return _finalize(
                st,
                registration_id,
                scheduling_enabled=scheduling_enabled,
                worker_ready=worker_ready,
                supported_models=supported_models,
                protocol_version=protocol_version,
                deadline=deadline,
            )
        except (_FinalizationLimit, QueryCanceled):
            return _finalization_failure(st, registration_id)
        except SerializationFailure:
            if attempt == 2:
                raise


def finalize_pending(
    st,
    tenant_id=None,
    limit=10,
    *,
    scheduling_enabled=False,
    worker_ready=False,
    max_seconds=15,
    supported_models=None,
    protocol_version=1,
):
    _check_job_protocol(protocol_version)
    rows = st.many(
        """SELECT r.id FROM session_registrations r
                   JOIN tenants t ON t.id=r.tenant_id AND t.status='active'
                   JOIN sensors s ON s.id=r.sensor_id AND s.tenant_id=r.tenant_id AND NOT s.disabled AND s.deleted_at IS NULL
                   JOIN tenant_users u ON u.id=r.owner_user_id AND u.tenant_id=r.tenant_id AND u.status='active'
                   LEFT JOIN session_finalizations f ON f.registration_id=r.id
                   LEFT JOIN tenant_session_detection_settings g ON g.tenant_id=r.tenant_id
                   WHERE ($1::uuid IS NULL OR r.tenant_id=$1) AND r.assessment_mode='inline' AND r.verified_at IS NOT NULL
                     AND (f.failure_code IS NULL OR f.failure_code='' OR f.next_evaluation_at<=clock_timestamp())
                     AND (EXISTS(SELECT 1 FROM session_input_dirty d WHERE d.registration_id=r.id)
                          OR f.next_evaluation_at<=clock_timestamp() OR COALESCE(f.settings_version,0)<>COALESCE(g.version,0)
                          OR ($3 AND $4 AND g.enabled AND g.job_protocol_version=$6
                              AND ($6=4 OR $5::text[] IS NULL OR g.model=ANY($5))
                              AND f.status->'routing'->>'status' IN ('disabled','waiting_worker')))
                   ORDER BY COALESCE(f.updated_at,r.created_at),r.id LIMIT $2""",
        tenant_id,
        max(1, min(int(limit), 100)),
        scheduling_enabled,
        worker_ready,
        list(supported_models) if supported_models is not None else None,
        protocol_version,
    )
    worked = 0
    for row in rows:
        try:
            result = finalize_one(
                st,
                row["id"],
                scheduling_enabled=scheduling_enabled,
                worker_ready=worker_ready,
                max_seconds=max_seconds,
                supported_models=supported_models,
                protocol_version=protocol_version,
            )
            worked += not bool(result.get("finalization_error"))
        except (NotFound, APIError) as exc:
            if isinstance(exc, APIError) and exc.status not in (403, 404):
                raise
            # Revocation between selection and authorization is not work.
    return worked


def read_snapshot(st, tenant_id, user_id, snapshot_id, limit=100, cursor=""):
    snapshot_id = _uuid(snapshot_id, "snapshot id")
    require(type(limit) is int and 1 <= limit <= 500, "invalid snapshot page limit")
    after = 0
    if cursor:
        try:
            require(
                isinstance(cursor, str) and len(cursor) <= 256,
                "invalid snapshot cursor",
            )
            parts = json.loads(
                base64.b64decode(
                    cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True
                )
            )
            require(
                isinstance(parts, list)
                and len(parts) == 2
                and parts[0] == snapshot_id
                and type(parts[1]) is int
                and 0 <= parts[1] < 1 << 63,
                "invalid snapshot cursor",
            )
            after = parts[1]
        except (ValueError, TypeError, UnicodeError):
            raise APIError(400, "invalid snapshot cursor") from None
    with st.transaction() as conn:
        snapshot = st.one(
            """SELECT * FROM session_snapshots WHERE tenant_id=$1 AND owner_user_id=$2 AND id=$3
                          AND sealed_at IS NOT NULL""",
            tenant_id,
            user_id,
            snapshot_id,
            conn=conn,
        )
        _owner_registration(st, tenant_id, user_id, snapshot["registration_id"], conn)
        page = """SELECT i.ordinal,i.kind,i.source_id,i.body FROM session_snapshot_items i
                         JOIN session_snapshots s ON s.id=i.snapshot_id
                         WHERE i.snapshot_id=$1 AND s.tenant_id=$2 AND s.owner_user_id=$3 AND i.ordinal>$4
                         ORDER BY i.ordinal LIMIT $5"""
        args = (snapshot_id, tenant_id, user_id, after, limit + 1)
        metadata = st.many(
            f"SELECT p.ordinal AS id,octet_length(to_jsonb(p)::text) AS byte_size FROM ({page}) p ORDER BY p.ordinal",
            *args,
            conn=conn,
        )
        keys = next(_page_groups(metadata[:limit]), [])
        rows = (
            st.many(
                f"SELECT p.* FROM ({page}) p WHERE p.ordinal=ANY($6::bigint[]) ORDER BY p.ordinal",
                *args,
                keys,
                conn=conn,
            )
            if keys
            else []
        )
        more = len(metadata) > len(rows)
        next_cursor = (
            base64.urlsafe_b64encode(_json([snapshot_id, rows[-1]["ordinal"]]))
            .decode()
            .rstrip("=")
            if more
            else ""
        )
        for name in ("risk_total", "risk_max"):
            if snapshot[name] is not None:
                snapshot[name] = str(snapshot[name])
        from .customer_views import snapshot_item

        return {"snapshot": snapshot, "items": [snapshot_item(item) for item in rows], "next_cursor": next_cursor}


def _job_authority(st, job, conn):
    if job.get("session_id"):
        from .ordinary_session_detection import authorize

        return authorize(st, job, conn)
    registration = _authorize(
        st,
        {"tenant_id": job["tenant_id"], "id": job["sensor_id"]},
        job["registration_id"],
        conn,
    )
    require(
        registration["owner_user_id"] == job["owner_user_id"],
        "job owner is unavailable",
        403,
    )
    return registration


def _job_current(st, job, settings, conn):
    if job.get("session_id"):
        from .ordinary_session_detection import current

        return current(st, job, settings, conn)
    return bool(
        settings["enabled"]
        and job["detector_config_version"] == settings["detector_config_version"]
        and st.scalar(
            """SELECT EXISTS(SELECT 1 FROM session_finalizations f JOIN session_snapshots s ON s.id=f.snapshot_id
               WHERE f.registration_id=$1 AND f.tenant_id=$2 AND f.snapshot_id=$3 AND f.input_version=s.input_version
                 AND f.lifecycle IN ('closed','incomplete') AND f.failure_code=''
                 AND (f.next_evaluation_at IS NULL OR f.next_evaluation_at>clock_timestamp())
                 AND NOT EXISTS(SELECT 1 FROM session_input_dirty d WHERE d.registration_id=f.registration_id))""",
            job["registration_id"],
            job["tenant_id"],
            job["snapshot_id"],
            conn=conn,
        )
    )


def _locked_settings(st, tenant_id, conn):
    # Settings updates never take registration or job locks. Taking SHARE here
    # before the job lock makes a disable or budget change commit either before
    # validation or after the durable claim/dispatch intent.
    st.many(
        "SELECT tenant_id FROM tenant_session_detection_settings WHERE tenant_id=$1 FOR SHARE",
        tenant_id,
        conn=conn,
    )
    return get_settings(st, tenant_id, conn)


def _threshold_matches(st, job, settings, conn):
    if job["routing_reason"] == "sample":
        return False
    if settings["selection_policy"] == "risk_budget":
        from . import detection_selection

        session_id = job.get("session_id") or st.scalar(
            "SELECT id FROM agent_sessions WHERE tenant_id=$1 AND registration_id=$2",
            job["tenant_id"], job["registration_id"], conn=conn,
        )
        reason = detection_selection.select(st, job["tenant_id"], session_id, settings, conn)["reason"]
        return bool(reason and (job["routing_reason"] != "urgent_risk" or reason == "urgent_risk"))
    snapshot = st.one(
        "SELECT lifecycle,coverage,risk_total FROM session_snapshots WHERE id=$1 AND tenant_id=$2",
        job["snapshot_id"],
        job["tenant_id"],
        conn=conn,
    )
    if job.get("session_id"):
        return snapshot["risk_total"] is not None and snapshot["risk_total"] > Decimal(settings["risk_threshold"])
    if (
        snapshot["lifecycle"] == "closed"
        and snapshot["coverage"]["status"] == "complete"
    ):
        return snapshot["risk_total"] is not None and snapshot["risk_total"] > Decimal(
            settings["risk_threshold"]
        )
    if settings["gap_policy"] != "investigate":
        return False
    # Use the same explicit-close or idle-close anchor as routing and candidate
    # selection. Copying a snapshot never restarts a session's gap wait.
    return st.scalar(
        """SELECT clock_timestamp()>=COALESCE((status->>'closing_at')::timestamptz,
                      last_activity_at+$3*interval '1 second')+$4*interval '1 second'
           FROM session_finalizations WHERE registration_id=$1 AND tenant_id=$2""",
        job["registration_id"],
        job["tenant_id"],
        settings["idle_seconds"],
        settings["gap_wait_seconds"],
        conn=conn,
    )


def _claim(st, candidate, worker_id):
    with st.transaction() as conn:
        # All claimants take the tenant admission lock before any sensor or job
        # lock. No ingestion/finalization path ever takes this budget lock.
        st.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "session-investigation-budget:" + candidate["tenant_id"],
            conn=conn,
        )
        _job_authority(st, candidate, conn)
        settings = _locked_settings(st, candidate["tenant_id"], conn)
        if not _jobs_allowed(st, candidate["tenant_id"], conn):
            return None
        job = st.one(
            "SELECT * FROM session_investigation_jobs WHERE id=$1 AND tenant_id=$2 FOR UPDATE",
            candidate["id"],
            candidate["tenant_id"],
            conn=conn,
        )
        now = st.scalar("SELECT clock_timestamp()", conn=conn)
        if (
            job["protocol_version"] == 4
            or job["state"] != "queued"
            or job["next_attempt_at"] > now
            or not _job_current(st, job, settings, conn)
        ):
            return None
        if (
            not _threshold_matches(st, job, settings, conn)
            or job["attempts"] >= settings["max_attempts"]
        ):
            if settings["selection_policy"] == "risk_budget":
                st.execute("UPDATE session_investigation_jobs SET next_attempt_at=clock_timestamp()+interval '60 seconds' WHERE id=$1",
                           job["id"], conn=conn)
            return None
        if settings["selection_policy"] == "risk_budget":
            from . import detection_selection

            if not detection_selection.admit(st, job, settings, conn):
                st.execute("UPDATE session_investigation_jobs SET next_attempt_at=clock_timestamp()+interval '60 seconds' WHERE id=$1",
                           job["id"], conn=conn)
                return None
        window = st.scalar(
            "SELECT date_trunc('hour',$1::timestamptz AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'",
            now,
            conn=conn,
        )
        usage = st.one(
            """SELECT count(*) AS attempts,COALESCE(sum(reserved_tokens),0) AS tokens,
                              COALESCE(sum(reserved_cost_usd),0) AS cost
                       FROM session_investigation_attempts WHERE tenant_id=$1 AND window_start=$2 AND state<>'released'""",
            job["tenant_id"],
            window,
            conn=conn,
        )
        config = job["configuration"]
        tokens, cost = (
            config["max_tokens_per_attempt"],
            Decimal(config["max_cost_usd_per_attempt"]),
        )
        if (
            usage["attempts"] >= settings["hourly_attempts"]
            or usage["tokens"] + tokens > settings["hourly_tokens"]
            or usage["cost"] + cost > Decimal(settings["hourly_cost_usd"])
        ):
            st.execute(
                "UPDATE session_investigation_jobs SET next_attempt_at=$2::timestamptz+interval '1 hour' WHERE id=$1",
                job["id"],
                window,
                conn=conn,
            )
            return None
        running = st.scalar(
            "SELECT count(*) FROM session_investigation_jobs WHERE tenant_id=$1 AND state='running' AND lease_deadline>$2",
            job["tenant_id"],
            now,
            conn=conn,
        )
        if running >= settings["max_concurrent"]:
            return None
        if job.get("owner_user_id") and st.scalar(
            """SELECT EXISTS(SELECT 1 FROM session_investigation_jobs WHERE tenant_id=$1
               AND owner_user_id=$2 AND state='running' AND lease_deadline>$3)""",
            job["tenant_id"], job["owner_user_id"], now, conn=conn,
        ):
            return None
        attempt_id, token = new_id(), new_id()
        deadline = now + timedelta(seconds=config["max_runtime_seconds"])
        st.execute(
            """INSERT INTO session_investigation_attempts(id,job_id,tenant_id,ordinal,claim_token,worker_id,state,
                       reserved_tokens,reserved_cost_usd,window_start,deadline_at)
                    VALUES($1,$2,$3,$4,$5,$6,'reserved',$7,$8,$9,$10)""",
            attempt_id,
            job["id"],
            job["tenant_id"],
            job["attempts"] + 1,
            token,
            worker_id,
            tokens,
            cost,
            window,
            deadline,
            conn=conn,
        )
        st.execute(
            """UPDATE session_investigation_jobs SET state='running',attempts=attempts+1,claim_token=$2,
                       lease_deadline=$3,result=NULL,completed_at=NULL WHERE id=$1""",
            job["id"],
            token,
            deadline,
            conn=conn,
        )
        return {
            "job_id": job["id"],
            "tenant_id": job["tenant_id"],
            "attempt_id": attempt_id,
            "claim_token": token,
            "deadline_at": deadline,
            "snapshot_id": job["snapshot_id"],
            "configuration": config,
        }


def claim_job(
    st, worker_id, tenant_id=None, *, worker_ready=False, supported_models=None,
):
    if not worker_ready:
        return None
    require(
        isinstance(worker_id, str)
        and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", worker_id),
        "invalid worker id",
    )
    expire_claims(st, tenant_id)
    candidates = st.many(
        """SELECT j.* FROM session_investigation_jobs j
                    LEFT JOIN session_registrations r ON r.id=j.registration_id AND r.tenant_id=j.tenant_id AND r.owner_user_id=j.owner_user_id
                    JOIN tenants t ON t.id=j.tenant_id AND t.status='active'
                    JOIN sensors s ON s.id=j.sensor_id AND s.tenant_id=j.tenant_id AND NOT s.disabled AND s.deleted_at IS NULL
                    LEFT JOIN tenant_users u ON u.id=j.owner_user_id AND u.tenant_id=j.tenant_id AND u.status='active'
                    JOIN tenant_session_detection_settings g ON g.tenant_id=j.tenant_id AND g.enabled AND g.job_protocol_version=1
                    LEFT JOIN session_finalizations f ON f.registration_id=j.registration_id AND f.tenant_id=j.tenant_id
                    LEFT JOIN ordinary_session_detection d ON d.session_id=j.session_id AND d.tenant_id=j.tenant_id
                    JOIN session_snapshots snap ON snap.id=j.snapshot_id AND snap.tenant_id=j.tenant_id
                    WHERE ($1::uuid IS NULL OR j.tenant_id=$1) AND j.state='queued' AND j.protocol_version IN (1,3)
                      AND j.next_attempt_at<=clock_timestamp()
                      AND j.routing_reason<>'sample'
                      AND ($2::text[] IS NULL OR j.configuration->>'model'=ANY($2))
                      AND j.detector_config_version=g.detector_config_version AND j.attempts<g.max_attempts
                      AND (SELECT count(*) FROM session_investigation_jobs busy
                           WHERE busy.tenant_id=j.tenant_id AND busy.state='running'
                             AND busy.lease_deadline>clock_timestamp())<g.max_concurrent
                      AND (j.owner_user_id IS NULL OR NOT EXISTS(
                           SELECT 1 FROM session_investigation_jobs busy
                           WHERE busy.tenant_id=j.tenant_id AND busy.owner_user_id=j.owner_user_id
                             AND busy.state='running' AND busy.lease_deadline>clock_timestamp()))
                      AND ((j.session_id IS NOT NULL AND snap.session_id=j.session_id
                            AND d.snapshot_id=j.snapshot_id AND d.input_version=snap.input_version
                            AND d.settings_version=g.version AND d.state->>'lifecycle'='incomplete'
                            AND (g.selection_policy='risk_budget' OR snap.risk_total>g.risk_threshold)
                            AND NOT EXISTS(SELECT 1 FROM ordinary_session_input_dirty i
                                           WHERE i.tenant_id=j.tenant_id AND i.session_id=j.session_id))
                      OR (r.verified_at IS NOT NULL AND u.id IS NOT NULL
                      AND f.snapshot_id=j.snapshot_id AND f.input_version=snap.input_version
                      AND f.lifecycle IN ('closed','incomplete') AND f.failure_code=''
                      AND (f.next_evaluation_at IS NULL OR f.next_evaluation_at>clock_timestamp())
                      AND NOT EXISTS(SELECT 1 FROM session_input_dirty d WHERE d.registration_id=j.registration_id)
                      AND (g.selection_policy='risk_budget' OR (snap.lifecycle='closed' AND snap.coverage->>'status'='complete' AND snap.risk_total>g.risk_threshold)
                           OR (snap.lifecycle='incomplete' AND g.gap_policy='investigate'
                               AND COALESCE((f.status->>'closing_at')::timestamptz,
                                   f.last_activity_at+g.idle_seconds*interval '1 second')+g.gap_wait_seconds*interval '1 second'<=clock_timestamp()))))
                    ORDER BY j.next_attempt_at,j.id LIMIT 100""",
        tenant_id,
        list(supported_models) if supported_models is not None else None,
    )
    for candidate in candidates:
        try:
            claimed = _claim(st, candidate, worker_id)
        except (NotFound, APIError) as exc:
            if isinstance(exc, APIError) and exc.status not in (403, 404):
                raise
            continue
        if claimed:
            return claimed
    return None


def _attempt(st, job_id, claim_token, attempt_id, conn):
    rows = st.many(
        """SELECT * FROM session_investigation_attempts WHERE id=$1 AND job_id=$2 AND claim_token=$3 FOR UPDATE""",
        attempt_id,
        job_id,
        claim_token,
        conn=conn,
    )
    return rows[0] if rows else None


def _expired(st, job, attempt, conn, now):
    if job.get("protocol_version") == 4 and st.scalar(
        "SELECT EXISTS(SELECT 1 FROM session_investigation_submissions WHERE attempt_id=$1 AND tenant_id=$2)",
        attempt["id"], job["tenant_id"], conn=conn,
    ):
        return False  # Accepted or ambiguous complete jobs require status/receipt reconciliation.
    if (
        job["state"] != "running"
        or job["claim_token"] != attempt["claim_token"]
        or now < min(job["lease_deadline"], attempt["deadline_at"])
    ):
        return False
    dispatched = attempt["dispatched_at"] is not None
    _uncertain_requests(st, attempt["id"], conn, now)
    retry = not dispatched and job["routing_reason"] != "sample" and job["attempts"] < job["configuration"]["max_attempts"]
    from .session_investigator import terminal_report

    report = terminal_report(st, job, attempt, "dispatch_uncertain" if dispatched else "attempts_exhausted", conn)
    st.execute(
        """UPDATE session_investigation_attempts SET state=$2,completed_at=$3,report=$4 WHERE id=$1""",
        attempt["id"],
        "uncertain" if dispatched else "released",
        now,
        Jsonb(report),
        conn=conn,
    )
    st.execute(
        """UPDATE session_investigation_jobs SET state=$2,claim_token=NULL,lease_deadline=NULL,
                    next_attempt_at=$3::timestamptz+$4*interval '1 second',completed_at=$5,result=$6 WHERE id=$1""",
        job["id"],
        "queued" if retry else "inconclusive",
        now,
        job["configuration"]["retry_delay_seconds"],
        None if retry else now,
        None
        if retry
        else Jsonb(
            {"reason": "dispatch_uncertain" if dispatched else "attempts_exhausted"}
        ),
        conn=conn,
    )
    return True


def _uncertain_requests(st, attempt_id, conn, now):
    """A persisted dispatch intent is never safe to replay after its lease ends."""
    st.execute(
        """UPDATE model_usage u SET status='error',completed_at=COALESCE(u.completed_at,$2)
           FROM session_investigation_requests r
           WHERE r.attempt_id=$1 AND r.state='dispatched' AND u.id=r.usage_id""",
        attempt_id,
        now,
        conn=conn,
    )
    st.execute(
        """UPDATE session_investigation_requests SET state='uncertain',completed_at=$2,
           error_code='claim_expired' WHERE attempt_id=$1 AND state='dispatched'""",
        attempt_id,
        now,
        conn=conn,
    )
    st.execute(
        """WITH totals AS (
               SELECT count(*) AS calls,
                 CASE WHEN count(u.input_tokens+u.output_tokens)=count(*) THEN sum(u.input_tokens+u.output_tokens) END AS tokens,
                 CASE WHEN count(u.cost_usd)=count(*) THEN sum(u.cost_usd) END AS cost
               FROM session_investigation_requests r JOIN model_usage u ON u.id=r.usage_id WHERE r.attempt_id=$1
           ) UPDATE session_investigation_attempts a SET actual_tokens=COALESCE(a.actual_tokens,totals.tokens),
               actual_cost_usd=COALESCE(a.actual_cost_usd,totals.cost) FROM totals WHERE a.id=$1 AND totals.calls>0""",
        attempt_id,
        conn=conn,
    )


def expire_claims(st, tenant_id=None, limit=100):
    with st.transaction() as conn:
        jobs = st.many(
            """SELECT j.* FROM session_investigation_jobs j
                        WHERE ($1::uuid IS NULL OR j.tenant_id=$1) AND j.state='running'
                          AND NOT (j.protocol_version=4 AND EXISTS(
                              SELECT 1 FROM session_investigation_submissions b
                              JOIN session_investigation_attempts a ON a.id=b.attempt_id
                              WHERE a.job_id=j.id AND a.claim_token=j.claim_token AND b.tenant_id=j.tenant_id))
                          AND (j.lease_deadline<=clock_timestamp() OR EXISTS(
                              SELECT 1 FROM session_investigation_attempts a WHERE a.job_id=j.id
                              AND a.claim_token=j.claim_token AND a.deadline_at<=clock_timestamp()))
                        ORDER BY j.lease_deadline,j.id LIMIT $2 FOR UPDATE OF j SKIP LOCKED""",
            tenant_id,
            max(1, min(int(limit), 500)),
            conn=conn,
        )
        count = 0
        for job in jobs:
            attempt = st.one(
                "SELECT * FROM session_investigation_attempts WHERE job_id=$1 AND claim_token=$2 FOR UPDATE",
                job["id"],
                job["claim_token"],
                conn=conn,
            )
            count += _expired(
                st, job, attempt, conn, st.scalar("SELECT clock_timestamp()", conn=conn)
            )
        return count


def mark_dispatched(st, job_id, claim_token, attempt_id):
    job_id, claim_token, attempt_id = (
        _uuid(job_id),
        _uuid(claim_token),
        _uuid(attempt_id),
    )
    with st.transaction() as conn:
        rows = st.many(
            "SELECT * FROM session_investigation_jobs WHERE id=$1", job_id, conn=conn
        )
        if not rows:
            return False
        try:
            _job_authority(st, rows[0], conn)
        except (NotFound, APIError):
            return False
        settings = _locked_settings(st, rows[0]["tenant_id"], conn)
        job = st.one(
            "SELECT * FROM session_investigation_jobs WHERE id=$1 FOR UPDATE",
            job_id,
            conn=conn,
        )
        attempt = _attempt(st, job_id, claim_token, attempt_id, conn)
        if not attempt:
            return False
        now = st.scalar("SELECT clock_timestamp()", conn=conn)
        if _expired(st, job, attempt, conn, now):
            return False
        if (
            job["state"] != "running"
            or job["claim_token"] != claim_token
            or attempt["state"] != "reserved"
        ):
            return False
        if not _job_current(st, job, settings, conn) or not _threshold_matches(
            st, job, settings, conn
        ):
            return False
        return _dispatch_attempt(st, attempt, conn, now)


def _dispatch_attempt(st, attempt, conn, now):
    """Caller holds the authorized job/attempt fence in this transaction."""
    return bool(
        st.execute(
            "UPDATE session_investigation_attempts SET state='dispatched',dispatched_at=$2 WHERE id=$1 AND state='reserved'",
            attempt["id"],
            now,
            conn=conn,
        )
    )


def _result(outcome, result):
    require(outcome in ("completed", "inconclusive", "failed"), "invalid job outcome")
    _body(result, ("summary", "finding_ids", "actual_tokens", "actual_cost_usd"))
    require(len(_json(result)) <= 16 << 10, "job result is too large", 413)
    require(
        "summary" not in result
        or isinstance(result["summary"], str)
        and len(result["summary"]) <= 4000,
        "invalid job summary",
    )
    result = dict(result)
    if "finding_ids" in result:
        require(
            isinstance(result["finding_ids"], list)
            and len(result["finding_ids"]) <= 100,
            "invalid finding_ids",
        )
        result["finding_ids"] = [
            _uuid(value, "finding id") for value in result["finding_ids"]
        ]
    value = result.get("actual_tokens")
    require(
        value is None or type(value) is int and 0 <= value < 1 << 63,
        "invalid actual_tokens",
    )
    if result.get("actual_cost_usd") is not None:
        result["actual_cost_usd"] = str(
            _decimal(result["actual_cost_usd"], "actual_cost_usd")
        )
    safe = redact_value(result)
    # These bounded values are measured usage, not credential-bearing fields.
    for key in ("actual_tokens", "actual_cost_usd", "finding_ids"):
        if key in result:
            safe[key] = result[key]
    return safe


def finish_job(st, job_id, claim_token, attempt_id, outcome, result):
    result = _result(outcome, result)
    job_id, claim_token, attempt_id = (
        _uuid(job_id),
        _uuid(claim_token),
        _uuid(attempt_id),
    )
    with st.transaction() as conn:
        rows = st.many(
            "SELECT * FROM session_investigation_jobs WHERE id=$1", job_id, conn=conn
        )
        if not rows or rows[0].get("protocol_version") == 4:
            return False
        authorized = True
        try:
            _job_authority(st, rows[0], conn)
        except (NotFound, APIError):
            authorized = False
        job = st.one(
            "SELECT * FROM session_investigation_jobs WHERE id=$1 FOR UPDATE",
            job_id,
            conn=conn,
        )
        attempt = _attempt(st, job_id, claim_token, attempt_id, conn)
        if not attempt:
            return False
        now = st.scalar("SELECT clock_timestamp()", conn=conn)
        # A recorded dispatch may have real late billing even after its fence
        # expires or its owner is revoked. It cannot revive a result or job.
        if attempt["dispatched_at"] is not None:
            tokens = result.get("actual_tokens")
            cost = (
                Decimal(result["actual_cost_usd"])
                if result.get("actual_cost_usd") is not None
                else None
            )
            if (
                attempt["actual_tokens"] is not None
                and tokens is not None
                and attempt["actual_tokens"] != tokens
                or attempt["actual_cost_usd"] is not None
                and cost is not None
                and attempt["actual_cost_usd"] != cost
            ):
                return False
            st.execute(
                """UPDATE session_investigation_attempts SET actual_tokens=COALESCE(actual_tokens,$2),
                        actual_cost_usd=COALESCE(actual_cost_usd,$3) WHERE id=$1""",
                attempt_id,
                tokens,
                cost,
                conn=conn,
            )
        if _expired(st, job, attempt, conn, now):
            return False
        if (
            not authorized
            or job["state"] != "running"
            or job["claim_token"] != claim_token
            or attempt["state"] != "dispatched"
        ):
            return False
        return _complete_attempt(st, job, attempt, outcome, result, conn, now)


def _complete_attempt(st, job, attempt, outcome, result, conn, now):
    """Commit result state beside caller-owned findings under an already checked fence."""
    retry = (
        outcome == "failed" and job["routing_reason"] != "sample"
        and job["attempts"] < job["configuration"]["max_attempts"]
    )
    state = (
        "queued"
        if retry
        else "inconclusive"
        if outcome in ("failed", "inconclusive")
        else "completed"
    )
    report = None
    if state == "inconclusive":
        from .session_investigator import terminal_report

        report = terminal_report(st, job, attempt, "incomplete_coverage", conn)
    st.execute(
        """UPDATE session_investigation_attempts SET state=$2,completed_at=$3,result=$4,report=COALESCE(report,$5) WHERE id=$1""",
        attempt["id"],
        "failed" if outcome == "failed" else "completed",
        now,
        Jsonb(result),
        Jsonb(report) if report else None,
        conn=conn,
    )
    st.execute(
        """UPDATE session_investigation_jobs SET state=$2,result=$3,completed_at=$4,claim_token=NULL,lease_deadline=NULL,
                   next_attempt_at=$5::timestamptz+$6*interval '1 second' WHERE id=$1""",
        job["id"],
        state,
        None if retry else Jsonb(result),
        None if retry else now,
        now,
        job["configuration"]["retry_delay_seconds"],
        conn=conn,
    )
    return True
