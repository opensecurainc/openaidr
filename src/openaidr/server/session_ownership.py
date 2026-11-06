"""User-confirmed session registration and owner-scoped session reads."""

import json
import re
import uuid

from psycopg.types.json import Jsonb

from . import _sql as sql
from .httpx import require
from .store import Conflict, NotFound, hash_token, new_id, new_token


PRODUCTS = ("codex-cli", "claude-code")
REGISTRATION_SECONDS = 600
TOKEN_PREFIX = "oasr_"
TOKEN_PATTERN = re.compile(r"oasr_[A-Za-z0-9_-]{43}")


class RegistrationRejected(Exception):
    """A permanent event rejection that does not invalidate other batch items."""


def _registration_id(value):
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        require(False, "invalid registration id")


def _external_id(value):
    require(
        isinstance(value, str) and 1 <= len(value) <= 256
        and all(ord(char) >= 32 and ord(char) != 127 for char in value),
        "external_id must be a nonempty string of at most 256 characters",
    )
    return value


def lock_sensor_sessions(st, sensor, conn):
    # Binding and ingestion can touch different native scopes but shared
    # registration or agent rows. Take this lock before their other locks.
    st.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
        "sensor-ingest:" + json.dumps(
            [sensor["tenant_id"], sensor["id"]], separators=(",", ":")
        ),
        conn=conn,
    )


def _active_sensor(st, sensor, conn):
    st.one(
        """SELECT s.id FROM sensors s JOIN tenants t ON t.id=s.tenant_id
           WHERE s.tenant_id=$1 AND s.id=$2 AND NOT s.disabled
             AND s.deleted_at IS NULL AND t.status='active' FOR SHARE OF t,s""",
        sensor["tenant_id"], sensor["id"], conn=conn,
    )


def _scope_lock(st, sensor, product, external_id, conn):
    scope = json.dumps(
        [sensor["tenant_id"], sensor["id"], product, external_id], separators=(",", ":")
    )
    st.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
        "session-registration:" + scope, conn=conn,
    )


def _load(st, sensor, registration_id, conn, *, lock=False, reference=False):
    row = st.one(
        """SELECT r.*,s.id AS session_id,s.agent_id,a.username AS agent_username,
                  COALESCE(g.version,0) AS settings_version,COALESCE(p.version,0) AS policy_version,
                  COALESCE(g.context_required,false) AS context_required,
                  COALESCE(g.context_failure_action,'ask') AS context_failure_action
           FROM session_registrations r
           LEFT JOIN agent_sessions s ON s.tenant_id=r.tenant_id AND s.registration_id=r.id
           LEFT JOIN agents a ON a.tenant_id=s.tenant_id AND a.id=s.agent_id
           LEFT JOIN tenant_guardrail_settings g ON g.tenant_id=r.tenant_id
           LEFT JOIN policies p ON p.tenant_id=r.tenant_id
           WHERE r.tenant_id=$1 AND r.sensor_id=$2 AND r.id=$3"""
        + (" FOR KEY SHARE OF r" if reference else " FOR NO KEY UPDATE OF r" if lock else ""),
        sensor["tenant_id"], sensor["id"], registration_id, conn=conn,
    )
    # Read authorization and time again after any registration row-lock wait.
    row.update(st.one(
        """SELECT clock_timestamp() AS checked_at,
                  EXISTS(SELECT 1 FROM tenant_users WHERE tenant_id=$1
                         AND id=$2 AND status='active') AS owner_active""",
        row["tenant_id"], row["owner_user_id"], conn=conn,
    ))
    return row


def authorize_inline(st, sensor, registration_id, conn, owner_user_id=None, *, snapshot=False):
    """Lock verified inline ownership before writes that retain the owner FK."""
    if not snapshot:
        lock_sensor_sessions(st, sensor, conn)
    _active_sensor(st, sensor, conn)
    row = _load(st, sensor, registration_id, conn)
    require(row["assessment_mode"] == "inline", "session does not use inline guardrails", 403)
    if owner_user_id is not None and row["owner_user_id"] != owner_user_id:
        raise NotFound("session owner is unavailable")
    require(
        row["verified_at"] and row["owner_user_id"] and row["owner_active"],
        "session owner is unavailable", 403,
    )
    # User deletion locks the owner before clearing registration and action FKs.
    # SHARE also makes a concurrent disable linearize before or after this work.
    users = st.many(
        """SELECT id FROM tenant_users WHERE tenant_id=$1 AND id=$2
           AND status='active' FOR SHARE""",
        sensor["tenant_id"], row["owner_user_id"], conn=conn,
    )
    require(users, "session owner is unavailable", 403)
    # Snapshot copies hold only immutable binding references. NO KEY UPDATE
    # writers still serialize with one another and can proceed beside readers.
    row = _load(st, sensor, registration_id, conn, lock=not snapshot, reference=snapshot)
    require(
        row["owner_user_id"] == users[0]["id"] and row["owner_active"],
        "session owner is unavailable", 403,
    )
    return row


def _view(row):
    state = (
        ("verified" if row["owner_active"] else "unavailable")
        if row["verified_at"] else "expired"
        if row["expires_at"] <= row["checked_at"] else "pending"
        if row["external_id"] is not None else "reserved"
    )
    result = {
        "id": row["id"], "product": row["product"], "status": state,
        "expires_at": row["expires_at"],
        "assessment_mode": row["assessment_mode"],
        "delivery_protocol": row["delivery_protocol"], "delivery_epoch": row["delivery_epoch"],
        "settings_version": row["settings_version"], "policy_version": row["policy_version"],
        "context_policy": {
            "version": row["settings_version"], "required": row["context_required"],
            "failure_action": row["context_failure_action"],
        },
        "context_version": 1,
    }
    for key in ("external_id", "session_id"):
        if row.get(key) is not None:
            result[key] = row[key]
    return result


def _bind_loaded(st, sensor, row, external_id, conn):
    if row["external_id"] is not None and row["external_id"] != external_id:
        raise Conflict("registration is already bound to another session")
    if row["verified_at"]:
        if not row["owner_active"]:
            raise NotFound("session owner is unavailable")
        return
    if row["expires_at"] <= row["checked_at"]:
        raise NotFound("registration expired")
    if row["external_id"] is not None:
        return
    if st.scalar(
        """SELECT EXISTS(
            SELECT 1 FROM agent_sessions WHERE tenant_id=$1 AND sensor_id=$2
              AND product=$3 AND external_id=$4 AND registration_id IS DISTINCT FROM $5
            UNION ALL
            SELECT 1 FROM session_registrations WHERE tenant_id=$1 AND sensor_id=$2
              AND product=$3 AND external_id=$4 AND id<>$5
        )""",
        sensor["tenant_id"], sensor["id"], row["product"], external_id, row["id"], conn=conn,
    ):
        raise Conflict("session already exists without this registration")
    st.one(
        """UPDATE session_registrations SET external_id=$4
           WHERE tenant_id=$1 AND sensor_id=$2 AND id=$3 AND verified_at IS NULL
             AND expires_at>clock_timestamp() RETURNING id""",
        sensor["tenant_id"], sensor["id"], row["id"], external_id, conn=conn,
    )
    row["external_id"] = external_id


def reserve(
    st,
    sensor,
    product,
    *,
    assessment_mode="legacy",
    inline_enabled=False,
    delivery_protocol=None,
    delivery_epoch=None,
):
    require(product in PRODUCTS, "product must be codex-cli or claude-code")
    require(assessment_mode in ("legacy", "inline"), "invalid assessment_mode")
    require(
        (delivery_protocol is None) == (delivery_epoch is None),
        "delivery protocol and epoch are required together",
    )
    if delivery_protocol is not None:
        require(
            type(delivery_protocol) is int
            and delivery_protocol == 1
            and assessment_mode == "inline",
            "unsupported delivery protocol",
        )
        delivery_epoch = _registration_id(delivery_epoch)
    with st.transaction() as conn:
        _active_sensor(st, sensor, conn)
        if assessment_mode == "inline":
            from .guardrail.inline import get_settings

            settings = get_settings(st, sensor["tenant_id"], conn=conn)
            require(
                inline_enabled and settings["enabled"],
                "inline guardrails are disabled",
                409,
            )
        registration_id = new_id()
        st.execute(
            """INSERT INTO session_registrations(id,tenant_id,sensor_id,product,expires_at,assessment_mode,delivery_protocol,delivery_epoch)
               VALUES($1,$2,$3,$4,clock_timestamp()+$5*interval '1 second',$6,$7,$8)""",
            registration_id,
            sensor["tenant_id"],
            sensor["id"],
            product,
            REGISTRATION_SECONDS,
            assessment_mode,
            delivery_protocol,
            delivery_epoch,
            conn=conn,
        )
        return _view(_load(st, sensor, registration_id, conn))


def bind(st, sensor, registration_id, external_id):
    registration_id, external_id = _registration_id(registration_id), _external_id(external_id)
    with st.transaction() as conn:
        lock_sensor_sessions(st, sensor, conn)
        _active_sensor(st, sensor, conn)
        initial = _load(st, sensor, registration_id, conn)
        _scope_lock(st, sensor, initial["product"], external_id, conn)
        row = _load(st, sensor, registration_id, conn, lock=True)
        _bind_loaded(st, sensor, row, external_id, conn)
        result = _view(row)
        if not row["verified_at"]:
            token, digest = new_token(TOKEN_PREFIX)
            st.one(
                """UPDATE session_registrations SET challenge_hash=$4
                   WHERE tenant_id=$1 AND sensor_id=$2 AND id=$3 AND verified_at IS NULL
                     AND expires_at>clock_timestamp() RETURNING id""",
                sensor["tenant_id"], sensor["id"], row["id"], digest, conn=conn,
            )
            result["confirmation_token"] = token
        return result


def status(st, sensor, registration_id, *, include_policy=False):
    require(type(include_policy) is bool, "invalid include_policy")
    registration_id = _registration_id(registration_id)
    with st.transaction() as conn:
        _active_sensor(st, sensor, conn)
        result = _view(_load(st, sensor, registration_id, conn))
        if include_policy:
            policy = st.get_policy(sensor["tenant_id"], conn=conn)
            result["policy"] = {**policy, "actions": ["allow", "ask", "deny", "warn"]}
            # The opt-in body and version come from the same policy read.
            result["policy_version"] = policy["version"]
        return result


def confirm(st, tenant_id, user_id, token):
    if not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token):
        raise NotFound("registration unavailable")
    with st.transaction() as conn:
        user = st.one(
            """SELECT u.id,u.name FROM tenant_users u JOIN tenants t ON t.id=u.tenant_id
               WHERE u.tenant_id=$1 AND u.id=$2 AND u.status='active'
                 AND t.status='active' FOR SHARE OF t,u""",
            tenant_id, user_id, conn=conn,
        )
        initial = st.one(
            "SELECT id,sensor_id FROM session_registrations WHERE tenant_id=$1 AND challenge_hash=$2",
            tenant_id, hash_token(token), conn=conn,
        )
        sensor = {"tenant_id": tenant_id, "id": initial["sensor_id"]}
        _active_sensor(st, sensor, conn)
        row = _load(st, sensor, initial["id"], conn, lock=True)
        if (
            row["verified_at"] is not None or row["external_id"] is None
            or row["challenge_hash"] != hash_token(token)
            or row["expires_at"] <= row["checked_at"]
        ):
            raise NotFound("registration unavailable")
        st.one(
            """UPDATE session_registrations SET owner_user_id=$4,
                   verified_at=clock_timestamp(),challenge_hash=NULL
               WHERE tenant_id=$1 AND sensor_id=$2 AND id=$3 AND verified_at IS NULL
                 AND challenge_hash=$5 AND expires_at>clock_timestamp() RETURNING id""",
            tenant_id, sensor["id"], row["id"], user_id, hash_token(token), conn=conn,
        )
        st.execute(
            """INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,
                   target_type,target_id,details)
               VALUES($1,$2,'user',$3,$4,'session.register','session_registration',$5,$6)""",
            new_id(), tenant_id, user_id, user["name"], row["id"],
            Jsonb({"sensor_id": sensor["id"], "product": row["product"],
                   "external_id": row["external_id"]}), conn=conn,
        )
        return _view(_load(st, sensor, row["id"], conn))


def validate_event_registration(st, sensor, event, conn):
    session = event.get("session") or {}
    product = (event.get("agent") or {}).get("product", "")
    external_id = session.get("id")
    registration_id = session.get("registration_id")
    _scope_lock(st, sensor, product, external_id, conn)
    if registration_id is None:
        if st.scalar(
            """SELECT EXISTS(SELECT 1 FROM session_registrations
               WHERE tenant_id=$1 AND sensor_id=$2 AND product=$3 AND external_id=$4)""",
            sensor["tenant_id"], sensor["id"], product, external_id, conn=conn,
        ):
            raise RegistrationRejected("session registration is required")
        return None
    try:
        registration_id = str(uuid.UUID(registration_id))
    except (ValueError, TypeError, AttributeError):
        raise RegistrationRejected("invalid session registration") from None
    try:
        _active_sensor(st, sensor, conn)
        row = _load(st, sensor, registration_id, conn, lock=True)
        if row["product"] != product:
            raise RegistrationRejected("session registration does not match this product")
        if not isinstance(external_id, str) or not 1 <= len(external_id) <= 256:
            raise RegistrationRejected("invalid registered session id")
        _bind_loaded(st, sensor, row, external_id, conn)
        return row
    except NotFound:
        raise RegistrationRejected("session registration is unavailable") from None
    except Conflict:
        raise RegistrationRejected("session does not match this registration") from None


def list_sessions(st, tenant_id, user_id, page=None):
    return st._page(
        sql.sessionColumns,
        "agent_sessions s",
        [
            "s.tenant_id=$1",
            """EXISTS(SELECT 1 FROM session_registrations r
                JOIN tenant_users u ON u.tenant_id=r.tenant_id AND u.id=r.owner_user_id
                WHERE r.tenant_id=s.tenant_id AND r.id=s.registration_id
                  AND r.owner_user_id=$2 AND r.verified_at IS NOT NULL AND u.status='active')""",
        ],
        [tenant_id, user_id], page, "s.last_event_at",
    )
