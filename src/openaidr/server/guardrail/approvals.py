"""Owner approvals and one-time action consumption, independent of model workers."""

import uuid

from psycopg.types.json import Jsonb

from .. import customer_views, session_ownership
from ..httpx import APIError, require
from openaidr.core.redact import redact_value
from .findings import CATEGORY_LABELS
from ..store import new_id


_ERRORS = {
    "context_changed": "company context changed; reassessment is required",
    "policy_changed": "guardrail policy changed",
    "policy_floor_changed": "the action requires a stronger policy decision",
    "payload_changed": "request payload changed",
    "approval_pending": "approval is pending",
    "approval_expired": "approval expired",
    "approval_revoked": "approval was revoked",
    "approval_decided": "approval already has a different decision",
    "approvals_disabled": "approvals are disabled",
    "action_rejected": "this action was rejected or revoked by its owner",
    "action_blocked": "this action is blocked",
    "action_already_consumed": "this action was already consumed",
    "outcome_conflict": "a different terminal outcome was already recorded",
}
_SYSTEM = {"type": "system", "id": "guardrail-approvals"}


def _conflict(code):
    return {"error": {"code": code, "message": _ERRORS[code]}}, 409


def _uuid(value, name="id"):
    try:
        return str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError):
        raise APIError(400, "invalid " + name) from None


def _body(payload, allowed, required=()):
    require(
        isinstance(payload, dict)
        and set(payload) <= set(allowed)
        and set(required) <= set(payload),
        "invalid approval request",
    )


def _audit(st, row, action, actor, conn, details=None):
    ident = new_id()
    st.execute(
        """INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,
               target_type,target_id,details) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)""",
        ident,
        row["tenant_id"],
        actor["type"],
        actor["id"],
        actor.get("name", ""),
        action,
        "guardrail_release"
        if action.startswith("guardrail.release.")
        else "guardrail_approval",
        row["id"],
        Jsonb(
            {
                "registration_id": row["registration_id"],
                "guardrail_event_id": row["guardrail_event_id"],
                **{
                    key: row[key]
                    for key in ("generation", "settings_version", "policy_version")
                    if key in row
                },
                **(details or {}),
            }
        ),
        conn=conn,
    )
    return ident


def _current(st, tenant_id, conn):
    settings = st.one(
        "SELECT * FROM tenant_guardrail_settings WHERE tenant_id=$1 FOR SHARE",
        tenant_id,
        conn=conn,
    )
    policy_version = st.scalar(
        "SELECT version FROM policies WHERE tenant_id=$1 FOR SHARE",
        tenant_id,
        conn=conn,
    )
    return settings, policy_version


def _same_versions(row, settings, policy_version):
    return (
        row["settings_version"] == settings["version"]
        and row["policy_version"] == policy_version
    )


def _release(st, event, conn):
    rows = st.many(
        "SELECT * FROM guardrail_releases WHERE tenant_id=$1 AND guardrail_event_id=$2",
        event["tenant_id"],
        event["id"],
        conn=conn,
    )
    return rows[0] if rows else None


def _action_error(st, event, conn):
    if st.scalar(
        """SELECT EXISTS(SELECT 1 FROM guardrail_approvals WHERE tenant_id=$1 AND guardrail_event_id=$2
           AND (status='rejected' OR (status='revoked' AND reason_code='owner_revoked')))""",
        event["tenant_id"],
        event["id"],
        conn=conn,
    ):
        return "action_rejected"
    if _release(st, event, conn):
        return "action_already_consumed"
    return None


def check_action_state(st, event, conn):
    code = _action_error(st, event, conn)
    if code:
        raise APIError(409, _ERRORS[code], code)


def policy_floor(st, check, conn):
    """Strongest requested floor while the caller holds this action's row lock."""
    rank = st.scalar(
        """SELECT COALESCE(max(CASE deterministic_result->>'policy_floor'
               WHEN 'block' THEN 2 WHEN 'ask' THEN 1 ELSE 0 END),0)
           FROM inline_guardrail_checks WHERE tenant_id=$1 AND guardrail_event_id=$2
             AND settings_version=$3 AND policy_version=$4""",
        check["tenant_id"],
        check["guardrail_event_id"],
        check["settings_version"],
        check["policy_version"],
        conn=conn,
    )
    return (None, "ask", "block")[rank]


def policy_floor_error(st, check, conn):
    floor = policy_floor(st, check, conn)
    action = (check.get("decision") or {}).get("action")
    if floor == "block" and action != "block":
        return "action_blocked"
    if floor == "ask" and action == "allow":
        return "policy_floor_changed"
    return None


def _refresh(
    st, approval, settings, policy_version, checked_at, conn, *, consumed=False
):
    if consumed or approval["status"] not in ("pending", "approved"):
        return approval
    reason, status = None, None
    if not _same_versions(approval, settings, policy_version):
        reason, status = "policy_changed", "revoked"
    elif not settings["approvals_enabled"]:
        reason, status = "approvals_disabled", "revoked"
    else:
        from .inline import context_changed

        event = st.one(
            "SELECT * FROM inline_guardrail_events WHERE tenant_id=$1 AND id=$2",
            approval["tenant_id"], approval["guardrail_event_id"], conn=conn,
        )
        if context_changed(st, event, settings, conn, approval):
            reason, status = "context_changed", "revoked"
    if reason is None and (approval["approved_until"] or approval["expires_at"]) <= checked_at:
        reason, status = "approval_expired", "expired"
    if reason:
        approval = st.one(
            """UPDATE guardrail_approvals SET status=$3,reason_code=$4,
                   revoked_at=CASE WHEN $3='revoked' THEN $5 ELSE revoked_at END
               WHERE tenant_id=$1 AND id=$2 RETURNING *""",
            approval["tenant_id"],
            approval["id"],
            status,
            reason,
            checked_at,
            conn=conn,
        )
        _audit(
            st,
            approval,
            "guardrail.approval.expire"
            if status == "expired"
            else "guardrail.approval.revoke",
            _SYSTEM,
            conn,
            {"reason_code": reason},
        )
    return approval


def _summary(approval):
    return {
        "availability": "available",
        "id": approval["id"],
        "generation": approval["generation"],
        "assessment_generation": approval["assessment_generation"],
        "status": approval["status"],
        "reason_code": approval["reason_code"],
        "expires_at": approval["approved_until"] or approval["expires_at"],
        "path": "/approvals/" + approval["id"],
    }


def ensure_for_check(st, check, event, settings, conn):
    """Attach an immutable check alias while its event and owner are locked."""
    check_action_state(st, event, conn)
    current, policy_version = _current(st, check["tenant_id"], conn)
    if not _same_versions(check, current, policy_version):
        raise APIError(409, _ERRORS["policy_changed"], "policy_changed")
    latest = st.many(
        """SELECT * FROM guardrail_approvals WHERE tenant_id=$1 AND guardrail_event_id=$2
           ORDER BY generation DESC LIMIT 1 FOR UPDATE""",
        check["tenant_id"],
        event["id"],
        conn=conn,
    )
    now = st.scalar("SELECT clock_timestamp()", conn=conn)
    previous = (
        _refresh(st, latest[0], current, policy_version, now, conn) if latest else None
    )
    if not check.get("decision") or check["decision"]["action"] != "ask":
        return None
    if check.get("approval_id"):
        row = st.one(
            "SELECT * FROM guardrail_approvals WHERE tenant_id=$1 AND id=$2",
            check["tenant_id"],
            check["approval_id"],
            conn=conn,
        )
        return _summary(row)
    active_generation = st.scalar(
        "SELECT assessment_generation FROM inline_guardrail_events WHERE tenant_id=$1 AND id=$2",
        check["tenant_id"], event["id"], conn=conn,
    )
    if check["assessment_generation"] != active_generation:
        return {"availability": "unavailable", "status": "unavailable", "reason_code": "context_changed"}
    if not current["approvals_enabled"]:
        return {"availability": "disabled", "status": "unavailable"}
    if (
        previous
        and _same_versions(previous, current, policy_version)
        and previous["assessment_generation"] == check["assessment_generation"]
        and (
            previous["status"] in ("pending", "approved")
            or (
                previous["status"] == "expired"
                and check["created_at"]
                <= (previous["approved_until"] or previous["expires_at"])
            )
        )
    ):
        approval = previous
    else:
        approval = st.one(
            """INSERT INTO guardrail_approvals
                   (id,tenant_id,sensor_id,registration_id,owner_user_id,guardrail_event_id,
                    originating_check_id,generation,settings_version,policy_version,status,expires_at,
                    assessment_generation)
               VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending',clock_timestamp()+$11*interval '1 second',$12)
               RETURNING *""",
            new_id(),
            check["tenant_id"],
            check["sensor_id"],
            check["registration_id"],
            check["owner_user_id"],
            event["id"],
            check["id"],
            previous["generation"] + 1 if previous else 1,
            check["settings_version"],
            check["policy_version"],
            current["approval_wait_seconds"],
            check["assessment_generation"],
            conn=conn,
        )
        _audit(
            st,
            approval,
            "guardrail.approval.create",
            {"type": "sensor", "id": check["sensor_id"]},
            conn,
        )
    st.execute(
        "UPDATE inline_guardrail_checks SET approval_id=$3 WHERE tenant_id=$1 AND id=$2 AND approval_id IS NULL",
        check["tenant_id"],
        check["id"],
        approval["id"],
        conn=conn,
    )
    return _summary(approval)


def _lock_event(st, sensor, registration_id, event_id, conn, owner_user_id=None):
    registration = session_ownership.authorize_inline(
        st,
        sensor,
        registration_id,
        conn,
        owner_user_id=owner_user_id,
    )
    event = st.one(
        """SELECT * FROM inline_guardrail_events WHERE tenant_id=$1 AND sensor_id=$2
           AND registration_id=$3 AND id=$4 FOR UPDATE""",
        sensor["tenant_id"],
        sensor["id"],
        registration_id,
        event_id,
        conn=conn,
    )
    require(
        event["owner_user_id"] == registration["owner_user_id"],
        "session owner is unavailable",
        403,
    )
    return event


def _load_approval(st, tenant_id, approval_id, conn, *, user_id=None, sensor=None):
    initial = st.one(
        """SELECT * FROM guardrail_approvals WHERE tenant_id=$1 AND id=$2
           AND ($3::uuid IS NULL OR owner_user_id=$3) AND ($4::uuid IS NULL OR sensor_id=$4)""",
        tenant_id,
        _uuid(approval_id),
        user_id,
        sensor["id"] if sensor else None,
        conn=conn,
    )
    sensor = sensor or {"id": initial["sensor_id"], "tenant_id": tenant_id}
    event = _lock_event(
        st,
        sensor,
        initial["registration_id"],
        initial["guardrail_event_id"],
        conn,
        user_id,
    )
    settings, policy_version = _current(st, tenant_id, conn)
    approval = st.one(
        "SELECT * FROM guardrail_approvals WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
        tenant_id,
        initial["id"],
        conn=conn,
    )
    release = _release(st, event, conn)
    now = st.scalar("SELECT clock_timestamp()", conn=conn)
    approval = _refresh(
        st, approval, settings, policy_version, now, conn, consumed=release is not None
    )
    return approval, event, release, settings, policy_version


def _receipt(release, event, *, granted=False, replayed=False):
    return {
        **{
            key: release[key]
            for key in (
                "id",
                "registration_id",
                "check_id",
                "approval_id",
                "consumed_at",
                "outcome",
                "outcome_at",
                "outcome_details",
                "outcome_audit_id",
            )
        },
        "event_id": event["event_id"],
        "logical_id": event["logical_id"],
        "action_commitment": event["action_commitment"],
        "granted": granted,
        "replayed": replayed,
    }


def _detail(st, approval, event, release, conn):
    from .inline import assessment_for_check

    event = assessment_for_check(st, event, approval, conn)
    tenant = st.one(
        "SELECT id,name,slug FROM tenants WHERE id=$1", approval["tenant_id"], conn=conn
    )
    device = st.one(
        "SELECT id,hostname,label FROM sensors WHERE tenant_id=$1 AND id=$2",
        approval["tenant_id"],
        approval["sensor_id"],
        conn=conn,
    )
    check = st.one(
        "SELECT decision FROM inline_guardrail_checks WHERE tenant_id=$1 AND id=$2",
        approval["tenant_id"],
        approval["originating_check_id"],
        conn=conn,
    )
    target, context = event["target_body"], event["captured_context"]
    withheld = target["kind"] == "response"
    assessment = customer_views.guardrail_assessment(event["assessment"]) or {}
    if withheld:
        # A model explanation or policy message can quote the held response.
        # Return only bounded assessment metadata on this approval boundary.
        assessment = {
            key: assessment.get(key) for key in ("status", "score", "category", "level")
        }
        assessment["status"] = event["status"]
        if not (
            type(assessment["score"]) in (int, float)
            and 0 <= assessment["score"] <= 100
        ):
            assessment["score"] = None
        if assessment["category"] not in (*CATEGORY_LABELS, "none", "unknown"):
            assessment["category"] = "unknown"
        if assessment["level"] not in ("info", "low", "medium", "high", "critical"):
            assessment["level"] = None
    gaps = set(context.get("gaps", [])) | set(event["prepared_state"].get("gaps", []))
    for item in [
        target,
        context.get("latest_prompt"),
        context.get("matched_tool_call"),
        *context.get("prior_events", []),
    ]:
        if item:
            gaps.update(item.get("evidence", {}).get("gaps", []))
    return {
        **{
            key: approval[key]
            for key in (
                "id",
                "generation",
                "status",
                "decision",
                "reason_code",
                "created_at",
                "decided_at",
                "approved_until",
                "registration_id",
                "settings_version",
                "policy_version",
            )
        },
        "expires_at": approval["approved_until"] or approval["expires_at"],
        "check_id": approval["originating_check_id"],
        "event_id": event["event_id"],
        "logical_id": event["logical_id"],
        "tenant": tenant,
        "client": {
            "product": target["agent"]["product"],
            "version": target["agent"].get("version", ""),
        },
        "device": device,
        "boundary": {
            "prompt": "prompt",
            "response": "assistant_response",
            "tool.result": "tool_output",
        }.get(target["kind"], "tool_call"),
        "preview": None
        if withheld
        else redact_value({"target": target, "context": context}),
        "preview_withheld": withheld,
        "assessment": assessment,
        "reason": "The current policy requires approval before displaying this response."
        if withheld
        else check["decision"]["reason"],
        "warnings": [] if withheld else check["decision"].get("warnings", []),
        "gaps": sorted(gaps),
        "release": {
            key: release[key]
            for key in ("id", "consumed_at", "outcome", "outcome_at", "outcome_details")
        }
        if release
        else None,
    }


def owner_get(st, tenant_id, user_id, approval_id):
    with st.transaction() as conn:
        approval, event, release, _, _ = _load_approval(
            st, tenant_id, approval_id, conn, user_id=user_id
        )
        return _detail(st, approval, event, release, conn)


def _state_error(approval, settings, policy_version):
    if not _same_versions(approval, settings, policy_version):
        return "policy_changed"
    if approval["status"] == "expired":
        return "approval_expired"
    if approval["status"] == "revoked":
        return (
            "action_rejected"
            if approval["reason_code"] == "owner_revoked"
            else "context_changed"
            if approval["reason_code"] == "context_changed"
            else "approval_revoked"
        )
    if approval["status"] == "rejected":
        return "action_rejected"
    return None


def owner_decide(st, tenant_id, user_id, approval_id, payload):
    _body(payload, ("decision",), ("decision",))
    require(
        payload["decision"] in ("approve", "reject"),
        "decision must be approve or reject",
    )
    with st.transaction() as conn:
        approval, event, release, settings, policy_version = _load_approval(
            st, tenant_id, approval_id, conn, user_id=user_id
        )
        if release:
            return _conflict("action_already_consumed")
        if approval["status"] in ("approved", "rejected"):
            if approval["decision"] == payload["decision"]:
                return _detail(st, approval, event, release, conn), 200
            return _conflict("approval_decided")
        code = _state_error(approval, settings, policy_version)
        if code:
            return _conflict(code)
        if approval["decision"] is not None:
            return _conflict("approval_decided")
        decision = payload["decision"]
        approval = st.one(
            """UPDATE guardrail_approvals SET decision=$3,status=$4,decided_at=clock_timestamp(),
                   decided_by_user_id=$5,
                   approved_until=CASE WHEN $3='approve' THEN clock_timestamp()+$6*interval '1 second' END
               WHERE tenant_id=$1 AND id=$2 RETURNING *""",
            tenant_id,
            approval["id"],
            decision,
            "approved" if decision == "approve" else "rejected",
            user_id,
            settings["approval_use_seconds"],
            conn=conn,
        )
        _audit(
            st,
            approval,
            "guardrail.approval." + decision,
            {"type": "user", "id": user_id},
            conn,
        )
        return _detail(st, approval, event, release, conn), 200


def owner_revoke(st, tenant_id, user_id, approval_id, payload):
    _body(payload, ())
    with st.transaction() as conn:
        approval, event, release, settings, policy_version = _load_approval(
            st, tenant_id, approval_id, conn, user_id=user_id
        )
        if release:
            return _conflict("action_already_consumed")
        if (
            approval["status"] == "revoked"
            and approval["reason_code"] == "owner_revoked"
        ):
            return _detail(st, approval, event, release, conn), 200
        code = _state_error(approval, settings, policy_version)
        if code:
            return _conflict(code)
        approval = st.one(
            """UPDATE guardrail_approvals SET status='revoked',reason_code='owner_revoked',revoked_at=clock_timestamp()
               WHERE tenant_id=$1 AND id=$2 RETURNING *""",
            tenant_id,
            approval["id"],
            conn=conn,
        )
        _audit(
            st,
            approval,
            "guardrail.approval.revoke",
            {"type": "user", "id": user_id},
            conn,
            {"reason_code": "owner_revoked"},
        )
        return _detail(st, approval, event, release, conn), 200


def sensor_status(st, sensor, approval_id, payload):
    _body(payload, ())
    with st.transaction() as conn:
        approval, event, release, _, _ = _load_approval(
            st, sensor["tenant_id"], approval_id, conn, sensor=sensor
        )
        return {
            **_summary(approval),
            "registration_id": approval["registration_id"],
            "event_id": event["event_id"],
            "logical_id": event["logical_id"],
            "valid": approval["status"] == "approved" and release is None,
            "release": _receipt(release, event) if release else None,
        }


def consume(st, sensor, check_id, payload):
    _body(
        payload,
        ("request_id", "action_commitment"),
        ("request_id", "action_commitment"),
    )
    request_id, check_id = (
        _uuid(payload["request_id"], "request id"),
        _uuid(check_id, "check id"),
    )
    require(
        isinstance(payload["action_commitment"], str)
        and len(payload["action_commitment"]) <= 128,
        "invalid action commitment",
    )
    with st.transaction() as conn:
        check = st.one(
            "SELECT * FROM inline_guardrail_checks WHERE tenant_id=$1 AND sensor_id=$2 AND id=$3",
            sensor["tenant_id"],
            sensor["id"],
            check_id,
            conn=conn,
        )
        event = _lock_event(
            st, sensor, check["registration_id"], check["guardrail_event_id"], conn
        )
        check = st.one(
            "SELECT * FROM inline_guardrail_checks WHERE tenant_id=$1 AND sensor_id=$2 AND id=$3",
            sensor["tenant_id"],
            sensor["id"],
            check_id,
            conn=conn,
        )
        if payload["action_commitment"] != event["action_commitment"]:
            return _conflict("payload_changed")
        replays = st.many(
            "SELECT * FROM guardrail_releases WHERE tenant_id=$1 AND sensor_id=$2 AND consume_request_id=$3",
            sensor["tenant_id"],
            sensor["id"],
            request_id,
            conn=conn,
        )
        if replays:
            if (
                replays[0]["check_id"] != check["id"]
                or replays[0]["guardrail_event_id"] != event["id"]
            ):
                return _conflict("payload_changed")
            return _receipt(replays[0], event, replayed=True), 200
        code = _action_error(st, event, conn)
        if code:
            return _conflict(code)
        settings, policy_version = _current(st, sensor["tenant_id"], conn)
        approval = None
        if check["approval_id"]:
            approval = st.one(
                "SELECT * FROM guardrail_approvals WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                sensor["tenant_id"],
                check["approval_id"],
                conn=conn,
            )
            approval = _refresh(
                st,
                approval,
                settings,
                policy_version,
                st.scalar("SELECT clock_timestamp()", conn=conn),
                conn,
            )
        if not _same_versions(check, settings, policy_version):
            return _conflict("policy_changed")
        from .inline import context_changed

        if context_changed(st, event, settings, conn, check):
            return _conflict("context_changed")
        if not check["decision"]:
            return _conflict("approval_pending")
        # A newer request alias can strengthen the floor for this action.
        # Exact historical consume receipts above still replay without a grant.
        code = policy_floor_error(st, check, conn)
        if code:
            return _conflict(code)
        action = check["decision"]["action"]
        if action == "block":
            return _conflict("action_blocked")
        approval_id = None
        if action == "ask":
            if not settings["approvals_enabled"]:
                return _conflict("approvals_disabled")
            if approval is None:
                return _conflict("approval_pending")
            code = _state_error(approval, settings, policy_version)
            if code:
                return _conflict(code)
            if approval["status"] != "approved":
                return _conflict("approval_pending")
            approval_id = approval["id"]
        release = st.one(
            """INSERT INTO guardrail_releases(id,tenant_id,sensor_id,registration_id,owner_user_id,
                   guardrail_event_id,check_id,approval_id,consume_request_id,assessment_generation)
               VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *""",
            new_id(),
            sensor["tenant_id"],
            sensor["id"],
            check["registration_id"],
            check["owner_user_id"],
            event["id"],
            check["id"],
            approval_id,
            request_id,
            check["assessment_generation"],
            conn=conn,
        )
        _audit(
            st,
            release,
            "guardrail.release.consume",
            {"type": "sensor", "id": sensor["id"]},
            conn,
            {"check_id": check["id"], "approval_id": approval_id},
        )
        return _receipt(release, event, granted=True), 201


def record_outcome(st, sensor, release_id, payload):
    _body(payload, ("outcome", "exit_code", "evidence_ids"), ("outcome",))
    require(
        payload["outcome"] in ("succeeded", "failed", "not_executed", "uncertain"),
        "invalid outcome",
    )
    exit_code = payload.get("exit_code")
    require(
        exit_code is None
        or type(exit_code) is int
        and -(1 << 31) <= exit_code < 1 << 31,
        "invalid exit_code",
    )
    ids = payload.get("evidence_ids", [])
    require(isinstance(ids, list) and len(ids) <= 16, "invalid evidence_ids")
    ids = [_uuid(value, "evidence id") for value in ids]
    require(len(set(ids)) == len(ids), "duplicate evidence id")
    details = {"exit_code": exit_code, "evidence_ids": ids}
    with st.transaction() as conn:
        release = st.one(
            "SELECT * FROM guardrail_releases WHERE tenant_id=$1 AND sensor_id=$2 AND id=$3",
            sensor["tenant_id"],
            sensor["id"],
            _uuid(release_id),
            conn=conn,
        )
        event = _lock_event(
            st, sensor, release["registration_id"], release["guardrail_event_id"], conn
        )
        release = st.one(
            "SELECT * FROM guardrail_releases WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            sensor["tenant_id"],
            release["id"],
            conn=conn,
        )
        if (
            release["outcome"] == payload["outcome"]
            and release["outcome_details"] == details
        ):
            return _receipt(release, event, replayed=True), 200
        if release["outcome"] is not None and release["outcome"] != "uncertain":
            return _conflict("outcome_conflict")
        if release["outcome"] == "uncertain" and payload["outcome"] == "uncertain":
            return _conflict("outcome_conflict")
        if ids:
            found = st.many(
                """SELECT e.id FROM events e JOIN agent_sessions s ON s.tenant_id=e.tenant_id AND s.id=e.session_id
                   WHERE e.tenant_id=$1 AND e.sensor_id=$2 AND s.registration_id=$3 AND e.id=ANY($4::uuid[])
                   UNION SELECT event_id AS id FROM inline_guardrail_events
                   WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3 AND event_id=ANY($4::uuid[])""",
                sensor["tenant_id"],
                sensor["id"],
                release["registration_id"],
                ids,
                conn=conn,
            )
            require(
                {row["id"] for row in found} == set(ids),
                "outcome evidence is unavailable",
                403,
            )
        release = st.one(
            """UPDATE guardrail_releases SET outcome=$3,outcome_at=clock_timestamp(),outcome_details=$4
               WHERE tenant_id=$1 AND id=$2 RETURNING *""",
            sensor["tenant_id"],
            release["id"],
            payload["outcome"],
            Jsonb(details),
            conn=conn,
        )
        outcome_audit_id = _audit(
            st,
            release,
            "guardrail.release.outcome",
            {"type": "sensor", "id": sensor["id"]},
            conn,
            {"outcome": payload["outcome"], **details},
        )
        st.execute(
            "UPDATE guardrail_releases SET outcome_audit_id=$3 WHERE tenant_id=$1 AND id=$2",
            sensor["tenant_id"],
            release["id"],
            outcome_audit_id,
            conn=conn,
        )
        release["outcome_audit_id"] = outcome_audit_id
        return _receipt(release, event), 200


def expire_pending(st, limit=100, tenant_id=None):
    with st.transaction() as conn:
        rows = st.many(
            """SELECT a.* FROM guardrail_approvals a WHERE ($1::uuid IS NULL OR a.tenant_id=$1)
               AND ((a.status='pending' AND a.expires_at<=clock_timestamp())
                 OR (a.status='approved' AND a.approved_until<=clock_timestamp()))
               AND NOT EXISTS(SELECT 1 FROM guardrail_releases r WHERE r.guardrail_event_id=a.guardrail_event_id)
               ORDER BY COALESCE(a.approved_until,a.expires_at),a.id LIMIT $2 FOR UPDATE OF a SKIP LOCKED""",
            tenant_id,
            max(1, min(int(limit), 500)),
            conn=conn,
        )
        expired = 0
        for row in rows:
            # Consumption takes this approval lock before inserting a release.
            # Recheck in a fresh snapshot after the lock acquisition so an
            # earlier SELECT snapshot cannot expire a just-consumed approval.
            if st.scalar(
                "SELECT EXISTS(SELECT 1 FROM guardrail_releases WHERE guardrail_event_id=$1)",
                row["guardrail_event_id"],
                conn=conn,
            ):
                continue
            st.execute(
                "UPDATE guardrail_approvals SET status='expired',reason_code='approval_expired' WHERE tenant_id=$1 AND id=$2",
                row["tenant_id"],
                row["id"],
                conn=conn,
            )
            _audit(
                st,
                row,
                "guardrail.approval.expire",
                _SYSTEM,
                conn,
                {"reason_code": "approval_expired"},
            )
            expired += 1
        return expired
