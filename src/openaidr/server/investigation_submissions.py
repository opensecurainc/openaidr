"""Dormant complete-job persistence, separate from authority and transport."""

from contextlib import nullcontext
import json
from typing import Any

from pydantic import Field
from openaidr_api_client.client import Connection

from . import service_billing
from .service_operations import contracts as customer_contracts


def _contracts():
    customer_contracts()
    from openaidr_api_client.contracts import investigations
    return investigations


def _connection(tenant, connection):
    if not isinstance(connection, Connection) or connection.tenant_id != tenant:
        raise ValueError("Investigation tenant mismatch")


def bound_request(row, connection):
    """Check the persisted binding after resolving its origin's current key."""
    wire = _contracts()
    _connection(row["tenant_id"], connection)
    request = json.loads(row["request"])
    if (row["api_tenant_id"] != connection.tenant_id or row["origin"] != connection.origin
            or request.get("request_id") != row["attempt_id"]
            or wire.canonical(request).decode() != row["request"]
            or wire.digest(request) != row["request_sha256"]):
        raise ValueError("Investigation submission binding mismatch")
    wire.InvestigationCreate.model_validate(request)
    # Replays preserve omitted optional fields and the exact canonical input.
    return json.loads(wire.canonical(request))


def save(st, tenant, attempt_id, connection, request, *, conn):
    """Persist within the caller's authorized evidence/admission transaction.

    This function grants no authority and dispatches nothing. The caller must
    acquire its normal authority fence and commit admission with this identity.
    """
    wire = _contracts()
    _connection(tenant, connection)
    if conn is None:
        raise ValueError("Investigation admission requires a caller transaction")
    raw = wire.canonical(request)
    if len(raw) > wire.MAX_INPUT:
        raise ValueError("Investigation input exceeds the byte limit")
    request = json.loads(raw)
    wire.InvestigationCreate.model_validate(request)
    if request["request_id"] != attempt_id:
        raise ValueError("Investigation request identity mismatch")
    attempt = st.one("""SELECT a.*,j.protocol_version FROM session_investigation_attempts a
        JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
        WHERE a.id=$1 AND a.tenant_id=$2""", attempt_id, tenant, conn=conn)
    if attempt["protocol_version"] != 4:
        raise ValueError("Complete submission requires a complete-job attempt")
    if attempt["admission_origin"] is not None:
        from openaidr_api_client.contracts.credits import microcredits

        if (attempt["admission_origin"] != connection.origin
                or wire.stamp(request["deadline_at"]) != attempt["deadline_at"].timestamp()
                or request.get("max_credits") is None
                or microcredits(request["max_credits"]) != attempt["reserved_credits_microcredits"]
                or request.get("expected_rate_version") != attempt["credit_rate_version"]):
            raise ValueError("Investigation request differs from captured admission")
    digest = wire.digest(request)
    st.execute("""INSERT INTO session_investigation_submissions
        (attempt_id,tenant_id,origin,api_tenant_id,request,request_sha256)
        VALUES($1,$2,$3,$2,$4,$5) ON CONFLICT DO NOTHING""",
        attempt_id, tenant, connection.origin, raw.decode(), digest, conn=conn)
    row = st.one("""SELECT * FROM session_investigation_submissions
        WHERE attempt_id=$1 AND tenant_id=$2 FOR UPDATE""", attempt_id, tenant, conn=conn)
    bound_request(row, connection)
    if row["request_sha256"] != digest:
        raise ValueError("Investigation request identity was reused with different content")
    return row


def record(st, tenant, attempt_id, connection, response, *, conn=None):
    """Atomically mirror observed status and authoritative customer billing.

    Return a validated response for separate authority/publication checks, or
    None for a stale poll or invalid result. Invalid results set last_error and
    cannot raise an exception that rolls back independently confirmed accounting.
    No report or raw response is persisted here.
    """
    wire = _contracts()
    _connection(tenant, connection)
    class Observation(wire.Investigation):
        # Reuse every known envelope/billing validator. Result content is checked
        # separately and excluded from envelope serialization, including invalid
        # JSON values, so malformed reports cannot erase confirmed accounting.
        result: Any = Field(exclude=True)

    remote = Observation.model_validate(response).model_dump()
    if remote["id"] != attempt_id:
        raise ValueError("Investigation response identity mismatch")
    try:
        parsed = wire.Investigation.model_validate(response).model_dump()
    except (ValueError, TypeError, RecursionError):
        parsed = None
    with nullcontext(conn) if conn is not None else st.transaction() as conn:
        row = st.one("""SELECT * FROM session_investigation_submissions
            WHERE attempt_id=$1 AND tenant_id=$2 FOR UPDATE""", attempt_id, tenant, conn=conn)
        request = bound_request(row, connection)
        if (row["remote_id"] not in (None, attempt_id)
                or wire.stamp(remote["deadline_at"]) != wire.stamp(request["deadline_at"])):
            raise ValueError("Investigation response binding mismatch")
        if row["remote_status"] in wire.TERMINAL:
            # Concurrent polls may arrive after a terminal observation. They
            # must not overwrite that status or regress its billing receipt.
            if remote["status"] not in wire.TERMINAL:
                return None
            if remote["status"] != row["remote_status"]:
                raise ValueError("Investigation terminal status changed")
        elif row["remote_status"] == "running" and remote["status"] == "queued":
            return None
        expected = request.get("expected_rate_version")
        if (remote["billing"]["state"] != "disabled" and expected is not None
                and remote["billing"]["rate_version"] != expected):
            raise ValueError("Investigation receipt rate differs from captured admission")
        maximum = request.get("max_credits") if remote["billing"]["state"] != "disabled" else None
        service_billing.record(st, tenant, connection, remote["billing"], request_id=attempt_id,
                               service="investigations", conn=conn, max_credits=maximum)
        st.execute("""UPDATE session_investigation_submissions SET remote_id=$2,remote_status=$3,
            checked_at=clock_timestamp(),last_error=$4 WHERE attempt_id=$1""", attempt_id, attempt_id,
            remote["status"], "invalid_result" if parsed is None else "", conn=conn)
    return parsed
