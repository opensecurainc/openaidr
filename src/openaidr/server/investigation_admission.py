"""Dormant, credit-bounded complete-job admission. No evidence export or transport."""

from datetime import timedelta
import re

from . import detection_selection, investigation_submissions as submissions, session_aggregation as aggregation
from .store import new_id


def claim(st, job_id, connection, worker_id, *, expected_rate_version=None, conn):
    """Reserve one protocol4 attempt inside the caller's short transaction.

    Commit this claim before starting a fresh repeatable-read evidence capture.
    Only capture may persist the exact request and dispatch intent together.
    An unexported claim may expire; a submitted claim requires reconciliation.
    """
    submissions._contracts()  # Fail before database access with the current SDK.
    if conn is None:
        raise ValueError("Investigation admission requires a caller transaction")
    submissions._connection(connection.tenant_id, connection)
    if not isinstance(worker_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", worker_id):
        raise ValueError("Invalid investigation worker id")
    if expected_rate_version is not None and (not isinstance(expected_rate_version, str)
                                            or not 1 <= len(expected_rate_version) <= 80):
        raise ValueError("Invalid investigation credit rate")
    tenant = connection.tenant_id
    st.execute("SET LOCAL statement_timeout='5s'", conn=conn)
    st.execute("SET LOCAL lock_timeout='3s'", conn=conn)
    # Match the retained admission path: tenant budget, authority, settings, job.
    st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
               "session-investigation-budget:" + tenant, conn=conn)
    candidate = st.one("SELECT * FROM session_investigation_jobs WHERE id=$1 AND tenant_id=$2",
                       job_id, tenant, conn=conn)
    if candidate["protocol_version"] != 4:
        raise ValueError("Complete admission requires a complete-job job")
    aggregation._job_authority(st, candidate, conn)
    settings = aggregation._locked_settings(st, tenant, conn)
    limits = st.one("""SELECT max_credits_per_attempt_microcredits AS ceiling,hourly_credits_microcredits AS hourly,
        weekly_credits_microcredits AS weekly
        FROM tenant_session_detection_settings WHERE tenant_id=$1""", tenant, conn=conn)
    job = st.one("SELECT * FROM session_investigation_jobs WHERE id=$1 AND tenant_id=$2 FOR UPDATE",
                 job_id, tenant, conn=conn)
    # Do not use authority acquired for a candidate whose identity was replaced.
    if any(job[key] != candidate[key] for key in ("sensor_id", "session_id", "registration_id", "owner_user_id", "configuration")):
        return None
    now = st.scalar("SELECT clock_timestamp()", conn=conn)
    if (job["state"] != "queued" or job["next_attempt_at"] > now
            or not aggregation._job_current(st, job, settings, conn)
            or limits["ceiling"] is None or limits["hourly"] is None
            or job["attempts"] >= settings["max_attempts"]
            or not aggregation._threshold_matches(st, job, settings, conn)):
        return None
    if settings["selection_policy"] == "risk_budget" and not detection_selection.admit(st, job, settings, conn):
        return None
    window = st.scalar("SELECT date_trunc('hour',$1::timestamptz AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'", now, conn=conn)
    usage = st.one("""SELECT count(*) FILTER(WHERE a.state<>'released') AS attempts,
        COALESCE(sum(CASE
          WHEN r.state IN ('disabled','released') THEN 0
          WHEN r.state='settled' THEN r.charged_microcredits
          WHEN a.state='released' AND a.dispatched_at IS NULL THEN 0
          ELSE a.reserved_credits_microcredits END) FILTER(WHERE j.protocol_version IN (3,4)),0) AS credits,
        COALESCE(bool_or(a.reserved_credits_microcredits IS NULL
          AND r.state IS DISTINCT FROM 'disabled' AND r.state IS DISTINCT FROM 'released'
          AND r.state IS DISTINCT FROM 'settled'
          AND NOT (a.state='released' AND a.dispatched_at IS NULL))
          FILTER(WHERE j.protocol_version IN (3,4)),false) AS unknown
        FROM session_investigation_attempts a JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
        LEFT JOIN service_credit_receipts r ON r.tenant_id=a.tenant_id AND r.request_id=a.id
          AND r.api_tenant_id=a.tenant_id AND r.service='investigations' AND r.origin=a.admission_origin
        WHERE a.tenant_id=$1 AND a.window_start=$2""", tenant, window, conn=conn)
    if usage["unknown"] or usage["attempts"] >= settings["hourly_attempts"] or usage["credits"] + limits["ceiling"] > limits["hourly"]:
        return None
    if limits["weekly"] is not None:
        # Settlement starts the seven-day charge window. Unresolved reservations
        # remain held regardless of age; a missing or foreign receipt cannot free them.
        weekly = st.one("""SELECT COALESCE(sum(CASE
              WHEN r.state IN ('disabled','released') THEN 0
              WHEN r.state='settled' THEN CASE WHEN r.updated_at>$2 THEN r.charged_microcredits ELSE 0 END
              WHEN a.state='released' AND a.dispatched_at IS NULL THEN 0
              ELSE a.reserved_credits_microcredits END),0) AS credits,
            COALESCE(bool_or(a.reserved_credits_microcredits IS NULL
              AND r.state IS DISTINCT FROM 'disabled' AND r.state IS DISTINCT FROM 'released'
              AND r.state IS DISTINCT FROM 'settled'
              AND NOT (a.state='released' AND a.dispatched_at IS NULL)),false) AS unknown
            FROM session_investigation_attempts a JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
            LEFT JOIN service_credit_receipts r ON r.tenant_id=a.tenant_id AND r.request_id=a.id
              AND r.api_tenant_id=a.tenant_id AND r.service='investigations' AND r.origin=a.admission_origin
            WHERE a.tenant_id=$1 AND j.protocol_version IN (3,4)""", tenant, now - timedelta(days=7), conn=conn)
        if weekly["unknown"] or weekly["credits"] + limits["ceiling"] > limits["weekly"]:
            return None
    running = st.one("""SELECT count(*) AS total,count(*) FILTER(WHERE owner_user_id=$3) AS owner
        FROM session_investigation_jobs WHERE tenant_id=$1 AND state='running' AND lease_deadline>$2""",
        tenant, now, job["owner_user_id"], conn=conn)
    if running["total"] >= settings["max_concurrent"] or job["owner_user_id"] and running["owner"]:
        return None
    ident, token = new_id(), new_id()
    deadline = now + timedelta(seconds=job["configuration"]["max_runtime_seconds"])
    st.execute("""INSERT INTO session_investigation_attempts
        (id,job_id,tenant_id,ordinal,claim_token,worker_id,state,window_start,deadline_at,
         reserved_credits_microcredits,credit_rate_version,admission_origin)
        VALUES($1,$2,$3,$4,$5,$6,'reserved',$7,$8,$9,$10,$11)""",
        ident, job_id, tenant, job["attempts"] + 1, token, worker_id, window, deadline,
        limits["ceiling"], expected_rate_version, connection.origin, conn=conn)
    st.execute("""UPDATE session_investigation_jobs SET state='running',attempts=attempts+1,claim_token=$2,
        lease_deadline=$3,result=NULL,completed_at=NULL WHERE id=$1""", job_id, token, deadline, conn=conn)
    return dict(job_id=job_id, tenant_id=tenant, attempt_id=ident, claim_token=token,
                deadline_at=deadline, snapshot_id=job["snapshot_id"], configuration=job["configuration"])
