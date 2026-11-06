"""Dormant, bounded evidence grants for complete investigation jobs."""

from datetime import timezone

from psycopg.errors import SerializationFailure

from . import detection_history, investigation_submissions as submissions
from . import session_aggregation as aggregation, session_investigator as inv
from .model import public

MAX_ITEMS, MAX_SESSIONS, MAX_POLICIES = 100000, 10000, 10000


def _utc(value):
    return public(value.astimezone(timezone.utc)) if value is not None else None


def _bounded(wire, request):
    inv._need(len(wire.canonical(request)) <= wire.MAX_INPUT, "invalid_request")


def _snapshot(st, c, wire, snapshot, request, items):
    inv._need(0 <= snapshot["item_count"] <= MAX_ITEMS, "invalid_request")
    after = 0
    while True:
        inv._checkpoint(c)
        metadata = st.many("""SELECT ordinal AS id,octet_length(to_jsonb(i)::text) AS byte_size
            FROM session_snapshot_items i WHERE snapshot_id=$1 AND ordinal>$2 ORDER BY ordinal LIMIT 250""",
            snapshot["id"], after, conn=c["conn"])
        if not metadata:
            break
        inv._need(all(row["byte_size"] <= wire.MAX_INPUT for row in metadata), "invalid_request")
        keys = next(aggregation._page_groups(metadata))
        page = st.many("""SELECT ordinal,kind,source_id,body FROM session_snapshot_items
            WHERE snapshot_id=$1 AND ordinal=ANY($2::bigint[]) ORDER BY ordinal""",
            snapshot["id"], keys, conn=c["conn"])
        inv._need([row["ordinal"] for row in page] == list(range(after + 1, after + len(keys) + 1)),
                  "incomplete_coverage")
        items.extend(public(page))
        inv._need(len(items) <= MAX_ITEMS, "invalid_request")
        _bounded(wire, request)
        after = page[-1]["ordinal"]
    inv._need(len(items) == snapshot["item_count"], "incomplete_coverage")


def _live(st, c, wire, source, request, session):
    start, end = detection_history.bounds(c["job"])
    after, order = None, []
    while True:
        inv._checkpoint(c)
        metadata = st.many("""SELECT id,octet_length(body::text) AS byte_size FROM events
            WHERE tenant_id=$1 AND session_id=$2 AND time>=$3 AND time<=$4 AND received_at<=$4
              AND ($5::uuid IS NULL OR id>$5) ORDER BY id LIMIT 250""",
            c["job"]["tenant_id"], source["id"], start, end, after, conn=c["conn"])
        if not metadata:
            break
        inv._need(all(row["byte_size"] <= wire.MAX_INPUT for row in metadata), "invalid_request")
        keys = next(aggregation._page_groups(metadata))
        page = st.many("""SELECT id,body,evidence_stream,evidence_sequence,evidence_part,time
            FROM events WHERE tenant_id=$1 AND session_id=$2 AND id=ANY($3::uuid[]) ORDER BY id""",
            c["job"]["tenant_id"], source["id"], keys, conn=c["conn"])
        inv._need([row["id"] for row in page] == keys, "incomplete_coverage")
        for row in page:
            order.append(tuple((row[key] is None, row[key]) for key in
                               ("evidence_stream", "evidence_sequence", "evidence_part", "time", "id")))
            session["items"].append(dict(ordinal=len(order), kind="observation", source_id=row["id"],
                                         body=aggregation._capture(public(row["body"]))))
        inv._need(len(order) <= MAX_ITEMS, "invalid_request")
        _bounded(wire, request)
        after = page[-1]["id"]
    session["items"] = [item for _, item in sorted(zip(order, session["items"]))]
    for index, item in enumerate(session["items"], 1):
        item["ordinal"] = index
    gaps = set()
    for item in session["items"]:
        metadata = item["body"].get("evidence")
        values = metadata.get("gaps") if isinstance(metadata, dict) else None
        if isinstance(values, list):
            gaps.update(gap for gap in values if isinstance(gap, str))
    session["coverage"]["gaps"] = sorted(gaps)


def _history(st, c, wire, request):
    if not c["job"]["owner_user_id"]:
        return
    start, end = detection_history.bounds(c["job"])
    history = dict(start_at=_utc(start), end_at=_utc(end), complete=True, sessions=[])
    request["history"] = history
    for ident, source in c["sources"].items():
        inv._checkpoint(c)
        if source is None:
            continue
        snapshots = st.many("""SELECT id,item_count,coverage FROM session_snapshots
            WHERE tenant_id=$1 AND sensor_id=$2 AND owner_user_id=$3 AND sealed_at<=$4
              AND (session_id=$5 OR registration_id=$6)
            ORDER BY revision DESC LIMIT 1""", c["job"]["tenant_id"], source["sensor_id"],
            c["job"]["owner_user_id"], end, ident, source["registration_id"], conn=c["conn"])
        session = dict(session_id=ident, product=source["product"], started_at=_utc(source["started_at"]),
            last_event_at=_utc(min(source["last_event_at"], end)),
            ended_at=_utc(source["ended_at"]) if source["ended_at"] and source["ended_at"] <= end else None,
            snapshot_id=snapshots[0]["id"] if snapshots else None,
            coverage=snapshots[0]["coverage"] if snapshots else dict(status="unknown", gaps=[]), items=[])
        history["sessions"].append(session)
        _bounded(wire, request)
        if snapshots:
            _snapshot(st, c, wire, snapshots[0], request, session["items"])
        else:
            _live(st, c, wire, source, request, session)
        _bounded(wire, request)


def _prepare(st, claim, connection, wire):
    from openaidr_api_client.contracts.credits import amount

    with st.transaction() as conn:
        # Enumeration and every evidence page share one database snapshot. The
        # normal authority row locks make concurrent revocation abort capture.
        st.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ", conn=conn)
        st.execute("SET LOCAL statement_timeout='5s'", conn=conn)
        st.execute("SET LOCAL lock_timeout='3s'", conn=conn)
        identities = st.many("""SELECT j.* FROM session_investigation_jobs j
            JOIN session_investigation_attempts a ON a.job_id=j.id AND a.tenant_id=j.tenant_id
            WHERE j.id=$1 AND j.tenant_id=$2 AND a.id=$3 AND a.claim_token=$4
              AND j.claim_token=$4 AND j.protocol_version=4
              AND a.deadline_at>clock_timestamp() AND j.lease_deadline>clock_timestamp()""",
            claim["job_id"], claim["tenant_id"], claim["attempt_id"], claim["claim_token"], conn=conn)
        inv._need(len(identities) == 1, "scope_unavailable")
        job = identities[0]
        start, end = detection_history.bounds(job)
        candidates = st.many("""SELECT s.id FROM agent_sessions s
            JOIN detection_session_identities i ON i.session_id=s.id AND i.tenant_id=s.tenant_id
            WHERE s.tenant_id=$1 AND i.owner_user_id=$2 AND s.last_event_at>=$3 AND s.started_at<=$4
            ORDER BY s.id LIMIT $5""", job["tenant_id"], job["owner_user_id"], start, end,
            MAX_SESSIONS + 1, conn=conn) if job["owner_user_id"] else []
        inv._need(len(candidates) <= MAX_SESSIONS, "invalid_request")
        # Managed finalization locks its aggregate before the job. Ordinary
        # finalization updates the job first; keep that ordering below.
        if job["registration_id"]:
            aggregation._job_authority(st, job, conn)
            st.many("SELECT registration_id FROM session_finalizations WHERE tenant_id=$1 AND registration_id=$2 FOR SHARE",
                    job["tenant_id"], job["registration_id"], conn=conn)
        with inv._fence(st, claim, sources=[row["id"] for row in candidates], conn=conn) as c:
            job, attempt = c["job"], c["attempt"]
            inv._need(job["tenant_id"] == attempt["tenant_id"] == connection.tenant_id == claim["tenant_id"],
                      "scope_unavailable")
            inv._need(c["registration"]["sensor_id"] == job["sensor_id"], "scope_unavailable")
            existing = st.many("SELECT * FROM session_investigation_submissions WHERE attempt_id=$1 FOR UPDATE",
                               attempt["id"], conn=conn)
            if existing:
                submissions.bound_request(existing[0], connection)
                return existing[0]
            # A generation update after our snapshot must retry, not admit a
            # replaced target through an older repeatable-read view.
            if job["session_id"]:
                st.many("SELECT session_id FROM ordinary_session_detection WHERE tenant_id=$1 AND session_id=$2 FOR SHARE",
                        job["tenant_id"], job["session_id"], conn=conn)
            inv._need(aggregation._job_current(st, job, c["settings"], conn)
                      and aggregation._threshold_matches(st, job, c["settings"], conn), "settings_changed")
            snapshot = st.one("""SELECT * FROM session_snapshots WHERE id=$1 AND tenant_id=$2 AND sensor_id=$3
                AND owner_user_id IS NOT DISTINCT FROM $4::uuid AND sealed_at IS NOT NULL
                AND session_id IS NOT DISTINCT FROM $5::uuid AND registration_id IS NOT DISTINCT FROM $6::uuid""",
                job["snapshot_id"], job["tenant_id"], job["sensor_id"], job["owner_user_id"],
                job["session_id"], job["registration_id"], conn=conn)
            reserved = attempt["reserved_credits_microcredits"]
            request = dict(request_id=attempt["id"], detector_config_version=job["detector_config_version"],
                trigger=job["routing_reason"], deadline_at=_utc(min(job["lease_deadline"], attempt["deadline_at"])),
                max_credits=amount(reserved) if reserved is not None else None,
                expected_rate_version=attempt["credit_rate_version"], company_policies=[], history=None,
                target=dict(snapshot_id=snapshot["id"], revision=snapshot["revision"],
                            item_count=snapshot["item_count"], coverage=snapshot["coverage"], items=[]))
            _snapshot(st, c, wire, snapshot, request, request["target"]["items"])
            request["company_policies"] = [{key: value for key, value in policy.items() if key != "source"}
                for policy in inv._company_policies(st, job, conn)]
            inv._need(len(request["company_policies"]) <= MAX_POLICIES, "invalid_request")
            _bounded(wire, request)
            _history(st, c, wire, request)
            inv._checkpoint(c)
            row = submissions.save(st, claim["tenant_id"], attempt["id"], connection, request, conn=conn)
            st.execute("""UPDATE session_investigation_attempts SET target_item_count=$2,target_byte_count=$3
                WHERE id=$1""", attempt["id"], len(request["target"]["items"]),
                sum(len(wire.canonical(item)) for item in request["target"]["items"]), conn=conn)
            inv._need(aggregation._dispatch_attempt(st, attempt, conn, c["now"]), "claim_expired")
        return row


def prepare(st, claim, connection):
    """Atomically capture an authorized finite grant; perform no HTTP or worker activation.

    Retry serialization conflicts with a fresh snapshot. An accepted submission
    is returned only under its current fence, with its original immutable binding.
    Expired or revoked accepted work belongs to the separate recovery boundary.
    """
    wire = submissions._contracts()  # Current SDK fails before any database read.
    submissions._connection(claim["tenant_id"], connection)
    for retry in range(3):
        try:
            return _prepare(st, claim, connection, wire)
        except SerializationFailure:
            if retry == 2:
                raise inv.InvestigationStopped("capture_conflict") from None
