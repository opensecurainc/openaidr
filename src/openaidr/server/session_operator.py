"""Read-only tenant operator archives, distinct from current-owner authority.

The HTTP boundary must authenticate an active
tenant viewer inside its private worker before calling these helpers. No helper
accepts a substitute owner, grants an action, or starts investigation work.
"""

from . import customer_views

import base64
import copy
from contextlib import contextmanager
from datetime import date, datetime, timezone
from decimal import Decimal
import json
import uuid

from .httpx import APIError, require
from .session_aggregation import _page_groups


PAGE_BYTES = 1 << 20
DETAIL_LIMIT = 100


def _json_safe(value):
    """Convert database scalars without changing retained JSON keys or nesting."""
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, (uuid.UUID, Decimal)):
        return str(value)
    return value


def _uuid(value):
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise APIError(400, "invalid archive id") from None


def _limit(value):
    require(type(value) is int and 1 <= value <= 500, "invalid archive limit")
    return value


def _encode(scope, position):
    data = json.dumps([1, scope, position], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _decode(value, scope, *, ordinal=False):
    if not value:
        return 0 if ordinal else None
    try:
        if not isinstance(value, str) or len(value) > 1024:
            raise ValueError()
        decoded = json.loads(
            base64.b64decode(
                value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
            )
        )
        if (
            not isinstance(decoded, list)
            or len(decoded) != 3
            or type(decoded[0]) is not int
            or decoded[0] != 1
            or decoded[1] != scope
        ):
            raise ValueError()
        position = decoded[2]
        if ordinal:
            if type(position) is not int or not 0 <= position < 1 << 63:
                raise ValueError()
            return position
        if not isinstance(position, list) or len(position) != 2:
            raise ValueError()
        stamp = datetime.fromisoformat(position[0].replace("Z", "+00:00"))
        ident = str(uuid.UUID(position[1]))
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError()
        return stamp, ident
    except (ValueError, TypeError, AttributeError, UnicodeError, RecursionError):
        raise APIError(400, "invalid archive cursor") from None


@contextmanager
def _read(st):
    # A fixed number of bounded reads, no source/registration locks, and a
    # consistent snapshot across size selection and full-row transfer.
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        conn.execute("SET LOCAL statement_timeout='5s'")
        yield conn


def _page(st, conn, query, args, scope, limit, cursor, *, detail=None):
    """Page a fixed internal query by time/UUID and bound transferred JSON."""
    _limit(limit)
    position = _decode(cursor, scope)
    values = list(args)
    seek = ""
    if position is not None:
        seek = f"WHERE (p.created_at,p.id)<(${len(values) + 1},${len(values) + 2})"
        values.extend(position)
    values.append(limit + 1)
    selected = (
        f"SELECT p.* FROM ({query}) p {seek} "
        f"ORDER BY p.created_at DESC,p.id DESC LIMIT ${len(values)}"
    )
    if detail is not None:
        # Page the narrow source identities before loading nested decisions,
        # generations and bodies. A large alias history must not be revisited
        # for every unrelated action while finding the first page.
        selected = detail.format(selected=selected)
    metadata = st.many(
        f"SELECT p.id,p.created_at,octet_length(to_jsonb(p)::text) AS byte_size "
        f"FROM ({selected}) p ORDER BY p.created_at DESC,p.id DESC",
        *values,
        conn=conn,
    )
    keys = next(_page_groups(metadata[:limit]), [])
    rows = (
        st.many(
            f"SELECT p.* FROM ({selected}) p WHERE p.id=ANY(${len(values) + 1}::uuid[]) "
            "ORDER BY p.created_at DESC,p.id DESC",
            *values,
            keys,
            conn=conn,
        )
        if keys
        else []
    )
    next_cursor = ""
    if rows and len(metadata) > len(rows):
        last = rows[-1]
        next_cursor = _encode(scope, [last["created_at"].isoformat(), str(last["id"])])
    return {"items": rows, "next_cursor": next_cursor}


def _session(st, tenant_id, session_id, conn):
    return st.one(
        """SELECT s.id,s.agent_id,s.sensor_id,s.external_id,s.product,s.cwd,s.git_branch,
                  s.started_at,s.last_event_at,s.ended_at,s.events_total,s.tool_calls,s.commands,
                  s.registration_id,
                  jsonb_build_object('product',s.product,'version',a.version) AS client,
                  jsonb_build_object('hostname',a.hostname,'os',a.os,'arch',a.arch,
                    'reported_user',a.username,'sensor_label',n.label,
                    'sensor_disabled',n.disabled,'sensor_deleted_at',n.deleted_at) AS device
           FROM agent_sessions s
           JOIN agents a ON a.id=s.agent_id AND a.tenant_id=s.tenant_id
           JOIN sensors n ON n.id=s.sensor_id AND n.tenant_id=s.tenant_id
           WHERE s.tenant_id=$1 AND s.id=$2""",
        tenant_id,
        session_id,
        conn=conn,
    )


def _registration(st, tenant_id, registration_id, conn):
    if registration_id is None:
        return None
    return st.one(
        """SELECT r.id,r.assessment_mode,r.verified_at,r.delivery_protocol,r.delivery_epoch,
                  CASE WHEN u.id IS NOT NULL THEN jsonb_build_object(
                    'id',u.id,'name',u.name,'email',u.email,'status',u.status) END AS owner,
                  COALESCE(u.status='active',false) AS owner_available
           FROM session_registrations r LEFT JOIN tenant_users u
             ON u.id=r.owner_user_id AND u.tenant_id=r.tenant_id
           WHERE r.tenant_id=$1 AND r.id=$2""",
        tenant_id,
        registration_id,
        conn=conn,
    )


def _projection(st, tenant_id, registration_id, conn, session_id=None):
    empty = {
        "available": False,
        "updated_at": None,
        "input_version": None,
        "revision": 0,
        "snapshot_id": None,
        "snapshot_current": False,
        "dirty": False,
        "evaluation_due": False,
        "settings_changed": False,
        "finalization_error": None,
    }
    if registration_id is None and session_id is not None:
        rows = st.many(
            """SELECT d.*,COALESCE(g.version,0) AS current_settings_version,
                      COALESCE(g.detector_config_version,0) AS current_config_version,
                      EXISTS(SELECT 1 FROM ordinary_session_input_dirty i
                             WHERE i.tenant_id=d.tenant_id AND i.session_id=d.session_id) AS dirty,
                      COALESCE(d.next_evaluation_at<=now(),false) AS due
               FROM ordinary_session_detection d LEFT JOIN tenant_session_detection_settings g ON g.tenant_id=d.tenant_id
               WHERE d.tenant_id=$1 AND d.session_id=$2""", tenant_id, session_id, conn=conn,
        )
        if not rows:
            return empty, None, 0
        row = rows[0]
        state = copy.deepcopy(row["state"])
        routing = state.get("routing") or {}
        if routing.get("job_id"):
            routing["status"] = st.scalar(
                "SELECT state FROM session_investigation_jobs WHERE tenant_id=$1 AND id=$2 AND session_id=$3",
                tenant_id, routing["job_id"], session_id, conn=conn,
            ) or routing["status"]
        return {
            **empty, "available": True, "updated_at": row["updated_at"], "input_version": row["input_version"],
            "revision": row["revision"], "snapshot_id": row["snapshot_id"],
            "snapshot_current": bool(row["snapshot_id"] and not row["dirty"]), "dirty": row["dirty"],
            "evaluation_due": row["due"], "settings_changed": row["settings_version"] != row["current_settings_version"],
        }, state, row["current_config_version"]
    if registration_id is None:
        return empty, None, 0
    row = st.one(
        """SELECT f.updated_at,f.input_version,f.revision,f.snapshot_id,f.lifecycle,
                  f.next_evaluation_at,f.status,f.failure_code,f.settings_version,
                  COALESCE(t.version,0) AS current_settings_version,
                  COALESCE(t.detector_config_version,0) AS current_config_version,
                  EXISTS(SELECT 1 FROM session_input_dirty d WHERE d.registration_id=r.id) AS dirty,
                  clock_timestamp() AS checked_at
           FROM session_registrations r
           LEFT JOIN session_finalizations f ON f.registration_id=r.id AND f.tenant_id=r.tenant_id
           LEFT JOIN tenant_session_detection_settings t ON t.tenant_id=r.tenant_id
           WHERE r.tenant_id=$1 AND r.id=$2""",
        tenant_id,
        registration_id,
        conn=conn,
    )
    if row["updated_at"] is None:
        return {**empty, "dirty": row["dirty"]}, None, row["current_config_version"]
    due = (
        row["next_evaluation_at"] is not None
        and row["next_evaluation_at"] <= row["checked_at"]
    )
    state = copy.deepcopy(row["status"])
    current = bool(
        row["snapshot_id"]
        and state.get("snapshot_current")
        and row["lifecycle"] in ("closed", "incomplete")
        and not row["dirty"]
        and not row["failure_code"]
        and not due
    )
    state["snapshot_current"] = current
    routing = state.get("routing") or {}
    if routing.get("job_id"):
        jobs = st.many(
            """SELECT state FROM session_investigation_jobs
               WHERE tenant_id=$1 AND registration_id=$2 AND id=$3""",
            tenant_id,
            registration_id,
            routing["job_id"],
            conn=conn,
        )
        if jobs:
            state["routing"] = {**routing, "status": jobs[0]["state"]}
    return (
        {
            "available": True,
            "updated_at": row["updated_at"],
            "input_version": row["input_version"],
            "revision": row["revision"],
            "snapshot_id": row["snapshot_id"],
            "snapshot_current": current,
            "dirty": row["dirty"],
            "evaluation_due": due,
            "settings_changed": row["settings_version"]
            != row["current_settings_version"],
            "finalization_error": row["failure_code"] or None,
        },
        state,
        row["current_config_version"],
    )


def _job_freshness(item, projection, config_version):
    item["snapshot_current"] = bool(
        projection["snapshot_current"]
        and item["snapshot_id"] == projection["snapshot_id"]
    )
    item["configuration_current"] = item["detector_config_version"] == config_version


def session_status(st, tenant_id, session_id, limit=20, cursor=""):
    """Read a stored projection and page retained job references; never aggregate."""
    from . import detection_eligibility

    tenant_id, session_id = _uuid(tenant_id), _uuid(session_id)
    _limit(limit)
    scope = [tenant_id, "session-jobs", session_id]
    with _read(st) as conn:
        session = _session(st, tenant_id, session_id, conn)
        registration_id = session.pop("registration_id")
        registration = _registration(st, tenant_id, registration_id, conn)
        projection, detection, config_version = _projection(
            st, tenant_id, registration_id, conn, session_id
        )
        jobs = _page(
            st,
            conn,
            """SELECT j.id,j.snapshot_id,s.revision,j.state,j.settings_version,
                      j.detector_config_version,j.routing_reason,j.created_at,j.completed_at
               FROM session_snapshots s JOIN session_investigation_jobs j
                 ON j.snapshot_id=s.id AND j.tenant_id=s.tenant_id
                   AND j.registration_id IS NOT DISTINCT FROM s.registration_id
                   AND j.session_id IS NOT DISTINCT FROM s.session_id
               WHERE s.tenant_id=$1 AND (s.registration_id=$2 OR s.session_id=$3)""",
            (tenant_id, registration_id, session_id),
            scope,
            limit,
            cursor,
        )
        for item in jobs["items"]:
            _job_freshness(item, projection, config_version)
        return _json_safe(
            {
                "session": session,
                "registration": registration,
                "projection": projection,
                "detection": detection,
                "eligibility": detection_eligibility.session(st, tenant_id, session_id, conn),
                "investigations": jobs,
            }
        )


_CHECK = """c.id,c.request_id,c.settings_version,c.policy_version,c.assessment_generation,c.decision,
            c.deterministic_result->>'policy_floor' AS requested_policy_floor,
            c.approval_id,c.created_at,c.completed_at"""
_APPROVAL = """a.id,a.originating_check_id,a.generation,a.assessment_generation,a.settings_version,a.policy_version,
               a.status,a.created_at,a.expires_at,a.decision,a.decided_at,a.decided_by_user_id,
               a.approved_until,a.revoked_at,a.reason_code"""

_TARGETS = """
        SELECT e.id,e.id AS action_id,e.event_id,e.logical_id,e.created_at,
               'inline_assessment'::text AS origin
        FROM inline_guardrail_events e WHERE e.tenant_id=$1 AND e.registration_id=$2
        UNION ALL
        SELECT d.id,NULL::uuid,d.event_id,d.logical_id,d.received_at,'delivery_receipt'
        FROM session_delivery_receipts d
        WHERE d.tenant_id=$1 AND d.registration_id=$2 AND d.kind='target'
          AND NOT EXISTS(SELECT 1 FROM inline_guardrail_events e
            WHERE e.tenant_id=$1 AND e.registration_id=$2 AND e.logical_id=d.logical_id)
"""

_ACTION_DETAIL = f"""
    WITH targets AS MATERIALIZED ({{selected}})
    SELECT t.*,CASE WHEN e.id IS NOT NULL THEN e.target_body ELSE d.captured_body END AS target_body,
           e.captured_context,
           jsonb_build_object('status',COALESCE(e.status,'missing'),'generation',e.assessment_generation,'value',e.assessment,
             'started_at',e.started_at,'completed_at',e.completed_at) AS assessment,
           to_jsonb(c) AS latest_decision,to_jsonb(a) AS latest_approval,
           to_jsonb(r) AS release,to_jsonb(o) AS reported_outcome,
           (SELECT count(*) FROM inline_guardrail_checks x
            WHERE x.tenant_id=$1 AND x.registration_id=$2 AND x.guardrail_event_id=t.action_id) AS decision_count,
           (SELECT count(*) FROM guardrail_approvals x
            WHERE x.tenant_id=$1 AND x.registration_id=$2 AND x.guardrail_event_id=t.action_id) AS approval_count
    FROM targets t
    LEFT JOIN inline_guardrail_events e ON e.id=t.action_id AND e.tenant_id=$1 AND e.registration_id=$2
    LEFT JOIN session_delivery_receipts d
      ON t.action_id IS NULL AND d.id=t.id AND d.tenant_id=$1 AND d.registration_id=$2 AND d.kind='target'
    LEFT JOIN LATERAL (
        SELECT {_CHECK} FROM inline_guardrail_checks c
        WHERE c.tenant_id=$1 AND c.registration_id=$2 AND c.guardrail_event_id=t.action_id
        ORDER BY c.created_at DESC,c.id DESC LIMIT 1
    ) c ON true
    LEFT JOIN LATERAL (
        SELECT {_APPROVAL} FROM guardrail_approvals a
        WHERE a.tenant_id=$1 AND a.registration_id=$2 AND a.guardrail_event_id=t.action_id
        ORDER BY a.generation DESC LIMIT 1
    ) a ON true
    LEFT JOIN LATERAL (
        SELECT r.id,r.check_id,r.approval_id,r.assessment_generation,r.consumed_at,r.outcome,r.outcome_at,
               r.outcome_details,r.outcome_audit_id
        FROM guardrail_releases r
        WHERE r.tenant_id=$1 AND r.registration_id=$2 AND r.guardrail_event_id=t.action_id
    ) r ON true
    LEFT JOIN LATERAL (
        SELECT o.id,o.sequence,o.payload,o.captured_body,o.received_at
        FROM session_delivery_receipts o
        WHERE o.tenant_id=$1 AND o.registration_id=$2 AND o.kind='outcome' AND o.logical_id=t.logical_id
        ORDER BY o.sequence DESC LIMIT 1
    ) o ON true
"""


def guardrail_actions(
    st, tenant_id, session_id, limit=50, cursor="", view="actions", action_id=None
):
    tenant_id, session_id = _uuid(tenant_id), _uuid(session_id)
    _limit(limit)
    require(view in ("actions", "decisions", "approvals"), "invalid action view")
    require((view == "actions") == (action_id is None), "invalid action reference")
    action_id = _uuid(action_id) if action_id is not None else None
    scope = [tenant_id, "guardrail-actions", session_id, view, action_id]
    with _read(st) as conn:
        session = _session(st, tenant_id, session_id, conn)
        registration_id = session["registration_id"]
        if action_id is not None:
            st.one(
                """SELECT id FROM inline_guardrail_events
                   WHERE tenant_id=$1 AND registration_id=$2 AND id=$3""",
                tenant_id,
                registration_id,
                action_id,
                conn=conn,
            )
        query, args = _TARGETS, (tenant_id, registration_id)
        if view == "decisions":
            query = f"""SELECT {_CHECK} FROM inline_guardrail_checks c
                        WHERE c.tenant_id=$1 AND c.registration_id=$2 AND c.guardrail_event_id=$3"""
            args += (action_id,)
        elif view == "approvals":
            query = f"""SELECT {_APPROVAL} FROM guardrail_approvals a
                        WHERE a.tenant_id=$1 AND a.registration_id=$2 AND a.guardrail_event_id=$3"""
            args += (action_id,)
        result = _page(
            st,
            conn,
            query,
            args,
            scope,
            limit,
            cursor,
            detail=_ACTION_DETAIL if view == "actions" else None,
        )
        if view == "actions":
            for item in result["items"]:
                item["assessment"]["value"] = customer_views.guardrail_assessment(item["assessment"]["value"])
        return _json_safe(
            {
                "session_id": session_id,
                "registration_id": registration_id,
                "view": view,
                "action_id": action_id,
                **result,
                "pagination": {
                    "scope": "live",
                    "order": "created_at_desc",
                    "byte_limit": PAGE_BYTES,
                },
            }
        )


def read_snapshot(st, tenant_id, snapshot_id, limit=100, cursor=""):
    tenant_id, snapshot_id = _uuid(tenant_id), _uuid(snapshot_id)
    _limit(limit)
    scope = [tenant_id, "snapshot", snapshot_id]
    with _read(st) as conn:
        snapshot = st.one(
            """SELECT id,sensor_id,registration_id,session_id,owner_user_id,revision,input_version,epoch_id,
                      closing_sequence,lifecycle,coverage,counts,risk_total,risk_max,item_count,sealed_at,created_at
               FROM session_snapshots WHERE tenant_id=$1 AND id=$2 AND sealed_at IS NOT NULL""",
            tenant_id,
            snapshot_id,
            conn=conn,
        )
        after = _decode(cursor, scope, ordinal=True)
        page = """SELECT i.ordinal,i.kind,i.source_id,i.body FROM session_snapshot_items i
                  JOIN session_snapshots s ON s.id=i.snapshot_id
                  WHERE s.tenant_id=$1 AND s.id=$2 AND s.sealed_at IS NOT NULL AND i.ordinal>$3
                  ORDER BY i.ordinal LIMIT $4"""
        args = (tenant_id, snapshot_id, after, limit + 1)
        metadata = st.many(
            f"SELECT p.ordinal AS id,octet_length(to_jsonb(p)::text) AS byte_size FROM ({page}) p ORDER BY p.ordinal",
            *args,
            conn=conn,
        )
        keys = next(_page_groups(metadata[:limit]), [])
        rows = (
            st.many(
                f"SELECT p.* FROM ({page}) p WHERE p.ordinal=ANY($5::bigint[]) ORDER BY p.ordinal",
                *args,
                keys,
                conn=conn,
            )
            if keys
            else []
        )
        next_cursor = (
            _encode(scope, rows[-1]["ordinal"])
            if rows and len(metadata) > len(rows)
            else ""
        )
        return _json_safe(
            {
                "snapshot": snapshot,
                "items": [customer_views.snapshot_item(item) for item in rows],
                "next_cursor": next_cursor,
                "pagination": {
                    "scope": "immutable",
                    "order": "ordinal_asc",
                    "byte_limit": PAGE_BYTES,
                },
            }
        )


def investigations(st, tenant_id, limit=50, cursor="", outcome="all", session_id=None):
    """List investigations, including reviews that did not publish a finding."""
    tenant_id = _uuid(tenant_id)
    session_id = _uuid(session_id) if session_id is not None else None
    require(outcome in ("all", "actionable_findings", "no_actionable_findings", "inconclusive", "pending",
                        "true_positive", "false_positive", "true_positive_non_malicious"),
            "invalid investigation outcome")
    scope = [tenant_id, "investigations", outcome, session_id]
    with _read(st) as conn:
        result = _page(
            st, conn,
            """SELECT q.* FROM (
               SELECT j.id,j.id AS job_id,j.state,j.snapshot_id,j.registration_id,s.id AS session_id,
                      j.created_at,j.completed_at,j.routing_reason,a.id AS report_attempt_id,
                      COALESCE(NULLIF(a.report->>'title',''),a.report->'findings'->0->>'title',
                        CASE WHEN j.state IN ('queued','running') THEN 'Session investigation'
                             ELSE 'Investigation report' END) AS title,
                      COALESCE(a.report->>'summary',
                        CASE WHEN j.state IN ('queued','running') THEN 'Investigation has not produced a report yet.'
                             ELSE 'The investigation ended without a completed assessment.' END) AS summary,
                      CASE WHEN j.state IN ('queued','running') THEN NULL
                           WHEN a.report->>'status'='finding' THEN 'actionable_findings'
                           WHEN a.report->>'status'='no_finding' THEN 'no_actionable_findings'
                           ELSE 'inconclusive' END AS outcome,
                      CASE WHEN j.state IN ('queued','running') THEN NULL
                           WHEN a.report->>'status'='finding' THEN 'true_positive'
                           WHEN a.report->>'status'='no_finding' THEN a.report->>'verdict'
                           ELSE NULL END AS verdict,
                      (SELECT f->>'severity' FROM jsonb_array_elements(COALESCE(a.report->'findings','[]'::jsonb)) f
                       ORDER BY array_position(ARRAY['critical','high','medium','low','info'],f->>'severity')
                       LIMIT 1) AS severity,
                      a.report->>'confidence' AS confidence,
                      COALESCE(a.report->'scope'->'subject',jsonb_build_object(
                        'name',u.name,'email',u.email,'reported_user',ag.username,
                        'hostname',ag.hostname,'ownership_verified',j.owner_user_id IS NOT NULL)) AS subject,
                      CASE WHEN j.session_id IS NOT NULL THEN
                        COALESCE(d.snapshot_id=j.snapshot_id,false) AND NOT EXISTS(
                          SELECT 1 FROM ordinary_session_input_dirty dirty
                          WHERE dirty.tenant_id=j.tenant_id AND dirty.session_id=j.session_id)
                      ELSE COALESCE(sf.snapshot_id=j.snapshot_id AND sf.failure_code=''
                             AND sf.status->>'snapshot_current'='true'
                             AND sf.lifecycle IN ('closed','incomplete')
                             AND (sf.next_evaluation_at IS NULL OR sf.next_evaluation_at>now()),false)
                           AND NOT EXISTS(SELECT 1 FROM session_input_dirty dirty
                             WHERE dirty.registration_id=j.registration_id)
                      END AS snapshot_current,
                      COALESCE(g.detector_config_version=j.detector_config_version,false) AS configuration_current
               FROM session_investigation_jobs j
               LEFT JOIN agent_sessions s ON s.tenant_id=j.tenant_id
                 AND (s.id=j.session_id OR s.registration_id=j.registration_id)
               LEFT JOIN agents ag ON ag.id=s.agent_id AND ag.tenant_id=j.tenant_id
               LEFT JOIN tenant_users u ON u.id=j.owner_user_id AND u.tenant_id=j.tenant_id
               LEFT JOIN ordinary_session_detection d ON d.session_id=j.session_id AND d.tenant_id=j.tenant_id
               LEFT JOIN session_finalizations sf ON sf.registration_id=j.registration_id AND sf.tenant_id=j.tenant_id
               LEFT JOIN tenant_session_detection_settings g ON g.tenant_id=j.tenant_id
               LEFT JOIN LATERAL (SELECT id,report FROM session_investigation_attempts a
                 WHERE a.job_id=j.id AND a.tenant_id=j.tenant_id ORDER BY ordinal DESC LIMIT 1) a ON true
               WHERE j.tenant_id=$1 AND ($2::uuid IS NULL OR s.id=$2)
               ) q WHERE $3='all' OR ($3='pending' AND q.outcome IS NULL) OR q.outcome=$3 OR q.verdict=$3""",
            (tenant_id, session_id, outcome), scope, limit, cursor,
        )
        return _json_safe(result)


def investigation(st, tenant_id, job_id, attempt_id=None):
    tenant_id, job_id = _uuid(tenant_id), _uuid(job_id)
    attempt_id = _uuid(attempt_id) if attempt_id is not None else None
    with _read(st) as conn:
        job = st.one(
            """SELECT j.id,j.id AS job_id,j.registration_id,j.snapshot_id,j.state,j.settings_version,
                      j.detector_config_version,j.configuration,j.routing_reason,j.created_at,j.completed_at,
                      s.revision AS snapshot_revision,
                      COALESCE(j.session_id,(SELECT a.id FROM agent_sessions a
                       WHERE a.tenant_id=j.tenant_id AND a.registration_id=j.registration_id)) AS session_id
               FROM session_investigation_jobs j JOIN session_snapshots s
                 ON s.id=j.snapshot_id AND s.tenant_id=j.tenant_id
                   AND s.registration_id IS NOT DISTINCT FROM j.registration_id
                   AND s.session_id IS NOT DISTINCT FROM j.session_id
               WHERE j.tenant_id=$1 AND j.id=$2""",
            tenant_id,
            job_id,
            conn=conn,
        )
        projection, _, config_version = _projection(
            st, tenant_id, job["registration_id"], conn, job["session_id"]
        )
        _job_freshness(job, projection, config_version)
        attempt_scope = "a.id=$3" if attempt_id is not None else "true"
        args = (
            (tenant_id, job_id, attempt_id)
            if attempt_id is not None
            else (tenant_id, job_id)
        )
        selected = st.many(
            f"""SELECT a.id,a.report FROM session_investigation_attempts a
                JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
                WHERE j.tenant_id=$1 AND j.id=$2 AND {attempt_scope}
                ORDER BY a.ordinal DESC LIMIT 1""",
            *args,
            conn=conn,
        )
        if attempt_id is not None:
            require(bool(selected), "no such investigation attempt", 404)
        report_attempt_id = selected[0]["id"] if selected else None
        report = selected[0]["report"] if selected else None
        report_generated_from_state = report is None and job["state"] not in ("queued", "running")
        if report_generated_from_state:
            from .session_investigator import terminal_report

            stored_job = st.one("SELECT * FROM session_investigation_jobs WHERE tenant_id=$1 AND id=$2",
                                tenant_id, job_id, conn=conn)
            stored_attempt = st.one(
                "SELECT * FROM session_investigation_attempts WHERE tenant_id=$1 AND id=$2",
                tenant_id, report_attempt_id, conn=conn,
            ) if report_attempt_id else None
            reason = (stored_job.get("result") or {}).get("reason") or job["state"]
            report = terminal_report(st, stored_job, stored_attempt, reason, conn)
        attempts = st.many(
            """SELECT a.id,a.ordinal,a.state,a.created_at,a.dispatched_at,a.completed_at,
                      a.reserved_tokens,a.reserved_cost_usd,a.actual_tokens,a.actual_cost_usd,a.runtime,
                      a.target_item_count,a.target_byte_count,a.target_chunk_count
               FROM session_investigation_attempts a JOIN session_investigation_jobs j
                 ON j.id=a.job_id AND j.tenant_id=a.tenant_id
               WHERE j.tenant_id=$1 AND j.id=$2 ORDER BY a.ordinal DESC LIMIT $3""",
            tenant_id,
            job_id,
            DETAIL_LIMIT,
            conn=conn,
        )
        attempt_count = st.scalar(
            """SELECT count(*) FROM session_investigation_attempts a
               JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
               WHERE j.tenant_id=$1 AND j.id=$2""",
            tenant_id,
            job_id,
            conn=conn,
        )
        reads = st.many(
            """SELECT r.id,r.step_id,r.tool_name,r.status,r.session_id,r.source_snapshot_id,
                      r.response_sha256,r.created_at
               FROM session_investigation_reads r JOIN session_investigation_attempts a ON a.id=r.attempt_id
               JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
               WHERE j.tenant_id=$1 AND j.id=$2 AND a.id=$3
               ORDER BY r.created_at DESC,r.id DESC LIMIT $4""",
            tenant_id,
            job_id,
            report_attempt_id,
            DETAIL_LIMIT,
            conn=conn,
        )
        read_count = st.scalar(
            """SELECT count(*) FROM session_investigation_reads r
               JOIN session_investigation_attempts a ON a.id=r.attempt_id
               JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
               WHERE j.tenant_id=$1 AND j.id=$2 AND a.id=$3""",
            tenant_id,
            job_id,
            report_attempt_id,
            conn=conn,
        )
        return _json_safe(
            {
                **job,
                "configuration": customer_views.detection_settings(job["configuration"]),
                "report_attempt_id": report_attempt_id,
                "report": customer_views.investigation_report(report),
                "report_generated_from_state": report_generated_from_state,
                "attempts": [customer_views.investigation_attempt(item) for item in reversed(attempts)],
                "attempt_count": attempt_count,
                "attempts_truncated": attempt_count > len(attempts),
                "reads": list(reversed(reads)),
                "read_count": read_count,
                "reads_truncated": read_count > len(reads),
            }
        )


def investigation_read(st, tenant_id, read_id):
    tenant_id, read_id = _uuid(tenant_id), _uuid(read_id)
    with _read(st) as conn:
        row = st.one(
                """SELECT r.id,j.id AS job_id,r.attempt_id,r.step_id,r.tool_name,r.status,r.created_at,
                      r.session_id,r.source_registration_id,r.source_sensor_id,r.source_snapshot_id,
                      r.response_sha256,r.response
               FROM session_investigation_reads r JOIN session_investigation_attempts a ON a.id=r.attempt_id
               JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
               WHERE j.tenant_id=$1 AND r.id=$2""",
                tenant_id,
                read_id,
                conn=conn,
            )
        return _json_safe(customer_views.retained_read(st, tenant_id, row, conn=conn))
