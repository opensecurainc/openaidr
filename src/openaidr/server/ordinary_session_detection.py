"""Risk-based investigation of ordinary captured sessions, outside hook execution."""

from datetime import datetime, timedelta
from contextlib import nullcontext
from decimal import Decimal
import time

from psycopg.errors import LockNotAvailable, QueryCanceled, SerializationFailure
from psycopg.types.json import Jsonb

from . import detection_history, detection_selection, session_aggregation as aggregation, session_ownership
from .httpx import APIError
from .store import NotFound, new_id


def authorize(st, job, conn):
    bound_owner = job.get("configuration", {}).get("history_owner_user_id")
    if bound_owner and job.get("owner_user_id") != bound_owner:
        raise NotFound("investigation owner is unavailable")
    if job.get("owner_user_id"):
        return detection_history.authorize(st, job, job["session_id"], conn, window=False)
    session_ownership._active_sensor(
        st, {"tenant_id": job["tenant_id"], "id": job["sensor_id"]}, conn,
    )
    return st.one(
        """SELECT * FROM agent_sessions WHERE tenant_id=$1 AND sensor_id=$2 AND id=$3
           AND registration_id IS NULL FOR KEY SHARE""",
        job["tenant_id"], job["sensor_id"], job["session_id"], conn=conn,
    )


def current(st, job, settings, conn):
    return bool(settings["enabled"]
        and job["detector_config_version"] == settings["detector_config_version"]
        and st.scalar(
            """SELECT EXISTS(SELECT 1 FROM ordinary_session_detection d
                 JOIN session_snapshots s ON s.id=d.snapshot_id AND s.tenant_id=d.tenant_id
                 WHERE d.tenant_id=$1 AND d.session_id=$2 AND d.snapshot_id=$3
                   AND s.session_id=d.session_id AND s.input_version=d.input_version
                   AND d.settings_version=$4 AND d.state->>'lifecycle'='incomplete'
                   AND NOT EXISTS(SELECT 1 FROM ordinary_session_input_dirty i
                                  WHERE i.tenant_id=d.tenant_id AND i.session_id=d.session_id))""",
            job["tenant_id"], job["session_id"], job["snapshot_id"], settings["version"], conn=conn,
        ))


def _risk(st, session, conn, action_threshold=70):
    try:
        from openaidr_api_client.contracts.service_guardrail import KINDS
    except ImportError:
        from openaidr_api_client.contracts.guardrail import KINDS

    # Copies carrying the same hook assessment, logical action, or native tool
    # call contribute once. Tool outputs are a separate scoring boundary.
    return st.one(
        """WITH actions AS (
             SELECT COALESCE('hook:'||NULLIF(risk->>'hook_check_id',''),
                       'logical:'||NULLIF(body->'evidence'->>'logical_id',''),
                       CASE WHEN kind IN ('tool.call','command','file.read','file.write','network','tool.result')
                         THEN CASE WHEN kind='tool.result' THEN 'output:' ELSE 'tool:' END
                              ||NULLIF(body->'tool'->>'call_id','') END,
                       'event:'||id::text) AS action,
                    CASE WHEN risk->>'status'='scored' AND jsonb_typeof(risk->'score')='number'
                         THEN CASE WHEN (risk->>'score')::numeric BETWEEN 0 AND 100
                              THEN (risk->>'score')::numeric END END AS score,
                    COALESCE(risk->>'status'='pending',false) AS pending
             FROM events WHERE tenant_id=$1 AND session_id=$2 AND kind=ANY($3)
           ), unique_actions AS (
             SELECT action,max(score) AS score,bool_or(pending) AS pending FROM actions GROUP BY action
           ) SELECT count(*) AS logical_targets,count(score) AS assessed,
                    count(*) FILTER(WHERE score IS NULL AND pending) AS pending,
                    count(*) FILTER(WHERE score IS NULL AND NOT pending) AS missing_assessments,
                    sum(score) AS risk_total,max(score) AS risk_max,
                    count(*) FILTER(WHERE score>=$4) AS high_actions,
                    md5(COALESCE(string_agg(action||':'||score::text,',' ORDER BY action) FILTER(WHERE score>=$4),'')) AS selection_signature
                    FROM unique_actions""",
        session["tenant_id"], session["id"], list(KINDS), action_threshold, conn=conn,
    )


def _snapshot(st, session, state, version, revision, conn):
    ident = new_id()
    st.execute(
        """INSERT INTO session_snapshots(id,tenant_id,sensor_id,session_id,revision,input_version,
                   owner_user_id,selection_signature,
                   lifecycle,coverage,counts,risk_total,risk_max)
           VALUES($1,$2,$3,$4,$5,$6,$11,$12,'incomplete',$7,$8,$9,$10)""",
        ident, session["tenant_id"], session["sensor_id"], session["id"], revision, version,
        Jsonb(state["coverage"]), Jsonb(state["counts"]), state["risk_total"], state["risk_max"], session.get("owner_user_id"), state["selection_signature"], conn=conn,
    )
    # Copy in the same repeatable-read transaction as scoring. The SQL copy
    # retains full captured bodies without loading a session into Python memory.
    count = st.execute(
        """INSERT INTO session_snapshot_items(snapshot_id,ordinal,kind,source_id,body)
           SELECT $1,row_number() OVER(ORDER BY evidence_stream COLLATE "C",evidence_sequence,
                         evidence_part,time,id,item_kind),item_kind,id,captured
           FROM (
             SELECT e.*, 'observation' AS item_kind,body AS captured
             FROM events e WHERE tenant_id=$2 AND session_id=$3 AND kind<>'sensor'
             UNION ALL
             SELECT e.*, 'event_assessment',jsonb_build_object('event_id',id,'risk',risk,
               'company_policy',(SELECT h.risk_settings->'company_policy' FROM ordinary_hook_checks h
                 WHERE h.tenant_id=e.tenant_id AND h.sensor_id=e.sensor_id
                   AND h.id=CASE WHEN e.risk->>'hook_check_id'
                     ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
                     THEN (e.risk->>'hook_check_id')::uuid END))
             FROM events e WHERE tenant_id=$2 AND session_id=$3 AND kind<>'sensor' AND risk IS NOT NULL
           ) evidence""",
        ident, session["tenant_id"], session["id"], conn=conn,
    )
    st.execute(
        "UPDATE session_snapshots SET item_count=$2,sealed_at=clock_timestamp() WHERE id=$1",
        ident, count, conn=conn,
    )
    return ident


def _retention_epoch(st, tenant_id, conn):
    # Lock existing policy rows against retirement. A first policy inserted after
    # the repeatable-read snapshot is invisible, so absence disables reuse.
    rows = st.many("SELECT last_cleanup_at FROM tenant_telemetry_retention WHERE tenant_id=$1 FOR SHARE",
                   tenant_id, conn=conn)
    retired_at = rows[0]["last_cleanup_at"] if rows else None
    return bool(rows), retired_at.isoformat() if retired_at else None


def _cached_evidence(prior, dirty, settings, retention):
    cached = prior["state"].get("evidence_summary") if prior else None
    if (retention[0] and prior and not dirty and prior["settings_version"] == settings["version"]
            and cached and cached.get("version") == 1 and cached.get("retired_at") == retention[1]):
        return cached
    return None


class _ChangedEvidence(Exception):
    pass


def finalize(st, tenant_id, session_id, *, scheduling_enabled=False, worker_ready=False, supported_models=None, protocol_version=1,
             _conn=None, _deadline=None, _selection=None):
    aggregation._check_job_protocol(protocol_version)
    deadline = _deadline if _deadline is not None else time.monotonic() + 15
    with (st.transaction() if _conn is None else nullcontext(_conn)) as conn:
        if _conn is None:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            conn.execute("SET LOCAL lock_timeout='1s'")
        st = aggregation._FinalizationStore(st, deadline)
        if not st.scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))",
                         "ordinary-session-detection:" + session_id, conn=conn):
            return None
        session = st.one(
            "SELECT * FROM agent_sessions WHERE tenant_id=$1 AND id=$2 AND registration_id IS NULL",
            tenant_id, session_id, conn=conn,
        )
        authorize(st, {**session, "session_id": session_id}, conn)
        identity = detection_history.owner(st, tenant_id, session_id, conn)
        session["owner_user_id"] = identity["owner_user_id"] if identity else None
        if identity:
            authorize(st, {**session, "session_id": session_id}, conn)
        settings = aggregation._job_settings(st, tenant_id, conn, protocol_version)
        prior = st.many("SELECT * FROM ordinary_session_detection WHERE session_id=$1", session_id, conn=conn)
        prior = prior[0] if prior else None
        dirty = st.one(
            "SELECT count(*) AS count,max(created_at) AS changed_at FROM ordinary_session_input_dirty WHERE tenant_id=$1 AND session_id=$2",
            tenant_id, session_id, conn=conn,
        )
        now = st.scalar("SELECT now()", conn=conn)
        version = (prior["input_version"] if prior else 0) + int(bool(dirty["count"]) or not prior)
        revision = prior["revision"] if prior else 0
        snapshot_id = prior["snapshot_id"] if prior and not dirty["count"] else None
        retention = _retention_epoch(st, tenant_id, conn)
        cached = _cached_evidence(prior, dirty["count"], settings, retention)
        unchanged = cached is not None
        if _selection is not None and not unchanged:
            raise _ChangedEvidence
        if unchanged:
            previous = prior["state"]
            totals = {name: previous["counts"][name] for name in
                      ("logical_targets", "assessed", "pending", "missing_assessments")}
            risk_total = Decimal(previous["risk_total"]) if previous["risk_total"] is not None else None
            risk_max = Decimal(previous["risk_max"]) if previous["risk_max"] is not None else None
            signature, high_actions = previous["selection_signature"], cached["high_actions"]
            evidence_gaps = cached["gaps"]
        else:
            totals = _risk(st, session, conn, settings["action_risk_threshold"])
            risk_total, risk_max = totals.pop("risk_total"), totals.pop("risk_max")
            signature, high_actions = totals.pop("selection_signature"), totals.pop("high_actions")
            gaps = st.many(
                """SELECT DISTINCT gap FROM events e CROSS JOIN LATERAL jsonb_array_elements_text(
                     CASE WHEN jsonb_typeof(e.body->'evidence'->'gaps')='array'
                          THEN e.body->'evidence'->'gaps' ELSE '[]'::jsonb END) gap
                   WHERE e.tenant_id=$1 AND e.session_id=$2 AND e.kind<>'sensor'""",
                tenant_id, session_id, conn=conn,
            )
            evidence_gaps = sorted({row["gap"] for row in gaps if row["gap"] in aggregation.GAPS})
        if prior and prior["state"].get("selection_signature") != signature and not dirty["count"]:
            version += 1
            snapshot_id = None
        if not unchanged:
            detection_selection.record(st, tenant_id, session_id, settings, risk_max, high_actions, signature, conn)
        counts = {**dict.fromkeys(("unavailable", "invalid_assessments", "blocked", "pending_approvals",
                                 "approved_unconsumed", "unreported_outcomes", "uncertain_outcomes"), 0), **totals}
        last_activity = session["last_event_at"]
        idle_at = last_activity + timedelta(seconds=settings["idle_seconds"] or 300)
        # Recently received late records get a delivery grace period even if
        # their event timestamps predate the session's recorded end.
        received_at = dirty["changed_at"] or (datetime.fromisoformat(prior["state"]["last_received_at"]) if prior else now)
        grace_at = received_at + timedelta(seconds=settings["delivery_grace_seconds"] or 0)
        settled = (session["ended_at"] is not None or now >= idle_at) and now >= grace_at and not counts["pending"]
        selection = None
        if settings["enabled"] and settings["selection_policy"] == "risk_budget":
            selection = _selection if _selection is not None else detection_selection.select(st, tenant_id, session_id, settings, conn)
            if detection_selection.reviewed(st, tenant_id, session_id, signature, settings, conn):
                selection["reason"] = None
                selection["reviewed_evidence"] = True
        urgent = bool(selection and selection["reason"] == "urgent_risk")
        ready = settled or urgent
        next_at = None if settled else max(now + timedelta(seconds=5), grace_at,
                                         idle_at if session["ended_at"] is None else now)
        coverage = {
            "status": "incomplete", "scope": "captured_session",
            "gaps": [] if identity else ["unverified_history"],
            "delivery": {"status": "unknown", "reasons": ["no_delivery_manifest"]},
            "content": {"status": "unknown", "reasons": ["captured_evidence_only"]},
            "assessment": {"status": "complete" if counts["assessed"] == counts["logical_targets"] else "incomplete",
                           "reasons": [] if counts["assessed"] == counts["logical_targets"] else ["missing_assessments"]},
            "execution": {"status": "unknown", "reasons": ["reported_evidence_only"]},
        }
        coverage["gaps"] = sorted(set(coverage["gaps"]) | set(evidence_gaps))
        routing = {"status": "disabled", "reason": "tenant_disabled", "job_id": None,
                   "settings_version": settings["version"], "detector_config_version": settings["detector_config_version"]}
        state = {
            "lifecycle": "incomplete" if ready else "active", "risk_total": str(risk_total) if risk_total is not None else None,
            "last_received_at": received_at.isoformat(),
            "risk_max": str(risk_max) if risk_max is not None else None, "counts": counts, "coverage": coverage,
            "last_activity_at": last_activity.isoformat(), "closing_at": session["ended_at"].isoformat() if session["ended_at"] else None,
            "next_evaluation_at": next_at.isoformat() if next_at else None, "last_sequence": 0, "closing_sequence": None,
            "delivery": {"received": 0, "expected": None, "complete": False, "gaps": ["unverified_history"]},
            "routing": routing,
            "selection_signature": signature,
            "evidence_summary": {"version": 1, "retired_at": retention[1],
                                 "high_actions": high_actions, "gaps": evidence_gaps},
        }
        if selection:
            state["selection"] = selection
        reason = selection["reason"] if selection else "risk_threshold"
        if settings["enabled"]:
            if not ready:
                routing.update(status="waiting_coverage", reason="session_active")
            elif (selection and not reason) or (not selection and (risk_total is None or risk_total <= Decimal(settings["risk_threshold"]))):
                routing.update(status="below_threshold", reason="outside_selection_budget" if selection else "threshold_not_exceeded")
                if selection:
                    finished = selection.get("reviewed_evidence") or selection["signals"].get("outside_history_window")
                    next_at = None if finished else now + timedelta(seconds=60)
                    state["next_evaluation_at"] = next_at.isoformat() if next_at else None
            else:
                if snapshot_id is None:
                    revision += 1
                    snapshot_id = _snapshot(st, session, state, version, revision, conn)
                if not scheduling_enabled:
                    routing.update(reason="scheduling_disabled")
                elif (not aggregation._jobs_allowed(st, tenant_id, conn, protocol_version) or not worker_ready
                      or (protocol_version == 1 and supported_models is not None and settings["model"] not in supported_models)):
                    routing.update(status="waiting_worker", reason="worker_unavailable")
                else:
                    job = st.one(
                        """INSERT INTO session_investigation_jobs(id,tenant_id,sensor_id,session_id,snapshot_id,owner_user_id,
                                  detector_config_version,settings_version,configuration,routing_reason,protocol_version)
                           VALUES($1,$2,$3,$4,$5,$10,$6,$7,$8,$9,$11)
                           ON CONFLICT(snapshot_id,detector_config_version) DO UPDATE SET id=session_investigation_jobs.id
                           RETURNING id,state,protocol_version""",
                        new_id(), tenant_id, session["sensor_id"], session_id, snapshot_id,
                        settings["detector_config_version"], settings["version"],
                        Jsonb({**aggregation._stored(settings), "history_owner_user_id": session.get("owner_user_id")}),
                        reason, session.get("owner_user_id"), protocol_version, conn=conn,
                    )
                    aggregation.require(job["protocol_version"] == protocol_version, "retained investigation contract conflict", 409)
                    routing.update(status=job["state"], reason=reason, job_id=job["id"])
                if routing["status"] in ("disabled", "waiting_worker"):
                    next_at = now + timedelta(seconds=30)
                    state["next_evaluation_at"] = next_at.isoformat()
        st.execute(
            """UPDATE session_investigation_jobs SET state='superseded',completed_at=clock_timestamp()
               WHERE tenant_id=$1 AND session_id=$2 AND state='queued'
                 AND (snapshot_id IS DISTINCT FROM $3::uuid OR detector_config_version<>$4)""",
            tenant_id, session_id, snapshot_id, settings["detector_config_version"], conn=conn,
        )
        st.execute(
            """INSERT INTO ordinary_session_detection(session_id,tenant_id,input_version,revision,snapshot_id,
                       settings_version,state,next_evaluation_at)
               VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(session_id) DO UPDATE SET
                 input_version=EXCLUDED.input_version,revision=EXCLUDED.revision,snapshot_id=EXCLUDED.snapshot_id,
                 settings_version=EXCLUDED.settings_version,state=EXCLUDED.state,
                 next_evaluation_at=EXCLUDED.next_evaluation_at,updated_at=clock_timestamp()""",
            session_id, tenant_id, version, revision, snapshot_id, settings["version"], Jsonb(state), next_at, conn=conn,
        )
        # Repeatable read deletes only visible wakeups, including when another
        # transaction allocated its sequence earlier but committed during copy.
        st.execute("DELETE FROM ordinary_session_input_dirty WHERE tenant_id=$1 AND session_id=$2",
                   tenant_id, session_id, conn=conn)
        return {**state, "snapshot_id": snapshot_id}


def _finalize_unchanged(st, candidates, options):
    """Return handled IDs; remaining work keeps its individual time budget."""
    tenant_id = candidates[0]["tenant_id"]
    ids = sorted(candidate["session_id"] for candidate in candidates)
    deadline = time.monotonic() + 15
    try:
        with st.transaction() as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            conn.execute("SET LOCAL lock_timeout='1s'")
            bounded = aggregation._FinalizationStore(st, deadline)
            settings = aggregation._job_settings(bounded, tenant_id, conn, options.get("protocol_version", 1))
            if not settings["enabled"] or settings["selection_policy"] != "risk_budget":
                return set()
            retention = _retention_epoch(bounded, tenant_id, conn)
            rows = bounded.many(
                """SELECT d.*,EXISTS(SELECT 1 FROM ordinary_session_input_dirty i
                       WHERE i.tenant_id=d.tenant_id AND i.session_id=d.session_id) AS dirty
                   FROM ordinary_session_detection d WHERE d.tenant_id=$1 AND d.session_id=ANY($2::uuid[])""",
                tenant_id, ids, conn=conn,
            )
            if len(rows) != len(ids) or any(_cached_evidence(row, row["dirty"], settings, retention) is None for row in rows):
                return set()
            # Keep lock ordering stable across workers; a busy session remains
            # due for the next pass. No evidence or signal rows change here.
            available = [ident for ident in ids if bounded.scalar(
                "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))",
                "ordinary-session-detection:" + ident, conn=conn,
            )]
            if not available:
                return set(ids)
            selections = detection_selection.select_many(bounded, tenant_id, available, settings, conn)
            if any(selections[row["session_id"]]["reason"] and not row["snapshot_id"]
                   for row in rows if row["session_id"] in selections):
                # Evidence copying must retain its full per-session budget.
                return set()
            handled = set(ids) - set(available)
            for ident in available:
                try:
                    with conn.transaction():
                        finalize(st, tenant_id, ident, **options, _conn=conn, _deadline=deadline, _selection=selections[ident])
                except aggregation._FinalizationLimit:
                    break
                except (NotFound, QueryCanceled, LockNotAvailable, SerializationFailure):
                    if time.monotonic() >= deadline:
                        break
                except APIError as exc:
                    if exc.status not in (403, 404):
                        raise
                handled.add(ident)
            return handled
    except _ChangedEvidence:
        # Roll back the batch and use fresh individual transactions if an input
        # no longer qualifies for shared selection.
        return set()
    except (QueryCanceled, LockNotAvailable, SerializationFailure, aggregation._FinalizationLimit):
        return set()


def finalize_pending(st, tenant_id=None, *, limit=10, **options):
    aggregation._check_job_protocol(options.get("protocol_version", 1))
    candidates = st.many(
        """WITH pending AS (
             SELECT tenant_id,session_id FROM ordinary_session_input_dirty WHERE ($1::uuid IS NULL OR tenant_id=$1)
             UNION
             SELECT d.tenant_id,d.session_id FROM ordinary_session_detection d
             LEFT JOIN tenant_session_detection_settings g ON g.tenant_id=d.tenant_id
             WHERE ($1::uuid IS NULL OR d.tenant_id=$1)
               AND (d.next_evaluation_at<=clock_timestamp() OR d.settings_version<>COALESCE(g.version,0))
           ) SELECT p.*,COALESCE(d.state->'evidence_summary'->>'version'='1',false)
               AND NOT EXISTS(SELECT 1 FROM ordinary_session_input_dirty i
                   WHERE i.tenant_id=p.tenant_id AND i.session_id=p.session_id) AS cached
             FROM pending p JOIN agent_sessions s ON s.id=p.session_id AND s.tenant_id=p.tenant_id
             JOIN tenants t ON t.id=p.tenant_id AND t.status='active'
             JOIN sensors n ON n.id=s.sensor_id AND n.tenant_id=s.tenant_id AND NOT n.disabled AND n.deleted_at IS NULL
             LEFT JOIN ordinary_session_detection d ON d.session_id=s.id
             WHERE s.registration_id IS NULL
               AND (d.updated_at IS NULL OR d.updated_at<clock_timestamp()-interval '5 seconds')
             ORDER BY EXISTS(SELECT 1 FROM ordinary_session_input_dirty i
                         WHERE i.tenant_id=p.tenant_id AND i.session_id=p.session_id) DESC,
                      d.updated_at NULLS FIRST,p.session_id LIMIT $2""",
        tenant_id, limit,
    )
    index = 0
    while index < len(candidates):
        candidate = candidates[index]
        end = index + 1
        handled = set()
        if candidate["cached"]:
            while end < min(len(candidates), index + 10) and candidates[end]["cached"] and candidates[end]["tenant_id"] == candidate["tenant_id"]:
                end += 1
            if end - index > 1:
                handled = _finalize_unchanged(st, candidates[index:end], options)
        for candidate in candidates[index:end]:
            if candidate["session_id"] in handled:
                continue
            try:
                finalize(st, candidate["tenant_id"], candidate["session_id"], **options)
            except (NotFound, QueryCanceled, LockNotAvailable, SerializationFailure, aggregation._FinalizationLimit):
                continue
            except APIError as exc:
                if exc.status not in (403, 404):
                    raise
        index = end
    return len(candidates)
