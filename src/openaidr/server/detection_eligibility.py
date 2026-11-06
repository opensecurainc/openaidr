"""Read-only explanations of retained selection decisions and worker readiness."""

from datetime import timedelta

from . import session_aggregation as aggregation
from .httpx import require


def availability(st, tenant_id, conn, settings=None, *, customer=False):
    read = aggregation.get_settings
    if customer:
        from .investigation_settings import read
    settings = settings if settings is not None else read(st, tenant_id, conn)
    workers = st.many(
        """SELECT last_seen_at,details FROM service_heartbeats
           WHERE service='detect' AND last_seen_at>now()-interval '90 seconds'
             AND (details->>'tenant_id' IS NULL OR details->>'tenant_id' IN ('',$1))
           ORDER BY last_seen_at DESC""", tenant_id, conn=conn,
    )
    scoped = [w for w in workers if w["details"].get("tenant_id") in ("", tenant_id)]
    enabled = [w for w in scoped if w["details"].get("session_detection_scheduling") is True]
    known = workers and len(scoped) == len(workers) and all(
        type(w["details"].get("session_detection_scheduling")) is bool for w in scoped
    )
    scheduling = True if enabled else False if known else None
    ready = any(
        w["details"].get("session_investigator", {}).get("ready") is True
        and (w["details"].get("session_investigator", {}).get("protocol_version") == 4 if customer else
             settings["model"] in w["details"].get("session_investigator", {}).get("supported_models", []))
        for w in enabled
    ) if enabled else None
    reason = ("tenant_disabled" if not settings["enabled"] else "worker_unavailable" if not workers
              else "scheduling_disabled" if scheduling is False else "readiness_unknown" if scheduling is None
              else "worker_unavailable" if not ready else "ready")
    return {
        "tenant_enabled": settings["enabled"], "scheduling_enabled": scheduling,
        "worker_ready": ready, "reason": reason,
        "checked_at": workers[0]["last_seen_at"] if workers else None,
    }


_SOURCE = """
SELECT s.id,s.started_at AS created_at,s.last_event_at,s.ended_at,s.product,
       a.hostname,a.username AS reported_user,sensor.disabled AS sensor_disabled,sensor.deleted_at,
       s.registration_id,r.assessment_mode,r.verified_at AS registration_verified_at,
       u.id AS owner_id,u.name AS owner_name,u.email AS owner_email,
       COALESCE(d.state,f.status) AS stored,
       COALESCE(d.updated_at,f.updated_at) AS evaluated_at,
       COALESCE(d.settings_version,f.settings_version) AS settings_version,
       COALESCE(d.next_evaluation_at,f.next_evaluation_at) AS next_evaluation_at,
       f.failure_code AS finalization_error,
       CASE WHEN s.registration_id IS NULL THEN
         EXISTS(SELECT 1 FROM ordinary_session_input_dirty dirty WHERE dirty.tenant_id=s.tenant_id AND dirty.session_id=s.id)
         ELSE EXISTS(SELECT 1 FROM session_input_dirty dirty WHERE dirty.registration_id=s.registration_id) END AS dirty,
       j.id AS job_id,j.state AS job_state
FROM agent_sessions s
JOIN agents a ON a.tenant_id=s.tenant_id AND a.id=s.agent_id
JOIN sensors sensor ON sensor.tenant_id=s.tenant_id AND sensor.id=s.sensor_id
LEFT JOIN session_registrations r ON r.tenant_id=s.tenant_id AND r.id=s.registration_id
LEFT JOIN detection_session_identities identity ON identity.tenant_id=s.tenant_id AND identity.session_id=s.id
LEFT JOIN tenant_users u ON u.tenant_id=s.tenant_id AND u.id=identity.owner_user_id AND u.status='active'
LEFT JOIN ordinary_session_detection d ON d.tenant_id=s.tenant_id AND d.session_id=s.id
LEFT JOIN session_finalizations f ON f.tenant_id=s.tenant_id AND f.registration_id=s.registration_id
LEFT JOIN session_investigation_jobs j ON j.tenant_id=s.tenant_id
  AND j.id=NULLIF(COALESCE(d.state,f.status)#>>'{routing,job_id}','')::uuid
  AND (j.session_id=s.id OR j.registration_id=s.registration_id)
WHERE s.tenant_id=$1
"""


def _assessment(row, settings, now):
    stored = row["stored"] or {}
    routing = stored.get("routing") or {}
    selection = stored.get("selection") or {}
    signals = selection.get("signals") or {}
    status, reason = "waiting", "evaluation_pending"
    if row["sensor_disabled"] or row["deleted_at"]:
        status, reason = "excluded", "sensor_unavailable"
    elif row["registration_id"] and row["assessment_mode"] != "inline":
        status, reason = "excluded", "legacy_session"
    elif row["registration_id"] and not (row["registration_verified_at"] and row["owner_id"]):
        status, reason = "excluded", "owner_unavailable"
    elif not settings["enabled"]:
        status, reason = "disabled", "tenant_disabled"
    elif row["finalization_error"]:
        status, reason = "unavailable", "evaluation_failed"
    elif (row["dirty"] or row["settings_version"] != settings["version"]
          or (row["next_evaluation_at"] is not None and row["next_evaluation_at"] <= now)):
        pass
    elif not row["evaluated_at"] or not routing:
        pass
    elif row["job_state"] in ("queued", "running"):
        status, reason = "selected", row["job_state"]
    elif row["job_state"] in ("completed", "inconclusive") or selection.get("reviewed_evidence"):
        status, reason = "reviewed", row["job_state"] or "reviewed_evidence"
    elif row["job_state"] in ("superseded", "cancelled", "failed"):
        status, reason = "waiting", "evaluation_pending"
    elif settings["selection_policy"] == "risk_budget" and (
        signals.get("outside_history_window") or row["last_event_at"] < now - timedelta(days=settings["history_days"])
    ):
        status, reason = "not_selected", "outside_history_window"
    elif routing.get("reason") in ("scheduling_disabled", "worker_unavailable"):
        # Selection can admit urgent risk or samples despite pending signals.
        status, reason = "eligible", routing["reason"]
    elif signals.get("pending_signals"):
        status, reason = "waiting", "pending_signals"
    elif stored.get("counts", {}).get("pending"):
        status, reason = "waiting", "pending_assessments"
    elif routing.get("status") == "waiting_coverage":
        status, reason = "waiting", routing.get("reason", "coverage_incomplete")
    elif routing.get("status") == "below_threshold":
        status, reason = "not_selected", routing.get("reason", "outside_selection_budget")
    return {
        "status": status, "reason": reason, "evaluated_at": row["evaluated_at"],
        "next_evaluation_at": row["next_evaluation_at"],
        "owner": {"id": row["owner_id"], "name": row["owner_name"], "email": row["owner_email"]} if row["owner_id"] else None,
        "history_available": bool(row["owner_id"] and not row["sensor_disabled"] and not row["deleted_at"]),
        "job_id": row["job_id"], "job_state": row["job_state"],
    }


def session(st, tenant_id, session_id, conn):
    settings = aggregation.get_settings(st, tenant_id, conn)
    now = st.scalar("SELECT now()", conn=conn)
    row = st.one(_SOURCE + " AND s.id=$2", tenant_id, session_id, conn=conn)
    return _assessment(row, settings, now)


def listing(st, tenant_id, range_name="30d", query="", limit=25, cursor="", *, customer=False):
    from .detection_pipeline import RANGES
    from .session_operator import _json_safe, _page, _read

    require(range_name in RANGES, "range must be 7d, 30d, or 90d")
    require(isinstance(query, str) and len(query) <= 200, "search must be at most 200 characters")
    require(type(limit) is int and 1 <= limit <= 100, "limit must be between 1 and 100")
    query = query.strip()
    with _read(st) as conn:
        read = aggregation.get_settings
        if customer:
            from .investigation_settings import read
        settings = read(st, tenant_id, conn)
        now = st.scalar("SELECT now()", conn=conn)
        # Search is literal and tenant scoped, including verified and reported identities.
        pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        result = _page(
            st, conn,
            _SOURCE + """ AND s.started_at>=$2 AND s.started_at<$3
              AND ($4='%%' OR a.hostname ILIKE $4 OR a.username ILIKE $4 OR u.name ILIKE $4
                   OR u.email ILIKE $4 OR s.id::text ILIKE $4)""",
            (tenant_id, now - timedelta(days=RANGES[range_name]), now, pattern),
            [tenant_id, "detection-eligibility", range_name, query], limit, cursor,
        )
        result["items"] = [{
            "id": row["id"], "started_at": row["created_at"], "last_event_at": row["last_event_at"],
            "product": row["product"], "hostname": row["hostname"], "reported_user": row["reported_user"],
            "eligibility": _assessment(row, settings, now),
        } for row in result["items"]]
        return _json_safe(result)
