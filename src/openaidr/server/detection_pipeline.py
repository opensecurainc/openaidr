"""Tenant-scoped progress for captured sessions and retained investigations."""

from datetime import timedelta

from .session_aggregation import get_settings


RANGES = {"7d": 7, "30d": 30, "90d": 90}


def overview(st, tenant_id, range_name="30d", *, customer=False):
    if range_name not in RANGES:
        raise ValueError("range must be 7d, 30d, or 90d")
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        until = st.scalar("SELECT now()", conn=conn)
        since = until - timedelta(days=RANGES[range_name])
        counts = st.one(
            """WITH cohort AS MATERIALIZED (
                   SELECT s.id,s.registration_id FROM agent_sessions s
                   LEFT JOIN session_registrations r ON s.registration_id=r.id AND s.tenant_id=r.tenant_id
                   WHERE s.tenant_id=$1 AND (s.registration_id IS NULL OR r.assessment_mode='inline')
                     AND s.started_at>=$2 AND s.started_at<$3
               ), scores AS (
                   SELECT c.id,count(*) AS actions
                   FROM inline_guardrail_events e JOIN cohort c ON c.registration_id=e.registration_id
                   WHERE e.tenant_id=$1 AND e.status='scored' AND e.completed_at<$3
                     AND CASE WHEN jsonb_typeof(e.assessment->'score')='number'
                         THEN (e.assessment->>'score')::numeric BETWEEN 0 AND 100 ELSE false END
                   GROUP BY c.id
                   UNION ALL
                   SELECT c.id,(d.state->'counts'->>'assessed')::bigint AS actions
                   FROM ordinary_session_detection d JOIN cohort c ON c.id=d.session_id
                   WHERE d.tenant_id=$1 AND d.updated_at<$3 AND (d.state->'counts'->>'assessed')::bigint>0
               ), eligible AS MATERIALIZED (
                   SELECT s.id,c.id AS session_id FROM session_snapshots s
                   JOIN cohort c ON c.registration_id=s.registration_id
                   WHERE s.tenant_id=$1 AND s.created_at<$3 AND s.sealed_at<$3
                     AND s.lifecycle='closed' AND s.coverage->>'status'='complete'
                     AND s.risk_total IS NOT NULL
                   UNION ALL
                   SELECT d.snapshot_id,c.id FROM ordinary_session_detection d JOIN cohort c ON c.id=d.session_id
                   WHERE d.tenant_id=$1 AND d.updated_at<$3 AND d.state->>'lifecycle'='incomplete'
                     AND d.state->>'risk_total' IS NOT NULL
               ), jobs AS MATERIALIZED (
                   SELECT j.id,c.id AS session_id,j.state,j.completed_at,j.snapshot_id,j.routing_reason,
                     (SELECT a.report->>'status' FROM session_investigation_attempts a
                      WHERE a.job_id=j.id AND a.tenant_id=j.tenant_id ORDER BY a.ordinal DESC LIMIT 1) AS report_status
                   FROM session_investigation_jobs j JOIN cohort c ON c.registration_id=j.registration_id OR c.id=j.session_id
                   WHERE j.tenant_id=$1 AND j.created_at<$3
               ), alerts AS (
                   SELECT j.session_id,f.id FROM findings f JOIN jobs j ON j.id=f.investigation_job_id
                   WHERE f.tenant_id=$1 AND f.created_at<$3
               ) SELECT
                   COALESCE((SELECT sum(actions) FROM scores),0)::bigint AS actions_scored,
                   (SELECT count(*) FROM scores) AS sessions_scored,
                   (SELECT count(DISTINCT session_id) FROM jobs
                    WHERE state='completed' AND completed_at<$3) AS sessions_inspected,
                   (SELECT count(DISTINCT session_id) FROM alerts) AS sessions_with_alerts,
                   (SELECT count(*) FROM alerts) AS alerts,
                   (SELECT count(*) FROM jobs WHERE state NOT IN ('queued','running')) AS reports,
                   (SELECT count(*) FROM jobs WHERE state NOT IN ('queued','running') AND report_status='finding') AS actionable_reports,
                   (SELECT count(*) FROM jobs WHERE state NOT IN ('queued','running') AND report_status='no_finding') AS no_finding_reports,
                   (SELECT count(*) FROM jobs WHERE state NOT IN ('queued','running')
                     AND report_status IS DISTINCT FROM 'finding' AND report_status IS DISTINCT FROM 'no_finding') AS inconclusive_reports,
                   (SELECT count(*) FROM jobs WHERE state IN ('queued','running')) AS pending_investigations,
                   (SELECT count(DISTINCT session_id) FROM jobs) AS sessions_selected,
                   (SELECT count(DISTINCT session_id) FROM eligible) AS sessions_eligible,
                   (SELECT count(DISTINCT j.session_id) FROM jobs j
                    JOIN eligible e ON e.id=j.snapshot_id AND e.session_id=j.session_id
                    WHERE j.routing_reason IN ('risk_threshold','session_risk','user_pattern','urgent_risk')) AS sessions_escalated""",
            tenant_id, since, until, conn=conn,
        )
        read = get_settings
        if customer:
            from .investigation_settings import read
        settings = read(st, tenant_id, conn)
        from .detection_eligibility import availability

        readiness = availability(st, tenant_id, conn, settings, customer=customer)
        criteria = {key: settings[key] for key in (
            "action_risk_threshold", "urgent_risk_threshold", "session_high_risk_actions",
            "user_high_risk_actions", "idle_seconds", "delivery_grace_seconds",
            "risk_threshold", "gap_policy", "gap_wait_seconds", "max_concurrent",
            "hourly_attempts",
        )}
    return {"range": range_name, "since": since, "until": until, **counts,
            "selection_policy": settings["selection_policy"],
            "investigation_percent": settings["investigation_percent"],
            "sample_percent": settings["sample_percent"], "history_days": settings["history_days"],
            "availability": readiness, "criteria": criteria}
