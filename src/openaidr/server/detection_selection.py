"""Independent, tenant-scoped selection of sessions for bounded investigations."""

from decimal import Decimal
import re


def _benchmark_all(st, conn):
    if not getattr(st, "_benchmark_all_sessions", False):
        return False
    schemas = st.scalar("SELECT current_schemas(false)", conn=conn)
    if len(schemas) != 1 or not re.fullmatch(r"detection_benchmark_[0-9a-f]{32}", schemas[0]):
        raise ValueError("Investigator diagnostics require an isolated benchmark schema")
    return True


def record(st, tenant_id, session_id, settings, peak, high_actions, signature, conn):
    if not session_id:
        return
    st.execute(
        """INSERT INTO session_detection_signals(session_id,tenant_id,action_risk_threshold,peak,high_actions,evidence_signature)
           VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(session_id) DO UPDATE SET
             action_risk_threshold=EXCLUDED.action_risk_threshold,peak=EXCLUDED.peak,
             high_actions=EXCLUDED.high_actions,evidence_signature=EXCLUDED.evidence_signature,
             updated_at=clock_timestamp()""",
        session_id, tenant_id, settings["action_risk_threshold"], peak, high_actions, signature, conn=conn,
    )


def reviewed(st, tenant_id, session_id, signature, settings, conn):
    return st.scalar(
        """SELECT EXISTS(SELECT 1 FROM session_investigation_jobs j JOIN session_snapshots s ON s.id=j.snapshot_id
           LEFT JOIN agent_sessions a ON a.registration_id=j.registration_id AND a.tenant_id=j.tenant_id
           WHERE j.tenant_id=$1 AND COALESCE(j.session_id,a.id)=$2 AND j.state IN ('completed','inconclusive')
             AND EXISTS(SELECT 1 FROM session_investigation_attempts reviewed WHERE reviewed.job_id=j.id
                        AND reviewed.report->'coverage'->>'status'='complete')
             AND j.detector_config_version=$3 AND s.selection_signature=$4)""",
        tenant_id, session_id, settings["detector_config_version"], signature, conn=conn,
    )


def admit(st, job, settings, conn):
    """Caller holds the tenant admission lock. Count distinct actual selections."""
    if job["routing_reason"] == "benchmark":
        return _benchmark_all(st, conn)
    if job["routing_reason"] == "sample":
        return False
    if job["routing_reason"] == "urgent_risk":
        return True
    row = st.one(
        """WITH selected AS (
           SELECT DISTINCT COALESCE(j.session_id,s.id) AS id
           FROM session_investigation_jobs j
           LEFT JOIN agent_sessions s ON s.registration_id=j.registration_id AND s.tenant_id=j.tenant_id
           WHERE j.tenant_id=$1 AND j.attempts>0 AND j.routing_reason<>'urgent_risk'
             AND EXISTS(SELECT 1 FROM session_investigation_attempts a WHERE a.job_id=j.id
                        AND a.created_at>=now()-$2*interval '1 day')
         ), population AS (
           SELECT count(*) AS size FROM agent_sessions s
           LEFT JOIN session_finalizations f ON f.registration_id=s.registration_id AND f.tenant_id=s.tenant_id
           JOIN sensors sensor ON sensor.id=s.sensor_id AND sensor.tenant_id=s.tenant_id
             AND NOT sensor.disabled AND sensor.deleted_at IS NULL
           WHERE s.tenant_id=$1 AND (s.registration_id IS NULL OR EXISTS(
             SELECT 1 FROM session_registrations r JOIN tenant_users u
               ON u.id=r.owner_user_id AND u.tenant_id=r.tenant_id AND u.status='active'
             WHERE r.id=s.registration_id AND r.tenant_id=s.tenant_id
               AND r.assessment_mode='inline' AND r.verified_at IS NOT NULL))
             AND s.last_event_at>=now()-$2*interval '1 day'
             AND (s.ended_at IS NOT NULL OR s.last_event_at<=now()-$3*interval '1 second'
                  OR (f.lifecycle IN ('closed','incomplete')
                      AND NOT COALESCE((f.status#>>'{coverage,active_session}')::boolean,false)))
         ) SELECT (SELECT count(*) FROM selected) AS selected,
             ceil(size*$4::numeric/100) AS slots,
             EXISTS(SELECT 1 FROM selected WHERE id=COALESCE($5::uuid,
                 (SELECT id FROM agent_sessions WHERE tenant_id=$1 AND registration_id=$6))) AS reused
           FROM population""",
        job["tenant_id"], settings["history_days"], settings["idle_seconds"],
        Decimal(settings["investigation_percent"]), job.get("session_id"), job.get("registration_id"),
        conn=conn,
    )
    return row["reused"] or row["selected"] < row["slots"]


def select(st, tenant_id, session_id, settings, conn):
    return select_many(st, tenant_id, [session_id], settings, conn)[session_id]


def select_many(st, tenant_id, session_ids, settings, conn):
    """Rank distinct sessions that meet risk criteria, preserving urgent cases.

    The denominator is recent ended/idle sessions, including those with missing
    scores. Active urgent sessions are exceptions. A retrieved context session
    is never counted as selected. Scores remain ordinal severity measurements.
    """
    if _benchmark_all(st, conn):
        return {ident: {"reason": "benchmark", "signals": {"diagnostic": True}} for ident in session_ids}
    rows = st.many(
        """WITH population AS (
          SELECT s.*,u.id AS owner_user_id,
            s.ended_at IS NOT NULL OR s.last_event_at<=now()-$3*interval '1 second'
              OR (f.lifecycle IN ('closed','incomplete')
                  AND NOT COALESCE((f.status#>>'{coverage,active_session}')::boolean,false)) AS settled
          FROM agent_sessions s
          LEFT JOIN session_finalizations f ON f.registration_id=s.registration_id AND f.tenant_id=s.tenant_id
          JOIN sensors sensor ON sensor.id=s.sensor_id AND sensor.tenant_id=s.tenant_id
            AND NOT sensor.disabled AND sensor.deleted_at IS NULL
          LEFT JOIN detection_session_identities i ON i.session_id=s.id AND i.tenant_id=s.tenant_id
          LEFT JOIN tenant_users u ON u.id=i.owner_user_id AND u.tenant_id=i.tenant_id AND u.status='active'
          WHERE s.tenant_id=$1 AND s.last_event_at>=now()-$2*interval '1 day'
            AND (s.registration_id IS NULL OR (u.id IS NOT NULL AND EXISTS(
              SELECT 1 FROM session_registrations r WHERE r.id=s.registration_id AND r.tenant_id=s.tenant_id
                AND r.assessment_mode='inline' AND r.verified_at IS NOT NULL)))
        ), signals AS (
          SELECT p.id,p.owner_user_id,p.last_event_at,p.settled,g.peak,
            COALESCE(g.high_actions,0) AS high_actions
          FROM population p LEFT JOIN session_detection_signals g ON g.session_id=p.id
            AND g.tenant_id=p.tenant_id AND g.action_risk_threshold=$4
        ), history AS (
          SELECT owner_user_id,sum(high_actions) AS high_actions,
            count(*) FILTER(WHERE high_actions>0) AS sessions,
            (array_agg(id ORDER BY last_event_at DESC,id DESC) FILTER(WHERE high_actions>0))[1] AS latest
          FROM signals WHERE owner_user_id IS NOT NULL GROUP BY owner_user_id
        ), candidates AS (
          SELECT s.*,COALESCE(h.high_actions,0) AS user_high_actions,
            COALESCE(h.sessions,0) AS user_sessions,
            CASE WHEN s.peak>=$5 THEN 'urgent_risk'
              WHEN s.settled AND h.latest=s.id AND h.high_actions>=$7 AND h.sessions>=2 THEN 'user_pattern'
              WHEN s.settled AND s.high_actions>=$6 THEN 'session_risk' END AS reason
          FROM signals s LEFT JOIN history h ON h.owner_user_id=s.owner_user_id
        ), ranked AS (
          SELECT id,row_number() OVER(ORDER BY peak DESC,high_actions DESC,last_event_at DESC,id) AS rank
          FROM candidates WHERE reason IN ('session_risk','user_pattern')
        ) SELECT c.*,r.rank,
          (SELECT count(*) FROM population WHERE settled) AS population_count,
          (SELECT count(*) FROM population p LEFT JOIN session_detection_signals g ON g.session_id=p.id
            LEFT JOIN (SELECT session_id,max(created_at) AS changed_at FROM ordinary_session_input_dirty
                       WHERE tenant_id=$1 GROUP BY session_id) d ON d.session_id=p.id
            WHERE p.settled AND (g.session_id IS NULL OR g.action_risk_threshold<>$4
              OR d.changed_at>g.updated_at
              OR EXISTS(SELECT 1 FROM session_input_dirty d WHERE d.registration_id=p.registration_id AND d.created_at>g.updated_at))) AS pending_signals,
          ceil((SELECT count(*) FROM population WHERE settled)*$8::numeric/100) AS risk_slots
          FROM candidates c LEFT JOIN ranked r ON r.id=c.id WHERE c.id=ANY($9::uuid[])""",
        tenant_id, settings["history_days"], settings["idle_seconds"],
        settings["action_risk_threshold"], settings["urgent_risk_threshold"],
        settings["session_high_risk_actions"], settings["user_high_risk_actions"],
        Decimal(settings["investigation_percent"]), session_ids,
        conn=conn,
    )
    result = {ident: {"reason": None, "signals": {"outside_history_window": True}} for ident in session_ids}
    for row in rows:
        reason = row["reason"]
        if reason != "urgent_risk" and (row["rank"] is None or row["rank"] > row["risk_slots"]):
            reason = None
        if reason != "urgent_risk" and row["pending_signals"]:
            reason = None
        result[row["id"]] = {
            "reason": reason,
            "signals": {"peak": str(row["peak"]) if row["peak"] is not None else None,
                        "high_risk_actions": row["high_actions"], "user_high_risk_actions": int(row["user_high_actions"]),
                        "user_sessions": row["user_sessions"], "population_sessions": row["population_count"],
                        "pending_signals": row["pending_signals"],
                        "risk_rank": row["rank"], "risk_slots": int(row["risk_slots"])},
        }
    return result
