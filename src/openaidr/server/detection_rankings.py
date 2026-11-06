"""Read-only comparison of observed risk with configured selection thresholds."""

from datetime import timedelta

from .httpx import require
from .session_aggregation import get_settings
from .session_operator import _decode, _encode, _json_safe, _read


def listing(st, tenant_id, group="sessions", band="all", limit=25, cursor=""):
    require(group in ("sessions", "users"), "group must be sessions or users")
    require(band in ("all", "meets", "below", "unknown"), "invalid threshold band")
    require(type(limit) is int and 1 <= limit <= 100, "limit must be 1 to 100")
    with _read(st) as conn:
        settings = get_settings(st, tenant_id, conn)
        until = st.scalar("SELECT now()", conn=conn)
        since = until - timedelta(days=settings["history_days"])
        criteria = {key: settings[key] for key in (
            "action_risk_threshold", "urgent_risk_threshold", "session_high_risk_actions",
            "user_high_risk_actions", "investigation_percent", "sample_percent",
        )}
        result = {"group": group, "band": band, "since": since, "until": until,
                  "history_days": settings["history_days"], "selection_policy": settings["selection_policy"],
                  "criteria": criteria, "items": [], "next_cursor": "", "summary": None}
        if settings["selection_policy"] != "risk_budget":
            return _json_safe(result)
        scope = [tenant_id, "detection-rankings", group, band, settings["version"]]
        offset = _decode(cursor, scope, ordinal=True)
        if group == "sessions":
            subjects = """SELECT id,product,hostname,reported_user,user_id,user_name,user_email,
                last_event_at,updated_at,peak,high_actions,1::bigint AS session_count,
                CASE WHEN high_actions>0 THEN 1 ELSE 0 END AS high_risk_sessions,
                ready,ready AND peak IS NOT NULL AS current,assessed,targets,pending
                FROM population"""
            meets = "high_actions >= $4 OR peak >= $6"
        else:
            subjects = """SELECT user_id AS id,NULL::text AS product,NULL::text AS hostname,
                NULL::text AS reported_user,user_id,user_name,user_email,
                max(last_event_at) AS last_event_at,min(updated_at) AS updated_at,
                max(peak) AS peak,sum(high_actions)::bigint AS high_actions,count(*) AS session_count,
                count(*) FILTER(WHERE high_actions>0) AS high_risk_sessions,
                bool_and(ready) AS ready,bool_and(ready AND peak IS NOT NULL) AS current,
                CASE WHEN count(assessed)=count(*) THEN sum(assessed)::bigint END AS assessed,
                CASE WHEN count(targets)=count(*) THEN sum(targets)::bigint END AS targets,
                CASE WHEN count(pending)=count(*) THEN sum(pending)::bigint END AS pending
                FROM population WHERE user_id IS NOT NULL GROUP BY user_id,user_name,user_email"""
            meets = "high_actions >= $5 AND high_risk_sessions >= 2"
        # Only fixed SQL fragments above are interpolated. Population follows
        # the scheduler's recent-activity and verified-owner boundaries.
        rows = st.one(
            f"""WITH population AS MATERIALIZED (
                SELECT s.id,s.product,s.last_event_at,a.hostname,a.username AS reported_user,
                    u.id AS user_id,u.name AS user_name,u.email AS user_email,
                    g.peak,g.high_actions,g.updated_at,
                    (COALESCE(d.state,f.status)->'counts'->>'assessed')::bigint AS assessed,
                    (COALESCE(d.state,f.status)->'counts'->>'logical_targets')::bigint AS targets,
                    (COALESCE(d.state,f.status)->'counts'->>'pending')::bigint AS pending,
                    (g.session_id IS NOT NULL AND g.action_risk_threshold=$3
                     AND NOT EXISTS(SELECT 1 FROM ordinary_session_input_dirty d
                         WHERE d.tenant_id=s.tenant_id AND d.session_id=s.id)
                     AND NOT EXISTS(SELECT 1 FROM session_input_dirty d
                         WHERE d.registration_id=s.registration_id)) AS ready
                FROM agent_sessions s
                JOIN agents a ON a.id=s.agent_id AND a.tenant_id=s.tenant_id
                JOIN sensors sensor ON sensor.id=s.sensor_id AND sensor.tenant_id=s.tenant_id
                    AND NOT sensor.disabled AND sensor.deleted_at IS NULL
                LEFT JOIN detection_session_identities i ON i.session_id=s.id AND i.tenant_id=s.tenant_id
                LEFT JOIN tenant_users u ON u.id=i.owner_user_id AND u.tenant_id=i.tenant_id AND u.status='active'
                LEFT JOIN session_detection_signals g ON g.session_id=s.id AND g.tenant_id=s.tenant_id
                LEFT JOIN ordinary_session_detection d ON d.session_id=s.id AND d.tenant_id=s.tenant_id
                LEFT JOIN session_finalizations f ON f.registration_id=s.registration_id AND f.tenant_id=s.tenant_id
                WHERE s.tenant_id=$1 AND s.last_event_at>=$2 AND s.last_event_at<=now()
                    AND (s.registration_id IS NULL OR (u.id IS NOT NULL AND EXISTS(
                        SELECT 1 FROM session_registrations r WHERE r.id=s.registration_id
                            AND r.tenant_id=s.tenant_id AND r.assessment_mode='inline' AND r.verified_at IS NOT NULL)))
            ), subjects AS ({subjects}), classified AS (
                SELECT *,CASE WHEN NOT current THEN 'unknown'
                    WHEN {meets} THEN 'meets' ELSE 'below' END AS band
                FROM subjects
            ), ranked AS (
                SELECT *,row_number() OVER(ORDER BY current DESC,peak DESC NULLS LAST,
                    high_actions DESC NULLS LAST,last_event_at DESC,id) AS rank
                FROM classified
            ), page AS (
                SELECT * FROM ranked WHERE $7='all' OR band=$7 ORDER BY rank LIMIT $8 OFFSET $9
            ) SELECT
                (SELECT jsonb_build_object('total',count(*),
                    'meets',count(*) FILTER(WHERE band='meets'),
                    'below',count(*) FILTER(WHERE band='below'),'unknown',count(*) FILTER(WHERE band='unknown'))
                 FROM classified) AS summary,
                COALESCE((SELECT jsonb_agg(to_jsonb(page) ORDER BY rank) FROM page),'[]'::jsonb) AS items""",
            tenant_id, since, settings["action_risk_threshold"], settings["session_high_risk_actions"],
            settings["user_high_risk_actions"], settings["urgent_risk_threshold"], band, limit + 1, offset, conn=conn,
        )
        result.update(rows)
        if len(rows["items"]) > limit:
            result["next_cursor"] = _encode(scope, offset + limit)
        result["items"] = rows["items"][:limit]
        # Stale or partial user aggregates must not look like measured zero risk.
        for row in result["items"]:
            ready = row.pop("ready")
            coverage = {key: row.pop(key) for key in ("assessed", "targets", "pending")}
            if not ready:
                coverage = dict.fromkeys(coverage)
                status = "updating"
            elif any(value is None for value in coverage.values()):
                status = "unknown"
            elif coverage["pending"]:
                status = "pending"
            elif not coverage["assessed"]:
                status = "not_assessed"
            elif coverage["assessed"] < coverage["targets"]:
                status = "partial"
            else:
                status = "complete"
            row["score_coverage"] = {"status": status, **coverage}
            if not row.pop("current"):
                row.update(peak=None, high_actions=None, high_risk_sessions=None)
        return _json_safe(result)
