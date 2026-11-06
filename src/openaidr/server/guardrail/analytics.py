"""Read-only guardrail analytics over endpoint and gateway checks for one tenant.

A guardrail decision is a ``hook.decision`` event a sensor's hook listener
recorded for a prompt, tool call, or tool result check. Native telemetry also reports
``hook.decision`` records for the agent's own permission prompts; those are
not OpenAIDR decisions and are excluded. Rates use evaluated policy decisions,
before Shadow mode or native agent controls change the returned action. Failed
or missing evaluations are excluded. Rates and latency use only decisions
that carry ``hook.latency_ms``: sensors before that field recorded matched
rules only, so including them would overstate deny and warn rates. They are
counted separately as ``legacy``.
"""

from datetime import timedelta

RANGES = {
    "1h": (timedelta(hours=1), 60),
    "24h": (timedelta(hours=24), 3600),
    "7d": (timedelta(days=7), 21600),
    "30d": (timedelta(days=30), 86400),
}
DECISIONS = ("allow", "warn", "ask", "deny")
# Matches the dashboard's idle threshold for a session.
ACTIVE_WINDOW = timedelta(minutes=5)

# Sensor-supplied numbers are cast only when they are JSON numbers within
# this many milliseconds (any JSON number fits numeric, not every one fits
# float8), so a malformed event cannot fail the query or skew percentiles.
MAX_LATENCY_MS = 3_600_000
# Sensor clocks may run behind the server's by this much and still count as
# current; older event times are backfilled history, not activity.
CLOCK_SKEW = timedelta(minutes=5)
CTE = """
WITH decisions AS MATERIALIZED (
    SELECT e.time,e.decision,e.rule_id,e.rule_name,e.current,e.policy_ms,e.e2e_ms
    FROM guardrail_decision_events e
    WHERE e.tenant_id=$1 AND e.time>=$2 AND e.time<$3
      AND EXISTS (SELECT 1 FROM telemetry_partition_days p
                  WHERE p.tenant_id=e.tenant_id AND p.storage_day=e.storage_day AND p.retired_at IS NULL)
), measured AS MATERIALIZED (
    SELECT * FROM decisions WHERE current AND decision IN ('allow','warn','ask','deny')
)
"""


def _counts(column="decision"):
    counts = ",".join(
        f"count(*) FILTER (WHERE {column}='{d}')::bigint AS {d}" for d in DECISIONS
    )
    return "count(*)::bigint AS total," + counts


LATENCY = """
    percentile_cont(0.5) WITHIN GROUP (ORDER BY e2e_ms) AS e2e_p50,
    percentile_cont(0.95) WITHIN GROUP (ORDER BY e2e_ms) AS e2e_p95,
    percentile_cont(0.99) WITHIN GROUP (ORDER BY e2e_ms) AS e2e_p99,
    percentile_cont(0.5) WITHIN GROUP (ORDER BY policy_ms) AS policy_p50,
    percentile_cont(0.95) WITHIN GROUP (ORDER BY policy_ms) AS policy_p95,
    percentile_cont(0.99) WITHIN GROUP (ORDER BY policy_ms) AS policy_p99"""


def _gateway_stats(st, args, range_name, interval, conn):
    rows = st.many(
        """WITH requests AS MATERIALIZED (
            SELECT floor(extract(epoch FROM (created_at-$2))/$4)::integer AS bucket,
                   CASE WHEN status='evaluated' THEN evaluated_decision END AS decision,
                   status='unavailable' OR (status='pending' AND deadline_at<=$3) AS unavailable,
                   status IN ('evaluated','unavailable') OR
                       (status='pending' AND deadline_at<=$3) AS finished,
                   CASE WHEN status='evaluated' AND policy_latency_ms BETWEEN 0 AND $5
                       THEN policy_latency_ms END AS policy_ms
            FROM gateway_requests WHERE tenant_id=$1 AND created_at>=$2 AND created_at<$3
        ) SELECT bucket, count(decision)::bigint AS total,
            count(*) FILTER (WHERE decision='allow')::bigint AS allow,
            count(*) FILTER (WHERE decision='deny')::bigint AS deny,
            count(*) FILTER (WHERE finished)::bigint AS completed,
            count(*) FILTER (WHERE unavailable)::bigint AS unavailable,
            percentile_cont(0.5) WITHIN GROUP (ORDER BY policy_ms) AS policy_p50,
            percentile_cont(0.95) WITHIN GROUP (ORDER BY policy_ms) AS policy_p95,
            percentile_cont(0.99) WITHIN GROUP (ORDER BY policy_ms) AS policy_p99
        FROM requests GROUP BY GROUPING SETS ((), (bucket))""",
        *args, interval, MAX_LATENCY_MS, conn=conn,
    )
    empty = dict(total=0, allow=0, warn=0, ask=0, deny=0,
                 **{f"{m}_{p}": None for m in ("e2e", "policy") for p in ("p50", "p95", "p99")})
    by_bucket = {}
    for row in rows:
        bucket = row.pop("bucket")
        availability = {"total": row.pop("completed"), "unavailable": row.pop("unavailable")}
        by_bucket[bucket] = dict(empty, **row, availability=availability)
    totals = by_bucket.pop(None)
    availability = totals.pop("availability")
    _, since, until = args
    return {
        "source": "gateways", "range": range_name, "since": since, "until": until,
        "bucket_seconds": interval, "totals": dict(totals, legacy=0),
        "availability": availability, "rules": [],
        "series": [dict(start=since + timedelta(seconds=i * interval),
                        **by_bucket.get(i, dict(empty, availability={"total": 0, "unavailable": 0})))
                   for i in range(int((until - since).total_seconds() // interval))],
    }


def _history_rules(st, args, conn):
    # A rule's name is its latest recorded one; a rule still in the policy
    # takes its current name below. An empty rule id is "no rule matched".
    return st.many(
        CTE
        + "SELECT rule_id,(array_agg(rule_name ORDER BY time DESC))[1] AS rule_name,"
        + "(array_agg(decision ORDER BY time DESC))[1] AS action,"
        + _counts()
        + ","
        + LATENCY
        + ",max(time) AS last_seen_at FROM measured GROUP BY rule_id"
        + " ORDER BY count(*) DESC,rule_id",
        *args,
        conn=conn,
    )


def _enrich_rules(st, tenant_id, rules):
    # This accessor may migrate legacy rules, outside the read-only snapshot.
    policy = {r.get("id"): r for r in st.get_policy(tenant_id).get("rules", [])}
    for rule in rules:
        current = policy.get(rule["rule_id"])
        rule["in_policy"] = current is not None
        if current:
            rule["rule_name"] = current.get("name") or rule["rule_name"]
            rule["action"] = current.get("action") or rule["action"]
    return rules


def stats(st, tenant_id, range_name="24h", source="endpoints"):
    if range_name not in RANGES:
        raise ValueError("range must be 1h, 24h, 7d, or 30d")
    if source not in ("all", "endpoints", "gateways"):
        raise ValueError("source must be all, endpoints, or gateways")
    duration, interval = RANGES[range_name]
    with st.transaction() as conn:
        # Totals, series, and rules come from one snapshot so they agree.
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        until = st.scalar("SELECT now()", conn=conn)
        since = until - duration
        args = (tenant_id, since, until)
        gateway = _gateway_stats(st, args, range_name, interval, conn) if source != "endpoints" else None
        if source == "gateways":
            return gateway
        execution_groups = st.many(
            """SELECT floor(extract(epoch FROM (time-$2))/$4)::integer AS bucket,
                      count(*)::bigint AS total,
                      count(*) FILTER (WHERE body->'hook'->>'outcome'='failed')::bigint AS failed
               FROM events WHERE tenant_id=$1 AND time>=$2 AND time<$3
                 AND kind='sensor' AND export_id IS NULL
                 AND body->'source'->>'collector'='hook-runtime'
                 AND body->'hook'->>'outcome' IN ('succeeded','failed')
               GROUP BY bucket ORDER BY bucket""",
            *args, interval, conn=conn,
        )
        totals = st.one(
            CTE
            + "SELECT "
            + _counts()
            + ","
            + LATENCY
            + ",(SELECT count(*) FROM decisions WHERE NOT current)::bigint AS legacy"
            + " FROM measured",
            *args,
            conn=conn,
        )
        grouped = st.many(
            CTE
            + "SELECT floor(extract(epoch FROM (time-$2))/$4)::integer AS bucket,"
            + _counts()
            + ","
            + LATENCY
            + " FROM measured GROUP BY bucket ORDER BY bucket",
            *args,
            interval,
            conn=conn,
        )
        rules = _history_rules(st, args, conn)
    _enrich_rules(st, tenant_id, rules)
    by_bucket = {row.pop("bucket"): row for row in grouped}
    executions_by_bucket = {row.pop("bucket"): row for row in execution_groups}
    executions = {
        key: sum(row[key] for row in execution_groups) for key in ("total", "failed")
    }
    empty = dict(
        {k: 0 for k in ("total", *DECISIONS)},
        **{f"{m}_{p}": None for m in ("e2e", "policy") for p in ("p50", "p95", "p99")},
    )
    series = [
        dict(start=since + timedelta(seconds=i * interval),
             executions=executions_by_bucket.get(i, {"total": 0, "failed": 0}),
             **by_bucket.get(i, empty))
        for i in range(int(duration.total_seconds() // interval))
    ]
    result = {
        "source": "endpoints",
        "range": range_name,
        "since": since,
        "until": until,
        "bucket_seconds": interval,
        "totals": totals,
        "executions": executions,
        "series": series,
        "rules": rules,
    }
    return {"sources": {"endpoints": result, "gateways": gateway}} if source == "all" else result


def history(st, tenant_id, range_name="24h", source="all"):
    """Shared charts; keep the legacy stats response available to older dashboards."""
    from ..hook_policy import delivery_receipt_match

    if range_name not in RANGES or source not in ("all", "endpoints", "gateways"):
        raise ValueError("invalid history range or source")
    skipped = ["capture_disabled", "unsupported_boundary", "unsupported_content",
               "content_redacted", "content_truncated", "oversized", "unsupported_evidence",
               "unsupported_evidence_context", "insufficient_evidence", "path_context_unavailable"]
    duration, interval = RANGES[range_name]
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        # Compilation adds latency to these bounded dashboard reads.
        conn.execute("SET LOCAL jit=off")
        # A cached short-window estimate makes prepared long-window reads slow.
        conn.execute("SET LOCAL plan_cache_mode=force_custom_plan")
        until = st.scalar("SELECT now()", conn=conn)
        since = until - duration
        rows = st.many(
            CTE + """, selected_checks AS MATERIALIZED (
                SELECT id,tenant_id,sensor_id,request_id,product,hook_event,status,
                    returned_decision,failure_reason,created_at,deadline_at
                FROM ordinary_hook_checks
                WHERE tenant_id=$1 AND created_at>=$2 AND created_at<$3 AND $6 IN ('all','endpoints')
            ), receipts AS MATERIALIZED (
                SELECT DISTINCT ON (c.id) c.id AS check_id,
                    e.delivery_status
                FROM selected_checks c JOIN hook_delivery_events e ON """ + delivery_receipt_match(projected=True) + """
                WHERE e.tenant_id=$1
                ORDER BY c.id,e.received_at,e.id
            ), samples AS MATERIALIZED (
                SELECT 'endpoints'::text AS source,time,decision,e2e_ms,NULL::text AS outcome
                FROM measured WHERE $6 IN ('all','endpoints')
                UNION ALL
                SELECT 'endpoints',time,NULL,NULL,'legacy'
                FROM decisions WHERE NOT current AND $6 IN ('all','endpoints')
                UNION ALL
                SELECT 'gateways',created_at,evaluated_decision,
                    CASE WHEN outcome IN ('blocked','forwarded','unconfirmed') THEN guardrail_e2e_ms END,NULL
                FROM gateway_requests
                WHERE tenant_id=$1 AND created_at>=$2 AND created_at<$3
                    AND status='evaluated' AND $6 IN ('all','gateways')
                UNION ALL
                SELECT 'endpoints',c.created_at,NULL,NULL,
                    CASE WHEN c.status='unavailable' AND c.failure_reason=ANY($5) THEN 'not_evaluated'
                         WHEN COALESCE(d.delivery_status,r.delivery_status) IN ('timed_out','failed') THEN 'failed'
                         WHEN c.status='unavailable' OR (c.status='pending' AND c.deadline_at<=$3) THEN 'failed'
                         WHEN c.status='evaluated' AND COALESCE(d.delivery_status,r.delivery_status)='delivered'
                             THEN 'succeeded'
                         ELSE 'unconfirmed' END
                FROM selected_checks c
                LEFT JOIN ordinary_hook_deliveries d ON d.check_id=c.id
                LEFT JOIN receipts r ON r.check_id=c.id
                UNION ALL
                SELECT 'gateways',created_at,NULL,NULL,
                    CASE WHEN (status='unavailable' OR outcome='fail_open') AND failure_reason=ANY($5)
                             THEN 'not_evaluated'
                         WHEN outcome='fail_open' OR status='unavailable'
                             OR (status='pending' AND deadline_at<=$3) THEN 'failed'
                         WHEN status='evaluated' AND (outcome IN ('blocked','forwarded')
                             OR (outcome='unconfirmed' AND guardrail_e2e_ms IS NOT NULL)) THEN 'succeeded'
                         ELSE 'unconfirmed' END
                FROM gateway_requests
                WHERE tenant_id=$1 AND created_at>=$2 AND created_at<$3 AND $6 IN ('all','gateways')
            ), bucketed AS (
                SELECT *,floor(extract(epoch FROM (time-$2))/$4)::integer AS bucket FROM samples
            ) SELECT source,bucket,count(decision)::bigint AS total,
                count(*) FILTER (WHERE decision='allow')::bigint AS allow,
                count(*) FILTER (WHERE decision='warn')::bigint AS warn,
                count(*) FILTER (WHERE decision='ask')::bigint AS ask,
                count(*) FILTER (WHERE decision='deny')::bigint AS deny,
                count(e2e_ms)::bigint AS latency_samples,
                percentile_cont(0.5) WITHIN GROUP (ORDER BY e2e_ms) AS e2e_p50,
                percentile_cont(0.95) WITHIN GROUP (ORDER BY e2e_ms) AS e2e_p95,
                percentile_cont(0.99) WITHIN GROUP (ORDER BY e2e_ms) AS e2e_p99,
                count(*) FILTER (WHERE outcome IN ('succeeded','failed'))::bigint AS attempted,
                count(*) FILTER (WHERE outcome='failed')::bigint AS failed,
                count(*) FILTER (WHERE outcome='not_evaluated')::bigint AS not_evaluated,
                count(*) FILTER (WHERE outcome='unconfirmed')::bigint AS unconfirmed,
                count(*) FILTER (WHERE outcome='legacy')::bigint AS legacy
            FROM bucketed GROUP BY GROUPING SETS ((source,bucket),(source),(bucket),())""",
            tenant_id, since, until, interval, skipped, source, conn=conn,
        )
        rules = _history_rules(st, (tenant_id, since, until), conn) if source != "gateways" else []
    if source != "gateways":
        _enrich_rules(st, tenant_id, rules)
    empty = dict(total=0, allow=0, warn=0, ask=0, deny=0, latency_samples=0,
                 e2e_p50=None, e2e_p95=None, e2e_p99=None,
                 attempted=0, failed=0, not_evaluated=0, unconfirmed=0, legacy=0)
    grouped = {(row.pop("source"), row.pop("bucket")): row for row in rows}

    def group(key):
        return {
            "totals": grouped.get((key, None), dict(empty)),
            "series": [dict(start=since + timedelta(seconds=i * interval),
                            **grouped.get((key, i), empty))
                       for i in range(int(duration.total_seconds() // interval))],
        }

    return {"source": source, "range": range_name, "since": since, "until": until,
            "bucket_seconds": interval, "rules": rules, **group(None),
            "sources": {key: group(key) for key in ("endpoints", "gateways") if source in ("all", key)}}


def active(st, tenant_id):
    """Users, sessions, and actions seen in the last few minutes. A session
    whose latest event is its end is not active."""
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        until = st.scalar("SELECT now()", conn=conn)
        since = until - ACTIVE_WINDOW
        # Both the arrival and the event's own time must be recent: backfilled
        # transcripts arrive now with their original times.
        row = st.one(
            """
            WITH recent AS MATERIALIZED (
                SELECT e.kind,e.time,e.id,
                       e.export_id IS NOT NULL AS native,
                       e.sensor_id::text || ':' || e.product || ':'
                           || COALESCE(e.body->'session'->>'id',e.session_id::text,'') AS session_key,
                       NULLIF(e.body->'agent'->>'account','') AS account,
                       NULLIF(e.body->'host'->>'user','') AS host_user,
                       NULLIF(e.body->'tool'->>'call_id','') AS call_id,
                       COALESCE(NULLIF(e.body->'hook'->>'enforced',''),e.body->'hook'->>'decision') AS enforced,
                       e.body->'source'->>'collector' AS collector
                FROM events e
                WHERE e.tenant_id=$1 AND e.received_at>=$2 AND e.received_at<=$3
                  AND e.time>=$4 AND e.kind<>'sensor'
            ), sessions AS (
                -- One principal per session: the agent account when any event
                -- reports it (hook events carry only the OS user), else the user.
                SELECT session_key,(array_agg(kind ORDER BY time DESC,id DESC))[1] AS last_kind,
                       COALESCE(max(account),max(host_user)) AS principal
                FROM recent GROUP BY session_key
            ), live AS (
                SELECT * FROM sessions WHERE last_kind<>'session.end'
            ), collected AS (
                -- What collectors (hooks, transcripts) reported per session;
                -- policy decisions and session boundaries are not actions.
                SELECT session_key,
                       bool_or(kind='prompt') AS prompts,
                       bool_or(kind IN ('tool.call','command','file.read','file.write','network')) AS calls,
                       bool_or(kind='tool.result') AS results
                FROM recent WHERE NOT native GROUP BY session_key
            ), actions AS (
                -- A native record of an action a collector also reported is
                -- counted once, as the live activity view joins them: a native
                -- prompt where a collector reported prompts, a native tool
                -- record with the call id of a collector record of the same
                -- kind, or without a call id where a collector reported that
                -- kind. Anything else native is the only record and counts.
                SELECT r.* FROM recent r LEFT JOIN collected c USING (session_key)
                WHERE r.kind IN ('prompt','tool.call','command','file.read','file.write','network','tool.result')
                  AND (NOT r.native OR CASE
                       WHEN r.kind='prompt' THEN NOT COALESCE(c.prompts,false)
                       WHEN r.call_id IS NOT NULL THEN NOT EXISTS (
                           SELECT 1 FROM recent x
                           WHERE NOT x.native AND x.session_key=r.session_key AND x.call_id=r.call_id
                             AND x.kind IN ('tool.call','command','file.read','file.write','network','tool.result')
                             AND (x.kind='tool.result')=(r.kind='tool.result'))
                       WHEN r.kind='tool.result' THEN NOT COALESCE(c.results,false)
                       ELSE NOT COALESCE(c.calls,false) END)
            ), decisions AS (
                SELECT * FROM recent
                WHERE kind='hook.decision' AND NOT native AND collector='hook'
            )
            SELECT (SELECT count(*) FROM live)::bigint AS sessions,
                   (SELECT count(DISTINCT principal) FROM live)::bigint AS users,
                   (SELECT count(*) FROM actions WHERE kind='prompt')::bigint AS prompts,
                   (SELECT count(*) FROM actions
                     WHERE kind IN ('tool.call','command','file.read','file.write','network'))::bigint AS tool_calls,
                   (SELECT count(*) FROM actions WHERE kind='tool.result')::bigint AS tool_results,
                   (SELECT count(*) FROM decisions)::bigint AS decisions,
                   (SELECT count(*) FROM decisions WHERE enforced='allow')::bigint AS allow,
                   (SELECT count(*) FROM decisions WHERE enforced='warn')::bigint AS warn,
                   (SELECT count(*) FROM decisions WHERE enforced='ask')::bigint AS ask,
                   (SELECT count(*) FROM decisions WHERE enforced='deny')::bigint AS deny
            """,
            tenant_id,
            since,
            until,
            since - CLOCK_SKEW,
            conn=conn,
        )
        labels = st.many(
            """
            SELECT COALESCE(risk->>'category','unknown') AS category,
                   COALESCE(risk->>'level','') AS level,count(*)::bigint AS count
            FROM events
            WHERE tenant_id=$1 AND received_at>=$2 AND received_at<=$3
              AND time>=$4 AND risk->>'status'='scored'
            GROUP BY 1,2 ORDER BY count DESC,1,2
            """,
            tenant_id,
            since,
            until,
            since - CLOCK_SKEW,
            conn=conn,
        )
        # Jev is an asynchronous assessment, separate from sensor policy
        # enforcement. Count provider attempts, including billed retries and
        # failures, using the ledger's recorded prices rather than estimates.
        jev = st.one(
            """
            SELECT count(*)::bigint AS calls,
                   count(*) FILTER (WHERE completed_at IS NULL)::bigint AS pending_calls,
                   count(*) FILTER (WHERE status='error')::bigint AS failed_calls,
                   count(*) FILTER (WHERE completed_at>=started_at)::bigint AS latency_samples,
                   percentile_cont(0.95) WITHIN GROUP (
                       ORDER BY extract(epoch FROM (completed_at-started_at))*1000
                   ) FILTER (WHERE completed_at>=started_at) AS latency_p95_ms
            FROM model_usage
            WHERE tenant_id=$1 AND started_at>=$2 AND started_at<=$3
              AND provider='typesafe' AND model LIKE 'jev%'
              AND purpose IN ('detection','guardrail')
            """,
            tenant_id,
            since,
            until,
            conn=conn,
        )
    return dict(row, since=since, until=until, labels=labels, jev=jev)
