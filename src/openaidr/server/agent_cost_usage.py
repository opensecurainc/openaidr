"""Durable cost projection and queries over accounting metadata."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging

from .agent_costs import (
    DIMENSIONS,
    PRICE_DATE,
    RANGES,
    UNKNOWN,
    extract,
    finish,
    totals,
)

log = logging.getLogger(__name__)
COLUMNS = {
    "user": "user_name",
    "model": "model",
    "project": "project",
    "activity": "activity",
    "reasoning_effort": "reasoning_effort",
}
COUNTERS = (
    "tokens",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
)
PRIORITY = (
    "Delegation",
    "Coding",
    "Testing",
    "Build/Deploy",
    "Git Ops",
    "Planning",
    "Exploration",
)


def key(value):
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()


def assign_context(conn, tenant, condition, args):
    """Reassign only new records or the interval changed by a late prompt."""
    rows = conn.execute(
        f"""WITH candidates AS MATERIALIZED (
            SELECT e.event_key,e.context_key AS previous,
                (SELECT p.explicit_context FROM agent_cost_records p
                 WHERE p.tenant_id=e.tenant_id AND p.session_key=e.session_key
                   AND p.is_prompt AND p.happened_at<=e.happened_at
                 ORDER BY p.happened_at DESC,p.event_key DESC LIMIT 1) AS resolved
            FROM agent_cost_records e
            WHERE e.tenant_id=%s AND e.explicit_context IS NULL
              AND e.session_key IS NOT NULL AND ({condition})
        )
        UPDATE agent_cost_records e SET context_key=c.resolved
        FROM candidates c WHERE e.tenant_id=%s AND e.event_key=c.event_key
          AND e.context_key IS DISTINCT FROM c.resolved
        RETURNING c.previous,e.context_key""",
        (tenant, *args, tenant),
    ).fetchall()
    return {value for row in rows for value in row.values() if value}


def resolve_contexts(conn, tenant, contexts):
    if not contexts:
        return
    conn.execute(
        """WITH context AS (
            SELECT context_key,
                CASE WHEN count(DISTINCT nullif(direct_project,''))=1
                     THEN max(direct_project) ELSE %s END AS project,
                min(array_position(%s::text[],direct_activity)) AS priority
            FROM agent_cost_records
            WHERE tenant_id=%s AND context_key=ANY(%s)
            GROUP BY context_key
        ), resolved AS (
            SELECT e.event_key,
                coalesce(nullif(e.direct_project,''),nullif(e.session_project,''),c.project) AS project,
                coalesce(nullif(e.direct_activity,''),(%s::text[])[c.priority],%s) AS activity
            FROM agent_cost_records e JOIN context c USING(context_key)
            WHERE e.tenant_id=%s AND e.is_usage
        )
        UPDATE agent_cost_records e SET project=r.project,activity=r.activity
        FROM resolved r WHERE e.tenant_id=%s AND e.event_key=r.event_key
          AND (e.project,e.activity) IS DISTINCT FROM (r.project,r.activity)""",
        (
            UNKNOWN,
            list(PRIORITY),
            tenant,
            list(contexts),
            list(PRIORITY),
            UNKNOWN,
            tenant,
            tenant,
        ),
    )


def project_export(conn, export, *, attribution_only=False):
    from . import agent_sessions, cursor_costs, hook_estimates
    cursor_costs.project(conn, export)
    agent_sessions.project(conn, export)
    hook_estimates.project(conn, export)
    tenant = export["tenant_id"]
    rows = []
    projects = {}
    metadata = {}
    prompts = set()
    sessions = set()
    scopes = {}
    contexts = set()
    for event in extract(export):
        session = key(event["scope"]) if event["scope"][-1] else None
        prompt = event["name"].endswith("user_prompt")
        turn = event["turn"] or (event["time"].isoformat() if prompt else "")
        context = key((session, turn)) if session and turn else None
        if session:
            sessions.add(session)
            product = {"codex": "codex-cli", "claude_code": "claude-code", "cowork": "cowork", "copilot": "github-copilot", "cursor": "cursor", "hermes": "hermes-agent", "opencode": "opencode", "workbuddy": "workbuddy"}[
                event["name"].split(".")[0]
            ]
            scopes.setdefault((export["sensor_id"], product, event["scope"][-1]), set()).add(session)
        if context:
            contexts.add(context)
        if prompt and session:
            prompts.add((session, event["time"]))
        usage = event["usage"] or {}
        metadata.setdefault(event["key"], (
            export["sensor_id"], event["reasoning_effort"], tenant, event["key"], export["id"],
        ))
        projects.setdefault(
            event["key"],
            (event["project"], event["project"] or UNKNOWN,
             tenant, event["key"], export["id"]),
        )
        rows.append(
            (
                tenant,
                event["key"],
                export["id"],
                event["export_record"],
                event["time"],
                session,
                context,
                context,
                prompt,
                event["usage"] is not None,
                event["user"],
                event["model"],
                event["project"],
                event["activity"],
                event["project"] or UNKNOWN,
                event["activity"] or UNKNOWN,
                usage.get("cost"),
                usage.get("source"),
                PRICE_DATE,
                *(usage.get(column, 0) for column in COUNTERS),
                event["demo"],
            )
        )
    if not rows:
        return
    # An upsert can touch each key once per statement; keep the first delivery.
    unique = {}
    for row in rows:
        unique.setdefault(row[1], row)
    rows = list(unique.values())
    rows.sort(key=lambda row: row[1])
    from .agent_projects import register

    for scope, keys in sorted(scopes.items()):
        register(conn, tenant, *scope, sorted(keys))
    # Serialize correlation within a session. Unrelated sessions and tenants
    # can be projected concurrently; a stable lock order avoids deadlocks.
    for session in sorted(sessions):
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
            (f"agent-cost:{tenant}:{session}",),
        )
    # Keep each statement below PostgreSQL's bind-parameter limit.
    for start in range(0, len(rows), 1000):
        batch = rows[start : start + 1000]
        if not attribution_only:
            placeholders = ",".join(
                ["(" + ",".join(["%s"] * len(rows[0])) + ")"] * len(batch)
            )
            conn.execute(
                f"""INSERT INTO agent_cost_records
                   (tenant_id,event_key,export_id,export_record,happened_at,session_key,
                    explicit_context,context_key,is_prompt,is_usage,user_name,model,
                    direct_project,direct_activity,project,activity,cost_usd,price_source,
                    price_date,tokens,input_tokens,output_tokens,cache_read_tokens,cache_write_tokens,demo)
                   VALUES {placeholders}
                   ON CONFLICT (tenant_id,event_key) DO UPDATE SET
                       cost_usd=excluded.cost_usd,price_source=excluded.price_source,
                       price_date=excluded.price_date,tokens=excluded.tokens,
                       input_tokens=excluded.input_tokens,output_tokens=excluded.output_tokens,
                       cache_read_tokens=excluded.cache_read_tokens,cache_write_tokens=excluded.cache_write_tokens
                   WHERE agent_cost_records.export_id=excluded.export_id
                     AND agent_cost_records.price_date<>excluded.price_date""",
                tuple(value for row in batch for value in row),
            )
        placeholders = ",".join(["(%s::text,%s::text,%s::uuid,%s::text,%s::uuid)"] * len(batch))
        conn.execute(
            f"""UPDATE agent_cost_records e SET direct_project=p.direct_project,
                project=coalesce(nullif(p.direct_project,''),nullif(e.session_project,''),p.project)
                FROM (VALUES {placeholders}) p(direct_project,project,tenant_id,event_key,export_id)
                WHERE e.tenant_id=p.tenant_id AND e.event_key=p.event_key AND e.export_id=p.export_id
                  AND e.direct_project IS DISTINCT FROM p.direct_project""",
            tuple(value for row in batch for value in projects[row[1]]),
        )
        placeholders = ",".join(["(%s::uuid,%s::text,%s::uuid,%s::text,%s::uuid)"] * len(batch))
        conn.execute(
            f"""UPDATE agent_cost_records e SET sensor_id=p.sensor_id,reasoning_effort=p.reasoning_effort
                FROM (VALUES {placeholders}) p(sensor_id,reasoning_effort,tenant_id,event_key,export_id)
                WHERE e.tenant_id=p.tenant_id AND e.event_key=p.event_key AND e.export_id=p.export_id
                  AND (e.sensor_id,e.reasoning_effort) IS DISTINCT FROM (p.sensor_id,p.reasoning_effort)""",
            tuple(value for row in batch for value in metadata[row[1]]),
        )
    contexts.update(
        assign_context(conn, tenant, "e.event_key=ANY(%s)", ([row[1] for row in rows],))
    )
    for session, stamp in sorted(prompts):
        contexts.update(
            assign_context(
                conn,
                tenant,
                """e.session_key=%s AND e.happened_at>=%s AND e.happened_at<coalesce(
                (SELECT min(p.happened_at) FROM agent_cost_records p
                 WHERE p.tenant_id=e.tenant_id AND p.session_key=e.session_key
                   AND p.is_prompt AND p.happened_at>%s),'infinity'::timestamptz)""",
                (session, stamp, stamp),
            )
        )
    contexts.update(
        row["context_key"] for row in conn.execute(
            """SELECT DISTINCT context_key FROM agent_cost_records
               WHERE tenant_id=%s AND event_key=ANY(%s) AND context_key IS NOT NULL""",
            (tenant, [row[1] for row in rows]),
        )
    )
    resolve_contexts(conn, tenant, contexts)


def process_pending(st, tenant_id=None, limit=50):
    """Commit each export and its accounting together; failures remain queued."""
    done = {"exports": 0, "failed": 0}
    for index in range(limit):
        with st.transaction() as conn:
            # Reserve part of each batch for old history while keeping new
            # telemetry moving during a large backfill.
            order = "ASC" if index % 5 == 0 else "DESC"
            export = conn.execute(
                f"""SELECT e.id,e.tenant_id,e.sensor_id,e.batch_id,e.signal,e.payload,e.received_at,e.costs_reattribute,
                           coalesce(s.username,'') AS username
                    FROM telemetry_exports e LEFT JOIN sensors s
                      ON s.id=e.sensor_id AND s.tenant_id=e.tenant_id
                    WHERE (e.signal='logs' OR (e.signal='metrics' AND e.service_names @> ARRAY['cursor']::text[]
                           AND e.received_at>=now()-interval '30 days')) AND e.costs_processed_at IS NULL
                      AND (e.costs_retry_at IS NULL OR e.costs_retry_at<=now())
                      AND (%s::uuid IS NULL OR e.tenant_id=%s)
                    ORDER BY e.received_at {order},e.id {order}
                    LIMIT 1 FOR UPDATE OF e SKIP LOCKED""",
                (tenant_id, tenant_id),
            ).fetchone()
            if export is None:
                break
            try:
                with conn.transaction():
                    conn.execute("SET LOCAL lock_timeout='5s'")
                    conn.execute("SET LOCAL statement_timeout='30s'")
                    project_export(conn, export, attribution_only=export["costs_reattribute"])
                    conn.execute(
                        "UPDATE telemetry_exports SET costs_processed_at=clock_timestamp(),costs_retry_at=NULL,costs_reattribute=false WHERE id=%s",
                        (export["id"],),
                    )
                done["exports"] += 1
            except Exception:
                log.exception("Cost projection failed for export %s", export["id"])
                conn.execute(
                    "UPDATE telemetry_exports SET costs_retry_at=now()+interval '1 minute' WHERE id=%s",
                    (export["id"],),
                )
                done["failed"] += 1
    return done


def queue_repricing(st, tenant_id):
    if not tenant_id:
        raise ValueError("OPENAIDR_TENANT_ID is required for repricing")
    return st.execute(
        """UPDATE telemetry_exports e SET costs_processed_at=NULL,costs_retry_at=NULL,costs_reattribute=false
           WHERE e.tenant_id=$1 AND e.signal='logs'
             AND jsonb_array_length(coalesce(e.payload->'resourceLogs','[]'::jsonb))>0
             AND EXISTS (SELECT 1 FROM agent_cost_records r
                 WHERE r.tenant_id=e.tenant_id AND r.export_id=e.id AND r.is_usage
                   AND r.price_source IN ('calculated','unpriced') AND r.price_date<>$2::date)""",
        tenant_id,
        PRICE_DATE,
    )


def overview(st, tenant_id, range_name="24h", filters=None):
    from .agent_projects import pending_count

    days, interval = RANGES[range_name]
    filters = filters or {}
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        until = conn.execute("SELECT now() AS time").fetchone()["time"]
        since = until - timedelta(days=days)
        pending_projects = pending_count(conn, tenant_id)
        pending = conn.execute(
            """SELECT count(*) AS pending_exports,min(received_at) AS pending_since
               FROM telemetry_exports WHERE tenant_id=%s AND signal='logs'
                 AND costs_processed_at IS NULL""",
            (tenant_id,),
        ).fetchone()
        options = conn.execute(
            """SELECT array_agg(DISTINCT user_name ORDER BY user_name) AS user,
                      array_agg(DISTINCT model ORDER BY model) AS model,
                      array_agg(DISTINCT project ORDER BY project) AS project,
                      array_agg(DISTINCT activity ORDER BY activity) AS activity,
                      array_agg(DISTINCT reasoning_effort ORDER BY reasoning_effort) AS reasoning_effort,
                      array_agg(DISTINCT price_date ORDER BY price_date) FILTER (WHERE price_source='calculated') AS price_dates
               FROM agent_cost_records WHERE tenant_id=%s AND is_usage
                 AND happened_at>=%s AND happened_at<%s""",
            (tenant_id, since, until),
        ).fetchone()
        rows = conn.execute(
            """WITH selected AS (
                SELECT *,floor(extract(epoch FROM happened_at)/%s)::bigint*%s AS bucket
                FROM agent_cost_records
                WHERE tenant_id=%s AND is_usage AND happened_at>=%s AND happened_at<%s
                  AND (%s='' OR user_name=%s) AND (%s='' OR model=%s)
                  AND (%s='' OR project=%s) AND (%s='' OR activity=%s)
                  AND (%s='' OR reasoning_effort=%s)
            )
            SELECT bucket,user_name,model,project,activity,reasoning_effort,
                count(*) AS calls,count(cost_usd) AS priced_calls,
                count(*) FILTER (WHERE cost_usd IS NULL) AS unpriced_calls,
                count(*) FILTER (WHERE cost_usd IS NOT NULL AND price_source='reported') AS reported_calls,
                count(*) FILTER (WHERE cost_usd IS NOT NULL AND price_source='calculated') AS calculated_calls,
                count(*) FILTER (WHERE demo) AS demo_calls,
                sum(cost_usd) AS cost_usd,coalesce(sum(tokens),0) AS tokens,
                coalesce(sum(input_tokens),0) AS input_tokens,coalesce(sum(output_tokens),0) AS output_tokens,
                coalesce(sum(cache_read_tokens),0) AS cache_read_tokens,
                coalesce(sum(cache_write_tokens),0) AS cache_write_tokens
            FROM selected GROUP BY GROUPING SETS ((),(bucket),(user_name),(model),(project),(activity),(reasoning_effort))""",
            (
                interval,
                interval,
                tenant_id,
                since,
                until,
                *(
                    value
                    for dimension in DIMENSIONS
                    for value in (filters.get(dimension, ""),) * 2
                ),
            ),
        ).fetchall()
    series = {
        stamp: finish(totals())
        for stamp in range(
            int(since.timestamp()) // interval * interval,
            int(until.timestamp()) + 1,
            interval,
        )
    }
    result = dict(
        range=range_name,
        since=since.isoformat(),
        until=until.isoformat(),
        currency="USD",
        price_date=PRICE_DATE,
        price_dates=[str(value) for value in options["price_dates"] or []],
        bucket_seconds=interval,
        summary=finish(totals()),
        available_filters={
            dimension: options[dimension] or [] for dimension in DIMENSIONS
        },
        processing={
            "pending_exports": pending["pending_exports"],
            "pending_project_sessions": pending_projects,
            "pending_since": pending["pending_since"].isoformat()
            if pending["pending_since"]
            else None,
        },
        **{"by_" + dimension: [] for dimension in DIMENSIONS},
    )
    for row in rows:
        values = {
            name: (float(row[name]) if name == "cost_usd" else int(row[name]))
            if row[name] is not None
            else None
            for name in result["summary"]
        }
        if row["bucket"] is not None:
            series[row["bucket"]] = values
        else:
            dimension = next(
                (name for name, column in COLUMNS.items() if row[column] is not None),
                None,
            )
            if dimension:
                result["by_" + dimension].append(
                    {"name": row[COLUMNS[dimension]], **values}
                )
            else:
                result["summary"] = values
    result["series"] = [
        {"time": datetime.fromtimestamp(stamp, timezone.utc).isoformat(), **values}
        for stamp, values in sorted(series.items())
    ]
    for dimension in DIMENSIONS:
        result["by_" + dimension].sort(
            key=lambda row: (-(row["cost_usd"] or 0), row["name"])
        )
    return result
