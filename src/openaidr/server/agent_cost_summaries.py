"""Incremental hourly accounting and bounded, cached dashboard queries."""

from collections import OrderedDict
from concurrent.futures import Future
from datetime import datetime, timedelta, timezone
import json
from threading import Lock
import time

from psycopg.errors import DeadlockDetected, LockNotAvailable, QueryCanceled

from .agent_costs import DIMENSIONS, PRICE_DATE, RANGES, finish, totals
from .agent_cost_usage import COLUMNS, COUNTERS
from .store import Busy

METRICS = tuple(finish(totals()))
SUMS = ",".join(f"sum({name}) AS {name}" for name in METRICS)
FACT_SUMS = (
    """
    count(*) AS calls,count(cost_usd) AS priced_calls,
    count(*) FILTER (WHERE cost_usd IS NULL) AS unpriced_calls,
    count(*) FILTER (WHERE cost_usd IS NOT NULL AND price_source='reported') AS reported_calls,
    count(*) FILTER (WHERE cost_usd IS NOT NULL AND price_source='calculated') AS calculated_calls,
    count(*) FILTER (WHERE demo) AS demo_calls,
"""
    + ",".join(f"sum({name}) AS {name}" for name in COUNTERS)
    + ",sum(cost_usd) AS cost_usd"
)
FIELDS = "user_name,model,project,activity,reasoning_effort,price_date"
MARGINAL_FIELDS = (
    ",".join(f"coalesce({column},'') AS {column}" for column in COLUMNS.values())
    + ",price_date"
)
KIND = (
    "CASE "
    + " ".join(
        f"WHEN grouping({column})=0 THEN '{dimension}'"
        for dimension, column in COLUMNS.items()
    )
    + " ELSE 'summary' END"
)
HOURLY_GROUPS = (
    "GROUPING SETS ((bucket,price_date),"
    + ",".join(f"(bucket,price_date,{column})" for column in COLUMNS.values())
    + ")"
)


def mark_dirty(conn, tenant, stamps):
    buckets = sorted(
        {
            stamp.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
            for stamp in stamps
        }
    )
    if not buckets:
        return
    # Match the triggers: acquire the tenant revision before any hour locks.
    conn.execute(
        """INSERT INTO agent_cost_versions (tenant_id) VALUES (%s)
           ON CONFLICT (tenant_id) DO UPDATE SET revision=agent_cost_versions.revision+1""",
        (tenant,),
    )
    conn.execute(
        """INSERT INTO agent_cost_dirty_hours (tenant_id,bucket)
           SELECT %s,unnest(%s::timestamptz[]) ORDER BY 2
           ON CONFLICT (tenant_id,bucket) DO UPDATE SET bucket=excluded.bucket""",
        (tenant, buckets),
    )


def rebuild_pending(st, tenant_id=None, limit=24):
    completed = 0
    failure = None
    for index in range(limit):
        with st.transaction() as conn:
            conn.execute("SET LOCAL statement_timeout='30s'")
            order = "ASC" if index % 5 == 0 else "DESC"
            row = conn.execute(
                f"""SELECT tenant_id,bucket FROM agent_cost_dirty_hours
                   WHERE retry_after<=now() AND (%s::uuid IS NULL OR tenant_id=%s)
                   ORDER BY bucket {order},tenant_id LIMIT 1 FOR UPDATE SKIP LOCKED""",
                (tenant_id, tenant_id),
            ).fetchone()
            if row is None:
                break
            tenant, bucket = row["tenant_id"], row["bucket"]
            try:
                with conn.transaction():
                    conn.execute(
                        "DELETE FROM agent_cost_hours WHERE tenant_id=%s AND bucket=%s",
                        (tenant, bucket),
                    )
                    conn.execute(
                        f"""INSERT INTO agent_cost_hours (tenant_id,bucket,kind,{FIELDS},
                            {",".join(METRICS)})
                            SELECT tenant_id,%s,'joint',{FIELDS},{FACT_SUMS}
                            FROM agent_cost_records WHERE tenant_id=%s AND is_usage
                              AND happened_at>=%s AND happened_at<%s
                            GROUP BY tenant_id,{FIELDS}""",
                        (bucket, tenant, bucket, bucket + timedelta(hours=1)),
                    )
                    conn.execute(
                        f"""INSERT INTO agent_cost_hours (tenant_id,bucket,kind,{FIELDS},{",".join(METRICS)})
                            SELECT %s,bucket,{KIND},{MARGINAL_FIELDS},{SUMS}
                            FROM agent_cost_hours WHERE tenant_id=%s AND bucket=%s AND kind='joint'
                            GROUP BY {HOURLY_GROUPS}""",
                        (tenant, tenant, bucket),
                    )
                    conn.execute(
                        "DELETE FROM agent_cost_dirty_hours WHERE tenant_id=%s AND bucket=%s",
                        (tenant, bucket),
                    )
            except (QueryCanceled, DeadlockDetected, LockNotAvailable) as exc:
                # The savepoint preserves both the previous summary and our
                # queue lock, so other workers observe the delay atomically.
                conn.execute(
                    """UPDATE agent_cost_dirty_hours
                       SET retry_after=clock_timestamp()+interval '1 minute'
                       WHERE tenant_id=%s AND bucket=%s""",
                    (tenant, bucket),
                )
                failure = exc
                continue
        completed += 1
    if failure is not None:
        raise failure
    return completed


def queue_rebuild(st, tenant_id):
    if not tenant_id:
        raise ValueError("OPENAIDR_TENANT_ID is required to rebuild summaries")
    with st.transaction() as conn:
        stamps = conn.execute(
            """SELECT DISTINCT date_trunc('hour',happened_at,'UTC') AS bucket
               FROM agent_cost_records WHERE tenant_id=%s AND is_usage
               UNION SELECT bucket FROM agent_cost_hours WHERE tenant_id=%s""",
            (tenant_id, tenant_id),
        ).fetchall()
        mark_dirty(conn, tenant_id, [row["bucket"] for row in stamps])


def source(tenant, since, until, *, marginal=False, filters=None, options_only=False):
    """Use facts only for partial hours and hours whose summaries are dirty."""
    start = since.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    end = until.replace(minute=0, second=0, microsecond=0)
    predicates, values = [], []
    for dimension, column in COLUMNS.items():
        if filters and filters.get(dimension):
            predicates.append(f"{column}=%s")
            values.append(filters[dimension])
    condition = " AND ".join(predicates) or "true"
    kind = "kind<>'joint'" if marginal else "kind='joint'"
    raw_kind = "'raw'" if options_only else KIND if marginal else "'joint'"
    fields = MARGINAL_FIELDS if marginal and not options_only else FIELDS
    metrics = "calculated_calls" if options_only else ",".join(METRICS)
    raw_metrics = (
        "CASE WHEN cost_usd IS NOT NULL AND price_source='calculated' THEN 1 ELSE 0 END AS calculated_calls"
        if options_only
        else FACT_SUMS
    )
    groups = (
        ""
        if options_only
        else "GROUP BY " + (HOURLY_GROUPS if marginal else f"bucket,{FIELDS}")
    )
    return (
        f"""WITH dirty AS MATERIALIZED (
            SELECT bucket FROM agent_cost_dirty_hours
            WHERE tenant_id=%s AND bucket>=%s AND bucket<%s
        ), spans AS (
            SELECT %s::timestamptz AS lo,%s::timestamptz AS hi
            UNION ALL SELECT %s::timestamptz,%s::timestamptz
            UNION ALL SELECT bucket,bucket+interval '1 hour' FROM dirty
        ), usage AS MATERIALIZED (
            SELECT kind,bucket,{FIELDS},{metrics} FROM agent_cost_hours h
            WHERE tenant_id=%s AND bucket>=%s AND bucket<%s AND {kind} AND {condition}
              AND NOT EXISTS (SELECT 1 FROM dirty d WHERE d.bucket=h.bucket)
            UNION ALL
            SELECT {raw_kind} AS kind,date_trunc('hour',r.happened_at,'UTC') AS bucket,{fields},{raw_metrics}
            FROM spans CROSS JOIN LATERAL (
                SELECT * FROM agent_cost_records r
                WHERE r.tenant_id=%s AND r.is_usage AND {condition}
                  AND r.happened_at>=spans.lo AND r.happened_at<spans.hi
            ) r {groups}
        )""",
        (
            tenant,
            start,
            end,
            since,
            start,
            end,
            until,
            tenant,
            start,
            end,
            *values,
            tenant,
            *values,
        ),
    )


def values(row):
    return {
        name: float(row[name])
        if name == "cost_usd" and row[name] is not None
        else None
        if name == "cost_usd"
        else int(row[name] or 0)
        for name in METRICS
    }


def overview(st, tenant, range_name="24h", filters=None, pages=None):
    from .agent_projects import pending_count

    filters, pages = filters or {}, pages or {}
    days, interval = RANGES[range_name]
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        conn.execute("SET LOCAL statement_timeout='10s'")
        # Compilation dominates these bounded dashboard reads at high estimates.
        conn.execute("SET LOCAL jit=off")
        until = (
            conn.execute("SELECT now() AS time")
            .fetchone()["time"]
            .astimezone(timezone.utc)
        )
        since = until - timedelta(days=days)
        pending_projects = pending_count(conn, tenant)
        cte, args = source(tenant, since, until, marginal=True, options_only=True)
        pending = conn.execute(
            """SELECT count(*) AS pending_exports,min(received_at) AS pending_since
               FROM telemetry_exports WHERE tenant_id=%s AND signal='logs'
                 AND costs_processed_at IS NULL""",
            (tenant,),
        ).fetchone()
        options = conn.execute(
            cte
            + " SELECT "
            + ",".join(
                f"ARRAY(SELECT DISTINCT {column} FROM usage WHERE kind IN ('{dimension}','raw') ORDER BY {column} LIMIT 101) AS {dimension}"
                for dimension, column in COLUMNS.items()
            )
            + ",ARRAY(SELECT DISTINCT price_date FROM usage WHERE kind IN ('summary','raw') AND calculated_calls>0 ORDER BY price_date) AS price_dates",
            args,
        ).fetchone()
        if any(filters.values()):
            cte, args = source(tenant, since, until, filters=filters)
            grouped = f"""SELECT period,user_name,model,project,activity,reasoning_effort,{SUMS},
                CASE WHEN grouping(user_name)=0 THEN 'user' WHEN grouping(model)=0 THEN 'model'
                     WHEN grouping(project)=0 THEN 'project' WHEN grouping(activity)=0 THEN 'activity'
                     WHEN grouping(reasoning_effort)=0 THEN 'reasoning_effort'
                     WHEN grouping(period)=0 THEN 'series' ELSE 'summary' END AS kind
                FROM selected GROUP BY GROUPING SETS ((),(period),(user_name),(model),(project),(activity),(reasoning_effort))"""
        else:
            cte, args = source(tenant, since, until, marginal=True)
            grouped = f"""SELECT NULL::bigint AS period,
                nullif(user_name,'') AS user_name,nullif(model,'') AS model,
                nullif(project,'') AS project,nullif(activity,'') AS activity,
                nullif(reasoning_effort,'') AS reasoning_effort,{SUMS},kind
                FROM selected WHERE kind<>'summary' GROUP BY kind,user_name,model,project,activity,reasoning_effort
                UNION ALL SELECT period,NULL,NULL,NULL,NULL,NULL,{SUMS},'series'
                FROM selected WHERE kind='summary' GROUP BY period
                UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,{SUMS},'summary'
                FROM selected WHERE kind='summary'"""
        user_kind = "joint" if any(filters.values()) else "user"
        metric = (
            "CASE kind "
            + " ".join(
                f"WHEN '{dimension}' THEN {pages.get(dimension, {}).get('sort', 'cost_usd')}"
                for dimension in DIMENSIONS
            )
            + " END"
        )
        descending = [
            dim
            for dim in DIMENSIONS
            if pages.get(dim, {}).get("order", "desc") == "desc"
        ]
        bounds = " OR ".join("(kind=%s AND rank>%s AND rank<=%s)" for _ in DIMENSIONS)
        rows = conn.execute(
            cte
            + f""", selected AS (
            SELECT *,floor(extract(epoch FROM bucket)/%s)::bigint*%s AS period FROM usage
        ), grouped AS (
            {grouped}
        ), chart_users AS (
            SELECT user_name FROM grouped WHERE kind='user'
            ORDER BY cost_usd DESC NULLS LAST,user_name LIMIT 5
        ), chart_series AS (
            SELECT period,
                CASE WHEN user_name IN (SELECT user_name FROM chart_users)
                     THEN user_name END AS user_name,
                {SUMS}
            FROM selected WHERE kind='{user_kind}'
            GROUP BY period,2
        ), ranked AS (
            SELECT *,row_number() OVER (PARTITION BY kind ORDER BY
                CASE WHEN kind=ANY(%s) THEN {metric} END DESC NULLS LAST,
                CASE WHEN NOT kind=ANY(%s) THEN {metric} END ASC NULLS LAST,
                coalesce(user_name,model,project,activity,reasoning_effort)) AS rank,
                count(*) OVER (PARTITION BY kind) AS row_count,
                max(cost_usd) OVER (PARTITION BY kind) AS maximum
            FROM grouped
        ) SELECT * FROM ranked WHERE kind IN ('summary','series') OR rank=1 OR {bounds}
        UNION ALL SELECT period,user_name,NULL,NULL,NULL,NULL,{','.join(METRICS)},
            'user_series',NULL,NULL,NULL FROM chart_series""",
            (
                *args,
                interval,
                interval,
                descending,
                descending,
                *(
                    v
                    for dim in DIMENSIONS
                    for v in (
                        dim,
                        pages.get(dim, {}).get("offset", 0),
                        pages.get(dim, {}).get("offset", 0) + 25,
                    )
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
        price_dates=[str(value) for value in options["price_dates"]],
        bucket_seconds=interval,
        summary=finish(totals()),
        available_filters={dim: options[dim][:100] for dim in DIMENSIONS},
        filters_truncated={dim: len(options[dim]) > 100 for dim in DIMENSIONS},
        processing={
            "pending_exports": pending["pending_exports"],
            "pending_project_sessions": pending_projects,
            "pending_since": pending["pending_since"].isoformat()
            if pending["pending_since"]
            else None,
        },
        pagination={
            dim: {
                "offset": pages.get(dim, {}).get("offset", 0),
                "sort": pages.get(dim, {}).get("sort", "cost_usd"),
                "order": pages.get(dim, {}).get("order", "desc"),
                "limit": 25,
                "total": 0,
                "maximum": None,
            }
            for dim in DIMENSIONS
        },
        **{"by_" + dim: [] for dim in DIMENSIONS},
    )
    user_series = {}
    for row in rows:
        kind = row["kind"]
        if kind == "summary":
            result["summary"] = values(row)
        elif kind == "series":
            series[row["period"]] = values(row)
        elif kind == "user_series":
            user = user_series.setdefault(
                row["user_name"], {"totals": totals(), "series": {}}
            )
            user["series"][row["period"]] = values(row)
            for metric in METRICS:
                if metric == "cost_usd":
                    user["totals"]["cost"] += row[metric] or 0
                else:
                    user["totals"][metric] += int(row[metric] or 0)
        else:
            offset = result["pagination"][kind]["offset"]
            if offset < row["rank"] <= offset + 25:
                result["by_" + kind].append(
                    {"name": row[COLUMNS[kind]], "rank": row["rank"], **values(row)}
                )
            result["pagination"][kind].update(
                total=row["row_count"],
                maximum=float(row["maximum"]) if row["maximum"] is not None else None,
            )
    for dim in DIMENSIONS:
        result["by_" + dim].sort(key=lambda row: row.pop("rank"))
    result["series"] = [
        {"time": datetime.fromtimestamp(stamp, timezone.utc).isoformat(), **v}
        for stamp, v in sorted(series.items())
    ]
    result["user_series"] = [
        {
            "name": name,
            **finish(user["totals"]),
            "series": [
                {
                    "time": datetime.fromtimestamp(stamp, timezone.utc).isoformat(),
                    **user["series"].get(stamp, finish(totals())),
                }
                for stamp in sorted(series)
            ],
        }
        for name, user in user_series.items()
    ]
    result["user_series"].sort(
        key=lambda user: (
            user["name"] is None,
            user["cost_usd"] is None,
            -(user["cost_usd"] or 0),
            user["name"] or "",
        )
    )
    return result


def filter_options(st, tenant, range_name, dimension, search):
    until = datetime.now(timezone.utc)
    cte, args = source(
        tenant,
        until - timedelta(days=RANGES[range_name][0]),
        until,
        marginal=True,
        options_only=True,
    )
    column = COLUMNS[dimension]
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        conn.execute("SET LOCAL statement_timeout='10s'")
        conn.execute("SET LOCAL jit=off")
        rows = conn.execute(
            cte
            + f""" SELECT DISTINCT {column} AS name FROM usage
            WHERE kind IN ('{dimension}','raw') AND (
                position(lower(%s) in lower({column}))>0
                OR position(lower(%s) in replace(lower({column}), 'jev', 'guardrail'))>0
            ) ORDER BY name LIMIT 101""",
            (*args, search, search),
        ).fetchall()
    return {"items": [row["name"] for row in rows[:100]], "has_more": len(rows) > 100}


class CostCache:
    """Per-service cache with a byte cap and one computation per request key."""

    def __init__(self, *, clock=time.monotonic):
        self.clock = clock
        self.lock = Lock()
        self.entries = OrderedDict()
        self.pending = {}
        self.bytes = 0

    def get(self, st, tenant, key, compute):
        revision = (
            st.scalar(
                "SELECT coalesce((SELECT revision FROM agent_cost_versions WHERE tenant_id=$1),0)",
                tenant,
            )
            or 0
        )
        key = (tenant, *key)
        with self.lock:
            now = self.clock()
            for old in list(self.entries):
                if self.entries[old][0] <= now:
                    self.bytes -= self.entries.pop(old)[2]
            if key in self.entries:
                entry = self.entries[key]
                if entry[3] == revision or now < entry[4]:
                    self.entries.move_to_end(key)
                    return json.loads(entry[1])
            future = self.pending.get(key)
            owner = future is None
            if not owner and key in self.entries:
                return json.loads(self.entries[key][1])
            if owner:
                if len(self.pending) >= 16:
                    raise Busy("cost query capacity exhausted")
                future = self.pending[key] = Future()
        if not owner:
            try:
                return future.result(timeout=35)
            except TimeoutError:
                raise Busy("cost query timed out") from None
        try:
            result = compute()
            encoded = json.dumps(result).encode()
            size = len(encoded)
            with self.lock:
                if size <= 1 << 20:
                    if key in self.entries:
                        self.bytes -= self.entries.pop(key)[2]
                    while self.entries and (
                        len(self.entries) >= 128 or self.bytes + size > 8 << 20
                    ):
                        self.bytes -= self.entries.popitem(last=False)[1][2]
                    now = self.clock()
                    self.entries[key] = (now + 15, encoded, size, revision, now + 2)
                    self.bytes += size
            future.set_result(result)
            return result
        except QueryCanceled:
            error = Busy("cost query timed out")
            future.set_exception(error)
            raise error from None
        except Exception as exc:
            future.set_exception(exc)
            raise
        finally:
            with self.lock:
                self.pending.pop(key, None)
