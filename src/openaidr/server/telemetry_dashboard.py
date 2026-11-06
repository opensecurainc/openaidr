"""Read-only analytics over canonical OTLP exports, scoped to one tenant.

Record counts mean log records, metric data points, or spans. Metric values are
never summed: cumulative samples cannot safely be treated as usage or cost.
"""

import json
import time
from collections import OrderedDict
from concurrent.futures import Future
from contextlib import contextmanager
from datetime import timedelta
from threading import Lock

from fastapi.encoders import jsonable_encoder
from psycopg.errors import QueryCanceled

from ._sql import sensorPolicyDelivery
from .sensor_health import assess
from .store import Busy, Cursor, page_of

STATEMENT_TIMEOUT_MS = 10_000

RANGES = {
    "24h": (timedelta(hours=24), 3600),
    "7d": (timedelta(days=7), 21600),
    "30d": (timedelta(days=30), 86400),
}

# Summaries retain per-service counts, including mixed-service exports. Only
# old exports awaiting the bounded backfill still need their payload parsed.
CTE = """
WITH exports AS (
    SELECT id,batch_id,sensor_id,signal,record_count,received_at,
           COALESCE(resource_summary,telemetry_resource_summary(signal,payload)) AS resources
    FROM telemetry_exports
    WHERE tenant_id=$1 AND received_at >= $2 AND received_at < $3
), resources AS MATERIALIZED (
    SELECT e.id,e.batch_id,e.sensor_id,e.signal,e.record_count AS total_record_count,e.received_at,
           r.service,r.demo,r.records
    FROM exports e
    CROSS JOIN LATERAL jsonb_to_recordset(e.resources) r(service text,demo boolean,records bigint)
), selected_resources AS MATERIALIZED (
    SELECT * FROM resources WHERE ($4='' OR service=$4)
), selected AS MATERIALIZED (
    SELECT id,batch_id,sensor_id,signal,total_record_count,received_at,
           bool_and(demo) AS demo,
           CASE WHEN $4='' THEN total_record_count ELSE sum(records)::bigint END AS record_count,
           array_agg(DISTINCT service ORDER BY service) AS service_names
    FROM selected_resources
    GROUP BY id,batch_id,sensor_id,signal,total_record_count,received_at
)
"""


def backfill_summaries(st, tenant_id=None, limit=25):
    """Fill one bounded batch, newest first; concurrent workers skip locked rows."""
    with st.transaction() as conn:
        conn.execute("SET LOCAL statement_timeout = '10s'")
        conn.execute("SET LOCAL lock_timeout = '1s'")
        return st.execute(
            """UPDATE telemetry_exports e
               SET resource_summary=telemetry_resource_summary(e.signal,e.payload)
               FROM (SELECT id FROM telemetry_exports
                     WHERE resource_summary IS NULL AND ($1::uuid IS NULL OR tenant_id=$1)
                     ORDER BY received_at DESC,id DESC LIMIT $2
                     FOR UPDATE SKIP LOCKED) pending
               WHERE e.id=pending.id""",
            tenant_id, limit, conn=conn,
        )


COUNTS = """count(*)::bigint AS exports,
    COALESCE(sum(record_count) FILTER (WHERE signal='logs'),0)::bigint AS log_records,
    COALESCE(sum(record_count) FILTER (WHERE signal='metrics'),0)::bigint AS metric_points,
    COALESCE(sum(record_count) FILTER (WHERE signal='traces'),0)::bigint AS spans"""


def _window(st, conn, range_name):
    if range_name not in RANGES:
        raise ValueError("range must be 24h, 7d, or 30d")
    duration, interval = RANGES[range_name]
    until = st.scalar("SELECT now()", conn=conn)
    return until - duration, until, interval


def _recent(st, conn, args, page=None):
    page = page_of(page)
    cursor_filter = ""
    values = list(args)
    if page.cursor.id:
        values.extend((page.cursor.time, page.cursor.id))
        cursor_filter = "WHERE (e.received_at,e.id)<($5,$6::uuid)"
    values.append(page.limit + 1)
    rows = st.many(
        CTE
        + f"""
        SELECT e.id,e.batch_id,e.sensor_id,COALESCE(s.hostname,'') AS hostname,
               e.signal,e.record_count,e.total_record_count,e.service_names,e.received_at,e.demo
        FROM selected e LEFT JOIN sensors s ON s.id=e.sensor_id AND s.tenant_id=$1
        {cursor_filter} ORDER BY e.received_at DESC,e.id DESC LIMIT ${len(values)}
    """,
        *values,
        conn=conn,
    )
    more = len(rows) > page.limit
    rows = rows[: page.limit]
    cursor = Cursor(rows[-1]["received_at"], rows[-1]["id"]).encode() if more else ""
    return rows, cursor


def recent_exports(st, tenant_id, range_name="24h", service="", page=None):
    with _read_transaction(st) as conn:
        since, until, _ = _window(st, conn, range_name)
        return _recent(st, conn, (tenant_id, since, until, service), page)


@contextmanager
def _read_transaction(st):
    try:
        with st.transaction() as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            # Compilation costs more than execution for these dashboard reads.
            conn.execute("SET LOCAL jit=off")
            conn.execute("SELECT set_config('statement_timeout', %s, true)",
                         (str(STATEMENT_TIMEOUT_MS),))
            yield conn
    except QueryCanceled:
        raise Busy("telemetry query timed out") from None


def overview(st, tenant_id, range_name="24h", service=""):
    with _read_transaction(st) as conn:
        since, until, interval = _window(st, conn, range_name)
        args = (tenant_id, since, until, service)
        # Materialize resource metadata once for every panel. Materializing the
        # raw exports would also copy the large JSON payloads into a work table.
        panels = st.one(
            CTE
            + ", totals AS (SELECT "
            + COUNTS
            + ",max(received_at) AS last_export_at FROM selected), grouped AS ("
            + """
            SELECT floor(extract(epoch FROM (received_at-$2))/$5)::integer AS bucket,
        """
            + COUNTS
            + " FROM selected GROUP BY bucket), available AS ("
            + "SELECT DISTINCT service AS name FROM resources), services AS ("
            + f"""
            SELECT service AS name,count(DISTINCT id)::bigint AS exports,
                   COALESCE(sum(records) FILTER (WHERE signal='logs'),0)::bigint AS log_records,
                   COALESCE(sum(records) FILTER (WHERE signal='metrics'),0)::bigint AS metric_points,
                   COALESCE(sum(records) FILTER (WHERE signal='traces'),0)::bigint AS spans,
                   max(received_at) AS last_export_at
            FROM selected_resources GROUP BY service
        ), device_activity AS (
            SELECT sensor_id,count(*)::bigint AS exports,
                   COALESCE(sum(record_count) FILTER (WHERE signal='logs'),0)::bigint AS log_records,
                   COALESCE(sum(record_count) FILTER (WHERE signal='metrics'),0)::bigint AS metric_points,
                   COALESCE(sum(record_count) FILTER (WHERE signal='traces'),0)::bigint AS spans,
                   max(received_at) AS latest_export_at
            FROM selected GROUP BY sensor_id
        ), devices AS (
        SELECT s.id,s.hostname,s.label,s.os,s.arch,s.host_kind,sa.version AS sensor_version,
               CASE WHEN s.disabled THEN 'disabled'
                    WHEN sa.last_heartbeat_at >= $3 - interval '90 seconds' THEN 'online'
                    ELSE 'offline' END AS status,
               sa.last_heartbeat_at,sa.queue_depth,'legacy_events' AS queue_depth_kind,
               sa.telemetry_queue_depth,sa.cpu_percent,sa.memory_rss_bytes,a.latest_export_at,
               sa.health_report,sa.health_reported_at,
               {sensorPolicyDelivery.format(activity="sa")},
               COALESCE(a.exports,0)::bigint AS exports,
               COALESCE(a.log_records,0)::bigint AS log_records,
               COALESCE(a.metric_points,0)::bigint AS metric_points,
               COALESCE(a.spans,0)::bigint AS spans
        FROM sensors s JOIN sensor_activity sa ON sa.sensor_id=s.id LEFT JOIN device_activity a ON a.sensor_id=s.id
        WHERE s.tenant_id=$1 AND s.deleted_at IS NULL AND ($4='' OR a.sensor_id IS NOT NULL)
        ), recent AS (
            SELECT e.id,e.batch_id,e.sensor_id,COALESCE(s.hostname,'') AS hostname,
                   e.signal,e.record_count,e.total_record_count,e.service_names,e.received_at,e.demo
            FROM selected e LEFT JOIN sensors s ON s.id=e.sensor_id AND s.tenant_id=$1
            ORDER BY e.received_at DESC,e.id DESC LIMIT 20
        )
        SELECT (SELECT to_jsonb(t) FROM totals t) AS summary,
               (SELECT coalesce(jsonb_agg(g ORDER BY bucket),'[]') FROM grouped g) AS activity,
               (SELECT coalesce(jsonb_agg(name ORDER BY name),'[]') FROM available) AS available_services,
               (SELECT coalesce(jsonb_agg(s ORDER BY name),'[]') FROM services s) AS services,
               (SELECT coalesce(jsonb_agg(d ORDER BY latest_export_at DESC NULLS LAST,hostname,id),'[]')
                FROM devices d) AS devices,
               (SELECT coalesce(jsonb_agg(r ORDER BY received_at DESC,id DESC),'[]') FROM recent r) AS recent_exports
        """,
            *args,
            interval,
            conn=conn,
        )
        totals = panels["summary"]
        totals["records"] = totals["log_records"] + totals["metric_points"] + totals["spans"]
        by_bucket = {row.pop("bucket"): row for row in panels["activity"]}
        activity = [
            dict(
                start=since + timedelta(seconds=i * interval),
                **by_bucket.get(i, dict(exports=0, log_records=0, metric_points=0, spans=0)),
            )
            for i in range(int((until - since).total_seconds() // interval))
        ]
        devices = panels["devices"]
        for device in devices:
            device["health"] = assess(device)
            device.pop("health_report")
            device.pop("health_reported_at")
        totals.update(
            devices=len(devices),
            online_devices=sum(d["status"] == "online" for d in devices),
            offline_devices=sum(d["status"] == "offline" for d in devices),
            disabled_devices=sum(d["status"] == "disabled" for d in devices),
        )
        return dict(
            range=range_name,
            service=service or None,
            generated_at=until,
            window_start=since,
            bucket_seconds=interval,
            summary=totals,
            activity=activity,
            available_services=panels["available_services"],
            services=panels["services"],
            devices=devices,
            recent_exports=panels["recent_exports"],
        )


class OverviewCache:
    """Bound overview work per API process, including simultaneous cache misses."""

    def __init__(self, *, clock=time.monotonic):
        self.clock = clock
        self.lock = Lock()
        self.entries = OrderedDict()
        self.pending = {}
        self.bytes = 0

    def get(self, tenant, range_name, service, compute):
        key = (tenant, range_name, service)
        with self.lock:
            now = self.clock()
            for old in list(self.entries):
                if self.entries[old][0] <= now:
                    self.bytes -= len(self.entries.pop(old)[1])
            if key in self.entries:
                self.entries.move_to_end(key)
                return json.loads(self.entries[key][1])
            future = self.pending.get(key)
            owner = future is None
            if owner:
                if len(self.pending) >= 2:
                    raise Busy("telemetry query capacity exhausted")
                future = self.pending[key] = Future()
        if not owner:
            try:
                return json.loads(future.result(timeout=20))
            except TimeoutError:
                raise Busy("telemetry query timed out") from None
        try:
            encoded = json.dumps(jsonable_encoder(compute())).encode()
            with self.lock:
                if len(encoded) <= 1 << 20:
                    while self.entries and (
                        len(self.entries) >= 128 or self.bytes + len(encoded) > 8 << 20
                    ):
                        self.bytes -= len(self.entries.popitem(last=False)[1][1])
                    self.entries[key] = (self.clock() + 30, encoded)
                    self.bytes += len(encoded)
            future.set_result(encoded)
            return json.loads(encoded)
        except BaseException as exc:
            future.set_exception(exc)
            raise
        finally:
            with self.lock:
                self.pending.pop(key, None)
