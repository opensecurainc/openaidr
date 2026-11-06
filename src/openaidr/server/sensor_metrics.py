"""Tenant-scoped sensor process measurements and bounded history queries."""

from datetime import datetime, timedelta, timezone

from .httpx import require

RANGES = {
    "1h": (timedelta(hours=1), 60),
    "6h": (timedelta(hours=6), 60),
    "24h": (timedelta(hours=24), 300),
    "7d": (timedelta(days=7), 1800),
    "30d": (timedelta(days=30), 7200),
}


def validate(data):
    cpu, memory = data.get("cpu_percent"), data.get("memory_rss_bytes")
    require(
        cpu is None or (type(cpu) in (int, float) and 0 <= cpu <= 1000000),
        "cpu_percent must be a finite number from 0 to 1000000 or null",
    )
    require(
        memory is None or (type(memory) is int and 0 <= memory <= 9223372036854775807),
        "memory_rss_bytes must be a nonnegative signed 64-bit integer or null",
    )


def history(st, tenant_id, sensor_id, range_name):
    duration, interval = RANGES[range_name]
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        latest = st.one(
            """SELECT a.last_heartbeat_at,a.cpu_percent,a.memory_rss_bytes,
                      CASE WHEN s.disabled THEN 'disabled'
                           WHEN a.last_heartbeat_at >= now()-interval '90 seconds' THEN 'online'
                           ELSE 'offline' END AS status
               FROM sensors s JOIN sensor_activity a ON a.sensor_id=s.id
               WHERE s.id=$1 AND s.tenant_id=$2 AND s.deleted_at IS NULL""",
            sensor_id,
            tenant_id,
            conn=conn,
        )
        until = st.scalar("SELECT now()", conn=conn)
        since = until - duration
        samples = st.many(
            """SELECT to_timestamp(floor(extract(epoch FROM r.sampled_at)/$4)*$4) AS time,
                      avg(r.cpu_percent) AS cpu_percent,
                      avg(r.memory_rss_bytes)::double precision AS memory_rss_bytes
               FROM sensor_resource_samples r JOIN sensors s ON s.id=r.sensor_id
               WHERE r.sensor_id=$1 AND s.tenant_id=$5 AND s.deleted_at IS NULL
                 AND r.sampled_at >= $2 AND r.sampled_at <= $3
               GROUP BY 1 ORDER BY 1""",
            sensor_id,
            since,
            until,
            interval,
            tenant_id,
            conn=conn,
        )
    window_start = datetime.fromtimestamp(
        since.timestamp() // interval * interval, timezone.utc
    )
    return dict(
        sensor_id=sensor_id,
        range=range_name,
        generated_at=until,
        window_start=window_start,
        bucket_seconds=interval,
        latest=latest,
        samples=samples,
    )


def prune(st, tenant_id=None):
    # A bounded batch on each maintenance tick also removes offline sensors' data.
    return st.execute(
        """DELETE FROM sensor_resource_samples WHERE (sensor_id,sampled_at) IN (
               SELECT r.sensor_id,r.sampled_at FROM sensor_resource_samples r
               JOIN sensors s ON s.id=r.sensor_id
               WHERE r.sampled_at < now()-interval '30 days'
                 AND ($1::uuid IS NULL OR s.tenant_id=$1)
               ORDER BY r.sampled_at LIMIT 10000
           )""",
        tenant_id,
    )
