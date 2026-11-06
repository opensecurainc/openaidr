"""Last recorded daily counts of components with known vulnerability findings."""

import asyncio
import logging
from datetime import timedelta, timezone

from starlette.concurrency import run_in_threadpool

from .store import now

log = logging.getLogger(__name__)
SOURCES = (
    "osquery-npm-packages", "osquery-python-packages",
    "openaidr-mcp-servers", "openaidr-plugins",
)
INTERVAL = 300
DAYS = 30


def capture(st, tenant):
    """One statement observes inventory and cached findings in the same DB snapshot.

    Copies and versions on one device count once. Retained findings still count,
    as in the inventory API; collection failures alone never trigger attention.
    """
    with st.transaction() as conn:
        st.execute("SET LOCAL statement_timeout = '30s'", conn=conn)
        st.execute("""WITH stamp AS (SELECT statement_timestamp() AS captured_at),
            affected AS (
                SELECT r.source,COALESCE(NULLIF(c.identifier,''),c.id::text) AS identifier,c.sensor_id
                FROM inventory_components c
                JOIN inventory_roots r ON r.id=c.root_id AND r.tenant_id=c.tenant_id AND r.sensor_id=c.sensor_id
                JOIN sensors s ON s.id=c.sensor_id AND s.tenant_id=c.tenant_id
                JOIN inventory_osv_packages p ON p.tenant_id=c.tenant_id AND p.ecosystem=c.ecosystem
                    AND p.identifier=c.identifier AND p.version=c.version
                WHERE c.tenant_id=$1 AND s.deleted_at IS NULL AND c.kind='package'
                    AND r.source=ANY($2) AND jsonb_array_length(p.findings)>0
            ), counts AS (
                SELECT source,count(DISTINCT identifier) AS components,
                    count(DISTINCT (identifier,sensor_id)) AS device_weighted
                FROM affected GROUP BY source
            )
            INSERT INTO inventory_attention_daily(tenant_id,day,captured_at,source,components,device_weighted)
            SELECT $1,(stamp.captured_at AT TIME ZONE 'UTC')::date,stamp.captured_at,source,
                COALESCE(counts.components,0),COALESCE(counts.device_weighted,0)
            FROM unnest($2::text[]) AS sources(source) CROSS JOIN stamp LEFT JOIN counts USING(source)
            ON CONFLICT(tenant_id,day,source) DO UPDATE SET captured_at=EXCLUDED.captured_at,
                components=EXCLUDED.components,device_weighted=EXCLUDED.device_weighted
            WHERE inventory_attention_daily.captured_at < EXCLUDED.captured_at""", tenant, list(SOURCES), conn=conn)
        st.execute("DELETE FROM inventory_attention_daily WHERE tenant_id=$1 AND day < (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date - 29",
                   tenant, conn=conn)


def tick(st, tenant=""):
    # Include previously recorded tenants after their last device is removed, so
    # a subsequent real observation can record zero without rewriting history.
    tenants = st.many("""SELECT DISTINCT tenant_id FROM (
        SELECT r.tenant_id FROM inventory_roots r JOIN sensors s ON s.id=r.sensor_id AND s.tenant_id=r.tenant_id
        WHERE r.source=ANY($1) AND s.deleted_at IS NULL
        UNION SELECT tenant_id FROM inventory_attention_daily
        ) AS known WHERE ($2::uuid IS NULL OR tenant_id=$2::uuid)""", list(SOURCES), tenant or None)
    for row in tenants:
        try:
            capture(st, row["tenant_id"])
        except Exception:
            log.warning("Inventory attention snapshot unavailable")


async def run(st, stop, tenant=""):
    while not stop.is_set():
        try:
            await run_in_threadpool(tick, st, tenant)
        except Exception:
            log.warning("Inventory attention history unavailable")
        try:
            await asyncio.wait_for(stop.wait(), timeout=INTERVAL)
        except TimeoutError:
            pass


def history(st, tenant, enabled=True):
    today = now().astimezone(timezone.utc).date()
    start = today - timedelta(days=DAYS - 1)
    rows = st.many("""SELECT day,captured_at,source,components,device_weighted
        FROM inventory_attention_daily WHERE tenant_id=$1 AND day BETWEEN $2 AND $3
        ORDER BY day,source""", tenant, start, today)
    by_day = {}
    for row in rows:
        by_day.setdefault(row["day"].isoformat(), []).append(row)
    days = []
    for offset in range(DAYS):
        day = (start + timedelta(days=offset)).isoformat()
        values = by_day.get(day, [])
        # A missing or incomplete snapshot is unavailable, never a measured zero.
        available = len(values) == len(SOURCES) and len({value["captured_at"] for value in values}) == 1
        days.append({
            "date": day,
            "captured_at": values[0]["captured_at"] if available else None,
            "categories": {row["source"]: {"components": row["components"], "device_weighted": row["device_weighted"]}
                           for row in values} if available else None,
        })
    return {"timezone": "UTC", "scope": "tenant", "checks_enabled": enabled,
            "interval_seconds": INTERVAL, "days": days}
