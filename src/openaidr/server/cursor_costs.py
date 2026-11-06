"""Cursor's preliminary USD deltas, grouped by collector rather than invoices."""

from datetime import datetime, timedelta, timezone
import hashlib
import json

from openaidr.core.agent_usage import UNKNOWN, number, text, token
from openaidr.core.telemetry import attributes, records

RANGES = {"24h": 1, "7d": 7, "30d": 30}


def points(export):
    received = export["received_at"]
    if isinstance(received, str):
        received = datetime.fromisoformat(received.replace("Z", "+00:00"))
    for metric_index, (resource, _, metric) in enumerate(records("metrics", export["payload"])):
        attrs = attributes(resource.get("attributes"))
        team = token(attrs, "cursor.team.id")
        if (attrs.get("service.name") != "cursor" or team is None
                or attrs.get("openaidr.demo") in (True, "true")
                or metric.get("name") != "cursor.cost.usage" or metric.get("unit") != "USD"):
            continue
        delta = metric.get("sum") or {}
        if delta.get("aggregationTemporality") not in (1, "AGGREGATION_TEMPORALITY_DELTA") or delta.get("isMonotonic") is not True:
            continue
        for point_index, point in enumerate(delta.get("dataPoints", [])):
            cost = number(point.get("asDouble"))
            try:
                if cost is None or int(point.get("flags", 0)) & 1:
                    continue
                stamp = int(point["timeUnixNano"])
                when = datetime.fromtimestamp(stamp / 1e9, timezone.utc)
                start = int(point.get("startTimeUnixNano", 0))
                window = datetime.fromtimestamp(start / 1e9, timezone.utc) if start else None
            except (KeyError, ValueError, TypeError, OverflowError, OSError):
                continue
            if stamp <= 0 or start < 0 or start > stamp or not -300 <= (received - when).total_seconds() <= 30 * 86400:
                continue
            # Native metric points have no event IDs. Dedupe the accepted batch
            # and its point position, without collapsing overlapping windows.
            identity = [str(export["sensor_id"]), str(export["batch_id"]), metric_index, point_index]
            key = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
            yield (export["tenant_id"], key, export["sensor_id"], export["id"], team,
                   text(attributes(point.get("attributes")), "cursor.model.name") or UNKNOWN,
                   when, window, received, cost)


def project(conn, export):
    for point in points(export):
        conn.execute("""INSERT INTO cursor_cost_points VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT(tenant_id,event_key) DO NOTHING""", point)
    if export.get("signal") == "metrics":
        conn.execute("DELETE FROM cursor_cost_points WHERE tenant_id=%s AND happened_at<now()-interval '30 days'",
                     (export["tenant_id"],))


def overview(st, tenant, range_name="24h"):
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        until = conn.execute("SELECT now() AS time").fetchone()["time"]
        since = until - timedelta(days=RANGES[range_name])
        rows = conn.execute("""SELECT sensor_id,team_id,model,count(*) AS points,
            sum(estimated_usd) AS estimated_usd,min(window_start) AS first_window_start,
            max(happened_at) AS last_window_end,max(received_at) AS last_received_at
            FROM cursor_cost_points WHERE tenant_id=%s AND happened_at>=%s AND happened_at<%s
            GROUP BY sensor_id,team_id,model ORDER BY sensor_id,team_id,model LIMIT 1001""",
            (tenant, since, until)).fetchall()
        pending = conn.execute("""SELECT count(*) AS count FROM telemetry_exports
            WHERE tenant_id=%s AND signal='metrics' AND service_names @> ARRAY['cursor']::text[]
              AND received_at>=now()-interval '30 days' AND costs_processed_at IS NULL""", (tenant,)).fetchone()["count"]
    items = [dict(row, estimated_usd=str(row["estimated_usd"]),
                  first_window_start=row["first_window_start"].isoformat() if row["first_window_start"] else None,
                  last_window_end=row["last_window_end"].isoformat(), last_received_at=row["last_received_at"].isoformat())
             for row in rows[:1000]]
    return dict(currency="USD", cost_kind="unreconciled_agent_estimate", range=range_name,
                since=since.isoformat(), until=until.isoformat(), items=items,
                truncated=len(rows) > 1000, pending_exports=pending, corrections_applied=False,
                coverage="Sum of observed delta windows ending in this range, separately per collector/team/model. Gaps and rebatching can affect totals; mirrored collectors must not be added. Includes quota usage. BYOK covers only Cursor's token fee. Not billed charges or subscription fees.")
