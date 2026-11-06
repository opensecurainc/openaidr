"""Device usage and aggregate company comparisons for the desktop window."""

from collections import defaultdict
from datetime import timedelta, timezone

from openaidr.core.reasoning import EFFORTS
from .agent_costs import UNKNOWN

HIGH_EFFORTS = ("high", "xhigh", "max", "ultra")
KNOWN_EFFORTS = tuple(effort for effort in EFFORTS if effort != "auto")
MIN_PEER_DEVICES = 5
MIN_CALLS = 20


def overview(st, sensor, days):
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        conn.execute("SET LOCAL statement_timeout='5s'")
        until = conn.execute("SELECT now() AS time").fetchone()["time"].astimezone(timezone.utc)
        since = until.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days - 1)
        personal = conn.execute(
            """SELECT date_trunc('day',happened_at,'UTC') AS day,model,reasoning_effort,
                      count(*) AS calls,count(cost_usd) AS priced_calls,
                      sum(tokens) AS tokens,sum(cost_usd) AS cost_usd
               FROM agent_cost_records WHERE tenant_id=%s AND sensor_id=%s AND is_usage AND NOT demo
                 AND happened_at>=%s AND happened_at<%s
               GROUP BY day,model,reasoning_effort""",
            (sensor["tenant_id"], sensor["id"], since, until),
        ).fetchall()
        # Publish only a company-wide cohort with enough other participating devices.
        peers = conn.execute(
            """SELECT model,count(DISTINCT sensor_id) AS devices,count(*) AS calls,
                      count(*) FILTER (WHERE reasoning_effort=ANY(%s)) AS known_calls,
                      count(DISTINCT sensor_id) FILTER (WHERE reasoning_effort=ANY(%s)) AS known_devices,
                      count(*) FILTER (WHERE reasoning_effort=ANY(%s)) AS high_calls
               FROM agent_cost_records WHERE tenant_id=%s AND sensor_id<>%s AND is_usage AND NOT demo
                 AND happened_at>=%s AND happened_at<%s
               GROUP BY model HAVING count(DISTINCT sensor_id)>=%s AND count(*)>=%s""",
            (list(KNOWN_EFFORTS), list(KNOWN_EFFORTS), list(HIGH_EFFORTS),
             sensor["tenant_id"], sensor["id"], since, until, MIN_PEER_DEVICES, MIN_CALLS),
        ).fetchall()
        coverage = conn.execute(
            """SELECT count(*) AS pending,EXISTS (
                   SELECT 1 FROM agent_cost_records WHERE tenant_id=%s AND sensor_id IS NULL
                     AND is_usage AND NOT demo AND happened_at>=%s AND happened_at<%s
               ) AS history_incomplete FROM telemetry_exports
               WHERE tenant_id=%s AND sensor_id=%s AND signal='logs' AND costs_processed_at IS NULL""",
            (sensor["tenant_id"], since, until, sensor["tenant_id"], sensor["id"]),
        ).fetchone()

    def empty():
        return dict(calls=0, priced_calls=0, tokens=0, cost_usd=None)

    def add(target, row):
        for field in ("calls", "priced_calls", "tokens"):
            target[field] += int(row[field] or 0)
        if row["cost_usd"] is not None:
            target["cost_usd"] = (target["cost_usd"] or 0) + float(row["cost_usd"])

    total = empty()
    series = {(since + timedelta(days=day)).date().isoformat(): empty() for day in range(days)}
    models, efforts = defaultdict(empty), defaultdict(empty)
    for row in personal:
        add(total, row)
        add(series[row["day"].astimezone(timezone.utc).date().isoformat()], row)
        add(models[row["model"]], row)
        add(efforts[row["reasoning_effort"]], row)
    baseline = dict(status="insufficient_data", minimum_devices=MIN_PEER_DEVICES, minimum_calls=MIN_CALLS)
    # Effort labels have different meanings across models. Compare each model separately.
    for model in sorted(models, key=lambda name: -models[name]["calls"]):
        if model == UNKNOWN:
            continue
        own = [row for row in personal if row["model"] == model and row["reasoning_effort"] in KNOWN_EFFORTS]
        own_calls = sum(row["calls"] for row in own)
        peer = next((row for row in peers if row["model"] == model), None)
        if own_calls < MIN_CALLS or not peer or peer["known_calls"] < MIN_CALLS or peer["known_devices"] < MIN_PEER_DEVICES:
            continue
        own_share = sum(row["calls"] for row in own if row["reasoning_effort"] in HIGH_EFFORTS) / own_calls
        peer_share = peer["high_calls"] / peer["known_calls"]
        baseline = dict(
            status="available", model=model, own_calls=own_calls,
            peer_calls=peer["known_calls"], peer_devices=peer["known_devices"],
            own_high_share=own_share, company_high_share=peer_share,
            own_coverage=own_calls / models[model]["calls"],
            company_coverage=peer["known_calls"] / peer["calls"],
        )
        break
    return dict(
        days=days, timezone="UTC", since=since.isoformat(), until=until.isoformat(),
        summary=total, series=[dict(date=day, **values) for day, values in series.items()],
        by_model=[dict(name=name, **values) for name, values in sorted(models.items(), key=lambda row: -(row[1]["cost_usd"] or 0))],
        by_reasoning_effort=[dict(name=name, **efforts[name]) for name in (*EFFORTS, "unknown") if name in efforts],
        baseline=baseline, pending_exports=coverage["pending"], history_incomplete=coverage["history_incomplete"],
    )
