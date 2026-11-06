"""Latest Antigravity CLI session estimates, isolated from request accounting."""

from openaidr.core.agent_sessions import observations, report


def project(conn, export):
    items = list(observations(export))
    if not items:
        return
    for item in items:
        conn.execute("""INSERT INTO agent_session_usage VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT(tenant_id,sensor_id,session_id) DO UPDATE SET
                observed_at=excluded.observed_at,observation_ns=excluded.observation_ns,
                input_tokens=excluded.input_tokens,output_tokens=excluded.output_tokens,
                estimated_cost_usd=excluded.estimated_cost_usd
            WHERE excluded.observation_ns>agent_session_usage.observation_ns""",
            (export["tenant_id"], export["sensor_id"], item["session_id"], item["observed_at"],
             item["observation_ns"], item["input_tokens"], item["output_tokens"], item["estimated_cost_usd"]))
    conn.execute("DELETE FROM agent_session_usage WHERE tenant_id=%s AND observed_at<now()-interval '30 days'",
                 (export["tenant_id"],))


def overview(st, tenant):
    rows = st.many("""SELECT sensor_id,session_id,observed_at,input_tokens,output_tokens,estimated_cost_usd
        FROM agent_session_usage WHERE tenant_id=$1 AND observed_at>now()-interval '30 days'
        ORDER BY observed_at DESC,sensor_id,session_id LIMIT 1001""", tenant)
    return dict(report([dict(row, observed_at=row["observed_at"].isoformat(),
                            estimated_cost_usd=str(row["estimated_cost_usd"]) if row["estimated_cost_usd"] is not None else None)
                        for row in rows[:1000]]), truncated=len(rows) > 1000)
