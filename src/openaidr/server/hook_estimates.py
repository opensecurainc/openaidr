"""Tenant reports for hook text estimates; never mixed with native usage."""

from openaidr.core.hook_estimates import observations, report

RANGES = {"24h": 1, "7d": 7, "30d": 30}


def project(conn, export):
    items = list(observations(export))
    for item in items:
        conn.execute("""INSERT INTO agent_hook_estimates
            (tenant_id,sensor_id,application,observation_id,observed_at,model,model_source,
             estimated_input_tokens,estimated_output_tokens,estimated_cost_usd,modified)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (export["tenant_id"], export["sensor_id"], item["application"], item["observation_id"],
             item["observed_at"], item["model"], item["model_source"], item["estimated_input_tokens"],
             item["estimated_output_tokens"], item["estimated_cost_usd"], item["modified"]))
    if items:
        conn.execute("DELETE FROM agent_hook_estimates WHERE tenant_id=%s AND observed_at<now()-interval '30 days'",
                     (export["tenant_id"],))


def overview(st, tenant, range_name="24h"):
    rows = st.many("""SELECT application,model,model_source,count(*) AS observations,
        count(estimated_cost_usd) AS priced_observations,
        count(*) FILTER (WHERE model_source='configured') AS assumed_model_observations,
        count(*) FILTER (WHERE modified) AS modified_observations,
        sum(estimated_input_tokens) AS estimated_input_tokens,
        sum(estimated_output_tokens) AS estimated_output_tokens,
        sum(estimated_cost_usd) AS estimated_cost_usd
        FROM agent_hook_estimates WHERE tenant_id=$1
            AND observed_at>=now()-($2::int * interval '1 day') AND observed_at<=now()
        GROUP BY application,model,model_source""", tenant, RANGES[range_name])
    return dict(report(rows), range=range_name)
