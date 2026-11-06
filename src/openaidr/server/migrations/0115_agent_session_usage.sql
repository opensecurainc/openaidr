-- Session totals are snapshots, never model requests or daily spend increments.
CREATE TABLE agent_session_usage (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    session_id text NOT NULL,
    observed_at timestamptz NOT NULL,
    observation_ns bigint NOT NULL,
    input_tokens bigint,
    output_tokens bigint,
    estimated_cost_usd numeric,
    PRIMARY KEY (tenant_id,sensor_id,session_id)
);
CREATE INDEX agent_session_usage_time ON agent_session_usage (tenant_id,observed_at);
