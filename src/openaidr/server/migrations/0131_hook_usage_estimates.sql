CREATE TABLE agent_hook_estimates (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    application text NOT NULL,
    observation_id text NOT NULL,
    observed_at timestamptz NOT NULL,
    model text NOT NULL,
    model_source text NOT NULL,
    estimated_input_tokens bigint NOT NULL,
    estimated_output_tokens bigint NOT NULL,
    estimated_cost_usd numeric,
    modified boolean NOT NULL,
    PRIMARY KEY (tenant_id,sensor_id,application,observation_id)
);
CREATE INDEX agent_hook_estimates_time ON agent_hook_estimates (tenant_id,observed_at);
