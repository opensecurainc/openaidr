CREATE TABLE model_usage (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL,
    event_id uuid NOT NULL,
    attempt integer NOT NULL CHECK (attempt > 0),
    purpose text NOT NULL CHECK (purpose IN ('detection', 'guardrail')),
    provider text NOT NULL,
    model text NOT NULL,
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'error')),
    input_tokens bigint CHECK (input_tokens >= 0),
    output_tokens bigint CHECK (output_tokens >= 0),
    input_rate_usd numeric(20,10),
    output_rate_usd numeric(20,10),
    price_date date,
    cost_usd numeric(24,12) CHECK (cost_usd >= 0),
    UNIQUE (tenant_id, purpose, event_id, attempt)
);
CREATE INDEX model_usage_tenant_time_idx ON model_usage (tenant_id, started_at);
