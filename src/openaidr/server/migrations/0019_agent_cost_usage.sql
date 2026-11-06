-- Exports are the durable work queue. Ingestion and queueing commit together,
-- including for old senders and exports retained before this migration.
ALTER TABLE telemetry_exports ADD COLUMN costs_processed_at timestamptz;
ALTER TABLE telemetry_exports ADD COLUMN costs_retry_at timestamptz;
CREATE INDEX telemetry_exports_cost_pending_idx
    ON telemetry_exports (received_at, id)
    WHERE signal = 'logs' AND costs_processed_at IS NULL;
CREATE INDEX telemetry_exports_cost_tenant_pending_idx
    ON telemetry_exports (tenant_id, received_at, id)
    WHERE signal = 'logs' AND costs_processed_at IS NULL;

-- Only accounting and attribution metadata is projected, never raw log bodies,
-- prompts, or tool arguments. Context records allow late attribution updates.
CREATE TABLE agent_cost_records (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    event_key text NOT NULL,
    export_id uuid REFERENCES telemetry_exports(id) ON DELETE SET NULL,
    export_record integer NOT NULL,
    happened_at timestamptz NOT NULL,
    session_key text,
    explicit_context text,
    context_key text,
    is_prompt boolean NOT NULL,
    is_usage boolean NOT NULL,
    user_name text NOT NULL,
    model text NOT NULL,
    direct_project text NOT NULL,
    direct_activity text NOT NULL,
    project text NOT NULL,
    activity text NOT NULL,
    cost_usd numeric,
    price_source text,
    price_date date NOT NULL,
    tokens bigint NOT NULL,
    input_tokens bigint NOT NULL,
    output_tokens bigint NOT NULL,
    cache_read_tokens bigint NOT NULL,
    cache_write_tokens bigint NOT NULL,
    demo boolean NOT NULL,
    PRIMARY KEY (tenant_id, event_key)
);
CREATE INDEX agent_cost_records_time_idx
    ON agent_cost_records (tenant_id, happened_at) WHERE is_usage;
CREATE INDEX agent_cost_records_prompt_idx
    ON agent_cost_records (tenant_id, session_key, happened_at DESC, event_key DESC)
    WHERE is_prompt;
CREATE INDEX agent_cost_records_implicit_idx
    ON agent_cost_records (tenant_id, session_key, happened_at)
    WHERE explicit_context IS NULL;
CREATE INDEX agent_cost_records_context_idx
    ON agent_cost_records (tenant_id, context_key) WHERE context_key IS NOT NULL;
