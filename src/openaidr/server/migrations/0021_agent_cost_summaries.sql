CREATE TABLE agent_cost_dirty_hours (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    bucket timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, bucket)
);

CREATE TABLE agent_cost_versions (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
    revision bigint NOT NULL DEFAULT 1
);

CREATE TABLE agent_cost_hours (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    bucket timestamptz NOT NULL,
    kind text NOT NULL,
    user_name text NOT NULL,
    model text NOT NULL,
    project text NOT NULL,
    activity text NOT NULL,
    price_date date NOT NULL,
    calls bigint NOT NULL,
    priced_calls bigint NOT NULL,
    unpriced_calls bigint NOT NULL,
    reported_calls bigint NOT NULL,
    calculated_calls bigint NOT NULL,
    demo_calls bigint NOT NULL,
    cost_usd numeric,
    tokens numeric NOT NULL,
    input_tokens numeric NOT NULL,
    output_tokens numeric NOT NULL,
    cache_read_tokens numeric NOT NULL,
    cache_write_tokens numeric NOT NULL
);
CREATE INDEX agent_cost_hours_time_idx ON agent_cost_hours (tenant_id, bucket);
CREATE INDEX agent_cost_hours_breakdown_idx ON agent_cost_hours (tenant_id, bucket) WHERE kind<>'joint';

CREATE FUNCTION agent_cost_queue_changed_hours() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    tenants uuid[];
    buckets timestamptz[];
BEGIN
    IF TG_OP = 'UPDATE' THEN
        SELECT array_agg(tenant_id ORDER BY tenant_id,bucket),
               array_agg(bucket ORDER BY tenant_id,bucket)
        INTO tenants,buckets
        FROM (
            SELECT tenant_id,date_trunc('hour',happened_at,'UTC') AS bucket
            FROM changed_cost_records WHERE is_usage
            UNION
            SELECT tenant_id,date_trunc('hour',happened_at,'UTC') AS bucket
            FROM previous_cost_records WHERE is_usage
        ) affected;
    ELSE
        SELECT array_agg(tenant_id ORDER BY tenant_id,bucket),
               array_agg(bucket ORDER BY tenant_id,bucket)
        INTO tenants,buckets
        FROM (
            SELECT DISTINCT tenant_id,date_trunc('hour',happened_at,'UTC') AS bucket
            FROM changed_cost_records WHERE is_usage
        ) affected;
    END IF;
    IF tenants IS NULL THEN
        RETURN NULL;
    END IF;
    INSERT INTO agent_cost_versions (tenant_id)
        SELECT DISTINCT tenant FROM unnest(tenants) AS tenant ORDER BY tenant
        ON CONFLICT (tenant_id) DO UPDATE SET revision=agent_cost_versions.revision+1;
    INSERT INTO agent_cost_dirty_hours (tenant_id,bucket)
        SELECT * FROM unnest(tenants,buckets) ORDER BY 1,2
        ON CONFLICT (tenant_id,bucket) DO UPDATE SET bucket=excluded.bucket;
    RETURN NULL;
END;
$$;

CREATE TRIGGER agent_cost_records_inserted AFTER INSERT ON agent_cost_records
    REFERENCING NEW TABLE AS changed_cost_records
    FOR EACH STATEMENT EXECUTE FUNCTION agent_cost_queue_changed_hours();
CREATE TRIGGER agent_cost_records_updated AFTER UPDATE ON agent_cost_records
    REFERENCING OLD TABLE AS previous_cost_records NEW TABLE AS changed_cost_records
    FOR EACH STATEMENT EXECUTE FUNCTION agent_cost_queue_changed_hours();
CREATE TRIGGER agent_cost_records_deleted AFTER DELETE ON agent_cost_records
    REFERENCING OLD TABLE AS changed_cost_records
    FOR EACH STATEMENT EXECUTE FUNCTION agent_cost_queue_changed_hours();
