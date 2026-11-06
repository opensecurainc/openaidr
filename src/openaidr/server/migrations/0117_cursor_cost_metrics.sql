-- Separate preliminary native estimates from request costs and provider bills.
CREATE TABLE cursor_cost_points (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    event_key text NOT NULL,
    sensor_id uuid NOT NULL REFERENCES sensors(id),
    export_id uuid REFERENCES telemetry_export_keys(id) ON DELETE SET NULL,
    team_id bigint NOT NULL,
    model text NOT NULL,
    happened_at timestamptz NOT NULL,
    window_start timestamptz,
    received_at timestamptz NOT NULL,
    estimated_usd numeric NOT NULL,
    PRIMARY KEY (tenant_id,event_key)
);
CREATE INDEX cursor_cost_points_time ON cursor_cost_points (tenant_id,happened_at);
CREATE INDEX telemetry_exports_cursor_cost_pending ON telemetry_exports (received_at,id)
    WHERE signal='metrics' AND service_names @> ARRAY['cursor']::text[] AND costs_processed_at IS NULL;
CREATE INDEX telemetry_exports_cursor_cost_tenant_pending ON telemetry_exports (tenant_id,received_at,id)
    WHERE signal='metrics' AND service_names @> ARRAY['cursor']::text[] AND costs_processed_at IS NULL;
