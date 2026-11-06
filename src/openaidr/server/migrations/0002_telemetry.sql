-- Canonical OTLP exports are retained without flattening signal-specific data.
-- Authentication, never resource attributes, determines tenant_id and sensor_id.
CREATE TABLE telemetry_exports (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    sensor_id uuid NOT NULL REFERENCES sensors(id),
    signal text NOT NULL CHECK (signal IN ('logs', 'metrics', 'traces')),
    batch_id uuid NOT NULL,
    payload_sha256 text NOT NULL,
    record_count bigint NOT NULL CHECK (record_count >= 0),
    service_names text[] NOT NULL DEFAULT '{}',
    first_event_unix_nano numeric(20,0),
    last_event_unix_nano numeric(20,0),
    received_at timestamptz NOT NULL DEFAULT now(),
    payload jsonb NOT NULL,
    UNIQUE (tenant_id, sensor_id, signal, batch_id)
);
CREATE INDEX telemetry_exports_tenant_signal_time_idx
    ON telemetry_exports (tenant_id, signal, received_at DESC);
CREATE INDEX telemetry_exports_sensor_time_idx
    ON telemetry_exports (tenant_id, sensor_id, received_at DESC);
CREATE INDEX telemetry_exports_service_idx
    ON telemetry_exports USING gin (service_names);
CREATE INDEX telemetry_exports_event_time_idx
    ON telemetry_exports (tenant_id, signal, first_event_unix_nano);
