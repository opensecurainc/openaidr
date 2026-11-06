ALTER TABLE events ADD COLUMN risk jsonb;
ALTER TABLE events ADD COLUMN risk_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE events ADD COLUMN risk_retry_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE events ADD COLUMN risk_next_attempt_at timestamptz NOT NULL DEFAULT '-infinity';
ALTER TABLE events ADD COLUMN risk_body_omitted boolean
    GENERATED ALWAYS AS (octet_length(body::text)>64000) STORED;
CREATE INDEX events_risk_leases_idx ON events (risk_next_attempt_at)
    WHERE risk->>'status' = 'pending';
CREATE INDEX events_received_idx ON events (received_at, id) WHERE NOT risk_body_omitted;
CREATE INDEX events_risk_oversized_idx ON events (tenant_id, id)
    WHERE risk_body_omitted AND risk IS NULL AND risk_next_attempt_at<'infinity';

CREATE TABLE risk_provider_backoff (
    provider text PRIMARY KEY,
    retry_at timestamptz NOT NULL
);

CREATE TABLE risk_assessment_usage (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    sensor_id uuid NOT NULL REFERENCES sensors(id),
    window_start timestamptz NOT NULL,
    attempts integer NOT NULL,
    PRIMARY KEY (tenant_id, sensor_id)
);
CREATE INDEX risk_assessment_usage_window_idx ON risk_assessment_usage (window_start, tenant_id);
