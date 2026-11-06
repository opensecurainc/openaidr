CREATE TABLE retained_ingest_evidence (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    source text NOT NULL CHECK (source IN ('events','hook-checks','otlp-logs','otlp-metrics','otlp-traces')),
    record_key text NOT NULL CHECK (record_key ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    encoding text NOT NULL CHECK (encoding='json-ascii-v1'),
    reason text NOT NULL CHECK (reason ~ '^[a-z_]{1,64}$'),
    status text NOT NULL DEFAULT 'unavailable' CHECK (status='unavailable'),
    payload bytea NOT NULL CHECK (octet_length(payload)<=67108864),
    payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(tenant_id,sensor_id,source,record_key)
);
CREATE INDEX retained_ingest_evidence_tenant_received_idx
    ON retained_ingest_evidence(tenant_id,received_at DESC,id DESC);
