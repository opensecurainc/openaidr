CREATE TABLE tenant_summary_report_settings (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    automatic boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 0,
    destination_sha256 text NOT NULL DEFAULT '',
    next_report_at timestamptz,
    last_sent_at timestamptz
);

CREATE TABLE summary_report_outbox (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source text NOT NULL CHECK (source IN ('manual','automatic')),
    payload jsonb NOT NULL,
    destination_sha256 text NOT NULL,
    status text NOT NULL CHECK (status IN ('preview','pending','sent','failed','cancelled')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    error_code text NOT NULL DEFAULT ''
);
CREATE INDEX summary_report_outbox_tenant_idx ON summary_report_outbox(tenant_id,created_at DESC);
