CREATE TABLE platform_summary_reports (
    tenant_id uuid NOT NULL,
    report_id uuid NOT NULL,
    bucket text NOT NULL,
    object_name text NOT NULL,
    payload_sha256 text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, report_id)
);
CREATE INDEX platform_summary_reports_received_idx
    ON platform_summary_reports(tenant_id, received_at DESC);
