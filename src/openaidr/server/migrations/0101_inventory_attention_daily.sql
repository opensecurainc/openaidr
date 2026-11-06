-- Aggregate history only. No package, device, or path identities are retained.
CREATE TABLE inventory_attention_daily (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    day date NOT NULL,
    captured_at timestamptz NOT NULL,
    source text NOT NULL CHECK (source IN (
        'osquery-npm-packages','osquery-python-packages','openaidr-mcp-servers','openaidr-plugins'
    )),
    components bigint NOT NULL CHECK (components >= 0),
    device_weighted bigint NOT NULL CHECK (device_weighted >= components),
    PRIMARY KEY (tenant_id,day,source),
    CHECK (day = (captured_at AT TIME ZONE 'UTC')::date)
);
