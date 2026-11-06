CREATE TABLE tenant_support_settings (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    slack_channel_url text NOT NULL DEFAULT '' CHECK (length(slack_channel_url) <= 2048),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
