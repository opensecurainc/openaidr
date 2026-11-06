CREATE TABLE tenant_model_key_sync (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 0,
    available_until timestamptz,
    next_attempt_at timestamptz,
    attempt_id uuid,
    lease_until timestamptz,
    last_synced_at timestamptz,
    last_error text NOT NULL DEFAULT ''
);
