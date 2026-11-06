CREATE TABLE tenant_model_keys (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('guardrail', 'detection')),
    api_key text NOT NULL CHECK (length(api_key) BETWEEN 13 AND 512),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, kind)
);
