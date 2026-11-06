CREATE TABLE overview_summaries (
    tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    roles           text[] NOT NULL,
    key_fingerprint text NOT NULL DEFAULT '',
    summary         jsonb,
    generated_at    timestamptz,
    refresh_after   timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, roles)
);
