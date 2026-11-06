-- Provider billing reports are replaceable snapshots, never per-request costs.
CREATE TABLE agent_billing_reports (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    provider text NOT NULL,
    account_scope text NOT NULL,
    account text NOT NULL,
    period text NOT NULL,
    basis text NOT NULL,
    attempted_at timestamptz NOT NULL,
    collected_at timestamptz,
    error_code text,
    report jsonb,
    PRIMARY KEY (tenant_id,provider,account_scope,account,period,basis)
);
