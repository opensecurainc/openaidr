-- Additive cache: older servers can continue using inventory unchanged.
CREATE TABLE inventory_osv_packages (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ecosystem text NOT NULL CHECK (ecosystem IN ('npm','pypi')),
    identifier text NOT NULL CHECK (length(identifier) <= 214 AND identifier ~ '^[A-Za-z0-9@._/-]+$'),
    version text NOT NULL CHECK (length(version) <= 256 AND version ~ '^[A-Za-z0-9.!_+-]+$'),
    checked_at timestamptz,
    attempted_at timestamptz NOT NULL DEFAULT now(),
    next_check_at timestamptz NOT NULL,
    claim_token uuid,
    error text NOT NULL DEFAULT '',
    findings jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(findings) = 'array'),
    PRIMARY KEY (tenant_id,ecosystem,identifier,version)
);
CREATE INDEX inventory_osv_due ON inventory_osv_packages(next_check_at);
