-- Keep revocation independent of mutable email addresses and deleted user rows.
CREATE TABLE tenant_identity_revocations (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    issuer text NOT NULL,
    subject text NOT NULL,
    removed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, issuer, subject)
);
