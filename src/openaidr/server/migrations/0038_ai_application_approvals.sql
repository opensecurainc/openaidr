CREATE TABLE ai_application_approvals (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    product_id text NOT NULL CHECK (length(product_id) BETWEEN 1 AND 80),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 1024),
    approved boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, product_id)
);
