CREATE TABLE tenant_intelligence_keys (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    origin text NOT NULL CHECK (origin = 'https://api.opensecura.ai'),
    encrypted_api_key text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, origin)
);
