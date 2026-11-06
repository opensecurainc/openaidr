CREATE TABLE tenant_intelligence_selection (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    origin text NOT NULL CHECK (origin = 'https://api.opensecura.ai'),
    version integer NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now()
);
