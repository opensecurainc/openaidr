CREATE TABLE skill_reviews (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    skill_id text NOT NULL,
    sha256 text CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    approved boolean,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,skill_id),
    CHECK (approved IS NOT TRUE OR (sha256 IS NOT NULL AND skill_id=sha256))
);
