CREATE TABLE tenant_skill_llm_settings (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    mode text NOT NULL DEFAULT 'off' CHECK (mode IN ('off','pilot','automatic')),
    budget_usd numeric(12,6) NOT NULL DEFAULT 5 CHECK (budget_usd BETWEEN 0 AND 1000),
    budget_blocked boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Hashes, scheduling metadata, and results only. Never store skill contents.
CREATE TABLE skill_llm_jobs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    profile text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','complete','failed')),
    lease_id uuid,
    lease_until timestamptz,
    report jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (tenant_id,sha256,profile)
);
CREATE INDEX skill_llm_jobs_queue ON skill_llm_jobs(tenant_id,status);

ALTER TABLE model_usage ADD COLUMN skill_scan_id uuid REFERENCES skill_llm_jobs(id);
ALTER TABLE model_usage ADD COLUMN reserved_cost_usd numeric(24,12) CHECK (reserved_cost_usd >= 0);
CREATE INDEX model_usage_skill_scan ON model_usage(tenant_id,skill_scan_id) WHERE skill_scan_id IS NOT NULL;
