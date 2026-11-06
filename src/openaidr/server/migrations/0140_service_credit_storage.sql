-- Customer receipt mirrors never replace retained private provider accounting.
CREATE TABLE service_credit_receipts (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id uuid NOT NULL,
    origin text NOT NULL,
    api_tenant_id uuid NOT NULL,
    service text NOT NULL CHECK (service IN ('url_reputation','package_vulnerabilities','guardrail',
        'application_research','assistant','rule_generation','overview_summaries','session_summaries',
        'skill_assessment','investigations')),
    state text NOT NULL CHECK (state IN ('disabled','reserved','pending','settled','released')),
    reserved_microcredits bigint CHECK (reserved_microcredits BETWEEN 0 AND 9007199254740991),
    charged_microcredits bigint CHECK (charged_microcredits BETWEEN 0 AND 9007199254740991),
    rate_version text CHECK (length(rate_version) BETWEEN 1 AND 80),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(tenant_id,request_id),
    CHECK ((state='disabled' AND reserved_microcredits IS NULL AND charged_microcredits IS NULL AND rate_version IS NULL)
        OR (state<>'disabled' AND reserved_microcredits IS NOT NULL AND rate_version IS NOT NULL AND (
            (state IN ('reserved','pending') AND charged_microcredits IS NULL)
            OR (state='settled' AND charged_microcredits IS NOT NULL AND charged_microcredits=reserved_microcredits)
            OR (state='released' AND charged_microcredits IS NOT NULL AND charged_microcredits=0)
        )))
);

-- Metadata-only dispatch identities support later callers without retaining
-- request content or provider metadata. Unknown outcomes have no completion.
CREATE TABLE service_call_intents (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id uuid NOT NULL,
    service text NOT NULL CHECK (service IN ('url_reputation','package_vulnerabilities','guardrail',
        'application_research','assistant','rule_generation','overview_summaries','session_summaries',
        'skill_assessment','investigations')),
    origin text NOT NULL,
    api_tenant_id uuid NOT NULL,
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    scope_id uuid NOT NULL,
    attempt integer NOT NULL CHECK (attempt>0),
    outcome text CHECK (outcome IN ('completed','failed')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY(tenant_id,request_id),
    UNIQUE(tenant_id,service,scope_id,request_sha256,attempt),
    CHECK ((outcome IS NULL)=(completed_at IS NULL))
);
