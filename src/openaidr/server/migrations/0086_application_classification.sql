CREATE TABLE application_classifications (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    product_id text NOT NULL,
    evidence_hash text NOT NULL,
    evidence jsonb NOT NULL,
    needs_attention boolean,
    category text CHECK (category IN ('coding_agent','chat_assistant','local_model_runtime','other_ai','ordinary')),
    reason text NOT NULL DEFAULT '',
    sources jsonb NOT NULL DEFAULT '[]',
    model text NOT NULL DEFAULT '',
    checked_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    claim_token uuid,
    lease_until timestamptz,
    last_error text NOT NULL DEFAULT '',
    usage jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id,product_id)
);
CREATE INDEX application_classification_due
    ON application_classifications(tenant_id,next_attempt_at);

CREATE TABLE application_classification_scans (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    next_scan_at timestamptz NOT NULL
);
