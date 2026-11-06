CREATE TABLE skill_bundles (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    manifest jsonb NOT NULL,
    files jsonb,
    content_bytes bigint NOT NULL CHECK (content_bytes BETWEEN 0 AND 4194304),
    status text NOT NULL DEFAULT 'awaiting_upload'
        CHECK (status IN ('awaiting_upload','queued','running','complete','failed')),
    report jsonb,
    scanner_profile text NOT NULL DEFAULT '',
    lease_id uuid,
    lease_until timestamptz,
    attempts integer NOT NULL DEFAULT 0,
    retry_after timestamptz NOT NULL DEFAULT now(),
    error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    PRIMARY KEY (tenant_id,sha256)
);
CREATE INDEX skill_bundles_queue ON skill_bundles(tenant_id,status,retry_after);

CREATE TABLE skill_installations (
    component_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    sensor_id uuid NOT NULL,
    sha256 text NOT NULL,
    observed_at timestamptz NOT NULL,
    FOREIGN KEY (component_id,tenant_id,sensor_id)
        REFERENCES inventory_components(id,tenant_id,sensor_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,sha256) REFERENCES skill_bundles(tenant_id,sha256)
);
CREATE INDEX skill_installations_bundle ON skill_installations(tenant_id,sha256);
