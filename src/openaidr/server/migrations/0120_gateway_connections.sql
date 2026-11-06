CREATE TABLE gateway_instances (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name text NOT NULL,
    kind text NOT NULL DEFAULT 'kong' CHECK (kind='kong'),
    environment text NOT NULL DEFAULT '',
    enabled boolean NOT NULL DEFAULT true,
    mode text NOT NULL DEFAULT 'shadow' CHECK (mode IN ('shadow','enforce')),
    capture_content boolean NOT NULL DEFAULT false,
    policy_rule_ids jsonb NOT NULL DEFAULT '[]',
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(tenant_id,id)
);
CREATE TABLE gateway_credentials (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    gateway_id uuid NOT NULL,
    token_hash text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    FOREIGN KEY(tenant_id,gateway_id) REFERENCES gateway_instances(tenant_id,id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX gateway_credential_active ON gateway_credentials(gateway_id) WHERE revoked_at IS NULL;
CREATE TABLE gateway_nodes (
    tenant_id uuid NOT NULL,
    gateway_id uuid NOT NULL,
    node_id text NOT NULL,
    plugin_version text NOT NULL,
    kong_version text NOT NULL DEFAULT '',
    dropped_events bigint NOT NULL DEFAULT 0 CHECK (dropped_events>=0),
    routes jsonb NOT NULL DEFAULT '[]',
    last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(gateway_id,node_id),
    FOREIGN KEY(tenant_id,gateway_id) REFERENCES gateway_instances(tenant_id,id) ON DELETE CASCADE
);
CREATE TABLE gateway_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    gateway_id uuid NOT NULL,
    request_id uuid NOT NULL,
    node_id text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}',
    check_digest text,
    outcome_digest text,
    status text NOT NULL CHECK (status IN ('pending','evaluated','unavailable')),
    mode text CHECK (mode IN ('shadow','enforce')),
    settings_version integer,
    policy_version integer,
    risk_settings_version integer NOT NULL DEFAULT 0,
    company_policy_revision integer NOT NULL DEFAULT 0,
    evaluated_decision text CHECK (evaluated_decision IN ('allow','deny')),
    returned_decision text CHECK (returned_decision IN ('allow','deny')),
    reason text NOT NULL DEFAULT '',
    failure_reason text NOT NULL DEFAULT '',
    messages jsonb,
    assessment jsonb,
    outcome text CHECK (outcome IN ('blocked','forwarded','fail_open','unconfirmed')),
    status_code integer CHECK (status_code BETWEEN 100 AND 599),
    latency_ms double precision CHECK (latency_ms>=0 AND latency_ms<'Infinity'::double precision),
    policy_latency_ms double precision CHECK (policy_latency_ms>=0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deadline_at timestamptz,
    completed_at timestamptz,
    UNIQUE(gateway_id,request_id),
    UNIQUE(tenant_id,id),
    FOREIGN KEY(tenant_id,gateway_id) REFERENCES gateway_instances(tenant_id,id) ON DELETE CASCADE,
    CHECK (status<>'evaluated' OR (mode IS NOT NULL AND evaluated_decision IS NOT NULL AND returned_decision IS NOT NULL)),
    CHECK (outcome<>'blocked' OR (status='evaluated' AND mode='enforce' AND returned_decision='deny'))
);
CREATE INDEX gateway_requests_tenant_time ON gateway_requests(tenant_id,created_at DESC,id DESC);
CREATE INDEX gateway_requests_instance_time ON gateway_requests(tenant_id,gateway_id,created_at DESC,id DESC);
CREATE INDEX gateway_requests_retention ON gateway_requests(created_at);
CREATE INDEX gateway_requests_pending ON gateway_requests(deadline_at) WHERE status='pending';

-- Keep classifier accounting after evidence retention, as for endpoint events.
-- The gateway request identifier is not a sensor or an endpoint event.
ALTER TABLE model_usage ADD COLUMN gateway_request_id uuid;
ALTER TABLE model_usage DROP CONSTRAINT model_usage_anchor;
ALTER TABLE model_usage ADD CONSTRAINT model_usage_anchor CHECK (
    (gateway_request_id IS NULL AND (
        (event_id IS NOT NULL AND sensor_id IS NOT NULL AND investigation_job_id IS NULL
            AND investigation_attempt_id IS NULL AND investigation_request_id IS NULL)
        OR (event_id IS NULL AND investigation_job_id IS NOT NULL AND investigation_attempt_id IS NOT NULL
            AND investigation_request_id IS NOT NULL AND purpose='detection')
        OR (event_id IS NULL AND sensor_id IS NULL AND investigation_job_id IS NULL
            AND investigation_attempt_id IS NULL AND investigation_request_id IS NULL
            AND purpose IN ('assistant','verification','asset_management','benchmark'))
    )) OR (gateway_request_id IS NOT NULL AND purpose='guardrail' AND event_id IS NULL
        AND sensor_id IS NULL AND investigation_job_id IS NULL
        AND investigation_attempt_id IS NULL AND investigation_request_id IS NULL)
);
CREATE UNIQUE INDEX model_usage_gateway_attempt ON model_usage(tenant_id,gateway_request_id,attempt)
    WHERE gateway_request_id IS NOT NULL;
