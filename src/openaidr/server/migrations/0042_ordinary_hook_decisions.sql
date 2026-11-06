CREATE TABLE tenant_hook_settings (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    mode text NOT NULL DEFAULT 'shadow' CHECK (mode IN ('shadow', 'enforce')),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE ordinary_hook_checks (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    request_id uuid NOT NULL,
    payload_sha256 text NOT NULL,
    product text NOT NULL CHECK (product IN ('codex-cli', 'claude-code')),
    hook_event text NOT NULL,
    session_id text NOT NULL,
    tool_call_id text NOT NULL DEFAULT '',
    mode text NOT NULL CHECK (mode IN ('shadow', 'enforce')),
    settings_version bigint NOT NULL,
    policy_version bigint NOT NULL,
    status text NOT NULL CHECK (status IN ('evaluated', 'unavailable')),
    evaluated_decision text CHECK (evaluated_decision IN ('allow', 'warn', 'ask', 'deny')),
    returned_decision text CHECK (returned_decision IN ('allow', 'warn', 'ask', 'deny')),
    reason text NOT NULL DEFAULT '',
    rule_id text NOT NULL DEFAULT '',
    rule_name text NOT NULL DEFAULT '',
    matched_rule jsonb,
    failure_reason text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, sensor_id, request_id),
    CHECK ((status = 'unavailable' AND evaluated_decision IS NULL AND returned_decision IS NULL)
        OR (status = 'evaluated' AND evaluated_decision IS NOT NULL AND returned_decision IS NOT NULL)),
    CHECK (mode <> 'shadow' OR returned_decision IS NULL OR returned_decision = 'allow')
);
CREATE INDEX ordinary_hook_checks_tenant_idx
    ON ordinary_hook_checks(tenant_id, created_at DESC, id DESC);

CREATE TABLE ordinary_hook_deliveries (
    check_id uuid PRIMARY KEY REFERENCES ordinary_hook_checks(id) ON DELETE CASCADE,
    delivery_status text NOT NULL CHECK (delivery_status IN ('delivered', 'timed_out', 'failed')),
    delivered_decision text NOT NULL CHECK (delivered_decision IN ('allow', 'warn', 'ask', 'deny')),
    reported_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (delivery_status = 'delivered' OR delivered_decision = 'allow')
);
