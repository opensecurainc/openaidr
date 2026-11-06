ALTER TABLE ordinary_hook_checks DROP CONSTRAINT ordinary_hook_checks_product_check;
ALTER TABLE ordinary_hook_checks ADD CONSTRAINT ordinary_hook_checks_product_check
    CHECK (product IN ('codex-cli', 'claude-code', 'github-copilot', 'cursor', 'antigravity', 'opencode', 'hermes-agent', 'cowork', 'claude-ai', 'unknown'));

CREATE TABLE cowork_connections (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('enterprise', 'plugin')),
    organization_id text NOT NULL DEFAULT '',
    token_hash text NOT NULL UNIQUE,
    encrypted_signing_secrets text NOT NULL DEFAULT '',
    capture_content boolean NOT NULL DEFAULT false,
    disabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_hook_at timestamptz,
    last_telemetry_at timestamptz,
    UNIQUE (tenant_id, id)
);

CREATE TABLE cowork_accounts (
    connection_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    account_id text NOT NULL,
    sensor_id uuid NOT NULL UNIQUE,
    PRIMARY KEY (connection_id, account_id),
    FOREIGN KEY (tenant_id, connection_id) REFERENCES cowork_connections(tenant_id, id),
    FOREIGN KEY (tenant_id, sensor_id) REFERENCES sensors(tenant_id, id)
);
