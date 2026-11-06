CREATE TABLE dashboard_mcp_write_receipts (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    grant_id uuid NOT NULL,
    request_id uuid NOT NULL,
    tool_name text NOT NULL,
    request_hash text NOT NULL,
    result jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, grant_id, request_id)
);

CREATE TABLE dashboard_mcp_changes (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    grant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    client_name text NOT NULL,
    requester_id uuid NOT NULL,
    requester_name text NOT NULL,
    request_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN ('hook_mode', 'detection_scheduling', 'company_policy')),
    parameters jsonb NOT NULL,
    expected_version bigint NOT NULL CHECK (expected_version >= 0),
    before_state jsonb NOT NULL,
    after_state jsonb NOT NULL,
    digest text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'rejected')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '15 minutes',
    decided_at timestamptz,
    decided_by uuid,
    result jsonb,
    UNIQUE (tenant_id, grant_id, request_id)
);
CREATE INDEX dashboard_mcp_changes_listing ON dashboard_mcp_changes(tenant_id, created_at DESC, id DESC);
