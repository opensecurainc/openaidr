CREATE TABLE dashboard_mcp_settings (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
    enabled boolean NOT NULL DEFAULT false,
    allowed_scopes text[] NOT NULL,
    revision bigint NOT NULL DEFAULT 1
);

CREATE TABLE dashboard_mcp_clients (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    id uuid NOT NULL,
    name text NOT NULL,
    redirect_uris text[] NOT NULL,
    scopes text[] NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    PRIMARY KEY (tenant_id,id)
);

CREATE TABLE dashboard_mcp_grants (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    id uuid NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL REFERENCES tenant_users(id) ON DELETE CASCADE,
    resource text NOT NULL,
    scopes text[] NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (tenant_id,id),
    FOREIGN KEY (tenant_id,client_id) REFERENCES dashboard_mcp_clients(tenant_id,id)
);
CREATE INDEX dashboard_mcp_grants_user_idx ON dashboard_mcp_grants(tenant_id,user_id,created_at);

CREATE TABLE dashboard_mcp_authorizations (
    request_hash text PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    client_id uuid NOT NULL,
    user_id uuid REFERENCES tenant_users(id) ON DELETE CASCADE,
    session_id uuid REFERENCES auth_sessions(id) ON DELETE CASCADE,
    scopes text[] NOT NULL,
    redirect_uri text NOT NULL,
    resource text NOT NULL,
    state text,
    code_challenge text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','used')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    code_hash text UNIQUE,
    grant_id uuid,
    FOREIGN KEY (tenant_id,client_id) REFERENCES dashboard_mcp_clients(tenant_id,id),
    FOREIGN KEY (tenant_id,grant_id) REFERENCES dashboard_mcp_grants(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX dashboard_mcp_authorizations_expiry_idx ON dashboard_mcp_authorizations(tenant_id,expires_at);

CREATE TABLE dashboard_mcp_tokens (
    token_hash text PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    grant_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('access','refresh')),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (tenant_id,grant_id) REFERENCES dashboard_mcp_grants(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX dashboard_mcp_tokens_grant_idx ON dashboard_mcp_tokens(tenant_id,grant_id);
