-- Local passwords remain the default. External membership is explicitly bound.
ALTER TABLE tenant_users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE tenant_users ADD COLUMN oidc_issuer text;
ALTER TABLE tenant_users ADD COLUMN oidc_subject text;
ALTER TABLE tenant_users ADD CONSTRAINT tenant_user_identity CHECK (
    (password_hash IS NOT NULL AND oidc_issuer IS NULL AND oidc_subject IS NULL)
    OR (password_hash IS NULL AND oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL)
);
CREATE UNIQUE INDEX tenant_users_oidc_idx
    ON tenant_users(tenant_id, oidc_issuer, oidc_subject)
    WHERE oidc_subject IS NOT NULL;

ALTER TABLE auth_sessions ADD COLUMN oidc_issuer text;
ALTER TABLE auth_sessions ADD COLUMN verified_at timestamptz;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_session_identity CHECK (
    (oidc_issuer IS NULL AND verified_at IS NULL)
    OR (oidc_issuer IS NOT NULL AND verified_at IS NOT NULL
        AND expires_at <= verified_at + interval '1 hour')
);

CREATE TABLE cloud_bootstraps (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
    bootstrap_id uuid NOT NULL UNIQUE,
    specification jsonb NOT NULL,
    owner_invite_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE oidc_login_transactions (
    state_hash text PRIMARY KEY,
    browser_hash text NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    nonce text NOT NULL,
    verifier text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now() + interval '10 minutes'
);
CREATE INDEX oidc_transactions_expiry_idx ON oidc_login_transactions(expires_at);

CREATE TABLE oidc_pending_memberships (
    token_hash text PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    invite_id uuid NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
    issuer text NOT NULL,
    subject text NOT NULL,
    email text NOT NULL,
    name text NOT NULL,
    verified_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL DEFAULT now() + interval '10 minutes'
);
CREATE INDEX oidc_pending_expiry_idx ON oidc_pending_memberships(expires_at);
