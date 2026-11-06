-- Staff admission is operator-managed and separate from tenant identities.
ALTER TABLE platform_admins ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE platform_admins ADD COLUMN google_hosted_domain text;
ALTER TABLE platform_admins ADD COLUMN google_approved boolean NOT NULL DEFAULT false;
ALTER TABLE platform_admins ADD COLUMN google_approved_at timestamptz;
ALTER TABLE platform_admins ADD COLUMN oidc_issuer text;
ALTER TABLE platform_admins ADD COLUMN oidc_subject text;
ALTER TABLE platform_admins ADD CONSTRAINT platform_admin_identity CHECK (
    (password_hash IS NOT NULL AND google_hosted_domain IS NULL
        AND NOT google_approved AND google_approved_at IS NULL
        AND oidc_issuer IS NULL AND oidc_subject IS NULL)
    OR (password_hash IS NULL AND google_hosted_domain IS NOT NULL
        AND google_approved_at IS NOT NULL
        AND ((oidc_issuer IS NULL AND oidc_subject IS NULL)
            OR (oidc_issuer IS NOT NULL AND oidc_issuer = 'https://accounts.google.com' AND oidc_subject IS NOT NULL)))
);
CREATE UNIQUE INDEX platform_admins_oidc_idx
    ON platform_admins(oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL;

ALTER TABLE platform_sessions ADD COLUMN oidc_issuer text;
ALTER TABLE platform_sessions ADD COLUMN oidc_subject text;
ALTER TABLE platform_sessions ADD COLUMN verified_at timestamptz;
ALTER TABLE platform_sessions ADD CONSTRAINT platform_session_identity CHECK (
    (oidc_issuer IS NULL AND oidc_subject IS NULL AND verified_at IS NULL)
    OR (oidc_issuer IS NOT NULL AND oidc_issuer = 'https://accounts.google.com' AND oidc_subject IS NOT NULL
        AND verified_at IS NOT NULL AND expires_at <= verified_at + interval '1 hour')
);

CREATE TABLE staff_oidc_login_transactions (
    state_hash text PRIMARY KEY,
    browser_hash text NOT NULL,
    nonce text NOT NULL,
    verifier text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now() + interval '10 minutes'
);
CREATE INDEX staff_oidc_transactions_expiry_idx ON staff_oidc_login_transactions(expires_at);
