-- Tenant renewal keeps the original Google verification time and a fixed cap.
-- Staff sessions retain their separate one-hour constraint.
ALTER TABLE auth_sessions DROP CONSTRAINT auth_session_identity;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_session_identity CHECK (
    (oidc_issuer IS NULL AND verified_at IS NULL)
    OR (oidc_issuer IS NOT NULL AND verified_at IS NOT NULL
        AND expires_at <= verified_at + interval '12 hours')
);
