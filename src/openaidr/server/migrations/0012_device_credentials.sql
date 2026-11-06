-- Device credentials are additive. Legacy sensor bearer credentials remain valid
-- until explicit certificate activation or revocation retires them.
ALTER TABLE sensors ADD COLUMN credential_generation bigint NOT NULL DEFAULT 0
    CHECK (credential_generation >= 0);
ALTER TABLE sensors ADD CONSTRAINT sensors_tenant_identity UNIQUE (tenant_id, id);

CREATE TABLE device_issuers (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    fingerprint text NOT NULL UNIQUE CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    certificate_pem text NOT NULL,
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL CHECK (not_after > not_before),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX device_issuers_active ON device_issuers (tenant_id)
    WHERE state = 'active';

CREATE TABLE sensor_certificates (
    fingerprint text PRIMARY KEY CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    tenant_id uuid NOT NULL,
    sensor_id uuid NOT NULL,
    issuer_id uuid NOT NULL,
    serial text NOT NULL,
    certificate_pem text NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'active', 'revoked')),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL CHECK (not_after > not_before),
    overlap_until timestamptz,
    activated_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, sensor_id) REFERENCES sensors(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, issuer_id) REFERENCES device_issuers(tenant_id, id),
    UNIQUE (issuer_id, serial),
    UNIQUE (tenant_id, sensor_id, generation),
    UNIQUE (tenant_id, sensor_id, fingerprint)
);

CREATE TABLE device_credential_requests (
    tenant_id uuid NOT NULL,
    request_id uuid NOT NULL,
    sensor_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN ('enroll', 'migrate', 'renew', 'recover')),
    credential_reference text NOT NULL CHECK (credential_reference ~ '^[0-9a-f]{64}$'),
    csr_sha256 text NOT NULL CHECK (csr_sha256 ~ '^[0-9a-f]{64}$'),
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    certificate_fingerprint text NOT NULL,
    response jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, request_id),
    FOREIGN KEY (tenant_id, sensor_id, certificate_fingerprint)
        REFERENCES sensor_certificates(tenant_id, sensor_id, fingerprint)
);

CREATE TABLE device_recovery_tokens (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    sensor_id uuid NOT NULL,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, sensor_id) REFERENCES sensors(tenant_id, id) ON DELETE CASCADE
);
