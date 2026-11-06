-- Separate operator telemetry. No tenant or service business state is changed.
CREATE TABLE platform_api_operations_status (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    target_key char(64) NOT NULL,
    attempt_id uuid NOT NULL,
    attempted_at timestamptz NOT NULL,
    outcome text NOT NULL CHECK (outcome IN (
        'collecting', 'ok', 'unsupported', 'authentication_failed', 'http_error',
        'connection_failed', 'timeout', 'invalid_snapshot', 'secret_unavailable')),
    http_status integer CHECK (http_status BETWEEN 100 AND 599),
    elapsed_seconds double precision CHECK (elapsed_seconds >= 0 AND elapsed_seconds < 60),
    last_observed_at timestamptz
);

CREATE TABLE platform_api_operations_samples (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target_key char(64) NOT NULL,
    collected_at timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    payload text NOT NULL CHECK (octet_length(payload) <= 16384)
);
CREATE INDEX platform_api_operations_samples_time
    ON platform_api_operations_samples (collected_at DESC, id DESC);
