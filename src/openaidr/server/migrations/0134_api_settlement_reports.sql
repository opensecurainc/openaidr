-- Latest bounded tenant accounting observation. No accounting state is changed.
CREATE TABLE platform_api_settlement_reports (
    tenant_id uuid PRIMARY KEY REFERENCES cloud_deployments(id),
    generated_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    state text NOT NULL CHECK (state IN ('current','unavailable')),
    reason text NOT NULL CHECK (reason IN ('ok','query_timeout','read_failed','out_of_order')),
    observed_at timestamptz,
    observation jsonb CHECK (octet_length(observation::text)<=4096),
    CHECK ((observed_at IS NULL)=(observation IS NULL))
);
