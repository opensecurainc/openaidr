CREATE TABLE session_activity_summaries (
    session_id uuid NOT NULL REFERENCES agent_sessions(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    time_zone text NOT NULL,
    requested_since timestamptz NOT NULL,
    requested_through timestamptz NOT NULL,
    requested_event_count bigint NOT NULL,
    key_fingerprint text NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','ready','unavailable')),
    summary text CHECK (length(summary) BETWEEN 1 AND 240),
    generated_at timestamptz,
    last_requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_attempt_at timestamptz,
    refresh_after timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_token uuid,
    PRIMARY KEY (session_id,time_zone)
);
CREATE INDEX session_activity_summaries_due_idx ON session_activity_summaries(refresh_after);
CREATE INDEX session_activity_summaries_tenant_idx ON session_activity_summaries(tenant_id,last_attempt_at);
