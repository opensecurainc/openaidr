CREATE TABLE tenant_slack_settings (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    encrypted_webhook text NOT NULL DEFAULT '',
    enabled boolean NOT NULL DEFAULT false,
    enabled_since timestamptz NOT NULL DEFAULT clock_timestamp(),
    version bigint NOT NULL DEFAULT 1,
    next_delivery_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (NOT enabled OR encrypted_webhook <> '')
);

CREATE TABLE slack_outbox (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenant_slack_settings(tenant_id) ON DELETE CASCADE,
    event_key text NOT NULL,
    message jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed','cancelled')),
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    sent_at timestamptz,
    error_code text NOT NULL DEFAULT '',
    UNIQUE(tenant_id,event_key)
);
CREATE INDEX slack_outbox_pending_idx ON slack_outbox(tenant_id,next_attempt_at,id) WHERE status='pending';
CREATE INDEX slack_outbox_history_idx ON slack_outbox(tenant_id,created_at DESC);
CREATE INDEX investigation_slack_completed_idx ON session_investigation_jobs(tenant_id,completed_at,id)
    WHERE state IN ('completed','inconclusive');
