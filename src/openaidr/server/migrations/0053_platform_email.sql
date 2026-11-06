-- Staff notifications are committed with the action that creates them.
CREATE TABLE platform_email_outbox (
    id uuid PRIMARY KEY,
    event_key text NOT NULL,
    admin_id uuid NOT NULL REFERENCES platform_admins(id) ON DELETE CASCADE,
    recipient text NOT NULL,
    subject text NOT NULL,
    body text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed','cancelled')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz,
    error_code text NOT NULL DEFAULT '',
    UNIQUE(event_key, admin_id)
);
CREATE INDEX platform_email_pending_idx ON platform_email_outbox(next_attempt_at, id) WHERE status='pending';
