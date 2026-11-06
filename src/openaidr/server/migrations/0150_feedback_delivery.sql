CREATE TABLE tenant_feedback_settings (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    sharing_scope text NOT NULL DEFAULT 'none' CHECK (sharing_scope IN ('none','metadata','evidence')),
    retention_days integer NOT NULL DEFAULT 7 CHECK (retention_days BETWEEN 1 AND 30),
    origin text NOT NULL DEFAULT '',
    enabled_at timestamptz,
    version integer NOT NULL DEFAULT 0
);

CREATE TABLE feedback_delivery (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    feedback_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision>0),
    subject_type text NOT NULL CHECK (subject_type IN ('hook_check','case')),
    origin text NOT NULL,
    sharing_scope text NOT NULL CHECK (sharing_scope IN ('metadata','evidence')),
    settings_version integer NOT NULL,
    payload jsonb,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','cancelled','deleting','deleted','failed')),
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    receipt jsonb,
    error_code text NOT NULL DEFAULT '',
    PRIMARY KEY(tenant_id,feedback_id,revision)
);
CREATE INDEX feedback_delivery_pending_idx ON feedback_delivery(tenant_id,next_attempt_at)
    WHERE status IN ('pending','deleting');
