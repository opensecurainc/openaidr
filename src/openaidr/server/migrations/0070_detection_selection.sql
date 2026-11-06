ALTER TABLE tenant_session_detection_settings
    ADD COLUMN selection_policy text NOT NULL DEFAULT 'legacy' CHECK (selection_policy IN ('legacy','risk_budget')),
    ADD COLUMN history_days integer NOT NULL DEFAULT 7 CHECK (history_days BETWEEN 1 AND 90),
    ADD COLUMN investigation_percent numeric NOT NULL DEFAULT 1 CHECK (investigation_percent>0 AND investigation_percent<=100),
    ADD COLUMN sample_percent numeric NOT NULL DEFAULT 0.1 CHECK (sample_percent>=0 AND sample_percent<=investigation_percent),
    ADD COLUMN action_risk_threshold integer NOT NULL DEFAULT 70 CHECK (action_risk_threshold BETWEEN 1 AND 100),
    ADD COLUMN urgent_risk_threshold integer NOT NULL DEFAULT 95 CHECK (urgent_risk_threshold BETWEEN action_risk_threshold AND 100),
    ADD COLUMN session_high_risk_actions integer NOT NULL DEFAULT 2 CHECK (session_high_risk_actions>0),
    ADD COLUMN user_high_risk_actions integer NOT NULL DEFAULT 3 CHECK (user_high_risk_actions>0);

CREATE TABLE session_detection_owners (
    session_id uuid PRIMARY KEY REFERENCES agent_sessions(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_user_id uuid REFERENCES tenant_users(id) ON DELETE SET NULL,
    verified_by_user_id uuid REFERENCES tenant_users(id) ON DELETE SET NULL,
    verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz
);
CREATE INDEX detection_owner_history_idx ON session_detection_owners(tenant_id,owner_user_id,session_id)
    WHERE revoked_at IS NULL;

CREATE VIEW detection_session_identities AS
    SELECT s.id AS session_id,s.tenant_id,s.sensor_id,s.registration_id,r.owner_user_id,r.verified_at
      FROM agent_sessions s JOIN session_registrations r
        ON r.id=s.registration_id AND r.tenant_id=s.tenant_id AND r.sensor_id=s.sensor_id
      WHERE r.verified_at IS NOT NULL AND r.owner_user_id IS NOT NULL
    UNION ALL
    SELECT s.id,s.tenant_id,s.sensor_id,s.registration_id,o.owner_user_id,o.verified_at
      FROM agent_sessions s JOIN session_detection_owners o
        ON o.session_id=s.id AND o.tenant_id=s.tenant_id
      WHERE s.registration_id IS NULL AND o.revoked_at IS NULL AND o.owner_user_id IS NOT NULL;

ALTER TABLE session_snapshots DROP CONSTRAINT snapshot_session_scope,
    ADD CONSTRAINT snapshot_session_scope CHECK ((registration_id IS NULL)<>(session_id IS NULL));
ALTER TABLE session_investigation_jobs DROP CONSTRAINT investigation_session_scope,
    ADD CONSTRAINT investigation_session_scope CHECK ((registration_id IS NULL)<>(session_id IS NULL)),
    DROP CONSTRAINT session_investigation_jobs_routing_reason_check,
    ADD CONSTRAINT session_investigation_jobs_routing_reason_check CHECK (
        routing_reason IN ('risk_threshold','persistent_gap','session_risk','user_pattern','urgent_risk','sample'));
CREATE INDEX investigation_user_running_idx ON session_investigation_jobs(tenant_id,owner_user_id)
    WHERE state='running';

CREATE TABLE session_detection_signals (
    session_id uuid PRIMARY KEY REFERENCES agent_sessions(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action_risk_threshold integer NOT NULL,
    peak numeric,
    high_actions bigint NOT NULL,
    evidence_signature text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX detection_signal_tenant_idx ON session_detection_signals(tenant_id,session_id);
ALTER TABLE session_snapshots ADD COLUMN selection_signature text;
