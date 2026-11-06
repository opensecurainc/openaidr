CREATE TABLE tenant_guardrail_settings (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    version bigint NOT NULL DEFAULT 1 CHECK (version>0),
    enabled boolean NOT NULL DEFAULT false,
    ask_threshold smallint CHECK (ask_threshold BETWEEN 0 AND 100),
    block_threshold smallint CHECK (block_threshold BETWEEN 0 AND 100),
    timeout_ms integer CHECK (timeout_ms BETWEEN 100 AND 10000),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (ask_threshold<=block_threshold),
    CHECK (NOT enabled OR (ask_threshold IS NOT NULL AND block_threshold IS NOT NULL
                           AND timeout_ms IS NOT NULL))
);

ALTER TABLE session_registrations ADD COLUMN assessment_mode text NOT NULL DEFAULT 'legacy'
    CHECK (assessment_mode IN ('legacy','inline'));

CREATE FUNCTION preserve_session_assessment_mode() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.assessment_mode IS DISTINCT FROM OLD.assessment_mode THEN
        RAISE EXCEPTION 'session assessment mode is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER session_assessment_mode_guard BEFORE UPDATE OF assessment_mode
    ON session_registrations FOR EACH ROW EXECUTE FUNCTION preserve_session_assessment_mode();

CREATE TABLE inline_guardrail_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    registration_id uuid NOT NULL REFERENCES session_registrations(id) ON DELETE CASCADE,
    owner_user_id uuid REFERENCES tenant_users(id) ON DELETE SET NULL,
    logical_id text NOT NULL CHECK (length(logical_id) BETWEEN 1 AND 128),
    event_id uuid NOT NULL UNIQUE,
    action_commitment text NOT NULL,
    payload_sha256 text NOT NULL,
    target_body jsonb NOT NULL,
    captured_context jsonb NOT NULL,
    prepared_state jsonb NOT NULL,
    model text NOT NULL,
    rubric_version integer NOT NULL,
    status text NOT NULL CHECK (status IN ('pending','scored','unavailable')),
    assessment jsonb,
    claim_token uuid,
    deadline_at timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (registration_id,logical_id),
    CHECK (status<>'pending' OR (claim_token IS NOT NULL AND deadline_at IS NOT NULL)),
    CHECK ((status='pending' AND completed_at IS NULL)
           OR (status<>'pending' AND assessment IS NOT NULL AND completed_at IS NOT NULL))
);
CREATE INDEX inline_guardrail_events_pending_idx ON inline_guardrail_events(deadline_at)
    WHERE status='pending';
CREATE INDEX inline_guardrail_events_registration_idx
    ON inline_guardrail_events(registration_id,created_at,id);

CREATE TABLE inline_guardrail_checks (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    registration_id uuid NOT NULL REFERENCES session_registrations(id) ON DELETE CASCADE,
    owner_user_id uuid REFERENCES tenant_users(id) ON DELETE SET NULL,
    request_id uuid NOT NULL,
    guardrail_event_id uuid NOT NULL REFERENCES inline_guardrail_events(id) ON DELETE CASCADE,
    settings_version bigint NOT NULL,
    policy_version bigint NOT NULL,
    policy_snapshot jsonb NOT NULL,
    deterministic_result jsonb NOT NULL,
    decision jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    UNIQUE (tenant_id,sensor_id,request_id),
    CHECK ((decision IS NULL)=(completed_at IS NULL))
);
CREATE INDEX inline_guardrail_checks_event_idx ON inline_guardrail_checks(guardrail_event_id);

ALTER TABLE model_usage ADD COLUMN guardrail_check_id uuid
    REFERENCES inline_guardrail_checks(id) ON DELETE SET NULL;
