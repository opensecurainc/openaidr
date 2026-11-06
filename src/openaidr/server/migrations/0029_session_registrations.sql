CREATE TABLE session_registrations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    product text NOT NULL CHECK (product IN ('codex-cli', 'claude-code')),
    external_id text CHECK (length(external_id) BETWEEN 1 AND 256),
    challenge_hash text,
    expires_at timestamptz NOT NULL,
    owner_user_id uuid REFERENCES tenant_users(id) ON DELETE SET NULL,
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (owner_user_id IS NULL OR verified_at IS NOT NULL),
    CHECK (verified_at IS NULL OR (external_id IS NOT NULL AND challenge_hash IS NULL)),
    CHECK (challenge_hash IS NULL OR external_id IS NOT NULL)
);
CREATE UNIQUE INDEX session_registrations_native_idx
    ON session_registrations (tenant_id, sensor_id, product, external_id)
    WHERE external_id IS NOT NULL;
CREATE UNIQUE INDEX session_registrations_challenge_idx
    ON session_registrations (challenge_hash) WHERE challenge_hash IS NOT NULL;
CREATE INDEX session_registrations_owner_idx
    ON session_registrations (tenant_id, owner_user_id) WHERE verified_at IS NOT NULL;

ALTER TABLE agent_sessions ADD COLUMN registration_id uuid
    REFERENCES session_registrations(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX agent_sessions_registration_idx
    ON agent_sessions (registration_id) WHERE registration_id IS NOT NULL;

-- Older receivers must not mix unregistered observations into owned evidence.
CREATE FUNCTION enforce_event_session_registration() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    stored_session agent_sessions%ROWTYPE;
    registration session_registrations%ROWTYPE;
BEGIN
    SELECT * INTO stored_session FROM agent_sessions WHERE id=NEW.session_id;
    IF stored_session.registration_id IS NULL THEN
        IF (NEW.body->'session') ? 'registration_id' THEN
            RAISE EXCEPTION 'registered event requires its registered session'
                USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    SELECT * INTO registration FROM session_registrations
        WHERE id=stored_session.registration_id;
    IF lower(NEW.body #>> '{session,registration_id}') IS DISTINCT FROM registration.id::text
       OR NEW.tenant_id IS DISTINCT FROM registration.tenant_id
       OR NEW.sensor_id IS DISTINCT FROM registration.sensor_id
       OR NEW.product IS DISTINCT FROM registration.product
       OR NEW.body #>> '{agent,product}' IS DISTINCT FROM registration.product
       OR NEW.agent_id IS DISTINCT FROM stored_session.agent_id
       OR NEW.body #>> '{session,id}' IS DISTINCT FROM registration.external_id
       OR stored_session.tenant_id IS DISTINCT FROM registration.tenant_id
       OR stored_session.sensor_id IS DISTINCT FROM registration.sensor_id
       OR stored_session.product IS DISTINCT FROM registration.product
       OR stored_session.external_id IS DISTINCT FROM registration.external_id THEN
        RAISE EXCEPTION 'event does not match its session registration'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER events_session_registration_guard
    BEFORE INSERT OR UPDATE OF tenant_id, sensor_id, agent_id, session_id, product, body
    ON events FOR EACH ROW EXECUTE FUNCTION enforce_event_session_registration();
