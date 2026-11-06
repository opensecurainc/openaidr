ALTER TABLE session_snapshots
    ALTER COLUMN registration_id DROP NOT NULL,
    ADD COLUMN session_id uuid REFERENCES agent_sessions(id) ON DELETE CASCADE,
    ADD CONSTRAINT snapshot_session_scope CHECK (
        (registration_id IS NOT NULL AND session_id IS NULL)
        OR (registration_id IS NULL AND session_id IS NOT NULL AND owner_user_id IS NULL)
    );
CREATE UNIQUE INDEX ordinary_snapshot_revision_idx ON session_snapshots(session_id,revision)
    WHERE session_id IS NOT NULL;

ALTER TABLE session_investigation_jobs
    ALTER COLUMN registration_id DROP NOT NULL,
    ADD COLUMN session_id uuid REFERENCES agent_sessions(id) ON DELETE CASCADE,
    ADD CONSTRAINT investigation_session_scope CHECK (
        (registration_id IS NOT NULL AND session_id IS NULL)
        OR (registration_id IS NULL AND session_id IS NOT NULL AND owner_user_id IS NULL)
    );
CREATE INDEX ordinary_investigation_session_idx ON session_investigation_jobs(tenant_id,session_id);

CREATE TABLE ordinary_session_detection (
    session_id uuid PRIMARY KEY REFERENCES agent_sessions(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    input_version bigint NOT NULL,
    revision bigint NOT NULL DEFAULT 0,
    snapshot_id uuid REFERENCES session_snapshots(id),
    settings_version bigint NOT NULL,
    state jsonb NOT NULL,
    next_evaluation_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX ordinary_detection_due_idx ON ordinary_session_detection(tenant_id,next_evaluation_at);

-- Append-only wakeups do not lock an aggregate row in the ordinary hook path.
CREATE TABLE ordinary_session_input_dirty (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL,
    session_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX ordinary_session_dirty_idx ON ordinary_session_input_dirty(tenant_id,session_id,id);

CREATE FUNCTION mark_ordinary_session_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.session_id IS NOT NULL AND NEW.kind<>'sensor'
       AND (TG_OP='INSERT' OR NEW.risk IS DISTINCT FROM OLD.risk)
       AND EXISTS (SELECT 1 FROM agent_sessions s WHERE s.id=NEW.session_id
                   AND s.tenant_id=NEW.tenant_id AND s.registration_id IS NULL) THEN
        INSERT INTO ordinary_session_input_dirty(tenant_id,session_id)
            VALUES(NEW.tenant_id,NEW.session_id);
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER ordinary_session_dirty AFTER INSERT OR UPDATE OF risk ON events
    FOR EACH ROW EXECUTE FUNCTION mark_ordinary_session_dirty();

-- Existing captured sessions become candidates without calling a provider.
INSERT INTO ordinary_session_input_dirty(tenant_id,session_id)
    SELECT tenant_id,id FROM agent_sessions WHERE registration_id IS NULL;
