ALTER TABLE agents ADD COLUMN has_native_activity boolean NOT NULL DEFAULT false;
ALTER TABLE agent_sessions ADD COLUMN has_native_activity boolean NOT NULL DEFAULT false;

-- Keep activity state atomic with event insertion, including older writers.
CREATE FUNCTION record_native_activity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE agents SET has_native_activity=true
        WHERE id=NEW.agent_id AND tenant_id=NEW.tenant_id AND NOT has_native_activity;
    UPDATE agent_sessions SET has_native_activity=true
        WHERE id=NEW.session_id AND tenant_id=NEW.tenant_id AND NOT has_native_activity;
    RETURN NEW;
END;
$$;
CREATE TRIGGER events_native_activity AFTER INSERT ON events
    FOR EACH ROW WHEN (NEW.kind<>'sensor') EXECUTE FUNCTION record_native_activity();
