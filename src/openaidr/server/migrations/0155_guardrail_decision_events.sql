-- Extract report fields once when an event arrives, preserving its raw evidence.
CREATE TABLE guardrail_decision_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    storage_day date NOT NULL,
    time timestamptz NOT NULL,
    decision text,
    rule_id text NOT NULL,
    rule_name text NOT NULL,
    current boolean NOT NULL,
    policy_ms double precision,
    e2e_ms double precision,
    FOREIGN KEY (tenant_id,storage_day,id)
        REFERENCES event_keys(tenant_id,storage_day,id) ON DELETE CASCADE
);
CREATE INDEX guardrail_decision_events_time_idx ON guardrail_decision_events(tenant_id,time);

CREATE FUNCTION guardrail_decision_fields(payload jsonb)
RETURNS TABLE(decision text,rule_id text,rule_name text,current boolean,
              policy_ms double precision,e2e_ms double precision)
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT
           CASE WHEN NULLIF(payload->'hook'->>'failure_reason','') IS NOT NULL THEN NULL
                WHEN payload->'hook' ?| ARRAY['evaluated_decision','returned_decision','mode','check_id']
                     THEN payload->'hook'->>'evaluated_decision'
                ELSE payload->'hook'->>'decision' END AS decision,
           COALESCE(payload->'hook'->>'rule_id','') AS rule_id,
           COALESCE(payload->'hook'->>'rule_name','') AS rule_name,
           COALESCE(jsonb_typeof(payload->'hook'->'latency_ms')='number',false) AS current,
           CASE WHEN jsonb_typeof(payload->'hook'->'latency_ms')='number' THEN
                CASE WHEN (payload->'hook'->>'latency_ms')::numeric BETWEEN 0 AND 3600000
                     THEN (payload->'hook'->>'latency_ms')::float8 END END AS policy_ms,
           CASE WHEN jsonb_typeof(payload->'hook'->'e2e_ms')='number' THEN
                CASE WHEN (payload->'hook'->>'e2e_ms')::numeric BETWEEN 0 AND 3600000
                     THEN (payload->'hook'->>'e2e_ms')::float8 END END AS e2e_ms;
$$;

CREATE FUNCTION project_guardrail_decision_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.kind='hook.decision' AND NEW.export_id IS NULL
        AND NEW.body->'source'->>'collector'='hook' THEN
        INSERT INTO guardrail_decision_events
            SELECT NEW.id,NEW.tenant_id,NEW.storage_day,NEW.time,f.*
            FROM guardrail_decision_fields(NEW.body) f
        ON CONFLICT (id) DO UPDATE SET time=EXCLUDED.time,decision=EXCLUDED.decision,
            rule_id=EXCLUDED.rule_id,rule_name=EXCLUDED.rule_name,current=EXCLUDED.current,
            policy_ms=EXCLUDED.policy_ms,e2e_ms=EXCLUDED.e2e_ms;
    ELSE
        DELETE FROM guardrail_decision_events WHERE id=NEW.id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER events_project_guardrail_decision_insert AFTER INSERT ON events
    FOR EACH ROW WHEN (NEW.kind='hook.decision' AND NEW.export_id IS NULL
        AND NEW.body->'source'->>'collector'='hook')
    EXECUTE FUNCTION project_guardrail_decision_event();
CREATE TRIGGER events_project_guardrail_decision_update AFTER UPDATE OF body,kind,export_id,time ON events
    FOR EACH ROW WHEN (
        (OLD.kind='hook.decision' AND OLD.export_id IS NULL AND OLD.body->'source'->>'collector'='hook')
        OR (NEW.kind='hook.decision' AND NEW.export_id IS NULL AND NEW.body->'source'->>'collector'='hook'))
    EXECUTE FUNCTION project_guardrail_decision_event();

INSERT INTO guardrail_decision_events
    SELECT e.id,e.tenant_id,e.storage_day,e.time,f.*
    FROM events e CROSS JOIN LATERAL guardrail_decision_fields(e.body) f
    WHERE e.kind='hook.decision' AND e.export_id IS NULL AND e.body->'source'->>'collector'='hook';
ANALYZE guardrail_decision_events;
