-- Keep aggregate receipt lookups independent of the wide event JSON heap.
-- Identity cleanup removes this projection with its retained source event.
CREATE TABLE hook_delivery_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    storage_day date NOT NULL,
    sensor_id uuid NOT NULL,
    product text NOT NULL,
    received_at timestamptz NOT NULL,
    request_id uuid NOT NULL,
    delivery_status text NOT NULL CHECK (delivery_status IN ('delivered','timed_out','failed')),
    delivered_decision text NOT NULL CHECK (delivered_decision IN ('allow','warn','ask','deny')),
    FOREIGN KEY (tenant_id,storage_day,id)
        REFERENCES event_keys(tenant_id,storage_day,id) ON DELETE CASCADE
);
CREATE INDEX hook_delivery_events_request_idx
    ON hook_delivery_events(tenant_id,sensor_id,request_id,received_at,id);

CREATE FUNCTION project_hook_delivery_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.kind='sensor' AND NEW.export_id IS NULL
        AND NEW.body->'source'->>'collector'='hook-delivery'
        AND NEW.body->'source'->>'hook_request_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        AND NEW.body->'hook'->>'delivery_status' IN ('delivered','timed_out','failed')
        AND NEW.body->'hook'->>'delivered_decision' IN ('allow','warn','ask','deny') THEN
        INSERT INTO hook_delivery_events
            (id,tenant_id,storage_day,sensor_id,product,received_at,request_id,delivery_status,delivered_decision)
        VALUES (NEW.id,NEW.tenant_id,NEW.storage_day,NEW.sensor_id,NEW.product,NEW.received_at,
            (NEW.body->'source'->>'hook_request_id')::uuid,
            NEW.body->'hook'->>'delivery_status',NEW.body->'hook'->>'delivered_decision')
        ON CONFLICT (id) DO UPDATE SET sensor_id=EXCLUDED.sensor_id,product=EXCLUDED.product,
            received_at=EXCLUDED.received_at,request_id=EXCLUDED.request_id,
            delivery_status=EXCLUDED.delivery_status,delivered_decision=EXCLUDED.delivered_decision;
    ELSE
        DELETE FROM hook_delivery_events WHERE id=NEW.id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER events_project_hook_delivery_insert AFTER INSERT ON events
    FOR EACH ROW WHEN (NEW.kind='sensor' AND NEW.export_id IS NULL
        AND NEW.body->'source'->>'collector'='hook-delivery')
    EXECUTE FUNCTION project_hook_delivery_event();
CREATE TRIGGER events_project_hook_delivery_update
    AFTER UPDATE OF body,kind,export_id,sensor_id,product,received_at ON events
    FOR EACH ROW WHEN (
        (OLD.kind='sensor' AND OLD.export_id IS NULL AND OLD.body->'source'->>'collector'='hook-delivery')
        OR (NEW.kind='sensor' AND NEW.export_id IS NULL AND NEW.body->'source'->>'collector'='hook-delivery'))
    EXECUTE FUNCTION project_hook_delivery_event();

INSERT INTO hook_delivery_events
    (id,tenant_id,storage_day,sensor_id,product,received_at,request_id,delivery_status,delivered_decision)
SELECT id,tenant_id,storage_day,sensor_id,product,received_at,
    CASE WHEN body->'source'->>'hook_request_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
         THEN (body->'source'->>'hook_request_id')::uuid END,
    body->'hook'->>'delivery_status',body->'hook'->>'delivered_decision'
FROM events WHERE kind='sensor' AND export_id IS NULL
    AND body->'source'->>'collector'='hook-delivery'
    AND body->'source'->>'hook_request_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND body->'hook'->>'delivery_status' IN ('delivered','timed_out','failed')
    AND body->'hook'->>'delivered_decision' IN ('allow','warn','ask','deny');
ANALYZE hook_delivery_events;
