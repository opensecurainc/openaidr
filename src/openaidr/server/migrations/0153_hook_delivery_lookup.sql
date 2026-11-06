-- Receipt lookups must not scan ordinary sensor or decision event bodies.
-- Keep the event-time window unrestricted: delayed receipts still count.
CREATE INDEX events_hook_delivery_idx
    ON events(tenant_id,sensor_id,(body->'source'->>'hook_request_id'),received_at,id)
    WHERE kind='sensor' AND export_id IS NULL
      AND body->'source'->>'collector'='hook-delivery';
