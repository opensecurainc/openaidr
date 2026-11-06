ALTER TABLE agent_cost_records
    ADD COLUMN sensor_id uuid REFERENCES sensors(id) ON DELETE SET NULL,
    ADD COLUMN reasoning_effort text NOT NULL DEFAULT 'unknown';

UPDATE agent_cost_records r SET sensor_id=e.sensor_id
FROM telemetry_exports e WHERE e.id=r.export_id AND e.tenant_id=r.tenant_id;

CREATE INDEX agent_cost_records_sensor_time_idx
    ON agent_cost_records (tenant_id,sensor_id,happened_at) WHERE is_usage;

-- Retained exports can supply request effort without changing accounted usage.
UPDATE telemetry_exports SET costs_processed_at=NULL,costs_retry_at=NULL,costs_reattribute=true
WHERE signal='logs' AND costs_processed_at IS NOT NULL;
