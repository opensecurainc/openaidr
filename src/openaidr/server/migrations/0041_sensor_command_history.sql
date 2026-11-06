-- Command history is listed per sensor, newest first; the pending index
-- covers only undelivered rows.
CREATE INDEX sensor_commands_history_idx ON sensor_commands (tenant_id, sensor_id, created_at DESC, id DESC);
