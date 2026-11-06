ALTER TABLE sensor_activity
    ADD COLUMN cpu_percent double precision CHECK (cpu_percent >= 0 AND cpu_percent <= 1000000),
    ADD COLUMN memory_rss_bytes bigint CHECK (memory_rss_bytes >= 0);

-- Keep the last heartbeat in each minute to bound storage per sensor.
-- History survives the documented rollback of sensor_activity.
CREATE TABLE IF NOT EXISTS sensor_resource_samples (
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    sampled_at timestamptz NOT NULL,
    cpu_percent double precision CHECK (cpu_percent >= 0 AND cpu_percent <= 1000000),
    memory_rss_bytes bigint CHECK (memory_rss_bytes >= 0),
    PRIMARY KEY (sensor_id, sampled_at)
);
CREATE INDEX IF NOT EXISTS sensor_resource_samples_expiry ON sensor_resource_samples(sampled_at);
