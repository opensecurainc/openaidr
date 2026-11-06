-- Apply with server processes stopped: activity columns move off credential rows.
CREATE TABLE sensor_activity (
    sensor_id uuid PRIMARY KEY REFERENCES sensors(id) ON DELETE CASCADE,
    version text NOT NULL DEFAULT '',
    last_heartbeat_at timestamptz,
    collectors jsonb NOT NULL DEFAULT '[]'::jsonb,
    hook_installed boolean NOT NULL DEFAULT false,
    queue_depth int NOT NULL DEFAULT 0,
    policy_version bigint NOT NULL DEFAULT 0,
    uptime_s bigint NOT NULL DEFAULT 0,
    agents_total bigint NOT NULL DEFAULT 0,
    events_total bigint NOT NULL DEFAULT 0,
    telemetry_queue_depth bigint CHECK (telemetry_queue_depth IS NULL OR telemetry_queue_depth >= 0)
);

INSERT INTO sensor_activity (
    sensor_id,version,last_heartbeat_at,collectors,hook_installed,queue_depth,
    policy_version,uptime_s,agents_total,events_total,telemetry_queue_depth
)
SELECT id,version,last_heartbeat_at,collectors,hook_installed,queue_depth,
       policy_version,uptime_s,agents_total,events_total,telemetry_queue_depth
FROM sensors;

ALTER TABLE sensors
    DROP COLUMN version,
    DROP COLUMN last_heartbeat_at,
    DROP COLUMN collectors,
    DROP COLUMN hook_installed,
    DROP COLUMN queue_depth,
    DROP COLUMN policy_version,
    DROP COLUMN uptime_s,
    DROP COLUMN agents_total,
    DROP COLUMN events_total,
    DROP COLUMN telemetry_queue_depth;
