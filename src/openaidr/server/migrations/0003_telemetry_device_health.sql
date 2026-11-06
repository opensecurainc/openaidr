-- NULL distinguishes older sensors from sensors explicitly reporting no queue.
ALTER TABLE sensors ADD COLUMN telemetry_queue_depth bigint
    CHECK (telemetry_queue_depth IS NULL OR telemetry_queue_depth >= 0);
