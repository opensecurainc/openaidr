ALTER TABLE sensor_activity
    ADD COLUMN health_report jsonb,
    ADD COLUMN health_reported_at timestamptz;
