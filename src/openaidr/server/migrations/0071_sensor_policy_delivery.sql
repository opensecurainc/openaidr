ALTER TABLE sensor_activity
    ADD COLUMN policy_delivery text,
    ADD COLUMN policy_delivery_reported_at timestamptz;
