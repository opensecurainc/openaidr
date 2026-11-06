ALTER TABLE sensor_activity
    ADD COLUMN latest_signed_in_user text NOT NULL DEFAULT '',
    ADD COLUMN latest_signed_in_at timestamptz;
