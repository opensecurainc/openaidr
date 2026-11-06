-- Hardware and OS installation identifiers reported by the sensor. They help
-- recognize the same device after a reinstall or rename. They are reported
-- values and never authenticate a device.
ALTER TABLE sensors
    ADD COLUMN serial_number text NOT NULL DEFAULT '',
    ADD COLUMN hardware_uuid text NOT NULL DEFAULT '',
    ADD COLUMN machine_id text NOT NULL DEFAULT '',
    ADD COLUMN device_id_source text NOT NULL DEFAULT '';
CREATE INDEX sensors_serial_idx ON sensors (tenant_id, serial_number)
    WHERE serial_number <> '';
