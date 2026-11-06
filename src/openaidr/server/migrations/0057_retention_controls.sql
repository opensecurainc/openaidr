ALTER TABLE tenant_telemetry_retention
    DROP CONSTRAINT tenant_telemetry_retention_mode_check,
    ADD CONSTRAINT tenant_telemetry_retention_mode_check
        CHECK (mode IN ('7','30','90','automatic','unlimited')),
    ADD COLUMN cleanup_threshold_percent smallint
        CHECK (cleanup_threshold_percent IN (70,80,90));

-- Preserve existing policies until an administrator saves new settings.
UPDATE tenant_telemetry_retention SET cleanup_threshold_percent=80 WHERE mode='automatic';
