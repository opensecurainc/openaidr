-- Bound cost lookups by the end of an export's event window, so a recent
-- window does not scan every older export whose first event precedes it.
CREATE INDEX telemetry_exports_last_event_time_idx
    ON telemetry_exports (tenant_id, signal, last_event_unix_nano);
