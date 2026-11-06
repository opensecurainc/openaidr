-- Normalized events derived from stored OTLP log records keep a durable link
-- to their export and record index, so findings can cite the raw evidence.
ALTER TABLE events ADD COLUMN export_id uuid REFERENCES telemetry_exports(id) ON DELETE SET NULL;
ALTER TABLE events ADD COLUMN export_record integer;
CREATE INDEX events_export_idx ON events (export_id, export_record);

-- Set whenever translation ran for an export, including when it produced no
-- events, so the backfill does not revisit it. NULL marks pending exports.
ALTER TABLE telemetry_exports ADD COLUMN translated_at timestamptz;
CREATE INDEX telemetry_exports_untranslated_idx
    ON telemetry_exports (received_at, id) WHERE translated_at IS NULL AND signal = 'logs';
