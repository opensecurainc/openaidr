-- Bind new paid admissions to the connection selected when the scan lease was
-- claimed. NULL preserves uncertainty for leases created before this migration.
ALTER TABLE skill_bundles ADD COLUMN model_connection_binding text
    CHECK (model_connection_binding = 'direct' OR model_connection_binding ~ '^[0-9a-f]{64}$');
