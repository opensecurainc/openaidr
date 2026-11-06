-- No row means retention has never been enabled by an administrator.
CREATE TABLE tenant_telemetry_retention (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    mode text NOT NULL CHECK (mode IN ('7','30','90','automatic')),
    version bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    pressure_active boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'waiting',
    checked_at timestamptz,
    last_deleted_day date,
    scan_after_day date,
    last_cleanup_at timestamptz,
    sample_at timestamptz,
    sample_used_bytes bigint,
    sample_total_bytes bigint
);
-- A committed drop and its tombstone survive process restarts. Identity rows
-- are retired separately in bounded batches because DROP does not fire DELETE.
ALTER TABLE telemetry_partition_days ADD COLUMN retired_at timestamptz;
