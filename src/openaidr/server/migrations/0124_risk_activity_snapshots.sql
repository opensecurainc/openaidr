CREATE TABLE risk_activity_snapshots (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    time_zone text NOT NULL,
    since timestamptz,
    until timestamptz,
    refresh_after timestamptz NOT NULL DEFAULT clock_timestamp(),
    refresh_failed boolean NOT NULL DEFAULT false,
    last_requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,time_zone),
    CHECK ((since IS NULL) = (until IS NULL))
);

CREATE TABLE risk_activity_rows (
    tenant_id uuid NOT NULL,
    time_zone text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('sessions','users')),
    id text NOT NULL,
    body jsonb NOT NULL,
    PRIMARY KEY (tenant_id,time_zone,kind,id),
    FOREIGN KEY (tenant_id,time_zone) REFERENCES risk_activity_snapshots(tenant_id,time_zone) ON DELETE CASCADE
);
