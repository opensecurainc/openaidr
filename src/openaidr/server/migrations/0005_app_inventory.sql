-- Inventory belongs to authenticated sensor identity, never a supplied tenant.
CREATE TABLE application_inventory_sources (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    source text NOT NULL,
    platform text NOT NULL,
    status text NOT NULL CHECK (status IN ('ok','partial','unavailable','error')),
    message text NOT NULL DEFAULT '',
    collected_at timestamptz NOT NULL,
    last_success_at timestamptz,
    PRIMARY KEY (sensor_id, source)
);
CREATE INDEX application_inventory_sources_tenant ON application_inventory_sources(tenant_id,sensor_id);

CREATE TABLE application_inventory (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    source text NOT NULL,
    identity_hash text NOT NULL,
    identifier text NOT NULL,
    name text NOT NULL,
    version text NOT NULL DEFAULT '',
    path text NOT NULL DEFAULT '',
    publisher text NOT NULL DEFAULT '',
    architecture text NOT NULL DEFAULT '',
    kind text NOT NULL CHECK (kind IN ('application','package')),
    scope text NOT NULL CHECK (scope IN ('system','user','unknown')),
    last_seen_at timestamptz NOT NULL,
    UNIQUE(sensor_id,source,identity_hash)
);
CREATE INDEX application_inventory_tenant_page ON application_inventory(tenant_id,last_seen_at DESC,id DESC);
CREATE INDEX application_inventory_sensor_source ON application_inventory(tenant_id,sensor_id,source);
