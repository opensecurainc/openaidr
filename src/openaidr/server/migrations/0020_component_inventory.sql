CREATE TABLE inventory_roots (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    source text NOT NULL,
    root text NOT NULL,
    platform text NOT NULL,
    scope text NOT NULL CHECK (scope IN ('system','user','project','unknown')),
    user_name text NOT NULL DEFAULT '',
    environment text NOT NULL DEFAULT '',
    status text NOT NULL CHECK (status IN ('ok','partial','error','unavailable')),
    message text NOT NULL DEFAULT '',
    collected_at timestamptz NOT NULL,
    last_success_at timestamptz,
    UNIQUE (id,tenant_id,sensor_id)
);
CREATE INDEX inventory_roots_page ON inventory_roots(tenant_id,left(lower(root),256),id);
CREATE INDEX inventory_roots_sensor ON inventory_roots(sensor_id);

CREATE TABLE inventory_components (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    sensor_id uuid NOT NULL,
    root_id uuid NOT NULL,
    key text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('application','package','skill','mcp_server','plugin')),
    ecosystem text NOT NULL CHECK (ecosystem IN ('','npm','pypi')),
    identifier text NOT NULL,
    name text NOT NULL,
    version text NOT NULL DEFAULT '',
    path text NOT NULL DEFAULT '',
    publisher text NOT NULL DEFAULT '',
    architecture text NOT NULL DEFAULT '',
    evidence text NOT NULL CHECK (evidence IN ('installed','declared','configured','observed')),
    metadata jsonb NOT NULL DEFAULT '{}',
    last_seen_at timestamptz NOT NULL,
    UNIQUE (id,tenant_id,sensor_id),
    FOREIGN KEY (root_id,tenant_id,sensor_id)
        REFERENCES inventory_roots(id,tenant_id,sensor_id) ON DELETE CASCADE
);
CREATE INDEX inventory_components_page ON inventory_components(tenant_id,left(lower(name),256),id);
CREATE INDEX inventory_components_root ON inventory_components(root_id);

CREATE TABLE inventory_relationships (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    sensor_id uuid NOT NULL,
    root_id uuid NOT NULL,
    from_component_id uuid NOT NULL,
    to_component_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('depends_on','configured_with','provides')),
    evidence text NOT NULL CHECK (evidence IN ('declared','configured','observed')),
    path text NOT NULL DEFAULT '',
    last_seen_at timestamptz NOT NULL,
    FOREIGN KEY (root_id,tenant_id,sensor_id)
        REFERENCES inventory_roots(id,tenant_id,sensor_id) ON DELETE CASCADE,
    FOREIGN KEY (from_component_id,tenant_id,sensor_id)
        REFERENCES inventory_components(id,tenant_id,sensor_id) ON DELETE CASCADE,
    FOREIGN KEY (to_component_id,tenant_id,sensor_id)
        REFERENCES inventory_components(id,tenant_id,sensor_id) ON DELETE CASCADE
);
CREATE INDEX inventory_relationships_page ON inventory_relationships(tenant_id,id);
CREATE INDEX inventory_relationships_root ON inventory_relationships(root_id);
CREATE INDEX inventory_relationships_from ON inventory_relationships(from_component_id);
CREATE INDEX inventory_relationships_to ON inventory_relationships(to_component_id);
