ALTER TABLE knowledge_sources DROP CONSTRAINT knowledge_sources_source_type_check;
ALTER TABLE knowledge_sources ADD CONSTRAINT knowledge_sources_source_type_check
    CHECK (source_type IN ('markdown', 'manual', 'upload', 'mcp'));

CREATE TABLE knowledge_mcp_connections (
    tenant_id uuid NOT NULL REFERENCES tenant_knowledge(tenant_id) ON DELETE CASCADE,
    connection_id uuid NOT NULL,
    name text NOT NULL,
    endpoint text NOT NULL,
    encrypted_token text NOT NULL DEFAULT '',
    resource_uris jsonb NOT NULL DEFAULT '[]',
    synced_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, connection_id)
);
