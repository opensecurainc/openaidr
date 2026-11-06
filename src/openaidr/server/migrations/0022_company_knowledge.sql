CREATE TABLE tenant_knowledge (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE knowledge_documents (
    tenant_id uuid NOT NULL REFERENCES tenant_knowledge(tenant_id) ON DELETE CASCADE,
    id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('command', 'resource')),
    title text NOT NULL,
    keywords text[] NOT NULL,
    body text NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX knowledge_document_keywords ON knowledge_documents USING gin (keywords);
