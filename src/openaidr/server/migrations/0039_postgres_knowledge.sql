ALTER TABLE tenant_knowledge
    ADD COLUMN retrieval_mode text NOT NULL DEFAULT 'legacy'
    CHECK (retrieval_mode IN ('legacy', 'postgres'));

CREATE TABLE knowledge_sources (
    tenant_id uuid NOT NULL REFERENCES tenant_knowledge(tenant_id) ON DELETE CASCADE,
    source_id text NOT NULL,
    source_type text NOT NULL CHECK (source_type IN ('markdown', 'manual')),
    title text NOT NULL,
    source_uri text NOT NULL,
    scope_key text NOT NULL DEFAULT '',
    generation bigint NOT NULL CHECK (generation > 0),
    source_version text NOT NULL,
    desired_hash text NOT NULL,
    active_revision_id uuid,
    status text NOT NULL CHECK (status IN ('pending', 'current', 'revoked')),
    freshness_seconds integer NOT NULL CHECK (freshness_seconds BETWEEN 0 AND 86400),
    verified_at timestamptz,
    fresh_until timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, source_id),
    CHECK ((status = 'current') = (active_revision_id IS NOT NULL)),
    CHECK (status <> 'current' OR (verified_at IS NOT NULL AND fresh_until IS NOT NULL))
);

CREATE TABLE knowledge_revisions (
    tenant_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    source_id text NOT NULL,
    generation bigint NOT NULL,
    source_version text NOT NULL,
    content_hash text NOT NULL,
    parser_version text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, revision_id),
    UNIQUE (tenant_id, source_id, generation),
    UNIQUE (tenant_id, source_id, revision_id),
    FOREIGN KEY (tenant_id, source_id)
        REFERENCES knowledge_sources(tenant_id, source_id) ON DELETE CASCADE
);

ALTER TABLE knowledge_sources ADD CONSTRAINT knowledge_sources_active_revision
    FOREIGN KEY (tenant_id, source_id, active_revision_id)
    REFERENCES knowledge_revisions(tenant_id, source_id, revision_id);

CREATE TABLE knowledge_passages (
    tenant_id uuid NOT NULL,
    passage_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    kind text NOT NULL CHECK (kind IN ('command', 'resource', 'reference')),
    title text NOT NULL,
    section_path text NOT NULL,
    body text NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 2000),
    content_hash text NOT NULL,
    search_vector tsvector GENERATED ALWAYS AS (
        setweight(to_tsvector('english'::regconfig, title), 'A') ||
        setweight(to_tsvector('english'::regconfig, section_path), 'B') ||
        setweight(to_tsvector('english'::regconfig, body), 'D')
    ) STORED,
    PRIMARY KEY (tenant_id, passage_id),
    UNIQUE (tenant_id, revision_id, ordinal),
    FOREIGN KEY (tenant_id, revision_id)
        REFERENCES knowledge_revisions(tenant_id, revision_id) ON DELETE CASCADE
);

CREATE INDEX knowledge_passages_search ON knowledge_passages USING gin(search_vector);
CREATE INDEX knowledge_passages_kind_revision ON knowledge_passages(tenant_id, kind, revision_id);

CREATE TABLE knowledge_passage_keys (
    tenant_id uuid NOT NULL,
    passage_id uuid NOT NULL,
    key_type text NOT NULL CHECK (key_type IN ('operation', 'resource', 'term')),
    scope_key text NOT NULL,
    lookup_value text NOT NULL,
    canonical_key text NOT NULL,
    PRIMARY KEY (tenant_id, passage_id, key_type, scope_key, lookup_value, canonical_key),
    FOREIGN KEY (tenant_id, passage_id)
        REFERENCES knowledge_passages(tenant_id, passage_id) ON DELETE CASCADE
);

CREATE INDEX knowledge_passage_key_lookup ON knowledge_passage_keys
    (tenant_id, key_type, scope_key, lookup_value) INCLUDE (passage_id, canonical_key);
