ALTER TABLE knowledge_sources DROP CONSTRAINT knowledge_sources_source_type_check;
ALTER TABLE knowledge_sources ADD CONSTRAINT knowledge_sources_source_type_check
    CHECK (source_type IN ('markdown', 'manual', 'upload'));
