ALTER TABLE knowledge_mcp_connections
    ADD COLUMN auth_type text NOT NULL DEFAULT 'none'
        CHECK (auth_type IN ('none', 'bearer', 'basic', 'header')),
    ADD COLUMN imports jsonb NOT NULL DEFAULT '[]';

UPDATE knowledge_mcp_connections SET
    auth_type = CASE WHEN encrypted_token <> '' THEN 'bearer' ELSE 'none' END,
    imports = COALESCE((SELECT jsonb_agg(jsonb_build_object('kind', 'resource', 'uri', value))
                       FROM jsonb_array_elements_text(resource_uris)), '[]');
