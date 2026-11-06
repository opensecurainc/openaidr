-- Keep version 1 ordering stable for retained evidence and older writers.
CREATE FUNCTION session_evidence_valid_v1(metadata jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT COALESCE(
        jsonb_typeof(metadata)='object'
        AND jsonb_typeof(metadata->'version')='number'
        AND metadata->>'version'='1'
        AND jsonb_typeof(metadata->'logical_id')='string'
        AND (metadata->>'logical_id') COLLATE "C" ~ '^[A-Za-z0-9_.:-]{1,128}$'
        AND jsonb_typeof(metadata->'observation_id')='string'
        AND (metadata->>'observation_id') COLLATE "C" ~ '^[A-Za-z0-9_.:-]{1,128}$'
        AND jsonb_typeof(metadata->'stream_id')='string'
        AND (metadata->>'stream_id') COLLATE "C" ~ '^[A-Za-z0-9_.:-]{1,128}$'
        AND jsonb_typeof(metadata->'sequence')='number'
        AND metadata->>'sequence' ~ '^[0-9]{1,19}$'
        AND (length(metadata->>'sequence')<19
             OR (metadata->>'sequence') COLLATE "C"<='9223372036854775807')
        AND jsonb_typeof(metadata->'part')='number'
        AND metadata->>'part' ~ '^[0-9]{1,19}$'
        AND (length(metadata->>'part')<19
             OR (metadata->>'part') COLLATE "C"<='9223372036854775807')
        AND CASE WHEN jsonb_typeof(metadata->'gaps')='array'
            THEN jsonb_array_length(metadata->'gaps')<=32 ELSE false END
        AND metadata->'gaps' <@ '["skipped_history","source_reset","parser_restart",
            "malformed_record","oversized_record","unsupported_content","skipped_content",
            "missing_tool_call","capture_disabled","content_truncated","content_redacted"]'::jsonb
        AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(
                CASE WHEN jsonb_typeof(metadata->'gaps')='array'
                     THEN metadata->'gaps' ELSE '[]'::jsonb END
            ) AS gap WHERE jsonb_typeof(gap)<>'string'
        ), false
    );
$$;

ALTER TABLE events
    ADD COLUMN evidence_stream text GENERATED ALWAYS AS (
        CASE WHEN session_evidence_valid_v1(body->'evidence')
             THEN body->'evidence'->>'stream_id' ELSE '' END
    ) STORED,
    ADD COLUMN evidence_sequence bigint GENERATED ALWAYS AS (
        CASE WHEN session_evidence_valid_v1(body->'evidence')
             THEN (body->'evidence'->>'sequence')::bigint ELSE -1 END
    ) STORED,
    ADD COLUMN evidence_part bigint GENERATED ALWAYS AS (
        CASE WHEN session_evidence_valid_v1(body->'evidence')
             THEN (body->'evidence'->>'part')::bigint ELSE -1 END
    ) STORED;

CREATE INDEX events_session_evidence_order_idx ON events
    (tenant_id,session_id,evidence_stream COLLATE "C",evidence_sequence,evidence_part,time,id)
    WHERE session_id IS NOT NULL;
