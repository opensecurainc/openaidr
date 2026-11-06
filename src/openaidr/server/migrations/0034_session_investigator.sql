ALTER TABLE session_investigation_attempts
    ADD COLUMN runtime jsonb,
    ADD COLUMN report jsonb,
    ADD COLUMN plan_sealed_at timestamptz,
    ADD COLUMN target_item_count bigint CHECK (target_item_count>=0),
    ADD COLUMN target_byte_count bigint CHECK (target_byte_count>=0),
    ADD COLUMN target_chunk_count integer CHECK (target_chunk_count>=0),
    ADD CONSTRAINT investigation_sealed_plan CHECK (plan_sealed_at IS NULL OR (
        target_item_count IS NOT NULL AND target_byte_count IS NOT NULL AND target_chunk_count IS NOT NULL
    ));

CREATE TABLE session_investigation_steps (
    id uuid PRIMARY KEY,
    attempt_id uuid NOT NULL REFERENCES session_investigation_attempts(id) ON DELETE CASCADE,
    ordinal integer NOT NULL CHECK (ordinal>0),
    kind text NOT NULL CHECK (kind IN ('chunk','reduce')),
    state text NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','completed','failed')),
    input_manifest jsonb NOT NULL,
    input_sha256 text NOT NULL CHECK (input_sha256 ~ '^[a-f0-9]{64}$'),
    input_bytes bigint NOT NULL CHECK (input_bytes>=0),
    result jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    UNIQUE(attempt_id,ordinal),
    UNIQUE(id,attempt_id),
    CHECK ((state='prepared')=(completed_at IS NULL)),
    CHECK (state<>'completed' OR result IS NOT NULL)
);

CREATE INDEX investigation_step_children_idx ON session_investigation_steps USING gin(input_manifest jsonb_path_ops);

CREATE TABLE session_investigation_reads (
    id uuid PRIMARY KEY,
    attempt_id uuid NOT NULL REFERENCES session_investigation_attempts(id) ON DELETE CASCADE,
    step_id uuid NOT NULL,
    tool_call_id text NOT NULL CHECK (length(tool_call_id) BETWEEN 1 AND 128),
    tool_name text NOT NULL CHECK (tool_name IN ('search_sessions','read_session')),
    arguments jsonb NOT NULL,
    status text NOT NULL CHECK (status IN ('delivered','denied')),
    session_id uuid,
    source_registration_id uuid,
    source_sensor_id uuid,
    source_snapshot_id uuid,
    response jsonb NOT NULL,
    response_sha256 text NOT NULL CHECK (response_sha256 ~ '^[a-f0-9]{64}$'),
    next_position jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(step_id,attempt_id) REFERENCES session_investigation_steps(id,attempt_id) ON DELETE CASCADE,
    UNIQUE(step_id,tool_call_id)
);
CREATE INDEX investigation_reads_attempt_idx ON session_investigation_reads(attempt_id,id);

CREATE TABLE session_investigation_requests (
    id uuid PRIMARY KEY,
    attempt_id uuid NOT NULL REFERENCES session_investigation_attempts(id) ON DELETE CASCADE,
    step_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal>0),
    input_sha256 text NOT NULL CHECK (input_sha256 ~ '^[a-f0-9]{64}$'),
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[a-f0-9]{64}$'),
    input_tokens_counted bigint NOT NULL CHECK (input_tokens_counted>=0),
    max_output_tokens bigint NOT NULL CHECK (max_output_tokens>0),
    reserved_tokens bigint NOT NULL CHECK (reserved_tokens>0),
    reserved_cost_usd numeric NOT NULL CHECK (reserved_cost_usd>0 AND reserved_cost_usd<'Infinity'::numeric),
    price_quote jsonb NOT NULL,
    usage_id uuid NOT NULL UNIQUE,
    state text NOT NULL DEFAULT 'dispatched' CHECK (state IN ('dispatched','completed','error','uncertain')),
    error_code text NOT NULL DEFAULT '',
    provider_response_id text CHECK (length(provider_response_id) BETWEEN 1 AND 256),
    dispatched_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    FOREIGN KEY(step_id,attempt_id) REFERENCES session_investigation_steps(id,attempt_id) ON DELETE CASCADE,
    UNIQUE(attempt_id,ordinal),
    UNIQUE(step_id,input_sha256),
    CHECK ((state='dispatched')=(completed_at IS NULL))
);

ALTER TABLE model_usage
    ALTER COLUMN event_id DROP NOT NULL,
    ADD COLUMN investigation_job_id uuid,
    ADD COLUMN investigation_attempt_id uuid,
    ADD COLUMN investigation_request_id uuid,
    ADD COLUMN reported_model text,
    ADD COLUMN service_tier text,
    ADD COLUMN cached_input_tokens bigint CHECK (cached_input_tokens>=0),
    ADD COLUMN cache_write_input_tokens bigint CHECK (cache_write_input_tokens>=0),
    ADD COLUMN reasoning_output_tokens bigint CHECK (reasoning_output_tokens>=0),
    ADD COLUMN price_quote jsonb,
    ADD CONSTRAINT model_usage_anchor CHECK (
        (event_id IS NOT NULL AND investigation_job_id IS NULL AND investigation_attempt_id IS NULL AND investigation_request_id IS NULL)
        OR (event_id IS NULL AND investigation_job_id IS NOT NULL AND investigation_attempt_id IS NOT NULL
            AND investigation_request_id IS NOT NULL AND purpose='detection')
    );
CREATE UNIQUE INDEX model_usage_investigation_request_idx ON model_usage(investigation_request_id)
    WHERE investigation_request_id IS NOT NULL;

ALTER TABLE findings
    ADD COLUMN investigation_job_id uuid,
    ADD COLUMN investigation_attempt_id uuid,
    ADD COLUMN snapshot_id uuid,
    ADD COLUMN finding_index integer CHECK (finding_index>=0),
    ADD COLUMN investigation_evidence jsonb,
    ADD CONSTRAINT finding_investigation_anchor CHECK (
        (investigation_job_id IS NULL AND investigation_attempt_id IS NULL AND snapshot_id IS NULL
            AND finding_index IS NULL AND investigation_evidence IS NULL)
        OR (investigation_job_id IS NOT NULL AND investigation_attempt_id IS NOT NULL AND snapshot_id IS NOT NULL
            AND finding_index IS NOT NULL AND investigation_evidence IS NOT NULL)
    );
DROP INDEX findings_dedupe_idx;
CREATE UNIQUE INDEX findings_dedupe_idx ON findings
    (tenant_id,rule_id,COALESCE(session_id,'00000000-0000-0000-0000-000000000000'::uuid),primary_event_id)
    WHERE investigation_job_id IS NULL;
CREATE UNIQUE INDEX findings_investigation_idx ON findings(investigation_job_id,finding_index)
    WHERE investigation_job_id IS NOT NULL;

CREATE FUNCTION preserve_investigation_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME='session_investigation_reads' THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'investigation read is immutable' USING ERRCODE='23514';
        END IF;
    ELSIF TG_TABLE_NAME='session_investigation_steps' THEN
        IF ROW(NEW.id,NEW.attempt_id,NEW.ordinal,NEW.kind,NEW.input_manifest,NEW.input_sha256,NEW.input_bytes)
            IS DISTINCT FROM ROW(OLD.id,OLD.attempt_id,OLD.ordinal,OLD.kind,OLD.input_manifest,OLD.input_sha256,OLD.input_bytes)
            OR (OLD.state<>'prepared' AND NEW IS DISTINCT FROM OLD) THEN
            RAISE EXCEPTION 'investigation step is immutable' USING ERRCODE='23514';
        END IF;
    ELSIF ROW(NEW.id,NEW.attempt_id,NEW.step_id,NEW.ordinal,NEW.input_sha256,NEW.request_sha256,
              NEW.input_tokens_counted,NEW.max_output_tokens,NEW.reserved_tokens,NEW.reserved_cost_usd,NEW.price_quote,NEW.usage_id,NEW.dispatched_at)
          IS DISTINCT FROM ROW(OLD.id,OLD.attempt_id,OLD.step_id,OLD.ordinal,OLD.input_sha256,OLD.request_sha256,
              OLD.input_tokens_counted,OLD.max_output_tokens,OLD.reserved_tokens,OLD.reserved_cost_usd,OLD.price_quote,OLD.usage_id,OLD.dispatched_at) THEN
        RAISE EXCEPTION 'investigation request is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER investigation_read_guard BEFORE UPDATE ON session_investigation_reads
    FOR EACH ROW EXECUTE FUNCTION preserve_investigation_evidence();
CREATE TRIGGER investigation_step_guard BEFORE UPDATE ON session_investigation_steps
    FOR EACH ROW EXECUTE FUNCTION preserve_investigation_evidence();
CREATE TRIGGER investigation_request_guard BEFORE UPDATE ON session_investigation_requests
    FOR EACH ROW EXECUTE FUNCTION preserve_investigation_evidence();
