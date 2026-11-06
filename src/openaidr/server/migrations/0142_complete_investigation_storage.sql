-- Dormant preparation. Existing writers retain protocol 1, provider budgets,
-- settings defaults and detector revisions until a separate activation.
ALTER TABLE tenant_session_detection_settings
    ADD COLUMN max_credits_per_attempt_microcredits bigint
        CHECK (max_credits_per_attempt_microcredits BETWEEN 0 AND 9007199254740991),
    ADD COLUMN hourly_credits_microcredits bigint
        CHECK (hourly_credits_microcredits BETWEEN 0 AND 9007199254740991),
    ADD CONSTRAINT investigation_credit_limits CHECK (
        (max_credits_per_attempt_microcredits IS NULL)=(hourly_credits_microcredits IS NULL)
        AND hourly_credits_microcredits>=max_credits_per_attempt_microcredits
    );

ALTER TABLE session_investigation_jobs
    ADD COLUMN protocol_version smallint NOT NULL DEFAULT 1 CHECK (protocol_version IN (1,3,4));

CREATE FUNCTION preserve_investigation_protocol() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.protocol_version IS DISTINCT FROM OLD.protocol_version THEN
        RAISE EXCEPTION 'investigation protocol is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER investigation_protocol_guard BEFORE UPDATE OF protocol_version
    ON session_investigation_jobs FOR EACH ROW EXECUTE FUNCTION preserve_investigation_protocol();

ALTER TABLE session_investigation_attempts
    ADD COLUMN reserved_credits_microcredits bigint
        CHECK (reserved_credits_microcredits BETWEEN 0 AND 9007199254740991),
    ADD COLUMN credit_rate_version text CHECK (length(credit_rate_version) BETWEEN 1 AND 80),
    ADD CONSTRAINT investigation_attempt_tenant_identity UNIQUE(id,tenant_id);

-- The request ID is known before dispatch. An uncertain create can be looked
-- up at the captured origin without generating another paid request.
CREATE TABLE session_investigation_submissions (
    attempt_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    origin text NOT NULL CHECK (length(origin) BETWEEN 1 AND 2048),
    api_tenant_id uuid NOT NULL,
    -- Canonical JSON text is the retry payload. JSONB changes valid numeric
    -- representations such as 1e+20 and -0.0 and would invalidate its hash.
    request text NOT NULL,
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[a-f0-9]{64}$'),
    remote_id uuid CHECK (remote_id=attempt_id),
    remote_status text CHECK (remote_status IN ('queued','running','completed','failed','cancelled')),
    cancel_requested boolean NOT NULL DEFAULT false,
    publication jsonb,
    closed_at timestamptz,
    last_error text NOT NULL DEFAULT '',
    checked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(attempt_id,tenant_id) REFERENCES session_investigation_attempts(id,tenant_id) ON DELETE CASCADE,
    UNIQUE(origin,api_tenant_id,remote_id),
    CHECK (tenant_id=api_tenant_id),
    CHECK (json_typeof(request::json)='object' AND
        (request::json->>'request_id') IS NOT DISTINCT FROM attempt_id::text)
);
CREATE INDEX investigation_submissions_pending ON session_investigation_submissions(tenant_id,checked_at,attempt_id);

CREATE FUNCTION preserve_investigation_submission() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.attempt_id,NEW.tenant_id,NEW.origin,NEW.api_tenant_id,NEW.request,NEW.request_sha256,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.attempt_id,OLD.tenant_id,OLD.origin,OLD.api_tenant_id,OLD.request,OLD.request_sha256,OLD.created_at)
       OR (OLD.remote_id IS NOT NULL AND NEW.remote_id IS DISTINCT FROM OLD.remote_id) THEN
        RAISE EXCEPTION 'investigation submission identity is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER investigation_submission_guard BEFORE UPDATE ON session_investigation_submissions
    FOR EACH ROW EXECUTE FUNCTION preserve_investigation_submission();

-- Complete reports cite submitted evidence without fabricated tenant steps.
-- Retained step-bound reads keep their existing foreign key and identity.
ALTER TABLE session_investigation_reads ALTER COLUMN step_id DROP NOT NULL;
ALTER TABLE session_investigation_reads ADD COLUMN submission_id uuid
    REFERENCES session_investigation_submissions(attempt_id) ON DELETE CASCADE;
ALTER TABLE session_investigation_reads ADD CONSTRAINT investigation_read_binding CHECK (
    (step_id IS NOT NULL AND submission_id IS NULL)
    OR (step_id IS NULL AND submission_id IS NOT NULL AND submission_id=attempt_id)
);
CREATE UNIQUE INDEX investigation_submission_read ON session_investigation_reads(submission_id,tool_call_id)
    WHERE submission_id IS NOT NULL;
