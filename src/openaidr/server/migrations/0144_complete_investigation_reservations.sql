-- Dormant complete-job admission. No settings, defaults or retained values change.
ALTER TABLE session_investigation_attempts
    ALTER COLUMN reserved_tokens DROP NOT NULL,
    ALTER COLUMN reserved_cost_usd DROP NOT NULL,
    ADD COLUMN admission_origin text CHECK (length(admission_origin) BETWEEN 1 AND 2048);

CREATE FUNCTION preserve_investigation_admission() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE protocol smallint;
BEGIN
    SELECT protocol_version INTO protocol FROM session_investigation_jobs
        WHERE id=NEW.job_id AND tenant_id=NEW.tenant_id;
    IF protocol IS NULL THEN
        RAISE EXCEPTION 'investigation attempt job tenant mismatch' USING ERRCODE='23503';
    END IF;
    IF (NEW.reserved_tokens IS NULL)<>(NEW.reserved_cost_usd IS NULL)
       OR (protocol<>4 AND NEW.reserved_tokens IS NULL) THEN
        RAISE EXCEPTION 'retained investigation requires provider reservations' USING ERRCODE='23502';
    END IF;
    IF NEW.admission_origin IS NOT NULL AND (protocol<>4 OR NEW.reserved_credits_microcredits IS NULL)
       OR (NEW.reserved_tokens IS NULL AND NEW.admission_origin IS NULL) THEN
        RAISE EXCEPTION 'complete investigation requires captured credit admission' USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' AND OLD.admission_origin IS NOT NULL AND
       ROW(NEW.id,NEW.job_id,NEW.tenant_id,NEW.ordinal,NEW.claim_token,NEW.window_start,
           NEW.deadline_at,NEW.admission_origin,NEW.reserved_credits_microcredits,NEW.credit_rate_version,
           NEW.reserved_tokens,NEW.reserved_cost_usd,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.job_id,OLD.tenant_id,OLD.ordinal,OLD.claim_token,OLD.window_start,
           OLD.deadline_at,OLD.admission_origin,OLD.reserved_credits_microcredits,OLD.credit_rate_version,
           OLD.reserved_tokens,OLD.reserved_cost_usd,OLD.created_at) THEN
        RAISE EXCEPTION 'investigation admission is immutable' USING ERRCODE='23514';
    END IF;
    IF NEW.admission_origin IS NOT NULL AND (TG_OP='INSERT' OR OLD.admission_origin IS NULL)
       AND (NEW.state<>'reserved' OR NEW.dispatched_at IS NOT NULL
            OR (TG_OP='UPDATE' AND (OLD.state<>'reserved' OR OLD.dispatched_at IS NOT NULL))) THEN
        RAISE EXCEPTION 'investigation admission must precede dispatch' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER investigation_admission_guard BEFORE INSERT OR UPDATE ON session_investigation_attempts
    FOR EACH ROW EXECUTE FUNCTION preserve_investigation_admission();
