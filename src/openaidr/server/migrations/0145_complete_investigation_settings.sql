-- Receiving boundary only. Existing rows, versions and defaults stay unchanged.
ALTER TABLE tenant_session_detection_settings
    ADD COLUMN job_protocol_version smallint NOT NULL DEFAULT 1 CHECK (job_protocol_version IN (1,4)),
    DROP CONSTRAINT tenant_session_detection_settings_check3,
    ADD CONSTRAINT investigation_enabled_contract CHECK (NOT enabled OR (
        risk_threshold IS NOT NULL AND idle_seconds IS NOT NULL
        AND delivery_grace_seconds IS NOT NULL AND gap_policy IS NOT NULL
        AND gap_wait_seconds IS NOT NULL AND max_runtime_seconds IS NOT NULL
        AND max_attempts IS NOT NULL AND max_concurrent IS NOT NULL
        AND hourly_attempts IS NOT NULL AND retry_delay_seconds IS NOT NULL
        AND ((job_protocol_version=1 AND model IS NOT NULL AND max_tokens_per_attempt IS NOT NULL
              AND max_cost_usd_per_attempt IS NOT NULL AND hourly_tokens IS NOT NULL AND hourly_cost_usd IS NOT NULL)
             OR (job_protocol_version=4 AND max_credits_per_attempt_microcredits IS NOT NULL
                 AND hourly_credits_microcredits IS NOT NULL))
    ));

CREATE FUNCTION preserve_investigation_settings_protocol() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.job_protocol_version=4 AND NEW.job_protocol_version<>4 THEN
        RAISE EXCEPTION 'complete investigation settings cannot return to the legacy contract' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER investigation_settings_protocol_guard BEFORE UPDATE OF job_protocol_version
    ON tenant_session_detection_settings FOR EACH ROW EXECUTE FUNCTION preserve_investigation_settings_protocol();

CREATE FUNCTION reject_converted_legacy_investigation() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE protocol smallint;
BEGIN
    -- SHARE serializes old writers with conversion, including repeatable-read
    -- finalizers. A stale snapshot retries instead of admitting an old contract.
    SELECT job_protocol_version INTO protocol FROM tenant_session_detection_settings
        WHERE tenant_id=NEW.tenant_id FOR SHARE;
    IF protocol=4 AND NEW.protocol_version<>4 THEN
        RAISE EXCEPTION 'tenant requires complete investigation jobs' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER investigation_job_contract_guard BEFORE INSERT ON session_investigation_jobs
    FOR EACH ROW EXECUTE FUNCTION reject_converted_legacy_investigation();
