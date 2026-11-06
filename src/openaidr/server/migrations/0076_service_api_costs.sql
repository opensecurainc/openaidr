ALTER TABLE model_usage
    ALTER COLUMN sensor_id DROP NOT NULL,
    DROP CONSTRAINT model_usage_purpose_check,
    DROP CONSTRAINT model_usage_anchor,
    ADD CONSTRAINT model_usage_purpose_check CHECK (purpose IN ('detection','guardrail','assistant','verification')),
    ADD CONSTRAINT model_usage_anchor CHECK (
        (event_id IS NOT NULL AND sensor_id IS NOT NULL AND investigation_job_id IS NULL
            AND investigation_attempt_id IS NULL AND investigation_request_id IS NULL)
        OR (event_id IS NULL AND investigation_job_id IS NOT NULL AND investigation_attempt_id IS NOT NULL
            AND investigation_request_id IS NOT NULL AND purpose='detection')
        OR (event_id IS NULL AND sensor_id IS NULL AND investigation_job_id IS NULL
            AND investigation_attempt_id IS NULL AND investigation_request_id IS NULL
            AND purpose IN ('assistant','verification'))
    );
