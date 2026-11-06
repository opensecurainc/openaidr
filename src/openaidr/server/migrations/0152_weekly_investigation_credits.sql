-- Optional rolling seven-day customer credit limit. Preserve existing settings.
ALTER TABLE tenant_session_detection_settings
    ADD COLUMN weekly_credits_microcredits bigint
        CHECK (weekly_credits_microcredits BETWEEN 0 AND 9007199254740991),
    ADD CONSTRAINT investigation_weekly_credit_limit CHECK (
        weekly_credits_microcredits >= max_credits_per_attempt_microcredits
    );
