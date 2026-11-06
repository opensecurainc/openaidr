-- The reason a host reported for a definite failure. Only host_failed jobs carry one.
ALTER TABLE deployment_jobs
    ADD COLUMN failure_reason text
        CHECK (failure_reason IS NULL OR failure_reason ~ '^[a-z][a-z0-9_]{0,63}$');
