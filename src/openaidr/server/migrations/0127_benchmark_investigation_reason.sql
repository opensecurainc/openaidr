ALTER TABLE session_investigation_jobs
    DROP CONSTRAINT session_investigation_jobs_routing_reason_check,
    ADD CONSTRAINT session_investigation_jobs_routing_reason_check CHECK (
        routing_reason IN ('risk_threshold','persistent_gap','session_risk','user_pattern','urgent_risk','sample','benchmark'));
