ALTER TABLE gateway_requests ADD COLUMN guardrail_e2e_ms double precision
    CHECK (guardrail_e2e_ms >= 0 AND guardrail_e2e_ms <= 3600000);
