CREATE TABLE platform_api_operations_alerts (
    rule text PRIMARY KEY CHECK (rule IN (
        'https_failure', 'collection_stale', 'worker_heartbeat', 'queue_age',
        'disk_space', 'settlement_age',
        'provider_errors_web_risk_urls', 'provider_errors_osv_packages',
        'provider_errors_typesafe_guardrail', 'provider_errors_openai_applications',
        'provider_errors_openai_assistant', 'provider_errors_openai_summaries',
        'provider_errors_openai_rules', 'provider_errors_openai_skills',
        'provider_errors_openai_investigation_tokens', 'provider_errors_openai_investigation_inference')),
    target_key char(64) NOT NULL,
    policy_hash char(64) NOT NULL,
    state text NOT NULL CHECK (state IN (
        'disabled', 'unknown', 'healthy', 'pending', 'firing', 'recovering', 'suppressed')),
    active boolean NOT NULL DEFAULT false,
    evaluated_at timestamptz NOT NULL,
    evidence_at timestamptz,
    condition_since timestamptz,
    last_transition_at timestamptz,
    reason text NOT NULL,
    value double precision,
    threshold double precision NOT NULL,
    owner text NOT NULL CHECK (length(owner) BETWEEN 1 AND 80),
    maintenance_until timestamptz,
    event_id uuid,
    event_payload text CHECK (octet_length(event_payload) <= 2048),
    delivery_state text NOT NULL DEFAULT 'disabled'
        CHECK (delivery_state IN ('disabled', 'sending', 'sent', 'failed')),
    delivery_attempts integer NOT NULL DEFAULT 0 CHECK (delivery_attempts BETWEEN 0 AND 3),
    next_delivery_at timestamptz,
    dropped_events bigint NOT NULL DEFAULT 0 CHECK (dropped_events BETWEEN 0 AND 9007199254740991)
);
