-- Supply bounded defaults without changing a tenant's saved on/off choice.
ALTER TABLE tenant_session_detection_settings
    ALTER COLUMN enabled SET DEFAULT true,
    ALTER COLUMN selection_policy SET DEFAULT 'risk_budget',
    ALTER COLUMN risk_threshold SET DEFAULT 100,
    ALTER COLUMN idle_seconds SET DEFAULT 60,
    ALTER COLUMN delivery_grace_seconds SET DEFAULT 30,
    ALTER COLUMN gap_wait_seconds SET DEFAULT 90,
    ALTER COLUMN gap_policy SET DEFAULT 'investigate',
    ALTER COLUMN model SET DEFAULT 'gpt-6.1-sol',
    ALTER COLUMN max_runtime_seconds SET DEFAULT 120,
    ALTER COLUMN max_tokens_per_attempt SET DEFAULT 200000,
    ALTER COLUMN max_cost_usd_per_attempt SET DEFAULT 2,
    ALTER COLUMN max_attempts SET DEFAULT 1,
    ALTER COLUMN max_concurrent SET DEFAULT 1,
    ALTER COLUMN hourly_attempts SET DEFAULT 10,
    ALTER COLUMN hourly_tokens SET DEFAULT 1000000,
    ALTER COLUMN hourly_cost_usd SET DEFAULT 10,
    ALTER COLUMN retry_delay_seconds SET DEFAULT 60;

UPDATE tenant_session_detection_settings SET
    risk_threshold=COALESCE(risk_threshold,100),
    idle_seconds=COALESCE(idle_seconds,60),
    delivery_grace_seconds=COALESCE(delivery_grace_seconds,LEAST(gap_wait_seconds,30),30),
    gap_wait_seconds=COALESCE(gap_wait_seconds,GREATEST(delivery_grace_seconds,90)),
    gap_policy=COALESCE(gap_policy,'investigate'),
    model=COALESCE(model,'gpt-6.1-sol'),
    max_runtime_seconds=COALESCE(max_runtime_seconds,120),
    max_tokens_per_attempt=COALESCE(max_tokens_per_attempt,LEAST(hourly_tokens,200000),200000),
    max_cost_usd_per_attempt=COALESCE(max_cost_usd_per_attempt,LEAST(hourly_cost_usd,2),2),
    max_attempts=COALESCE(max_attempts,1),
    max_concurrent=COALESCE(max_concurrent,1),
    hourly_attempts=COALESCE(hourly_attempts,10),
    hourly_tokens=COALESCE(hourly_tokens,GREATEST(max_tokens_per_attempt,1000000)),
    hourly_cost_usd=COALESCE(hourly_cost_usd,GREATEST(max_cost_usd_per_attempt,10)),
    retry_delay_seconds=COALESCE(retry_delay_seconds,60),
    version=version+1,detector_config_version=detector_config_version+1,updated_at=clock_timestamp()
WHERE risk_threshold IS NULL OR idle_seconds IS NULL OR delivery_grace_seconds IS NULL
   OR gap_wait_seconds IS NULL OR gap_policy IS NULL OR model IS NULL
   OR max_runtime_seconds IS NULL OR max_tokens_per_attempt IS NULL OR max_cost_usd_per_attempt IS NULL
   OR max_attempts IS NULL OR max_concurrent IS NULL OR hourly_attempts IS NULL
   OR hourly_tokens IS NULL OR hourly_cost_usd IS NULL OR retry_delay_seconds IS NULL;

INSERT INTO tenant_session_detection_settings(tenant_id)
SELECT id FROM tenants ON CONFLICT(tenant_id) DO NOTHING;

CREATE FUNCTION initialize_session_detection_settings() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO tenant_session_detection_settings(tenant_id) VALUES(NEW.id);
    RETURN NEW;
END;
$$;
CREATE TRIGGER tenants_initialize_session_detection
    AFTER INSERT ON tenants FOR EACH ROW EXECUTE FUNCTION initialize_session_detection_settings();
