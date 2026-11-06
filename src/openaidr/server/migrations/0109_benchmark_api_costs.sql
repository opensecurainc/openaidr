ALTER TABLE model_usage
    DROP CONSTRAINT model_usage_purpose_check,
    DROP CONSTRAINT model_usage_anchor,
    ADD CONSTRAINT model_usage_purpose_check CHECK (purpose IN ('detection','guardrail','assistant','verification','asset_management','benchmark')),
    ADD CONSTRAINT model_usage_anchor CHECK (
        (event_id IS NOT NULL AND sensor_id IS NOT NULL AND investigation_job_id IS NULL
            AND investigation_attempt_id IS NULL AND investigation_request_id IS NULL)
        OR (event_id IS NULL AND investigation_job_id IS NOT NULL AND investigation_attempt_id IS NOT NULL
            AND investigation_request_id IS NOT NULL AND purpose='detection')
        OR (event_id IS NULL AND sensor_id IS NULL AND investigation_job_id IS NULL
            AND investigation_attempt_id IS NULL AND investigation_request_id IS NULL
            AND purpose IN ('assistant','verification','asset_management','benchmark'))
    );

ALTER TABLE platform_api_costs
    DROP CONSTRAINT platform_api_costs_purpose_check,
    ADD CONSTRAINT platform_api_costs_purpose_check CHECK (purpose IN ('detection','guardrail','assistant','verification','asset_management','benchmark'));

ALTER TABLE guardrail_benchmark_results ADD COLUMN usage_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE;

-- Retained results already contain validated billing metadata. Preserve their
-- recorded costs. Older results only have a run timestamp, not a call timestamp.
INSERT INTO model_usage(id,tenant_id,attempt,purpose,provider,model,started_at,completed_at,
    status,input_tokens,output_tokens,input_rate_usd,output_rate_usd,price_date,cost_usd)
SELECT b.usage_id,b.tenant_id,1,'benchmark','typesafe',r.configuration->>'model',
    COALESCE(r.started_at,r.created_at),
    CASE WHEN b.result->>'status'<>'pending' THEN COALESCE(r.finished_at,r.started_at,r.created_at) END,
    CASE b.result->>'status' WHEN 'pending' THEN 'pending' WHEN 'error' THEN 'error' ELSE 'completed' END,
    (b.result #>> '{usage,input_tokens}')::bigint,(b.result #>> '{usage,output_tokens}')::bigint,
    (r.configuration #>> '{rates,0}')::numeric,(r.configuration #>> '{rates,1}')::numeric,
    (r.configuration->>'price_date')::date,(b.result->>'cost_usd')::numeric
FROM guardrail_benchmark_results b JOIN guardrail_benchmark_runs r ON r.id=b.run_id;
