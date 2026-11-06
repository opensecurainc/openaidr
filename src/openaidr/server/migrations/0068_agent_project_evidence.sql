ALTER TABLE agent_cost_records ADD COLUMN session_project text NOT NULL DEFAULT '';
CREATE INDEX agent_cost_records_session_usage_idx
    ON agent_cost_records (tenant_id,session_key,happened_at) WHERE is_usage;

-- Directory observations are accounting metadata, without prompts or tool input.
CREATE TABLE agent_project_evidence (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    product text NOT NULL,
    session_id text NOT NULL,
    event_key text NOT NULL,
    observed_at timestamptz NOT NULL,
    project text NOT NULL DEFAULT '',
    parent_id text NOT NULL DEFAULT '',
    pending boolean NOT NULL DEFAULT true,
    PRIMARY KEY (tenant_id,sensor_id,product,session_id,event_key)
);
CREATE INDEX agent_project_evidence_session_idx
    ON agent_project_evidence (tenant_id,sensor_id,product,session_id,observed_at);
CREATE INDEX agent_project_evidence_parent_idx
    ON agent_project_evidence (tenant_id,sensor_id,product,parent_id) WHERE parent_id<>'';
CREATE INDEX agent_project_evidence_pending_idx
    ON agent_project_evidence (observed_at) WHERE pending;

CREATE TABLE agent_project_sessions (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    product text NOT NULL,
    session_id text NOT NULL,
    session_keys text[] NOT NULL DEFAULT '{}',
    pending boolean NOT NULL DEFAULT true,
    backfill boolean NOT NULL DEFAULT false,
    retry_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,sensor_id,product,session_id)
);
CREATE INDEX agent_project_sessions_pending_idx
    ON agent_project_sessions (updated_at) WHERE pending;

-- Workers repair retained history in small transactions after deployment.
INSERT INTO agent_project_sessions (tenant_id,sensor_id,product,session_id,backfill)
    SELECT tenant_id,sensor_id,product,external_id,true FROM agent_sessions
    WHERE product IN ('codex-cli','claude-code')
    UNION SELECT tenant_id,sensor_id,product,session_id,true FROM ordinary_hook_checks
    ON CONFLICT DO NOTHING;

-- Refresh retained direct folder labels with the final-folder naming rule.
-- Pending usage/repricing work keeps its original processing mode.
WITH exports AS MATERIALIZED (
    SELECT DISTINCT export_id FROM agent_cost_records WHERE direct_project<>'' AND export_id IS NOT NULL
)
UPDATE telemetry_exports e SET costs_processed_at=NULL,costs_retry_at=NULL,costs_reattribute=true
    FROM exports x WHERE e.id=x.export_id AND e.signal='logs' AND e.costs_processed_at IS NOT NULL
      AND jsonb_array_length(coalesce(e.payload->'resourceLogs','[]'::jsonb))>0;
