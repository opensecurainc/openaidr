-- Trigger installation has committed before this retained-history scan.
CREATE TEMP TABLE agent_cost_backfill_hours ON COMMIT DROP AS
    SELECT DISTINCT tenant_id,date_trunc('hour',happened_at,'UTC') AS bucket
    FROM agent_cost_records WHERE is_usage;
INSERT INTO agent_cost_versions (tenant_id)
    SELECT DISTINCT tenant_id FROM agent_cost_backfill_hours ORDER BY tenant_id
    ON CONFLICT (tenant_id) DO UPDATE SET revision=agent_cost_versions.revision+1;
INSERT INTO agent_cost_dirty_hours (tenant_id,bucket)
    SELECT tenant_id,bucket FROM agent_cost_backfill_hours ORDER BY 1,2
    ON CONFLICT (tenant_id,bucket) DO UPDATE SET bucket=excluded.bucket;
