-- Revisit retained project metadata without replacing stored usage or prices.
ALTER TABLE telemetry_exports ADD COLUMN costs_reattribute boolean NOT NULL DEFAULT false;
UPDATE telemetry_exports e
SET costs_processed_at=NULL, costs_retry_at=NULL, costs_reattribute=true
WHERE e.signal='logs' AND e.costs_processed_at IS NOT NULL
  AND jsonb_typeof(e.payload->'resourceLogs')='array'
  AND EXISTS (SELECT 1 FROM agent_cost_records r
              WHERE r.tenant_id=e.tenant_id AND r.export_id=e.id);
