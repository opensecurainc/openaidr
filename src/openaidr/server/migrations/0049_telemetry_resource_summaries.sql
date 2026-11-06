-- Keep dashboard metadata separate from the retained OTLP payload. Adding a
-- nullable column avoids rewriting old exports during application startup.
ALTER TABLE telemetry_exports ADD COLUMN resource_summary jsonb;

CREATE FUNCTION telemetry_resource_summary(signal text, payload jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
    SELECT COALESCE(jsonb_agg(to_jsonb(summary) ORDER BY service),
                   '[{"service":"(unknown)","records":0,"demo":false}]'::jsonb)
    FROM (
        SELECT service, sum(records)::bigint AS records, bool_and(demo) AS demo
        FROM (
            SELECT COALESCE(NULLIF((
                       SELECT a #>> '{value,stringValue}'
                       FROM jsonb_array_elements(COALESCE(r.value #> '{resource,attributes}', '[]'::jsonb)) a
                       WHERE a->>'key'='service.name'
                         AND jsonb_typeof(a #> '{value,stringValue}')='string'
                       LIMIT 1), ''), '(unknown)') AS service,
                   EXISTS (
                       SELECT 1
                       FROM jsonb_array_elements(COALESCE(r.value #> '{resource,attributes}', '[]'::jsonb)) a
                       WHERE a->>'key'='openaidr.demo'
                         AND a #> '{value,boolValue}'='true'::jsonb) AS demo,
                   COALESCE(jsonb_array_length(jsonb_path_query_array(r.value, CASE $1
                       WHEN 'logs' THEN '$.scopeLogs[*].logRecords[*]'
                       WHEN 'metrics' THEN '$.scopeMetrics[*].metrics[*].*.dataPoints[*]'
                       ELSE '$.scopeSpans[*].spans[*]' END::jsonpath)), 0)::bigint AS records
            FROM jsonb_array_elements($2 -> CASE $1
                WHEN 'logs' THEN 'resourceLogs' WHEN 'metrics' THEN 'resourceMetrics'
                ELSE 'resourceSpans' END) r(value)
        ) resources GROUP BY service
    ) summary;
$$;

-- A database trigger also covers writers running an older application during
-- rollout or rollback. Ordinary processing updates do not reparse the payload.
CREATE FUNCTION set_telemetry_resource_summary() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.resource_summary = telemetry_resource_summary(NEW.signal, NEW.payload);
    RETURN NEW;
END;
$$;
CREATE TRIGGER telemetry_resource_summary_on_write
BEFORE INSERT OR UPDATE OF payload, signal ON telemetry_exports
FOR EACH ROW EXECUTE FUNCTION set_telemetry_resource_summary();

CREATE INDEX telemetry_exports_summary_pending_idx
ON telemetry_exports (tenant_id, received_at DESC, id DESC)
WHERE resource_summary IS NULL;
