ALTER TABLE findings ADD COLUMN account text NOT NULL DEFAULT '';

-- Correct derived identity fields from retained evidence. Keep canonical
-- exports, event IDs, agent/session links, and finding decisions unchanged.
CREATE TEMP TABLE telemetry_user_identity ON COMMIT DROP AS
WITH log_records AS (
    SELECT t.id AS export_id, t.tenant_id, t.sensor_id, s.username AS sensor_user,
           r.value #> '{resource,attributes}' AS resource_attributes,
           l.value -> 'attributes' AS log_attributes,
           row_number() OVER (
               PARTITION BY t.id ORDER BY r.ordinality, sc.ordinality, l.ordinality
           ) - 1 AS record_index
    FROM telemetry_exports t
    JOIN sensors s ON s.id = t.sensor_id AND s.tenant_id = t.tenant_id
    CROSS JOIN LATERAL jsonb_array_elements(t.payload -> 'resourceLogs') WITH ORDINALITY r
    CROSS JOIN LATERAL jsonb_array_elements(r.value -> 'scopeLogs') WITH ORDINALITY sc
    CROSS JOIN LATERAL jsonb_array_elements(sc.value -> 'logRecords') WITH ORDINALITY l
    WHERE t.signal = 'logs'
      AND EXISTS (SELECT 1 FROM events e WHERE e.export_id = t.id)
), identities AS (
    SELECT logs.*,
           COALESCE(NULLIF(a.attrs ->> 'os.user', ''),
                    NULLIF(r.attrs ->> 'os.user', ''), sensor_user, '') AS os_user,
           COALESCE(NULLIF(a.attrs ->> 'user.email', ''),
                    NULLIF(a.attrs ->> 'user.id', ''),
                    NULLIF(a.attrs ->> 'user.account_id', ''),
                    NULLIF(a.attrs ->> 'user.account_uuid', ''),
                    NULLIF(a.attrs ->> 'user.name', ''),
                    NULLIF(r.attrs ->> 'user.email', ''),
                    NULLIF(r.attrs ->> 'user.id', ''),
                    NULLIF(r.attrs ->> 'user.account_id', ''),
                    NULLIF(r.attrs ->> 'user.account_uuid', ''),
                    NULLIF(r.attrs ->> 'user.name', ''), '') AS account
    FROM log_records logs
    CROSS JOIN LATERAL (
        SELECT jsonb_object_agg(value ->> 'key', COALESCE(
            value #> '{value,stringValue}', value #> '{value,intValue}',
            value #> '{value,bytesValue}') ORDER BY ordinality) AS attrs
        FROM jsonb_array_elements(logs.log_attributes) WITH ORDINALITY
        WHERE value ->> 'key' IS NOT NULL
    ) a
    CROSS JOIN LATERAL (
        SELECT jsonb_object_agg(value ->> 'key', COALESCE(
            value #> '{value,stringValue}', value #> '{value,intValue}',
            value #> '{value,bytesValue}') ORDER BY ordinality) AS attrs
        FROM jsonb_array_elements(logs.resource_attributes) WITH ORDINALITY
        WHERE value ->> 'key' IS NOT NULL
    ) r
)
SELECT e.id, e.tenant_id, e.sensor_id,
       COALESCE(e.body #>> '{host,user}', '') AS reported_user,
       i.os_user, i.account
FROM events e
JOIN identities i ON i.export_id = e.export_id AND i.record_index = e.export_record
                 AND i.tenant_id = e.tenant_id AND i.sensor_id = e.sensor_id
WHERE e.body ->> 'source' = 'otlp';

CREATE UNIQUE INDEX ON telemetry_user_identity (id);

UPDATE events e
SET body = jsonb_set(
    jsonb_set(e.body, '{host,user}', to_jsonb(i.os_user)),
    '{agent,account}', to_jsonb(i.account)
)
FROM telemetry_user_identity i
WHERE e.id = i.id;

-- The detector appends the triggering event to the evidence list. Earlier
-- correlated evidence may belong to another account or have a later client
-- timestamp, so it must not determine this finding's attribution.
UPDATE findings f SET username = i.os_user, account = i.account
FROM telemetry_user_identity i
WHERE i.tenant_id = f.tenant_id AND i.sensor_id = f.sensor_id
  AND i.id = f.event_ids[cardinality(f.event_ids)]
  AND i.reported_user = f.username;
