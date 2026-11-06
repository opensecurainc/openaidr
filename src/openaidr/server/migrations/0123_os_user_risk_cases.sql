ALTER TABLE risk_cases ADD COLUMN accounts text[] NOT NULL DEFAULT '{}';

-- Preserve historical user groups, their report membership, and analyst verdicts.
-- Session attribution can be corrected from retained evidence without regrouping.
WITH identities AS (
    SELECT c.id,count(DISTINCT COALESCE(i.body->'host'->>'user','') COLLATE "C") AS identity_count,
        min(COALESCE(i.body->'host'->>'user','') COLLATE "C") AS reported_user,
        COALESCE(array_agg(DISTINCT (i.body->'agent'->>'account') COLLATE "C"
            ORDER BY (i.body->'agent'->>'account') COLLATE "C")
            FILTER (WHERE COALESCE(i.body->'agent'->>'account','')<>''),'{}'::text[]) AS accounts
    FROM risk_cases c JOIN risk_case_jobs cj ON cj.case_id=c.id AND cj.tenant_id=c.tenant_id
    JOIN session_investigation_jobs j ON j.id=cj.job_id AND j.tenant_id=cj.tenant_id
    JOIN session_snapshots s ON s.id=j.snapshot_id AND s.tenant_id=j.tenant_id
    JOIN session_snapshot_items i ON i.snapshot_id=s.id
    WHERE i.kind='observation' AND i.body->>'kind' NOT IN ('sensor','session.start','session.end')
    GROUP BY c.id
)
UPDATE risk_cases c SET accounts=i.accounts,
    identity_kind=CASE WHEN c.kind='users' THEN c.identity_kind
        WHEN i.identity_count>1 THEN 'mixed' WHEN i.reported_user='' THEN 'unknown' ELSE 'os_user' END,
    reported_user=CASE WHEN c.kind='users' THEN c.reported_user
        WHEN i.identity_count>1 THEN '' ELSE i.reported_user END,
    version=c.version+1,updated_at=clock_timestamp()
FROM identities i WHERE i.id=c.id;

CREATE OR REPLACE FUNCTION attach_risk_cases(job session_investigation_jobs) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    identity_record record;
    identity_kind text;
    case_kind text;
    case_key text;
    case_id uuid;
BEGIN
    IF EXISTS(SELECT 1 FROM risk_case_jobs WHERE job_id=job.id) THEN RETURN; END IF;
    SELECT count(DISTINCT COALESCE(body->'host'->>'user','') COLLATE "C") AS identity_count,
        min(COALESCE(body->'host'->>'user','') COLLATE "C") AS reported_user,
        min(COALESCE(body->'host'->>'hostname','')) AS hostname,
        min(COALESCE(body->'agent'->>'product','')) AS product,
        COALESCE(array_agg(DISTINCT (body->'agent'->>'account') COLLATE "C"
            ORDER BY (body->'agent'->>'account') COLLATE "C")
            FILTER (WHERE COALESCE(body->'agent'->>'account','')<>''),'{}'::text[]) AS accounts
    INTO identity_record FROM session_snapshot_items
    WHERE snapshot_id=job.snapshot_id AND kind='observation'
        AND EXISTS(SELECT 1 FROM session_snapshots WHERE id=job.snapshot_id AND tenant_id=job.tenant_id)
        AND body->>'kind' NOT IN ('sensor','session.start','session.end');
    identity_kind := CASE WHEN identity_record.identity_count>1 THEN 'mixed'
        WHEN identity_record.identity_count=0 OR identity_record.reported_user='' THEN 'unknown' ELSE 'os_user' END;
    IF identity_kind<>'os_user' THEN identity_record.reported_user := ''; END IF;
    FOREACH case_kind IN ARRAY ARRAY['sessions','users'] LOOP
        IF case_kind='users' AND identity_kind<>'os_user' THEN CONTINUE; END IF;
        case_key := CASE WHEN case_kind='sessions' THEN COALESCE(job.session_id::text,job.registration_id::text)
            ELSE encode(sha256(convert_to(jsonb_build_array('os_user',identity_record.reported_user,
                job.sensor_id)::text,'UTF8')),'hex') END;
        INSERT INTO risk_cases(tenant_id,kind,subject_key,identity_kind,reported_user,hostname,product,accounts,opened_at)
            VALUES(job.tenant_id,case_kind,case_key,identity_kind,identity_record.reported_user,
                COALESCE(identity_record.hostname,''),COALESCE(identity_record.product,''),identity_record.accounts,job.created_at)
            ON CONFLICT(tenant_id,kind,subject_key) WHERE outcome='review' DO UPDATE
                SET version=risk_cases.version+1,updated_at=clock_timestamp(),
                    accounts=ARRAY(SELECT DISTINCT value COLLATE "C" FROM unnest(risk_cases.accounts||EXCLUDED.accounts) value
                        ORDER BY value COLLATE "C"),
                    identity_kind=CASE WHEN risk_cases.identity_kind<>EXCLUDED.identity_kind
                        OR risk_cases.reported_user<>EXCLUDED.reported_user THEN 'mixed' ELSE risk_cases.identity_kind END,
                    reported_user=CASE WHEN risk_cases.identity_kind<>EXCLUDED.identity_kind
                        OR risk_cases.reported_user<>EXCLUDED.reported_user THEN '' ELSE risk_cases.reported_user END
            RETURNING id INTO case_id;
        INSERT INTO risk_case_jobs(case_id,tenant_id,job_id,kind) VALUES(case_id,job.tenant_id,job.id,case_kind);
    END LOOP;
END;
$$;
