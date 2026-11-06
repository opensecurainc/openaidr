CREATE TABLE risk_cases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('sessions','users')),
    subject_key text NOT NULL,
    identity_kind text NOT NULL CHECK (identity_kind IN ('account','os_user','mixed','unknown')),
    reported_user text NOT NULL DEFAULT '',
    hostname text NOT NULL DEFAULT '',
    product text NOT NULL DEFAULT '',
    outcome text NOT NULL DEFAULT 'review' CHECK (outcome IN ('review','tp','fp')),
    opened_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    closed_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    CHECK ((outcome='review')=(closed_at IS NULL)),
    UNIQUE (id,tenant_id)
);
CREATE UNIQUE INDEX risk_case_open_subject_idx ON risk_cases(tenant_id,kind,subject_key) WHERE outcome='review';
CREATE INDEX risk_case_opened_idx ON risk_cases(tenant_id,opened_at DESC,id);

CREATE TABLE risk_case_jobs (
    case_id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_id uuid NOT NULL REFERENCES session_investigation_jobs(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('sessions','users')),
    PRIMARY KEY(case_id,job_id),
    FOREIGN KEY(case_id,tenant_id) REFERENCES risk_cases(id,tenant_id) ON DELETE CASCADE,
    UNIQUE(job_id,kind)
);

-- Cases follow retained investigations, independently of model conclusions.
-- The partial unique index serializes arrival with analyst closure. It also
-- keeps old backend versions compatible during a rolling deployment.
CREATE FUNCTION attach_risk_cases(job session_investigation_jobs) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    identity_record record;
    identity_count integer;
    case_kind text;
    case_key text;
    case_id uuid;
    subject_id text;
BEGIN
    IF EXISTS(SELECT 1 FROM risk_case_jobs WHERE job_id=job.id) THEN RETURN; END IF;
    subject_id := COALESCE(job.session_id::text,job.registration_id::text);
    SELECT min(identity_kind) AS identity_kind,min(reported_user) AS reported_user,
           min(hostname) AS hostname,min(product) AS product
      INTO identity_record
      FROM (
        SELECT DISTINCT
            CASE WHEN COALESCE(body->'agent'->>'account','')<>'' THEN 'account' ELSE 'os_user' END AS identity_kind,
            CASE WHEN COALESCE(body->'agent'->>'account','')<>'' THEN body->'agent'->>'account'
                 ELSE COALESCE(body->'host'->>'user','') END AS reported_user,
            COALESCE(body->'host'->>'hostname','') AS hostname,
            COALESCE(body->'agent'->>'product','') AS product
        FROM session_snapshot_items WHERE snapshot_id=job.snapshot_id AND kind='observation'
          AND body->>'kind' NOT IN ('sensor','session.start','session.end')
      ) identities;
    -- Hostname/product differences do not change the reported identity.
    SELECT count(DISTINCT jsonb_build_array(
        CASE WHEN COALESCE(body->'agent'->>'account','')<>'' THEN 'account' ELSE 'os_user' END,
        CASE WHEN COALESCE(body->'agent'->>'account','')<>'' THEN body->'agent'->>'account'
             ELSE COALESCE(body->'host'->>'user','') END)) INTO identity_count
      FROM session_snapshot_items WHERE snapshot_id=job.snapshot_id AND kind='observation'
        AND body->>'kind' NOT IN ('sensor','session.start','session.end');
    IF identity_count>1 THEN
        identity_record.identity_kind := 'mixed';
        identity_record.reported_user := '';
    ELSIF identity_count=0 OR identity_record.reported_user='' THEN
        identity_record.identity_kind := 'unknown';
        identity_record.reported_user := '';
    END IF;
    FOREACH case_kind IN ARRAY ARRAY['sessions','users'] LOOP
        IF case_kind='users' AND identity_record.identity_kind IN ('mixed','unknown') THEN CONTINUE; END IF;
        case_key := CASE WHEN case_kind='sessions' THEN subject_id
            ELSE encode(sha256(convert_to(jsonb_build_array(identity_record.identity_kind,identity_record.reported_user,
                CASE WHEN identity_record.identity_kind='os_user' THEN job.sensor_id END)::text,'UTF8')),'hex') END;
        INSERT INTO risk_cases(tenant_id,kind,subject_key,identity_kind,reported_user,hostname,product,opened_at)
            VALUES(job.tenant_id,case_kind,case_key,identity_record.identity_kind,
                COALESCE(identity_record.reported_user,''),COALESCE(identity_record.hostname,''),
                COALESCE(identity_record.product,''),job.created_at)
            ON CONFLICT(tenant_id,kind,subject_key) WHERE outcome='review' DO UPDATE
                SET version=risk_cases.version+1,updated_at=clock_timestamp(),
                    identity_kind=CASE WHEN risk_cases.identity_kind<>EXCLUDED.identity_kind
                        OR risk_cases.reported_user<>EXCLUDED.reported_user THEN 'mixed' ELSE risk_cases.identity_kind END,
                    reported_user=CASE WHEN risk_cases.identity_kind<>EXCLUDED.identity_kind
                        OR risk_cases.reported_user<>EXCLUDED.reported_user THEN '' ELSE risk_cases.reported_user END
            RETURNING id INTO case_id;
        INSERT INTO risk_case_jobs(case_id,tenant_id,job_id,kind) VALUES(case_id,job.tenant_id,job.id,case_kind);
    END LOOP;
END;
$$;
CREATE FUNCTION attach_new_risk_cases() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM attach_risk_cases(NEW);
    RETURN NEW;
END;
$$;
CREATE TRIGGER investigation_risk_cases AFTER INSERT ON session_investigation_jobs
    FOR EACH ROW EXECUTE FUNCTION attach_new_risk_cases();

-- Seed the displayed window once. No verdict is inferred for historical work.
DO $$
DECLARE job session_investigation_jobs;
BEGIN
    FOR job IN SELECT * FROM session_investigation_jobs
        WHERE created_at>=now()-interval '30 days' ORDER BY created_at,id
    LOOP PERFORM attach_risk_cases(job); END LOOP;
END;
$$;
