-- Assigned workload identities are control-plane metadata, never credentials.
CREATE TABLE deployment_workloads (
    tenant_id uuid PRIMARY KEY REFERENCES cloud_deployments(id),
    project_id text NOT NULL,
    zone text NOT NULL,
    instance_id text NOT NULL,
    service_account_id text NOT NULL UNIQUE,
    service_account_email text NOT NULL,
    UNIQUE (project_id, zone, instance_id)
);

CREATE TABLE deployment_readiness_commands (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES deployment_workloads(tenant_id),
    job_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    expected jsonb NOT NULL CHECK (jsonb_typeof(expected) = 'object'),
    outcome jsonb CHECK (jsonb_typeof(outcome) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '15 minutes',
    acknowledged_at timestamptz,
    FOREIGN KEY (tenant_id, job_id) REFERENCES deployment_jobs(tenant_id, id),
    CHECK ((outcome IS NULL) = (acknowledged_at IS NULL))
);
CREATE INDEX deployment_readiness_pending_idx
    ON deployment_readiness_commands (tenant_id, created_at, id)
    WHERE outcome IS NULL;
