-- Control-plane metadata only. Customer accounts and data stay in tenant databases.
CREATE TABLE cloud_deployments (
    id                    uuid PRIMARY KEY,
    name                  text NOT NULL,
    slug                  text NOT NULL UNIQUE,
    hostname              text NOT NULL UNIQUE,
    approved_domains      jsonb NOT NULL CHECK (jsonb_typeof(approved_domains) = 'array'),
    initial_owner_email   text NOT NULL,
    initial_owner_name    text NOT NULL DEFAULT '',
    project_id            text NOT NULL,
    zone                  text NOT NULL,
    release_id            text NOT NULL,
    trial_expires_at      timestamptz NOT NULL,
    requested_by          uuid NOT NULL,
    approved_by           uuid,
    approved_at           timestamptz,
    desired_state         text NOT NULL DEFAULT 'unprovisioned'
                          CHECK (desired_state IN ('unprovisioned','active','suspended','deleted')),
    desired_generation    bigint NOT NULL DEFAULT 0 CHECK (desired_generation >= 0),
    observed_state        text NOT NULL DEFAULT 'absent'
                          CHECK (observed_state IN ('absent','active','suspended','deleted','unknown')),
    observed_generation   bigint NOT NULL DEFAULT 0
                          CHECK (observed_generation >= 0 AND observed_generation <= desired_generation),
    observed_at           timestamptz,
    last_job_id           uuid,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    CHECK (desired_generation = 0 OR approved_at IS NOT NULL)
);
CREATE INDEX cloud_deployments_created_idx ON cloud_deployments (created_at DESC, id DESC);

CREATE TABLE deployment_jobs (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES cloud_deployments(id),
    operation             text NOT NULL CHECK (operation = 'provision'),
    target_generation     bigint NOT NULL CHECK (target_generation > 0),
    idempotency_key        uuid NOT NULL UNIQUE,
    payload_digest        text NOT NULL,
    spec                  jsonb NOT NULL CHECK (jsonb_typeof(spec) = 'object'),
    state                 text NOT NULL DEFAULT 'queued'
                          CHECK (state IN ('queued','running','succeeded','failed')),
    checkpoint            jsonb NOT NULL DEFAULT '{}'::jsonb,
    attempt               integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    lease_owner           text,
    lease_expires_at      timestamptz,
    worker_epoch          bigint NOT NULL DEFAULT 0 CHECK (worker_epoch >= 0),
    next_attempt_at       timestamptz,
    error_code            text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    completed_at          timestamptz,
    UNIQUE (tenant_id, target_generation),
    UNIQUE (tenant_id, id),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL))
);
CREATE INDEX deployment_jobs_tenant_idx ON deployment_jobs (tenant_id, created_at DESC, id DESC);

ALTER TABLE cloud_deployments ADD CONSTRAINT cloud_deployments_last_job_fk
    FOREIGN KEY (id, last_job_id) REFERENCES deployment_jobs(tenant_id, id);

-- Snapshots make successful POST retries return the original result after later changes.
CREATE TABLE deployment_requests (
    idempotency_key        uuid PRIMARY KEY,
    operation             text NOT NULL,
    payload_digest        text NOT NULL,
    tenant_id             uuid NOT NULL REFERENCES cloud_deployments(id),
    response              jsonb NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now()
);
