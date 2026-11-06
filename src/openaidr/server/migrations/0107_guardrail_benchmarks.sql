CREATE TABLE guardrail_benchmark_datasets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name text NOT NULL,
    sha256 text NOT NULL,
    cases jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(tenant_id,sha256)
);

CREATE TABLE guardrail_benchmark_runs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id uuid NOT NULL,
    dataset jsonb NOT NULL,
    configuration jsonb NOT NULL,
    cases jsonb NOT NULL DEFAULT '[]',
    summary jsonb NOT NULL DEFAULT '{}',
    status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','completed','cancelled','interrupted','failed')),
    cancel_requested boolean NOT NULL DEFAULT false,
    error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    started_at timestamptz,
    finished_at timestamptz,
    lease_owner uuid,
    lease_until timestamptz,
    UNIQUE(tenant_id,request_id),
    UNIQUE(id,tenant_id)
);
CREATE UNIQUE INDEX guardrail_benchmark_active_idx ON guardrail_benchmark_runs(tenant_id) WHERE status IN ('queued','running');
CREATE INDEX guardrail_benchmark_history_idx ON guardrail_benchmark_runs(tenant_id,created_at DESC,id DESC);
CREATE INDEX guardrail_benchmark_queue_idx ON guardrail_benchmark_runs(created_at,id) WHERE status='queued';
CREATE INDEX guardrail_benchmark_lease_idx ON guardrail_benchmark_runs(lease_until) WHERE status='running';

CREATE TABLE guardrail_benchmark_results (
    run_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    ordinal integer NOT NULL,
    result jsonb NOT NULL,
    PRIMARY KEY(run_id,ordinal),
    FOREIGN KEY(run_id,tenant_id) REFERENCES guardrail_benchmark_runs(id,tenant_id) ON DELETE CASCADE
);
