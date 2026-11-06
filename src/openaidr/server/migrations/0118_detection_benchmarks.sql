CREATE TABLE detection_benchmark_settings (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT false,
    hour_utc integer NOT NULL DEFAULT 9 CHECK (hour_utc BETWEEN 0 AND 23),
    daily_budget_usd numeric(12,6) NOT NULL DEFAULT 20 CHECK (daily_budget_usd>0 AND daily_budget_usd<=20),
    version bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE detection_benchmark_runs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id uuid NOT NULL,
    billing_day date NOT NULL,
    trigger text NOT NULL CHECK (trigger IN ('manual','daily')),
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','partial','failed','cancelled','interrupted')),
    configuration jsonb NOT NULL,
    result jsonb,
    reserved_usd numeric(12,6) NOT NULL CHECK (reserved_usd>=0),
    charged_usd numeric(24,12) CHECK (charged_usd>=0),
    cancel_requested boolean NOT NULL DEFAULT false,
    error text NOT NULL DEFAULT '',
    lease_owner uuid,
    lease_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    started_at timestamptz,
    finished_at timestamptz,
    UNIQUE(tenant_id,request_id)
);
CREATE UNIQUE INDEX detection_benchmark_active ON detection_benchmark_runs(tenant_id) WHERE status IN ('queued','running');
CREATE UNIQUE INDEX detection_benchmark_daily ON detection_benchmark_runs(tenant_id,billing_day) WHERE trigger='daily';
CREATE INDEX detection_benchmark_history ON detection_benchmark_runs(tenant_id,created_at DESC,id);
