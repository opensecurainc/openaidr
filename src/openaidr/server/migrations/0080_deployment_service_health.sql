CREATE TABLE deployment_service_health (
    tenant_id uuid PRIMARY KEY REFERENCES cloud_deployments(id) ON DELETE CASCADE,
    observed_generation bigint NOT NULL CHECK (observed_generation > 0),
    release_id text NOT NULL CHECK (release_id ~ '^[a-f0-9]{40}$'),
    instance_id text NOT NULL,
    service_account_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('healthy', 'down', 'unknown')),
    reason text NOT NULL CHECK (reason IN ('backend_ready', 'backend_unhealthy',
        'backend_starting', 'vm_stopped', 'probe_unavailable', 'identity_mismatch')),
    components jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(components) = 'object'),
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
