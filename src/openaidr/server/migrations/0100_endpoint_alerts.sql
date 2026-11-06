CREATE TABLE endpoint_alerts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id uuid NOT NULL,
    application_id text NOT NULL,
    content jsonb NOT NULL,
    sensor_ids jsonb NOT NULL,
    sender_id uuid NOT NULL,
    sender_name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now() + interval '30 days',
    UNIQUE (tenant_id, request_id),
    UNIQUE (tenant_id, id)
);
CREATE INDEX endpoint_alert_history ON endpoint_alerts(tenant_id, application_id, created_at DESC, id DESC);
CREATE TABLE endpoint_alert_receipts (
    tenant_id uuid NOT NULL,
    alert_id uuid NOT NULL,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    received_at timestamptz,
    acknowledged_at timestamptz,
    PRIMARY KEY (tenant_id, alert_id, sensor_id),
    FOREIGN KEY (tenant_id, alert_id) REFERENCES endpoint_alerts(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX endpoint_alert_inbox ON endpoint_alert_receipts(tenant_id, sensor_id, acknowledged_at);
