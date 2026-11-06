-- Initial schema. Every tenant-owned table carries tenant_id.

CREATE TABLE tenants (
    id          uuid PRIMARY KEY,
    name        text NOT NULL,
    slug        text NOT NULL UNIQUE,
    status      text NOT NULL DEFAULT 'active',
    plan        text NOT NULL DEFAULT 'trial',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenant_users (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    email         text NOT NULL,
    name          text NOT NULL DEFAULT '',
    password_hash text NOT NULL,
    role          text NOT NULL,
    status        text NOT NULL DEFAULT 'active',
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);
CREATE UNIQUE INDEX tenant_users_email_idx ON tenant_users (lower(email));
CREATE INDEX tenant_users_tenant_idx ON tenant_users (tenant_id);

CREATE TABLE invites (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    token_hash      text NOT NULL UNIQUE,
    email           text NOT NULL,
    role            text NOT NULL,
    expires_at      timestamptz NOT NULL,
    accepted_at     timestamptz,
    created_by_type text NOT NULL DEFAULT '',
    created_by_id   text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX invites_tenant_idx ON invites (tenant_id, created_at DESC);

CREATE TABLE auth_sessions (
    id           uuid PRIMARY KEY,
    token_hash   text NOT NULL UNIQUE,
    user_id      uuid NOT NULL REFERENCES tenant_users(id) ON DELETE CASCADE,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE platform_admins (
    id            uuid PRIMARY KEY,
    email         text NOT NULL,
    name          text NOT NULL DEFAULT '',
    password_hash text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);
CREATE UNIQUE INDEX platform_admins_email_idx ON platform_admins (lower(email));

CREATE TABLE platform_sessions (
    id           uuid PRIMARY KEY,
    token_hash   text NOT NULL UNIQUE,
    admin_id     uuid NOT NULL REFERENCES platform_admins(id) ON DELETE CASCADE,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE enrollment_tokens (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    token_hash text NOT NULL UNIQUE,
    label      text NOT NULL DEFAULT '',
    expires_at timestamptz,
    max_uses   int NOT NULL DEFAULT 0,
    uses       int NOT NULL DEFAULT 0,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX enrollment_tokens_tenant_idx ON enrollment_tokens (tenant_id, created_at DESC);

CREATE TABLE sensors (
    id                uuid PRIMARY KEY,
    tenant_id         uuid NOT NULL REFERENCES tenants(id),
    token_hash        text UNIQUE,
    label             text NOT NULL DEFAULT '',
    hostname          text NOT NULL DEFAULT '',
    os                text NOT NULL DEFAULT '',
    arch              text NOT NULL DEFAULT '',
    username          text NOT NULL DEFAULT '',
    host_kind         text NOT NULL DEFAULT 'workstation',
    version           text NOT NULL DEFAULT '',
    disabled          boolean NOT NULL DEFAULT false,
    enrolled_at       timestamptz NOT NULL DEFAULT now(),
    last_heartbeat_at timestamptz,
    collectors        jsonb NOT NULL DEFAULT '[]'::jsonb,
    hook_installed    boolean NOT NULL DEFAULT false,
    queue_depth       int NOT NULL DEFAULT 0,
    policy_version    bigint NOT NULL DEFAULT 0,
    uptime_s          bigint NOT NULL DEFAULT 0,
    agents_total      bigint NOT NULL DEFAULT 0,
    events_total      bigint NOT NULL DEFAULT 0,
    deleted_at        timestamptz
);
CREATE INDEX sensors_tenant_idx ON sensors (tenant_id, enrolled_at DESC, id);

CREATE TABLE sensor_commands (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    sensor_id    uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    type         text NOT NULL,
    params       jsonb NOT NULL DEFAULT '{}'::jsonb,
    status       text NOT NULL DEFAULT 'pending',
    action_id    uuid,
    created_at   timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    acked_at     timestamptz,
    message      text NOT NULL DEFAULT ''
);
CREATE INDEX sensor_commands_pending_idx ON sensor_commands (sensor_id, created_at) WHERE status IN ('pending', 'delivered');

CREATE TABLE agents (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenants(id),
    sensor_id      uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    product        text NOT NULL,
    version        text NOT NULL DEFAULT '',
    hostname       text NOT NULL DEFAULT '',
    os             text NOT NULL DEFAULT '',
    arch           text NOT NULL DEFAULT '',
    username       text NOT NULL DEFAULT '',
    models         text[] NOT NULL DEFAULT '{}',
    first_seen     timestamptz NOT NULL DEFAULT now(),
    last_seen      timestamptz NOT NULL DEFAULT now(),
    sessions_total bigint NOT NULL DEFAULT 0,
    events_total   bigint NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, sensor_id, product, username)
);
CREATE INDEX agents_tenant_idx ON agents (tenant_id, last_seen DESC, id);

CREATE TABLE agent_sessions (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    agent_id      uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    sensor_id     uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    external_id   text NOT NULL,
    product       text NOT NULL,
    cwd           text NOT NULL DEFAULT '',
    git_branch    text NOT NULL DEFAULT '',
    started_at    timestamptz NOT NULL,
    last_event_at timestamptz NOT NULL,
    ended_at      timestamptz,
    events_total  bigint NOT NULL DEFAULT 0,
    tool_calls    bigint NOT NULL DEFAULT 0,
    commands      bigint NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, agent_id, external_id)
);
CREATE INDEX agent_sessions_agent_idx ON agent_sessions (agent_id, last_event_at DESC, id);
CREATE INDEX agent_sessions_tenant_idx ON agent_sessions (tenant_id, last_event_at DESC);

CREATE TABLE events (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    sensor_id    uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    agent_id     uuid REFERENCES agents(id) ON DELETE CASCADE,
    session_id   uuid REFERENCES agent_sessions(id) ON DELETE CASCADE,
    time         timestamptz NOT NULL,
    observed_at  timestamptz,
    received_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    kind         text NOT NULL,
    product      text NOT NULL,
    command_text text,
    file_path    text,
    network_host text,
    tool_name    text,
    body         jsonb NOT NULL
);
CREATE INDEX events_tenant_received_idx ON events (tenant_id, received_at, id);
CREATE INDEX events_tenant_time_idx ON events (tenant_id, time DESC, id DESC);
CREATE INDEX events_session_time_idx ON events (session_id, time, id);
CREATE INDEX events_agent_time_idx ON events (agent_id, time DESC);
CREATE INDEX events_tenant_kind_idx ON events (tenant_id, kind, time DESC);

CREATE TABLE detection_rules (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    rule_id   text NOT NULL,
    enabled   boolean NOT NULL DEFAULT true,
    PRIMARY KEY (tenant_id, rule_id)
);

CREATE TABLE detect_cursors (
    tenant_id        uuid PRIMARY KEY REFERENCES tenants(id),
    last_received_at timestamptz NOT NULL DEFAULT '1970-01-01',
    last_event_id    uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE findings (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES tenants(id),
    rule_id          text NOT NULL,
    category         text NOT NULL,
    severity         text NOT NULL,
    status           text NOT NULL DEFAULT 'open',
    title            text NOT NULL,
    summary          text NOT NULL DEFAULT '',
    agent_id         uuid REFERENCES agents(id) ON DELETE SET NULL,
    session_id       uuid REFERENCES agent_sessions(id) ON DELETE SET NULL,
    sensor_id        uuid NOT NULL,
    hostname         text NOT NULL DEFAULT '',
    os               text NOT NULL DEFAULT '',
    arch             text NOT NULL DEFAULT '',
    username         text NOT NULL DEFAULT '',
    product          text NOT NULL DEFAULT '',
    event_ids        uuid[] NOT NULL DEFAULT '{}',
    primary_event_id uuid NOT NULL,
    first_event_at   timestamptz NOT NULL,
    assignee_id      uuid REFERENCES tenant_users(id) ON DELETE SET NULL,
    resolution       text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX findings_dedupe_idx ON findings (tenant_id, rule_id, COALESCE(session_id, '00000000-0000-0000-0000-000000000000'::uuid), primary_event_id);
CREATE INDEX findings_tenant_idx ON findings (tenant_id, created_at DESC, id DESC);
CREATE INDEX findings_open_idx ON findings (tenant_id, status) WHERE status IN ('open', 'triaged');

CREATE TABLE finding_notes (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    author_id  uuid NOT NULL,
    body       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX finding_notes_finding_idx ON finding_notes (finding_id, created_at);

CREATE TABLE response_actions (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    finding_id uuid REFERENCES findings(id) ON DELETE SET NULL,
    type       text NOT NULL,
    params     jsonb NOT NULL DEFAULT '{}'::jsonb,
    status     text NOT NULL DEFAULT 'pending',
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    applied_at timestamptz,
    message    text NOT NULL DEFAULT ''
);
CREATE INDEX response_actions_tenant_idx ON response_actions (tenant_id, created_at DESC, id DESC);

CREATE TABLE policies (
    tenant_id  uuid PRIMARY KEY REFERENCES tenants(id),
    version    bigint NOT NULL DEFAULT 1,
    rules      jsonb NOT NULL DEFAULT '[]'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id          uuid PRIMARY KEY,
    tenant_id   uuid,
    at          timestamptz NOT NULL DEFAULT now(),
    actor_type  text NOT NULL,
    actor_id    text NOT NULL,
    actor_name  text NOT NULL DEFAULT '',
    action      text NOT NULL,
    target_type text NOT NULL DEFAULT '',
    target_id   text NOT NULL DEFAULT '',
    details     jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_tenant_idx ON audit_log (tenant_id, at DESC, id DESC);

CREATE TABLE service_heartbeats (
    service      text NOT NULL,
    instance     text NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    details      jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (service, instance)
);
