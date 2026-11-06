-- Transport identities share the tenant controller's transaction and authority.
CREATE TABLE session_investigation_remote_bindings (
    attempt_id uuid PRIMARY KEY REFERENCES session_investigation_attempts(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_tenant_id uuid NOT NULL,
    origin text NOT NULL CHECK (length(origin) BETWEEN 1 AND 2048),
    profile jsonb NOT NULL,
    create_request jsonb NOT NULL,
    remote_id uuid,
    publication jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(owner_tenant_id,origin,remote_id)
);

CREATE TABLE session_investigation_remote_messages (
    id uuid PRIMARY KEY,
    attempt_id uuid NOT NULL REFERENCES session_investigation_remote_bindings(attempt_id) ON DELETE CASCADE,
    step_id uuid,
    kind text NOT NULL CHECK (kind IN ('step','reply','step_ack','finish')),
    message jsonb,
    message_sha256 text NOT NULL CHECK (message_sha256 ~ '^[a-f0-9]{64}$'),
    operation_id uuid,
    operation_sequence bigint CHECK (operation_sequence>0),
    operation_sha256 text CHECK (operation_sha256 ~ '^[a-f0-9]{64}$'),
    operation_kind text CHECK (operation_kind IN ('read_tool','admit_call','finish_call')),
    read_id uuid REFERENCES session_investigation_reads(id) ON DELETE CASCADE,
    ack_revision bigint CHECK (ack_revision>0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(step_id,attempt_id) REFERENCES session_investigation_steps(id,attempt_id) ON DELETE CASCADE,
    UNIQUE(attempt_id,operation_id),
    UNIQUE(attempt_id,operation_sequence),
    CHECK ((kind='reply')=(operation_id IS NOT NULL AND operation_sequence IS NOT NULL
           AND operation_sha256 IS NOT NULL AND operation_kind IS NOT NULL)),
    CHECK (message IS NOT NULL OR kind='step' OR operation_kind='read_tool')
);
CREATE UNIQUE INDEX investigation_remote_step_message ON session_investigation_remote_messages(attempt_id,kind,step_id)
    WHERE kind IN ('step','step_ack');
CREATE UNIQUE INDEX investigation_remote_finish_message ON session_investigation_remote_messages(attempt_id)
    WHERE kind='finish';
