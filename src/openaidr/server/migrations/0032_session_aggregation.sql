ALTER TABLE session_registrations
    ADD COLUMN delivery_protocol smallint CHECK (delivery_protocol=1),
    ADD COLUMN delivery_epoch uuid,
    ADD CONSTRAINT session_delivery_protocol_pair CHECK (
        (delivery_protocol IS NULL)=(delivery_epoch IS NULL)
        AND (delivery_protocol IS NULL OR assessment_mode='inline')
    );

CREATE FUNCTION preserve_session_delivery_protocol() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.delivery_protocol,NEW.delivery_epoch)
       IS DISTINCT FROM ROW(OLD.delivery_protocol,OLD.delivery_epoch) THEN
        RAISE EXCEPTION 'session delivery protocol is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER session_delivery_protocol_guard
    BEFORE UPDATE OF delivery_protocol,delivery_epoch ON session_registrations
    FOR EACH ROW EXECUTE FUNCTION preserve_session_delivery_protocol();

CREATE FUNCTION preserve_verified_session_binding() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id,NEW.tenant_id,NEW.sensor_id,NEW.product,NEW.created_at)
         IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.sensor_id,OLD.product,OLD.created_at)
       OR (OLD.external_id IS NOT NULL AND NEW.external_id IS DISTINCT FROM OLD.external_id)
       OR (OLD.verified_at IS NOT NULL AND (NEW.verified_at IS DISTINCT FROM OLD.verified_at
           OR (NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id AND NEW.owner_user_id IS NOT NULL))) THEN
        RAISE EXCEPTION 'verified session binding is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER verified_session_binding_guard BEFORE UPDATE ON session_registrations
    FOR EACH ROW EXECUTE FUNCTION preserve_verified_session_binding();

ALTER TABLE guardrail_releases ADD COLUMN outcome_audit_id uuid;

CREATE TABLE tenant_session_detection_settings (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    version bigint NOT NULL DEFAULT 1 CHECK (version>0),
    detector_config_version bigint NOT NULL DEFAULT 1 CHECK (detector_config_version>0),
    enabled boolean NOT NULL DEFAULT false,
    risk_threshold numeric CHECK (risk_threshold>=0 AND risk_threshold<'Infinity'::numeric),
    idle_seconds integer CHECK (idle_seconds>0),
    delivery_grace_seconds integer CHECK (delivery_grace_seconds>=0),
    gap_policy text CHECK (gap_policy IN ('retain','investigate')),
    gap_wait_seconds integer CHECK (gap_wait_seconds>=delivery_grace_seconds),
    model text CHECK (length(model) BETWEEN 1 AND 128),
    max_runtime_seconds integer CHECK (max_runtime_seconds>0),
    max_tokens_per_attempt bigint CHECK (max_tokens_per_attempt>0),
    max_cost_usd_per_attempt numeric CHECK (max_cost_usd_per_attempt>0 AND max_cost_usd_per_attempt<'Infinity'::numeric),
    max_attempts integer CHECK (max_attempts>0),
    max_concurrent integer CHECK (max_concurrent>0),
    hourly_attempts integer CHECK (hourly_attempts>0),
    hourly_tokens bigint CHECK (hourly_tokens>=max_tokens_per_attempt),
    hourly_cost_usd numeric CHECK (hourly_cost_usd>=max_cost_usd_per_attempt AND hourly_cost_usd<'Infinity'::numeric),
    retry_delay_seconds integer CHECK (retry_delay_seconds>=0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (NOT enabled OR (
        risk_threshold IS NOT NULL AND idle_seconds IS NOT NULL
        AND delivery_grace_seconds IS NOT NULL AND gap_policy IS NOT NULL
        AND gap_wait_seconds IS NOT NULL AND model IS NOT NULL
        AND max_runtime_seconds IS NOT NULL AND max_tokens_per_attempt IS NOT NULL
        AND max_cost_usd_per_attempt IS NOT NULL AND max_attempts IS NOT NULL
        AND max_concurrent IS NOT NULL AND hourly_attempts IS NOT NULL
        AND hourly_tokens IS NOT NULL AND hourly_cost_usd IS NOT NULL
        AND retry_delay_seconds IS NOT NULL
    ))
);

CREATE TABLE session_delivery_receipts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    registration_id uuid NOT NULL REFERENCES session_registrations(id) ON DELETE CASCADE,
    epoch_id uuid NOT NULL,
    record_id uuid NOT NULL,
    sequence bigint CHECK (sequence>0),
    kind text NOT NULL CHECK (kind IN ('target','observation','outcome','gap','close')),
    logical_id text,
    event_id uuid,
    release_id uuid,
    payload_sha256 text NOT NULL,
    payload jsonb NOT NULL,
    captured_body jsonb,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (registration_id,record_id),
    UNIQUE (registration_id,sequence),
    CHECK ((kind='close')=(sequence IS NULL)),
    CHECK (kind<>'target' OR (logical_id IS NOT NULL AND event_id IS NOT NULL))
);
CREATE UNIQUE INDEX session_delivery_target_idx ON session_delivery_receipts(registration_id,logical_id)
    WHERE kind='target';
CREATE INDEX session_delivery_close_idx ON session_delivery_receipts(registration_id,received_at,id)
    WHERE kind='close';
CREATE INDEX session_delivery_event_idx ON session_delivery_receipts(registration_id,event_id,id)
    WHERE kind IN ('target','observation');

-- Append-only wakeups deliberately have no parent FK or shared counter lock.
-- Their identities are not commit watermarks. Finalizers delete visible rows
-- under one MVCC snapshot; a later commit remains dirty even with an older ID.
CREATE TABLE session_input_dirty (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    registration_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX session_input_dirty_registration_idx ON session_input_dirty(registration_id,id);

CREATE TABLE session_finalizations (
    registration_id uuid PRIMARY KEY REFERENCES session_registrations(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    input_version bigint NOT NULL DEFAULT 0,
    revision bigint NOT NULL DEFAULT 0,
    snapshot_id uuid,
    lifecycle text NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active','closing','closed','incomplete')),
    last_activity_at timestamptz,
    next_evaluation_at timestamptz,
    closing_sequence bigint,
    status jsonb NOT NULL DEFAULT '{}'::jsonb,
    settings_version bigint NOT NULL DEFAULT 0,
    failure_code text NOT NULL DEFAULT '' CHECK (failure_code IN ('','finalization_timeout')),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX session_finalizations_due_idx ON session_finalizations(next_evaluation_at,registration_id);

CREATE TABLE session_snapshots (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    registration_id uuid NOT NULL REFERENCES session_registrations(id) ON DELETE CASCADE,
    owner_user_id uuid REFERENCES tenant_users(id) ON DELETE SET NULL,
    revision bigint NOT NULL CHECK (revision>0),
    input_version bigint NOT NULL CHECK (input_version>0),
    epoch_id uuid,
    closing_sequence bigint,
    lifecycle text NOT NULL CHECK (lifecycle IN ('closed','incomplete')),
    coverage jsonb NOT NULL,
    counts jsonb NOT NULL,
    risk_total numeric,
    risk_max numeric,
    item_count bigint NOT NULL DEFAULT 0 CHECK (item_count>=0),
    sealed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (registration_id,revision)
);
CREATE INDEX session_snapshots_owner_idx ON session_snapshots(tenant_id,owner_user_id,created_at,id);

CREATE TABLE session_snapshot_items (
    snapshot_id uuid NOT NULL REFERENCES session_snapshots(id) ON DELETE CASCADE,
    ordinal bigint NOT NULL CHECK (ordinal>0),
    kind text NOT NULL,
    source_id uuid NOT NULL,
    body jsonb NOT NULL,
    PRIMARY KEY (snapshot_id,ordinal),
    UNIQUE (snapshot_id,kind,source_id)
);

CREATE TABLE session_investigation_jobs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    registration_id uuid NOT NULL REFERENCES session_registrations(id) ON DELETE CASCADE,
    owner_user_id uuid REFERENCES tenant_users(id) ON DELETE SET NULL,
    snapshot_id uuid NOT NULL REFERENCES session_snapshots(id) ON DELETE CASCADE,
    detector_config_version bigint NOT NULL,
    settings_version bigint NOT NULL,
    configuration jsonb NOT NULL,
    routing_reason text NOT NULL CHECK (routing_reason IN ('risk_threshold','persistent_gap')),
    state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','completed','inconclusive','superseded')),
    attempts integer NOT NULL DEFAULT 0,
    claim_token uuid,
    lease_deadline timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    result jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    UNIQUE (snapshot_id,detector_config_version)
);
CREATE INDEX session_investigation_jobs_queue_idx ON session_investigation_jobs(next_attempt_at,id)
    WHERE state='queued';
CREATE INDEX session_investigation_jobs_running_idx ON session_investigation_jobs(tenant_id,lease_deadline)
    WHERE state='running';

CREATE TABLE session_investigation_attempts (
    id uuid PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES session_investigation_jobs(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ordinal integer NOT NULL CHECK (ordinal>0),
    claim_token uuid NOT NULL UNIQUE,
    worker_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('reserved','dispatched','completed','failed','uncertain','released')),
    reserved_tokens bigint NOT NULL CHECK (reserved_tokens>0),
    reserved_cost_usd numeric NOT NULL CHECK (reserved_cost_usd>0),
    window_start timestamptz NOT NULL,
    deadline_at timestamptz NOT NULL,
    dispatched_at timestamptz,
    completed_at timestamptz,
    actual_tokens bigint CHECK (actual_tokens>=0),
    actual_cost_usd numeric CHECK (actual_cost_usd>=0 AND actual_cost_usd<'Infinity'::numeric),
    result jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (job_id,ordinal)
);
CREATE INDEX session_investigation_attempts_budget_idx ON session_investigation_attempts(tenant_id,window_start);
CREATE INDEX session_checks_registration_idx ON inline_guardrail_checks(registration_id,id);
CREATE INDEX session_approvals_registration_idx ON guardrail_approvals(registration_id,id);
CREATE INDEX session_releases_registration_idx ON guardrail_releases(registration_id,id);

CREATE FUNCTION preserve_session_snapshot() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.sealed_at IS NOT NULL AND (
        (to_jsonb(NEW)-'owner_user_id') IS DISTINCT FROM (to_jsonb(OLD)-'owner_user_id')
        OR (NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id AND NEW.owner_user_id IS NOT NULL)
    ) THEN
        RAISE EXCEPTION 'session snapshot is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER session_snapshot_guard BEFORE UPDATE ON session_snapshots
    FOR EACH ROW EXECUTE FUNCTION preserve_session_snapshot();

CREATE FUNCTION preserve_session_snapshot_item() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='UPDATE' OR EXISTS (
        SELECT 1 FROM session_snapshots WHERE id=CASE WHEN TG_OP='DELETE' THEN OLD.snapshot_id ELSE NEW.snapshot_id END
          AND sealed_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'session snapshot item is immutable' USING ERRCODE='23514';
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER session_snapshot_item_guard BEFORE INSERT OR UPDATE OR DELETE ON session_snapshot_items
    FOR EACH ROW EXECUTE FUNCTION preserve_session_snapshot_item();

CREATE FUNCTION preserve_session_receipt() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'session receipt is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER session_receipt_guard BEFORE UPDATE ON session_delivery_receipts
    FOR EACH ROW EXECUTE FUNCTION preserve_session_receipt();

CREATE FUNCTION mark_session_input_dirty() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE registration uuid;
BEGIN
    IF TG_TABLE_NAME='session_delivery_receipts' THEN
        IF NEW.kind='close' AND EXISTS (
            SELECT 1 FROM session_delivery_receipts d WHERE d.registration_id=NEW.registration_id
              AND d.kind='close' AND d.id<>NEW.id AND d.payload-'record_id'=NEW.payload-'record_id'
        ) THEN
            RETURN NEW;
        END IF;
    END IF;
    IF TG_TABLE_NAME='events' THEN
        SELECT registration_id INTO registration FROM agent_sessions WHERE id=NEW.session_id;
    ELSE
        registration := NEW.registration_id;
    END IF;
    IF registration IS NOT NULL AND EXISTS (
        SELECT 1 FROM session_registrations r WHERE r.id=registration AND r.assessment_mode='inline'
    ) THEN
        INSERT INTO session_input_dirty(registration_id) VALUES(registration);
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER session_observation_dirty AFTER INSERT ON events
    FOR EACH ROW EXECUTE FUNCTION mark_session_input_dirty();
CREATE TRIGGER session_assessment_dirty AFTER INSERT OR UPDATE OF status,assessment ON inline_guardrail_events
    FOR EACH ROW EXECUTE FUNCTION mark_session_input_dirty();
CREATE TRIGGER session_check_dirty AFTER INSERT OR UPDATE OF decision,approval_id ON inline_guardrail_checks
    FOR EACH ROW EXECUTE FUNCTION mark_session_input_dirty();
CREATE TRIGGER session_approval_dirty AFTER INSERT OR UPDATE OF status,approved_until ON guardrail_approvals
    FOR EACH ROW EXECUTE FUNCTION mark_session_input_dirty();
CREATE TRIGGER session_release_dirty AFTER INSERT OR UPDATE OF outcome,outcome_details ON guardrail_releases
    FOR EACH ROW EXECUTE FUNCTION mark_session_input_dirty();
CREATE TRIGGER session_delivery_dirty AFTER INSERT ON session_delivery_receipts
    FOR EACH ROW EXECUTE FUNCTION mark_session_input_dirty();

-- Existing inline sessions become eligible for an honest unknown-coverage
-- projection. Delivery protocol cannot be attached to them retrospectively.
INSERT INTO session_input_dirty(registration_id)
    SELECT id FROM session_registrations WHERE assessment_mode='inline';
