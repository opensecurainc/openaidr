ALTER TABLE tenant_guardrail_settings
    ADD COLUMN approvals_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN approval_wait_seconds integer CHECK (approval_wait_seconds BETWEEN 1 AND 86400),
    ADD COLUMN approval_use_seconds integer CHECK (approval_use_seconds BETWEEN 1 AND 86400),
    ADD CONSTRAINT guardrail_approval_configuration CHECK (
        NOT approvals_enabled OR (approval_wait_seconds IS NOT NULL AND approval_use_seconds IS NOT NULL)
    );

CREATE TABLE guardrail_approvals (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    registration_id uuid NOT NULL REFERENCES session_registrations(id) ON DELETE CASCADE,
    owner_user_id uuid REFERENCES tenant_users(id) ON DELETE SET NULL,
    guardrail_event_id uuid NOT NULL REFERENCES inline_guardrail_events(id) ON DELETE CASCADE,
    originating_check_id uuid NOT NULL REFERENCES inline_guardrail_checks(id) ON DELETE CASCADE,
    generation bigint NOT NULL CHECK (generation>0),
    settings_version bigint NOT NULL,
    policy_version bigint NOT NULL,
    status text NOT NULL CHECK (status IN ('pending','approved','rejected','expired','revoked')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    decision text CHECK (decision IN ('approve','reject')),
    decided_at timestamptz,
    decided_by_user_id uuid REFERENCES tenant_users(id) ON DELETE SET NULL,
    approved_until timestamptz,
    revoked_at timestamptz,
    reason_code text NOT NULL DEFAULT '' CHECK (reason_code IN (
        '', 'approval_expired', 'policy_changed', 'approvals_disabled', 'owner_revoked'
    )),
    UNIQUE (guardrail_event_id,generation),
    CHECK ((decision IS NULL)=(decided_at IS NULL)),
    CHECK (status<>'pending' OR decision IS NULL),
    CHECK (status<>'approved' OR (decision IS NOT DISTINCT FROM 'approve' AND approved_until IS NOT NULL)),
    CHECK (status<>'rejected' OR decision IS NOT DISTINCT FROM 'reject'),
    CHECK (status<>'revoked' OR (revoked_at IS NOT NULL AND reason_code<>''))
);
CREATE UNIQUE INDEX guardrail_approvals_active_idx ON guardrail_approvals(guardrail_event_id)
    WHERE status IN ('pending','approved');
CREATE INDEX guardrail_approvals_owner_idx ON guardrail_approvals(tenant_id,owner_user_id,created_at,id);
CREATE INDEX guardrail_approvals_pending_idx ON guardrail_approvals(expires_at,id) WHERE status='pending';
CREATE INDEX guardrail_approvals_approved_idx ON guardrail_approvals(approved_until,id) WHERE status='approved';

ALTER TABLE inline_guardrail_checks ADD COLUMN approval_id uuid REFERENCES guardrail_approvals(id);

CREATE TABLE guardrail_releases (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    registration_id uuid NOT NULL REFERENCES session_registrations(id) ON DELETE CASCADE,
    owner_user_id uuid REFERENCES tenant_users(id) ON DELETE SET NULL,
    guardrail_event_id uuid NOT NULL UNIQUE REFERENCES inline_guardrail_events(id) ON DELETE CASCADE,
    check_id uuid NOT NULL REFERENCES inline_guardrail_checks(id) ON DELETE CASCADE,
    approval_id uuid REFERENCES guardrail_approvals(id) ON DELETE CASCADE,
    consume_request_id uuid NOT NULL,
    consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    outcome text CHECK (outcome IN ('succeeded','failed','not_executed','uncertain')),
    outcome_at timestamptz,
    outcome_details jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (tenant_id,sensor_id,consume_request_id),
    CHECK ((outcome IS NULL)=(outcome_at IS NULL))
);

CREATE FUNCTION guardrail_approval_binding_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id,NEW.tenant_id,NEW.sensor_id,NEW.registration_id,NEW.guardrail_event_id,
           NEW.originating_check_id,NEW.generation,NEW.settings_version,NEW.policy_version,
           NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_id,OLD.sensor_id,OLD.registration_id,OLD.guardrail_event_id,
           OLD.originating_check_id,OLD.generation,OLD.settings_version,OLD.policy_version,
           OLD.created_at)
       OR NEW.expires_at>OLD.expires_at
       OR (OLD.status IN ('rejected','expired','revoked') AND NEW.status<>OLD.status)
       OR (OLD.status='approved' AND NEW.status='pending')
       OR (NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id AND NEW.owner_user_id IS NOT NULL)
       OR (OLD.decision IS NOT NULL AND ROW(NEW.decision,NEW.decided_at)
           IS DISTINCT FROM ROW(OLD.decision,OLD.decided_at))
       OR (OLD.approved_until IS NOT NULL
           AND (NEW.approved_until IS NULL OR NEW.approved_until>OLD.approved_until))
       OR (OLD.decided_by_user_id IS NOT NULL AND NEW.decided_by_user_id IS DISTINCT FROM OLD.decided_by_user_id
           AND NEW.decided_by_user_id IS NOT NULL) THEN
        RAISE EXCEPTION 'approval binding is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER guardrail_approval_binding_guard BEFORE UPDATE ON guardrail_approvals
    FOR EACH ROW EXECUTE FUNCTION guardrail_approval_binding_guard();

CREATE FUNCTION guardrail_check_approval_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.approval_id IS NOT NULL AND NEW.approval_id IS DISTINCT FROM OLD.approval_id THEN
        RAISE EXCEPTION 'check approval is immutable' USING ERRCODE='23514';
    END IF;
    IF NEW.approval_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM guardrail_approvals a WHERE a.id=NEW.approval_id
          AND a.tenant_id=NEW.tenant_id AND a.sensor_id=NEW.sensor_id
          AND a.registration_id=NEW.registration_id AND a.guardrail_event_id=NEW.guardrail_event_id
          AND a.owner_user_id IS NOT DISTINCT FROM NEW.owner_user_id
          AND a.settings_version=NEW.settings_version AND a.policy_version=NEW.policy_version
    ) THEN
        RAISE EXCEPTION 'check approval scope does not match' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER guardrail_check_approval_guard BEFORE UPDATE OF approval_id ON inline_guardrail_checks
    FOR EACH ROW EXECUTE FUNCTION guardrail_check_approval_guard();

CREATE FUNCTION guardrail_release_binding_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id,NEW.tenant_id,NEW.sensor_id,NEW.registration_id,NEW.guardrail_event_id,
           NEW.check_id,NEW.approval_id,NEW.consume_request_id,NEW.consumed_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_id,OLD.sensor_id,OLD.registration_id,OLD.guardrail_event_id,
           OLD.check_id,OLD.approval_id,OLD.consume_request_id,OLD.consumed_at)
       OR (NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id AND NEW.owner_user_id IS NOT NULL)
       OR (OLD.outcome IS NOT NULL AND OLD.outcome<>'uncertain'
           AND ROW(NEW.outcome,NEW.outcome_at,NEW.outcome_details)
               IS DISTINCT FROM ROW(OLD.outcome,OLD.outcome_at,OLD.outcome_details))
       OR (OLD.outcome='uncertain' AND (NEW.outcome IS NULL
           OR (NEW.outcome='uncertain' AND ROW(NEW.outcome_at,NEW.outcome_details)
               IS DISTINCT FROM ROW(OLD.outcome_at,OLD.outcome_details)))) THEN
        RAISE EXCEPTION 'release binding or terminal outcome is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER guardrail_release_binding_guard BEFORE UPDATE ON guardrail_releases
    FOR EACH ROW EXECUTE FUNCTION guardrail_release_binding_guard();
