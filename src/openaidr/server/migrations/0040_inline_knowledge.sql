ALTER TABLE tenant_guardrail_settings
    ADD COLUMN context_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN context_required boolean NOT NULL DEFAULT false,
    ADD COLUMN context_failure_action text NOT NULL DEFAULT 'ask'
        CHECK (context_failure_action IN ('ask','block')),
    ADD CONSTRAINT guardrail_required_context CHECK (NOT context_required OR context_enabled);

ALTER TABLE session_registrations ADD UNIQUE (id,tenant_id);
CREATE TABLE session_knowledge_scopes (
    registration_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope_key text,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (scope_key IS NULL OR octet_length(scope_key) BETWEEN 1 AND 240),
    FOREIGN KEY (registration_id,tenant_id) REFERENCES session_registrations(id,tenant_id) ON DELETE CASCADE
);

ALTER TABLE inline_guardrail_events
    ADD COLUMN assessment_generation integer NOT NULL DEFAULT 1 CHECK (assessment_generation > 0),
    ADD COLUMN context_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN context_pinned boolean NOT NULL DEFAULT false,
    ADD COLUMN knowledge_snapshot jsonb,
    ADD COLUMN context_revision bigint,
    ADD COLUMN scope_key text,
    ADD COLUMN scope_version bigint NOT NULL DEFAULT 0;

ALTER TABLE inline_guardrail_events ADD UNIQUE (id,tenant_id);
CREATE TABLE inline_guardrail_assessments (
    guardrail_event_id uuid NOT NULL,
    generation integer NOT NULL CHECK (generation > 0),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    prepared_state jsonb NOT NULL,
    model text NOT NULL,
    rubric_version integer NOT NULL,
    status text NOT NULL CHECK (status IN ('pending','scored','unavailable')),
    assessment jsonb,
    claim_token uuid,
    deadline_at timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    context_enabled boolean NOT NULL,
    context_pinned boolean NOT NULL,
    knowledge_snapshot jsonb,
    context_revision bigint,
    scope_key text,
    scope_version bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (guardrail_event_id,generation),
    FOREIGN KEY (guardrail_event_id,tenant_id) REFERENCES inline_guardrail_events(id,tenant_id) ON DELETE CASCADE
);

INSERT INTO inline_guardrail_assessments
    (guardrail_event_id,generation,tenant_id,prepared_state,model,rubric_version,status,
     assessment,claim_token,deadline_at,started_at,completed_at,context_enabled,
     context_pinned,knowledge_snapshot,context_revision,scope_key,scope_version)
SELECT id,assessment_generation,tenant_id,prepared_state,model,rubric_version,status,
       assessment,claim_token,deadline_at,started_at,completed_at,context_enabled,
       context_pinned,knowledge_snapshot,context_revision,scope_key,scope_version
FROM inline_guardrail_events;

ALTER TABLE inline_guardrail_checks ADD COLUMN assessment_generation integer NOT NULL DEFAULT 1;
ALTER TABLE guardrail_approvals ADD COLUMN assessment_generation integer NOT NULL DEFAULT 1;
ALTER TABLE guardrail_releases ADD COLUMN assessment_generation integer NOT NULL DEFAULT 1;
ALTER TABLE inline_guardrail_checks ADD FOREIGN KEY (guardrail_event_id,assessment_generation)
    REFERENCES inline_guardrail_assessments(guardrail_event_id,generation);
ALTER TABLE guardrail_approvals ADD FOREIGN KEY (guardrail_event_id,assessment_generation)
    REFERENCES inline_guardrail_assessments(guardrail_event_id,generation);
ALTER TABLE guardrail_releases ADD FOREIGN KEY (guardrail_event_id,assessment_generation)
    REFERENCES inline_guardrail_assessments(guardrail_event_id,generation);

ALTER TABLE guardrail_approvals DROP CONSTRAINT guardrail_approvals_reason_code_check;
ALTER TABLE guardrail_approvals ADD CHECK (reason_code IN (
    '', 'approval_expired', 'policy_changed', 'approvals_disabled', 'owner_revoked', 'context_changed'
));

CREATE FUNCTION guardrail_assessment_history_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.guardrail_event_id,NEW.generation,NEW.tenant_id,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.guardrail_event_id,OLD.generation,OLD.tenant_id,OLD.created_at)
       OR (OLD.status <> 'pending' AND NEW IS DISTINCT FROM OLD)
       OR (OLD.context_pinned AND ROW(NEW.context_pinned,NEW.prepared_state,
           NEW.knowledge_snapshot,NEW.context_revision,NEW.scope_key,NEW.scope_version)
           IS DISTINCT FROM ROW(OLD.context_pinned,OLD.prepared_state,
           OLD.knowledge_snapshot,OLD.context_revision,OLD.scope_key,OLD.scope_version)) THEN
        RAISE EXCEPTION 'assessment generation is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER guardrail_assessment_history_guard BEFORE UPDATE ON inline_guardrail_assessments
    FOR EACH ROW EXECUTE FUNCTION guardrail_assessment_history_guard();

-- Keep older receivers compatible while the default-off feature rolls out.
CREATE FUNCTION guardrail_sync_assessment() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO inline_guardrail_assessments
        (guardrail_event_id,generation,tenant_id,prepared_state,model,rubric_version,status,
         assessment,claim_token,deadline_at,started_at,completed_at,context_enabled,
         context_pinned,knowledge_snapshot,context_revision,scope_key,scope_version)
    VALUES(NEW.id,NEW.assessment_generation,NEW.tenant_id,NEW.prepared_state,NEW.model,
           NEW.rubric_version,NEW.status,NEW.assessment,NEW.claim_token,NEW.deadline_at,
           NEW.started_at,NEW.completed_at,NEW.context_enabled,NEW.context_pinned,
           NEW.knowledge_snapshot,NEW.context_revision,NEW.scope_key,NEW.scope_version)
    ON CONFLICT(guardrail_event_id,generation) DO UPDATE SET
        prepared_state=EXCLUDED.prepared_state,model=EXCLUDED.model,rubric_version=EXCLUDED.rubric_version,
        status=EXCLUDED.status,assessment=EXCLUDED.assessment,claim_token=EXCLUDED.claim_token,
        deadline_at=EXCLUDED.deadline_at,started_at=EXCLUDED.started_at,completed_at=EXCLUDED.completed_at,
        context_enabled=EXCLUDED.context_enabled,context_pinned=EXCLUDED.context_pinned,
        knowledge_snapshot=EXCLUDED.knowledge_snapshot,context_revision=EXCLUDED.context_revision,
        scope_key=EXCLUDED.scope_key,scope_version=EXCLUDED.scope_version
    WHERE inline_guardrail_assessments.status='pending';
    RETURN NEW;
END;
$$;
CREATE TRIGGER guardrail_sync_assessment AFTER INSERT OR UPDATE ON inline_guardrail_events
    FOR EACH ROW EXECUTE FUNCTION guardrail_sync_assessment();

CREATE FUNCTION guardrail_assessment_binding_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.assessment_generation IS DISTINCT FROM OLD.assessment_generation THEN
        RAISE EXCEPTION 'assessment binding is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER guardrail_check_assessment_guard BEFORE UPDATE OF assessment_generation
    ON inline_guardrail_checks FOR EACH ROW EXECUTE FUNCTION guardrail_assessment_binding_guard();
CREATE TRIGGER guardrail_approval_assessment_guard BEFORE UPDATE OF assessment_generation
    ON guardrail_approvals FOR EACH ROW EXECUTE FUNCTION guardrail_assessment_binding_guard();
CREATE TRIGGER guardrail_release_assessment_guard BEFORE UPDATE OF assessment_generation
    ON guardrail_releases FOR EACH ROW EXECUTE FUNCTION guardrail_assessment_binding_guard();
