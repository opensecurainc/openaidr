ALTER TABLE inline_guardrail_events
    ADD COLUMN profile text,
    ALTER COLUMN model DROP NOT NULL,
    ALTER COLUMN rubric_version DROP NOT NULL,
    ADD CHECK (CASE WHEN profile IS NULL THEN model IS NOT NULL AND rubric_version IS NOT NULL
        ELSE profile='guardrail.1' AND model IS NULL AND rubric_version IS NULL END);

ALTER TABLE inline_guardrail_assessments
    ADD COLUMN profile text,
    ALTER COLUMN model DROP NOT NULL,
    ALTER COLUMN rubric_version DROP NOT NULL,
    ADD CHECK (CASE WHEN profile IS NULL THEN model IS NOT NULL AND rubric_version IS NOT NULL
        ELSE profile='guardrail.1' AND model IS NULL AND rubric_version IS NULL END);

CREATE OR REPLACE FUNCTION guardrail_sync_assessment() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO inline_guardrail_assessments
        (guardrail_event_id,generation,tenant_id,prepared_state,model,rubric_version,status,
         assessment,claim_token,deadline_at,started_at,completed_at,context_enabled,
         context_pinned,knowledge_snapshot,context_revision,scope_key,scope_version,company_policy,profile)
    VALUES(NEW.id,NEW.assessment_generation,NEW.tenant_id,NEW.prepared_state,NEW.model,
           NEW.rubric_version,NEW.status,NEW.assessment,NEW.claim_token,NEW.deadline_at,
           NEW.started_at,NEW.completed_at,NEW.context_enabled,NEW.context_pinned,
           NEW.knowledge_snapshot,NEW.context_revision,NEW.scope_key,NEW.scope_version,NEW.company_policy,NEW.profile)
    ON CONFLICT(guardrail_event_id,generation) DO UPDATE SET
        prepared_state=EXCLUDED.prepared_state,model=EXCLUDED.model,rubric_version=EXCLUDED.rubric_version,
        status=EXCLUDED.status,assessment=EXCLUDED.assessment,claim_token=EXCLUDED.claim_token,
        deadline_at=EXCLUDED.deadline_at,started_at=EXCLUDED.started_at,completed_at=EXCLUDED.completed_at,
        context_enabled=EXCLUDED.context_enabled,context_pinned=EXCLUDED.context_pinned,
        knowledge_snapshot=EXCLUDED.knowledge_snapshot,context_revision=EXCLUDED.context_revision,
        scope_key=EXCLUDED.scope_key,scope_version=EXCLUDED.scope_version,company_policy=EXCLUDED.company_policy,profile=EXCLUDED.profile
    WHERE inline_guardrail_assessments.status='pending';
    RETURN NEW;
END;
$$;

CREATE FUNCTION preserve_inline_profile() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.profile IS DISTINCT FROM OLD.profile THEN
        RAISE EXCEPTION 'assessment profile is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER inline_profile_guard BEFORE UPDATE OF profile ON inline_guardrail_events
    FOR EACH ROW EXECUTE FUNCTION preserve_inline_profile();
CREATE TRIGGER inline_profile_guard BEFORE UPDATE OF profile ON inline_guardrail_assessments
    FOR EACH ROW EXECUTE FUNCTION preserve_inline_profile();
