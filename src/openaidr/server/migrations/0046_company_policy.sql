CREATE TABLE tenant_company_policies (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    prompt text NOT NULL DEFAULT '' CHECK (char_length(prompt) <= 10000),
    updated_at timestamptz
);

ALTER TABLE inline_guardrail_events
    ADD COLUMN company_policy jsonb NOT NULL DEFAULT '{"revision":0,"prompt":""}';
ALTER TABLE inline_guardrail_assessments
    ADD COLUMN company_policy jsonb NOT NULL DEFAULT '{"revision":0,"prompt":""}';

CREATE OR REPLACE FUNCTION guardrail_sync_assessment() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO inline_guardrail_assessments
        (guardrail_event_id,generation,tenant_id,prepared_state,model,rubric_version,status,
         assessment,claim_token,deadline_at,started_at,completed_at,context_enabled,
         context_pinned,knowledge_snapshot,context_revision,scope_key,scope_version,company_policy)
    VALUES(NEW.id,NEW.assessment_generation,NEW.tenant_id,NEW.prepared_state,NEW.model,
           NEW.rubric_version,NEW.status,NEW.assessment,NEW.claim_token,NEW.deadline_at,
           NEW.started_at,NEW.completed_at,NEW.context_enabled,NEW.context_pinned,
           NEW.knowledge_snapshot,NEW.context_revision,NEW.scope_key,NEW.scope_version,NEW.company_policy)
    ON CONFLICT(guardrail_event_id,generation) DO UPDATE SET
        prepared_state=EXCLUDED.prepared_state,model=EXCLUDED.model,rubric_version=EXCLUDED.rubric_version,
        status=EXCLUDED.status,assessment=EXCLUDED.assessment,claim_token=EXCLUDED.claim_token,
        deadline_at=EXCLUDED.deadline_at,started_at=EXCLUDED.started_at,completed_at=EXCLUDED.completed_at,
        context_enabled=EXCLUDED.context_enabled,context_pinned=EXCLUDED.context_pinned,
        knowledge_snapshot=EXCLUDED.knowledge_snapshot,context_revision=EXCLUDED.context_revision,
        scope_key=EXCLUDED.scope_key,scope_version=EXCLUDED.scope_version,company_policy=EXCLUDED.company_policy
    WHERE inline_guardrail_assessments.status='pending';
    RETURN NEW;
END;
$$;
