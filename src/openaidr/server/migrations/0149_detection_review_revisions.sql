CREATE TABLE risk_case_review_revisions (
    case_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    case_version bigint NOT NULL CHECK (case_version > 0),
    outcome text NOT NULL CHECK (outcome IN ('review','tp','fp')),
    reviewer_id uuid NOT NULL,
    reviewer_name text NOT NULL,
    reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    review_context jsonb,
    completeness text[] NOT NULL,
    PRIMARY KEY(case_id,revision),
    FOREIGN KEY(case_id,tenant_id) REFERENCES risk_cases(id,tenant_id) ON DELETE CASCADE
);

CREATE INDEX risk_case_review_revisions_tenant_idx
    ON risk_case_review_revisions(tenant_id,reviewed_at,case_id,revision);

CREATE FUNCTION preserve_risk_case_review_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'case review revisions are immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER risk_case_review_revision_guard BEFORE UPDATE ON risk_case_review_revisions
    FOR EACH ROW EXECUTE FUNCTION preserve_risk_case_review_revision();
