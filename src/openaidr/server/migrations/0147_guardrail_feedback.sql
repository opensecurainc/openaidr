ALTER TABLE ordinary_hook_checks
    ADD COLUMN assessment_input jsonb,
    ADD COLUMN assessment_input_sha256 text,
    ADD COLUMN assessment_context jsonb;

CREATE TABLE ordinary_hook_review_evidence (
    check_id uuid NOT NULL REFERENCES ordinary_hook_checks(id) ON DELETE CASCADE,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    evidence jsonb NOT NULL,
    PRIMARY KEY (check_id, sha256)
);

CREATE TABLE ordinary_hook_review_revisions (
    check_id uuid NOT NULL REFERENCES ordinary_hook_checks(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    label text NOT NULL CHECK (label IN ('correct_denial', 'false_positive', 'insufficient_context')),
    note text NOT NULL DEFAULT '' CHECK (length(note) <= 2000),
    reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    source_id uuid NOT NULL,
    request_id uuid,
    evidence_sha256 text,
    PRIMARY KEY (check_id, revision),
    UNIQUE (check_id, request_id),
    FOREIGN KEY (check_id, evidence_sha256)
        REFERENCES ordinary_hook_review_evidence(check_id, sha256) ON DELETE CASCADE
);

INSERT INTO ordinary_hook_review_revisions(check_id,revision,label,note,reviewed_at,source_id)
    SELECT r.check_id,1,r.label,r.note,r.updated_at,c.sensor_id
    FROM ordinary_hook_reviews r JOIN ordinary_hook_checks c ON c.id=r.check_id;

ALTER TABLE ordinary_hook_reviews
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    DROP CONSTRAINT ordinary_hook_reviews_label_check,
    ADD CONSTRAINT ordinary_hook_reviews_label_check
        CHECK (label IN ('correct_denial', 'false_positive', 'insufficient_context'));

CREATE FUNCTION preserve_guardrail_feedback() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'guardrail feedback evidence and revisions are immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER ordinary_hook_review_evidence_immutable BEFORE UPDATE ON ordinary_hook_review_evidence
    FOR EACH ROW EXECUTE FUNCTION preserve_guardrail_feedback();
CREATE TRIGGER ordinary_hook_review_revisions_immutable BEFORE UPDATE ON ordinary_hook_review_revisions
    FOR EACH ROW EXECUTE FUNCTION preserve_guardrail_feedback();

CREATE TRIGGER ordinary_hook_assessment_input_immutable BEFORE UPDATE ON ordinary_hook_checks
    FOR EACH ROW WHEN (OLD.assessment_input IS NOT NULL AND
        (OLD.assessment_input,OLD.assessment_input_sha256,OLD.assessment_context) IS DISTINCT FROM
        (NEW.assessment_input,NEW.assessment_input_sha256,NEW.assessment_context))
    EXECUTE FUNCTION preserve_guardrail_feedback();
