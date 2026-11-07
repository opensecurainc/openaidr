-- POC questionnaire records moved from the public website into Admin.
-- The website still serves the form; Admin stores every response and invitation.
CREATE TABLE platform_questionnaire_versions (
    version text PRIMARY KEY,
    schema jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE platform_questionnaire_invitations (
    id uuid PRIMARY KEY,
    email text NOT NULL,
    token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX platform_questionnaire_invitations_created_idx
    ON platform_questionnaire_invitations(created_at DESC, id DESC);

CREATE TABLE platform_questionnaire_submissions (
    id uuid PRIMARY KEY,
    email text NOT NULL,
    source text NOT NULL CHECK (source IN ('account', 'invitation')),
    invitation_id uuid REFERENCES platform_questionnaire_invitations(id),
    version text NOT NULL REFERENCES platform_questionnaire_versions(version),
    answers jsonb NOT NULL,
    effective_answers jsonb NOT NULL,
    owner_scope text NOT NULL,
    request_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (owner_scope, request_id),
    CHECK ((source = 'invitation') = (invitation_id IS NOT NULL))
);
CREATE INDEX platform_questionnaire_submissions_created_idx
    ON platform_questionnaire_submissions(created_at DESC, id DESC);
CREATE INDEX platform_questionnaire_submissions_email_idx
    ON platform_questionnaire_submissions(email, created_at DESC);

-- Set once, when Admin verified it holds exactly the website's records; opens Admin.
CREATE TABLE platform_questionnaire_cutover (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    counts jsonb NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$')
);
