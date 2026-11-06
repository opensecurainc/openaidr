ALTER TABLE application_classifications
    ADD COLUMN software_type text CHECK (software_type IN
        ('application','command_line_tool','library','helper','system_component')),
    ADD COLUMN display_name text NOT NULL DEFAULT '';

-- Enrich existing results without clearing their classification or changing the
-- evidence hash used by older API builds. The normal worker bounds the refresh.
UPDATE application_classifications SET next_attempt_at=clock_timestamp(),
    claim_token=NULL,lease_until=NULL;
