ALTER TABLE application_classifications
    ADD COLUMN assessment jsonb,
    ADD COLUMN assessment_checked_at timestamptz;

-- Preserve classifications and approvals during bounded capability enrichment.
-- Revoke old leases so pre-upgrade responses cannot finish the new research job.
UPDATE application_classifications SET next_attempt_at=clock_timestamp(),
    claim_token=NULL,lease_until=NULL;
