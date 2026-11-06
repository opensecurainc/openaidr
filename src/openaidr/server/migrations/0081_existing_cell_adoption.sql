-- An operator may record a verified existing cell without claiming a new VM was
-- provisioned. Adoption records are completed observations, never queued work.
ALTER TABLE deployment_jobs DROP CONSTRAINT deployment_jobs_operation_check;
ALTER TABLE deployment_jobs ADD CONSTRAINT deployment_jobs_operation_check
    CHECK (operation IN ('provision', 'suspend', 'resume', 'release', 'adopt'));
ALTER TABLE deployment_jobs ADD CONSTRAINT deployment_jobs_adopt_completed_check
    CHECK (operation <> 'adopt' OR (state = 'succeeded' AND completed_at IS NOT NULL
        AND lease_owner IS NULL AND lease_expires_at IS NULL));
