-- Retain every existing job and checkpoint. Old workers claim provision only.
ALTER TABLE deployment_jobs DROP CONSTRAINT deployment_jobs_operation_check;
ALTER TABLE deployment_jobs ADD CONSTRAINT deployment_jobs_operation_check
    CHECK (operation IN ('provision', 'suspend', 'resume'));
