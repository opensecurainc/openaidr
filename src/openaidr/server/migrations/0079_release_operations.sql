-- One release operation supports forward deployment and rollback alike.
ALTER TABLE deployment_jobs DROP CONSTRAINT deployment_jobs_operation_check;
ALTER TABLE deployment_jobs ADD CONSTRAINT deployment_jobs_operation_check
    CHECK (operation IN ('provision', 'suspend', 'resume', 'release'));
