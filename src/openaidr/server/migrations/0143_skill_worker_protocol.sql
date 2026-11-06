ALTER TABLE skill_bundles ADD COLUMN worker_protocol text NOT NULL DEFAULT 'skills-assess-v1'
    CHECK (worker_protocol IN ('skills-assess-v1','skills-service-v1'));
