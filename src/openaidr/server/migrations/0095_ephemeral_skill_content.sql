-- Preserve hashes, manifests, reports, and installation identities only.
UPDATE skill_bundles SET files=NULL,
    status=CASE WHEN status IN ('queued','running') THEN 'awaiting_upload' ELSE status END,
    lease_id=NULL,lease_until=NULL;
ALTER TABLE skill_bundles DROP COLUMN files;
