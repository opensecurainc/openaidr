-- Archived environments stay as audit and approval records but leave the active
-- console list. Archiving sets desired_state='deleted' so no worker can claim
-- their jobs; it never deletes cloud resources.
ALTER TABLE cloud_deployments
    ADD COLUMN archived_at timestamptz,
    ADD COLUMN archived_by uuid,
    ADD CONSTRAINT cloud_deployments_archive_actor_check CHECK ((archived_at IS NULL) = (archived_by IS NULL)),
    ADD CONSTRAINT cloud_deployments_archive_state_check CHECK (archived_at IS NULL OR desired_state = 'deleted');
