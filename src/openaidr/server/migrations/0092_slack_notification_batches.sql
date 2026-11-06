ALTER TABLE slack_outbox
    DROP CONSTRAINT slack_outbox_status_check,
    ADD CONSTRAINT slack_outbox_status_check
        CHECK (status IN ('pending','sent','failed','cancelled','grouped','suppressed')),
    ADD COLUMN batch_id uuid REFERENCES slack_outbox(id) ON DELETE CASCADE;

CREATE INDEX slack_outbox_batch_idx ON slack_outbox(tenant_id,batch_id)
    WHERE batch_id IS NOT NULL;
