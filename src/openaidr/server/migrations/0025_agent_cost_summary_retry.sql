ALTER TABLE agent_cost_dirty_hours
    ADD COLUMN retry_after timestamptz NOT NULL DEFAULT '-infinity';
