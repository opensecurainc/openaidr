ALTER TABLE ordinary_hook_checks DROP CONSTRAINT ordinary_hook_checks_status_check;
ALTER TABLE ordinary_hook_checks DROP CONSTRAINT ordinary_hook_checks_check;
ALTER TABLE ordinary_hook_checks
    ADD COLUMN actions jsonb NOT NULL DEFAULT '[]',
    ADD COLUMN assessment jsonb,
    ADD COLUMN risk_settings jsonb NOT NULL DEFAULT '{}',
    ADD COLUMN deadline_at timestamptz,
    ADD COLUMN completed_at timestamptz,
    ADD CONSTRAINT ordinary_hook_checks_status_check
        CHECK (status IN ('pending', 'evaluated', 'unavailable')),
    ADD CONSTRAINT ordinary_hook_checks_check CHECK (
        (status IN ('pending', 'unavailable') AND evaluated_decision IS NULL AND returned_decision IS NULL)
        OR (status = 'evaluated' AND evaluated_decision IS NOT NULL AND returned_decision IS NOT NULL));

CREATE INDEX ordinary_hook_checks_session_idx
    ON ordinary_hook_checks(tenant_id,sensor_id,product,session_id,created_at DESC,id DESC);

CREATE INDEX events_hook_request_idx
    ON events(tenant_id,sensor_id,(body->'source'->>'hook_request_id'))
    WHERE body->'source'->>'hook_request_id' IS NOT NULL;

CREATE INDEX events_hook_check_idx
    ON events(tenant_id,sensor_id,(risk->>'hook_check_id'))
    WHERE risk->>'hook_check_id' IS NOT NULL;
