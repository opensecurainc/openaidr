CREATE TABLE ordinary_hook_reviews (
    check_id uuid PRIMARY KEY REFERENCES ordinary_hook_checks(id) ON DELETE CASCADE,
    label text NOT NULL CHECK (label IN ('correct_denial', 'false_positive')),
    note text NOT NULL DEFAULT '' CHECK (length(note) <= 2000),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX ordinary_hook_checks_device_denials_idx
    ON ordinary_hook_checks(tenant_id, sensor_id, created_at DESC, id DESC)
    WHERE status = 'evaluated' AND evaluated_decision = 'deny';
