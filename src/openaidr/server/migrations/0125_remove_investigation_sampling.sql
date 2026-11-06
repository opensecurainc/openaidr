-- Retain the field for older clients and historical job configurations.
ALTER TABLE tenant_session_detection_settings ALTER COLUMN sample_percent SET DEFAULT 0;
UPDATE tenant_session_detection_settings
SET sample_percent=0,version=version+1,updated_at=clock_timestamp()
WHERE sample_percent<>0;
ALTER TABLE tenant_session_detection_settings
    ADD CONSTRAINT investigation_sampling_removed CHECK (sample_percent=0);

-- Preserve case and report history while retiring work selected only by sampling.
-- Rebuild affected snapshots so eligible risk work cannot conflict with a retired job.
INSERT INTO session_input_dirty(registration_id)
SELECT DISTINCT registration_id FROM session_investigation_jobs
WHERE routing_reason='sample' AND state='queued' AND registration_id IS NOT NULL;
INSERT INTO ordinary_session_input_dirty(tenant_id,session_id)
SELECT DISTINCT tenant_id,session_id FROM session_investigation_jobs
WHERE routing_reason='sample' AND state='queued' AND registration_id IS NULL;
UPDATE session_investigation_jobs SET state='superseded',completed_at=clock_timestamp()
WHERE routing_reason='sample' AND state='queued';
