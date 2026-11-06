ALTER TABLE tenant_slack_settings
    ADD COLUMN disk_alerts jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE slack_outbox SET status='cancelled'
WHERE status='pending' AND (event_key LIKE 'finding:%' OR event_key LIKE 'report:%'
    OR event_key LIKE 'batch:%' OR event_key LIKE 'digest:%');
