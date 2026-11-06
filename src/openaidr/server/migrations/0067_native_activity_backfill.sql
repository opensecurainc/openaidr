-- Scan retained history once, after the preceding migration releases DDL locks.
-- Concurrent inserts already maintain the flags through events_native_activity.
CREATE TEMP TABLE native_activity_backfill ON COMMIT DROP AS
    SELECT DISTINCT tenant_id,agent_id,session_id FROM events
    WHERE kind<>'sensor' AND (agent_id IS NOT NULL OR session_id IS NOT NULL);

-- Drain live inventory writers before taking any row locks. A batch can touch
-- multiple agents in any order; interleaving its row locks with ours can deadlock.
-- Keep the history scan above outside this write pause. Reads remain available.
LOCK TABLE agents IN SHARE ROW EXCLUSIVE MODE;

UPDATE agents a SET has_native_activity=true
    FROM (SELECT DISTINCT tenant_id,agent_id FROM native_activity_backfill) h
    WHERE a.id=h.agent_id AND a.tenant_id=h.tenant_id AND NOT a.has_native_activity;
UPDATE agent_sessions s SET has_native_activity=true
    FROM (SELECT DISTINCT tenant_id,session_id FROM native_activity_backfill) h
    WHERE s.id=h.session_id AND s.tenant_id=h.tenant_id AND NOT s.has_native_activity;
