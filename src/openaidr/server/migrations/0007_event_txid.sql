-- The top-level transaction that inserted each event. `received_at` is
-- stamped at insert, so a transaction can commit after a later-stamped one;
-- live views record the transactions still in progress when they read and
-- later fetch exactly those transactions' rows (Store.live_events).
-- pg_current_xact_id() is the top-level id even inside a savepoint. The
-- default is set separately so existing rows are not rewritten; they stay
-- NULL and are never pending.
ALTER TABLE events ADD COLUMN txid bigint;
ALTER TABLE events ALTER COLUMN txid SET DEFAULT (pg_current_xact_id()::text::bigint);
CREATE INDEX events_tenant_txid_idx ON events (tenant_id, txid) WHERE txid IS NOT NULL;
