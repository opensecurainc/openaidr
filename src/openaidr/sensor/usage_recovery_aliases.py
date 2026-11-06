"""Exact transcript links preserve historical calls across the legacy cutoff."""

from datetime import datetime, timezone

from . import usage, usage_recovery


def initialize(db):
    db.execute("""CREATE TABLE IF NOT EXISTS usage_request_aliases (
        event_key TEXT NOT NULL,legacy_key TEXT NOT NULL,happened_at REAL NOT NULL,
        partial INTEGER NOT NULL,PRIMARY KEY(event_key,legacy_key)
    ) WITHOUT ROWID""")


def bind(db, scope, application, item, legacy_key, *, partial=False):
    """Bind only a request and legacy record linked by the source's exact identity."""
    key = item["key"]
    if not legacy_key.startswith("history:") or key.startswith("history:"):
        raise ValueError("invalid history alias")
    previous = db.execute("SELECT partial FROM usage_request_aliases WHERE event_key=? AND legacy_key=?",
                          (key, legacy_key)).fetchone()
    if previous:
        return True
    old = db.execute("""SELECT u.scope,u.happened_at,u.model,u.effort,u.tokens,u.cost_usd,
        t.cached_input_tokens,t.uncached_input_tokens,t.output_tokens
        FROM usage_calls u JOIN usage_tokens t USING(scope,event_key)
        JOIN usage_apps a USING(scope,event_key) WHERE u.event_key=? AND a.application=?
        ORDER BY u.rowid LIMIT 1""", (legacy_key, application)).fetchone()
    compacted = db.execute("SELECT happened_at FROM usage_compacted WHERE event_key=?", (legacy_key,)).fetchone()
    if old is None and compacted is None:
        return False
    provisional = db.execute("SELECT 1 FROM usage_sources WHERE event_key=? AND kind='recovered'", (key,)).fetchone()
    if provisional:
        usage_recovery._withdraw(db, scope, key=key)
    native = db.execute("SELECT 1 FROM usage_calls WHERE event_key=?", (key,)).fetchone()
    native = native or db.execute("SELECT 1 FROM usage_compacted WHERE event_key=?", (key,)).fetchone()
    when = old["happened_at"] if old else compacted[0]
    if old and not partial:
        if not native:
            preserved = dict(key=key, time=datetime.fromtimestamp(when, timezone.utc),
                        name=application + ".api_request", model=old["model"], reasoning_effort=old["effort"],
                        usage=dict(tokens=old["tokens"], cost=old["cost_usd"], cache_read_tokens=old["cached_input_tokens"],
                                   input_tokens=old["uncached_input_tokens"], cache_write_tokens=0,
                                   output_tokens=old["output_tokens"]))
            usage.record_calls(db, old["scope"], [preserved])
            db.execute("INSERT INTO usage_sources VALUES (?,?,'legacy',?)", (key, application, when))
            db.execute("INSERT INTO usage_recovered VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       (key, application, when, old["model"], old["effort"], old["tokens"],
                        old["cached_input_tokens"], old["uncached_input_tokens"], old["output_tokens"], old["cost_usd"],
                        item.get("attributes", {}).get("service_tier", "")))
        db.execute("DELETE FROM usage_calls WHERE event_key=?", (legacy_key,))
        db.execute("INSERT OR IGNORE INTO usage_compacted VALUES (?,?)", (legacy_key, when))
    elif not native:
        # The old rollup no longer has the individual price. Keep its counted
        # contribution and suppress the canonical replay without inventing it.
        db.execute("INSERT OR IGNORE INTO usage_compacted VALUES (?,?)", (key, when))
        db.execute("INSERT OR IGNORE INTO usage_sources VALUES (?,?,'legacy',?)", (key, application, when))
    db.execute("INSERT INTO usage_request_aliases VALUES (?,?,?,?)", (key, legacy_key, when, int(partial or old is None)))
    return True
