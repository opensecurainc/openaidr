"""Local request provenance and reversible recovery from retained agent history."""

from openaidr.core.agent_usage import text, token


def initialize(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS usage_sources (
            event_key TEXT PRIMARY KEY, application TEXT NOT NULL,
            kind TEXT NOT NULL, happened_at REAL NOT NULL
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS usage_sources_application ON usage_sources(application,kind);
        CREATE TABLE IF NOT EXISTS usage_recovered (
            event_key TEXT PRIMARY KEY, application TEXT NOT NULL, happened_at REAL NOT NULL,
            model TEXT NOT NULL, effort TEXT NOT NULL, tokens INTEGER NOT NULL,
            cached_input_tokens INTEGER NOT NULL, uncached_input_tokens INTEGER NOT NULL,
            output_tokens INTEGER NOT NULL, cost_usd REAL, service_tier TEXT NOT NULL
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS usage_recovered_application ON usage_recovered(application);
        CREATE TABLE IF NOT EXISTS usage_recovery_state (
            application TEXT PRIMARY KEY, revision INTEGER NOT NULL
        ) WITHOUT ROWID;
        CREATE TRIGGER IF NOT EXISTS usage_recovered_call_update AFTER UPDATE ON usage_calls
        WHEN new.rowid=(SELECT min(rowid) FROM usage_calls WHERE event_key=new.event_key)
        BEGIN
            UPDATE usage_recovered SET happened_at=new.happened_at,model=new.model,
                effort=new.effort,tokens=new.tokens,cost_usd=new.cost_usd
                WHERE event_key=new.event_key;
            UPDATE usage_sources SET happened_at=new.happened_at WHERE event_key=new.event_key;
        END;
        CREATE TRIGGER IF NOT EXISTS usage_recovered_tokens_update AFTER UPDATE ON usage_tokens
        WHEN new.scope=(SELECT scope FROM usage_calls WHERE event_key=new.event_key ORDER BY rowid LIMIT 1)
        BEGIN
            UPDATE usage_recovered SET cached_input_tokens=new.cached_input_tokens,
                uncached_input_tokens=new.uncached_input_tokens,output_tokens=new.output_tokens
                WHERE event_key=new.event_key;
        END;
        CREATE TRIGGER IF NOT EXISTS usage_recovered_tokens_insert AFTER INSERT ON usage_tokens
        WHEN new.scope=(SELECT scope FROM usage_calls WHERE event_key=new.event_key ORDER BY rowid LIMIT 1)
        BEGIN
            UPDATE usage_recovered SET cached_input_tokens=new.cached_input_tokens,
                uncached_input_tokens=new.uncached_input_tokens,output_tokens=new.output_tokens
                WHERE event_key=new.event_key;
        END;
    """)


def generation(db, application):
    row = db.execute("SELECT revision FROM usage_recovery_state WHERE application=?", (application,)).fetchone()
    return row[0] if row else 0


def prove(db, application, keys):
    """An exact request key can identify otherwise unattributed legacy native usage."""
    keys = list(dict.fromkeys(key for key in keys if not key.startswith("history:")))
    for start in range(0, len(keys), 400):
        batch = keys[start:start + 400]
        placeholders = ",".join("?" for _ in batch)
        rows = db.execute(f"""SELECT u.event_key,min(u.happened_at) FROM usage_calls u
            LEFT JOIN usage_apps a USING(scope,event_key)
            WHERE u.event_key IN ({placeholders}) AND (a.application=? OR a.application IS NULL)
            GROUP BY u.event_key UNION ALL
            SELECT event_key,happened_at FROM usage_compacted WHERE event_key IN ({placeholders})""",
            (*batch, application, *batch)).fetchall()
        db.executemany("""INSERT INTO usage_sources VALUES (?,?,'native',?)
            ON CONFLICT(event_key) DO UPDATE SET kind='native'
            WHERE usage_sources.kind='native_unknown' AND usage_sources.application=excluded.application""",
            [(key, application, when) for key, when in rows])


def allowed(db, application):
    """Unmatched native identities cannot safely be added beside transcript usage."""
    from . import usage

    cutoff = usage.local_start(usage.datetime.now(usage.timezone.utc), 30).timestamp()
    return not (
        db.execute("""SELECT 1 FROM usage_sources WHERE application=? AND kind='native_unknown'
            AND happened_at>=? LIMIT 1""", (application, cutoff)).fetchone()
        or db.execute("""SELECT 1 FROM usage_calls u LEFT JOIN usage_sources s USING(event_key)
            LEFT JOIN usage_apps a USING(scope,event_key)
            WHERE u.event_key NOT LIKE 'history:%' AND s.event_key IS NULL
            AND (a.application=? OR a.application IS NULL) AND u.happened_at>=? LIMIT 1""",
            (application, cutoff)).fetchone()
        or db.execute("""SELECT 1 FROM usage_compacted c LEFT JOIN usage_sources s USING(event_key)
            WHERE c.event_key NOT LIKE 'history:%' AND s.event_key IS NULL AND c.happened_at>=? LIMIT 1""",
            (cutoff,)).fetchone()
    )


def reconcile(db, scope):
    """An older writer may have accepted ambiguous native usage while downgraded."""
    for (application,) in db.execute("SELECT DISTINCT application FROM usage_recovered").fetchall():
        if not allowed(db, application):
            _withdraw(db, scope, application=application)


def recover(db, scope, application, events):
    """Insert exact-ID history in the caller's write transaction; None means blocked."""
    from . import usage

    prove(db, application, [event["key"] for event in events])
    permitted = allowed(db, application)
    added = 0
    for event in events:
        key = event["key"]
        previous = db.execute("SELECT kind FROM usage_sources WHERE event_key=?", (key,)).fetchone()
        if not permitted and (previous is None or previous[0] != "legacy"):
            continue
        if previous:
            receipt = db.execute("SELECT * FROM usage_recovered WHERE event_key=?", (key,)).fetchone()
            if previous[0] == "legacy" and receipt is not None:
                event = dict(event, time=usage.datetime.fromtimestamp(receipt["happened_at"], usage.timezone.utc))
            counts = event["usage"]
            if previous[0] not in {"recovered", "legacy"} or receipt is None or not (
                counts["tokens"] > receipt["tokens"] or (
                    receipt["cost_usd"] is None and counts["cost"] is not None and (
                        event["time"].timestamp(), event["model"], event["reasoning_effort"], counts["tokens"],
                        counts["cache_read_tokens"], counts["input_tokens"] + counts["cache_write_tokens"],
                        counts["output_tokens"], text(event.get("attributes", {}), "service_tier")
                    ) == (receipt["happened_at"], receipt["model"], receipt["effort"], receipt["tokens"],
                          receipt["cached_input_tokens"], receipt["uncached_input_tokens"],
                          receipt["output_tokens"], receipt["service_tier"])
                )
            ):
                continue
            _withdraw(db, scope, key=key)
        usage.record_calls(db, scope, [event])
        row = db.execute("""SELECT u.happened_at,u.model,u.effort,u.tokens,
            t.cached_input_tokens,t.uncached_input_tokens,t.output_tokens,u.cost_usd
            FROM usage_calls u JOIN usage_tokens t USING(scope,event_key)
            WHERE u.event_key=? ORDER BY u.rowid LIMIT 1""", (key,)).fetchone()
        if row is None:
            continue
        db.execute("INSERT INTO usage_sources VALUES (?,?,?,?)", (key, application, previous[0] if previous else "recovered", row[0]))
        db.execute("INSERT INTO usage_recovered VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (key, application, *row, text(event.get("attributes", {}), "service_tier")))
        added += previous is None
    return added if permitted else None


def _withdraw(db, scope, *, application=None, key=None):
    """Remove only recovered contributions, including those already compacted."""
    from . import usage

    db.execute("CREATE TEMP TABLE IF NOT EXISTS usage_recovery_remove (event_key TEXT PRIMARY KEY)")
    db.execute("DELETE FROM usage_recovery_remove")
    field, value = ("application", application) if application is not None else ("event_key", key)
    db.execute(f"INSERT INTO usage_recovery_remove SELECT event_key FROM usage_recovered WHERE {field}=?"
               + (" AND event_key IN (SELECT event_key FROM usage_sources WHERE kind='recovered')" if application is not None else ""), (value,))
    count, latest = db.execute("""SELECT count(*),max(happened_at) FROM usage_recovered
        WHERE event_key IN (SELECT event_key FROM usage_recovery_remove)""").fetchone()
    if not count:
        return
    groups = db.execute(f"""SELECT CAST(r.happened_at/{usage.ROLLUP_SECONDS} AS INTEGER)*{usage.ROLLUP_SECONDS},
        r.model,r.effort,r.application,count(*),count(r.cost_usd),sum(r.tokens),
        sum(r.cached_input_tokens),sum(r.uncached_input_tokens),sum(r.output_tokens),sum(r.cost_usd)
        FROM usage_recovered r JOIN usage_compacted USING(event_key)
        WHERE r.event_key IN (SELECT event_key FROM usage_recovery_remove) GROUP BY 1,2,3,4""").fetchall()
    for bucket, model, effort, app, calls, priced, tokens, cached, incoming, outgoing, cost in groups:
        db.execute("""UPDATE usage_rollups SET calls=calls-?,priced_calls=priced_calls-?,tokens=tokens-?,
            cached_input_tokens=cached_input_tokens-?,uncached_input_tokens=uncached_input_tokens-?,
            output_tokens=output_tokens-?,cost_usd=CASE WHEN priced_calls-?=0 THEN NULL ELSE cost_usd-? END
            WHERE bucket=? AND model=? AND effort=? AND application=?""",
            (calls, priced, tokens, cached, incoming, outgoing, priced, cost or 0, bucket, model, effort, app))
        db.execute("DELETE FROM usage_rollups WHERE bucket=? AND model=? AND effort=? AND application=? AND calls=0",
                   (bucket, model, effort, app))
    # Compacted corrections do not fire detail triggers, so invalidate their cached hours too.
    db.execute("""INSERT INTO usage_revisions SELECT ?,CAST(r.happened_at/3600 AS INTEGER),1
        FROM usage_recovered r WHERE event_key IN (SELECT event_key FROM usage_recovery_remove) GROUP BY 2
        ON CONFLICT(scope,bucket) DO UPDATE SET revision=revision+1""", (scope,))
    for table in ("usage_calls", "usage_compacted", "usage_sources", "usage_recovered"):
        db.execute(f"DELETE FROM {table} WHERE event_key IN (SELECT event_key FROM usage_recovery_remove)")
    if application is not None:
        db.execute("""INSERT INTO usage_recovery_state VALUES (?,1)
            ON CONFLICT(application) DO UPDATE SET revision=revision+1""", (application,))
        db.execute("UPDATE usage_history SET truncated_at=max(coalesce(truncated_at,?),?)", (latest, latest))


def _valid_tokens(event):
    attrs = event["attributes"]
    incoming = token(attrs, "input_token_count", "input_tokens")
    outgoing = token(attrs, "output_token_count", "output_tokens")
    cached = token(attrs, "cached_token_count", "cache_read_tokens", optional=True)
    written = token(attrs, "cache_write_token_count", "cache_creation_tokens", optional=True)
    return None not in (incoming, outgoing, cached, written) and (
        not event["name"].startswith("codex.") or cached + written <= incoming)


def _canonical(event):
    attrs = event["attributes"]
    selected = text(attrs, "request_id", "response_id", "gen_ai.response.id")
    application = event["name"].split(".")[0]
    if application == "codex":
        response_ids = {text(attrs, field) for field in ("response_id", "gen_ai.response.id")} - {""}
        return len(response_ids) == 1 and selected in response_ids
    if application == "claude_code":
        return bool(text(attrs, "request_id"))
    return bool(selected) or event["name"] == "cursor.api_request"


def native(db, scope, events):
    """Prepare native records and remove recovered equivalents before native insertion."""
    from . import usage

    keys = list(dict.fromkeys(event["key"] for event in events))
    receipts = {}
    proven = set()
    for start in range(0, len(keys), 400):
        batch = keys[start:start + 400]
        receipts.update((row["event_key"], row) for row in db.execute(
            f"SELECT * FROM usage_recovered WHERE event_key IN ({','.join('?' for _ in batch)})", batch))
        proven.update(row[0] for row in db.execute(
            f"SELECT event_key FROM usage_sources WHERE kind IN ('native','recovered','legacy') "
            f"AND event_key IN ({','.join('?' for _ in batch)})", batch))
    proven.update(event["key"] for event in events if _canonical(event))
    cutoff = usage.local_start(usage.datetime.now(usage.timezone.utc), 30).timestamp()
    unknown = {event["name"].split(".")[0] for event in events
               if not _canonical(event) and event["key"] not in proven and event["time"].timestamp() >= cutoff}
    for application in unknown:
        _withdraw(db, scope, application=application)
    for event in events:
        key, application = event["key"], event["name"].split(".")[0]
        receipt = receipts.get(key)
        if receipt:
            counts = dict(event["usage"])
            if not _valid_tokens(event):
                counts.update(tokens=receipt["tokens"], cache_read_tokens=receipt["cached_input_tokens"],
                              input_tokens=receipt["uncached_input_tokens"], cache_write_tokens=0,
                              output_tokens=receipt["output_tokens"])
            if event["model"] == "Unattributed":
                event["model"] = receipt["model"]
            if event["reasoning_effort"] == "unknown":
                event["reasoning_effort"] = receipt["effort"]
            if counts["cost"] is None and (
                event["model"], counts["tokens"], counts["cache_read_tokens"],
                counts["input_tokens"] + counts["cache_write_tokens"], counts["output_tokens"],
                text(event["attributes"], "service_tier")
            ) == (receipt["model"], receipt["tokens"], receipt["cached_input_tokens"],
                  receipt["uncached_input_tokens"], receipt["output_tokens"], receipt["service_tier"]):
                counts["cost"] = receipt["cost_usd"]
            event["usage"] = counts
            _withdraw(db, scope, key=key)
        when = db.execute("SELECT happened_at FROM usage_calls WHERE event_key=? ORDER BY rowid LIMIT 1",
                          (key,)).fetchone() or db.execute(
                              "SELECT happened_at FROM usage_compacted WHERE event_key=?", (key,)).fetchone()
        db.execute("""INSERT INTO usage_sources VALUES (?,?,?,?) ON CONFLICT(event_key)
            DO UPDATE SET kind='native' WHERE usage_sources.kind='native_unknown' AND excluded.kind='native'""",
                   (key, application, "native" if _canonical(event) or key in proven else "native_unknown",
                    when[0] if when else event["time"].timestamp()))


def prune(db, cutoff):
    db.execute("DELETE FROM usage_recovered WHERE happened_at<?", (cutoff,))
    db.execute("DELETE FROM usage_sources WHERE happened_at<?", (cutoff,))
