"""Private, bounded usage metadata retained after raw exports are delivered."""

from collections import defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import time

from openaidr.core.reasoning import EFFORTS


MAX_RECORDS = 100_000
STORAGE_ALLOWANCE = 256 << 20
PROJECTION_VERSION = 9
# Quarter-hour slices keep local midnight exact in fractional-offset timezones,
# including when the device changes timezone after details have been compacted.
ROLLUP_SECONDS = 15 * 60
COUNTERS = ("calls", "priced_calls", "tokens", "cached_input_tokens",
            "uncached_input_tokens", "output_tokens", "unclassified_tokens")


def identity(config):
    return hashlib.sha256(json.dumps([
        config.get("server_url", "").rstrip("/"),
        config.get("tenant_id", ""), config.get("sensor_id", ""),
    ]).encode()).hexdigest()


def local_identity(config):
    # Keep one accounting identity for this local ledger across reconnects.
    # Existing event keys include this value, so retain the original identity.
    path = Path(config["data_dir"]) / "telemetry.sqlite3"
    if path.exists():
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='usage_history'").fetchone():
                first = db.execute("SELECT scope FROM usage_history ORDER BY rowid LIMIT 1").fetchone()
                if first:
                    return first[0]
    return identity(config)


def initialize(db, scope):
    from . import antigravity_usage, hook_estimates, usage_recovery
    antigravity_usage.initialize(db)
    hook_estimates.initialize(db)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS usage_calls (
            scope TEXT NOT NULL, event_key TEXT NOT NULL, happened_at REAL NOT NULL,
            model TEXT NOT NULL, effort TEXT NOT NULL, tokens INTEGER NOT NULL,
            cost_usd REAL, PRIMARY KEY (scope,event_key)
        );
        CREATE INDEX IF NOT EXISTS usage_time ON usage_calls(happened_at);
        CREATE INDEX IF NOT EXISTS usage_event ON usage_calls(event_key);
        CREATE TABLE IF NOT EXISTS usage_history (
            scope TEXT PRIMARY KEY, started_at REAL NOT NULL, truncated_at REAL
        );
        CREATE TABLE IF NOT EXISTS usage_imports (
            scope TEXT NOT NULL, application TEXT NOT NULL, cutoff REAL NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (scope,application)
        );
        CREATE TABLE IF NOT EXISTS usage_import_sources (
            scope TEXT NOT NULL, application TEXT NOT NULL, fingerprint TEXT NOT NULL,
            PRIMARY KEY (scope,application)
        );
        CREATE TABLE IF NOT EXISTS usage_tokens (
            scope TEXT NOT NULL, event_key TEXT NOT NULL,
            cached_input_tokens INTEGER NOT NULL, uncached_input_tokens INTEGER NOT NULL,
            output_tokens INTEGER NOT NULL, PRIMARY KEY (scope,event_key)
        );
        CREATE TRIGGER IF NOT EXISTS usage_tokens_prune AFTER DELETE ON usage_calls
        BEGIN
            DELETE FROM usage_tokens WHERE scope=old.scope AND event_key=old.event_key;
        END;
        CREATE TABLE IF NOT EXISTS usage_apps (
            scope TEXT NOT NULL, event_key TEXT NOT NULL,
            application TEXT NOT NULL, PRIMARY KEY (scope,event_key)
        );
        CREATE TRIGGER IF NOT EXISTS usage_apps_prune AFTER DELETE ON usage_calls
        BEGIN
            DELETE FROM usage_apps WHERE scope=old.scope AND event_key=old.event_key;
        END;
        CREATE TABLE IF NOT EXISTS usage_rollups (
            bucket INTEGER NOT NULL, model TEXT NOT NULL, effort TEXT NOT NULL,
            application TEXT NOT NULL, calls INTEGER NOT NULL, priced_calls INTEGER NOT NULL,
            tokens INTEGER NOT NULL, cached_input_tokens INTEGER NOT NULL,
            uncached_input_tokens INTEGER NOT NULL, output_tokens INTEGER NOT NULL,
            unclassified_tokens INTEGER NOT NULL, cost_usd REAL,
            PRIMARY KEY (bucket,model,effort,application)
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS usage_compacted (
            event_key TEXT PRIMARY KEY, happened_at REAL NOT NULL
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS usage_compacted_time ON usage_compacted(happened_at);
        CREATE TRIGGER IF NOT EXISTS usage_compacted_replay BEFORE INSERT ON usage_calls
        WHEN EXISTS (SELECT 1 FROM usage_compacted WHERE event_key=new.event_key)
        BEGIN SELECT RAISE(IGNORE); END;
    """)
    usage_recovery.initialize(db)
    # Triggers also invalidate cached hours when an older sensor writes the ledger.
    triggers = []
    for table in ("usage_calls", "usage_tokens", "usage_apps"):
        for operation, records in (("INSERT", ("new",)), ("DELETE", ("old",)), ("UPDATE", ("old", "new"))):
            updates = []
            for record in records:
                source = (f"SELECT {record}.scope,CAST({record}.happened_at/3600 AS INTEGER),1 WHERE true"
                          if table == "usage_calls" else
                          f"SELECT scope,CAST(happened_at/3600 AS INTEGER),1 FROM usage_calls "
                          f"WHERE scope={record}.scope AND event_key={record}.event_key")
                updates.append(f"INSERT INTO usage_revisions {source} "
                               "ON CONFLICT(scope,bucket) DO UPDATE SET revision=revision+1;")
            triggers.append(f"CREATE TRIGGER IF NOT EXISTS {table}_revision_{operation.lower()} "
                            f"AFTER {operation} ON {table} BEGIN {' '.join(updates)} END;")
    db.executescript("""BEGIN IMMEDIATE;
        CREATE INDEX IF NOT EXISTS usage_scope_time ON usage_calls(scope,happened_at);
        CREATE TABLE IF NOT EXISTS usage_revisions (
            scope TEXT NOT NULL, bucket INTEGER NOT NULL, revision INTEGER NOT NULL,
            PRIMARY KEY (scope,bucket)
        );
    """ + "\n".join(triggers) + "\nCOMMIT;")
    db.execute("INSERT OR IGNORE INTO usage_history(scope,started_at) VALUES (?,?)",
               (scope, datetime.now(timezone.utc).timestamp()))
    if "usage_projected" not in {row[1] for row in db.execute("PRAGMA table_info(exports)")}:
        db.execute("ALTER TABLE exports ADD COLUMN usage_projected INTEGER NOT NULL DEFAULT 0")
    usage_recovery.reconcile(db, scope)


def record(db, scope, export):
    """Called in the export transaction, including for queues from older sensors."""
    from openaidr.core.agent_usage import extract
    from openaidr.core.telemetry import decode_export

    if export["signal"] == "logs":
        from . import antigravity_usage, hook_estimates, usage_recovery
        received = datetime.fromtimestamp(export["created_at"], timezone.utc)
        decoded = dict(
            id=export["batch_id"], sensor_id=scope, received_at=received,
            payload=decode_export("logs", export["body"], export["content_type"]),
        )
        antigravity_usage.record(db, scope, decoded)
        hook_estimates.record(db, scope, decoded)
        events = [event for event in extract(decoded) if event["usage"] is not None and not event["demo"]]
        # Legacy history keeps its fixed boundary. Exact recovered request keys
        # can also accept a native correction across that boundary.
        cutoffs = dict(db.execute("SELECT application,min(cutoff) FROM usage_imports GROUP BY application"))
        events = [event for event in events if event["time"].timestamp() >= cutoffs.get(event["name"].split(".")[0], 0)
                  or db.execute("SELECT 1 FROM usage_recovered WHERE event_key=?", (event["key"],)).fetchone()]
        usage_recovery.native(db, scope, events)
        record_calls(db, scope, events)
    db.execute("UPDATE exports SET usage_projected=? WHERE batch_id=?",
               (PROJECTION_VERSION, export["batch_id"]))


def record_calls(db, scope, events):
    """Store normalized usage metadata without retaining its source content."""
    # Replays can refer to rows written under a former enrollment. Keep their
    # original row and metadata together instead of adding another local call.
    scopes = {}
    for start in range(0, len(events), 400):
        keys = [event["key"] for event in events[start:start + 400]]
        # Stay below the parameter limit of older bundled SQLite versions.
        for key, previous in db.execute(
                f"SELECT event_key,scope FROM usage_calls WHERE event_key IN ({','.join('?' for _ in keys)}) ORDER BY rowid",
                keys):
            scopes.setdefault(key, previous)
    for event in events:
        event["local_scope"] = scopes.get(event["key"], scope)
    db.executemany(
        "INSERT OR IGNORE INTO usage_calls VALUES (?,?,?,?,?,?,?)",
        [(event["local_scope"], event["key"], event["time"].timestamp(), event["model"],
          event["reasoning_effort"], event["usage"]["tokens"],
          float(event["usage"]["cost"]) if event["usage"]["cost"] is not None else None)
         for event in events],
    )
    # Keep the original ledger schema writable by older sensor versions.
    db.executemany(
        "INSERT OR IGNORE INTO usage_tokens "
        "SELECT scope,event_key,?,?,? FROM usage_calls "
        "WHERE scope=? AND event_key=? AND tokens=?",
        [(event["usage"]["cache_read_tokens"],
          event["usage"]["input_tokens"] + event["usage"]["cache_write_tokens"],
          event["usage"]["output_tokens"], event["local_scope"], event["key"], event["usage"]["tokens"])
         for event in events],
    )
    db.executemany(
        "INSERT OR IGNORE INTO usage_apps "
        "SELECT scope,event_key,? FROM usage_calls WHERE scope=? AND event_key=?",
        [(event["name"].split(".")[0], event["local_scope"], event["key"]) for event in events],
    )
    # Recover missing prices from matching evidence without replacing quotes
    # or pricing conflicting usage that reused the same response ID.
    db.executemany(
        "UPDATE usage_calls SET cost_usd=? WHERE scope=? AND event_key=? "
        "AND cost_usd IS NULL AND happened_at=? AND model=? AND effort=? AND tokens=? "
        "AND EXISTS (SELECT 1 FROM usage_tokens t "
        "WHERE t.scope=usage_calls.scope AND t.event_key=usage_calls.event_key "
        "AND t.cached_input_tokens=? AND t.uncached_input_tokens=? AND t.output_tokens=?)",
        [(float(event["usage"]["cost"]), event["local_scope"], event["key"], event["time"].timestamp(),
          event["model"], event["reasoning_effort"], event["usage"]["tokens"],
          event["usage"]["cache_read_tokens"],
          event["usage"]["input_tokens"] + event["usage"]["cache_write_tokens"],
          event["usage"]["output_tokens"])
         for event in events if event["usage"]["cost"] is not None],
    )


def local_start(now, days):
    # Resolve the offset at the target midnight, including daylight-saving changes.
    return (now.astimezone().replace(tzinfo=None, hour=0, minute=0, second=0, microsecond=0)
            - timedelta(days=days - 1)).astimezone()


def prune(db, *, compact=True):
    from . import antigravity_usage, hook_estimates, usage_recovery
    antigravity_usage.prune(db)
    hook_estimates.prune(db)
    cutoff = local_start(datetime.now(timezone.utc), 30).timestamp()
    usage_recovery.prune(db, cutoff)
    db.execute("DELETE FROM usage_calls WHERE happened_at<?", (cutoff,))
    db.execute("DELETE FROM usage_rollups WHERE bucket<?", (cutoff,))
    db.execute("DELETE FROM usage_compacted WHERE happened_at<?", (cutoff,))
    db.execute("DELETE FROM usage_revisions WHERE bucket<?", (int(cutoff // 3600),))
    if not compact:
        return
    excess = db.execute("SELECT count(*) FROM usage_calls").fetchone()[0] - MAX_RECORDS
    if excess > 0:
        # Keep the rolling 24-hour cutoff exact, even during a burst above the
        # detail target. Only complete older slices can be summarized.
        before = int((datetime.now(timezone.utc).timestamp() - 86400) // ROLLUP_SECONDS) * ROLLUP_SECONDS
        _compact(db, before, excess)


def _compact(db, before, limit):
    """Move details to aggregates atomically in the caller's write transaction."""
    db.execute("CREATE TEMP TABLE IF NOT EXISTS usage_pruning (id INTEGER PRIMARY KEY)")
    db.execute("DELETE FROM usage_pruning")
    # An import can still replace a partial assistant block with its final usage.
    # Keep those details until that application's scan commits completion.
    db.execute("""INSERT INTO usage_pruning SELECT u.rowid FROM usage_calls u
        WHERE happened_at<? AND NOT (u.event_key LIKE 'history:%' AND EXISTS (
            SELECT 1 FROM usage_imports i JOIN usage_apps a ON a.application=i.application
            WHERE a.scope=u.scope AND a.event_key=u.event_key AND i.completed IN (0,2)))
        ORDER BY happened_at,u.rowid LIMIT ?""", (before, limit))
    # Select the original event across enrollments before removing any copies.
    # A later copy with an earlier timestamp must not replace the original.
    original = """u.rowid IN (SELECT id FROM usage_pruning)
        AND u.rowid=(SELECT min(v.rowid) FROM usage_calls v WHERE v.event_key=u.event_key)
        AND NOT EXISTS (SELECT 1 FROM usage_compacted c WHERE c.event_key=u.event_key)"""
    updates = ",".join(f"{field}={field}+excluded.{field}" for field in COUNTERS)
    db.execute(f"""
        INSERT INTO usage_rollups
        SELECT CAST(u.happened_at/{ROLLUP_SECONDS} AS INTEGER)*{ROLLUP_SECONDS},
            u.model,u.effort,coalesce(a.application,'unknown'),count(*),count(u.cost_usd),sum(u.tokens),
            coalesce(sum(t.cached_input_tokens),0),coalesce(sum(t.uncached_input_tokens),0),
            coalesce(sum(t.output_tokens),0),sum(CASE WHEN t.event_key IS NULL THEN u.tokens ELSE 0 END),
            sum(u.cost_usd)
        FROM usage_calls u
        LEFT JOIN usage_tokens t ON t.scope=u.scope AND t.event_key=u.event_key
        LEFT JOIN usage_apps a ON a.scope=u.scope AND a.event_key=u.event_key
        WHERE {original} GROUP BY 1,2,3,4
        ON CONFLICT(bucket,model,effort,application) DO UPDATE SET {updates},
            cost_usd=CASE WHEN cost_usd IS NULL AND excluded.cost_usd IS NULL THEN NULL
                         ELSE coalesce(cost_usd,0)+coalesce(excluded.cost_usd,0) END
    """)
    db.execute(f"INSERT INTO usage_compacted SELECT event_key,happened_at FROM usage_calls u WHERE {original}")
    db.execute("DELETE FROM usage_calls WHERE rowid IN (SELECT id FROM usage_pruning)")
    db.execute("DELETE FROM usage_pruning")


def _query(db, since, until, has_tokens, has_apps, first_hour=None, hour_offset=None, deduplicate=False,
           has_rollups=False):
    detail = """coalesce(sum(t.cached_input_tokens),0) AS cached_input_tokens,
                coalesce(sum(t.uncached_input_tokens),0) AS uncached_input_tokens,
                coalesce(sum(t.output_tokens),0) AS output_tokens,
                sum(CASE WHEN t.event_key IS NULL THEN u.tokens ELSE 0 END) AS unclassified_tokens""" if has_tokens else """
                0 AS cached_input_tokens,0 AS uncached_input_tokens,
                0 AS output_tokens,sum(u.tokens) AS unclassified_tokens"""
    join = "LEFT JOIN usage_tokens t ON t.scope=u.scope AND t.event_key=u.event_key" if has_tokens else ""
    application = "coalesce(a.application,'unknown')" if has_apps else "'unknown'"
    if has_apps:
        join += " LEFT JOIN usage_apps a ON a.scope=u.scope AND a.event_key=u.event_key"
    bucket = "CAST((u.happened_at-?)/3600 AS INTEGER)" if first_hour is not None else "date(CAST(u.happened_at AS INTEGER),'unixepoch','localtime')"
    params = (first_hour,) if first_hour is not None else ()
    slot = f",CAST((u.happened_at-{int(hour_offset)})/3600 AS INTEGER) AS hour_bucket" if hour_offset is not None else ""
    source = ("(SELECT *,row_number() OVER (PARTITION BY event_key ORDER BY rowid) AS occurrence FROM usage_calls)"
              if deduplicate else "usage_calls")
    return db.execute(f"""
        SELECT {bucket} AS bucket,model,effort,{application} AS application,
               count(*) AS calls,count(cost_usd) AS priced_calls,
               sum(u.tokens) AS tokens,sum(cost_usd) AS cost_usd,{detail}{slot}
        FROM {source} u {join} WHERE happened_at>=? AND happened_at<?
        {'AND occurrence=1' if deduplicate else ''}
        {'AND NOT EXISTS (SELECT 1 FROM usage_compacted c WHERE c.event_key=u.event_key)' if has_rollups else ''}
        GROUP BY bucket,model,effort,application{',hour_bucket' if slot else ''}
    """, (*params, since, until)).fetchall()


def _rollup_query(db, since, until):
    return db.execute(f"""
        SELECT date(bucket,'unixepoch','localtime') AS bucket,model,effort,application,
            {','.join(f'sum({field}) AS {field}' for field in COUNTERS)},sum(cost_usd) AS cost_usd
        FROM usage_rollups WHERE bucket>=? AND bucket<? GROUP BY 1,2,3,4
    """, (since, until)).fetchall()


class UsageReader:
    """A read-only connection and bounded hourly aggregates, owned by the desktop helper."""

    def __init__(self):
        self.db = None
        self.key = None
        self.hours = {}
        self.hook_reports = {}

    def close(self):
        if self.db is not None:
            self.db.close()
        self.db = self.key = None
        self.hours.clear()
        self.hook_reports.clear()

    def hook_overview(self, config, period, since, until, *, cache):
        from .hook_estimates import overview
        key = (since.date(), until.date(), until.utcoffset())
        previous = self.hook_reports.get(period)
        # The desktop polls native usage each second. Hook estimates need only
        # a 30-second refresh, avoiding repeated scans of the bounded ledger.
        if cache and previous and previous[0] == key and time.monotonic() - previous[1] < 30:
            return previous[2]
        try:
            result = overview(config, since, until, timeout=0)
            if not result["summary"]["observations"]:
                result = None
        except (sqlite3.Error, OSError):
            result = None
        self.hook_reports[period] = (key, time.monotonic(), result)
        return result

    def read(self, config, since, until, hourly_since, first_hour, with_hours, cache=True):
        path = (Path(config["data_dir"]) / "telemetry.sqlite3").resolve()
        try:
            stat = path.stat()
        except FileNotFoundError:
            self.close()
            return {}, None
        key = (str(path), stat.st_dev, stat.st_ino, time.tzname, time.timezone,
               until.tzname(), until.utcoffset())
        if key != self.key:
            self.close()
            self.db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)
            self.db.row_factory = sqlite3.Row
            self.key = key
        db = self.db
        try:
            db.execute("BEGIN")
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "usage_calls" not in tables:
                self.hours.clear()
                return {}, None
            history = db.execute("SELECT min(started_at) AS started_at,max(truncated_at) AS truncated_at "
                                 "FROM usage_history").fetchone()
            if history["started_at"] is None:
                history = None
            elif "usage_request_sources" in tables:
                from .usage_import import recovery_status
                history = dict(history)
                recovery = recovery_status(db)
                recovery["recovered_calls"] = db.execute(
                    "SELECT count(*) FROM usage_recovered r JOIN usage_sources s USING(event_key) "
                    "WHERE s.kind='recovered' AND r.happened_at>=? AND r.happened_at<?",
                    (local_start(until, 30).timestamp(), until.timestamp()),
                ).fetchone()[0]
                history["recovery"] = recovery
            has_tokens, has_apps = "usage_tokens" in tables, "usage_apps" in tables
            has_rollups = "usage_rollups" in tables
            start, end = since.timestamp(), until.timestamp()
            cutoff, first = hourly_since.timestamp(), first_hour.timestamp()
            offset = first % 3600
            duplicates = bool(db.execute("SELECT 1 FROM usage_calls GROUP BY event_key HAVING count(*)>1 LIMIT 1").fetchone())
            # Legacy enrollments may contain a replay with a different timestamp.
            # Select its original row across the whole ledger, not per cached hour.
            if not cache or "usage_revisions" not in tables or duplicates:
                self.hours.clear()
                rows = {False: _query(db, start, end, has_tokens, has_apps, deduplicate=duplicates,
                                     has_rollups=has_rollups)}
                if with_hours:
                    rows[True] = _query(db, cutoff, end, has_tokens, has_apps, first, deduplicate=duplicates,
                                        has_rollups=has_rollups)
                if has_rollups:
                    rows[False].extend(_rollup_query(db, start, end))
                return rows, history
            low, high = int(start // 3600), int(end // 3600)
            revisions = dict(db.execute("SELECT bucket,sum(revision) FROM usage_revisions "
                                        "WHERE bucket BETWEEN ? AND ? GROUP BY bucket", (low, high)))
            self.hours = {hour: value for hour, value in self.hours.items() if low <= hour <= high}
            rows = {False: [], True: []}
            for hour in range(low, high + 1):
                left, right = max(start, hour * 3600), min(end, (hour + 1) * 3600)
                tag = (revisions.get(hour, 0), left, right, has_tokens, has_apps, has_rollups, offset)
                cached = self.hours.get(hour)
                if cached is None or cached[0] != tag:
                    cached = (tag, _query(db, left, right, has_tokens, has_apps, hour_offset=offset,
                                         has_rollups=has_rollups))
                    self.hours[hour] = cached
                rows[False].extend(cached[1])
                if with_hours and right > cutoff:
                    selected = cached[1] if left >= cutoff else _query(db, cutoff, right, has_tokens, has_apps,
                                                                     hour_offset=offset, has_rollups=has_rollups)
                    rows[True].extend(dict(row, bucket=row['hour_bucket'] - int(first // 3600)) for row in selected)
            if has_rollups:
                rows[False].extend(_rollup_query(db, start, end))
            return rows, history
        except Exception:
            self.close()
            raise
        finally:
            if self.db is not None:
                # Release the snapshot between requests so collection and pruning can proceed.
                self.db.rollback()


def overview(config, days, reader=None):
    """Read a snapshot without a running daemon, network, or current credentials."""
    until = datetime.now(timezone.utc).astimezone()
    periods = (1, 14, 30) if days in (1, 14, 30) else (days,)
    since = local_start(until, max(periods))
    hourly_since = (until - timedelta(hours=24)).astimezone()
    first_hour = (until.replace(minute=0, second=0, microsecond=0).astimezone(timezone.utc)
                  - timedelta(hours=24))
    owned = reader is None
    reader = reader or UsageReader()
    try:
        rows, history = reader.read(config, since, until, hourly_since, first_hour, 1 in periods, cache=not owned)
    finally:
        if owned:
            reader.close()

    def empty():
        return dict(calls=0, priced_calls=0, tokens=0, cost_usd=None,
                    cached_input_tokens=0, uncached_input_tokens=0, output_tokens=0, unclassified_tokens=0)

    def breakdown(groups):
        return [dict(application=app, model=model, reasoning_effort=effort, **values)
                for (app, model, effort), values in sorted(groups.items())]

    def summarize(period):
        hourly = period == 1
        since = hourly_since if hourly else local_start(until, period)
        total = empty()
        # The rolling cutoff and current hour can each contain a partial hour.
        series = {hour: empty() for hour in range(25)} if hourly else {
            (since + timedelta(days=day)).date().isoformat(): empty() for day in range(period)}
        models, efforts = defaultdict(empty), defaultdict(empty)
        groups = defaultdict(empty)
        daily_groups = defaultdict(lambda: defaultdict(empty))
        for row in rows.get(hourly, []):
            if row["bucket"] not in series:
                continue
            key = (row["application"], row["model"], row["effort"])
            for target in (total, series[row["bucket"]], models[row["model"]], efforts[row["effort"]],
                           groups[key], daily_groups[row["bucket"]][key]):
                for field in ("calls", "priced_calls", "tokens", "cached_input_tokens",
                              "uncached_input_tokens", "output_tokens", "unclassified_tokens"):
                    target[field] += row[field]
                if row["cost_usd"] is not None:
                    target["cost_usd"] = (target["cost_usd"] or 0) + row["cost_usd"]
        incomplete = not history or history["started_at"] > since.timestamp() or (
            history["truncated_at"] is not None and history["truncated_at"] >= since.timestamp()
        )
        hook_report = reader.hook_overview(config, period, since, until, cache=not owned)
        return dict(
            source="local", days=period, granularity="hour" if hourly else "day",
            timezone=until.tzname(), since=since.isoformat(), until=until.isoformat(),
            summary=total, series=[dict(date=(first_hour + timedelta(hours=day)).astimezone().isoformat() if hourly else day,
                                       **values, breakdown=breakdown(daily_groups[day]))
                                   for day, values in series.items()],
            breakdown=breakdown(groups),
            by_model=[dict(name=name, **values) for name, values in sorted(models.items(), key=lambda row: -(row[1]["cost_usd"] or 0))],
            by_reasoning_effort=[dict(name=name, **efforts[name]) for name in (*EFFORTS, "unknown") if name in efforts],
            pending_exports=0, history_incomplete=bool(incomplete),
            tracking_started_at=datetime.fromtimestamp(history["started_at"], timezone.utc).isoformat() if history else None,
            **({"history_recovery": history["recovery"]} if history and "recovery" in history.keys() else {}),
            **({"hook_estimates": hook_report} if hook_report is not None else {}),
        )

    summaries = {str(period): summarize(period) for period in periods}
    result = summaries[str(days)]
    return dict(result, periods=summaries) if len(periods) > 1 else result


def main():
    """Serve bounded, read-only JSON requests until the desktop closes stdin."""
    import sys
    import psutil
    from .config import Config

    # Only the dedicated display helper yields CPU priority to other applications.
    try:
        process = psutil.Process()
        process.nice(psutil.IDLE_PRIORITY_CLASS if psutil.WINDOWS else max(10, process.nice()))
    except psutil.Error:
        pass

    reader = UsageReader()
    try:
        while raw := sys.stdin.buffer.readline(65537):
            try:
                if len(raw) > 65536:
                    raise ValueError("Usage request exceeded the size limit.")
                request = json.loads(raw)
                if (not isinstance(request, dict) or set(request) - {"action", "params", "config_path"}
                        or request.get("action") != "usage.summary"):
                    raise ValueError("Only usage.summary is available on the usage helper.")
                params = request.get("params", {})
                if not isinstance(params, dict) or set(params) - {"days"}:
                    raise ValueError("Invalid usage parameters.")
                days = params.get("days", 30)
                if type(days) is not int or days not in (1, 7, 14, 30):
                    raise ValueError("days must be 1, 7, 14, or 30")
                if "config_path" in request and not isinstance(request["config_path"], str):
                    raise ValueError("Invalid configuration path.")
                if hasattr(time, "tzset"):
                    time.tzset()
                try:
                    data = overview(Config.load(request.get("config_path")), days, reader)
                except Exception:
                    reader.close()
                    raise ValueError("Could not read usage stored on this device. Try again later.") from None
                response = {"ok": True, "data": data}
            except (ValueError, TypeError) as error:
                response = {"ok": False, "error": str(error)}
            encoded = json.dumps(response)
            if len(encoded.encode()) > 8 * 1024 * 1024:
                encoded = json.dumps({"ok": False, "error": "Usage response exceeded the size limit."})
            print(encoded, flush=True)
            if len(raw) > 65536:
                break
    finally:
        reader.close()
    return 0
