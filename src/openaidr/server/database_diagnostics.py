"""Bounded, read-only observations for an explicitly dedicated tenant database."""

from collections import deque
import asyncio
from datetime import datetime, timezone
import re
from threading import Lock
from time import monotonic

import psycopg
from psycopg import sql
from starlette.concurrency import run_in_threadpool

WINDOW_SECONDS = 300
SAMPLE_SECONDS = 30
QUERY_COUNTERS = ("calls", "total_exec_time", "shared_blks_hit", "shared_blks_read")
SCAN_COUNTERS = ("seq_scan", "seq_tup_read", "idx_scan")
TABLES = re.compile(r"^(?:agents|sensors|events(?:_[a-f0-9]{32}(?:_\d{8})?)?|"
                   r"telemetry_exports(?:_[a-f0-9]{32}(?:_\d{8})?)?|"
                   r"agent_sessions|session_investigation_jobs|findings)$")


def query_label(query):
    # Only fixed labels leave the collector. Even normalized SQL can contain
    # literals, comments, credentials, or captured action evidence.
    text = " ".join((query or "").lower().split())
    if text.startswith("update agents set") and "first_seen" in text and "last_seen" in text:
        return "Update agent statistics"
    if text.startswith("update events set risk=") and "risk_assessment_usage" in text:
        return "Claim risk assessment work"
    for verb, label in (("select", "Read"), ("insert", "Insert"), ("update", "Update"), ("delete", "Delete")):
        if text.startswith(verb + " "):
            return label + " query"
    return "Other statement"


def snapshot(st, tenant):
    pool = st.pools["data"]
    with pool.connection(timeout=min(1, pool.timeout)) as conn:
        conn.execute("SET TRANSACTION READ ONLY")
        conn.execute("SET LOCAL statement_timeout='500ms'")
        conn.execute("SET LOCAL lock_timeout='100ms'")
        if conn.execute("SELECT EXISTS (SELECT 1 FROM tenants WHERE id<>%s) AS shared", (tenant,)).fetchone()["shared"]:
            return {"status": "disabled", "message": "Database diagnostics require a database dedicated to one tenant."}
        clock = conn.execute("""SELECT clock_timestamp() AS sampled_at,
            pg_postmaster_start_time() AS started_at,
            (SELECT stats_reset FROM pg_stat_database WHERE datname=current_database()) AS stats_reset""").fetchone()
        active = conn.execute("""SELECT pid,query_id::text AS query_id,left(query,4096) AS query,
            greatest(0,extract(epoch FROM clock_timestamp()-query_start))::float8 AS seconds,
            wait_event_type,wait_event,count(*) OVER () AS total
            FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user
              AND backend_type='client backend' AND state='active' AND pid<>pg_backend_pid()
            ORDER BY query_start,pid LIMIT 10""").fetchall()
        scans = conn.execute("""SELECT relid,relname,seq_scan,seq_tup_read,coalesce(idx_scan,0) AS idx_scan
            FROM pg_stat_user_tables WHERE schemaname=current_schema()
            ORDER BY relid LIMIT 1001""").fetchall()
        extension = conn.execute("""SELECT n.nspname FROM pg_extension e
            JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='pg_stat_statements'""").fetchone()
        query_status, queries, epoch = "disabled", [], None
        if extension:
            try:
                with conn.transaction():
                    info = conn.execute(sql.SQL("SELECT stats_reset,dealloc FROM {}.pg_stat_statements_info").format(
                        sql.Identifier(extension["nspname"]))).fetchone()
                    queries = conn.execute(sql.SQL("""SELECT queryid::text AS query_id,
                        left(query,4096) AS query,calls,total_exec_time,shared_blks_hit,shared_blks_read
                        FROM {}.pg_stat_statements
                        WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database())
                          AND userid=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND toplevel
                        ORDER BY queryid LIMIT 5001""").format(sql.Identifier(extension["nspname"]))).fetchall()
                    epoch = (info["stats_reset"], info["dealloc"])
                    query_status = "ok" if len(queries) <= 5000 else "limited"
            except (psycopg.errors.ObjectNotInPrerequisiteState, psycopg.errors.UndefinedTable,
                    psycopg.errors.UndefinedColumn, psycopg.errors.InsufficientPrivilege):
                query_status = "disabled"
        for row in queries + active:
            row["label"] = query_label(row.pop("query"))
        return {
            "status": "ok", "sampled_at": clock["sampled_at"].isoformat(),
            "epoch": (clock["started_at"], clock["stats_reset"]),
            "query_epoch": epoch, "query_status": query_status,
            "queries": {row["query_id"]: row for row in queries} if query_status == "ok" else {},
            "active": active, "active_total": active[0]["total"] if active else 0,
            "scans": {row["relid"]: row for row in scans if TABLES.fullmatch(row["relname"])} if len(scans) <= 1000 else {},
            "scan_status": "ok" if len(scans) <= 1000 else "limited",
        }


def deltas(before, after, counters):
    result = []
    skipped = 0
    for key, row in after.items():
        previous = before.get(key)
        # A new/reset entry has no trusted baseline. Never substitute lifetime
        # totals for an observed interval or silently turn missing into zero.
        if previous is None or any(row[name] < previous[name] for name in counters):
            skipped += 1
            continue
        result.append({**row, **{name: row[name] - previous[name] for name in counters}})
    return result, skipped


class Diagnostics:
    def __init__(self):
        self.lock = Lock()
        self.samples = deque(maxlen=WINDOW_SECONDS // SAMPLE_SECONDS + 1)
        self.sampled_at = 0
        self.result = None

    async def run(self, st, tenant, stop):
        self.samples.clear()
        st.query_sources.clear()
        self.publish(None, 0)
        try:
            while not stop.is_set():
                await run_in_threadpool(self.collect, st, tenant)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=SAMPLE_SECONDS)
                except TimeoutError:
                    pass
        finally:
            st.query_sources.clear()

    def publish(self, result, sampled_at):
        with self.lock:
            self.result, self.sampled_at = result, sampled_at

    def read(self):
        with self.lock:
            if self.result is None:
                return {"status": "warming", "message": "Waiting for the first background sample."}
            age = monotonic() - self.sampled_at
            if self.result["status"] != "ok":
                return self.result
            if age > WINDOW_SECONDS:
                return {"status": "unavailable", "message": "No database diagnostics sample in the last five minutes.",
                        "checked_at": self.result["checked_at"]}
            return {**self.result, "stale": age > 2 * SAMPLE_SECONDS}

    def collect(self, st, tenant):
        now = monotonic()
        try:
            latest = snapshot(st, tenant)
            if latest["status"] != "ok":
                self.samples.clear()
                st.query_sources.clear()
                self.publish(latest, now)
                return
            if self.samples and any(self.samples[-1][1][key] != latest[key] for key in ("epoch", "query_epoch")):
                self.samples.clear()
            while self.samples and now - self.samples[0][0] > WINDOW_SECONDS:
                self.samples.popleft()
            self.samples.append((now, latest))
            started, first = self.samples[0]
            seconds = now - started
            query_status = latest["query_status"]
            scan_status = latest["scan_status"]
            queries, scans, skipped_queries, skipped_scans = [], [], 0, 0
            if seconds == 0 or first["epoch"] != latest["epoch"]:
                query_status = "warming" if query_status == "ok" else query_status
                scan_status = "warming" if scan_status == "ok" else scan_status
            else:
                if query_status == "ok":
                    if first["query_status"] == "ok" and first["query_epoch"] == latest["query_epoch"]:
                        queries, skipped_queries = deltas(first["queries"], latest["queries"], QUERY_COUNTERS)
                    else:
                        query_status = "warming"
                if scan_status == "ok":
                    if first["scan_status"] == "ok":
                        scans, skipped_scans = deltas(first["scans"], latest["scans"], SCAN_COUNTERS)
                    else:
                        scan_status = "warming"
            queries = sorted((row for row in queries if row["calls"] > 0), key=lambda row: row["total_exec_time"], reverse=True)
            scans = sorted((row for row in scans if any(row[key] for key in SCAN_COUNTERS)), key=lambda row: row["seq_tup_read"], reverse=True)
            result = {
                "status": "ok", "checked_at": latest["sampled_at"],
                "window_start": first["sampled_at"], "window_seconds": round(seconds, 1),
                "queries": {"status": query_status, "items": queries[:10], "without_baseline": skipped_queries},
                "scans": {"status": scan_status, "items": scans[:10], "without_baseline": skipped_scans},
                "active": latest["active"], "active_total": latest["active_total"],
                "sources": st.query_sources.read(),
            }
        except Exception:
            # Database and pool failures must not stop the timer or expose SQL.
            self.samples.clear()
            st.query_sources.clear()
            result = {"status": "unavailable", "message": "Database diagnostics could not be collected.",
                      "checked_at": datetime.now(timezone.utc).isoformat()}
        self.publish(result, now)
