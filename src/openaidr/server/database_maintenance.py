"""Refresh planner statistics that ordinary autovacuum leaves stale."""

import asyncio
import logging

from psycopg import sql
from psycopg.errors import LockNotAvailable, QueryCanceled
from starlette.concurrency import run_in_threadpool

log = logging.getLogger(__name__)


def analyze_one(st, after=""):
    """Attempt one due table without overlapping another worker."""
    with st.transaction() as conn:
        conn.execute("SET LOCAL lock_timeout='250ms'")
        conn.execute("SET LOCAL statement_timeout='60s'")
        if not st.scalar("SELECT pg_try_advisory_xact_lock(hashtextextended('dashboard-planner-statistics',0))", conn=conn):
            return False
        # Autovacuum does not analyze partitioned parents. Growing timestamp
        # columns also need fresher upper bounds than the default 10% threshold.
        due = st.many("""SELECT targets.name FROM (VALUES
                ('events', interval '30 minutes'),
                ('telemetry_exports', interval '30 minutes'),
                ('ordinary_hook_checks', interval '5 minutes'),
                ('agent_cost_records', interval '5 minutes')
            ) AS targets(name,age)
            JOIN pg_stat_all_tables s ON s.relid=to_regclass(targets.name)
            JOIN pg_class c ON c.oid=s.relid
            WHERE (c.relkind<>'p' OR EXISTS(SELECT 1 FROM pg_inherits WHERE inhparent=c.oid))
              AND (greatest(s.last_analyze,s.last_autoanalyze) IS NULL
               OR greatest(s.last_analyze,s.last_autoanalyze)<clock_timestamp()-targets.age)
            ORDER BY (targets.name<=$1),targets.name
            LIMIT 1""", after, conn=conn)
        if not due:
            return False
        name = due[0]['name']
        try:
            with conn.transaction():
                conn.execute(sql.SQL("ANALYZE (SKIP_LOCKED) {}").format(sql.Identifier(name)))
        except (LockNotAvailable, QueryCanceled):
            log.warning("Database statistics refresh deferred for %s", name)
        # Publish the new analysis time at commit so another API process can
        # observe it immediately after acquiring the shared maintenance lock.
        conn.execute("SELECT pg_stat_force_next_flush()")
        return name


async def run(st, stop):
    previous = ""
    while not stop.is_set():
        try:
            previous = await run_in_threadpool(analyze_one, st, previous) or previous
        except Exception:
            log.warning("Database statistics refresh deferred", exc_info=True)
        try:
            await asyncio.wait_for(stop.wait(), timeout=60)
        except TimeoutError:
            pass
