"""Persisted activity rankings refreshed independently of dashboard requests."""

import asyncio
from datetime import datetime, time, timedelta, timezone
import logging
from zoneinfo import ZoneInfo

from psycopg.errors import LockNotAvailable, QueryCanceled
from starlette.concurrency import run_in_threadpool

from .httpx import require

REFRESH_SECONDS = 15 * 60
RETRY_SECONDS = 60
IDLE_SECONDS = 30 * 60
RETENTION_SECONDS = 24 * 60 * 60
MAX_SNAPSHOTS = 16
log = logging.getLogger(__name__)

# Keep the complete population so searches and pages share one saved snapshot.
POPULATION = """WITH sessions AS MATERIALIZED (
    SELECT id,sensor_id,registration_id,external_id,product FROM agent_sessions
    WHERE tenant_id=$1 AND last_event_at>=$2 AND started_at<=$3
), observations AS (
    SELECT s.id,e.body->'agent'->>'account' AS account,e.body->'host'->>'user' AS os_user,
        e.body->'host'->>'hostname' AS hostname,e.time,e.risk->>'status' AS status,e.risk->'score' AS score
    FROM sessions s JOIN events e ON e.session_id=s.id AND e.tenant_id=$1
    WHERE e.time>=$2 AND e.time<=$3 AND e.kind NOT IN ('sensor','session.start','session.end')
    UNION ALL
    SELECT s.id,e.target_body->'agent'->>'account',e.target_body->'host'->>'user',
        e.target_body->'host'->>'hostname',e.created_at,e.status,e.assessment->'score'
    FROM sessions s JOIN inline_guardrail_events e ON e.registration_id=s.registration_id AND e.tenant_id=$1
    WHERE e.created_at>=$2 AND e.created_at<=$3
), measured AS (
    SELECT id,max(time) AS last_activity_at,
        max(CASE WHEN status='scored' AND jsonb_typeof(score)='number' THEN
            CASE WHEN score::text::numeric BETWEEN 0 AND 100 THEN score::text::numeric END END)::double precision AS peak,
        min(COALESCE(os_user,'') COLLATE "C")<>max(COALESCE(os_user,'') COLLATE "C") AS mixed,
        min(COALESCE(os_user,'') COLLATE "C") AS reported_user,
        COALESCE(array_agg(DISTINCT account COLLATE "C" ORDER BY account COLLATE "C")
            FILTER (WHERE COALESCE(account,'')<>''),'{}'::text[]) AS accounts,
        COALESCE(min(hostname),'') AS hostname
    FROM observations GROUP BY id
), population AS MATERIALIZED (
    SELECT s.id::text,s.id AS session_id,s.sensor_id,s.external_id,s.product,m.hostname,
        CASE WHEN m.mixed THEN 'mixed' WHEN m.reported_user='' THEN 'unknown' ELSE 'os_user' END AS identity_kind,
        CASE WHEN m.mixed THEN '' ELSE m.reported_user END AS reported_user,
        m.accounts,
        m.peak,m.last_activity_at,1::bigint AS session_count,1::bigint AS device_count
    FROM sessions s JOIN measured m ON m.id=s.id
), user_accounts AS (
    SELECT sensor_id,reported_user,array_agg(DISTINCT account COLLATE "C" ORDER BY account COLLATE "C") AS accounts
    FROM population CROSS JOIN LATERAL unnest(accounts) AS account
    WHERE identity_kind='os_user' GROUP BY sensor_id,reported_user
), users AS (
    SELECT encode(sha256(convert_to(jsonb_build_array('os_user',p.reported_user,p.sensor_id)::text,'UTF8')),'hex') AS id,
        (array_agg(p.session_id ORDER BY p.peak DESC NULLS LAST,p.last_activity_at DESC,p.session_id))[1] AS session_id,
        p.sensor_id,''::text AS external_id,''::text AS product,min(p.hostname) AS hostname,
        'os_user'::text AS identity_kind,p.reported_user,COALESCE(a.accounts,'{}'::text[]) AS accounts,
        max(p.peak) AS peak,max(p.last_activity_at) AS last_activity_at,
        count(*) AS session_count,1::bigint AS device_count
    FROM population p LEFT JOIN user_accounts a USING (sensor_id,reported_user)
    WHERE p.identity_kind='os_user' GROUP BY p.sensor_id,p.reported_user,a.accounts
), filtered AS MATERIALIZED (
    SELECT 'sessions' AS kind,* FROM population
    UNION ALL SELECT 'users' AS kind,* FROM users
) SELECT * FROM filtered"""


def request_snapshot(st, tenant_id, zone_name):
    snapshots = st.many("""SELECT last_requested_at>now()-interval '1 minute' AS recent
        FROM risk_activity_snapshots WHERE tenant_id=$1 AND time_zone=$2""", tenant_id, zone_name)
    if snapshots and snapshots[0]["recent"]:
        return
    try:
        with st.transaction() as conn:
            conn.execute("SET LOCAL lock_timeout='100ms'; SET LOCAL statement_timeout='1s'")
            if snapshots:
                # Coalesce active readers without waiting on a refresh claim.
                st.execute("""WITH available AS (
                    SELECT tenant_id,time_zone FROM risk_activity_snapshots
                    WHERE tenant_id=$1 AND time_zone=$2 AND last_requested_at<=now()-interval '1 minute'
                    FOR UPDATE SKIP LOCKED
                ) UPDATE risk_activity_snapshots s SET last_requested_at=clock_timestamp()
                    FROM available a WHERE s.tenant_id=a.tenant_id AND s.time_zone=a.time_zone""",
                    tenant_id, zone_name, conn=conn)
            else:
                # Serialize only new slots; cached reads and renewal do not wait.
                require(st.scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))",
                                  f"risk-activity:{tenant_id}", conn=conn),
                        "Activity preparation is busy. Try again shortly.", 429)
                if st.scalar("SELECT EXISTS(SELECT 1 FROM risk_activity_snapshots WHERE tenant_id=$1 AND time_zone=$2)",
                             tenant_id, zone_name, conn=conn):
                    return
                count = st.scalar("SELECT count(*) FROM risk_activity_snapshots WHERE tenant_id=$1", tenant_id, conn=conn)
                if count >= MAX_SNAPSHOTS:
                    removed = st.execute("""WITH idle AS (
                        SELECT tenant_id,time_zone FROM risk_activity_snapshots
                        WHERE tenant_id=$1 AND last_requested_at<=now()-$2*interval '1 second'
                        ORDER BY last_requested_at,time_zone LIMIT 1 FOR UPDATE SKIP LOCKED
                    ) DELETE FROM risk_activity_snapshots s USING idle i
                        WHERE s.tenant_id=i.tenant_id AND s.time_zone=i.time_zone""", tenant_id, IDLE_SECONDS, conn=conn)
                    require(count - removed < MAX_SNAPSHOTS,
                            "Activity rankings are already tracking 16 time zones. Try again later.", 429)
                st.execute("""INSERT INTO risk_activity_snapshots(tenant_id,time_zone) VALUES($1,$2)
                    ON CONFLICT DO NOTHING""", tenant_id, zone_name, conn=conn)
    except (LockNotAvailable, QueryCanceled):
        # Another request or worker may be creating the first snapshot. The
        # reader can report preparation without waiting for that transaction.
        pass


def listing(st, tenant_id, zone_name, search, offsets, limit, conn):
    snapshots = st.many("""SELECT since,until,refresh_failed,
            until<=now()-$3*interval '1 second' AS stale
        FROM risk_activity_snapshots WHERE tenant_id=$1 AND time_zone=$2""",
        tenant_id, zone_name, REFRESH_SECONDS, conn=conn)
    snapshot = snapshots[0] if snapshots else {"since": None, "until": None, "refresh_failed": False, "stale": True}
    state = ("unavailable" if snapshot["refresh_failed"] else "pending") if snapshot["until"] is None else (
        "stale" if snapshot["stale"] or snapshot["refresh_failed"] else "current")
    metadata = {"state": state, "since": snapshot["since"], "until": snapshot["until"],
                "refresh_interval_seconds": REFRESH_SECONDS, "refresh_failed": snapshot["refresh_failed"]}
    if snapshot["until"] is None:
        return None, metadata
    rows = st.one(
        """WITH matches AS MATERIALIZED (
            SELECT kind,body,(body->>'peak')::double precision AS peak,
                (body->>'last_activity_at')::timestamptz AS last_activity_at,id
            FROM risk_activity_rows WHERE tenant_id=$1 AND time_zone=$2
                AND ($3='' OR position(lower($3) in lower(concat_ws(' ',body->>'external_id',
                    body->>'product',body->>'hostname',body->>'reported_user',
                    (SELECT string_agg(value,' ') FROM jsonb_array_elements_text(body->'accounts')))))>0)
        ), session_page AS (
            SELECT * FROM matches WHERE kind='sessions'
            ORDER BY peak DESC NULLS LAST,last_activity_at DESC,id LIMIT $4 OFFSET $5
        ), user_page AS (
            SELECT * FROM matches WHERE kind='users'
            ORDER BY peak DESC NULLS LAST,last_activity_at DESC,id LIMIT $4 OFFSET $6
        ) SELECT
            (SELECT count(*) FROM matches WHERE kind='sessions') AS session_total,
            (SELECT count(*) FROM matches WHERE kind='users') AS user_total,
            COALESCE((SELECT jsonb_agg(body ORDER BY peak DESC NULLS LAST,last_activity_at DESC,id)
                FROM session_page),'[]'::jsonb) AS sessions,
            COALESCE((SELECT jsonb_agg(body ORDER BY peak DESC NULLS LAST,last_activity_at DESC,id)
                FROM user_page),'[]'::jsonb) AS users""",
        tenant_id, zone_name, search, limit, offsets["sessions"], offsets["users"], conn=conn,
    )
    return {kind: {"items": rows[kind], "total": rows[singular + "_total"],
                   "offset": offsets[kind], "limit": limit}
            for kind, singular in (("sessions", "session"), ("users", "user"))}, metadata


def refresh_one(st, tenant_id=None):
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        conn.execute("SET LOCAL statement_timeout='30s'; SET LOCAL lock_timeout='100ms'")
        removed = st.execute("""WITH expired AS (
            SELECT tenant_id,time_zone FROM risk_activity_snapshots
            WHERE last_requested_at<=now()-$2*interval '1 second'
                AND ($1::uuid IS NULL OR tenant_id=$1)
            ORDER BY last_requested_at,tenant_id,time_zone LIMIT 1 FOR UPDATE SKIP LOCKED
        ) DELETE FROM risk_activity_snapshots s USING expired e
            WHERE s.tenant_id=e.tenant_id AND s.time_zone=e.time_zone""", tenant_id, RETENTION_SECONDS, conn=conn)
        jobs = st.many("""SELECT a.tenant_id,a.time_zone FROM risk_activity_snapshots a
            JOIN tenants t ON t.id=a.tenant_id AND t.status='active'
            WHERE a.refresh_after<=now() AND a.last_requested_at>now()-$2*interval '1 second'
                AND ($1::uuid IS NULL OR a.tenant_id=$1)
            ORDER BY a.refresh_after,a.tenant_id,a.time_zone LIMIT 1 FOR UPDATE OF a SKIP LOCKED""",
            tenant_id, IDLE_SECONDS, conn=conn)
        if not jobs:
            return bool(removed)
        tenant, zone_name = jobs[0]["tenant_id"], jobs[0]["time_zone"]
        try:
            with conn.transaction():
                until = st.scalar("SELECT now()", conn=conn)
                zone = ZoneInfo(zone_name)
                since = datetime.combine(until.astimezone(zone).date() - timedelta(days=29), time.min, zone).astimezone(timezone.utc)
                st.execute("DELETE FROM risk_activity_rows WHERE tenant_id=$1 AND time_zone=$2", tenant, zone_name, conn=conn)
                st.execute("""INSERT INTO risk_activity_rows(tenant_id,time_zone,kind,id,body)
                    SELECT $1,$4,p.kind,p.id,to_jsonb(p) FROM (""" + POPULATION + ") p",
                    tenant, since, until, zone_name, conn=conn)
                st.execute("""UPDATE risk_activity_snapshots SET since=$3,until=$4,
                    refresh_after=$4+$5*interval '1 second',refresh_failed=false
                    WHERE tenant_id=$1 AND time_zone=$2""", tenant, zone_name, since, until, REFRESH_SECONDS, conn=conn)
        except Exception:
            # Roll back the replacement, retain the complete prior snapshot,
            # and release the job with a retry delay. Saved reads never wait on this lock.
            st.execute("""UPDATE risk_activity_snapshots SET refresh_failed=true,
                refresh_after=clock_timestamp()+$3*interval '1 second' WHERE tenant_id=$1 AND time_zone=$2""",
                tenant, zone_name, RETRY_SECONDS, conn=conn)
            log.warning("Activity snapshot refresh deferred")
        return True


async def run(st, cfg, stop):
    while not stop.is_set():
        worked = False
        try:
            worked = await run_in_threadpool(refresh_one, st, cfg.tenant_id or None)
        except Exception:
            log.warning("Activity snapshot scheduler unavailable")
        try:
            await asyncio.wait_for(stop.wait(), timeout=1 if worked else 5)
        except TimeoutError:
            pass
