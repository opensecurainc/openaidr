"""Cached, bounded descriptions of captured session activity for analysts."""

from openaidr_api_client.validation.session_activity_summaries import (
    MAX_RECORDS as MAX_RECORDS,
    MAX_INPUT_CHARS as MAX_INPUT_CHARS,
    validate_answer as validate_answer,
)

import asyncio
import hashlib
import json
import logging
from functools import partial

from starlette.concurrency import run_in_threadpool

from .guardrail.evidence import event_evidence
from .session_operator import _json_safe, _read
from .store import new_id

log = logging.getLogger(__name__)
REFRESH_SECONDS = 900
CACHE_SECONDS = 24 * 3600
LEASE_SECONDS = 120


def cache_identity(chat, tenant, connection, *, customer):
    fingerprint = chat.cache_identity(tenant, connection=connection)
    return hashlib.sha256(("customer-session-summary-v1:" + fingerprint).encode()).hexdigest() if customer else fingerprint


def attach(service, tenant, result, *, customer=False):
    """Queue only the returned session page; never call the model in a request."""
    if customer:
        from .service_operations import contracts
        contracts()
    if result.get("view") != "activity" or not result.get("groups"):
        return
    items = result["groups"]["sessions"]["items"]
    for item in items:
        item["activity_summary"] = {"state": "unavailable", "text": None, "through": None}
    if not items:
        return
    st = service.st
    try:
        connection = service.page_chat.connection
        if connection is None or str(tenant) != connection.tenant_id:
            return
        fingerprint = cache_identity(service.page_chat, tenant, connection, customer=customer)
        since = result["activity_snapshot"]["since"]
        with st.transaction() as conn:
            conn.execute("SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='100ms'")
            for item in items:
                rows = st.many("""INSERT INTO session_activity_summaries AS q
                    (tenant_id,session_id,requested_since,requested_through,key_fingerprint,requested_event_count,time_zone)
                    SELECT tenant_id,id,$3,$4,$5,events_total,$8 FROM agent_sessions WHERE tenant_id=$1 AND id=$2
                    ON CONFLICT(session_id,time_zone) DO UPDATE SET last_requested_at=now(),
                        requested_since=EXCLUDED.requested_since,requested_through=EXCLUDED.requested_through,
                        requested_event_count=EXCLUDED.requested_event_count,
                        key_fingerprint=EXCLUDED.key_fingerprint,
                        state=CASE WHEN (q.requested_since,q.requested_through,q.key_fingerprint,q.requested_event_count)=
                            (EXCLUDED.requested_since,EXCLUDED.requested_through,EXCLUDED.key_fingerprint,EXCLUDED.requested_event_count)
                            AND (q.generated_at IS NULL OR q.generated_at>now()-$6*interval '1 second')
                            THEN q.state ELSE 'pending' END,
                        summary=CASE WHEN (q.requested_since,q.requested_through,q.key_fingerprint,q.requested_event_count)=
                            (EXCLUDED.requested_since,EXCLUDED.requested_through,EXCLUDED.key_fingerprint,EXCLUDED.requested_event_count)
                            AND q.generated_at>now()-$6*interval '1 second' THEN q.summary END,
                        refresh_after=CASE WHEN q.lease_token IS NOT NULL THEN q.refresh_after
                            WHEN (q.requested_since,q.requested_through,q.key_fingerprint,q.requested_event_count) IS DISTINCT FROM
                                (EXCLUDED.requested_since,EXCLUDED.requested_through,EXCLUDED.key_fingerprint,EXCLUDED.requested_event_count)
                            THEN greatest(now(),q.last_attempt_at+$7*interval '1 second') ELSE q.refresh_after END
                    WHERE q.tenant_id=EXCLUDED.tenant_id
                    RETURNING state,summary AS text,CASE WHEN summary IS NOT NULL THEN requested_through END AS through""",
                    tenant, item["session_id"], since, item["last_activity_at"], fingerprint,
                    CACHE_SECONDS, REFRESH_SECONDS, result["time_zone"], conn=conn)
                if rows:
                    item["activity_summary"] = _json_safe(rows[0])
    except Exception:
        # Summary storage must not hide an otherwise available activity list.
        for item in items:
            item["activity_summary"] = {"state": "unavailable", "text": None, "through": None}
        log.warning("Session activity summaries unavailable")


def claim(st, tenant=None):
    with st.transaction() as conn:
        conn.execute("SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='100ms'")
        st.execute("""DELETE FROM session_activity_summaries WHERE (session_id,time_zone) IN (
            SELECT session_id,time_zone FROM session_activity_summaries
            WHERE last_requested_at<now()-interval '24 hours'
                AND ($1::uuid IS NULL OR tenant_id=$1) LIMIT 100)""", tenant, conn=conn)
        rows = st.many("""SELECT q.* FROM session_activity_summaries q
            JOIN tenants t ON t.id=q.tenant_id AND t.status='active'
            WHERE q.refresh_after<=now() AND q.last_requested_at>now()-interval '1 hour'
                AND ($1::uuid IS NULL OR q.tenant_id=$1)
                AND (SELECT count(*) FROM session_activity_summaries recent
                    WHERE recent.tenant_id=q.tenant_id AND recent.last_attempt_at>now()-interval '1 minute')<3
            ORDER BY q.refresh_after,q.session_id,q.time_zone LIMIT 1 FOR UPDATE OF q SKIP LOCKED""", tenant, conn=conn)
        if not rows:
            return None
        job = rows[0]
        # Serialize the rate check across workers for this tenant only.
        if not st.scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))",
                         "session-summary:" + job["tenant_id"], conn=conn):
            return None
        if st.scalar("""SELECT count(*) FROM session_activity_summaries
            WHERE tenant_id=$1 AND last_attempt_at>now()-interval '1 minute'""", job["tenant_id"], conn=conn) >= 3:
            return None
        job["lease_token"] = new_id()
        st.execute("""UPDATE session_activity_summaries SET lease_token=$2,last_attempt_at=now(),
            refresh_after=now()+$3*interval '1 second' WHERE session_id=$1 AND time_zone=$4""",
            job["session_id"], job["lease_token"], LEASE_SECONDS, job["time_zone"], conn=conn)
        return job


def collect(st, job):
    """Take the initial prompt and recent observations within the displayed window."""
    with _read(st) as conn:
        sessions = st.many("SELECT registration_id FROM agent_sessions WHERE tenant_id=$1 AND id=$2",
                           job["tenant_id"], job["session_id"], conn=conn)
        if not sessions:
            return []
        records = []
        for table, scope, stamp, body, ident in (
            ("events", "session_id", "time", "body", job["session_id"]),
            ("inline_guardrail_events", "registration_id", "created_at", "target_body", sessions[0]["registration_id"]),
        ):
            if not ident:
                continue
            kind = "kind" if table == "events" else "target_body->>'kind'"
            for prompt, order, limit in ((True, "ASC", 1), (False, "DESC", MAX_RECORDS)):
                records.extend(st.many(f"""SELECT id,{stamp} AS time,{kind} AS kind,{body} AS body
                    FROM {table} WHERE tenant_id=$1 AND {scope}=$2 AND {stamp}>=$3 AND {stamp}<=$4
                        AND {kind} {"='prompt'" if prompt else "IN ('prompt','response','tool.call','tool.result','command','file.read','file.write','network')"}
                    ORDER BY {stamp} {order},id {order} LIMIT $5""",
                    job["tenant_id"], ident, job["requested_since"], job["requested_through"], limit, conn=conn))
    records = sorted({row["id"]: row for row in records}.values(), key=lambda row: (row["time"], row["id"]))
    if len(records) > MAX_RECORDS:
        records = records[:1] + records[-(MAX_RECORDS - 1):]
    evidence, size = [], 2
    for record in records[:1] + list(reversed(records[1:])):
        safe = event_evidence(record)
        if not any(safe.get(key) for key in ("text", "command", "file", "network", "tool", "content")):
            continue
        text = json.dumps(safe, ensure_ascii=False)
        # Bound each record so the task description does not crowd out later work.
        if len(text) > 1200:
            safe = {"kind": record["kind"], "content": text[:1200], "truncated": True}
        cost = len(json.dumps(safe, ensure_ascii=False)) + (2 if evidence else 0)
        if size + cost > MAX_INPUT_CHARS:
            break
        evidence.append((record["time"], record["id"], safe))
        size += cost
    return [safe for _, _, safe in sorted(evidence, key=lambda item: item[:2])]


def generate(service, job, *, customer=False, transport=None):
    if customer:
        from .service_session_summaries import generate as customer_generate
        return customer_generate(service, job, transport=transport)
    from openaidr_api_client.validation.page_chat import MODEL
    from .service_costs import Call

    st, tenant = service.st, job["tenant_id"]
    summary = None
    try:
        connection = service.page_chat.connection
        if (connection is None or str(tenant) != connection.tenant_id
                or service.page_chat.cache_identity(tenant, connection=connection) != job["key_fingerprint"]):
            return
        evidence = collect(st, job)
        if evidence:
            with service.page_chat._admit(tenant, connection=connection):
                call = Call(st, tenant, "assistant", "openai", MODEL)
                failed = True
                try:
                    answer = json.dumps(service.page_chat.request_generation("/v1/summaries/generate", {
                        "kind": "session_activity", "evidence": evidence}, call, connection=connection))
                    summary = validate_answer(answer)["summary"]
                    failed = False
                finally:
                    call.finish(failed)
    except Exception:
        log.warning("Session activity summary generation deferred")
    finally:
        save(st, job, summary)


def save(st, job, summary, *, conn=None):
    tenant = job["tenant_id"]
    # A late response cannot replace a request for newer evidence or keys.
    return st.execute("""UPDATE session_activity_summaries SET summary=$3,
        state=CASE WHEN $3::text IS NULL THEN 'unavailable' ELSE 'ready' END,
        generated_at=now(),lease_token=NULL,refresh_after=now()+$4*interval '1 second'
        WHERE tenant_id=$1 AND session_id=$2 AND lease_token=$5
            AND requested_since=$6 AND requested_through=$7 AND key_fingerprint=$8 AND requested_event_count=$9
            AND time_zone=$10""",
        tenant, job["session_id"], summary, CACHE_SECONDS if summary else REFRESH_SECONDS,
        job["lease_token"], job["requested_since"], job["requested_through"], job["key_fingerprint"],
        job["requested_event_count"], job["time_zone"], conn=conn)


async def run(service, stop, *, customer=False):
    if customer:
        from .service_operations import contracts
        contracts()
    while not stop.is_set():
        try:
            job = await run_in_threadpool(claim, service.st, service.cfg.tenant_id or None)
            if job and not stop.is_set():
                await run_in_threadpool(partial(generate, customer=customer), service, job)
        except Exception:
            log.warning("Session activity summary worker unavailable")
        try:
            await asyncio.wait_for(stop.wait(), timeout=5)
        except TimeoutError:
            pass
