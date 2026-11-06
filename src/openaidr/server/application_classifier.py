"""Search-backed application classification, independent of organization approval."""

import asyncio
import hashlib
import logging
from datetime import timedelta
from functools import partial

import httpx
from psycopg.types.json import Jsonb
from starlette.concurrency import run_in_threadpool

from openaidr_api_client.validation.applications import (
    SCHEMA as SCHEMA,
    _url as _url,
    parse_classification as parse_classification,
    cited_urls as cited_urls,
    retry_delay as retry_delay,
)

from . import application_review
from openaidr_api_client.client import IntelligenceClient, Unavailable
from .intelligence import selected_connection
from .store import new_id, now

log = logging.getLogger(__name__)


async def classify_remote(item, connection, call):
    from openaidr_api_client.validation.applications import validate_assessment
    from .service_costs import validate_response_usage

    client = IntelligenceClient.from_connection(connection)
    try:
        value = await client.request("/v1/apps/assess", {
            "evidence": item["evidence"], "evidence_hash": item["evidence_hash"],
        }, 4 << 20, 85)
    finally:
        await client.aclose()
    if value.get("evidence_hash") != item["evidence_hash"]:
        raise ValueError("Application evidence binding mismatch")
    if value.get("usage") is not None:
        call.payload = validate_response_usage(value["usage"])
    if value.get("status") == "error":
        if value.get("code") == "rate_limited":
            delay = value.get("retry_after")
            raise Unavailable("Application research rate limited", status_code=429,
                              retry_after=str(delay) if type(delay) in (int, float) else None)
        raise Unavailable("Application research unavailable")
    if value.get("status") != "completed" or set(value) != {
            "status", "evidence_hash", "result", "source_urls", "usage"}:
        raise ValueError("Invalid application research response")
    return validate_assessment(value["result"], value["source_urls"])


def claim(st, tenant):
    rows = st.many(
        """UPDATE application_classifications SET claim_token=$2,
            lease_until=clock_timestamp()+interval '2 minutes'
        WHERE (tenant_id,product_id)=(
            SELECT tenant_id,product_id FROM application_classifications
            WHERE tenant_id=$1 AND (next_attempt_at<=clock_timestamp()
              OR (checked_at IS NOT NULL AND last_error='' AND
                  (assessment_checked_at IS DISTINCT FROM checked_at
                   OR (needs_attention IS DISTINCT FROM false
                       AND (software_type IS NULL OR software_type IN ('application','command_line_tool'))
                       AND ((assessment->'risk'->>'score' IS NULL
                             AND NOT COALESCE(assessment->'risk' ? 'provisional_score', false))
                            OR NOT COALESCE(assessment ? 'report', false))))))
              AND (lease_until IS NULL OR lease_until<clock_timestamp())
            ORDER BY next_attempt_at,product_id FOR UPDATE SKIP LOCKED LIMIT 1)
        RETURNING *""", tenant, new_id(),
    )
    return rows[0] if rows else None


def finish(st, item, result=None, *, customer=False, conn=None):
    if result is None:
        # A temporary failure never clears a prior classification or an approval.
        return st.execute(
            """UPDATE application_classifications SET last_error='classification_unavailable',
                next_attempt_at=clock_timestamp()+interval '1 hour',claim_token=NULL,lease_until=NULL
            WHERE tenant_id=$1 AND product_id=$2 AND claim_token=$3 AND evidence_hash=$4""",
            item["tenant_id"], item["product_id"], item["claim_token"], item["evidence_hash"], conn=conn,
        )
    if customer:
        model, usage = "", {}
    else:
        from openaidr_api_client.validation.applications import MODEL
        model, usage = MODEL, result["usage"]
    return st.execute(
        """UPDATE application_classifications SET needs_attention=$5,reason=$6,sources=$7,
            checked_at=statement_timestamp(),next_attempt_at=$8,model=$9,usage=$10,
            last_error='',claim_token=NULL,lease_until=NULL,category=$11,
            software_type=$12,display_name=$13,assessment=$14,
            assessment_checked_at=statement_timestamp()
        WHERE tenant_id=$1 AND product_id=$2 AND claim_token=$3 AND evidence_hash=$4""",
        item["tenant_id"], item["product_id"], item["claim_token"], item["evidence_hash"],
        result["needs_attention"], result["reason"], Jsonb(result["sources"]),
        now() + timedelta(days=30 if result["needs_attention"] is False or result["assessment"]["risk"]["score"] is not None else 1),
        model, Jsonb(usage), result["category"],
        result["software_type"], result["display_name"] or "",
        Jsonb(result["assessment"]), conn=conn,
    )


def refresh_inventory(st, tenant):
    if st.scalar("""SELECT EXISTS(SELECT 1 FROM application_classification_scans
        WHERE tenant_id=$1 AND next_scan_at>clock_timestamp())""", tenant):
        return False
    with st.transaction() as conn:
        # One scanner per tenant across API replicas, including empty inventories.
        if not st.scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))",
                         "application-classification-scan:" + tenant, conn=conn):
            return False
        due = st.many("""INSERT INTO application_classification_scans(tenant_id,next_scan_at)
            VALUES($1,clock_timestamp()+interval '5 minutes')
            ON CONFLICT(tenant_id) DO UPDATE SET next_scan_at=EXCLUDED.next_scan_at
            WHERE application_classification_scans.next_scan_at<=clock_timestamp()
            RETURNING tenant_id""", tenant, conn=conn)
        if not due:
            return False
        products = application_review.observed(st, tenant, conn=conn)
        application_review.sync(st, tenant, products, conn=conn)
    return True


async def run_once(st, cfg, tenant, cooldowns=None, run_sync=run_in_threadpool, *, customer=False, transport=None):
    if customer:
        from .service_operations import contracts
        contracts()
    if not cfg.application_classification:
        return False
    connection = await run_sync(selected_connection, cfg, st)
    if connection is None or str(tenant) != connection.tenant_id:
        return False
    key = "intelligence:" + hashlib.sha256((connection.origin + ":" + connection.tenant_id).encode()).hexdigest()
    if cooldowns is None:
        cooldowns = {}
    loop = asyncio.get_running_loop()
    if cooldowns.get(key, 0) > loop.time():
        return False
    cooldowns.pop(key, None)
    await run_sync(refresh_inventory, st, tenant)
    item = await run_sync(claim, st, tenant)
    if not item:
        return False
    # Another request with this credential may have received a 429 while this
    # worker was claiming. Do not submit the newly claimed item during backoff.
    if cooldowns.get(key, 0) > loop.time():
        await run_sync(
            st.execute,
            """UPDATE application_classifications SET claim_token=NULL,lease_until=NULL
            WHERE tenant_id=$1 AND product_id=$2 AND claim_token=$3 AND evidence_hash=$4""",
            item["tenant_id"], item["product_id"], item["claim_token"], item["evidence_hash"],
        )
        return False
    if customer:
        from .service_application_worker import classify
        await classify(st, item, connection, cooldowns, key, run_sync, transport=transport)
        return True
    from openaidr_api_client.validation.applications import MODEL
    from .service_costs import Call

    call = await run_sync(partial(Call, st, tenant, "asset_management", "openai", MODEL, web_search=True))
    failed = True
    try:
        result = await classify_remote(item, connection, call)
        failed = False
    except (httpx.HTTPStatusError, Unavailable) as exc:
        status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else exc.status_code
        retry_after = exc.response.headers.get("retry-after") if isinstance(exc, httpx.HTTPStatusError) else exc.retry_after
        if status == 429:
            cooldowns[key] = max(cooldowns.get(key, 0), loop.time() + retry_delay(retry_after))
        await run_sync(finish, st, item)
    except Exception:
        await run_sync(finish, st, item)
    else:
        await run_sync(finish, st, item, result)
    finally:
        await run_sync(call.finish, failed)
    return True


async def _worker(st, cfg, stop, cooldowns, run_sync, *, customer=False):
    while not stop.is_set():
        worked = False
        try:
            tenants = await run_sync(partial(
                st.many, "SELECT DISTINCT tenant_id FROM sensors WHERE deleted_at IS NULL "
                         "AND ($1='' OR tenant_id::text=$1)", cfg.tenant_id,
            ))
            for tenant in tenants:
                if stop.is_set():
                    break
                try:
                    worked = await run_once(st, cfg, tenant["tenant_id"], cooldowns, run_sync, customer=customer) or worked
                except Exception:
                    log.warning("Application classification deferred for a tenant")
        except Exception:
            log.warning("Application classification deferred")
        if worked:
            continue
        try:
            await asyncio.wait_for(stop.wait(), timeout=10)
        except TimeoutError:
            pass


async def run(st, cfg, stop, *, customer=False):
    if customer:
        from .service_operations import contracts
        contracts()
    if not cfg.application_classification:
        return
    # All slots share credential backoff, including tenants using the same key.
    # TaskGroup joins every slot on cancellation before the database is closed.
    cooldowns = {}
    # Reserve most shared database connections and thread tokens for HTTP work.
    # A one-connection deployment remains serial at the database boundary.
    database_slots = asyncio.Semaphore(max(1, min(4, cfg.db_pool_size // 2)))

    async def run_sync(function, *args):
        async with database_slots:
            return await run_in_threadpool(function, *args)

    connection = await run_sync(selected_connection, cfg, st)
    if connection is None:
        return
    # Acquire service capacity before claiming two-minute leases.
    concurrency = min(cfg.application_classification_concurrency, 8)
    async with asyncio.TaskGroup() as group:
        for _ in range(concurrency):
            group.create_task(_worker(st, cfg, stop, cooldowns, run_sync, customer=customer))
