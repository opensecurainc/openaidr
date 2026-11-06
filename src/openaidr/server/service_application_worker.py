"""Customer application research with durable claim admission and publication."""

import asyncio
from functools import partial
from uuid import UUID, uuid5

import anyio
import httpx
from openaidr_api_client.client import Unavailable

from . import application_classifier as classifier, service_applications
from .guardrail import calls
from .service_operations import ServiceOperation


async def classify(st, item, connection, cooldowns, key, run_sync, *, transport=None):
    tenant = item["tenant_id"]
    operation = ServiceOperation(st, tenant, "application_research", connection)
    scope = str(uuid5(UUID(tenant), "application-research.1:" + item["product_id"]))

    def admit(conn):
        return bool(st.many("""SELECT a.product_id FROM application_classifications a
            JOIN tenants t ON t.id=a.tenant_id AND t.status='active'
            WHERE a.tenant_id=$1 AND a.product_id=$2 AND a.claim_token=$3
                AND a.evidence_hash=$4 AND a.lease_until>clock_timestamp()
            FOR UPDATE OF a""", tenant, item["product_id"], item["claim_token"], item["evidence_hash"], conn=conn))

    def publish(conn):
        return classifier.finish(st, item, result, customer=True, conn=conn)

    admitted, published, result, failed = False, False, None, None
    try:
        await run_sync(partial(calls.begin, operation, scope,
            {field: item[field] for field in ("evidence", "evidence_hash")}, "", refresh=True, admit=admit))
        admitted = True
        try:
            result = await service_applications.assess(operation, item, run_sync=run_sync,
                                                       transport=transport, record_receipt=False)
            failed = False
        except service_applications.ApplicationFailed:
            failed = True
            raise
    except (httpx.HTTPStatusError, Unavailable) as exc:
        status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else exc.status_code
        retry_after = exc.response.headers.get("retry-after") if isinstance(exc, httpx.HTTPStatusError) else exc.retry_after
        if status == 429:
            loop = asyncio.get_running_loop()
            cooldowns[key] = max(cooldowns.get(key, 0), loop.time() + classifier.retry_delay(retry_after))
    except Exception:
        classifier.log.warning("Application classification deferred for a tenant")
    finally:
        with anyio.CancelScope(shield=True):
            if admitted:
                try:
                    published = await run_sync(partial(calls.finish, operation, failed=failed, publish=publish))
                except Exception:
                    # Keep known accounting if publication rolled back. The
                    # unresolved intent still prevents a replacement dispatch.
                    await run_sync(operation.finish)
            if not published:
                await run_sync(classifier.finish, st, item)
