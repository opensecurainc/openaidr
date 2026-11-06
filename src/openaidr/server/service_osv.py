"""Customer OSV batches admitted and published against their original claims."""

import asyncio
import json
from functools import partial

import anyio
from starlette.concurrency import run_in_threadpool

from . import osv
from .guardrail import calls
from .service_operations import ServiceOperation


async def tick(st, intelligence, tenant):
    if intelligence is None:
        return False
    if str(tenant) != intelligence.tenant_id:
        raise osv.Unavailable("Intelligence worker requires its bound tenant")
    client = await intelligence.client(run_sync=run_in_threadpool)
    rows = await run_in_threadpool(osv.claim, st, tenant)
    if not rows:
        return False
    await assess(st, client, rows)
    return True


async def assess(st, client, rows):
    tenant = client.tenant_id
    if any(row["tenant_id"] != tenant for row in rows):
        raise osv.Unavailable("Package claims require their bound tenant")
    queries, indices, valid = [], {}, []
    for row in rows:
        query, _ = osv.package_query(row)
        if query is None:
            await run_in_threadpool(osv.save, st, row, [])
            continue
        key = json.dumps(query, sort_keys=True)
        if key not in indices:
            indices[key] = len(queries)
            queries.append(query)
        valid.append((row, indices[key]))
    if not valid:
        return
    operation = ServiceOperation(st, tenant, "package_vulnerabilities", client.connection)
    scope = str(valid[0][0]["claim_token"])

    def admit(conn):
        for row, _ in valid:
            st.many("""SELECT claim_token FROM inventory_osv_packages
                WHERE tenant_id=$1 AND ecosystem=$2 AND identifier=$3 AND version=$4 FOR UPDATE""",
                tenant, *(row[field] for field in osv.KEY_FIELDS), conn=conn)
            if not st.many("""SELECT p.claim_token FROM inventory_osv_packages p
                JOIN tenants t ON t.id=p.tenant_id AND t.status='active'
                WHERE p.tenant_id=$1 AND p.ecosystem=$2 AND p.identifier=$3 AND p.version=$4
                    AND p.claim_token=$5 AND p.attempted_at=$6 AND p.next_check_at>clock_timestamp()""",
                tenant, *(row[field] for field in osv.KEY_FIELDS),
                row["claim_token"], row["attempted_at"], conn=conn):
                return False
        return True

    def publish(conn):
        complete = True
        for row, index in valid:
            result = results[index]
            if result["status"] != "complete":
                complete = False
                continue
            saved = osv.save(st, row, result["findings"], checked_at=result["checked_at"],
                             expires_at=result["expires_at"], conn=conn)
            complete = bool(saved) and complete
        return complete

    failed, published, results = None, False, None
    try:
        async with asyncio.timeout(30):
            results = await client.packages(operation, queries, scope_id=scope, run_sync=run_in_threadpool,
                                           admit=admit, record_receipt=False)
            failed = all(item["status"] == "unavailable" for item in results)
    except Exception:
        osv.log.warning("Inventory vulnerability assessment unavailable")
    finally:
        with anyio.CancelScope(shield=True):
            try:
                published = await run_in_threadpool(partial(calls.finish, operation, failed=failed, publish=publish))
            except Exception:
                await run_in_threadpool(operation.finish)
            if not published:
                for row, _ in valid:
                    await run_in_threadpool(osv.save, st, row, [], "OSV check unavailable; retry scheduled")
