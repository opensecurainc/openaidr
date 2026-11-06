"""Customer hook assessments with one connection and atomic decision storage."""

import asyncio
from functools import partial
import time
from uuid import UUID, uuid5

import anyio
from openaidr_api_client.validation.web_risk import extract_urls

from . import hook_policy, service_billing, service_guardrail
from .guardrail import calls
from .guardrail.storage import _bounded_transaction
from .service_operations import ServiceOperation
from .store import NotFound


async def check(st, row, created, deadline, client, run_sync, *, link_client=None):
    error = service_guardrail.contract()
    if row["status"] != "pending":
        return hook_policy._reply(row)
    if not created:
        def saved():
            with _bounded_transaction(st, deadline, wait_for_capacity=True) as conn:
                rows = st.many("SELECT * FROM ordinary_hook_checks WHERE id=$1 AND tenant_id=$2",
                               row["id"], row["tenant_id"], conn=conn)
                return rows[0] if rows else {**row, "status": "unavailable"}

        while row["status"] == "pending" and time.monotonic() < deadline:
            await asyncio.sleep(.02)
            row = await run_sync(saved)
        return hook_policy._reply(row)
    operations, results, failures = {}, {}, {}
    scope = str(uuid5(UUID(row["sensor_id"]), "hook-check.1:" + row["request_id"]))
    settings = row["risk_settings"]
    policy = settings.get("company_policy", {}).get("prompt", "")
    availability = "unsupported_evidence" if settings.get("retained_evidence_id") else settings.get("availability", "available")
    urls, skipped = extract_urls(row["actions"])
    include_links = bool(link_client and settings.get("link_detection_enabled"))

    def admit(conn):
        st.many("SELECT id FROM ordinary_hook_checks WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                row["tenant_id"], row["id"], conn=conn)
        return bool(st.many("""SELECT h.id FROM ordinary_hook_checks h
            JOIN sensors s ON s.id=h.sensor_id AND s.tenant_id=h.tenant_id
            JOIN tenants t ON t.id=h.tenant_id AND t.status='active'
            WHERE h.tenant_id=$1 AND h.id=$2 AND h.status='pending' AND h.deadline_at>clock_timestamp()
                AND NOT s.disabled AND s.deleted_at IS NULL""", row["tenant_id"], row["id"], conn=conn))

    def begin(state):
        with _bounded_transaction(st, deadline, wait_for_capacity=True) as conn:
            if client is None or client.tenant != row["tenant_id"]:
                raise error("provider_unavailable")
            connection = client.select(conn=conn)
            if connection is None:
                raise error("provider_unavailable")
            for service, value, text in (("guardrail", state, policy), ("url_reputation", row["actions"], availability)):
                if service == "url_reputation" and not (include_links and urls):
                    continue
                operation = ServiceOperation(st, row["tenant_id"], service, connection)
                calls.begin(operation, scope, value, text, admit=admit, conn=conn)
                operations[service], failures[service] = operation, None

    async def guardrail(state):
        operation = operations["guardrail"]
        try:
            seconds = max(0, deadline - time.monotonic() - .05)
            result = await client.clients.assess(operation.tenant, operation.connection, state,
                request_id=operation.id, company_policy=policy, timeout=seconds)
            operation.capture(result.pop("billing"))
            results["guardrail"], failures["guardrail"] = result, False
        except error as exc:
            if exc.billing is not None:
                operation.capture(exc.billing)
                failures["guardrail"] = None if exc.code == "invalid_response" else True
            results["guardrail"] = {"status": "unavailable", "reason": exc.code}

    async def reputation():
        operation = operations.get("url_reputation") or ServiceOperation(
            st, row["tenant_id"], "url_reputation", operations["guardrail"].connection)

        async def received(receipt):
            operation.capture(receipt)

        result = await link_client.bound(operation.connection).client.assess(operation.tenant, row["actions"],
            availability, request_id=operation.id, receipt=received)
        failures["url_reputation"] = (None if "intelligence_unavailable" in result["reasons"]
                                       else result["status"] == "unavailable")
        results["url_reputation"] = result

    def finish():
        try:
            with _bounded_transaction(st, deadline, wait_for_capacity=True) as conn:
                usable = {name: calls.finish(operation, failed=failures[name], publish=lambda conn: True, conn=conn)
                          for name, operation in operations.items()}
                assessment = (results["guardrail"] if usable.get("guardrail")
                              else {"status": "unavailable", "reason": results.get("guardrail", {}).get("reason", "provider_unavailable")})
                if include_links:
                    assessment["links"] = (results["url_reputation"]
                        if usable.get("url_reputation") or not urls and "url_reputation" in results
                        else {"profile": "url-reputation.1", "status": "unavailable", "checked": 0,
                              "skipped": skipped, "failed": len(urls), "matches": [], "reasons": ["intelligence_unavailable"]})
                return hook_policy.finish(st, row, assessment, None, None, deadline, conn=conn)
        except Exception as exc:
            for operation in operations.values():
                if operation.receipt is not None:
                    try:
                        with _bounded_transaction(st, max(deadline, time.monotonic()+.05)) as conn:
                            service_billing.record(st, operation.tenant, operation.connection, operation.receipt,
                                request_id=operation.id, service=operation.service, conn=conn)
                    except Exception:
                        pass
            if isinstance(exc, NotFound):
                return hook_policy._reply(row)
            raise

    tasks = []
    try:
        if settings.get("retained_evidence_id"):
            raise error("unsupported_evidence")
        _, state = await run_sync(partial(hook_policy.assessment_input, st, row, deadline, customer=True))
        await run_sync(begin, state)
        async with asyncio.timeout(max(0, deadline - time.monotonic() - .05)):
            tasks.append(asyncio.create_task(guardrail(state)))
            if include_links:
                tasks.append(asyncio.create_task(reputation()))
            await asyncio.gather(*tasks, return_exceptions=True)
    except error as exc:
        results["guardrail"] = {"status": "unavailable", "reason": exc.code}
    except TimeoutError:
        results.setdefault("guardrail", {"status": "unavailable", "reason": "timeout"})
    except Exception:
        results.setdefault("guardrail", {"status": "unavailable", "reason": "provider_unavailable"})
    finally:
        with anyio.CancelScope(shield=True):
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            reply = await run_sync(finish)
    return reply
