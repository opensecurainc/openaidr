"""Customer gateway checks with bounded durable admission and publication."""

import asyncio
from functools import partial
import time
from uuid import UUID, uuid5

import anyio

from . import company_policy, gateways, service_billing, service_guardrail
from .guardrail import calls
from .guardrail.storage import _bounded_transaction, get_settings
from .service_operations import ServiceOperation


async def check(st, cfg, token, data, deadline, clients, run_sync):
    error = service_guardrail.contract()
    prepared = await run_sync(partial(gateways.prepare, st, cfg, token, data, deadline, customer=True))
    if "reply" in prepared:
        return prepared["reply"]
    row = prepared["row"]
    operation = ServiceOperation(st, row["tenant_id"], "guardrail", prepared["key"])
    scope = str(uuid5(UUID(row["gateway_id"]), "gateway-check.1:" + row["request_id"]))
    state = {"target_event": {"kind": "prompt", "source": prepared["kind"] + "_gateway",
                              "messages": row["messages"]},
             "prior_events": [], "context_limited": True}
    policy = prepared["company_policy"]["prompt"]

    def admit(conn):
        st.many("SELECT id FROM gateway_requests WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                row["tenant_id"], row["id"], conn=conn)
        gateway = gateways.principal(st, cfg, token, conn)
        return bool(gateway["version"] == row["settings_version"] and gateway["capture_content"]
            and st.get_policy(row["tenant_id"], conn=conn)["version"] == row["policy_version"]
            and get_settings(st, row["tenant_id"], conn)["version"] == row["risk_settings_version"]
            and company_policy.read(st, row["tenant_id"], conn=conn)["revision"] == row["company_policy_revision"]
            and st.many("""SELECT id FROM gateway_requests WHERE tenant_id=$1 AND id=$2
                AND status='pending' AND deadline_at>clock_timestamp()""", row["tenant_id"], row["id"], conn=conn))

    def begin():
        with _bounded_transaction(st, deadline) as conn:
            calls.begin(operation, scope, state, policy, admit=admit, conn=conn)

    assessment, failure, failed, reply = None, "", None, None

    def publish(conn):
        nonlocal reply
        reply = gateways.finish(st, cfg, token, prepared, assessment, failure, deadline, conn=conn)
        return reply[1] == 200

    def finish():
        try:
            with _bounded_transaction(st, deadline) as conn:
                calls.finish(operation, failed=failed, publish=publish, conn=conn)
                if reply is None:
                    return gateways.finish(st, cfg, token, prepared, None, failure or "provider_unavailable",
                                           deadline, conn=conn)
                return reply
        except Exception:
            # Accounting can survive a rolled-back publication, but recovery
            # must still release the caller's bounded database worker promptly.
            if operation.receipt is not None:
                try:
                    with _bounded_transaction(st, max(deadline, time.monotonic() + .05)) as conn:
                        service_billing.record(st, operation.tenant, operation.connection, operation.receipt,
                                               request_id=operation.id, service=operation.service, conn=conn)
                except Exception:
                    pass
            raise

    try:
        await run_sync(begin)
        seconds = max(0, deadline - time.monotonic() - .08)
        async with asyncio.timeout(seconds):
            assessment = await clients.assess(operation.tenant, operation.connection, state,
                                              request_id=operation.id, company_policy=policy, timeout=seconds)
            operation.capture(assessment.pop("billing"))
            failed = False
            if assessment["status"] != "scored":
                failure = "invalid_response"
    except error as exc:
        failure = exc.code
        if exc.billing is not None:
            operation.capture(exc.billing)
            failed = None if exc.code == "invalid_response" else True
    except TimeoutError:
        failure = "timeout"
    except Exception:
        failure = "provider_unavailable"
    finally:
        with anyio.CancelScope(shield=True):
            result = await run_sync(finish)
    return result
