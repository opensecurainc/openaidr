"""Customer assessments bound to registered actions and retained generations."""

import asyncio
from datetime import datetime, timezone
import time
from uuid import UUID, uuid5

import anyio

from . import service_billing, service_guardrail
from .guardrail import calls
from .guardrail.inline import _unavailable, context_changed
from .guardrail.storage import _bounded_transaction
from .service_operations import ServiceOperation


async def assess(worker, sensor, check, event, client):
    error = service_guardrail.contract()
    st, tenant = worker.st, event["tenant_id"]
    deadline = time.monotonic() + max(0, (event["deadline_at"] - datetime.now(timezone.utc)).total_seconds())
    scope = str(uuid5(UUID(event["registration_id"]), "inline-check.1:" + event["logical_id"]))
    operation, failed, assessment, acquired = None, None, _unavailable("provider_unavailable"), False

    def authorize(conn):
        worker._authorize(sensor, event["registration_id"], conn)
        settings, _ = worker._versions(sensor, check["settings_version"], check["policy_version"], conn)
        if context_changed(st, event, settings, conn):
            raise error("context_changed")

    def begin():
        nonlocal operation
        with _bounded_transaction(st, deadline, wait_for_capacity=True) as conn:
            authorize(conn)
            row = st.one("SELECT * FROM inline_guardrail_events WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                         tenant, event["id"], conn=conn)
            if (row["status"] != "pending" or row["started_at"] or row["claim_token"] != event["claim_token"]
                    or row["assessment_generation"] != check["assessment_generation"]
                    or row["context_enabled"] and not row["context_pinned"]):
                raise error("dispatch_already_recorded")
            connection = client.select(conn=conn)
            if connection is None:
                raise error("provider_unavailable")
            candidate = ServiceOperation(st, tenant, "guardrail", connection)
            calls.begin(candidate, scope, row["prepared_state"], row["company_policy"]["prompt"],
                refresh=row["assessment_generation"] > 1, conn=conn,
                admit=lambda conn: st.scalar("SELECT $1::timestamptz>clock_timestamp()", row["deadline_at"], conn=conn))
            st.execute("UPDATE inline_guardrail_events SET started_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2",
                       tenant, row["id"], conn=conn)
        operation = candidate

    def publish(conn):
        authorize(conn)
        return worker._finish(event, assessment, conn=conn)

    def finish():
        try:
            # A late result may only persist an unavailable assessment and its
            # known receipt. It cannot become a completed usable dispatch.
            with _bounded_transaction(st, max(deadline, time.monotonic()+.05), wait_for_capacity=True) as conn:
                if operation is None or not calls.finish(operation, failed=failed, publish=publish, conn=conn):
                    worker._finish(event, _unavailable(assessment.get("reason") or "provider_unavailable"), conn=conn)
        except Exception:
            if operation is not None and operation.receipt is not None:
                try:
                    with _bounded_transaction(st, time.monotonic()+.05) as conn:
                        service_billing.record(st, tenant, operation.connection, operation.receipt,
                            request_id=operation.id, service=operation.service, conn=conn)
                except Exception:
                    pass
            raise

    try:
        settings = check["policy_snapshot"]["settings"]
        if not worker.cfg.inline_guardrails or not settings["enabled"]:
            raise error("disabled")
        if client is None or client.tenant != tenant:
            raise error("provider_unavailable")
        if event["target_body"]["kind"] == "tool.result" and not event["captured_context"]["matched_tool_call"]:
            raise error("missing_tool_call")
        async with asyncio.timeout(max(0, deadline-time.monotonic()-.05)):
            await worker.capacity.acquire()
            acquired = True
            await worker.run_sync(begin)
            seconds = max(0, deadline-time.monotonic()-.05)
            assessment = await client.clients.assess(tenant, operation.connection, event["prepared_state"],
                request_id=operation.id, company_policy=event["company_policy"]["prompt"], timeout=seconds)
            operation.capture(assessment.pop("billing"))
            failed = False
            if assessment["status"] != "scored":
                assessment = _unavailable("insufficient_evidence")
    except error as exc:
        if operation is not None and exc.billing is not None:
            operation.capture(exc.billing)
            failed = None if exc.code == "invalid_response" else True
        assessment = _unavailable(exc.code)
    except TimeoutError:
        assessment = _unavailable("timeout")
    except asyncio.CancelledError:
        assessment = _unavailable("cancelled")
        raise
    except Exception:
        assessment = _unavailable("provider_unavailable")
    finally:
        if acquired:
            worker.capacity.release()
        with anyio.CancelScope(shield=True):
            await worker.run_sync(finish)
