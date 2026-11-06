"""Dormant guardrail adapters with caller-owned selection, workers and pools."""

import asyncio
from functools import partial
import time

from openaidr_api_client.client import Unavailable

from .guardrail import calls


def contract():
    try:
        from openaidr_api_client.contracts.service_guardrail import GuardrailError
    except ImportError:
        raise Unavailable("Customer service SDK is unavailable") from None
    return GuardrailError


class WorkspaceClient:
    """Explicit customer selection using the caller's bounded storage context."""

    def __init__(self, st, tenant, cfg, *, clients):
        contract()
        self.st, self.tenant, self.cfg, self.clients = st, str(tenant), cfg, clients

    def select(self, *, conn=None):
        from .model_keys import guardrail_credential
        return guardrail_credential(self.st, self.tenant, self.cfg, conn=conn)


async def assess(operation, state, *, scope_id, clients, run_sync, company_policy="", timeout=None):
    error = contract()
    deadline = time.monotonic() + timeout if timeout is not None else None
    try:
        if operation.service != "guardrail":
            raise ValueError("Guardrail service required")
        await run_sync(calls.begin, operation, scope_id, state, company_policy)
        failed = None
        try:
            remaining = max(0, deadline - time.monotonic()) if deadline is not None else None
            result = await clients.assess(operation.tenant, operation.connection, state, request_id=operation.id,
                                          company_policy=company_policy, timeout=remaining)
            operation.capture(result.pop("billing"))
            failed = False
            return result
        except error as exc:
            if exc.billing is not None:
                operation.capture(exc.billing)
                failed = None if exc.code == "invalid_response" else True
            raise
        finally:
            if operation.receipt is not None:
                await asyncio.shield(run_sync(partial(calls.finish, operation, failed=failed)))
    except error:
        raise
    except Exception:
        raise error("provider_unavailable") from None


def request(operation, state, *, scope_id, clients, company_policy=""):
    error = contract()
    try:
        if operation.service != "guardrail":
            raise ValueError("Guardrail service required")
        calls.begin(operation, scope_id, state, company_policy)
        failed = None
        try:
            result = clients.assess(operation.tenant, operation.connection, state, request_id=operation.id,
                                   company_policy=company_policy)
            operation.capture(result.pop("billing"))
            failed = False
            return result
        except error as exc:
            if exc.billing is not None:
                operation.capture(exc.billing)
                failed = None if exc.code == "invalid_response" else True
            raise
        finally:
            calls.finish(operation, failed=failed)
    except error:
        raise
    except Exception:
        raise error("provider_unavailable") from None
