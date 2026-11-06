"""Dormant application research boundary; inventory leases remain caller-owned."""

import anyio
from openaidr_api_client.client import IntelligenceClient, Unavailable

from .service_operations import contracts


class ApplicationFailed(Unavailable):
    """A validated service error, distinct from an unknown or unusable reply."""


async def assess(operation, item, *, run_sync, transport=None, record_receipt=True):
    schema = contracts().ServiceApplicationAssessment
    if operation.service != "application_research":
        raise ValueError("Application operation service mismatch")
    payload = {"evidence": item["evidence"], "evidence_hash": item["evidence_hash"]}
    client = IntelligenceClient.from_connection(operation.connection, transport=transport)
    try:
        value = await client.request("/v1/services/apps/assess", payload, 4 << 20, 85, request_id=operation.id)
        operation.capture(value.get("billing"))
        parsed = schema.model_validate(value).root
        if parsed.evidence_hash != payload["evidence_hash"]:
            raise ValueError("Application evidence binding mismatch")
        if parsed.status == "error":
            if parsed.code == "rate_limited":
                raise ApplicationFailed("Application research rate limited", status_code=429,
                                  retry_after=str(parsed.retry_after) if parsed.retry_after is not None else None)
            raise ApplicationFailed("Application research unavailable")
        return parsed.result
    finally:
        with anyio.CancelScope(shield=True):
            try:
                await client.aclose()
            finally:
                if record_receipt:
                    await run_sync(operation.finish)
