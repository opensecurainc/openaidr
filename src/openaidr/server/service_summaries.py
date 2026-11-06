"""Dormant customer summaries with durable admission and atomic publication."""

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID, uuid5

from . import service_billing, service_generation
from .httpx import APIError
from .overview_summary import OverviewSummary
from .service_operations import ServiceOperation, contracts


def generate(operation, identity, data, publish, *, transport=None, admit=None):
    # A key rotation or a changed observation cannot release an unknown dispatch.
    # These scopes outlive the disposable summary cache and worker leases.
    if operation.service not in ("overview_summaries", "session_summaries"):
        raise ValueError("Not a queued summary service")
    scope = str(uuid5(UUID(operation.tenant), json.dumps([operation.service, identity], sort_keys=True)))
    _, _, _, payload = service_generation.prepare(operation, data)
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False,
                                      allow_nan=False).encode()).hexdigest()
    st, tenant = operation.store, operation.tenant
    with st.transaction() as conn:
        st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                   f"{operation.service}:{tenant}:{scope}", conn=conn)
        previous = st.one("""SELECT bool_or(outcome IS NULL) AS held,coalesce(max(attempt),0)+1 AS attempt
            FROM service_call_intents WHERE tenant_id=$1 AND service=$2 AND scope_id=$3""",
            tenant, operation.service, scope, conn=conn)
        if previous["held"]:
            raise APIError(503, "The previous summary request is unresolved.")
        if admit is not None and not admit(conn):
            raise APIError(503, "The summary request is no longer current.")
        st.execute("""INSERT INTO service_call_intents
            (tenant_id,request_id,service,origin,api_tenant_id,request_sha256,scope_id,attempt)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)""",
            tenant, operation.id, operation.service, operation.connection.origin,
            operation.connection.tenant_id, digest, scope,
            previous["attempt"], conn=conn)
    answer, failed = None, False
    try:
        answer = service_generation.request(operation, data, transport=transport, record_receipt=False)
    except service_generation.GenerationFailed:
        failed = True
        raise
    finally:
        try:
            published = finish(operation, answer, publish, failed=failed)
        except BaseException:
            # A failed publication leaves the intent held. Preserve independently
            # confirmed accounting even when the cache transaction rolled back.
            operation.finish()
            raise
    if not published:
        raise APIError(503, "The summary could not be saved.")
    return answer


def finish(operation, answer, publish, *, failed):
    if operation.receipt is None:
        return False
    st, tenant, connection = operation.store, operation.tenant, operation.connection
    with st.transaction() as conn:
        intent = st.one("""SELECT * FROM service_call_intents
            WHERE tenant_id=$1 AND request_id=$2 FOR UPDATE""", tenant, operation.id, conn=conn)
        if (intent["service"] != operation.service or intent["origin"] != connection.origin
                or intent["api_tenant_id"] != connection.tenant_id or intent["outcome"] is not None):
            raise ValueError("Summary dispatch identity changed")
        receipt = service_billing.record(st, tenant, connection, operation.receipt,
                                        request_id=operation.id, service=operation.service, conn=conn)
        published = answer is not None and receipt["state"] in ("disabled", "settled") and publish(conn, answer)
        if published or failed and receipt["state"] in ("disabled", "released"):
            st.execute("""UPDATE service_call_intents SET outcome=$3,completed_at=clock_timestamp()
                WHERE tenant_id=$1 AND request_id=$2""", tenant, operation.id,
                "completed" if published else "failed", conn=conn)
        return bool(published)


class CustomerOverviewSummary(OverviewSummary):
    def __init__(self, st, *, transport=None):
        contracts()
        super().__init__(st)
        self.transport = transport

    @staticmethod
    def _key(tenant, user, chat, *, fingerprint=None):
        tenant, roles, previous = OverviewSummary._key(tenant, user, chat, fingerprint=fingerprint)
        return tenant, roles, hashlib.sha256(("customer-overview-v1:" + previous).encode()).hexdigest()

    def _generate(self, tenant, key, chat, connection, sources):
        operation = ServiceOperation(self.st, tenant, "overview_summaries", connection)

        def publish(conn, answer):
            answer.update(sources=sources, generated_at=datetime.now(timezone.utc).isoformat())
            return self._save(key, answer, conn=conn)

        return generate(operation, list(key[1]), {"kind": "overview", "sources": sources},
                        publish, transport=self.transport)
