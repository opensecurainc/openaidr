"""Durable service dispatch identities; no request content is retained here."""

import hashlib
import json
from contextlib import nullcontext
from uuid import UUID

from openaidr_api_client.client import Unavailable

from .. import service_billing


def begin(operation, scope_id, state, policy, *, refresh=False, admit=None, conn=None):
    if not isinstance(scope_id, str) or str(UUID(scope_id)) != scope_id:
        raise ValueError("Invalid service scope identity")
    digest = hashlib.sha256(json.dumps([state, policy], sort_keys=True, ensure_ascii=False,
                                      allow_nan=False).encode()).hexdigest()
    st, tenant, service = operation.store, operation.tenant, operation.service
    with nullcontext(conn) if conn is not None else st.transaction() as conn:
        st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", f"{service}:{tenant}:{scope_id}", conn=conn)
        previous = st.many("""SELECT outcome,attempt FROM service_call_intents
            WHERE tenant_id=$1 AND service=$3 AND scope_id=$2
            ORDER BY created_at DESC,request_id DESC LIMIT 1""", tenant, scope_id, service, conn=conn)
        if previous and previous[0]["outcome"] not in (("failed", "completed") if refresh else ("failed",)):
            raise Unavailable("Service dispatch is already completed or unresolved")
        if admit is not None and not admit(conn):
            raise Unavailable("Service dispatch claim is no longer current")
        st.execute("""INSERT INTO service_call_intents
            (tenant_id,request_id,service,origin,api_tenant_id,request_sha256,scope_id,attempt)
            VALUES($1,$2,$8,$3,$4,$5,$6,$7)""", tenant, operation.id, operation.connection.origin,
            operation.connection.tenant_id, digest, scope_id,
            previous[0]["attempt"] + 1 if previous else 1, service, conn=conn)


def finish(operation, *, failed, publish=None, conn=None):
    if operation.receipt is None:
        return False
    st, tenant, connection = operation.store, operation.tenant, operation.connection
    with nullcontext(conn) if conn is not None else st.transaction() as conn:
        intent = st.one("""SELECT * FROM service_call_intents
            WHERE tenant_id=$1 AND request_id=$2 FOR UPDATE""", tenant, operation.id, conn=conn)
        if (intent["service"] != operation.service or intent["origin"] != connection.origin
                or intent["api_tenant_id"] != connection.tenant_id):
            raise ValueError("Service dispatch connection changed")
        receipt = service_billing.record(st, tenant, connection, operation.receipt,
                                        request_id=operation.id, service=operation.service, conn=conn)
        completed = failed is False and receipt["state"] in ("disabled", "settled")
        if publish is not None:
            completed = completed and intent["outcome"] is None and bool(publish(conn))
        if completed or failed is True and receipt["state"] in ("disabled", "released"):
            st.execute("""UPDATE service_call_intents SET outcome=$3,completed_at=clock_timestamp()
                WHERE tenant_id=$1 AND request_id=$2 AND outcome IS NULL""", tenant, operation.id,
                "failed" if failed else "completed", conn=conn)
        return completed
