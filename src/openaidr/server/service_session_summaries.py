"""Dormant customer session summaries with durable admission and lease fences."""

from . import service_summaries, session_activity_summaries as summaries
from .service_operations import ServiceOperation, contracts


def generate(service, job, *, transport=None):
    contracts()
    st, tenant = service.st, job["tenant_id"]
    published = False
    try:
        chat, connection = service.page_chat, service.page_chat.connection
        if (connection is None or str(tenant) != connection.tenant_id
                or summaries.cache_identity(chat, tenant, connection, customer=True) != job["key_fingerprint"]):
            return
        evidence = summaries.collect(st, job)
        if not evidence:
            return
        operation = ServiceOperation(st, tenant, "session_summaries", connection)

        def admit(conn):
            return bool(st.many("""SELECT q.session_id FROM session_activity_summaries q
                JOIN tenants t ON t.id=q.tenant_id AND t.status='active'
                WHERE q.tenant_id=$1 AND q.session_id=$2 AND q.time_zone=$3 AND q.lease_token=$4
                    AND q.requested_since=$5 AND q.requested_through=$6 AND q.requested_event_count=$7
                    AND q.key_fingerprint=$8 AND q.refresh_after>now()
                FOR UPDATE OF q""", tenant, job["session_id"], job["time_zone"], job["lease_token"],
                job["requested_since"], job["requested_through"], job["requested_event_count"],
                job["key_fingerprint"], conn=conn))

        def publish(conn, answer):
            return summaries.save(st, job, answer["summary"], conn=conn)

        with chat._admit(tenant, connection=connection):
            service_summaries.generate(operation, [job["session_id"], job["time_zone"]],
                {"kind": "session_activity", "evidence": evidence}, publish, admit=admit, transport=transport)
        published = True
    except Exception:
        summaries.log.warning("Session activity summary generation deferred")
    finally:
        if not published:
            # This cache lease can expire or disappear; the durable intent above
            # continues to fence this session and time zone after cache cleanup.
            summaries.save(st, job, None)
