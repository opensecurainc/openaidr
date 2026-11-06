"""One tenant-scoped, ordered page of endpoint checks and gateway requests."""

from .. import customer_views, gateways, hook_policy
from ..httpx import APIError, require
from ..store import Cursor, decode_cursor


def checks(st, tenant, query):
    if any(key in query for key in ("range", "until", "identity", "product", "risk", "decision", "session", "boundary")):
        from .flow import checks as scoped_checks

        return scoped_checks(st, tenant, query)
    source = query.get("source", "all")
    require(source in ("all", "endpoints", "gateways"), "invalid activity source")
    try:
        limit = int(query.get("limit", "100"))
        raw, separator, cursor_source = query.get("cursor", "").partition(":")
        cursor = decode_cursor(raw)
        require(not raw or separator and cursor_source in ("endpoint", "gateway"), "invalid cursor")
        require(bool(raw) == bool(separator), "invalid cursor")
    except (ValueError, TypeError):
        raise APIError(400, "invalid pagination") from None
    require(1 <= limit <= 200, "limit must be 1 to 200")
    sources = []
    if source != "gateways":
        fields, tables, conditions = hook_policy.decision_query(classified=True)
        sources.append("SELECT c.created_at,c.id,'endpoint'::text AS source,to_jsonb(c) AS record FROM (SELECT "
                       + fields + " FROM " + tables + " WHERE " + " AND ".join(conditions) + """
                       AND ($2::timestamptz IS NULL OR (c.created_at,c.id,'endpoint'::text)<($2,$3::uuid,$4::text))
                       ORDER BY c.created_at DESC,c.id DESC LIMIT $5) c""")
    if source != "endpoints":
        sources.append("""SELECT r.created_at,r.id,'gateway'::text AS source,to_jsonb(r) AS record FROM (
            SELECT r.*,g.name AS gateway_name,g.kind AS gateway_kind FROM gateway_requests r JOIN gateway_instances g
            ON g.id=r.gateway_id AND g.tenant_id=r.tenant_id WHERE r.tenant_id=$1
            AND (r.status<>'pending' OR r.deadline_at<=clock_timestamp())
            AND ($2::timestamptz IS NULL OR (r.created_at,r.id,'gateway'::text)<($2,$3::uuid,$4::text))
            ORDER BY r.created_at DESC,r.id DESC LIMIT $5) r""")
    rows = st.many("SELECT * FROM (" + " UNION ALL ".join(sources) + """
        ) checks
        ORDER BY created_at DESC,id DESC,source DESC LIMIT $5""",
        tenant, cursor.time, cursor.id or None, cursor_source, limit + 1)
    items = []
    for row in rows[:limit]:
        record = row["record"]
        if row["source"] == "gateway":
            if record["status"] == "pending":
                record.update(status="unavailable", failure_reason="timeout")
            record = gateways._request(record, detail=True)
        else:
            record["assessment"] = customer_views.guardrail_assessment(record["assessment"])
        items.append({**record, "source": row["source"]})
    last = rows[limit - 1] if len(rows) > limit else None
    return {"items": items, "next_cursor":
            Cursor(last["created_at"], last["id"]).encode() + ":" + last["source"] if last else ""}
