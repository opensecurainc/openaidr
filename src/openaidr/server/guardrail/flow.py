"""Complete, tenant-scoped activity aggregates and bounded drill-down lists."""

from datetime import timedelta

from .. import customer_views, gateways, hook_policy
from ..httpx import APIError, parse_time, require
from ..store import Cursor, decode_cursor, now

RANGES = {"15m": timedelta(minutes=15), "1h": timedelta(hours=1), "24h": timedelta(days=1)}
RISKS = ("none", "secret_exfiltration", "data_exfiltration", "destructive_command", "supply_chain",
         "excessive_agency", "hallucination", "unknown", "unassessed")
DECISIONS = ("allow", "ask", "deny", "warn", "unavailable", "unknown")

# Read only identity and grouping fields here. Full action evidence and delivery
# receipts are fetched only for the requested page of checks.
CTE = """
WITH activity AS (
    SELECT c.id,c.created_at,'endpoint'::text AS source,c.product,
        'endpoint:' || c.product AS product_key,
        CASE WHEN COALESCE(c.actions->0->'agent'->>'account','')<>''
            THEN jsonb_build_array('account',c.actions->0->'agent'->>'account')::text
            ELSE jsonb_build_array('sensor',c.sensor_id,s.username)::text END AS identity_key,
        jsonb_build_object('source','endpoint','account',COALESCE(c.actions->0->'agent'->>'account',''),
            'username',s.username,'hostname',s.hostname) AS identity,
        jsonb_build_array('endpoint',c.sensor_id,c.product,COALESCE(NULLIF(c.session_id,''),c.id::text))::text AS session_key,
        COALESCE(NULLIF(c.actions->0->'session'->>'cwd',''),NULLIF(s.hostname,''),c.session_id) AS detail,
        c.hook_event AS boundary,c.mode,
        CASE WHEN c.status<>'evaluated' THEN 'unavailable'
            ELSE COALESCE(c.evaluated_decision,'unknown') END AS decision,
        CASE WHEN c.status='pending' OR c.assessment->>'status' IS DISTINCT FROM 'scored' THEN 'unassessed'
            WHEN c.assessment->>'category'=ANY($5) THEN c.assessment->>'category' ELSE 'unknown' END AS risk
    FROM ordinary_hook_checks c JOIN sensors s ON s.id=c.sensor_id AND s.tenant_id=c.tenant_id
    WHERE c.tenant_id=$1 AND c.created_at>=$2 AND c.created_at<$3
        AND c.deadline_at IS NOT NULL AND (c.status<>'pending' OR c.deadline_at<=$4)
        AND $6 IN ('all','endpoints')
    UNION ALL
    SELECT r.id,r.created_at,'gateway',g.kind,'gateway:' || g.kind,
        jsonb_build_array('gateway',r.gateway_id,COALESCE(NULLIF(r.metadata->>'consumer_id',''),r.id::text))::text,
        jsonb_build_object('source','gateway','gateway_name',g.name,
            'consumer_id',COALESCE(r.metadata->>'consumer_id',''),
            'consumer_name',COALESCE(r.metadata->>'consumer_name','')),
        jsonb_build_array('gateway',r.gateway_id,r.node_id,COALESCE(NULLIF(r.metadata->>'route_id',''),r.id::text),
            COALESCE(NULLIF(r.metadata->>'consumer_id',''),r.id::text),COALESCE(r.metadata->>'application_name',''))::text,
        g.name || ' · Route: ' || COALESCE(NULLIF(r.metadata->>'route_id',''),'Not reported')
            || ' · Node: ' || r.node_id,
        'GatewayRequest',r.mode,
        CASE WHEN r.status<>'evaluated' THEN 'unavailable' ELSE COALESCE(r.evaluated_decision,'unknown') END,
        CASE WHEN r.status='pending' OR r.assessment->>'status' IS DISTINCT FROM 'scored' THEN 'unassessed'
            WHEN r.assessment->>'category'=ANY($5) THEN r.assessment->>'category' ELSE 'unknown' END
    FROM gateway_requests r JOIN gateway_instances g ON g.id=r.gateway_id AND g.tenant_id=r.tenant_id
    WHERE r.tenant_id=$1 AND r.created_at>=$2 AND r.created_at<$3
        AND (r.status<>'pending' OR r.deadline_at<=$4) AND $6 IN ('all','gateways')
), filtered AS MATERIALIZED (
    SELECT * FROM activity WHERE ($7='' OR identity_key=$7) AND ($8='' OR product_key=$8)
        AND ($9='' OR risk=$9) AND ($10='' OR decision=$10) AND ($11='' OR session_key=$11)
        AND ($12='' OR boundary=$12)
)
"""

COUNTS = """count(*)::bigint AS checks,count(DISTINCT identity_key)::bigint AS identities,
    count(DISTINCT session_key)::bigint AS sessions,
    count(*) FILTER (WHERE risk NOT IN ('none','unknown','unassessed'))::bigint AS flagged,
    count(*) FILTER (WHERE decision='unavailable')::bigint AS failed"""


def _scope(tenant, query):
    source, period = query.get("source", "all"), query.get("range", "1h")
    require(source in ("all", "endpoints", "gateways"), "invalid activity source")
    require(period in RANGES, "invalid activity range")
    current = now()
    try:
        until = parse_time(query["until"]) if query.get("until") else current
        require(until.tzinfo is not None and until <= current + timedelta(minutes=1), "invalid activity window")
        since = until - RANGES[period]
    except (ValueError, TypeError, OverflowError):
        raise APIError(400, "invalid activity window") from None
    filters = [query.get(key, "") for key in ("identity", "product", "risk", "decision", "session", "boundary")]
    require(all(isinstance(value, str) and len(value) <= 8192 for value in filters), "invalid activity filter")
    require(not filters[2] or filters[2] in RISKS, "invalid risk category")
    require(not filters[3] or filters[3] in DECISIONS, "invalid decision")
    return [tenant, since, until, current, list(RISKS[:-1]), source, *filters]


def _groups(column):
    # column is selected from two constants by the caller, never query text.
    return "SELECT " + column + " AS key," + COUNTS + """,
        (array_agg(identity ORDER BY created_at DESC,id DESC,source DESC))[1] AS identity,
        (array_agg(detail ORDER BY created_at DESC,id DESC,source DESC))[1] AS detail,
        (array_agg(product ORDER BY created_at DESC,id DESC,source DESC))[1] AS product,
        (array_agg(product_key ORDER BY created_at DESC,id DESC,source DESC))[1] AS product_key,
        (array_agg(source ORDER BY created_at DESC,id DESC,source DESC))[1] AS source,
        max(created_at) AS last_seen,
        string_agg(DISTINCT identity::text || ' ' || detail || ' ' || product,' ') AS search_text
        FROM filtered GROUP BY """ + column


def summary(st, tenant, query):
    args = _scope(tenant, query)
    view = query.get("view", "identities")
    require(view in ("identities", "sessions", "checks"), "invalid activity view")
    search = query.get("search", "").strip()
    require(len(search) <= 256, "search is too long")
    try:
        limit, offset = int(query.get("limit", "20")), int(query.get("offset", "0"))
    except (ValueError, TypeError):
        raise APIError(400, "invalid pagination") from None
    require(1 <= limit <= 100 and 0 <= offset <= 1_000_000, "invalid pagination")
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        conn.execute("SET LOCAL statement_timeout = '5s'")
        totals = st.one(CTE + "SELECT " + COUNTS + """,
            count(*) FILTER (WHERE boundary='UserPromptSubmit')::bigint AS prompts,
            count(*) FILTER (WHERE boundary='PreToolUse')::bigint AS tool_calls,
            count(*) FILTER (WHERE boundary IN ('PostToolUse','PostToolUseFailure'))::bigint AS tool_results,
            count(*) FILTER (WHERE source='gateway')::bigint AS gateway_requests,
            count(*) FILTER (WHERE mode='shadow')::bigint AS shadow,
            count(*) FILTER (WHERE mode='enforce')::bigint AS enforce
            FROM filtered""", *args, conn=conn)
        grouped = st.many(CTE + "SELECT product_key,product,source,risk,decision,count(*)::bigint AS checks,"
                          "count(DISTINCT identity_key)::bigint AS identities,"
                          "count(DISTINCT session_key)::bigint AS sessions FROM filtered "
                          "GROUP BY GROUPING SETS ((product_key,product,source),(risk),(decision))",
                          *args, conn=conn)
        top = st.many(CTE + _groups("identity_key") + " ORDER BY checks DESC,key LIMIT 10", *args, conn=conn)
        recent = st.many(CTE + "SELECT id,source,product_key,risk FROM filtered "
                         "ORDER BY created_at DESC,id DESC,source DESC LIMIT 100",
                         *args, conn=conn) if view == "checks" else []
        items, total = [], totals["checks"]
        if view != "checks":
            columns = "identity_key" if view == "identities" else "session_key"
            groups = CTE + ", groups AS (" + _groups(columns) + "), matching AS ("
            groups += "SELECT * FROM groups WHERE strpos(lower(search_text),lower($13))>0) "
            total = st.scalar(groups + "SELECT count(*) FROM matching", *args, search, conn=conn)
            items = st.many(groups + "SELECT * FROM matching ORDER BY checks DESC,key LIMIT $14 OFFSET $15",
                            *args, search, limit, offset, conn=conn)
    for row in [*top, *items]:
        row.pop("search_text", None)
    return {"range": query.get("range", "1h"), "source": args[5], "since": args[1], "until": args[2],
            "totals": totals,
            "sources": sorted((row for row in grouped if row["product_key"]),
                              key=lambda row: (-row["checks"], row["product_key"])),
            "risks": {row["risk"]: row["checks"] for row in grouped if row["risk"]},
            "decisions": {row["decision"]: row["checks"] for row in grouped if row["decision"]},
            "top_identities": top, "recent_checks": recent, "view": view, "items": items, "total": total,
            "offset": offset, "has_more": offset + len(items) < total if view != "checks" else False}


def checks(st, tenant, query):
    args = _scope(tenant, query)
    try:
        limit = int(query.get("limit", "100"))
        raw, separator, source = query.get("cursor", "").partition(":")
        cursor = decode_cursor(raw)
        require(not raw or separator and source in ("endpoint", "gateway"), "invalid cursor")
        require(bool(raw) == bool(separator), "invalid cursor")
    except (ValueError, TypeError):
        raise APIError(400, "invalid pagination") from None
    require(1 <= limit <= 200, "limit must be 1 to 200")
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        conn.execute("SET LOCAL statement_timeout = '5s'")
        rows = st.many(CTE + "SELECT id,created_at,source FROM filtered "
                       "WHERE ($13::timestamptz IS NULL OR (created_at,id,source)<($13,$14::uuid,$15::text)) "
                       "ORDER BY created_at DESC,id DESC,source DESC LIMIT $16",
                       *args, cursor.time, cursor.id or None, source, limit + 1, conn=conn)
        endpoint_ids = [row["id"] for row in rows[:limit] if row["source"] == "endpoint"]
        gateway_ids = [row["id"] for row in rows[:limit] if row["source"] == "gateway"]
        items = {}
        if endpoint_ids:
            fields, tables, conditions = hook_policy.decision_query(classified=True)
            for row in st.many("SELECT " + fields + " FROM " + tables + " WHERE "
                               + " AND ".join(conditions) + " AND c.id=ANY($2::uuid[])",
                               tenant, endpoint_ids, conn=conn):
                row["assessment"] = customer_views.guardrail_assessment(row["assessment"])
                items[("endpoint", row["id"])] = {**row, "source": "endpoint"}
        if gateway_ids:
            for row in st.many("SELECT r.*,g.name AS gateway_name,g.kind AS gateway_kind "
                               "FROM gateway_requests r JOIN gateway_instances g "
                               "ON g.id=r.gateway_id AND g.tenant_id=r.tenant_id "
                               "WHERE r.tenant_id=$1 AND r.id=ANY($2::uuid[])", tenant, gateway_ids, conn=conn):
                items[("gateway", row["id"])] = {**gateways._request(row, detail=True), "source": "gateway"}
    last = rows[limit - 1] if len(rows) > limit else None
    return {"items": [items[(row["source"], row["id"])] for row in rows[:limit]],
            "next_cursor": Cursor(last["created_at"], last["id"]).encode() + ":" + last["source"] if last else "",
            "since": args[1], "until": args[2]}
