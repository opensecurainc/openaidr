"""Gateway plugin identities, bounded checks and explicit enforcement receipts."""

from .customer_views import guardrail_assessment

import asyncio
import hashlib
import json
import math
import time
from contextlib import nullcontext
from datetime import timedelta
from importlib.resources import files

from psycopg.types.json import Jsonb

from openaidr.core.policy import Policy
from openaidr.core.redact import contains_secret, redact_value
from . import company_policy, model_keys
from .guardrail.storage import _bounded_transaction, get_settings
from .httpx import APIError, parse_time, require, uuid_param
from .store import Cursor, decode_cursor, hash_token, new_id, new_token, now

MAX_BODY = 64 << 10
PLUGINS = json.loads(files("openaidr.core").joinpath("gateway-plugins.json").read_text())
WORK_SECONDS = 2.5
CAPTURE_STATES = ("available", "capture_disabled", "unsupported_content",
                  "content_truncated", "content_redacted", "oversized")
FAILURES = ("timeout", "backend_unavailable", "invalid_response", *CAPTURE_STATES[1:])
META = ("route_id", "service_id", "consumer_id", "consumer_name", "application_name",
        "provider", "model", "protocol", "stream")
REQUEST_FIELDS = ("id", "gateway_id", "gateway_name", "gateway_kind", "request_id", "node_id", "status", "mode",
                  "evaluated_decision", "returned_decision", "outcome", "status_code", "latency_ms",
                  "policy_latency_ms", "guardrail_e2e_ms", "reason", "failure_reason", "created_at", "completed_at")


def _keys(data, required, optional=()):
    require(isinstance(data, dict) and set(required) <= set(data) <= set(required) | set(optional),
            "invalid fields")


def _text(value, name, maximum=256, *, empty=True):
    require(isinstance(value, str) and (empty or bool(value.strip())) and len(value) <= maximum
            and all(ord(c) >= 32 for c in value), "invalid " + name)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise APIError(400, "invalid " + name) from None
    return value


def _integer(value, name, low, high):
    require(type(value) is int and low <= value <= high, "invalid " + name)


def _digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def eligible_rule(rule, kind):
    match = rule.get("match") or {}
    return (rule.get("enabled", True) and rule.get("action") in ("allow", "deny")
            and bool(match) and set(match) <= {"kinds", "products"}
            and (not match.get("kinds") or "prompt" in match["kinds"])
            and (not match.get("products") or kind in match["products"]))


def _audit(st, tenant, actor, action, ident, details, conn):
    st.execute("""INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,
        target_type,target_id,details) VALUES($1,$2,$3,$4,$5,$6,'gateway',$7,$8)""",
        new_id(), tenant, actor.get("type", "user"), actor.get("id", ""), actor.get("name", ""),
        action, ident, Jsonb(details), conn=conn)


def _instance(st, tenant, ident, conn=None, *, lock=False):
    uuid_param(ident)
    return st.one("SELECT * FROM gateway_instances WHERE tenant_id=$1 AND id=$2"
                  + (" FOR UPDATE" if lock else ""), tenant, ident, conn=conn)


def _public_instance(st, row, conn=None):
    nodes = st.one("""SELECT count(*)::int AS node_count,max(last_seen_at) AS last_seen_at
        FROM gateway_nodes WHERE tenant_id=$1 AND gateway_id=$2""", row["tenant_id"], row["id"], conn=conn)
    seen = nodes["last_seen_at"]
    status = ("disabled" if not row["enabled"] else "never_seen" if seen is None
              else "reporting" if seen >= now() - timedelta(seconds=90) else "stale")
    return {**{k: v for k, v in row.items() if k != "tenant_id"}, **nodes, "status": status}


def _credential(st, tenant, gateway, conn):
    token, hashed = new_token("oagt_")
    st.execute("""UPDATE gateway_credentials SET revoked_at=clock_timestamp()
        WHERE tenant_id=$1 AND gateway_id=$2 AND revoked_at IS NULL""", tenant, gateway, conn=conn)
    row = st.one("""INSERT INTO gateway_credentials(id,tenant_id,gateway_id,token_hash)
        VALUES($1,$2,$3,$4) RETURNING id,created_at""", new_id(), tenant, gateway, hashed, conn=conn)
    return {**row, "token": token}


def _page(query):
    try:
        limit = int(query.get("limit", "50"))
        cursor = decode_cursor(query.get("cursor", ""))
    except (ValueError, TypeError):
        raise APIError(400, "invalid pagination") from None
    require(1 <= limit <= 200, "limit must be 1 to 200")
    return limit, cursor


def _request(row, *, detail=False):
    result = {**{k: row.get(k) for k in REQUEST_FIELDS},
              **{k: row["metadata"].get(k, False if k == "stream" else "") for k in META}}
    if row["status"] == "pending" and row["deadline_at"] <= now():
        result.update(status="unavailable", failure_reason="timeout")
    if detail:
        result.update({k: row[k] for k in ("messages", "assessment", "settings_version", "policy_version")})
        result["assessment"] = guardrail_assessment(row["assessment"])
        result["usage"] = None
    return result


def listing(st, tenant, query):
    limit, cursor = _page(query)
    rows = st.many("""SELECT * FROM gateway_instances WHERE tenant_id=$1
        AND ($2::timestamptz IS NULL OR (created_at,id)<($2,$3::uuid))
        ORDER BY created_at DESC,id DESC LIMIT $4""", tenant, cursor.time, cursor.id or None, limit + 1)
    return {"items": [_public_instance(st, row) for row in rows[:limit]],
            "next_cursor": Cursor(rows[limit-1]["created_at"], rows[limit-1]["id"]).encode()
            if len(rows) > limit else ""}


def requests(st, tenant, query):
    limit, cursor = _page(query)
    conditions, args = ["r.tenant_id=$1"], [tenant]

    def where(expression, value):
        args.append(value)
        conditions.append(expression.replace("?", "$" + str(len(args))))

    for key in ("gateway_id", "node_id", "mode"):
        if query.get(key):
            if key == "gateway_id":
                uuid_param(query[key])
            where("r." + key + "=?", query[key])
    if query.get("status") == "unavailable":
        conditions.append("(r.status='unavailable' OR (r.status='pending' AND r.deadline_at<=now()))")
    elif query.get("status") == "pending":
        conditions.append("(r.status='pending' AND r.deadline_at>now())")
    elif query.get("status"):
        where("r.status=?", query["status"])
    for key in ("route_id", "model", "provider", "consumer_id"):
        if query.get(key):
            where("r.metadata->>'" + key + "'=?", query[key])
    if query.get("outcome") == "unconfirmed":
        conditions.append("(r.outcome IS NULL OR r.outcome='unconfirmed')")
    elif query.get("outcome"):
        where("r.outcome=?", query["outcome"])
    try:
        since = parse_time(query["since"]) if query.get("since") else now() - timedelta(hours=24)
        until = parse_time(query["until"]) if query.get("until") else now()
        require(since.tzinfo is not None and until.tzinfo is not None and since <= until, "invalid time window")
    except (ValueError, TypeError):
        raise APIError(400, "invalid time window") from None
    where("r.created_at>=?", since)
    where("r.created_at<=?", until)
    if cursor.id:
        args.extend([cursor.time, cursor.id])
        conditions.append(f"(r.created_at,r.id)<(${len(args)-1},${len(args)}::uuid)")
    args.append(limit + 1)
    rows = st.many("SELECT r.*,g.name AS gateway_name,g.kind AS gateway_kind FROM gateway_requests r JOIN gateway_instances g "
                   "ON g.id=r.gateway_id AND g.tenant_id=r.tenant_id WHERE " + " AND ".join(conditions)
                   + f" ORDER BY r.created_at DESC,r.id DESC LIMIT ${len(args)}", *args)
    return {"items": [_request(row) for row in rows[:limit]],
            "next_cursor": Cursor(rows[limit-1]["created_at"], rows[limit-1]["id"]).encode()
            if len(rows) > limit else ""}


def overview(st, tenant):
    instances = st.many("""SELECT g.enabled,max(n.last_seen_at) AS last_seen_at
        FROM gateway_instances g LEFT JOIN gateway_nodes n ON n.gateway_id=g.id AND n.tenant_id=g.tenant_id
        WHERE g.tenant_id=$1 GROUP BY g.id""", tenant)
    counts = dict(total=len(instances), reporting=0, stale=0, never_seen=0, disabled=0)
    for row in instances:
        counts["disabled" if not row["enabled"] else "never_seen" if row["last_seen_at"] is None
               else "reporting" if row["last_seen_at"] >= now() - timedelta(seconds=90) else "stale"] += 1
    result = st.one("""SELECT count(*) AS total,
        count(*) FILTER(WHERE status='evaluated') AS evaluated,
        count(*) FILTER(WHERE status='unavailable' OR (status='pending' AND deadline_at<=now())) AS unavailable,
        count(*) FILTER(WHERE returned_decision='allow') AS allowed,
        count(*) FILTER(WHERE returned_decision='deny') AS denied,
        count(*) FILTER(WHERE mode='shadow' AND evaluated_decision='deny') AS would_deny,
        count(*) FILTER(WHERE outcome='blocked') AS blocked,
        count(*) FILTER(WHERE outcome='forwarded') AS forwarded,
        count(*) FILTER(WHERE outcome='fail_open') AS fail_open,
        count(*) FILTER(WHERE outcome IS NULL OR outcome='unconfirmed') AS unconfirmed,
        percentile_cont(0.5) WITHIN GROUP(ORDER BY policy_latency_ms) AS p50,
        percentile_cont(0.95) WITHIN GROUP(ORDER BY policy_latency_ms) AS p95
        FROM gateway_requests WHERE tenant_id=$1 AND created_at>=now()-interval '24 hours'""", tenant)
    latency = {key: result.pop(key) for key in ("p50", "p95")}
    return dict(window_hours=24, gateways=counts, requests=result, policy_latency_ms=latency, coverage="observed_only")


def console(st, tenant, method, path, data, query, actor):
    parts = path.split("/")
    if path == "gateways/overview" and method == "GET":
        return overview(st, tenant), 200
    if path == "gateways/requests" and method == "GET":
        return requests(st, tenant, query), 200
    if len(parts) == 3 and parts[1] == "requests" and method == "GET":
        row = st.one("""SELECT r.*,g.name AS gateway_name,g.kind AS gateway_kind FROM gateway_requests r JOIN gateway_instances g
            ON g.id=r.gateway_id AND g.tenant_id=r.tenant_id WHERE r.tenant_id=$1 AND r.id=$2""",
            tenant, uuid_param(parts[2]))
        return _request(row, detail=True), 200
    if path == "gateways" and method == "GET":
        return listing(st, tenant, query), 200
    if path == "gateways" and method == "POST":
        _keys(data, ("name",), ("environment", "kind"))
        kind = data.get("kind", "kong")
        require(isinstance(kind, str) and kind in PLUGINS, "unsupported gateway plugin")
        name = _text(data["name"], "name", 120, empty=False)
        environment = _text(data.get("environment", ""), "environment", 120)
        with st.transaction() as conn:
            row = st.one("""INSERT INTO gateway_instances(id,tenant_id,name,environment,kind)
                VALUES($1,$2,$3,$4,$5) RETURNING *""", new_id(), tenant, name, environment, kind, conn=conn)
            credential = _credential(st, tenant, row["id"], conn)
            _audit(st, tenant, actor, "gateway.create", row["id"], {}, conn)
            return {"gateway": _public_instance(st, row, conn), "credential": credential}, 201
    require(len(parts) >= 2, "no such route", 404)
    ident = uuid_param(parts[1])
    if len(parts) == 2 and method == "GET":
        gateway = _public_instance(st, _instance(st, tenant, ident))
        nodes = st.many("""SELECT node_id,plugin_version,gateway_version,kong_version,last_seen_at,dropped_events,routes
            FROM gateway_nodes WHERE tenant_id=$1 AND gateway_id=$2 ORDER BY node_id""", tenant, ident)
        routes = []
        if gateway["kind"] == "kong":
            for node in nodes:
                node["gateway_version"] = node["kong_version"]
        for node in nodes:
            routes.extend({**route, "node_id": node["node_id"], "last_seen_at": node["last_seen_at"]}
                          for route in node.pop("routes"))
            node["status"] = "reporting" if node["last_seen_at"] >= now() - timedelta(seconds=90) else "stale"
        credentials = st.many("""SELECT id,created_at,revoked_at FROM gateway_credentials
            WHERE tenant_id=$1 AND gateway_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1""", tenant, ident)
        return dict(gateway=gateway, nodes=nodes, routes=routes,
                    credential=credentials[0] if credentials else None, coverage="observed_only"), 200
    with st.transaction() as conn:
        row = _instance(st, tenant, ident, conn, lock=True)
        if len(parts) == 2 and method == "PATCH":
            _keys(data, ("version",), ("name", "environment", "enabled"))
            for key in ("name", "environment"):
                if key in data:
                    _text(data[key], key, 120, empty=key != "name")
            require("enabled" not in data or type(data["enabled"]) is bool, "invalid enabled")
            updates = {key: data.get(key, row[key]) for key in ("name", "environment", "enabled")}
        elif len(parts) == 3 and parts[2] == "settings" and method == "PUT":
            _keys(data, ("version", "mode", "capture_content", "policy_rule_ids"))
            require(data["mode"] in ("shadow", "enforce") and type(data["capture_content"]) is bool, "invalid settings")
            ids = data["policy_rule_ids"]
            require(isinstance(ids, list) and len(ids) <= 100 and all(isinstance(i, str) for i in ids)
                    and len(set(ids)) == len(ids), "invalid policy_rule_ids")
            eligible = {r["id"] for r in st.get_policy(tenant, conn=conn)["rules"] if eligible_rule(r, row["kind"])}
            require(set(ids) <= eligible, "only enabled prompt or matching gateway-product allow/deny rules can be assigned")
            updates = dict(mode=data["mode"], capture_content=data["capture_content"], policy_rule_ids=Jsonb(ids))
        elif len(parts) == 3 and parts[2] == "credentials" and method == "POST":
            require(data == {}, "credential rotation takes an empty object")
            credential = _credential(st, tenant, ident, conn)
            _audit(st, tenant, actor, "gateway.credential.rotate", ident, {"credential_id": credential["id"]}, conn)
            return credential, 200
        elif len(parts) == 4 and parts[2] == "credentials" and method == "DELETE":
            credential_id = uuid_param(parts[3])
            st.one("""UPDATE gateway_credentials SET revoked_at=COALESCE(revoked_at,clock_timestamp())
                WHERE tenant_id=$1 AND gateway_id=$2 AND id=$3 RETURNING id""", tenant, ident, credential_id, conn=conn)
            _audit(st, tenant, actor, "gateway.credential.revoke", ident, {"credential_id": credential_id}, conn)
            return {"revoked": True}, 200
        else:
            raise APIError(404, "no such route")
        _integer(data["version"], "version", 1, 2**31-1)
        require(data["version"] == row["version"], "gateway settings changed", 409)
        names = list(updates)
        assignments = ",".join(key + "=$" + str(i+3) for i, key in enumerate(names))
        row = st.one("UPDATE gateway_instances SET " + assignments
                     + ",version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 RETURNING *",
                     tenant, ident, *updates.values(), conn=conn)
        _audit(st, tenant, actor, "gateway.configure", ident,
               {"version": row["version"], "fields": names}, conn)
        return _public_instance(st, row, conn), 200


def principal(st, cfg, token, conn, *, exclusive=False):
    require(isinstance(token, str) and token.startswith("oagt_") and len(token) == 48,
            "invalid gateway credential", 401)
    rows = st.many("SELECT gateway_id,tenant_id,id FROM gateway_credentials WHERE token_hash=$1",
                   hash_token(token), conn=conn)
    require(bool(rows), "invalid gateway credential", 401)
    identity = rows[0]
    row = st.one("SELECT * FROM gateway_instances WHERE tenant_id=$1 AND id=$2 FOR "
                 + ("UPDATE" if exclusive else "SHARE"), identity["tenant_id"], identity["gateway_id"], conn=conn)
    require(not cfg.tenant_id or row["tenant_id"] == cfg.tenant_id, "invalid gateway credential", 401)
    active = st.scalar("SELECT revoked_at IS NULL FROM gateway_credentials WHERE id=$1 AND token_hash=$2",
                       identity["id"], hash_token(token), conn=conn)
    require(active, "invalid gateway credential", 401)
    require(row["enabled"], "gateway is disabled", 403)
    require(row["kind"] in PLUGINS, "unsupported gateway plugin", 503)
    require(st.scalar("SELECT status='active' FROM tenants WHERE id=$1", row["tenant_id"], conn=conn),
            "tenant is inactive", 403)
    return row


def heartbeat(st, cfg, token, data, deadline):
    _keys(data, ("node_id", "plugin_version", "coverage", "routes"), ("kind", "gateway_version", "kong_version", "dropped_events"))
    _text(data["node_id"], "node_id", 128, empty=False)
    _text(data["plugin_version"], "plugin_version", 80, empty=False)
    _text(data.get("kong_version", ""), "kong_version", 80)
    _text(data.get("gateway_version", ""), "gateway_version", 80)
    require(not {"gateway_version", "kong_version"} <= data.keys()
            or data["gateway_version"] == data["kong_version"], "conflicting gateway versions")
    _integer(data.get("dropped_events", 0), "dropped_events", 0, 2**53-1)
    require(data["coverage"] == "observed_only", "invalid coverage")
    routes = data["routes"]
    require(isinstance(routes, list) and len(routes) <= 256, "invalid routes")
    ids = set()
    for route in routes:
        _keys(route, ("route_id", "protocol"), ("service_id",))
        _text(route["route_id"], "route_id", empty=False)
        _text(route.get("service_id", ""), "service_id")
        require(route["protocol"] == "openai.chat" and route["route_id"] not in ids, "invalid route")
        ids.add(route["route_id"])
    with _bounded_transaction(st, deadline) as conn:
        gateway = principal(st, cfg, token, conn, exclusive=True)
        require(data.get("kind", gateway["kind"]) == gateway["kind"], "plugin kind does not match the connection")
        require("kong_version" not in data or gateway["kind"] == "kong", "kong_version requires a Kong connection")
        version = data.get("gateway_version", data.get("kong_version", ""))
        require(st.scalar("""SELECT count(*)<128 OR bool_or(node_id=$3) FROM gateway_nodes
            WHERE tenant_id=$1 AND gateway_id=$2""", gateway["tenant_id"], gateway["id"], data["node_id"], conn=conn),
            "gateway node capacity exhausted", 409)
        st.execute("""INSERT INTO gateway_nodes(tenant_id,gateway_id,node_id,plugin_version,kong_version,routes,dropped_events,gateway_version)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(gateway_id,node_id) DO UPDATE SET
            plugin_version=EXCLUDED.plugin_version,kong_version=EXCLUDED.kong_version,gateway_version=EXCLUDED.gateway_version,routes=EXCLUDED.routes,
            dropped_events=EXCLUDED.dropped_events,last_seen_at=clock_timestamp()""",
            gateway["tenant_id"], gateway["id"], data["node_id"], data["plugin_version"], version if gateway["kind"] == "kong" else "",
            Jsonb(routes), data.get("dropped_events", 0), version, conn=conn)
        return {"gateway_id": gateway["id"], "guardrail_metrics": True,
                **{k: gateway[k] for k in ("kind", "mode", "capture_content", "version", "enabled")}}


def _metadata(data):
    uuid_param(data.get("request_id"), "request_id")
    _text(data.get("node_id"), "node_id", 128, empty=False)
    for key in META[:-2]:
        if key in data:
            _text(data[key], key)
    require(not data.get("consumer_name") or bool(data.get("consumer_id", "").strip()),
            "consumer_name requires consumer_id")
    require("protocol" not in data or data["protocol"] == "openai.chat", "unsupported protocol")
    require("stream" not in data or type(data["stream"]) is bool, "invalid stream")
    return redact_value({key: data[key] for key in META if key in data})


def validate_check(data):
    _keys(data, ("request_id", "node_id", "protocol", "stream", "messages", "availability", "timeout_ms"), META[:-2])
    _metadata(data)
    _integer(data["timeout_ms"], "timeout_ms", 1, 2000)
    require(data["availability"] in CAPTURE_STATES, "invalid availability")
    messages = data["messages"]
    require(isinstance(messages, list) and len(messages) <= 128, "invalid messages")
    for message in messages:
        _keys(message, ("role", "content"))
        require(message["role"] in ("system", "developer", "user", "assistant", "tool"), "invalid message role")
        require(isinstance(message["content"], str) and "\x00" not in message["content"], "invalid message content")
        try:
            message["content"].encode("utf-8")
        except UnicodeError:
            raise APIError(400, "invalid message content") from None
    require(data["availability"] == "available" or not messages, "unavailable content must be omitted")
    require(data["availability"] != "available" or bool(messages), "available messages are required")


def _reply(row):
    if row["status"] != "evaluated":
        return {"id": row["id"], "request_id": row["request_id"], "status": "unavailable",
                "error": {"code": "unavailable", "message": "gateway evaluation is unavailable"}}, 503
    return {key: row[key] for key in ("id", "request_id", "status", "mode", "settings_version", "policy_version",
                                    "evaluated_decision", "returned_decision", "reason")}, 200


def prepare(st, cfg, token, data, deadline, *, customer=False):
    if customer:
        from .service_guardrail import contract
        contract()
    digest = _digest({k: v for k, v in data.items() if k != "timeout_ms"})
    with _bounded_transaction(st, deadline) as conn:
        gateway = principal(st, cfg, token, conn)
        tenant, ident = gateway["tenant_id"], gateway["id"]
        policy = st.get_policy(tenant, conn=conn)
        risk_settings = get_settings(st, tenant, conn)
        company = company_policy.read(st, tenant, conn=conn)
        rules = [r for r in policy["rules"] if r["id"] in gateway["policy_rule_ids"] and eligible_rule(r, gateway["kind"])]
        available = data["availability"] == "available" and gateway["capture_content"]
        failure = "" if available else data["availability"] if data["availability"] != "available" else "capture_disabled"
        if len(rules) != len(gateway["policy_rule_ids"]):
            failure = "invalid_policy"
        messages = data["messages"] if available else None
        if messages is not None:
            try:
                # Detect shared credential patterns without normalizing captured
                # text. JSON escapes and nested JSON still require inspection.
                if any(contains_secret(message["content"]) for message in messages):
                    failure, messages = "content_redacted", None
            except RecursionError:
                failure, messages = "unsupported_content", None
        rows = st.many("""INSERT INTO gateway_requests(id,tenant_id,gateway_id,request_id,node_id,metadata,
            check_digest,status,mode,settings_version,policy_version,messages,deadline_at,failure_reason,completed_at,
            risk_settings_version,company_policy_revision)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,clock_timestamp()+$13*interval '1 second',$14,
                CASE WHEN $14<>'' THEN clock_timestamp() END,$15,$16)
            ON CONFLICT(gateway_id,request_id) DO NOTHING RETURNING *""",
            new_id(), tenant, ident, data["request_id"], data["node_id"], Jsonb(_metadata(data)), digest,
            "unavailable" if failure else "pending", gateway["mode"], gateway["version"], policy["version"],
            Jsonb(messages) if messages is not None else None, max(0, deadline-time.monotonic()), failure,
            risk_settings["version"], company["revision"], conn=conn)
        if not rows:
            row = st.one("SELECT * FROM gateway_requests WHERE tenant_id=$1 AND gateway_id=$2 AND request_id=$3",
                         tenant, ident, data["request_id"], conn=conn)
            require(row["node_id"] == data["node_id"] and row["check_digest"] in (None, digest),
                    "request_id already used for different content", 409)
            # A previously valid deny is stale after any current settings change.
            if (row["settings_version"] != gateway["version"] or row["policy_version"] != policy["version"]
                    or row["risk_settings_version"] != risk_settings["version"]
                    or row["company_policy_revision"] != company["revision"]):
                return {"reply": (_reply({**row, "status": "unavailable"}))}
            return {"reply": _reply(row)}
        row = rows[0]
        if failure:
            return {"reply": _reply(row)}
        key = model_keys.guardrail_credential(st, tenant, cfg, conn=conn)
        if not key:
            row = st.one("""UPDATE gateway_requests SET status='unavailable',failure_reason='provider_unavailable',
                completed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 RETURNING *""", tenant, row["id"], conn=conn)
            return {"reply": _reply(row)}
        call_id = None
        if not customer:
            from .guardrail.scoring import MODEL
            from .model_costs import PRICE_DATE, RATES

            call_id = new_id()
            rates = RATES.get(("typesafe", MODEL), (None, None))
            st.execute("""INSERT INTO model_usage(id,tenant_id,gateway_request_id,attempt,purpose,provider,model,
                input_rate_usd,output_rate_usd,price_date) VALUES($1,$2,$3,1,'guardrail','typesafe',$4,$5,$6,$7)""",
                call_id, tenant, row["id"], MODEL, *rates, PRICE_DATE if rates[0] is not None else None, conn=conn)
        return dict(row=row, rules=rules, kind=gateway["kind"], risk_settings=risk_settings, company_policy=company,
                    key=key, call_id=call_id, started=time.monotonic())


def finish(st, cfg, token, prepared, assessment, failure, deadline, *, conn=None):
    row = prepared["row"]
    decision = {"action": "allow"}
    if not failure:
        decision = Policy({"rules": prepared["rules"]}).evaluate({"kind": "prompt", "agent": {"product": prepared["kind"]}})
        if decision.get("evaluation_unavailable"):
            failure = "evaluation_unavailable"
    settings = prepared["risk_settings"]
    if not failure and settings["enabled"] and settings["block_threshold"] is not None:
        if assessment["score"] >= settings["block_threshold"]:
            decision = {"action": "deny", "reason": "Guardrail risk threshold exceeded"}
    with nullcontext(conn) if conn is not None else _bounded_transaction(st, deadline) as conn:
        try:
            gateway = principal(st, cfg, token, conn)
        except APIError as exc:
            if exc.status not in (401, 403):
                raise
            gateway, failure = None, "identity_changed"
        policy = st.get_policy(row["tenant_id"], conn=conn)
        current_risk = get_settings(st, row["tenant_id"], conn)
        company = company_policy.read(st, row["tenant_id"], conn=conn)
        if gateway is not None and (gateway["version"] != row["settings_version"] or not gateway["capture_content"]
                or policy["version"] != row["policy_version"]
                or current_risk["version"] != settings["version"]
                or company["revision"] != prepared["company_policy"]["revision"]):
            failure = "settings_changed"
        if prepared["call_id"]:
            st.finish_model_call(row["tenant_id"], prepared["call_id"], (assessment or {}).get("usage"),
                                 failed=assessment is None or assessment.get("status") == "error", conn=conn)
        evaluated = None if failure else decision["action"]
        returned = None if failure else "allow" if row["mode"] == "shadow" else evaluated
        updated = st.many("""UPDATE gateway_requests SET status=$3,evaluated_decision=$4,returned_decision=$5,
            reason=$6,failure_reason=$7,assessment=$8,policy_latency_ms=$9,completed_at=clock_timestamp()
            WHERE tenant_id=$1 AND id=$2 AND status='pending' AND deadline_at>clock_timestamp() RETURNING *""",
            row["tenant_id"], row["id"], "unavailable" if failure else "evaluated", evaluated, returned,
            decision.get("reason", "") if not failure else "", failure,
            Jsonb(assessment) if assessment is not None else None,
            max(0, (time.monotonic()-prepared["started"])*1000), conn=conn)
        return _reply(updated[0] if updated else {**row, "status": "unavailable"})


async def check(st, cfg, token, data, deadline, clients, run_sync, *, customer=False):
    if customer:
        from .service_gateway import check as customer_check
        return await customer_check(st, cfg, token, data, deadline, clients, run_sync)
    from .guardrail.scoring import JevError

    prepared = await run_sync(prepare, st, cfg, token, data, deadline)
    if "reply" in prepared:
        return prepared["reply"]
    assessment, failure = None, ""
    try:
        # Leave bounded time for receipt persistence. A timed-out assessment can
        # never restrict a request even if the provider completes later.
        seconds = max(0, deadline-time.monotonic()-0.08)
        async with asyncio.timeout(seconds):
            state = {"target_event": {"kind": "prompt", "source": prepared["kind"] + "_gateway",
                                      "messages": prepared["row"]["messages"]},
                     "prior_events": [], "context_limited": True}
            assessment = await clients.assess(prepared["row"]["tenant_id"], prepared["key"], state,
                                              company_policy=prepared["company_policy"]["prompt"], timeout=seconds)
            if assessment.get("status") != "scored":
                failure = "invalid_response"
    except TimeoutError:
        failure = "timeout"
    except JevError as exc:
        failure = exc.code
        assessment = {"status": "error", "reason": exc.code, "usage": exc.usage}
    return await run_sync(finish, st, cfg, token, prepared, assessment, failure, deadline)


def outcome(st, cfg, token, data, deadline):
    _keys(data, ("request_id", "node_id", "outcome", "status_code", "latency_ms"),
          (*META, "check_id", "failure_reason", "guardrail_e2e_ms"))
    metadata = _metadata(data)
    require(data["outcome"] in ("blocked", "forwarded", "fail_open", "unconfirmed"), "invalid outcome")
    if data["status_code"] is not None:
        _integer(data["status_code"], "status_code", 100, 599)
    require(data["latency_ms"] is None or (type(data["latency_ms"]) in (float, int)
            and math.isfinite(data["latency_ms"]) and data["latency_ms"] >= 0), "invalid latency_ms")
    require("failure_reason" not in data or data["failure_reason"] in FAILURES, "invalid failure_reason")
    if "guardrail_e2e_ms" in data:
        value = data["guardrail_e2e_ms"]
        require(type(value) in (float, int) and math.isfinite(value) and 0 <= value <= 3_600_000,
                "invalid guardrail_e2e_ms")
    if "check_id" in data:
        uuid_param(data["check_id"], "check_id")
    digest = _digest(data)
    with _bounded_transaction(st, deadline) as conn:
        gateway = principal(st, cfg, token, conn)
        tenant, ident = gateway["tenant_id"], gateway["id"]
        rows = st.many("""SELECT * FROM gateway_requests WHERE tenant_id=$1 AND gateway_id=$2
            AND request_id=$3 FOR UPDATE""", tenant, ident, data["request_id"], conn=conn)
        if not rows:
            require(data["outcome"] != "blocked" and not data.get("check_id"), "check is not known", 409)
            st.execute("""INSERT INTO gateway_requests(id,tenant_id,gateway_id,request_id,node_id,metadata,status,
                failure_reason,completed_at) VALUES($1,$2,$3,$4,$5,$6,'unavailable','check_not_received',clock_timestamp())
                ON CONFLICT(gateway_id,request_id) DO NOTHING""", new_id(), tenant, ident, data["request_id"],
                data["node_id"], Jsonb(metadata), conn=conn)
            rows = st.many("""SELECT * FROM gateway_requests WHERE tenant_id=$1 AND gateway_id=$2
                AND request_id=$3 FOR UPDATE""", tenant, ident, data["request_id"], conn=conn)
        row = rows[0]
        require(row["node_id"] == data["node_id"] and (not data.get("check_id") or data["check_id"] == row["id"]),
                "outcome does not match check", 409)
        require(all(row["metadata"].get(k, v) == v for k, v in metadata.items()), "outcome metadata changed", 409)
        require(row["outcome_digest"] in (None, digest), "outcome already recorded", 409)
        require(data["outcome"] != "blocked" or (data.get("check_id") == row["id"] and row["status"] == "evaluated"
                and row["mode"] == "enforce" and row["returned_decision"] == "deny"), "block is not confirmed", 409)
        if row["outcome_digest"] is None:
            st.execute("""UPDATE gateway_requests SET outcome=$3,outcome_digest=$4,status_code=$5,latency_ms=$6,
                failure_reason=CASE WHEN $7<>'' THEN $7 ELSE failure_reason END,guardrail_e2e_ms=$8
                WHERE tenant_id=$1 AND id=$2""",
                tenant, row["id"], data["outcome"], digest, data["status_code"], data["latency_ms"],
                data.get("failure_reason", ""), data.get("guardrail_e2e_ms"), conn=conn)
        return {"accepted": True, "request_id": data["request_id"]}


def cleanup(st, cfg):
    """Respect tenant retention while bounding each cleanup transaction."""
    with _bounded_transaction(st, time.monotonic()+2) as conn:
        worked = st.execute("""UPDATE gateway_requests SET status='unavailable',failure_reason='timeout',
            completed_at=clock_timestamp() WHERE id IN (SELECT id FROM gateway_requests
            WHERE status='pending' AND deadline_at<now()-interval '1 minute'
            AND ($1::uuid IS NULL OR tenant_id=$1) ORDER BY deadline_at LIMIT 200 FOR UPDATE SKIP LOCKED)""",
            cfg.tenant_id or None, conn=conn)
        worked += st.execute("""UPDATE model_usage SET status='error',completed_at=clock_timestamp()
            WHERE id IN (SELECT u.id FROM model_usage u
                WHERE u.status='pending' AND u.gateway_request_id IS NOT NULL
                AND u.started_at<now()-interval '1 minute'
                AND ($1::uuid IS NULL OR u.tenant_id=$1)
                ORDER BY u.started_at LIMIT 200 FOR UPDATE OF u SKIP LOCKED)""", cfg.tenant_id or None, conn=conn)
        worked += st.execute("""DELETE FROM gateway_requests WHERE id IN (
            SELECT r.id FROM gateway_requests r JOIN tenant_telemetry_retention t ON t.tenant_id=r.tenant_id
            WHERE ($1::uuid IS NULL OR r.tenant_id=$1) AND r.status<>'pending'
                AND NOT EXISTS(SELECT 1 FROM model_usage u WHERE u.tenant_id=r.tenant_id
                    AND u.gateway_request_id=r.id AND u.status='pending') AND (
                (r.created_at<now()-(CASE WHEN t.mode IN ('7','30','90') THEN t.mode::int END)*interval '1 day')
                OR (t.cleanup_threshold_percent IS NOT NULL AND t.last_deleted_day IS NOT NULL
                    AND r.created_at<((t.last_deleted_day+1)::timestamp AT TIME ZONE 'UTC')))
            ORDER BY r.created_at LIMIT 200 FOR UPDATE OF r SKIP LOCKED)""", cfg.tenant_id or None, conn=conn)
        return bool(worked)
