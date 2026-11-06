"""Bounded MCP triage and browser-approved configuration changes."""

import hashlib
import json
import math
import time
from datetime import datetime, timedelta
from uuid import UUID

from fastapi.encoders import jsonable_encoder
from psycopg.types.json import Jsonb

from . import company_policy, hook_policy, session_aggregation
from .httpx import APIError, require
from .permissions import authorize, has_role
from .store import NotFound, new_id


TRIAGE_SCOPE = "triage:write"
PROPOSE_SCOPE = "configuration:propose"
_UUID = {"type": "string", "format": "uuid"}
_VERSION = {"type": "integer", "minimum": 0, "maximum": 9223372036854775806}
_TEXT = {"type": "string", "maxLength": 10000}
_OPERATIONS = {
    "hook_mode": ("response/hook-settings", "Change hook enforcement mode"),
    "detection_scheduling": ("response/session-detection", "Change detection scheduling"),
    "company_policy": ("response/company-policy", "Change company policy"),
}


def _schema(properties, required):
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


_TOOLS = {
    "update_finding": {
        "description": "Update one finding after checking its last observed update time. Retries reuse request_id.",
        "inputSchema": _schema({
            "request_id": _UUID, "finding_id": _UUID,
            "expected_updated_at": {"type": "string", "format": "date-time"},
            "status": {"type": "string", "enum": ["open", "triaged", "resolved", "false_positive"]},
            "assignee_id": {"type": ["string", "null"], "format": "uuid"}, "resolution": _TEXT,
        }, ["request_id", "finding_id", "expected_updated_at"]),
    },
    "add_finding_note": {
        "description": "Add one note to a finding. Reusing request_id never adds a duplicate note.",
        "inputSchema": _schema({"request_id": _UUID, "finding_id": _UUID, "body": _TEXT},
                               ["request_id", "finding_id", "body"]),
    },
    "propose_hook_mode": {
        "description": "Propose Shadow or Enforce mode. An authorized person must approve the exact change in the dashboard.",
        "inputSchema": _schema({"request_id": _UUID, "expected_version": _VERSION,
                                "mode": {"type": "string", "enum": ["shadow", "enforce"]}},
                               ["request_id", "expected_version", "mode"]),
    },
    "propose_detection_scheduling": {
        "description": "Propose enabling or disabling detection scheduling without changing its budget or settings. Requires dashboard approval.",
        "inputSchema": _schema({"request_id": _UUID, "expected_version": _VERSION, "enabled": {"type": "boolean"}},
                               ["request_id", "expected_version", "enabled"]),
    },
    "propose_company_policy": {
        "description": "Propose replacing company policy text. An authorized person must review and approve the exact text in the dashboard.",
        "inputSchema": _schema({"request_id": _UUID, "expected_version": _VERSION, "prompt": _TEXT},
                               ["request_id", "expected_version", "prompt"]),
    },
    "get_change_proposal": {
        "description": "Read the status of a change proposed by this client grant. This tool cannot approve a change.",
        "inputSchema": _schema({"proposal_id": _UUID}, ["proposal_id"]),
    },
}


def _permission(user, name):
    if name in ("update_finding", "add_finding_note"):
        authorize(user, "PATCH" if name == "update_finding" else "POST",
                  "findings/permission" + ("/notes" if name == "add_finding_note" else ""))
    elif name == "get_change_proposal":
        require(has_role(user, "it_admin") or has_role(user, "security_analyst"), "no change access", 403)
    else:
        operation = name.removeprefix("propose_")
        require(operation in _OPERATIONS, "unknown tool", 404)
        path = _OPERATIONS[operation][0]
        if operation == "detection_scheduling" and has_role(user, "it_admin"):
            path = "settings/session-detection"
        authorize(user, "PUT", path)


def _scope(name):
    return TRIAGE_SCOPE if name in ("update_finding", "add_finding_note") else PROPOSE_SCOPE


def tool_catalog(user, scopes):
    tools = []
    for name, definition in _TOOLS.items():
        if _scope(name) not in scopes:
            continue
        try:
            _permission(user, name)
        except APIError:
            continue
        tools.append({"name": name, **definition, "annotations": {
            "readOnlyHint": name == "get_change_proposal", "destructiveHint": name == "update_finding",
            "idempotentHint": True, "openWorldHint": False,
        }})
    return tools


def _uuid(value):
    try:
        require(isinstance(value, str), "invalid UUID")
        return str(UUID(value))
    except (ValueError, AttributeError):
        raise APIError(400, "invalid UUID") from None


def _text(value, *, nonempty=False):
    require(isinstance(value, str) and len(value) <= 10000 and "\x00" not in value,
            "text must contain at most 10000 characters")
    require(not nonempty or bool(value.strip()), "text must not be empty")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise APIError(400, "text must be valid UTF-8") from None


def _arguments(name, arguments):
    schema = _TOOLS[name]["inputSchema"]
    require(isinstance(arguments, dict) and set(schema["required"]) <= set(arguments)
            and set(arguments) <= set(schema["properties"]), "invalid tool arguments")
    data = dict(arguments)
    for key in ("request_id", "finding_id", "proposal_id", "assignee_id"):
        if key in data and (key != "assignee_id" or data[key] is not None):
            data[key] = _uuid(data[key])
    if "expected_version" in data:
        require(type(data["expected_version"]) is int and 0 <= data["expected_version"] <= 9223372036854775806,
                "invalid expected version")
    for key in ("body", "prompt", "resolution"):
        if key in data:
            _text(data[key], nonempty=key == "body")
    if name == "propose_hook_mode":
        require(data["mode"] in ("shadow", "enforce"), "invalid hook mode")
    if name == "propose_detection_scheduling":
        require(type(data["enabled"]) is bool, "enabled must be a boolean")
    if name == "update_finding":
        require(bool(set(data) & {"status", "assignee_id", "resolution"}), "provide a finding update")
        if "status" in data:
            require(data["status"] in ("open", "triaged", "resolved", "false_positive"), "invalid finding status")
        try:
            updated = datetime.fromisoformat(data["expected_updated_at"].replace("Z", "+00:00"))
            require(updated.tzinfo is not None, "update time must include a timezone")
        except (ValueError, TypeError, AttributeError):
            raise APIError(400, "invalid expected update time") from None
    return data


def _hash(value):
    return hashlib.sha256(json.dumps(jsonable_encoder(value), sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _deadline(principal):
    deadline = principal.get("mcp_deadline")
    if deadline is not None and (type(deadline) not in (int, float) or not math.isfinite(deadline)
                                 or time.monotonic() >= deadline):
        raise APIError(503, "MCP request deadline expired", "timeout")


def _actor(principal):
    return {"type": "user", "id": principal["user"]["id"], "name": principal["user"]["name"]}


def _audit(st, principal, action, target, target_id, details, conn):
    st.execute(
        """INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
           VALUES($1,$2,'user',$3,$4,$5,$6,$7,$8)""",
        new_id(), principal["tenant"]["id"], principal["user"]["id"], principal["user"]["name"],
        action, target, target_id, Jsonb(details), conn=conn,
    )


def _current_grant(service, principal, name, conn):
    from .dashboard_mcp_auth import validate_grant

    current = validate_grant(service.st, service.cfg, principal["grant_id"], conn=conn)
    require(all(current[key]["id"] == principal[key]["id"] for key in ("tenant", "user"))
            and current["client_id"] == principal["client_id"], "grant identity changed", 403)
    require(_scope(name) in current["scopes"], "grant does not allow this action", 403)
    _permission(current["user"], name)
    return current


def _proposal_row(st, tenant, ident, conn, *, lock=False):
    try:
        return st.one("SELECT *,clock_timestamp() >= expires_at AS expired FROM dashboard_mcp_changes "
                      "WHERE tenant_id=$1 AND id=$2" + (" FOR UPDATE" if lock else ""),
                      tenant, _uuid(ident), conn=conn)
    except NotFound:
        raise APIError(404, "change proposal not found") from None


def _proposal_view(row, *, browser=False):
    status = "expired" if row["status"] == "pending" and row["expired"] else row["status"]
    result = {
        "id": row["id"], "operation": row["operation"], "title": _OPERATIONS[row["operation"]][1],
        "requester": {"id": row["requester_id"], "name": row["requester_name"]},
        "client": {"id": row["client_id"], "name": row["client_name"]},
        "scope": PROPOSE_SCOPE,
        "expected_version": row["expected_version"], "digest": row["digest"], "status": status,
        "created_at": row["created_at"], "expires_at": row["expires_at"],
        "decided_at": row["decided_at"], "decided_by": row["decided_by"], "result": row["result"],
        "can_decide": browser and status == "pending",
        "review_path": "/mcp/changes/" + row["id"],
    }
    if browser:
        result.update(before=row["before_state"], after=row["after_state"])
    return jsonable_encoder(result)


def _snapshot(st, tenant, operation, data, conn):
    if operation == "hook_mode":
        current = hook_policy.get_settings(st, tenant, conn)
        before, parameters = {"mode": current["mode"]}, {"mode": data["mode"]}
    elif operation == "detection_scheduling":
        current = session_aggregation.get_settings(st, tenant, conn)
        require(not data["enabled"] or all(current[key] is not None for key in session_aggregation.SETTINGS),
                "configure explicit detection settings before enabling scheduling", 409)
        before = {key: current[key] for key in session_aggregation.SETTINGS}
        parameters = {"enabled": data["enabled"]}
    else:
        current = company_policy.read(st, tenant, conn=conn)
        before, parameters = {"prompt": current["prompt"]}, {"prompt": data["prompt"]}
    require(current.get("version", current.get("revision")) == data["expected_version"],
            "configuration changed; read the latest version and propose again", 409)
    return before, {**before, **parameters}, parameters


def call_tool(service, principal, name, arguments):
    _deadline(principal)
    require(name in _TOOLS, "unknown tool", 404)
    require(_scope(name) in principal["scopes"], "token does not allow this action", 403)
    data = _arguments(name, arguments)
    st = service.st
    with st.transaction() as conn:
        current = _current_grant(service, principal, name, conn)
        tenant, grant = current["tenant"]["id"], current["grant_id"]
        if name == "get_change_proposal":
            row = _proposal_row(st, tenant, data["proposal_id"], conn)
            require(row["grant_id"] == grant, "change proposal not found", 404)
            _permission(current["user"], "propose_" + row["operation"])
            _deadline(principal)
            return _proposal_view(row)
        request_id = data["request_id"]
        request_hash = _hash({"name": name, "arguments": data})
        prior = st.many("SELECT * FROM dashboard_mcp_write_receipts WHERE tenant_id=$1 AND grant_id=$2 AND request_id=$3",
                        tenant, grant, request_id, conn=conn)
        if prior:
            require(prior[0]["request_hash"] == request_hash, "request_id was already used for a different change", 409)
            result = prior[0]["result"]
            _deadline(principal)
            if name.startswith("propose_"):
                return _proposal_view(_proposal_row(st, tenant, result["id"], conn))
            return result
        details = {"client_id": current["client_id"], "grant_id": grant, "request_id": request_id}
        if name.startswith("propose_"):
            operation = name.removeprefix("propose_")
            require(st.scalar("SELECT count(*) FROM dashboard_mcp_changes WHERE tenant_id=$1 AND grant_id=$2 "
                              "AND status='pending' AND expires_at>clock_timestamp()", tenant, grant, conn=conn) < 20,
                    "too many pending change proposals", 429)
            before, after, parameters = _snapshot(st, tenant, operation, data, conn)
            ident = new_id()
            created_at = st.scalar("SELECT clock_timestamp()", conn=conn)
            expires_at = created_at + timedelta(minutes=15)
            client_name = st.scalar("SELECT name FROM dashboard_mcp_clients WHERE tenant_id=$1 AND id=$2",
                                    tenant, current["client_id"], conn=conn)
            digest = _hash({"tenant_id": tenant, "grant_id": grant, "client_id": current["client_id"],
                            "requester_id": current["user"]["id"], "id": ident, "operation": operation,
                            "expected_version": data["expected_version"], "before": before, "after": after,
                            "expires_at": expires_at})
            _deadline(principal)
            st.execute("""INSERT INTO dashboard_mcp_changes(id,tenant_id,grant_id,client_id,requester_id,requester_name,
                           request_id,operation,parameters,expected_version,before_state,after_state,digest,created_at,expires_at,client_name)
                          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)""",
                       ident, tenant, grant, current["client_id"], current["user"]["id"], current["user"]["name"],
                       request_id, operation, Jsonb(parameters), data["expected_version"], Jsonb(before), Jsonb(after),
                       digest, created_at, expires_at, client_name, conn=conn)
            result = _proposal_view(_proposal_row(st, tenant, ident, conn))
            _audit(st, current, "mcp.change.proposed", "mcp_change", ident, {**details, "operation": operation, "digest": digest}, conn)
        else:
            ident = data["finding_id"]
            try:
                row = st.one("SELECT status,resolution,updated_at FROM findings WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                             tenant, ident, conn=conn)
            except NotFound:
                raise APIError(404, "finding not found") from None
            if name == "add_finding_note":
                _deadline(principal)
                saved = st.add_note(tenant, ident, current["user"]["id"], data["body"], conn=conn)
                result = jsonable_encoder({"finding_id": ident, "note_id": saved["id"], "created_at": saved["created_at"]})
                details["note_id"] = saved["id"]
            else:
                expected = datetime.fromisoformat(data["expected_updated_at"].replace("Z", "+00:00"))
                require(row["updated_at"] == expected, "finding changed; read it again before updating", 409)
                update = {key: data[key] for key in ("status", "resolution", "assignee_id") if key in data}
                status = update.get("status", row["status"])
                require(status not in ("resolved", "false_positive") or bool(update.get("resolution", row["resolution"]).strip()),
                        "a resolution is required for a resolved or false-positive finding")
                if update.get("assignee_id"):
                    try:
                        assignee = st.get_user(tenant, update["assignee_id"], conn=conn)
                    except NotFound:
                        raise APIError(400, "assignee is not a user of this tenant") from None
                    require(assignee["status"] == "active", "assignee is inactive")
                elif "assignee_id" in update:
                    update["assignee_id"] = ""
                _deadline(principal)
                saved = st.update_finding(tenant, ident, update, conn=conn)
                result = jsonable_encoder({"finding_id": ident, "status": saved["status"],
                                           "assignee_id": saved["assignee_id"], "updated_at": saved["updated_at"]})
                details.update(fields=sorted(update), before_status=row["status"], status=saved["status"])
            _audit(st, current, "mcp." + name, "finding", ident, details, conn)
        st.execute("""INSERT INTO dashboard_mcp_write_receipts(tenant_id,grant_id,request_id,tool_name,request_hash,result)
                      VALUES($1,$2,$3,$4,$5,$6)""", tenant, grant, request_id, name, request_hash, Jsonb(result), conn=conn)
        _current_grant(service, principal, name, conn)
        _deadline(principal)
        return result


def _browser_user(service, principal, conn):
    from .dashboard_mcp_auth import validate_browser

    _deadline(principal)
    tenant = principal["tenant"]["id"]
    require(bool(service.cfg.tenant_id) and service.cfg.tenant_id == tenant, "incorrect tenant", 403)
    require(service.cfg.dashboard_mcp_enabled, "MCP is disabled", 403)
    try:
        current = validate_browser(service.st, service.cfg, principal, conn=conn)
    except NotFound:
        raise APIError(401, "account is unavailable") from None
    _deadline(principal)
    return current


def list_proposals(service, principal, *, limit=50, offset=0):
    require(type(limit) is int and 1 <= limit <= 100 and type(offset) is int and 0 <= offset <= 10000,
            "invalid proposal page")
    with service.st.transaction() as conn:
        current = _browser_user(service, principal, conn)
        _permission(current["user"], "get_change_proposal")
        allowed = [operation for operation in _OPERATIONS if _can_propose(current["user"], operation)]
        rows = service.st.many("SELECT *,clock_timestamp() >= expires_at AS expired FROM dashboard_mcp_changes "
                               "WHERE tenant_id=$1 AND operation=ANY($2::text[]) ORDER BY created_at DESC,id DESC LIMIT $3 OFFSET $4",
                               current["tenant"]["id"], allowed, limit + 1, offset, conn=conn)
        return {"items": [_proposal_view(row, browser=True) for row in rows[:limit]],
                "next_offset": offset + limit if len(rows) > limit else None}


def _can_propose(user, operation):
    try:
        _permission(user, "propose_" + operation)
        return True
    except APIError:
        return False


def get_proposal(service, principal, proposal_id):
    with service.st.transaction() as conn:
        current = _browser_user(service, principal, conn)
        row = _proposal_row(service.st, current["tenant"]["id"], proposal_id, conn)
        _permission(current["user"], "propose_" + row["operation"])
        return _proposal_view(row, browser=True)


def _lock_configuration(st, tenant, operation, conn):
    if operation == "company_policy":
        st.execute("INSERT INTO tenant_company_policies(tenant_id) VALUES($1) ON CONFLICT DO NOTHING", tenant, conn=conn)
        st.one("SELECT revision FROM tenant_company_policies WHERE tenant_id=$1 FOR UPDATE", tenant, conn=conn)
    else:
        prefix = "hook-settings:" if operation == "hook_mode" else "session-detection-settings:"
        st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", prefix + tenant, conn=conn)


def decide_proposal(service, principal, proposal_id, payload):
    _deadline(principal)
    require(isinstance(payload, dict) and set(payload) == {"decision", "digest"}
            and payload["decision"] in ("approve", "reject") and isinstance(payload["digest"], str),
            "provide decision and the reviewed digest")
    st = service.st
    with st.transaction() as conn:
        row = _proposal_row(st, principal["tenant"]["id"], proposal_id, conn, lock=True)
        require(row["digest"] == payload["digest"], "the reviewed change does not match", 409)
        if payload["decision"] == "approve":
            requester = {
                "tenant": {"id": row["tenant_id"]}, "user": {"id": row["requester_id"]},
                "grant_id": row["grant_id"], "client_id": row["client_id"],
            }
            _current_grant(service, requester, "propose_" + row["operation"], conn)
        current = _browser_user(service, principal, conn)
        _permission(current["user"], "propose_" + row["operation"])
        if row["status"] != "pending":
            require(row["status"] == ("applied" if payload["decision"] == "approve" else "rejected"),
                    "change proposal already decided", 409)
            _deadline(principal)
            return _proposal_view(row, browser=True)
        result = None
        if payload["decision"] == "approve":
            _lock_configuration(st, row["tenant_id"], row["operation"], conn)
            # Grant expiry continues to advance while a configuration writer holds its lock.
            _current_grant(service, requester, "propose_" + row["operation"], conn)
            current = _browser_user(service, principal, conn)
            _permission(current["user"], "propose_" + row["operation"])
        require(st.scalar("SELECT clock_timestamp() < $1", row["expires_at"], conn=conn),
                "change proposal expired; create a new proposal", 409)
        _deadline(principal)
        if payload["decision"] == "approve":
            data = {**row["parameters"], "expected_version": row["expected_version"]}
            before, after, _ = _snapshot(st, row["tenant_id"], row["operation"], data, conn)
            require(before == row["before_state"] and after == row["after_state"], "configuration changed; propose again", 409)
            actor = _actor(current)
            if row["operation"] == "hook_mode":
                result = hook_policy.save_settings(st, row["tenant_id"],
                                                  {"mode": data["mode"], "version": row["expected_version"]}, actor, conn=conn)
            elif row["operation"] == "detection_scheduling":
                result = session_aggregation.save_settings(st, row["tenant_id"], {"enabled": data["enabled"]}, actor,
                                                           expected_version=row["expected_version"], conn=conn)
            else:
                result = company_policy.save(st, row["tenant_id"],
                                             {"prompt": data["prompt"], "revision": row["expected_version"]}, actor, conn=conn)
            result = {"version": result.get("version", result.get("revision")), "applied": True}
        status = "applied" if payload["decision"] == "approve" else "rejected"
        st.execute("UPDATE dashboard_mcp_changes SET status=$3,decided_at=clock_timestamp(),decided_by=$4,result=$5 "
                   "WHERE tenant_id=$1 AND id=$2", row["tenant_id"], row["id"], status, current["user"]["id"],
                   Jsonb(result) if result is not None else None, conn=conn)
        _audit(st, current, "mcp.change." + status, "mcp_change", row["id"], {
            "client_id": row["client_id"], "grant_id": row["grant_id"], "requester_id": row["requester_id"],
            "operation": row["operation"], "digest": row["digest"],
        }, conn)
        result = _proposal_view(_proposal_row(st, row["tenant_id"], row["id"], conn), browser=True)
        if payload["decision"] == "approve":
            _current_grant(service, requester, "propose_" + row["operation"], conn)
        _browser_user(service, principal, conn)
        _deadline(principal)
        return result
