"""Tenant-scoped Cowork connectors for plugin hooks, inference hooks, and OTLP."""

import base64
import hashlib
import hmac
import json
import time

from cryptography.fernet import Fernet
from psycopg.types.json import Jsonb

from openaidr.core.cowork import identifier, inference_check, native_check
from openaidr.core.event import now
from openaidr.core.telemetry import attributes, count_records, scrub_export
from . import hook_policy, ingest_evidence
from .guardrail.inline import _bounded_transaction
from .httpx import APIError, require, uuid_param
from .store import hash_token, new_id, new_token

PUBLIC = "id,name,kind,organization_id,capture_content,disabled,created_at,last_hook_at,last_telemetry_at"


def signing_key(secret):
    if not isinstance(secret, str) or not secret.startswith("whsec_"):
        raise ValueError("invalid signing secret")
    key = base64.b64decode(secret[6:], validate=True)
    if len(key) < 16:
        raise ValueError("invalid signing secret")
    return key


def cipher(cfg):
    try:
        return Fernet(cfg.cowork_key.encode())
    except (ValueError, TypeError):
        raise APIError(503, "Configure OPENAIDR_COWORK_KEY before adding Enterprise connections") from None


def connections(st, tenant):
    return st.many(f"SELECT {PUBLIC} FROM cowork_connections WHERE tenant_id=$1 ORDER BY created_at DESC", tenant)


def create(st, tenant, data, actor, cfg):
    require(set(data) <= {"name", "kind", "organization_id", "signing_secrets", "capture_content"},
            "unknown Cowork connection field")
    name, kind = data.get("name"), data.get("kind")
    require(isinstance(name, str) and 0 < len(name.strip()) <= 128, "name is required")
    require(kind in ("enterprise", "plugin"), "kind must be enterprise or plugin")
    capture = data.get("capture_content", False)
    require(type(capture) is bool, "capture_content must be a boolean")
    org = data.get("organization_id", "")
    secrets = data.get("signing_secrets", [])
    require(isinstance(org, str) and len(org) <= 256, "invalid organization_id")
    require(isinstance(secrets, list) and len(secrets) <= 2, "provide at most two signing secrets")
    if kind == "enterprise":
        require(bool(org) and bool(secrets), "organization_id and signing_secrets are required")
        try:
            for secret in secrets:
                signing_key(secret)
        except (ValueError, TypeError):
            raise APIError(400, "invalid signing secret") from None
    else:
        require(not org and not secrets, "plugin connections must not contain organization credentials")
    ident, (token, hashed) = new_id(), new_token("oacw_")
    encrypted = (cipher(cfg).encrypt(json.dumps([tenant, ident, secrets]).encode()).decode()
                 if secrets else "")
    with st.transaction() as conn:
        row = st.one(f"""INSERT INTO cowork_connections
            (id,tenant_id,name,kind,organization_id,token_hash,encrypted_signing_secrets,capture_content)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING {PUBLIC}""",
            ident, tenant, name, kind, org, hashed, encrypted, capture, conn=conn)
        audit(st, tenant, actor, "cowork.create", ident, {"kind": kind, "capture_content": capture}, conn)
    root = cfg.browser_origin() + "/integrations/v1/cowork/" + ident
    return {**row, "token": token, "hook_url": root + ("/inference" if kind == "enterprise" else "/hooks"),
            "otlp_endpoint": root + "/otlp"}


def audit(st, tenant, actor, action, ident, details, conn):
    st.execute("""INSERT INTO audit_log
        (id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
        VALUES($1,$2,'user',$3,$4,$5,'cowork',$6,$7)""",
        new_id(), tenant, actor["id"], actor["name"], action, ident, Jsonb(details), conn=conn)


def revoke(st, tenant, ident, actor):
    uuid_param(ident, "connection id")
    with st.transaction() as conn:
        st.one("UPDATE cowork_connections SET disabled=true WHERE tenant_id=$1 AND id=$2 RETURNING id",
               tenant, ident, conn=conn)
        audit(st, tenant, actor, "cowork.revoke", ident, {}, conn)
    return {"disabled": True}


def verify_signature(secrets, headers, raw):
    ident, timestamp = headers.get("webhook-id", ""), headers.get("webhook-timestamp", "")
    try:
        if not ident or len(ident) > 256 or not timestamp.isascii() or not timestamp.isdecimal():
            return False
        if abs(time.time() - int(timestamp)) > 300:
            return False
        signed = (ident + "." + timestamp + ".").encode() + raw
        candidates = headers.get("webhook-signature", "").split()
        for secret in secrets:
            expected = b"v1," + base64.b64encode(hmac.new(signing_key(secret), signed, hashlib.sha256).digest())
            if any(hmac.compare_digest(expected, candidate.encode()) for candidate in candidates):
                return True
    except (ValueError, TypeError, OverflowError):
        pass
    return False


def authenticate(service, ident, headers, raw, *, inference=False, deadline):
    uuid_param(ident, "connection id")
    st, cfg = service.st, service.cfg
    require(cfg.enabled("ingest"), "no such route", 404)
    with _bounded_transaction(st, deadline, wait_for_capacity=True) as conn:
        rows = st.many("""SELECT c.*,t.status AS tenant_status FROM cowork_connections c
            JOIN tenants t ON t.id=c.tenant_id WHERE c.id=$1""", ident, conn=conn)
    require(bool(rows), "invalid Cowork connection", 401)
    row = rows[0]
    service.ensure_tenant(row["tenant_id"])
    require(not row["disabled"] and row["tenant_status"] == "active", "Cowork connection is disabled", 403)
    if inference:
        require(row["kind"] == "enterprise", "not an Enterprise connection", 403)
        bound_tenant, bound_id, secrets = json.loads(cipher(cfg).decrypt(row["encrypted_signing_secrets"].encode()))
        require(bound_tenant == row["tenant_id"] and bound_id == ident, "invalid signing credentials", 403)
        require(verify_signature(secrets, headers, raw), "invalid webhook signature", 401)
    else:
        value = headers.get("authorization", "")
        require(value.startswith("Bearer ") and hmac.compare_digest(hash_token(value[7:]), row["token_hash"]),
                "invalid Cowork token", 401)
    return row


def account_sensor(st, connection, account, deadline):
    # Enterprise identity comes from the signed actor or reported OTLP account.
    # A personal plugin token is always bound to its one configured account.
    account = account if connection["kind"] == "enterprise" else "plugin"
    require(isinstance(account, str) and 0 < len(account) <= 256, "invalid Cowork account")
    tenant, ident = connection["tenant_id"], connection["id"]
    with _bounded_transaction(st, deadline, wait_for_capacity=True) as conn:
        st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "cowork:" + ident, conn=conn)
        rows = st.many("""SELECT s.* FROM cowork_accounts a JOIN sensors s ON s.id=a.sensor_id
            WHERE a.connection_id=$1 AND a.account_id=$2 AND a.tenant_id=$3""", ident, account, tenant, conn=conn)
        if rows:
            sensor = rows[0]
        else:
            sensor_id = new_id()
            sensor = st.one("""INSERT INTO sensors(id,tenant_id,label,hostname,username,host_kind)
                VALUES($1,$2,$3,'Cowork connector',$4,'cloud') RETURNING *""",
                sensor_id, tenant, connection["name"], account, conn=conn)
            st.execute("INSERT INTO sensor_activity(sensor_id) VALUES($1)", sensor_id, conn=conn)
            st.execute("""INSERT INTO cowork_accounts(connection_id,tenant_id,account_id,sensor_id)
                VALUES($1,$2,$3,$4)""", ident, tenant, account, sensor_id, conn=conn)
    require(not sensor["disabled"] and sensor["deleted_at"] is None, "Cowork account is disabled", 403)
    return sensor


def prepare_hook(service, connection, headers, raw, inference, deadline):
    payload = ingest_evidence.loads(raw.decode("utf-8"))
    require(isinstance(payload, dict), "invalid Cowork request")
    if inference:
        require(payload.get("request_id") == headers.get("webhook-id"), "webhook identity mismatch", 401)
        require(payload.get("tenant_id") in (None, connection["organization_id"]), "organization mismatch", 403)
        actor = payload.get("actor")
        require(isinstance(actor, dict), "invalid inference actor")
        account = actor.get("id") or "unattributed"
        source = payload.get("source")
        require(isinstance(source, dict), "invalid inference source")
        # Source is advisory. The signed connection controls tenant routing.
        # Other Enterprise surfaces receive the same policy, not an allow bypass.
        ident = identifier(connection["id"], payload["request_id"])
        check = inference_check(payload, ident, capture_content=connection["capture_content"])
    else:
        require(connection["kind"] == "plugin", "not a plugin connection", 403)
        execution_id = headers.get("x-openaidr-execution-id", "")
        uuid_param(execution_id, "X-OpenAIDR-Execution-Id")
        ident = identifier(connection["id"], execution_id)
        account = "plugin"
        check = native_check(payload, ident, capture_content=connection["capture_content"])
    if check is None:
        return None, None, None, payload
    sensor = account_sensor(service.st, connection, account, deadline)
    row, created = hook_policy.prepare(service.st, sensor, check, deadline,
                                      link_detection=service.link_checker is not None, customer=service.customer)
    with _bounded_transaction(service.st, deadline, wait_for_capacity=True) as conn:
        if created and check["actions"]:
            events = [{**hook_policy.redact_value(action), "id": identifier(ident, index), "time": now(),
                       "agent": {"product": check["product"], "account": account},
                       "session": {"id": check["session_id"]},
                       "source": {"collector": "claude-inference" if inference else "cowork-hook",
                                  "hook_request_id": ident}}
                      for index, action in enumerate(check["actions"])]
            service.st.ingest_batch(sensor, events, conn=conn)
        service.st.execute("UPDATE cowork_connections SET last_hook_at=clock_timestamp() WHERE id=$1",
                           connection["id"], conn=conn)
    return row, created, check, payload


def telemetry(service, connection, payload, batch_id, deadline):
    groups = {}
    for resource in payload.get("resourceLogs", []):
        resource_attrs = attributes(resource.get("resource", {}).get("attributes"))
        account_resources = {}
        for scope in resource.get("scopeLogs", []):
            account_scopes = {}
            for item in scope.get("logRecords", []):
                attrs = {**resource_attrs, **attributes(item.get("attributes"))}
                require(resource_attrs.get("service.name") == "cowork" and attrs.get("service.name") == "cowork",
                        "only Cowork telemetry is accepted")
                if connection["kind"] == "enterprise":
                    require(attrs.get("organization.id") == connection["organization_id"], "organization mismatch", 403)
                    account = attrs.get("user.account_id") or attrs.get("user.account_uuid") or "unattributed"
                else:
                    account = "plugin"
                require(isinstance(account, str) and 0 < len(account) <= 256, "invalid Cowork account")
                group = groups.setdefault(account, {"resourceLogs": []})
                require(len(groups) <= 128, "too many Cowork accounts in one export", 413)
                # Preserve shared metadata once per resource/scope in each account.
                # scrub_export copies and redacts one account at a time below.
                if account not in account_resources:
                    account_resources[account] = {**resource, "scopeLogs": []}
                    group["resourceLogs"].append(account_resources[account])
                if account not in account_scopes:
                    account_scopes[account] = {**scope, "logRecords": []}
                    account_resources[account]["scopeLogs"].append(account_scopes[account])
                account_scopes[account]["logRecords"].append(item)
    for account, group in groups.items():
        sensor = account_sensor(service.st, connection, account, deadline)
        capture = connection["capture_content"]
        group = scrub_export("logs", group, capture_prompts=capture, capture_tool_details=capture,
                             capture={key: capture for key in ("prompt_text", "response_text", "tool_input", "tool_output")})
        for resource in group["resourceLogs"]:
            attrs = resource["resource"].get("attributes", [])
            resource["resource"]["attributes"] = [a for a in attrs if a.get("key") != "openaidr.cowork.account"] + [{
                "key": "openaidr.cowork.account", "value": {"stringValue": identifier(connection["id"], account)},
            }]
            for scope in resource["scopeLogs"]:
                for item in scope["logRecords"]:
                    item["attributes"] = [a for a in item.get("attributes", []) if a.get("key") != "openaidr.cowork.account"]
        # Retries of the same batch and account retain one export identity.
        with _bounded_transaction(service.st, deadline, wait_for_capacity=True) as conn:
            service.st.ingest_telemetry(sensor, "logs", identifier(connection["id"], batch_id, account),
                                       group, count_records("logs", group), conn=conn)
    with _bounded_transaction(service.st, deadline, wait_for_capacity=True) as conn:
        service.st.execute("UPDATE cowork_connections SET last_telemetry_at=clock_timestamp() WHERE id=$1",
                           connection["id"], conn=conn)


def record_returned(st, row, action, deadline):
    # The wire protocol can map ask to deny or warn to allow. This records the
    # response being returned, without asserting delivery or enforcement.
    with _bounded_transaction(st, deadline, wait_for_capacity=True) as conn:
        st.execute("""UPDATE ordinary_hook_checks SET returned_decision=$3
            WHERE id=$1 AND tenant_id=$2 AND status='evaluated'""",
            row["id"], row["tenant_id"], action, conn=conn)
