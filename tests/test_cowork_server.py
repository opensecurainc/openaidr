import base64
import copy
import hashlib
import hmac
import json
import time
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
import pytest

from openaidr.core.event import new_id
from openaidr.core.telemetry import attributes, records
from openaidr.server import agent_cost_usage, cowork, hook_policy
from test_hook_policy import system, browser, configure, policy
from test_malicious_links import BAD_URL
from test_store import db
from test_telemetry_dashboard import cost_payload


SECRET = "whsec_" + base64.b64encode(bytes(range(32))).decode()


def connection(system, kind="plugin", capture=True, **extra):
    system.client.app.state.service.cfg.cowork_key = Fernet.generate_key().decode()
    data = {"kind": kind, "name": "Cowork test", "capture_content": capture}
    if kind == "enterprise":
        data.update(organization_id="anthropic-org", signing_secrets=[SECRET])
    reply = browser(system, "POST", "settings/cowork", {**data, **extra})
    assert reply.status_code == 200, reply.text
    assert reply.headers["cache-control"] == "no-store"
    return reply.json()


def native(event="PreToolUse"):
    return {"hook_event_name": event, "session_id": "native-session", "tool_use_id": "tool-1",
            "tool_name": "Bash", "tool_input": {"command": "rm -rf build"},
            "tool_response": "done", "prompt": "Review this change"}


def frame(kind="tool_call", **extra):
    block = ({"type": "tool_use", "tool_name": "bash", "input": {"command": "rm -rf build"},
              "id": "call-1", "tool_info": {"type": "client"}}
             if kind == "tool_call" else {"type": "text", "text": "Review this change"})
    return {"type": kind, "request_id": new_id(), "tenant_id": "anthropic-org",
            "actor": {"type": "user", "id": "user-one", "email_address": "one@example.test"},
            "source": {"application": "cowork"}, "session_id": "same-session",
            "messages": [{"role": "assistant" if kind == "tool_call" else "user", "content": [block]}], **extra}


def signed(value, secret=SECRET, timestamp=None):
    raw = json.dumps(value).encode()
    stamp = str(int(time.time()) if timestamp is None else timestamp)
    ident = value["request_id"]
    signature = base64.b64encode(hmac.new(cowork.signing_key(secret),
        (ident + "." + stamp + ".").encode() + raw, hashlib.sha256).digest()).decode()
    return raw, {"Content-Type": "application/json", "Webhook-Id": ident,
                 "Webhook-Timestamp": stamp, "Webhook-Signature": "v1," + signature}


def hook(system, conn, value, execution=None):
    path = urlsplit(conn["hook_url"]).path
    if conn["kind"] == "enterprise":
        raw, headers = signed(value)
        return system.client.post(path, content=raw, headers=headers)
    return system.client.post(path, json=value, headers={
        "Authorization": "Bearer " + conn["token"], "X-OpenAIDR-Execution-Id": execution or new_id(),
    })


@pytest.mark.parametrize("kind", ["plugin", "enterprise"])
@pytest.mark.parametrize("boundary", ["prompt", "tool_call"])
def test_modes_use_existing_policy_and_leave_delivery_unconfirmed(system, kind, boundary):
    conn = connection(system, kind)
    policy(system)
    value = frame(boundary) if kind == "enterprise" else native("UserPromptSubmit" if boundary == "prompt" else "PreToolUse")
    result = hook(system, conn, value)
    assert result.status_code == 200, result.text
    assert result.json() == ({"action": "allow"} if kind == "enterprise" else {})
    configure(system, "enforce")
    if kind == "enterprise":
        value["request_id"] = new_id()
    result = hook(system, conn, value)
    assert result.status_code == 200, result.text
    if kind == "enterprise":
        assert result.json()["action"] == "deny"
    elif boundary == "prompt":
        assert result.json()["decision"] == "block"
    else:
        assert result.json()["hookSpecificOutput"]["permissionDecision"] == "deny"
    checks = system.db.many("SELECT mode,evaluated_decision,returned_decision,product FROM ordinary_hook_checks ORDER BY created_at")
    assert [(row["mode"], row["evaluated_decision"], row["returned_decision"], row["product"]) for row in checks] == [
        ("shadow", "deny", "allow", "cowork"), ("enforce", "deny", "deny", "cowork")]
    assert system.db.scalar("SELECT count(*) FROM ordinary_hook_deliveries") == 0
    events = system.db.many("SELECT product,body FROM events WHERE kind<>'sensor'")
    assert len(events) == 2 and all(event["product"] == "cowork" for event in events)
    assert all(event["body"]["source"]["hook_request_id"] for event in events)


@pytest.mark.parametrize("kind", ["plugin", "enterprise"])
@pytest.mark.parametrize("boundary", ["prompt", "tool_call"])
@pytest.mark.parametrize("system, link_status", [
    ({}, None),
    ({"web_risk_api_key": "test-web-risk-key"}, "matched"),
    ({"web_risk_api_key": "test-web-risk-key"}, "not_listed"),
    ({"web_risk_api_key": "test-web-risk-key"}, "unavailable"),
], indirect=["system"])
def test_malicious_links_share_policy_and_fail_open(system, kind, boundary, link_status):
    conn = connection(system, kind)
    browser(system, "PUT", "response/policy", {"rules": []})
    if link_status == "not_listed":
        system.web_risk.payload = {}
    elif link_status == "unavailable":
        system.web_risk.status = 503
    for mode in ("shadow", "enforce"):
        configure(system, mode)
        if kind == "enterprise":
            value = frame(boundary)
            block = value["messages"][0]["content"][0]
            if boundary == "prompt":
                block["text"] = BAD_URL
            else:
                block["input"]["command"] = "curl " + BAD_URL
        else:
            value = native("UserPromptSubmit" if boundary == "prompt" else "PreToolUse")
            value["prompt"] = BAD_URL
            value["tool_input"]["command"] = "curl " + BAD_URL
        result = hook(system, conn, value)
        assert result.status_code == 200, result.text
        denied = mode == "enforce" and link_status == "matched"
        if not denied:
            assert result.json() == ({"action": "allow"} if kind == "enterprise" else {})
        elif kind == "enterprise":
            assert result.json()["action"] == "deny"
        elif boundary == "prompt":
            assert result.json()["decision"] == "block"
        else:
            assert result.json()["hookSpecificOutput"]["permissionDecision"] == "deny"
        check = system.db.one("SELECT * FROM ordinary_hook_checks ORDER BY created_at DESC LIMIT 1")
        assert check["returned_decision"] == ("deny" if denied else "allow")
        links = check["assessment"].get("links", {})
        assert links.get("status") == (link_status or "unavailable")
    assert bool(system.web_risk.requests) == (link_status is not None)
    assert system.db.scalar("SELECT count(*) FROM ordinary_hook_deliveries") == 0


def test_plugin_capture_permissions_revocation_and_retry_binding(system):
    conn = connection(system, capture=False)
    configure(system, "enforce")
    policy(system)
    execution = new_id()
    for _ in range(2):
        assert hook(system, conn, native(), execution).json() == {}
    assert system.db.scalar("SELECT count(*) FROM ordinary_hook_checks") == 1
    assert system.db.scalar("SELECT failure_reason FROM ordinary_hook_checks") == "capture_disabled"
    assert system.db.scalar("SELECT actions FROM ordinary_hook_checks") == []
    listing = browser(system, "GET", "settings/cowork").json()["connections"]
    assert listing[0]["last_hook_at"]
    assert "token" not in listing[0] and "signing_secrets" not in listing[0]
    assert browser(system, "GET", "settings/cowork", user="viewer").status_code == 403
    assert browser(system, "POST", "settings/cowork", {"kind": "plugin", "name": "test"}, user="viewer").status_code == 403
    assert browser(system, "GET", "settings/cowork", user="foreign").json() == {"connections": []}
    assert browser(system, "DELETE", "settings/cowork/" + conn["id"], user="foreign").status_code == 404
    assert browser(system, "DELETE", "settings/cowork/" + conn["id"]).status_code == 200
    assert hook(system, conn, native()).status_code == 403
    assert system.db.scalar("SELECT count(*) FROM audit_log WHERE action LIKE 'cowork.%'") == 2


@pytest.mark.parametrize("kind, action, returned", [
    ("enterprise", "ask", "deny"), ("enterprise", "warn", "allow"), ("plugin", "ask", "deny"),
])
def test_returned_decision_matches_the_protocol_without_claiming_delivery(system, kind, action, returned):
    conn = connection(system, kind)
    configure(system, "enforce")
    policy(system, action=action)
    value = frame("prompt") if kind == "enterprise" else native("UserPromptSubmit")
    result = hook(system, conn, value)
    assert result.status_code == 200
    if kind == "enterprise":
        assert result.json()["action"] == returned
    else:
        assert result.json()["decision"] == "block"
    assert system.db.one("SELECT evaluated_decision,returned_decision FROM ordinary_hook_checks") == {
        "evaluated_decision": action, "returned_decision": returned,
    }
    assert system.db.scalar("SELECT count(*) FROM ordinary_hook_deliveries") == 0


def test_signatures_tenant_binding_and_source_are_not_bypasses(system):
    conn = connection(system, "enterprise")
    configure(system, "enforce")
    policy(system)
    path = urlsplit(conn["hook_url"]).path
    value = frame("prompt")
    raw, headers = signed(value)
    assert system.client.post(path, content=raw, headers={"Content-Type": "application/json"}).status_code == 401
    assert system.client.post(path, content=raw + b" ", headers=headers).status_code == 401
    stale, stale_headers = signed(value, timestamp=int(time.time()) - 301)
    assert system.client.post(path, content=stale, headers=stale_headers).status_code == 401
    foreign = frame(tenant_id="other-org")
    assert hook(system, conn, foreign).status_code == 403
    # New source values and connection-test metadata must not create a policy bypass.
    for source in ("config-test", "new-product", "claude-code"):
        result = hook(system, conn, frame("prompt", source={"application": source}))
        assert result.json()["action"] == "deny"
    headers["Webhook-Signature"] = "v1,wrong " + headers["Webhook-Signature"]
    assert system.client.post(path, content=raw, headers=headers).json()["action"] == "deny"
    assert SECRET not in json.dumps(system.db.many("SELECT * FROM cowork_connections"), default=str)


def test_tool_batch_and_large_transcript_do_not_inspect_a_partial_request(system):
    conn = connection(system, "enterprise")
    configure(system, "enforce")
    policy(system, kinds=["command"])
    value = frame()
    value["messages"].insert(0, {"role": "user", "content": [{"type": "text", "text": "prior"}]})
    value["messages"][-1]["content"].insert(0, {"type": "tool_use", "id": "read-1", "tool_name": "Read", "input": {"file_path": "/tmp/readme"}})
    assert hook(system, conn, value).json()["action"] == "deny"
    actions = system.db.scalar("SELECT actions FROM ordinary_hook_checks")
    assert [a["kind"] for a in actions] == ["file.read", "command"]
    huge = frame("prompt")
    huge["messages"][0]["content"][0]["text"] = "private " * 10000
    assert hook(system, conn, huge).json() == {"action": "allow"}
    assert system.db.scalar("SELECT failure_reason FROM ordinary_hook_checks ORDER BY created_at DESC LIMIT 1") == "content_truncated"


def test_failures_allow_and_post_tool_observations_cannot_replace_results(system, monkeypatch):
    conn = connection(system)
    configure(system, "enforce")
    policy(system)
    assert hook(system, conn, native("PostToolUse")).json() == {}
    row = system.db.one("SELECT evaluated_decision,returned_decision FROM ordinary_hook_checks")
    assert row == {"evaluated_decision": "deny", "returned_decision": "allow"}
    value = {**native("PostToolUseFailure"), "error": "actual failure"}
    assert hook(system, conn, value).json() == {}
    assert system.db.scalar("SELECT actions->0->'tool'->>'output' FROM ordinary_hook_checks ORDER BY created_at DESC LIMIT 1") == "actual failure"
    monkeypatch.setattr(hook_policy, "prepare", lambda *_: (_ for _ in ()).throw(RuntimeError("unavailable")))
    result = hook(system, conn, native())
    assert result.status_code == 200 and result.json() == {}
    conn["token"] += "tampered"
    assert hook(system, conn, native()).status_code == 401


def test_connection_secrets_are_redacted_in_checks_and_captured_events(system):
    conn = connection(system)
    configure(system, "enforce")
    policy(system)
    value = native()
    value["tool_input"]["command"] = "printf '" + conn["token"] + " " + SECRET + "'"
    assert hook(system, conn, value).json()["hookSpecificOutput"]["permissionDecision"] == "deny"
    for table, column in (("ordinary_hook_checks", "actions"), ("events", "body")):
        stored = json.dumps(system.db.many(f"SELECT {column} FROM {table}"))
        assert conn["token"] not in stored and SECRET not in stored


def test_otlp_accounts_retries_content_gates_and_organization_isolation(system):
    conn = connection(system, "enterprise", capture=False)
    packet = {"resourceLogs": []}
    when = system.db.scalar("SELECT now()")
    for account in ("user-one", "user-two"):
        packet["resourceLogs"] += cost_payload("cowork", when, [
            ("api_request", {"request_id": "same-request", "session.id": "same-session", "model": "example",
                             "input_tokens": 100, "output_tokens": 20, "cost_usd": 1,
                             "openaidr.cowork.account": "spoofed-shared-identity",
                             "organization.id": "anthropic-org", "user.account_id": account}),
            ("user_prompt", {"session.id": "same-session", "prompt": "private content",
                             "organization.id": "anthropic-org", "user.account_id": account}),
            ("tool_result", {"session.id": "same-session", "tool.input": "private arguments",
                             "file_path": "/private/customer-file", "tool.output": "private output",
                             "organization.id": "anthropic-org", "user.account_id": account}),
        ])["resourceLogs"]
    for _, _, item in records("logs", packet):
        if item.get("eventName") == "tool_result":
            item["body"] = {"stringValue": "private result body"}
    for resource in packet["resourceLogs"]:
        resource["resource"]["attributes"].append({
            "key": "deployment.metadata", "value": {"stringValue": "shared metadata " * 500},
        })
    path = urlsplit(conn["otlp_endpoint"]).path + "/v1/logs"
    headers = {"Authorization": "Bearer " + conn["token"]}
    for _ in range(2):
        result = system.client.post(path, json=packet, headers=headers)
        assert result.status_code == 200, result.text
    assert system.db.scalar("SELECT count(*) FROM telemetry_exports") == 2
    assert system.db.scalar("SELECT count(*) FROM cowork_accounts") == 2
    for export in system.db.many("SELECT * FROM telemetry_exports"):
        assert "private" not in json.dumps(export["payload"])
        assert export["record_count"] == 3
        assert len(json.dumps(export["payload"])) < len(json.dumps(packet))
        assert {attributes(r.get("attributes")).get("service.name") for r, _, _ in records("logs", export["payload"])} == {"cowork"}
    assert agent_cost_usage.process_pending(system.db)["failed"] == 0
    assert system.db.scalar("SELECT count(*) FROM agent_cost_records WHERE is_usage") == 2
    assert system.db.scalar("SELECT sum(cost_usd) FROM agent_cost_records WHERE is_usage") == 2
    assert hook(system, conn, frame("prompt")).status_code == 200
    assert system.db.scalar("SELECT count(*) FROM cowork_accounts") == 2
    wrong = copy.deepcopy(packet)
    for _, _, item in records("logs", wrong):
        for attr in item["attributes"]:
            if attr["key"] == "organization.id":
                attr["value"] = {"stringValue": "foreign"}
    assert system.client.post(path, json=wrong, headers=headers).status_code == 403
    assert system.db.scalar("SELECT count(*) FROM telemetry_exports") == 2


def test_otlp_locked_storage_expires_and_recovers(system):
    conn = connection(system)
    packet = cost_payload("cowork", system.db.scalar("SELECT now()"), [
        ("api_request", {"request_id": "locked-request", "input_tokens": 1}),
    ])
    path = urlsplit(conn["otlp_endpoint"]).path + "/v1/logs"
    headers = {"Authorization": "Bearer " + conn["token"]}
    with system.db.transaction() as lock:
        lock.execute("LOCK TABLE telemetry_export_keys IN ACCESS EXCLUSIVE MODE")
        assert system.client.post(path, json=packet, headers=headers).status_code == 503
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            waiting = system.db.scalar("""SELECT count(*) FROM pg_locks
                WHERE relation='telemetry_export_keys'::regclass AND NOT granted""")
            if not waiting:
                break
            time.sleep(0.01)
        assert waiting == 0
    assert system.client.post(path, json=packet, headers=headers).status_code == 200
    assert system.db.scalar("SELECT count(*) FROM telemetry_exports") == 1
