"""Ordinary hook decisions through HTTP and PostgreSQL, with only the external model transport mocked."""

import copy
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from openaidr.core.event import new_id
from openaidr.server import auth
from openaidr.server.app import create_app
from openaidr.server.config import Config
from test_store import db, sensor, tenant
from test_inline_guardrail import Provider
from openaidr.server.guardrail import scoring
from openaidr.server import malicious_links
from test_malicious_links import BAD_URL, WebRiskProvider


def upload_receipt(system, request, status, action="allow", device="sensor", ident=None, timestamp=None):
    from openaidr.core.event import now

    event = {"id": ident or new_id(), "time": timestamp or now(), "kind": "sensor",
             "agent": {"product": request["product"]},
             "source": {"collector": "hook-delivery", "hook_request_id": request["request_id"]},
             "hook": {"delivery_status": status, "delivered_decision": action}}
    client = system.foreign_client if device == "foreign_sensor" else system.client
    result = client.post("/ingest/v1/events", json={"events": [event]}, headers=system.headers[device])
    assert result.status_code == 200, result.text
    return event, result.json()


@pytest.fixture
def system(db, monkeypatch, request, tmp_path):
    provider = Provider()
    web_risk = WebRiskProvider()
    own, other = tenant(db), tenant(db)
    users = {
        "admin": db.create_user(own["id"], "admin@example.test", "Admin", "hash", "owner"),
        "viewer": db.create_user(own["id"], "viewer@example.test", "Viewer", "hash", "viewer"),
        "foreign": db.create_user(other["id"], "foreign@example.test", "Other", "hash", "owner"),
    }
    sensors = {"sensor": sensor(db, own["id"]), "peer": sensor(db, own["id"]),
               "foreign_sensor": sensor(db, other["id"])}
    headers = {key: {"Cookie": auth.CONSOLE_COOKIE + "=" + db.create_session(user["id"], user["tenant_id"]),
                     auth.CSRF_HEADER: "1"} for key, user in users.items()}
    headers.update({key: {"Authorization": "Bearer " + token} for key, (_, token, _) in sensors.items()})
    settings = getattr(request, "param", "test-provider-key")
    settings = {"jev_api_key": settings} if isinstance(settings, str) else dict(settings)
    from intelligence_fixture import intelligence_service
    guardrail_key = settings.pop("jev_api_key", "")
    web_risk_key = settings.pop("web_risk_api_key", "")
    origin = settings.pop("intelligence_origin", "https://intelligence.test")
    async def upstream(request):
        if request.url.host == "api.typesafe.ai":
            return await provider.handle(request)
        return await web_risk.handle(request)
    with intelligence_service(monkeypatch, tmp_path, own["id"], upstream,
                              guardrail_key=guardrail_key, web_risk_key=web_risk_key, origin=origin) as api:
        cfg = Config(database_url=db.url, public_url="http://testserver", cost_processing=False,
                     **api.config, **settings)
        cfg.set_services("ingest")
        foreign_cfg = replace(cfg, tenant_id=other["id"], intelligence_origin="", intelligence_api_key="")
        with TestClient(create_app(cfg, db)) as client, TestClient(create_app(foreign_cfg, db)) as foreign_client:
            # Start only ingest workers; expose API routes for test administration.
            cfg.set_services("api,ingest")
            foreign_cfg.set_services("api,ingest")
            yield SimpleNamespace(db=db, client=client, cfg=cfg, tenant=own, headers=headers, sensors=sensors,
                                  provider=provider, web_risk=web_risk, foreign_client=foreign_client)


def browser(system, method, path, value=None, user="admin"):
    client = getattr(system, "foreign_client", system.client) if user == "foreign" else system.client
    return client.request(method, "/api/v1/" + path, json=value, headers=system.headers[user])


def configure(system, mode):
    current = browser(system, "GET", "response/hook-settings").json()
    result = browser(system, "PUT", "response/hook-settings", {"mode": mode, "version": current["version"]})
    assert result.status_code == 200, result.text
    return result.json()


def policy(system, action="deny", kinds=None):
    result = browser(system, "PUT", "response/policy", {"rules": [{
        "id": "test-rule", "name": "Test rule", "enabled": True, "action": action,
        "reason": "Configured policy reason", "match": {"kinds": kinds or ["command", "prompt", "tool.result"]},
    }]})
    assert result.status_code == 200, result.text
    return result.json()["version"]


def payload(event="PreToolUse", product="claude-code"):
    action = ({"kind": "command", "command": {"text": "rm -rf build"}, "tool": {"name": "Bash"}}
              if event == "PreToolUse" else {"kind": "prompt", "text": "Review this change"}
              if event == "UserPromptSubmit" else {"kind": "tool.result", "tool": {"name": "Bash", "output": "done"}})
    return {"request_id": new_id(), "product": product, "hook_event": event,
            "session_id": "native-session", "tool_call_id": "", "actions": [action], "timeout_ms": 1800}


def check(system, value, expected=200, device="sensor"):
    client = system.foreign_client if device == "foreign_sensor" else system.client
    result = client.post("/ingest/v1/hook-checks", json=value, headers=system.headers.get(device, {}))
    assert result.status_code == expected, result.text
    assert result.headers["cache-control"] == "no-store"
    return result.json()


def test_shadow_settings_permissions_versions_and_audit(system):
    assert browser(system, "GET", "response/hook-settings").json() == {
        "mode": "shadow", "version": 0, "updated_at": None,
    }
    assert browser(system, "PUT", "response/hook-settings", {"mode": "enforce", "version": 0}, user="viewer").status_code == 403
    configured = configure(system, "enforce")
    assert configured["version"] == 1
    assert browser(system, "PUT", "response/hook-settings", {"mode": "shadow", "version": 0}).status_code == 409
    assert browser(system, "GET", "response/hook-settings", user="foreign").json()["mode"] == "shadow"
    audit = system.db.one("SELECT details FROM audit_log WHERE tenant_id=$1 AND action='hooks.configure'", system.tenant["id"])
    assert audit["details"] == {"before": "shadow", "mode": "enforce", "version": 1}


@pytest.mark.parametrize("event", ["UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure"])
@pytest.mark.parametrize("action", ["allow", "warn", "ask", "deny"])
def test_shadow_and_enforce_preserve_evaluated_decisions(system, event, action):
    version = policy(system, action)
    request = payload(event)
    request["actions"][0]["session"] = {"id": "native-session", "cwd": "/work/project"}
    shadow = check(system, request)
    assert shadow["mode"] == "shadow"
    assert shadow["evaluated_decision"] == action
    assert shadow["returned_decision"] == "allow"
    assert shadow["policy_version"] == version
    assert shadow["delivery_status"] == "unconfirmed"
    assert shadow["reason"] == "Configured policy reason"
    assert system.db.scalar("SELECT project FROM agent_project_evidence WHERE event_key=$1",
                            f"hook:{shadow['id']}:0") == "project"
    configure(system, "enforce")
    enforced = check(system, payload(event))
    assert enforced["returned_decision"] == action
    assert enforced["settings_version"] == 1
    assert enforced["delivery_status"] == "unconfirmed"


def test_retries_bind_content_and_keep_original_versions(system):
    policy(system)
    value = payload()
    first = check(system, value)
    configure(system, "enforce")
    retry = check(system, {**value, "timeout_ms": 1000})
    assert retry == first
    changed = copy.deepcopy(value)
    changed["actions"][0]["command"]["text"] = "git status"
    check(system, changed, 409)
    assert system.db.scalar("SELECT count(*) FROM ordinary_hook_checks") == 1
    peer = check(system, value, device="peer")
    assert peer["id"] != first["id"]


@pytest.mark.parametrize("product", ["github-copilot", "cursor", "antigravity", "opencode", "hermes-agent"])
def test_new_products_use_backend_modes_and_store_observation_limits(system, product):
    policy(system)
    shadow = check(system, payload(product=product))
    assert shadow["evaluated_decision"] == "deny" and shadow["returned_decision"] == "allow"
    configure(system, "enforce")
    denied = check(system, payload(product=product))
    assert denied["product"] == product and denied["returned_decision"] == "deny"
    observation = payload("PostToolUse", product)
    observation["control_supported"] = False
    result = check(system, observation)
    assert result["evaluated_decision"] == "deny" and result["returned_decision"] == "allow"
    policy(system, "allow")
    assert check(system, payload(product=product))["returned_decision"] == "allow"
    assert system.db.scalar("SELECT count(*) FROM ordinary_hook_checks WHERE product=$1", product) == 4


def test_multiple_targets_and_product_selectors_use_backend_policy(system):
    result = browser(system, "PUT", "response/policy", {"rules": [{
        "id": "private-path", "name": "Private files", "enabled": True, "action": "deny",
        "match": {"products": ["claude-code"], "kinds": ["file.write"], "path_glob": "**/.ssh/**"},
    }]})
    assert result.status_code == 200, result.text
    configure(system, "enforce")
    value = payload()
    value["actions"].append({"kind": "file.write", "file": {"path": "/home/alice/.ssh/config"}})
    assert check(system, value)["returned_decision"] == "deny"
    other = {**value, "request_id": new_id(), "product": "codex-cli"}
    allowed = check(system, other)
    assert allowed["returned_decision"] == "allow" and allowed["rule_id"] == ""


def test_remote_path_globs_use_sensor_platform_without_changing_regex_flags(system):
    result = browser(system, "PUT", "response/policy", {"rules": [
        {"id": "ssh", "name": "SSH keys", "enabled": True, "action": "deny",
         "match": {"kinds": ["file.read"], "path_glob": "~/.ssh/**"}},
        {"id": "command", "name": "Case sensitive command", "enabled": True, "action": "deny",
         "match": {"command_regex": "^SECRET$"}},
        {"id": "host", "name": "Host", "enabled": True, "action": "deny",
         "match": {"host_glob": "private.example"}},
    ]})
    assert result.status_code == 200, result.text
    configure(system, "enforce")
    sensor_id = system.sensors["sensor"][0]["id"]
    for source_os, target, expected in (
        ("windows", "C:/Users/Alice/.SSH/id_rsa", "deny"),
        ("windows", "C:/users/Alice/.ssh/id_rsa", "deny"),
        ("windows", r"C:\USERS\Alice\.SSH\id_rsa", "deny"),
        ("linux", "/home/alice/.SSH/id_rsa", "allow"),
        ("linux", "/home/alice/.ssh/id_rsa", "deny"),
        ("darwin", "/Users/alice/.SSH/id_rsa", "allow"),
    ):
        system.db.execute("UPDATE sensors SET os=$2 WHERE id=$1", sensor_id, source_os)
        value = payload()
        value["actions"] = [{"kind": "file.read", "file": {"path": target}}]
        value["path_home"] = ("C:/Users/Alice" if source_os == "windows" else
                              "/Users/alice" if source_os == "darwin" else "/home/alice")
        assert check(system, value)["returned_decision"] == expected
    system.db.execute("UPDATE sensors SET os='windows' WHERE id=$1", sensor_id)
    for command, expected in (("SECRET", "deny"), ("secret", "allow")):
        value = payload()
        value["actions"] = [{"kind": "command", "command": {"text": command}}]
        assert check(system, value)["returned_decision"] == expected
    value = payload()
    value["actions"] = [{"kind": "network", "network": {"host": "PRIVATE.EXAMPLE"}}]
    assert check(system, value)["returned_decision"] == "deny"


def test_remote_home_context_supports_custom_homes_without_backend_home(system, monkeypatch):
    result = browser(system, "PUT", "response/policy", {"rules": [{
        "id": "ssh", "name": "SSH keys", "enabled": True, "action": "deny",
        "match": {"kinds": ["file.read"], "path_glob": "~/.ssh/**"},
    }]})
    assert result.status_code == 200, result.text
    configure(system, "enforce")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/srv/backend-home")))
    sensor_id = system.sensors["sensor"][0]["id"]
    for source_os, home, target, expected in (
        ("linux", "/srv/users/a[1]", "/srv/backend-home/.ssh/id_rsa", "allow"),
        ("linux", "/srv/users/a[1]", "/srv/users/a[1]/.ssh/id_rsa", "deny"),
        ("linux", "/srv/users/a[1]/", "/srv/users/a[1]/.ssh/id_rsa", "deny"),
        ("linux", "/srv/users/a[1]", "/srv/users/a[1]/.SSH/id_rsa", "allow"),
        ("linux", "/", "/.ssh/id_rsa", "deny"),
        ("windows", r"D:\Profiles\Alice", r"d:\profiles\ALICE\.SSH\id_rsa", "deny"),
        ("windows", "D:/Profiles/Alice/", "d:/profiles/ALICE/.SSH/id_rsa", "deny"),
    ):
        system.db.execute("UPDATE sensors SET os=$2 WHERE id=$1", sensor_id, source_os)
        value = payload()
        value["actions"] = [{"kind": "file.read", "file": {"path": target}}]
        if home is not None:
            value["path_home"] = home
        assert check(system, value)["returned_decision"] == expected
    value["path_home"] = "D:/Profiles/Bob"
    check(system, value, 409)


def test_concurrent_source_platforms_do_not_change_process_path_semantics(system):
    from openaidr.core.policy import compile_glob

    result = browser(system, "PUT", "response/policy", {"rules": [{
        "id": "ssh", "name": "SSH keys", "enabled": True, "action": "deny",
        "match": {"kinds": ["file.read"], "path_glob": "~/.ssh/**"},
    }]})
    assert result.status_code == 200, result.text
    configure(system, "enforce")
    system.db.execute("UPDATE sensors SET os='windows' WHERE id=$1", system.sensors["sensor"][0]["id"])
    system.db.execute("UPDATE sensors SET os='linux' WHERE id=$1", system.sensors["peer"][0]["id"])
    flags = compile_glob("~/.ssh/**").flags

    def decide(device):
        value = payload()
        value["actions"] = [{"kind": "file.read", "file": {"path": "/home/alice/.SSH/id_rsa"}}]
        value["path_home"] = "/home/alice"
        return check(system, value, device=device)["returned_decision"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        for _ in range(4):
            assert list(pool.map(decide, ("sensor", "peer"))) == ["deny", "allow"]
    assert compile_glob("~/.ssh/**").flags == flags


def test_path_matching_requires_applicable_source_context(system):
    result = browser(system, "PUT", "response/policy", {"rules": [{
        "id": "ssh", "name": "SSH keys", "enabled": True, "action": "deny",
        "match": {"kinds": ["file.read"], "products": ["claude-code"], "path_glob": "~/.ssh/**"},
    }]})
    assert result.status_code == 200, result.text
    configure(system, "enforce")
    for target in ("D:/Profiles/Alice/.ssh/id_rsa", "/home/alice/.ssh/id_rsa"):
        value = payload()
        value["actions"] = [{"kind": "file.read", "file": {"path": target}}]
        unavailable = check(system, value, 503)
        row = system.db.one("SELECT * FROM ordinary_hook_checks WHERE id=$1", unavailable["id"])
        assert row["failure_reason"] == "path_context_unavailable"
        assert row["evaluated_decision"] is None and row["returned_decision"] is None
    # An excluded rule does not require source home context.
    value = {**value, "request_id": new_id(), "product": "codex-cli"}
    assert check(system, value)["returned_decision"] == "allow"
    system.db.execute("UPDATE sensors SET os='' WHERE id=$1", system.sensors["sensor"][0]["id"])
    value = {**value, "request_id": new_id(), "product": "claude-code", "path_home": "/home/alice"}
    assert check(system, value, 503)["error"]["code"] == "unavailable"
    # Command-only rules still work when no path semantics are needed.
    assert check(system, payload())["returned_decision"] == "allow"


def test_malformed_and_cross_boundary_targets_are_rejected(system):
    value = payload()
    invalid = [
        {**value, "timeout_ms": 2000},
        {**value, "actions": []},
        {**value, "availability": "capture_disabled"},
        {**value, "actions": [{"kind": "prompt", "text": "wrong boundary"}]},
        {**value, "actions": [{"kind": "tool.call", "agent": {"product": "codex-cli"}}]},
        {**value, "actions": [{"kind": "tool.call", "session": {"id": "another-session"}}]},
        {**value, "actions": [{"kind": "tool.call", "session": {"registration_id": new_id()}}]},
        {**value, "path_home": "/home/alice"},
        {**value, "availability": "capture_disabled", "actions": [], "path_home": "/home/alice"},
        {**value, "actions": [{"kind": "file.read", "file": {"path": "/home/alice/key"}}],
         "path_home": "relative/home"},
    ]
    for item in invalid:
        check(system, item, 400)
    assert system.db.scalar("SELECT count(*) FROM ordinary_hook_checks") == 0


def test_identity_scope_delivery_and_history_pagination(system):
    policy(system)
    configure(system, "enforce")
    value = payload()
    check(system, value, 401, device="anonymous")
    check(system, {**value, "tenant_id": new_id()}, 400)
    first = check(system, value)
    receipt = {"request_id": value["request_id"], "delivery_status": "delivered", "delivered_decision": "deny"}
    url = "/ingest/v1/hook-checks/" + first["id"] + "/delivery"
    for device in ("peer", "foreign_sensor"):
        assert system.client.post(url, json=receipt, headers=system.headers[device]).status_code == (403 if device == "foreign_sensor" else 404)
    result = system.client.post(url, json=receipt, headers=system.headers["sensor"])
    assert result.status_code == 200, result.text
    assert system.client.post(url, json=receipt, headers=system.headers["sensor"]).json() == result.json()
    changed = {**receipt, "delivery_status": "timed_out", "delivered_decision": "allow"}
    assert system.client.post(url, json=changed, headers=system.headers["sensor"]).status_code == 409
    check(system, payload())
    page = browser(system, "GET", "hook-decisions?limit=1").json()
    assert len(page["items"]) == 1 and page["next_cursor"]
    next_page = browser(system, "GET", "hook-decisions?limit=1&cursor=" + page["next_cursor"]).json()
    assert next_page["items"][0]["delivery_status"] == "delivered"
    assert next_page["items"][0]["delivered_decision"] == "deny"
    assert next_page["items"][0]["sensor_hostname"] == "host"
    assert next_page["items"][0]["assessment"]["status"] == "scored"
    assert browser(system, "GET", "hook-decisions", user="foreign").json()["items"] == []


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_unavailable_matching_and_capture_are_not_policy_allows(system, monkeypatch, mode):
    from openaidr.core import _policy_worker

    policy(system)
    configure(system, mode)
    pool = _policy_worker.WorkerPool()
    monkeypatch.setattr(_policy_worker, "_pool", pool)
    held = [pool.available.get_nowait() for _ in pool.workers]
    try:
        failed = check(system, payload(), 503)
    finally:
        for worker in held:
            pool.available.put(worker)
        pool.close()
    assert failed["error"]["code"] == "unavailable"
    assert "workers" not in str(failed)
    for availability in ("capture_disabled", "unsupported_boundary", "content_redacted", "content_truncated", "unsupported_content"):
        value = {**payload(), "actions": [], "availability": availability}
        check(system, value, 503)
    history = browser(system, "GET", "hook-decisions").json()["items"]
    assert len(history) == 6
    assert all(item["status"] == "unavailable" and item["evaluated_decision"] is None
               and item["returned_decision"] is None for item in history)
    assert {item["failure_reason"] for item in history} == {
        "evaluation_unavailable", "capture_disabled", "unsupported_boundary", "content_redacted",
        "content_truncated", "unsupported_content",
    }
    failed_row = next(item for item in history if item["id"] == failed["id"])
    assert failed_row["reason"] == "All policy workers were busy."


@pytest.mark.parametrize("failure,detail", [
    ("timeout", "Policy evaluation or worker startup timed out."),
    ("invalid_matcher", "An applicable policy rule has an invalid match expression."),
    ("missing_id", "A matched policy rule has no identifier."),
    ("unexpected", "Policy evaluation failed unexpectedly."),
])
def test_policy_failure_details_survive_history_and_retries(system, failure, detail):
    configure(system, "enforce")
    rule = {"id": "broken", "name": "Private rule name", "enabled": True, "action": "deny",
            "reason": "Private configured reason", "match": {"kinds": ["command"]}}
    value = payload()
    if failure == "timeout":
        rule["match"]["command_regex"] = "^(a+)+$"
        value["actions"][0]["command"]["text"] = "a" * 10000 + "!"
    elif failure == "invalid_matcher":
        rule["match"]["command_regex"] = "["
    elif failure == "missing_id":
        rule.pop("id")
    else:
        rule["match"]["path_glob"] = 7
        value["actions"][0]["file"] = {"path": "/private/file"}
    # Exercise malformed stored rules, including data from older servers.
    system.db.save_policy(system.tenant["id"], [rule])
    result = check(system, value, 503)
    assert check(system, value, 503) == result
    history = browser(system, "GET", "hook-decisions?classified=true").json()["items"]
    assert len(history) == 1
    row = history[0]
    assert row["failure_reason"] == "evaluation_unavailable"
    assert row["reason"] == detail
    assert row["status"] == "unavailable"
    assert row["evaluated_decision"] is None and row["returned_decision"] is None
    assert row["rule_id"] == "" and row["assessment"] is None
    assert not system.provider.requests
    assert browser(system, "GET", "hook-decisions", user="foreign").json()["items"] == []


def test_policy_snapshot_and_database_work_are_bounded(system, monkeypatch):
    monkeypatch.setattr("openaidr.server.hook_policy.WORK_TIMEOUT_SECONDS", 0.2)
    policy(system)
    configure(system, "enforce")
    # A real row lock exercises the database deadline without a mocked store.
    with system.db.transaction() as conn:
        system.db.execute("LOCK TABLE ordinary_hook_checks IN ACCESS EXCLUSIVE MODE", conn=conn)
        started = time.monotonic()
        reply = check(system, {**payload(), "timeout_ms": 80}, 503)
        elapsed = time.monotonic() - started
    assert reply["error"]["code"] == "unavailable"
    assert elapsed < 0.7
    assert system.db.scalar("SELECT count(*) FROM ordinary_hook_checks") == 0


@pytest.mark.parametrize("system", [{"jev_api_key":"test-provider-key", "web_risk_api_key":"test-web-risk-key",
                                     "intelligence_origin":"https://api.opensecura.ai"}], indirect=True)
@pytest.mark.parametrize("links_enabled", [False, True])
def test_workspace_selection_shares_request_database_capacity(system, links_enabled):
    import psycopg

    s = system
    service = s.client.app.state.service
    link_checker = service.link_checker
    if not links_enabled:
        service.link_checker = None
    s.db.pools["data"].resize(16, 16)
    s.db.pools["data"].wait()
    requests = []
    for index in range(8):
        value = payload("UserPromptSubmit")
        value["session_id"] = "bounded-selection-" + str(index)
        value["actions"][0]["text"] = BAD_URL
        requests.append(value)
    try:
        with ThreadPoolExecutor(max_workers=8) as pool, psycopg.connect(s.db.url) as storage:
            # Block the real selector, after request preparation and before external I/O.
            storage.execute("LOCK TABLE tenant_intelligence_selection IN ACCESS EXCLUSIVE MODE")
            pending = [pool.submit(check, s, value) for value in requests]
            try:
                until = time.monotonic() + 2
                peak = 0
                while time.monotonic() < until:
                    count = storage.execute("""SELECT count(*) FROM pg_locks
                        WHERE relation='tenant_intelligence_selection'::regclass
                          AND mode='AccessShareLock' AND NOT granted""").fetchone()[0]
                    peak = max(peak, count)
                    if peak > s.cfg.inline_guardrail_concurrency:
                        break
                    if count == s.cfg.inline_guardrail_concurrency:
                        # Hold confirmed database pressure while queued requests progress.
                        until = min(until, time.monotonic() + 0.2)
                    time.sleep(0.005)
                assert peak == s.cfg.inline_guardrail_concurrency
                assert not any(task.done() for task in pending)
                assert browser(s, "GET", "response/hook-settings").status_code == 200
            finally:
                storage.rollback()
            results = [task.result(timeout=5) for task in pending]
        assert len(s.provider.requests) == len(requests)
        if links_enabled:
            assert s.web_risk.requests
            # The real API separately admits only two concurrent URL checks per tenant.
            outcomes = [result["assessment"]["links"]["status"] for result in results]
            assert "matched" in outcomes and set(outcomes) <= {"matched", "unavailable"}
    finally:
        service.link_checker = link_checker


@pytest.mark.parametrize("timeout_ms", [80, 1800])
def test_authentication_storage_wait_respects_work_limit(system, monkeypatch, timeout_ms):
    monkeypatch.setattr("openaidr.server.hook_policy.WORK_TIMEOUT_SECONDS", 0.2)
    policy(system)
    configure(system, "enforce")
    with system.db.transaction() as conn:
        system.db.execute("LOCK TABLE sensors IN ACCESS EXCLUSIVE MODE", conn=conn)
        started = time.monotonic()
        reply = check(system, {**payload(), "timeout_ms": timeout_ms}, 503)
        elapsed = time.monotonic() - started
    assert reply["error"]["code"] == "unavailable"
    assert elapsed < 0.7
    assert system.db.scalar("SELECT count(*) FROM ordinary_hook_checks") == 0


def test_disabled_sensor_and_tenant_cannot_evaluate(system):
    sensor_id = system.sensors["sensor"][0]["id"]
    system.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", sensor_id)
    check(system, payload(), 403)
    system.db.execute("UPDATE sensors SET disabled=false WHERE id=$1", sensor_id)
    system.db.execute("UPDATE tenants SET status='suspended' WHERE id=$1", system.tenant["id"])
    check(system, payload(), 403)
    assert system.db.scalar("SELECT count(*) FROM ordinary_hook_checks") == 0


@pytest.mark.parametrize("event", ["UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure"])
@pytest.mark.parametrize("score,expected", [(0, "allow"), (60, "ask"), (90, "deny")])
def test_each_boundary_classifies_inline_and_uses_explicit_tenant_thresholds(system, event, score, expected):
    configured = browser(system, "PUT", "response/guardrails", {
        "enabled": True, "ask_threshold": 40, "block_threshold": 80, "timeout_ms": 1000,
    })
    assert configured.status_code == 200, configured.text
    browser(system, "PUT", "response/policy", {"rules": []})
    system.provider.payload = Provider.scored(score)
    shadow = check(system, payload(event))
    assert shadow["assessment"]["score"] == score
    assert shadow["evaluated_decision"] == expected and shadow["returned_decision"] == "allow"
    configure(system, "enforce")
    enforced = check(system, payload(event))
    assert enforced["returned_decision"] == expected
    assert enforced["completed_at"]
    assert len(system.provider.requests) == 2
    assert system.db.scalar("SELECT count(*) FROM model_usage WHERE status='completed'") == 2


@pytest.mark.parametrize("event", ["UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure"])
@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_unconfigured_thresholds_classify_without_model_enforcement(system, event, mode):
    if mode == "enforce":
        configure(system, mode)
    browser(system, "PUT", "response/policy", {"rules": []})
    system.provider.payload = Provider.scored(99)
    result = check(system, payload(event))
    assert result["assessment"]["score"] == 99
    assert result["mode"] == mode
    assert result["evaluated_decision"] == result["returned_decision"] == "allow"
    assert browser(system, "GET", "response/guardrails").json()["enabled"] is False
    assert not {"model", "usage", "rubric_version"}.intersection(result["assessment"])
    assert browser(system, "GET", "costs/detections?purpose=guardrail").status_code == 410
    usage = system.db.one("SELECT input_tokens,output_tokens,cost_usd FROM model_usage WHERE tenant_id=$1", system.tenant["id"])
    assert usage["input_tokens"] == 2000 and usage["output_tokens"] == 20 and usage["cost_usd"] > 0


def test_classification_uses_prompt_and_call_context_before_telemetry_arrives(system):
    prompt = payload("UserPromptSubmit")
    prompt["actions"][0]["text"] = "Only inspect the README"
    check(system, prompt)
    call = payload()
    call["tool_call_id"] = "call-context"
    check(system, call)
    check(system, {**payload("PostToolUse"), "tool_call_id": "call-context"})
    state = system.provider.requests[-1]["state"]
    assert state["latest_prompt"]["text"] == "Only inspect the README"
    assert any(event["kind"] == "command" for event in state["prior_events"])
    assert state["target_event"]["kind"] == "tool.result"
    assert system.db.scalar("SELECT count(*) FROM events") == 0
    check(system, payload(), device="peer")
    assert system.provider.requests[-1]["state"]["latest_prompt"] is None


@pytest.mark.parametrize("event", ["UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure"])
def test_company_policy_snapshot_is_used_without_disclosing_in_hook_responses(system, event):
    prompt = "Company policy: require approval before production changes."
    assert browser(system, "PUT", "response/company-policy", {"revision": 0, "prompt": prompt}).status_code == 200
    value = payload(event)
    result = check(system, value)
    assert all(prompt in question["instructions"] for question in system.provider.requests[-1]["questions"].values())
    assert result["assessment"]["company_policy"] == {"revision": 1}
    assert prompt not in str(result)
    assert prompt not in str(browser(system, "GET", "hook-decisions").json())
    assert system.db.scalar("SELECT risk_settings->'company_policy' FROM ordinary_hook_checks WHERE id=$1",
                            result["id"]) == {"revision": 1, "prompt": prompt}
    assert browser(system, "PUT", "response/company-policy", {"revision": 1, "prompt": ""}).status_code == 200
    assert check(system, value) == result
    assert len(system.provider.requests) == 1
    check(system, payload(event), device="foreign_sensor")
    assert len(system.provider.requests) == 1  # No configured API for the foreign tenant.


def test_pending_checks_wait_and_duplicates_share_one_provider_dispatch(system):
    system.provider.block()
    value = payload()
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(check, system, value)
        assert system.provider.entered.wait(1)
        pending = system.db.one("SELECT * FROM ordinary_hook_checks WHERE request_id=$1", value["request_id"])
        assert pending["status"] == "pending"
        assert pending["assessment_input"]["state"] == system.provider.requests[-1]["state"]
        second = pool.submit(check, system, value)
        try:
            history = browser(system, "GET", "hook-decisions?classified=true").json()["items"]
            assert history == []
            assert not first.done()
        finally:
            system.provider.release()
        assert first.result(3) == second.result(3)
    assert len(system.provider.requests) == 1
    history = browser(system, "GET", "hook-decisions?classified=true").json()["items"]
    assert len(history) == 1 and history[0]["assessment"]["status"] == "scored"
    assert history[0]["actions"][0]["command"]["text"] == "rm -rf build"
    assert history[0]["delivery_status"] == "unconfirmed"


def test_retained_assessment_input_survives_policy_changes_and_late_context(system):
    import hashlib
    import psycopg

    from openaidr.server.ingest_evidence import encode

    policy(system)
    company = "Only inspect the README."
    assert browser(system, "PUT", "response/company-policy", {"revision": 0, "prompt": company}).status_code == 200
    prompt = check(system, payload("UserPromptSubmit"))
    value = payload()
    value["actions"][0]["command"]["text"] = "echo sk-proj-" + "a" * 40
    result = check(system, value)
    retained = system.db.one("SELECT * FROM ordinary_hook_checks WHERE id=$1", result["id"])
    captured = retained["assessment_input"]
    assert captured == {"state": system.provider.requests[-1]["state"], "company_policy": company}
    assert retained["assessment_input_sha256"] == hashlib.sha256(encode(captured)).hexdigest()
    assert retained["assessment_context"]["latest_prompt_check_id"] == prompt["id"]
    assert retained["assessment_context"]["prior_actions"] == [{"check_id": prompt["id"], "action_index": 0}]
    assert "a" * 40 not in str(captured)
    assert retained["risk_settings"]["content_redacted"] is True
    detail = system.client.post("/ingest/v1/guardrails/check", json={"id": result["id"], "review_version": 1},
                                headers=system.headers["sensor"]).json()
    assert detail["evidence"]["decision_basis"]["policy"]["rules"][0]["action"] == "deny"
    assert "assessment_profile" not in detail["evidence"]["decision_basis"]
    assert retained["risk_settings"]["assessment_profile"] == {"model": scoring.MODEL, "rubric_version": scoring.RUBRIC_VERSION}
    assert "content_redacted" in detail["evidence"]["gaps"]
    policy(system, "allow")
    assert browser(system, "PUT", "response/company-policy", {"revision": 1, "prompt": "Changed"}).status_code == 200
    late = check(system, payload("UserPromptSubmit"))
    system.db.execute("UPDATE ordinary_hook_checks SET created_at=$2-interval '1 microsecond' WHERE id=$1",
                      late["id"], retained["created_at"])
    assert check(system, value) == result
    after = system.client.post("/ingest/v1/guardrails/check", json={"id": result["id"], "review_version": 1},
                               headers=system.headers["sensor"]).json()
    assert after["evidence"] == detail["evidence"] and after["evidence_sha256"] == detail["evidence_sha256"]
    with pytest.raises(psycopg.errors.CheckViolation):
        system.db.execute("UPDATE ordinary_hook_checks SET assessment_input='{}' WHERE id=$1", result["id"])
    disabled = check(system, {**payload(), "availability": "capture_disabled", "actions": []}, expected=503)
    assert system.db.scalar("SELECT assessment_input FROM ordinary_hook_checks WHERE id=$1", disabled["id"]) is None


def test_retained_context_reports_content_truncation(system):
    policy(system)
    prompt = payload("UserPromptSubmit")
    prompt["actions"][0]["text"] = "context " * (scoring.MAX_EVENT_BYTES // 8 + 1)
    check(system, prompt)
    result = check(system, payload())
    row = system.db.one("SELECT * FROM ordinary_hook_checks WHERE id=$1", result["id"])
    assert row["assessment_input"]["state"]["latest_prompt"]["truncated"] is True
    assert row["assessment_context"]["content_truncated"] is True
    detail = system.client.post("/ingest/v1/guardrails/check", json={"id": result["id"], "review_version": 1},
                                headers=system.headers["sensor"]).json()
    assert "content_truncated" in detail["evidence"]["gaps"]


@pytest.mark.parametrize("action", ["allow", "deny"])
@pytest.mark.parametrize("legacy_budget", [None, 80])
def test_client_timeout_does_not_cancel_backend_evaluation(system, action, legacy_budget):
    policy(system, action)
    configure(system, "enforce")
    value = payload()
    if legacy_budget is None:
        value.pop("timeout_ms")
    else:
        value["timeout_ms"] = legacy_budget
    # The timeout report can arrive before the check reaches the backend.
    upload_receipt(system, value, "timed_out")
    system.provider.block()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(check, system, value)
        try:
            assert system.provider.entered.wait(1)
            time.sleep(0.15)
            assert not future.done()
        finally:
            system.provider.release()
        result = future.result(3)
    assert result["evaluated_decision"] == result["returned_decision"] == action
    assert result["assessment"]["status"] == "scored"
    item = browser(system, "GET", "hook-decisions").json()["items"][0]
    assert item["failure_reason"] == ""
    assert item["delivery_status"] == "timed_out" and item["delivered_decision"] == "allow"


@pytest.mark.parametrize("action", ["allow", "deny"])
def test_spooled_delivery_reports_are_scoped_and_idempotent(system, action):
    policy(system, action)
    configure(system, "enforce")
    value = payload()
    check(system, value)
    for device in ("peer", "foreign_sensor"):
        upload_receipt(system, value, "timed_out", device=device)
    assert browser(system, "GET", "hook-decisions").json()["items"][0]["delivery_status"] == "unconfirmed"
    history = "guardrail/stats?view=unified&range=1h&source=endpoints"
    assert browser(system, "GET", history).json()["totals"]["unconfirmed"] == 1
    if action == "allow":
        upload_receipt(system, value, "delivered", "deny")
        assert browser(system, "GET", "hook-decisions").json()["items"][0]["delivery_status"] == "unconfirmed"
        assert browser(system, "GET", history).json()["totals"]["unconfirmed"] == 1
    # A spooled receipt's event time can precede the selected check window.
    # Match its request identity, including across event partitions.
    timestamp = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    event, result = upload_receipt(system, value, "delivered", action, timestamp=timestamp)
    assert result["accepted"] == 1
    _, replay = upload_receipt(system, value, "delivered", action, ident=event["id"], timestamp=timestamp)
    assert replay["duplicates"] == 1
    upload_receipt(system, value, "timed_out")
    item = browser(system, "GET", "hook-decisions").json()["items"][0]
    assert item["delivery_status"] == "delivered" and item["delivered_decision"] == action
    totals = browser(system, "GET", history).json()["totals"]
    assert totals["attempted"] == 1 and totals["failed"] == 0 and totals["unconfirmed"] == 0
    # The direct receipt retains priority over spooled evidence in both views.
    result = system.client.post("/ingest/v1/hook-checks/" + item["id"] + "/delivery", json={
        "request_id": value["request_id"], "delivery_status": "timed_out", "delivered_decision": "allow",
    }, headers=system.headers["sensor"])
    assert result.status_code == 200, result.text
    assert browser(system, "GET", history).json()["totals"]["failed"] == 1


@pytest.mark.parametrize("product,event,action,delivered", [
    ("claude-code", "PreToolUse", "warn", "warn"),
    ("claude-code", "PreToolUse", "ask", "ask"),
    ("codex-cli", "PreToolUse", "ask", "deny"),
    ("claude-code", "UserPromptSubmit", "ask", "deny"),
    ("claude-code", "PostToolUse", "ask", "deny"),
    ("github-copilot", "PreToolUse", "ask", "ask"),
    ("antigravity", "PreToolUse", "ask", "ask"),
    ("hermes-agent", "PreToolUse", "ask", "ask"),
    ("cursor", "PreToolUse", "ask", "deny"),
    ("opencode", "PreToolUse", "ask", "deny"),
    *[(product, "PreToolUse", "warn", "allow") for product in
      ("github-copilot", "cursor", "antigravity", "opencode", "hermes-agent")],
])
def test_delivery_reports_preserve_native_decision_mapping(system, product, event, action, delivered):
    policy(system, action)
    configure(system, "enforce")
    value = payload(event, product)
    check(system, value)
    upload_receipt(system, value, "delivered", delivered)
    item = browser(system, "GET", "hook-decisions").json()["items"][0]
    assert item["delivery_status"] == "delivered" and item["delivered_decision"] == delivered
    totals = browser(system, "GET", "guardrail/stats?view=unified&source=endpoints").json()["totals"]
    assert totals["attempted"] == 1 and totals["failed"] == 0


def test_model_requests_do_not_hold_the_four_database_workers(system):
    system.provider.block()
    with ThreadPoolExecutor(max_workers=6) as pool:
        pending = [pool.submit(check, system, payload()) for _ in range(6)]
        try:
            deadline = time.monotonic() + 1
            while len(system.provider.requests) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert len(system.provider.requests) == 2
            assert system.client.get("/healthz").status_code == 200
        finally:
            system.provider.release()
        results = [future.result(3) for future in pending]
        assert all(value["returned_decision"] == "allow" for value in results)
        assert sum(value["assessment"]["status"] == "scored" for value in results) >= 2


@pytest.mark.parametrize("failure", ["timeout", "provider_unavailable", "invalid_response", "insufficient_evidence"])
@pytest.mark.parametrize("mode", ["shadow", "enforce"])
@pytest.mark.parametrize("action", ["allow", "deny"])
def test_classifier_failures_preserve_backend_rule_decisions(system, failure, mode, action):
    policy(system, action)
    configure(system, mode)
    value = payload()
    expected_failure = failure
    if failure == "timeout":
        # Fail the external transport without also expiring policy/storage work.
        # The real provider client reports transport timeouts as connection_failed.
        system.provider.block()
        system.provider.gate.set_exception(httpx.ReadTimeout("simulated provider read timeout"))
        expected_failure = "connection_failed"
    elif failure == "provider_unavailable":
        system.provider.status = 503
    elif failure == "insufficient_evidence":
        system.provider.payload = Provider.scored(100)
        system.provider.payload["answers"]["category"]["choice"] = "unknown"
    else:
        system.provider.payload = {"model": "unexpected"}
    result = check(system, value)
    history = browser(system, "GET", "hook-decisions?classified=true").json()["items"]
    assert history[0]["status"] == "evaluated"
    assert result["evaluated_decision"] == action
    assert result["returned_decision"] == ("allow" if mode == "shadow" else action)
    assert result["assessment"]["status"] == ("unscored" if failure == "insufficient_evidence" else "unavailable")
    if failure == "insufficient_evidence":
        assert result["assessment"]["score"] is None
        assert history[0]["reason"] == "Configured policy reason"
    assert history[0]["failure_reason"] == expected_failure
    assert len(system.provider.requests) == 1
    assert check(system, value) == result
    assert len(system.provider.requests) == 1


@pytest.mark.parametrize("system", [""], indirect=True)
def test_missing_model_provider_preserves_backend_policy_and_unavailable_risk(system):
    from psycopg.types.json import Jsonb
    from test_risk_store import event

    for mode in ("shadow", "enforce"):
        configure(system, mode)
        for action in ("allow", "deny"):
            policy(system, action)
            value = payload()
            result = check(system, value)
            assert result["evaluated_decision"] == action
            assert result["returned_decision"] == ("allow" if mode == "shadow" else action)
            assert result["assessment"]["status"] == "unavailable"
            captured = event(source={"collector": "hook", "hook_request_id": value["request_id"]})
            system.db.ingest_batch(system.sensors["sensor"][0], [captured])
            risk = system.db.get_event(system.tenant["id"], captured["id"])["risk"]
            assert {key: risk[key] for key in ("status", "reason", "hook_check_id")} == {"status": "error", "reason": "provider_unavailable", "hook_check_id": result["id"]}
            # Reconcile a captured copy that committed after the finish transaction.
            system.db.execute("""UPDATE events SET risk=$2,received_at=received_at-interval '3 seconds'
                WHERE id=$1""", captured["id"], Jsonb({"status": "pending", "hook_check_id": result["id"]}))
            system.db.expire_risk_events(system.tenant["id"])
            reconciled = system.db.get_event(system.tenant["id"], captured["id"])["risk"]
            assert all(reconciled[key] == risk[key] for key in ("status", "reason", "hook_check_id"))
    assert system.provider.requests == []


def test_redacted_evidence_and_unsupported_controls_still_receive_classification(system):
    configure(system, "enforce")
    policy(system, "deny")
    value = {**payload("PostToolUse"), "availability": "unsupported_boundary", "control_supported": True}
    result = check(system, value)
    assert result["assessment"]["status"] == "scored"
    assert result["evaluated_decision"] == "deny" and result["returned_decision"] == "allow"
    value = {**payload(), "availability": "content_redacted"}
    value["actions"][0]["command"]["text"] = "curl -H 'Authorization: [REDACTED]' https://example.test"
    result = check(system, value)
    assert result["assessment"]["status"] == "scored"
    assert system.provider.requests[-1]["state"]["evidence_status"] == "content_redacted"
    configured = browser(system, "PUT", "response/guardrails", {
        "enabled": True, "ask_threshold": 40, "block_threshold": 80, "timeout_ms": 1000,
    })
    assert configured.status_code == 200
    system.provider.payload = Provider.scored(90)
    result = check(system, {**payload("PostToolUse"), "availability": "content_redacted",
                            "control_supported": False})
    assert result["assessment"]["score"] == 90
    assert result["evaluated_decision"] == "deny" and result["returned_decision"] == "allow"


@pytest.mark.parametrize("boundary", ["PreToolUse", "PostToolUse", "PostToolUseFailure"])
@pytest.mark.parametrize("score", [0, 90])
def test_captured_copies_share_inline_assessment_and_material_findings(system, boundary, score):
    from decimal import Decimal
    from openaidr.server import model_costs, ordinary_session_detection
    from test_risk_store import event

    value = payload(boundary)
    value["tool_call_id"] = "single-model-call"
    kind = value["actions"][0]["kind"]
    captured = event(kind=kind, session=value["session_id"], tool={"call_id": value["tool_call_id"]},
                     source={"collector": "hook", "hook_request_id": value["request_id"]})
    sensor_row = system.sensors["sensor"][0]
    # The first captured copy can arrive before the synchronous check.
    system.db.ingest_batch(sensor_row, [captured])
    assert system.db.claim_risk_event(system.tenant["id"]) is None
    system.provider.payload = Provider.scored(score)
    result = check(system, value)
    native = event(kind=kind, session=value["session_id"], tool={"call_id": value["tool_call_id"]}, source="otlp")
    system.db.ingest_batch(sensor_row, [native])
    for copy in (captured, native):
        risk = system.db.get_event(system.tenant["id"], copy["id"])["risk"]
        assert risk["score"] == score and risk["hook_check_id"] == result["id"]
    assert system.db.claim_risk_event(system.tenant["id"]) is None
    session_id = system.db.get_event(system.tenant["id"], captured["id"])["session_id"]
    state = ordinary_session_detection.finalize(system.db, system.tenant["id"], session_id,
                                               scheduling_enabled=False, worker_ready=False)
    assert Decimal(state["risk_total"]) == score
    assert state["counts"]["assessed"] == 1
    assert len(system.provider.requests) == 1
    assert (system.db.scalar("SELECT count(*) FROM findings WHERE rule_id='jev-risk-detection'") > 0) == (score > 0)
    assert model_costs.overview(system.db, system.tenant["id"], purpose="guardrail")["summary"]["calls"] == 1
    assert model_costs.overview(system.db, system.tenant["id"], purpose="detection")["summary"]["calls"] == 0


def raw_check(system, value, expected=200, device="sensor"):
    from openaidr.server import ingest_evidence

    client = system.foreign_client if device == "foreign_sensor" else system.client
    result = client.post(
        "/ingest/v1/hook-checks", content=ingest_evidence.encode(value),
        headers={**system.headers.get(device, {}), "Content-Type": "application/json"},
    )
    assert result.status_code == expected, result.text
    return result.json()


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
@pytest.mark.parametrize("matches", [False, True])
def test_unstorable_actions_preserve_exact_rule_inputs_and_redacted_evidence(system, mode, matches):
    from openaidr.server import ingest_evidence

    configure(system, mode)
    expression = r"^erase\x00target$" if matches else "^erasetarget$"
    assert browser(system, "PUT", "response/policy", {"rules": [{
        "id": "exact-command", "enabled": True, "name": "Exact command", "action": "deny",
        "match": {"command_regex": expression},
    }]}).status_code == 200
    value = payload()
    value["actions"][0]["command"]["text"] = "erase\x00target"
    value["actions"][0]["tool"]["input"] = {
        "\ud800": "unpaired key", "nested": ["\udfff", ingest_evidence.Number("1e200000")],
        "password": "this-must-remain-private",
    }
    first = raw_check(system, value)
    assert first["evaluated_decision"] == ("deny" if matches else "allow")
    assert first["returned_decision"] == ("deny" if matches and mode == "enforce" else "allow")
    assert first["assessment"]["status"] == "unavailable"
    assert first["failure_reason"] == "unsupported_evidence"
    retained = ingest_evidence.read(system.db, system.tenant["id"], first["retained_id"])
    captured = ingest_evidence.loads(retained["payload"])
    assert captured["actions"] == scoring.redact_value(value["actions"])
    assert b"this-must-remain-private" not in retained["payload"]
    row = system.db.one("SELECT * FROM ordinary_hook_checks WHERE id=$1", first["id"])
    assert row["actions"] == []
    assert row["risk_settings"]["retained_evidence_id"] == first["retained_id"]
    assert raw_check(system, {**value, "timeout_ms": 1000}) == first
    assert not system.provider.requests
    assert system.db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 1
    # Later model assessments must not silently omit this unavailable context.
    later = check(system, payload())
    assert later["failure_reason"] == "unsupported_evidence_context"
    assert not system.provider.requests
    # A separate session has no missing context and remains assessable.
    assert check(system, {**payload(), "session_id": "another-session"})["assessment"]["status"] == "scored"


@pytest.mark.parametrize("field,value", [("session_id", "session\x00id"), ("session_id", "\ud800"),
                                         ("tool_call_id", "call\x00id"), ("tool_call_id", "\udfff")])
def test_unstorable_hook_identities_are_retained_without_rebinding(system, field, value):
    from openaidr.server import ingest_evidence

    request = {**payload(), field: value}
    raw_check(system, request, 401, device="anonymous")
    assert system.db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 0
    first = raw_check(system, request, 503)
    retained = ingest_evidence.read(system.db, system.tenant["id"], first["retained_id"])
    assert ingest_evidence.loads(retained["payload"])[field] == value
    assert raw_check(system, {**request, "timeout_ms": 1000}, 503) == first
    assert system.db.scalar("SELECT count(*) FROM ordinary_hook_checks") == 0
    assert system.db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 1
    assert not system.provider.requests
    changed = copy.deepcopy(request)
    changed["actions"][0]["command"]["text"] = "another command"
    raw_check(system, changed, 409)
    raw_check(system, {**request, field: "valid-identity"}, 409)
    assert system.db.scalar("SELECT count(*) FROM ordinary_hook_checks") == 0


def test_retained_hook_writes_obey_the_work_limit(system, monkeypatch):
    monkeypatch.setattr("openaidr.server.hook_policy.WORK_TIMEOUT_SECONDS", 0.2)
    value = payload()
    value["actions"][0]["command"]["text"] = "echo\x00hi"
    value["timeout_ms"] = 100
    with system.db.transaction() as conn:
        conn.execute("LOCK TABLE retained_ingest_evidence IN ACCESS EXCLUSIVE MODE")
        started = time.monotonic()
        result = raw_check(system, value, 503)
        assert time.monotonic() - started < 1
        assert result["error"]["code"] == "unavailable"
    assert system.db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 0
    assert system.db.scalar("SELECT count(*) FROM ordinary_hook_checks") == 0
    assert not system.provider.requests


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
@pytest.mark.parametrize("matches", [False, True])
def test_deep_tool_input_does_not_bypass_a_valid_policy_restriction(system, mode, matches):
    from openaidr.server import ingest_evidence

    configure(system, mode)
    policy(system, "deny", kinds=["command"] if matches else ["file.write"])
    request = payload()
    nested = {"password": "never-retain-this-secret", "evidence": "original"}
    for _ in range(80):
        nested = {"nested": [nested]}
    request["actions"][0]["tool"]["input"] = nested
    result = raw_check(system, request)
    assert result["evaluated_decision"] == ("deny" if matches else "allow")
    assert result["returned_decision"] == ("deny" if matches and mode == "enforce" else "allow")
    assert result["failure_reason"] == "unsupported_evidence"
    retained = ingest_evidence.read(system.db, system.tenant["id"], result["retained_id"])
    assert retained["reason"] == "nesting_limit"
    assert b"never-retain-this-secret" not in retained["payload"]
    assert ingest_evidence.loads(retained["payload"])["actions"] == scoring.redact_value(request["actions"])
    assert not system.provider.requests


@pytest.mark.parametrize("system", [{"web_risk_api_key": "test-web-risk-key"}], indirect=True)
@pytest.mark.parametrize("event", ["UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure"])
def test_malicious_links_enforce_without_a_model_and_record_deduplicated_findings(system, event):
    from test_risk_store import event as captured_event

    browser(system, "PUT", "response/policy", {"rules": []})
    for mode in ("shadow", "enforce"):
        configure(system, mode)
        value = payload(event)
        value["actions"][0]["text"] = BAD_URL
        result = check(system, value)
        assert result["assessment"]["status"] == "unavailable"
        assert result["assessment"]["links"]["status"] == "matched"
        assert result["evaluated_decision"] == "deny"
        assert result["returned_decision"] == ("allow" if mode == "shadow" else "deny")
        assert result["rule_id"] == "malicious-link"
        assert check(system, value) == result
        captured = captured_event(kind=value["actions"][0]["kind"], text=BAD_URL,
                                  source={"collector": "hook", "hook_request_id": value["request_id"]})
        system.db.ingest_batch(system.sensors["sensor"][0], [captured])
        system.db.ingest_batch(system.sensors["sensor"][0], [captured])
        risk = system.db.get_event(system.tenant["id"], captured["id"])["risk"]
        assert "provider" not in result["assessment"]["links"]
        assert risk["links"] == {"provider": "google_web_risk", **result["assessment"]["links"]}
        finding = system.db.one("SELECT title,summary FROM findings WHERE primary_event_id=$1 AND rule_id='malicious-link'", captured["id"])
        assert finding["title"] == "Malicious link detected"
        assert "not proof" in finding["summary"]
    assert system.db.rule_finding_counts(system.tenant["id"]) == {"malicious-link": 2}
    assert len(system.web_risk.requests) == 1
    system.db.set_rule_enabled(system.tenant["id"], "malicious-link", False)
    muted = {**value, "request_id": new_id()}
    assert check(system, muted)["returned_decision"] == "deny"
    system.db.ingest_batch(system.sensors["sensor"][0], [captured_event(
        kind="prompt", text=BAD_URL, source={"collector": "hook", "hook_request_id": muted["request_id"]},
    )])
    assert system.db.rule_finding_counts(system.tenant["id"]) == {"malicious-link": 2}


@pytest.mark.parametrize("system", [{"web_risk_api_key": "test-web-risk-key", "jev_api_key": "test-model-key"}], indirect=True)
@pytest.mark.parametrize("outcome", ["unlisted", "unavailable", "invalid", "timeout"])
def test_link_lookup_outcomes_preserve_fixed_rules_and_model_scores(system, outcome, monkeypatch):
    configure(system, "enforce")
    policy(system, "allow")
    system.provider.payload = Provider.scored(0)
    if outcome == "unlisted":
        system.web_risk.payload = {}
    elif outcome == "unavailable":
        system.web_risk.status = 503
    elif outcome == "invalid":
        system.web_risk.payload = {"wrong": "secret-error-body"}
    else:
        monkeypatch.setattr(malicious_links, "LOOKUP_TIMEOUT", 0.03)
        system.web_risk.delay = 5
    value = payload()
    value["actions"][0]["text"] = BAD_URL
    result = check(system, value)
    assert result["returned_decision"] == "allow"
    assert result["assessment"]["score"] == 0
    assert result["assessment"]["links"]["status"] == ("not_listed" if outcome == "unlisted" else "unavailable")
    assert "secret-error-body" not in str(result)
    policy(system, "deny")
    restricted = check(system, {**value, "request_id": new_id()})
    assert restricted["returned_decision"] == "deny" and restricted["rule_id"] == "test-rule"
    assert restricted["assessment"]["links"]["matches"] == []


@pytest.mark.parametrize("system", [{"web_risk_api_key": "test-web-risk-key"}], indirect=True)
def test_link_checks_respect_capture_privacy_and_unsupported_native_controls(system):
    configure(system, "enforce")
    browser(system, "PUT", "response/policy", {"rules": []})
    value = payload("PostToolUse")
    value["actions"][0]["tool"]["output"] = BAD_URL
    value["control_supported"] = False
    result = check(system, value)
    assert result["evaluated_decision"] == "deny" and result["returned_decision"] == "allow"
    unavailable = {**value, "request_id": new_id(), "availability": "capture_disabled", "actions": []}
    check(system, unavailable, 503)
    private = {**value, "request_id": new_id(), "actions": [{"kind": "tool.result", "tool": {
        "output": "https://internal.local/private https://public.example.com/?token=never-send-this-value",
    }}]}
    result = check(system, private)
    assert result["assessment"]["links"]["checked"] == 0
    assert result["assessment"]["links"]["status"] == "unavailable"
    assert len(system.web_risk.requests) == 1
    assert "never-send-this-value" not in str(browser(system, "GET", "hook-decisions?classified=true").json())


def test_unconfigured_web_risk_makes_no_requests(system):
    value = payload()
    value["actions"][0]["text"] = BAD_URL
    result = check(system, value)
    assert result["assessment"]["links"]["status"] == "unavailable"
    assert not system.web_risk.requests


@pytest.mark.parametrize("system", [{"web_risk_api_key": "test-web-risk-key"}], indirect=True)
def test_many_long_malicious_links_fit_installed_sensor_response_limit(system):
    from datetime import datetime, timezone

    configure(system, "enforce")
    system.web_risk.payload = {"threat": {"threatTypes": ["MALWARE"],
        "expireTime": datetime.fromtimestamp(system.web_risk.expiry, timezone.utc).isoformat()}}
    value = payload("UserPromptSubmit")
    value["actions"][0]["text"] = " ".join(
        f"https://malware.example.com/{index}/" + "a" * 3900 for index in range(16)
    )
    response = system.client.post("/ingest/v1/hook-checks", json=value, headers=system.headers["sensor"])
    assert response.status_code == 200, response.text
    assert len(response.content) < 64 << 10
    result = response.json()
    assert result["returned_decision"] == "deny"
    assert result["assessment"]["links"]["checked"] == 6
    assert result["assessment"]["links"]["skipped"] == 10
