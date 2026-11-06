"""Gateway HTTP/storage integration; only the external classifier is simulated."""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from types import SimpleNamespace
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from openaidr.server import auth, gateways
from openaidr.server.app import create_app
from openaidr.server.config import Config
from openaidr.server.store import new_id
from test_inline_guardrail import Provider
from test_store import db, sensor, tenant


@pytest.fixture
def system(db, monkeypatch, tmp_path):
    own, foreign = tenant(db), tenant(db)
    users = {
        name: db.create_user(scope["id"], name + "@gateway.test", name, "hash", role)
        for name, scope, role in (("owner", own, "owner"), ("admin", own, "admin"),
                                  ("analyst", own, "analyst"), ("viewer", own, "viewer"),
                                  ("foreign", foreign, "owner"))
    }
    headers = {name: {"Cookie": auth.CONSOLE_COOKIE + "=" + db.create_session(user["id"], user["tenant_id"]),
                      auth.CSRF_HEADER: "1"} for name, user in users.items()}
    provider = Provider()
    from intelligence_fixture import intelligence_service
    with intelligence_service(monkeypatch, tmp_path, own["id"], provider.handle,
                              guardrail_key="gateway-test-provider-key") as api:
        cfg = Config(database_url=db.url, public_url="http://testserver", cost_processing=False, **api.config)
        cfg.set_services("ingest")
        foreign_cfg = replace(cfg, tenant_id=foreign["id"], intelligence_origin="", intelligence_api_key="")
        with TestClient(create_app(cfg, db)) as client, TestClient(create_app(foreign_cfg, db)) as foreign_client:
            # Start only ingest workers; expose API routes for test administration.
            cfg.set_services("api,ingest")
            foreign_cfg.set_services("api,ingest")
            system = SimpleNamespace(db=db, client=client, cfg=cfg, headers=headers, tenant=own,
                                     foreign=foreign, provider=provider, foreign_client=foreign_client)
            try:
                yield system
            finally:
                provider.release()


def browser(s, method, path, data=None, user="owner"):
    client = s.foreign_client if user == "foreign" else s.client
    return client.request(method, "/api/v1/" + path, json=data, headers=s.headers[user])


def create(s, user="owner"):
    response = browser(s, "POST", "gateways", {"name": "Production Kong", "environment": "production"}, user)
    assert response.status_code == 201, response.text
    data = response.json()
    return data["gateway"], {"Authorization": "Bearer " + data["credential"]["token"]}, data["credential"]


def settings(s, gateway, **changes):
    data = {k: gateway[k] for k in ("version", "mode", "capture_content", "policy_rule_ids")}
    response = browser(s, "PUT", "gateways/" + gateway["id"] + "/settings", {**data, **changes})
    assert response.status_code == 200, response.text
    return response.json()


def machine(s, route, headers, data):
    response = s.client.post("/ingest/v1/gateway-" + route, headers=headers, json=data)
    assert response.headers.get("cache-control") == "no-store"
    return response


def payload(**changes):
    return {"request_id": new_id(), "node_id": "kong-a", "protocol": "openai.chat", "stream": True,
            "route_id": "route-a", "provider": "configured-provider", "model": "requested-model",
            "messages": [{"role": "user", "content": "Summarize this public report."}],
            "availability": "available", "timeout_ms": 2000, **changes}


def heartbeat():
    return {"node_id": "kong-a", "plugin_version": "2026.10.23+abcdef0", "kong_version": "3.9",
            "coverage": "observed_only", "dropped_events": 2,
            "routes": [{"route_id": "route-a", "service_id": "service-a", "protocol": "openai.chat"}]}


def enable_risk(s):
    result = browser(s, "PUT", "response/guardrails",
                     {"enabled": True, "ask_threshold": 40, "block_threshold": 80, "timeout_ms": 10000})
    assert result.status_code == 200, result.text


@pytest.mark.parametrize("range_name", ["1h", "24h", "7d", "30d"])
def test_history_source_metrics_scope_and_unavailable_checks(system, range_name):
    from openaidr.server.guardrail.analytics import RANGES
    from test_guardrail import decision

    s = system
    gateway, _, _ = create(s)
    foreign, _, _ = create(s, user="foreign")
    endpoint, _, _ = sensor(s.db, s.tenant["id"])
    s.db.ingest_batch(endpoint, [decision("ask", e2e=500)])
    at = s.db.scalar("SELECT now()")
    duration, interval = RANGES[range_name]
    created = at - timedelta(seconds=interval / 2)

    def record(status, evaluated=None, latency=None, *, instance=gateway, time=created, deadline=None):
        s.db.execute("""INSERT INTO gateway_requests
            (id,tenant_id,gateway_id,request_id,node_id,status,mode,evaluated_decision,
             returned_decision,policy_latency_ms,created_at,deadline_at)
            VALUES($1,$2,$3,$4,'node',$5,'shadow',$6,'allow',$7,$8,$9)""",
            new_id(), s.foreign["id"] if instance is foreign else s.tenant["id"],
            instance["id"], new_id(), status, evaluated, latency, time, deadline)

    record("evaluated", "allow", 0)
    record("evaluated", "deny", 20)
    record("evaluated", "allow")
    record("unavailable", latency=900)
    record("pending", deadline=at - timedelta(seconds=1))
    record("pending", deadline=at + timedelta(minutes=1))
    record("pending")
    record("evaluated", "deny", 999, time=at - duration - timedelta(minutes=1))
    record("evaluated", "deny", 999, time=at + timedelta(minutes=1))
    record("evaluated", "deny", 999, instance=foreign)
    path = f"guardrail/stats?range={range_name}"
    response = browser(s, "GET", path + "&source=all", user="analyst")
    assert response.status_code == 200, response.text
    sources = response.json()["sources"]
    hooks, gateways = sources["endpoints"], sources["gateways"]
    assert hooks["totals"]["total"] == hooks["totals"]["ask"] == 1
    assert hooks["totals"]["e2e_p50"] == 500
    assert (hooks["since"], hooks["until"]) == (gateways["since"], gateways["until"])
    assert [b["start"] for b in hooks["series"]] == [b["start"] for b in gateways["series"]]
    assert gateways["source"] == "gateways"
    assert (gateways["totals"]["total"], gateways["totals"]["allow"], gateways["totals"]["deny"]) == (3, 2, 1)
    assert gateways["totals"]["policy_p50"] == 10
    assert gateways["totals"]["e2e_p50"] is None
    assert gateways["availability"] == {"total": 5, "unavailable": 2}
    assert "executions" not in gateways and gateways["rules"] == []
    assert sum(b["total"] for b in gateways["series"]) == 3
    assert sum(b["availability"]["total"] for b in gateways["series"]) == 5
    assert sum(b["availability"]["unavailable"] for b in gateways["series"]) == 2
    assert gateways["series"][0]["policy_p50"] is None
    assert gateways["series"][0]["availability"] == {"total": 0, "unavailable": 0}
    assert browser(s, "GET", path).json()["source"] == "endpoints"
    assert browser(s, "GET", path + "&source=endpoints").json()["totals"] == hooks["totals"]
    assert browser(s, "GET", path + "&source=gateways").json()["totals"] == gateways["totals"]
    other = browser(s, "GET", path + "&source=all", user="foreign").json()["sources"]
    assert other["endpoints"]["totals"]["total"] == 0
    assert other["gateways"]["totals"]["total"] == 1
    for source in ("all", "endpoints", "gateways"):
        assert browser(s, "GET", path + "&source=" + source, user="viewer").status_code == 403
    assert browser(s, "GET", path + "&source=invalid").status_code == 400
    assert browser(s, "GET", "guardrail/stats?range=90d&source=all").status_code == 400


def test_unified_history_counts_failures_skips_and_raw_latency_samples(system):
    from test_guardrail import decision

    s = system
    gateway, _, _ = create(s)
    foreign, _, _ = create(s, user="foreign")
    endpoint, _, _ = sensor(s.db, s.tenant["id"])
    at = s.db.scalar("SELECT now()-interval '1 minute'")

    def hook(status, action=None, delivery=None, failure="", *, deadline=None):
        ident = new_id()
        s.db.execute("""INSERT INTO ordinary_hook_checks
            (id,tenant_id,sensor_id,request_id,payload_sha256,product,hook_event,session_id,
             mode,settings_version,policy_version,status,evaluated_decision,returned_decision,
             failure_reason,created_at,deadline_at)
            VALUES($1,$2,$3,$4,'fixture','claude-code','PreToolUse','session','enforce',1,1,$5,$6,$6,$7,$8,$9)""",
            ident, s.tenant["id"], endpoint["id"], new_id(), status, action, failure, at, deadline)
        if delivery:
            s.db.execute("INSERT INTO ordinary_hook_deliveries(check_id,delivery_status,delivered_decision) VALUES($1,$2,$3)",
                         ident, delivery, action if delivery == "delivered" else "allow")

    def gateway_check(status, action=None, outcome=None, latency=None, failure="", *, instance=gateway, deadline=None):
        s.db.execute("""INSERT INTO gateway_requests
            (id,tenant_id,gateway_id,request_id,node_id,status,mode,evaluated_decision,returned_decision,
             outcome,guardrail_e2e_ms,policy_latency_ms,latency_ms,failure_reason,created_at,deadline_at)
            VALUES($1,$2,$3,$4,'node',$5,'enforce',$6,$6,$7,$8,1,9000,$9,$10,$11)""",
            new_id(), s.foreign["id"] if instance is foreign else s.tenant["id"], instance["id"], new_id(),
            status, action, outcome, latency, failure, at, deadline)

    hook("evaluated", "allow", "delivered")
    hook("evaluated", "deny", "delivered")
    hook("evaluated", "deny", "timed_out")
    hook("unavailable", failure="backend_unavailable")
    hook("unavailable", failure="capture_disabled")
    hook("evaluated", "allow")
    hook("pending", deadline=at + timedelta(minutes=5))
    s.db.ingest_batch(endpoint, [decision("allow", e2e=10), decision("deny", e2e=30)])
    gateway_check("evaluated", "allow", "unconfirmed", 100)
    gateway_check("evaluated", "deny", "blocked", 200)
    gateway_check("evaluated", "allow", "fail_open", 999, "timeout")
    gateway_check("pending", deadline=at)
    gateway_check("unavailable", failure="unsupported_content")
    gateway_check("evaluated", "allow")
    gateway_check("pending", deadline=at + timedelta(minutes=5))
    gateway_check("evaluated", "deny", "blocked", 9999, instance=foreign)
    path = "guardrail/stats?view=unified&range=1h&source="
    result = browser(s, "GET", path + "all", user="analyst")
    assert result.status_code == 200, result.text
    result = result.json()
    assert result["totals"] == dict(total=6, allow=4, warn=0, ask=0, deny=2, latency_samples=4,
                                   e2e_p50=65, e2e_p95=pytest.approx(185), e2e_p99=pytest.approx(197),
                                   attempted=8, failed=4, not_evaluated=2, unconfirmed=4, legacy=0)
    for source in ("endpoints", "gateways"):
        group = result["sources"][source]
        selected = browser(s, "GET", path + source).json()
        assert selected["totals"] == group["totals"]
        assert set(selected["sources"]) == {source}
        assert [b["start"] for b in group["series"]] == [b["start"] for b in result["series"]]
        assert group["totals"]["attempted"] == 4 and group["totals"]["failed"] == 2
    for key in ("total", "attempted", "failed", "not_evaluated", "unconfirmed", "latency_samples"):
        assert sum(b[key] for b in result["series"]) == result["totals"][key]
    assert browser(s, "GET", path + "all", user="foreign").json()["totals"]["total"] == 1
    assert browser(s, "GET", path + "all", user="viewer").status_code == 403
    assert browser(s, "GET", "guardrail/stats?view=invalid").status_code == 400


@pytest.mark.parametrize("view", ["sources", "unified"])
@pytest.mark.parametrize("source", ["endpoints", "all"])
def test_history_migrates_legacy_policy_outside_read_only_statistics(system, view, source):
    from test_guardrail import decision

    s = system
    endpoint, _, _ = sensor(s.db, s.tenant["id"])
    s.db.ingest_batch(endpoint, [decision("ask", rule_id="cred-ssh", rule_name="Previous name")])
    old = dict(id="cred", name="Credential reads", action="deny", enabled=True, source="builtin",
               match={"kinds": ["file.read"], "path_glob": "**/.{aws,ssh,kube}/*"})
    s.db.save_policy(s.tenant["id"], [])
    s.db.execute("UPDATE policies SET rules=$2::jsonb,ask_rule_ids=$3 WHERE tenant_id=$1",
                 s.tenant["id"], json.dumps([old]), ["cred"])
    version = s.db.scalar("SELECT version FROM policies WHERE tenant_id=$1", s.tenant["id"])
    path = f"guardrail/stats?source={source}&view={view}"
    response = browser(s, "GET", path)
    assert response.status_code == 200, response.text
    data = response.json()
    rules = data["sources"]["endpoints"]["rules"] if view == "sources" and source == "all" else data["rules"]
    rule, = rules
    assert (rule["rule_id"], rule["rule_name"], rule["action"], rule["in_policy"], rule["total"]) == (
        "cred-ssh", "Credential reads (.ssh)", "ask", True, 1)
    stored = s.db.one("SELECT version,rules,ask_rule_ids FROM policies WHERE tenant_id=$1", s.tenant["id"])
    assert stored["version"] == version + 1
    assert {r["id"] for r in stored["rules"]} == {"cred-aws", "cred-ssh", "cred-kube"}
    assert set(stored["ask_rule_ids"]) == {"cred-aws", "cred-ssh", "cred-kube"}
    assert browser(s, "GET", path).status_code == 200
    assert s.db.scalar("SELECT version FROM policies WHERE tenant_id=$1", s.tenant["id"]) == version + 1


def test_guardrail_duration_receipts_validate_and_preserve_legacy_contract(system):
    s = system
    gateway, headers, _ = create(s)
    settings(s, gateway, capture_content=True)
    assert machine(s, "heartbeats", headers, heartbeat()).json()["guardrail_metrics"] is True
    checked = machine(s, "checks", headers, payload()).json()
    receipt = dict(request_id=checked["request_id"], node_id="kong-a", check_id=checked["id"],
                   outcome="unconfirmed", status_code=None, latency_ms=None, guardrail_e2e_ms=123.5)
    for value in (-1, 3600001, True, "123", None):
        assert machine(s, "outcomes", headers, {**receipt, "guardrail_e2e_ms": value}).status_code == 400
    assert machine(s, "outcomes", headers, receipt).status_code == 200
    assert machine(s, "outcomes", headers, receipt).status_code == 200
    assert machine(s, "outcomes", headers, {**receipt, "guardrail_e2e_ms": 124}).status_code == 409
    row = browser(s, "GET", "gateways/requests/" + checked["id"]).json()
    assert row["guardrail_e2e_ms"] == 123.5 and row["latency_ms"] is None
    assert row["evaluated_decision"] == row["returned_decision"] == "allow"
    legacy = machine(s, "checks", headers, payload()).json()
    old_receipt = {k: v for k, v in receipt.items() if k != "guardrail_e2e_ms"}
    old_receipt.update(request_id=legacy["request_id"], check_id=legacy["id"])
    assert machine(s, "outcomes", headers, old_receipt).status_code == 200
    assert browser(s, "GET", "gateways/requests/" + legacy["id"]).json()["guardrail_e2e_ms"] is None


def test_plugin_identity_policy_and_legacy_heartbeat_contract(system, monkeypatch):
    s = system
    kong, kong_headers, _ = create(s)
    assert kong["kind"] == "kong"
    assert machine(s, "heartbeats", kong_headers, {**heartbeat(), "kind": "litellm"}).status_code == 400
    assert browser(s, "GET", "gateways/" + kong["id"]).json()["nodes"] == []
    assert machine(s, "heartbeats", kong_headers, heartbeat()).status_code == 200
    path = "gateways/" + kong["id"]
    node = browser(s, "GET", path).json()["nodes"][0]
    assert node["gateway_version"] == node["kong_version"] == "3.9"
    generic = {k: v for k, v in heartbeat().items() if k != "kong_version"}
    generic["gateway_version"] = "3.10"
    assert machine(s, "heartbeats", kong_headers, generic).status_code == 200
    node = browser(s, "GET", path).json()["nodes"][0]
    assert node["gateway_version"] == node["kong_version"] == "3.10"
    assert machine(s, "heartbeats", kong_headers, {**generic, "kong_version": "different"}).status_code == 400
    # A previous backend can still update the legacy column during a rolling deploy.
    s.db.execute("UPDATE gateway_nodes SET kong_version='3.11' WHERE gateway_id=$1", kong["id"])
    assert browser(s, "GET", path).json()["nodes"][0]["gateway_version"] == "3.11"

    for kind in ("unknown", [], None):
        assert browser(s, "POST", "gateways", {"name": "Invalid", "kind": kind}).status_code == 400
    monkeypatch.setitem(gateways.PLUGINS, "fixture", {"label": "Fixture"})
    response = browser(s, "POST", "gateways", {"name": "Fixture gateway", "kind": "fixture"})
    assert response.status_code == 201, response.text
    other = response.json()["gateway"]
    headers = {"Authorization": "Bearer " + response.json()["credential"]["token"]}
    other_path = "gateways/" + other["id"]
    assert browser(s, "POST", "gateways", {"name": "Fixture", "kind": "fixture"}, "analyst").status_code == 403
    assert browser(s, "PATCH", other_path, {"version": 1, "kind": "kong"}).status_code == 400
    assert machine(s, "heartbeats", headers, heartbeat()).status_code == 400
    connected = machine(s, "heartbeats", headers, generic)
    assert connected.status_code == 200 and connected.json()["kind"] == "fixture"
    node = browser(s, "GET", other_path).json()["nodes"][0]
    assert node["gateway_version"] == "3.10" and node["kong_version"] == ""

    rules = [{"id": kind, "name": kind + " prompts", "enabled": True, "action": action,
              "match": {"products": [kind]}} for kind, action in (("kong", "allow"), ("fixture", "deny"))]
    assert browser(s, "PUT", "response/policy", {"rules": rules}).status_code == 200
    for gateway, wrong in ((kong, "fixture"), (other, "kong")):
        data = {"version": gateway["version"], "capture_content": True, "mode": "enforce", "policy_rule_ids": [wrong]}
        assert browser(s, "PUT", "gateways/" + gateway["id"] + "/settings", data).status_code == 400
    settings(s, kong, capture_content=True, mode="enforce", policy_rule_ids=["kong"])
    other = settings(s, other, capture_content=True, policy_rule_ids=["fixture"])
    shadow = machine(s, "checks", headers, payload()).json()
    assert (shadow["evaluated_decision"], shadow["returned_decision"]) == ("deny", "allow")
    settings(s, other, mode="enforce")
    denied = machine(s, "checks", headers, payload()).json()
    assert denied["returned_decision"] == "deny"
    assert machine(s, "checks", kong_headers, payload()).json()["returned_decision"] == "allow"
    assert "fixture_gateway" in json.dumps(s.provider.requests)
    assert machine(s, "checks", headers, payload(kind="kong")).status_code == 400
    detail = browser(s, "GET", "gateways/requests/" + denied["id"]).json()
    assert detail["gateway_kind"] == "fixture"
    for route in ("gateways/requests", "guardrail/checks?source=gateways"):
        rows = browser(s, "GET", route).json()["items"]
        assert {r["gateway_kind"] for r in rows} == {"kong", "fixture"}
        assert browser(s, "GET", route, user="foreign").json()["items"] == []
    assert browser(s, "GET", other_path, user="foreign").status_code == 404
    monkeypatch.delitem(gateways.PLUGINS, "fixture")
    assert machine(s, "heartbeats", headers, generic).status_code == 503
    assert machine(s, "checks", headers, payload()).status_code == 503


def test_gateway_plugin_migration_backfills_existing_nodes(system):
    s = system
    gateway, headers, _ = create(s)
    assert machine(s, "heartbeats", headers, heartbeat()).status_code == 200
    s.db.execute("ALTER TABLE gateway_nodes DROP COLUMN gateway_version")
    s.db.execute("ALTER TABLE gateway_instances DROP CONSTRAINT gateway_instances_kind_check")
    s.db.execute("ALTER TABLE gateway_instances ADD CONSTRAINT gateway_instances_kind_check CHECK (kind='kong')")
    s.db.execute("DELETE FROM schema_migrations WHERE version=121")
    s.db.migrate()
    detail = browser(s, "GET", "gateways/" + gateway["id"]).json()
    assert detail["gateway"]["kind"] == "kong"
    node = s.db.one("SELECT * FROM gateway_nodes WHERE gateway_id=$1", gateway["id"])
    assert node["gateway_version"] == node["kong_version"] == "3.9"
    assert machine(s, "heartbeats", headers, heartbeat()).status_code == 200


def test_gateway_page_visits_validate_roles_and_tenant_resources(system):
    s = system
    gateway, headers, _ = create(s)
    request_id = new_id()
    receipt = {"request_id": request_id, "node_id": "audit-fixture", "outcome": "unconfirmed",
               "status_code": 200, "latency_ms": 0}
    assert machine(s, "outcomes", headers, receipt).status_code == 200
    row = browser(s, "GET", "gateways/requests").json()["items"][0]
    paths = ("/gateways/overview", "/gateways/instances", "/gateways/requests",
             "/gateways/instances/" + gateway["id"], "/gateways/requests/" + row["id"])
    for user in ("owner", "admin", "analyst", "viewer"):
        for path in paths:
            permitted = user in ("owner", "analyst") or path == "/gateways/overview" or (user == "admin" and "/instances" in path)
            result = browser(s, "POST", "audit/page-views", {"path": path}, user)
            assert result.status_code == (204 if permitted else 403), (user, path, result.text)
    for path in paths[-2:]:
        assert browser(s, "POST", "audit/page-views", {"path": path}, "foreign").status_code == 404
        prefix = path.rsplit("/", 1)[0] + "/"
        assert browser(s, "POST", "audit/page-views", {"path": prefix + new_id()}).status_code == 404
        for invalid in (prefix + ":id", prefix + "invalid", path + "?token=secret", path + "#fragment"):
            assert browser(s, "POST", "audit/page-views", {"path": invalid}).status_code == 400
    visits = s.db.many("SELECT * FROM audit_log WHERE action='dashboard.page.view' AND tenant_id=$1", s.tenant["id"])
    assert {visit["target_id"] for visit in visits} == set(paths)
    detail = next(visit for visit in visits if visit["target_id"] == paths[-1])
    assert detail["details"] == {"source": "browser", "page": "Gateway Request",
                                 "resource_type": "gateway_request", "resource_id": row["id"]}


def test_unified_activity_orders_sources_and_preserves_evidence_and_access(system):
    from test_hook_policy import payload as hook_payload

    s = system
    _, token, _ = sensor(s.db, s.tenant["id"])
    endpoint = s.client.post("/ingest/v1/hook-checks", json=hook_payload("UserPromptSubmit"),
                             headers={"Authorization": "Bearer " + token})
    assert endpoint.status_code == 200, endpoint.text
    endpoint_id = endpoint.json()["id"]
    gateway, headers, _ = create(s)
    gateway = settings(s, gateway, capture_content=True)
    value = payload(consumer_id="alice", consumer_name="Alice Example", application_name="Support assistant")
    checked = machine(s, "checks", headers, value)
    assert checked.status_code == 200, checked.text
    assert machine(s, "outcomes", headers, {
        "request_id": value["request_id"], "node_id": value["node_id"], "check_id": checked.json()["id"],
        "outcome": "forwarded", "status_code": 200, "latency_ms": 20,
    }).status_code == 200
    # Even identical timestamps and IDs across the two tables must page separately.
    s.db.execute("""UPDATE gateway_requests SET id=$1,
        created_at=(SELECT created_at FROM ordinary_hook_checks WHERE id=$1) WHERE id=$2""",
        endpoint_id, checked.json()["id"])
    response = browser(s, "GET", "guardrail/checks?limit=1", user="analyst")
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    first = response.json()
    record = first["items"][0]
    assert record["source"] == "gateway" and record["id"] == endpoint_id
    assert record["consumer_id"] == "alice" and record["messages"] == value["messages"]
    assert record["consumer_name"] == "Alice Example" and record["application_name"] == "Support assistant"
    assert record["assessment"]["status"] == "scored" and record["outcome"] == "forwarded"
    assert not {"sensor_id", "sensor_username", "actions", "tenant_id", "check_digest"} & record.keys()
    second = browser(s, "GET", "guardrail/checks?limit=1&cursor=" + first["next_cursor"]).json()
    assert len(second["items"]) == 1 and second["next_cursor"] == ""
    assert second["items"][0]["source"] == "endpoint" and second["items"][0]["id"] == endpoint_id
    assert second["items"][0]["actions"][0]["text"] == "Review this change"
    for source, kind in (("endpoints", "endpoint"), ("gateways", "gateway")):
        filtered = browser(s, "GET", "guardrail/checks?source=" + source).json()
        assert len(filtered["items"]) == 1 and filtered["items"][0]["source"] == kind
    assert len(browser(s, "GET", "hook-decisions?classified=true").json()["items"]) == 1
    assert browser(s, "GET", "guardrail/checks", user="foreign").json()["items"] == []
    for user in ("viewer", "admin"):
        assert browser(s, "GET", "guardrail/checks", user=user).status_code == 403
    for query in ("source=invalid", "limit=201", "cursor=invalid", "cursor=" + first["next_cursor"] + ":extra"):
        assert browser(s, "GET", "guardrail/checks?" + query).status_code == 400
    settings(s, gateway, capture_content=False)
    unavailable = machine(s, "checks", headers, payload(messages=[], availability="capture_disabled")).json()
    s.db.execute("""UPDATE gateway_requests SET status='pending',deadline_at=clock_timestamp()+interval '1 minute'
        WHERE id=$1""", unavailable["id"])
    assert len(browser(s, "GET", "guardrail/checks").json()["items"]) == 2
    s.db.execute("UPDATE gateway_requests SET deadline_at=clock_timestamp()-interval '1 second' WHERE id=$1", unavailable["id"])
    expired = browser(s, "GET", "guardrail/checks").json()["items"][0]
    assert expired["status"] == "unavailable" and expired["failure_reason"] == "timeout"
    assert expired["messages"] is None and expired["assessment"] is None and expired["outcome"] is None
    assert expired["consumer_name"] == "" and expired["application_name"] == ""


def test_activity_summary_covers_full_window_and_filters_beyond_first_page(system):
    from urllib.parse import urlencode
    from psycopg.types.json import Jsonb
    from test_hook_policy import payload as hook_payload

    s = system
    _, token, _ = sensor(s.db, s.tenant["id"])
    created = s.client.post("/ingest/v1/hook-checks", json=hook_payload("UserPromptSubmit"),
                            headers={"Authorization": "Bearer " + token})
    assert created.status_code == 200, created.text
    template = created.json()["id"]
    for index in range(12):
        # Distinct reported accounts on one device must remain distinct. The
        # oldest account is outside the first hundred checks, but is searchable.
        action = {"agent": {"account": f"worker-{index:02d}@example.test"},
                  "session": {"cwd": f"/project/{index}"}}
        s.db.execute("""INSERT INTO ordinary_hook_checks
            (id,tenant_id,sensor_id,request_id,payload_sha256,product,hook_event,session_id,mode,
             settings_version,policy_version,status,evaluated_decision,returned_decision,actions,assessment,
             created_at,deadline_at,completed_at)
            SELECT gen_random_uuid(),tenant_id,sensor_id,gen_random_uuid(),'test',product,hook_event,$2,'shadow',
                1,1,'evaluated',$3,'allow',$4,$5,now()-($6 * interval '1 minute'),now(),now()
            FROM ordinary_hook_checks CROSS JOIN generate_series(1,15) WHERE id=$1""",
            template, f"session-{index}", "deny" if index == 11 else "allow", Jsonb([action]),
            Jsonb({"status": "scored", "category": "supply_chain" if index == 11 else "none", "score": 80}),
            index + 1)
    gateway, headers, _ = create(s)
    settings(s, gateway, capture_content=True)
    result = machine(s, "checks", headers, payload(consumer_id="worker-11@example.test", consumer_name="Gateway caller"))
    assert result.status_code == 200, result.text

    def flow(**query):
        response = browser(s, "GET", "guardrail/flow?" + urlencode({"range": "1h", **query}))
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        return response.json()

    summary = flow(limit=5)
    assert summary["totals"]["checks"] == 182
    assert summary["totals"]["identities"] == 14
    assert len(summary["top_identities"]) == 10
    assert len(summary["items"]) == 5 and summary["has_more"]
    assert summary["total"] == 14
    assert sum(item["checks"] for item in summary["sources"]) == 182
    assert sum(summary["risks"].values()) == sum(summary["decisions"].values()) == 182
    assert summary["totals"]["flagged"] >= 15
    assert "actions" not in str(summary) and "messages" not in str(summary)
    recent = flow(view="checks")["recent_checks"]
    assert len(recent) == 100
    assert {row["source"] for row in recent} == {"endpoint", "gateway"}
    assert all(set(row) == {"id", "source", "product_key", "risk"} for row in recent)
    second = flow(until=summary["until"], limit=5, offset=5)
    assert second["totals"] == summary["totals"]
    assert not {row["key"] for row in summary["items"]} & {row["key"] for row in second["items"]}
    search = flow(until=summary["until"], source="endpoints", search="worker-11@example.test")
    assert search["total"] == 1 and search["items"][0]["checks"] == 15
    key = search["items"][0]["key"]
    selected = flow(until=summary["until"], identity=key, view="sessions")
    assert selected["totals"]["checks"] == selected["decisions"]["deny"] == selected["risks"]["supply_chain"] == 15
    assert selected["totals"]["identities"] == selected["total"] == 1
    focused = flow(identity=key, view="checks")["recent_checks"]
    assert len(focused) == 15
    assert all(row["risk"] == "supply_chain" and row["product_key"] == selected["sources"][0]["product_key"] for row in focused)
    assert flow(identity=key, view="checks", decision="allow")["recent_checks"] == []
    query = {"range": "1h", "until": summary["until"], "identity": key, "limit": 7}
    page = browser(s, "GET", "guardrail/checks?" + urlencode(query)).json()
    assert len(page["items"]) == 7 and page["next_cursor"]
    assert all(row["actions"][0]["agent"]["account"] == "worker-11@example.test" for row in page["items"])
    next_page = browser(s, "GET", "guardrail/checks?" + urlencode({**query, "cursor": page["next_cursor"]})).json()
    assert len(next_page["items"]) == 7
    assert not {row["id"] for row in page["items"]} & {row["id"] for row in next_page["items"]}
    assert flow(identity=key, decision="allow")["totals"]["checks"] == 0
    assert flow(identity=key, risk="supply_chain", product=selected["sources"][0]["product_key"])["totals"]["checks"] == 15
    assert flow(session=selected["items"][0]["key"])["totals"]["checks"] == 15
    assert flow(boundary="PreToolUse")["totals"]["checks"] == 0
    assert flow(range="15m")["totals"]["checks"] == 182
    assert flow(search="%_")["total"] == 0  # Search text is literal, not a LIKE expression.
    for user in ("owner", "analyst"):
        assert browser(s, "GET", "guardrail/flow", user=user).status_code == 200
    for user in ("viewer", "admin"):
        assert browser(s, "GET", "guardrail/flow", user=user).status_code == 403
    assert browser(s, "GET", "guardrail/flow", user="foreign").json()["totals"]["checks"] == 0
    assert browser(s, "GET", "guardrail/flow?view=checks", user="foreign").json()["recent_checks"] == []
    assert browser(s, "GET", "guardrail/checks?" + urlencode(query), user="foreign").json()["items"] == []
    for invalid in ("range=bad", "until=2026-10-28", "until=bad", "offset=-1", "limit=101",
                    "risk=bad", "decision=bad", "source=bad", "view=bad"):
        assert browser(s, "GET", "guardrail/flow?" + invalid).status_code == 400

    # A fixed window excludes later arrivals, includes its start, and excludes
    # its end. The older account remains visible in the hour but not 15 minutes.
    s.db.execute("UPDATE ordinary_hook_checks SET created_at=$2::timestamptz-interval '1 hour' WHERE session_id=$1",
                 "session-11", summary["until"])
    assert flow(until=summary["until"], identity=key)["totals"]["checks"] == 15
    assert flow(range="15m", until=summary["until"], identity=key)["totals"]["checks"] == 0
    s.db.execute("UPDATE ordinary_hook_checks SET created_at=$2::timestamptz WHERE session_id=$1",
                 "session-11", summary["until"])
    empty = flow(until=summary["until"], identity=key)
    assert empty["totals"]["checks"] == 0 and empty["items"] == empty["top_identities"] == []

    for table, record_id, source in (("ordinary_hook_checks", template, "endpoints"),
                                    ("gateway_requests", result.json()["id"], "gateways")):
        s.db.execute("UPDATE " + table + " SET status='pending',evaluated_decision=NULL,returned_decision=NULL,assessment=NULL,deadline_at=now()+interval '1 minute' WHERE id=$1", record_id)
        pending = flow(source=source)
        s.db.execute("UPDATE " + table + " SET deadline_at=now()-interval '1 second' WHERE id=$1", record_id)
        expired = flow(source=source, decision="unavailable")
        assert expired["totals"]["checks"] == expired["risks"]["unassessed"] == 1
        assert flow(source=source)["totals"]["checks"] == pending["totals"]["checks"] + 1
        rows = browser(s, "GET", "guardrail/checks?range=1h&source=" + source + "&decision=unavailable").json()["items"]
        assert len(rows) == 1 and rows[0]["status"] == "unavailable" and rows[0]["failure_reason"] == "timeout"


def test_gateway_names_are_bounded_redacted_and_bound_to_the_check(system):
    s = system
    gateway, headers, credential = create(s)
    # Labels remain available without prompt capture, including outcome-only records.
    names = {"consumer_id": "user:alice", "consumer_name": "Alice Example", "application_name": "Support assistant"}
    value = payload(messages=[], availability="capture_disabled", **names)
    checked = machine(s, "checks", headers, value)
    assert checked.status_code == 503
    receipt = {"request_id": value["request_id"], "node_id": value["node_id"], "check_id": checked.json()["id"],
               "outcome": "fail_open", "status_code": None, "latency_ms": None, **names}
    for field in ("consumer_name", "application_name"):
        assert machine(s, "outcomes", headers, {**receipt, field: "Changed label"}).status_code == 409
        assert machine(s, "checks", headers, {**value, field: "Changed label"}).status_code == 409
        for invalid in (123, "x" * 257, "line\nbreak"):
            assert machine(s, "checks", headers, payload(**{**names, field: invalid})).status_code == 400
    assert machine(s, "checks", headers, payload(consumer_name="Unbound caller")).status_code == 400
    assert machine(s, "outcomes", headers, receipt).status_code == 200
    orphan = {**receipt, "request_id": new_id()}
    del orphan["check_id"]
    assert machine(s, "outcomes", headers, orphan).status_code == 200
    for path in ("gateways/requests", "guardrail/checks?source=gateways"):
        rows = browser(s, "GET", path).json()["items"]
        assert len(rows) == 2
        assert all(all(row[key] == val for key, val in names.items()) for row in rows)
    detail = browser(s, "GET", "gateways/requests/" + checked.json()["id"]).json()
    assert all(detail[key] == val for key, val in names.items())
    secret = credential["token"]
    redacted = machine(s, "checks", headers, payload(messages=[], availability="capture_disabled",
        consumer_id="user:alice", consumer_name=secret, application_name=secret))
    assert redacted.status_code == 503
    stored = s.db.one("SELECT metadata FROM gateway_requests WHERE id=$1", redacted.json()["id"])
    assert secret not in json.dumps(stored)


def test_identity_roles_tenant_scope_and_credential_lifecycle(system):
    s = system
    gateway, headers, credential = create(s, "admin")
    assert gateway["mode"] == "shadow" and gateway["capture_content"] is False
    assert gateway["status"] == "never_seen" and gateway["node_count"] == 0
    assert browser(s, "POST", "gateways", {"name": "Forbidden"}, "analyst").status_code == 403
    for user in ("viewer", "admin", "analyst"):
        assert browser(s, "GET", "gateways/overview", user=user).status_code == 200
    assert browser(s, "GET", "gateways", user="viewer").status_code == 403
    assert browser(s, "GET", "gateways/requests", user="admin").status_code == 403
    assert browser(s, "GET", "gateways/" + gateway["id"], user="foreign").status_code == 404
    assert browser(s, "GET", "gateways", user="foreign").json()["items"] == []
    assert browser(s, "PUT", "gateways/" + gateway["id"] + "/settings",
                   {"version": 1, "mode": "enforce", "capture_content": True, "policy_rule_ids": []}, "admin").status_code == 403
    assert browser(s, "PATCH", "gateways/" + gateway["id"], {"version": 1, "enabled": False}, "analyst").status_code == 403
    result = machine(s, "heartbeats", headers, heartbeat())
    assert result.status_code == 200 and result.json()["capture_content"] is False
    assert machine(s, "heartbeats", headers, heartbeat()).status_code == 200
    detail = browser(s, "GET", "gateways/" + gateway["id"], user="admin").json()
    assert detail["gateway"]["node_count"] == 1 and detail["gateway"]["status"] == "reporting"
    assert len(detail["routes"]) == 1 and detail["nodes"][0]["dropped_events"] == 2
    assert "token" not in str(detail) and "token_hash" not in str(detail)
    stored = s.db.one("SELECT token_hash FROM gateway_credentials WHERE id=$1", credential["id"])
    assert stored["token_hash"] != credential["token"] and len(stored["token_hash"]) == 64
    rotated = browser(s, "POST", "gateways/" + gateway["id"] + "/credentials", {}, "admin")
    assert rotated.status_code == 200
    assert machine(s, "heartbeats", headers, heartbeat()).status_code == 401
    new_headers = {"Authorization": "Bearer " + rotated.json()["token"]}
    assert machine(s, "heartbeats", new_headers, heartbeat()).status_code == 200
    revoked = browser(s, "DELETE", "gateways/" + gateway["id"] + "/credentials/" + rotated.json()["id"], user="admin")
    assert revoked.status_code == 200
    assert machine(s, "heartbeats", new_headers, heartbeat()).status_code == 401
    assert credential["token"] not in str(s.db.many("SELECT details FROM audit_log WHERE tenant_id=$1", s.tenant["id"]))


def test_shadow_enforce_capture_and_truthful_outcomes(system):
    s = system
    gateway, headers, _ = create(s)
    value = payload()
    assert machine(s, "checks", headers, value).status_code == 503
    assert not s.provider.requests
    row = s.db.one("SELECT * FROM gateway_requests WHERE request_id=$1", value["request_id"])
    assert row["messages"] is None and row["evaluated_decision"] is None and row["failure_reason"] == "capture_disabled"
    gateway = settings(s, gateway, capture_content=True)
    allowed = machine(s, "checks", headers, payload())
    assert allowed.status_code == 200 and allowed.json()["returned_decision"] == "allow"
    enable_risk(s)
    s.provider.payload = s.provider.scored(100)
    value = payload()
    shadow = machine(s, "checks", headers, value)
    assert shadow.status_code == 200, shadow.text
    result = shadow.json()
    assert result["evaluated_decision"] == "deny" and result["returned_decision"] == "allow"
    receipt = {"request_id": value["request_id"], "node_id": value["node_id"], "check_id": result["id"],
               "outcome": "blocked", "status_code": 403, "latency_ms": 25}
    assert machine(s, "outcomes", headers, receipt).status_code == 409
    receipt.update(outcome="unconfirmed", status_code=200)
    assert machine(s, "outcomes", headers, receipt).status_code == 200
    assert machine(s, "outcomes", headers, receipt).status_code == 200
    assert machine(s, "outcomes", headers, {**receipt, "outcome": "forwarded"}).status_code == 409
    gateway = settings(s, gateway, mode="enforce")
    value = payload()
    result = machine(s, "checks", headers, value).json()
    assert result["evaluated_decision"] == result["returned_decision"] == "deny"
    receipt = {**receipt, "request_id": value["request_id"], "check_id": result["id"], "outcome": "blocked", "status_code": 403}
    assert machine(s, "outcomes", headers, receipt).status_code == 200
    detail = browser(s, "GET", "gateways/requests/" + result["id"]).json()
    assert detail["outcome"] == "blocked" and detail["assessment"]["score"] == 100 and detail["usage"] is None
    assert not {"model", "usage", "rubric_version"}.intersection(detail["assessment"])
    assert detail["model"] == "requested-model" and detail["provider"] == "configured-provider"
    assert detail["messages"] == value["messages"]
    assert browser(s, "GET", "gateways/requests/" + result["id"], user="foreign").status_code == 404
    overview = browser(s, "GET", "gateways/overview").json()
    assert overview["requests"]["would_deny"] == 1 and overview["requests"]["blocked"] == 1
    assert overview["requests"]["unavailable"] == 1 and overview["coverage"] == "observed_only"
    usage = s.db.one("SELECT * FROM model_usage WHERE gateway_request_id=$1", result["id"])
    assert usage["purpose"] == "guardrail" and usage["sensor_id"] is None and usage["event_id"] is None
    assert usage["status"] == "completed" and usage["input_tokens"] == 2000


def test_request_retries_failures_and_receipts_before_checks(system):
    s = system
    gateway, headers, _ = create(s)
    settings(s, gateway, capture_content=True, mode="enforce")
    value = payload()
    first = machine(s, "checks", headers, value)
    second = machine(s, "checks", headers, value)
    assert first.status_code == second.status_code == 200 and first.json() == second.json()
    assert len(s.provider.requests) == 1
    changed = {**value, "messages": [{"role": "user", "content": "A different request"}]}
    assert machine(s, "checks", headers, changed).status_code == 409
    assert machine(s, "checks", headers, {**value, "node_id": "different-node"}).status_code == 409
    early = payload()
    receipt = {"request_id": early["request_id"], "node_id": early["node_id"], "outcome": "fail_open",
               "status_code": 200, "latency_ms": 10, "failure_reason": "backend_unavailable"}
    assert machine(s, "outcomes", headers, receipt).status_code == 200
    assert machine(s, "checks", headers, early).status_code == 503
    assert len(s.provider.requests) == 1
    s.provider.status = 503
    unavailable = machine(s, "checks", headers, payload())
    assert unavailable.status_code == 503
    s.provider.status, s.provider.payload = 200, {"invalid": "response"}
    assert machine(s, "checks", headers, payload()).status_code == 503
    s.provider.payload = s.provider.scored(100)
    s.provider.block()
    timeout_value = payload(timeout_ms=160)
    started = time.monotonic()
    timed_out = machine(s, "checks", headers, timeout_value)
    assert timed_out.status_code == 503 and time.monotonic()-started < 1
    s.provider.release()
    row = s.db.one("SELECT * FROM gateway_requests WHERE request_id=$1", timeout_value["request_id"])
    assert row["status"] == "unavailable" and row["failure_reason"] in {"timeout", "connection_failed"}
    assert row["returned_decision"] is None and row["evaluated_decision"] is None
    assert machine(s, "outcomes", headers, {**receipt, "request_id": timeout_value["request_id"],
                                          "check_id": row["id"], "failure_reason": "timeout"}).status_code == 200


def test_policy_eligibility_concurrency_and_capture_change(system):
    s = system
    gateway, headers, _ = create(s)
    rules = [{"id": "gateway-rule", "name": "Kong prompts", "enabled": True, "action": "deny",
              "reason": "Preserve configured reason", "match": {"kinds": ["prompt"], "products": ["kong"]}},
             {"id": "endpoint-rule", "name": "Command", "enabled": True, "action": "deny",
              "match": {"command_regex": "secret"}},
             {"id": "host-rule", "name": "Host", "enabled": True, "action": "deny",
              "match": {"host_glob": "*"}}]
    assert browser(s, "PUT", "response/policy", {"rules": rules}).status_code == 200
    for ineligible in ("endpoint-rule", "host-rule", "removed"):
        data = {"version": gateway["version"], "mode": "enforce", "capture_content": True, "policy_rule_ids": [ineligible]}
        assert browser(s, "PUT", "gateways/" + gateway["id"] + "/settings", data).status_code == 400
    gateway = settings(s, gateway, capture_content=True, mode="enforce", policy_rule_ids=["gateway-rule"])
    stale = {"version": 1, "enabled": False}
    assert browser(s, "PATCH", "gateways/" + gateway["id"], stale).status_code == 409
    decision = machine(s, "checks", headers, payload())
    assert decision.status_code == 200, decision.text
    assert decision.json()["returned_decision"] == "deny" and decision.json()["reason"] == rules[0]["reason"]
    s.provider.block()
    value = payload()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(machine, s, "checks", headers, value)
        assert s.provider.entered.wait(1)
        duplicate = machine(s, "checks", headers, value)
        assert duplicate.status_code == 503
        settings(s, gateway, capture_content=False)
        s.provider.release()
        assert pending.result().status_code == 503
    row = s.db.one("SELECT * FROM gateway_requests WHERE request_id=$1", value["request_id"])
    assert row["failure_reason"] == "settings_changed" and row["returned_decision"] is None
    assert len(s.provider.requests) == 2


def test_unavailable_content_limits_filtering_and_retention(system):
    s = system
    gateway, headers, credential = create(s)
    gateway = settings(s, gateway, capture_content=True)
    for availability in gateways.CAPTURE_STATES[1:]:
        result = machine(s, "checks", headers, payload(availability=availability, messages=[]))
        assert result.status_code == 503
    for secret in ("sk-proj-" + "A" * 80, credential["token"]):
        redacted = machine(s, "checks", headers, payload(messages=[{"role": "user", "content": "Please use " + secret}]))
        assert redacted.status_code == 503
        stored = s.db.one("SELECT * FROM gateway_requests WHERE id=$1", redacted.json()["id"])
        assert stored["messages"] is None and stored["failure_reason"] == "content_redacted"
        assert secret not in str(stored) and secret not in redacted.text
    assert not s.provider.requests
    rows = s.db.many("SELECT messages FROM gateway_requests WHERE tenant_id=$1", s.tenant["id"])
    assert all(row["messages"] is None for row in rows)
    assert secret not in str(rows)
    assert machine(s, "checks", headers, payload(extra="forbidden")).status_code == 400
    assert machine(s, "checks", headers, payload(messages=[{"role": "user", "content": "a" * 70000}])).status_code == 413
    assert machine(s, "checks", headers, payload(messages=[{"role": "user", "content": ["multipart"]}])).status_code == 400
    all_rows = browser(s, "GET", "gateways/requests?limit=2").json()
    assert len(all_rows["items"]) == 2 and all_rows["next_cursor"]
    next_rows = browser(s, "GET", "gateways/requests?limit=2&cursor=" + all_rows["next_cursor"]).json()
    assert not {r["id"] for r in all_rows["items"]} & {r["id"] for r in next_rows["items"]}
    assert len(browser(s, "GET", "gateways/requests?gateway_id=" + gateway["id"] + "&status=unavailable&outcome=unconfirmed").json()["items"]) == 7
    s.db.execute("UPDATE gateway_requests SET created_at=now()-interval '8 days' WHERE tenant_id=$1", s.tenant["id"])
    assert gateways.cleanup(s.db, s.cfg) is False
    s.db.execute("INSERT INTO tenant_telemetry_retention(tenant_id,mode) VALUES($1,'7')", s.tenant["id"])
    assert gateways.cleanup(s.db, s.cfg) is True
    assert s.db.scalar("SELECT count(*) FROM gateway_requests WHERE tenant_id=$1", s.tenant["id"]) == 0
    s.db.execute("DELETE FROM gateway_instances WHERE id=$1", gateway["id"])
    assert s.db.scalar("SELECT count(*) FROM gateway_credentials WHERE gateway_id=$1", gateway["id"]) == 0
    isolated = new_id()
    s.db.execute("INSERT INTO tenants(id,name,slug) VALUES($1,'Gateway cascade',$2)", isolated, isolated)
    s.db.execute("INSERT INTO gateway_instances(id,tenant_id,name) VALUES($1,$2,'Gateway')", new_id(), isolated)
    s.db.execute("DELETE FROM telemetry_partition_days WHERE tenant_id=$1", isolated)
    s.db.execute("DELETE FROM tenants WHERE id=$1", isolated)
    assert s.db.scalar("SELECT count(*) FROM gateway_instances WHERE tenant_id=$1", isolated) == 0


def test_json_capture_preserves_text_and_omits_decoded_secrets(system):
    s = system
    gateway, headers, credential = create(s)
    gateway = settings(s, gateway, capture_content=True)
    enable_risk(s)
    messages = [{"role": "user", "content": content} for content in (
        '{"x":1}',
        '[1,{"label":"public"}]',
        r'{"label":"\u2603"}',
        '{\n "x": 1, "x": 2\n}',
        json.dumps({"nested": '{"x":1}'}, separators=(",", ":")),
    )]
    messages[1]["role"] = "tool"
    for mode, score, evaluated, returned in (
        ("enforce", 0, "allow", "allow"),
        ("enforce", 100, "deny", "deny"),
        ("shadow", 100, "deny", "allow"),
    ):
        gateway = settings(s, gateway, mode=mode)
        s.provider.payload = s.provider.scored(score)
        result = machine(s, "checks", headers, payload(messages=messages))
        assert result.status_code == 200, result.text
        assert result.json()["evaluated_decision"] == evaluated and result.json()["returned_decision"] == returned
        stored = s.db.one("SELECT messages,mode,evaluated_decision,returned_decision "
                          "FROM gateway_requests WHERE id=$1", result.json()["id"])
        assert stored == {"messages": messages, "mode": mode,
                          "evaluated_decision": evaluated, "returned_decision": returned}
        assert s.provider.requests[-1]["state"]["target_event"]["messages"] == messages
    escaped = "".join("\\u%04x" % ord(character) for character in credential["token"])
    sensitive = (
        '{"value":"' + escaped + '"}',
        '"' + escaped + '"',
        r'{"\u0074oken":"private-value"}',
        json.dumps({"nested": '{"value":"' + escaped + '"}'}),
        '{"value":"' + escaped + '","value":"public"}',
        '{"' + escaped + '":"public"}',
    )
    for content in sensitive:
        result = machine(s, "checks", headers, payload(messages=[{"role": "user", "content": content}]))
        assert result.status_code == 503
        stored = s.db.one("SELECT * FROM gateway_requests WHERE id=$1", result.json()["id"])
        assert stored["failure_reason"] == "content_redacted" and stored["messages"] is None
        assert content not in str(stored) and credential["token"] not in str(stored)
    assert len(s.provider.requests) == 3


def test_admission_is_bounded_and_separate_from_dashboard(system, monkeypatch):
    s = system
    gateway, headers, _ = create(s)
    settings(s, gateway, capture_content=True)
    # Exercise HTTP admission with capacity ready for all four DB workers.
    data_pool = s.db.pools["data"]
    data_pool.resize(4, data_pool.max_size)
    data_pool.wait()
    import asyncio
    import threading
    upstream = httpx.AsyncHTTPTransport.handle_async_request
    entered, release = threading.Condition(), threading.Event()
    count = 0

    async def delayed(transport, request):
        nonlocal count
        with entered:
            count += 1
            entered.notify_all()
        assert await asyncio.to_thread(release.wait, 5)
        return await upstream(transport, request)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", delayed)
    with ThreadPoolExecutor(max_workers=8) as pool:
        pending = [pool.submit(machine, s, "checks", headers, payload()) for _ in range(8)]
        try:
            with entered:
                assert entered.wait_for(lambda: count == 8, timeout=1.5)
            started = time.monotonic()
            rejected = machine(s, "checks", headers, payload())
            assert rejected.status_code == 503 and time.monotonic()-started < 0.5
            assert browser(s, "GET", "gateways/overview").status_code == 200
        finally:
            release.set()
        assert all(result.result().status_code in (200, 503) for result in pending)


def test_gateway_postgres_lock_contention_returns_unavailable_without_dispatch(system):
    s = system
    gateway, headers, _ = create(s)
    settings(s, gateway, capture_content=True)
    s.db.pools["data"].resize(5, s.db.pools["data"].max_size)
    s.db.pools["data"].wait()
    with ThreadPoolExecutor(max_workers=8) as pool:
        with s.db.transaction() as owner:
            s.db.one("SELECT id FROM gateway_instances WHERE id=$1 FOR UPDATE", gateway["id"], conn=owner)
            started = time.monotonic()
            pending = [pool.submit(machine, s, "checks", headers, payload()) for _ in range(8)]
            assert browser(s, "GET", "gateways/overview").status_code == 200
            assert all(future.result(timeout=1).status_code == 503 for future in pending)
            assert time.monotonic() - started < 1
            assert not s.provider.requests
    assert machine(s, "checks", headers, payload()).status_code == 200
    assert len(s.provider.requests) == 1


def test_replays_and_inflight_checks_revalidate_shared_policy_and_identity(system):
    s = system
    gateway, headers, _ = create(s)
    settings(s, gateway, capture_content=True, mode="enforce")
    enable_risk(s)
    s.provider.payload = s.provider.scored(100)
    value = payload()
    checked = machine(s, "checks", headers, value)
    assert checked.status_code == 200 and checked.json()["returned_decision"] == "deny"
    assert browser(s, "PUT", "response/guardrails", {"enabled": False}).status_code == 200
    assert machine(s, "checks", headers, value).status_code == 503
    assert len(s.provider.requests) == 1
    fresh = payload()
    assert machine(s, "checks", headers, fresh).status_code == 200
    assert browser(s, "PUT", "response/company-policy", {"revision": 0, "prompt": "Only public reports are approved."}).status_code == 200
    assert machine(s, "checks", headers, fresh).status_code == 503
    assert len(s.provider.requests) == 2
    foreign_gateway, foreign_headers, _ = create(s, "foreign")
    receipt = {"request_id": value["request_id"], "node_id": value["node_id"], "check_id": checked.json()["id"],
               "outcome": "blocked", "status_code": 403, "latency_ms": 10}
    assert s.foreign_client.post("/ingest/v1/gateway-outcomes", headers=foreign_headers, json=receipt).status_code == 409
    assert s.db.scalar("SELECT count(*) FROM gateway_requests WHERE gateway_id=$1", foreign_gateway["id"]) == 0
    s.provider.block()
    in_flight = payload()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(machine, s, "checks", headers, in_flight)
        assert s.provider.entered.wait(1)
        assert browser(s, "POST", "gateways/" + gateway["id"] + "/credentials", {}).status_code == 200
        s.provider.release()
        assert pending.result().status_code == 503
    row = s.db.one("SELECT * FROM gateway_requests WHERE request_id=$1", in_flight["request_id"])
    assert row["status"] == "unavailable" and row["failure_reason"] == "identity_changed"
    assert row["returned_decision"] is None
    assert s.db.one("SELECT status,input_tokens FROM model_usage WHERE gateway_request_id=$1", row["id"]) == {
        "status": "completed", "input_tokens": 2000}


def test_abandoned_checks_filter_as_unavailable_and_cleanup_unknown_usage(system):
    s = system
    gateway, headers, _ = create(s)
    settings(s, gateway, capture_content=True)
    s.provider.block()
    value = payload()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(machine, s, "checks", headers, value)
        assert s.provider.entered.wait(1)
        with s.db.transaction() as conn:
            s.db.one("SELECT id FROM gateway_instances WHERE id=$1 FOR UPDATE", gateway["id"], conn=conn)
            s.provider.release()
            assert pending.result().status_code == 503
    s.db.execute("UPDATE gateway_requests SET deadline_at=now()-interval '2 minutes' WHERE request_id=$1", value["request_id"])
    s.db.execute("UPDATE model_usage SET started_at=now()-interval '2 minutes' WHERE gateway_request_id IN "
                 "(SELECT id FROM gateway_requests WHERE request_id=$1)", value["request_id"])
    result = browser(s, "GET", "gateways/requests?status=unavailable").json()
    assert len(result["items"]) == 1 and result["items"][0]["failure_reason"] == "timeout"
    assert browser(s, "GET", "gateways/requests?status=pending").json()["items"] == []
    assert gateways.cleanup(s.db, s.cfg) is True
    row = s.db.one("SELECT * FROM gateway_requests WHERE request_id=$1", value["request_id"])
    assert row["status"] == "unavailable"
    usage = s.db.one("SELECT status,input_tokens,cost_usd FROM model_usage WHERE gateway_request_id=$1", row["id"])
    assert usage == {"status": "error", "input_tokens": None, "cost_usd": None}
    s.db.execute("UPDATE model_usage SET status='pending',completed_at=NULL WHERE gateway_request_id=$1", row["id"])
    s.db.execute("DELETE FROM gateway_requests WHERE id=$1", row["id"])
    assert gateways.cleanup(s.db, s.cfg) is True
    assert s.db.one("SELECT status,input_tokens,cost_usd FROM model_usage WHERE gateway_request_id=$1", row["id"]) == usage


def test_expired_stored_deadline_returns_unavailable_over_http(system, monkeypatch):
    s = system
    gateway, headers, _ = create(s)
    settings(s, gateway, capture_content=True, mode="enforce")
    enable_risk(s)
    s.provider.payload = s.provider.scored(100)
    original = gateways.finish

    def expire(st, cfg, token, prepared, *args, **kwargs):
        st.execute("UPDATE gateway_requests SET deadline_at=clock_timestamp()-interval '1 second' WHERE id=$1",
                   prepared["row"]["id"])
        return original(st, cfg, token, prepared, *args, **kwargs)

    monkeypatch.setattr(gateways, "finish", expire)
    response = machine(s, "checks", headers, payload())
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "unavailable"
    row = s.db.one("SELECT * FROM gateway_requests")
    assert row["returned_decision"] is None and row["evaluated_decision"] is None
    assert s.db.scalar("SELECT count(*) FROM model_usage WHERE status='completed'") == 1
