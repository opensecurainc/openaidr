"""Free sensor behavior at the native hook, telemetry and external HTTP boundaries."""

import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from threading import Event
from unittest.mock import Mock
from uuid import uuid4

import httpx
import pytest

from openaidr.sensor import free_enrollment, free_runtime, runtime, usage
from openaidr.sensor.config import Config
from openaidr.sensor.telemetry import Telemetry


def free_config(tmp_path, mode="free"):
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"), listen="127.0.0.1:0")
    cfg.save()
    identity = free_enrollment.prepare(cfg)
    connection = identity.connection
    cfg.update(connection_mode=mode, server_url=connection.origin, sensor_id=identity.device_id,
               sensor_token=connection.api_key, tenant_id=connection.tenant_id)
    cfg.save()
    return cfg


class Service:
    def __init__(self, cfg, *, failure=None, score=90):
        self.cfg, self.failure, self.score, self.requests = cfg, failure, score, []
        self.status = "available"

    def __call__(self, request):
        self.requests.append(request)
        assert request.url.host == "api.opensecura.ai"
        assert request.headers["authorization"] == "Bearer " + self.cfg["sensor_token"]
        if self.failure == "timeout":
            raise httpx.ReadTimeout("private-timeout-detail")
        if self.failure == "connection":
            raise httpx.ConnectError("private-connection-detail")
        if self.failure == "unexpected":
            raise RuntimeError("private-unexpected-detail")
        if self.failure in ("exhausted", "authentication", "rate_limit", "service"):
            code = {"exhausted": 402, "authentication": 401, "rate_limit": 429, "service": 503}[self.failure]
            return httpx.Response(code, json={"error": "private-service-detail"})
        if self.failure == "redirect":
            return httpx.Response(307, headers={"location": "https://other.example/"})
        if request.url.path == "/v1/capabilities":
            from openaidr_api_client.contracts.capabilities import CAPABILITIES
            return httpx.Response(200, json=dict(tenant_id=self.cfg["tenant_id"], build="test",
                capabilities={name: "configured" for name in CAPABILITIES},
                provider_access="not_checked", investigation_worker="not_checked"))
        if request.url.path == "/v1/free/status":
            assert request.method == "GET" and not request.content
            return httpx.Response(200, json=dict(tenant_id=self.cfg["tenant_id"], plan="free", status=self.status,
                guardrail_available=self.status == "available", guardrail_configured=True,
                credit_status="disabled", credits_per_usd="100", reset_at=None))
        assert request.url.path == "/v1/services/guardrail/assess"
        assert set(json.loads(request.content)) == {"state", "company_policy", "timeout_ms"}
        score = 500 if self.failure == "invalid" else self.score
        result = dict(profile="guardrail.1", status="scored", score=score,
            level=("info", "low", "medium", "high", "critical")[min(4, self.score // 20)],
            category="destructive_command" if score else "none", confidence=1, category_confidence=1,
            assessed_at="2026-11-01T12:00:00Z", billing=dict(request_id=request.headers["idempotency-key"],
                service="guardrail", state="disabled", credits_reserved=None, credits_charged=None, rate_version=None))
        if self.failure == "unscored":
            result.update(status="unscored", score=None, level=None, category="unknown")
        return httpx.Response(200, json=result)


@pytest.mark.parametrize("mode", ["free", "api_key"])
@pytest.mark.parametrize("score,decision", [(0, "allow"), (60, "ask"), (90, "deny")])
def test_native_free_hooks_assess_remotely_and_keep_shadow_results_across_restart(tmp_path, monkeypatch, score, decision, mode):
    cfg = free_config(tmp_path, mode)
    remote = Service(cfg, score=score)
    actual = free_runtime.FreeClient
    monkeypatch.setattr(free_runtime, "FreeClient", lambda config: actual(config, transport=httpx.MockTransport(remote)))
    sensor = runtime.Sensor(Config.load(cfg.path))
    try:
        sensor.heartbeat_once()
        assert sensor.last_heartbeat
        assert sensor.cloud_protection["state"] == "active" if mode == "free" else sensor.cloud_protection is None
        assert sensor.inventory.local and sensor.component_inventory.local and sensor.component_inventory.options["enabled"]
        reply = sensor.hooks.evaluate(dict(hook_event_name="PreToolUse", session_id="test-session", tool_name="Bash",
            tool_input={"command": "echo hello", "password": "private-password"}), "claude-code")
        assert reply["decision"] == "allow"
        assert "private-password" not in remote.requests[-1].content.decode()
        summary = sensor.client.post("guardrails/summary", {"days": 1})
        assert summary["summary"][decision] == summary["summary"]["completed"] == 1
        assert summary["recent"][0]["returned_decision"] == "allow"
        assert summary["recent"][0]["failure_reason"] is None
        assert summary["by_mode"]["enforce"]["completed"] == 0
        sensor.client.post("events", {"events": [{"private": "raw activity"}]})
        assert len(remote.requests) == 2
    finally:
        sensor.client.close()
        sensor.hook_clients.close()
        sensor.telemetry.close()
        sensor.spool.close()
    resumed = actual(Config.load(cfg.path), transport=httpx.MockTransport(remote))
    try:
        assert resumed.summary(1)["summary"] == summary["summary"]
        if decision == "ask":
            from openaidr.sensor import bridge

            def inspect(action, **params):
                return bridge.handle(dict(action="guardrails." + action, config_path=str(cfg.path), params=params))

            page = inspect("denials", decision="ask", days=1, until=summary["until"], cursor="")
            detail = inspect("check", decision="ask", id=page["items"][0]["id"], scope=page["scope"], review_version=1)
            assert detail["evidence"]["assessment"]["score"] == score
            assert detail["actions"][0]["command"]["text"] == "echo hello"
            assert detail["returned_decision"] == "allow"
            assert "private-password" not in json.dumps(detail)
            assert "billing" not in json.dumps(detail)
            with pytest.raises(ValueError, match="connection changed"):
                inspect("check", decision="ask", id=detail["id"], scope="wrong")
            with pytest.raises(ValueError, match="Could not save"):
                inspect("review", id=detail["id"], scope=page["scope"], label="false_positive", note="")
        else:
            with resumed.database() as db:
                assert not db.execute("SELECT * FROM check_details").fetchall()
        assert len(remote.requests) == 2
        with pytest.raises(httpx.HTTPStatusError):
            resumed.post("inventory/snapshots", {"private": "inventory"})
        assert len(remote.requests) == 2
    finally:
        resumed.close()


def test_local_ask_inspection_pages_legacy_checks_and_isolates_evidence(tmp_path):
    cfg = free_config(tmp_path)
    remote = Service(cfg, score=65)
    client = free_runtime.FreeClient(cfg, transport=httpx.MockTransport(remote))
    now = datetime.now(timezone.utc)
    body = dict(request_id=str(uuid4()), product="codex-cli", hook_event="PreToolUse", availability="available",
                actions=[{"kind": "command", "command": {"text": "captured action <script>literal</script>"}}])
    try:
        client.check(body, time.monotonic() + 10)
        until = client.summary(1)["until"]
        window = dict(days=1, until=until, cursor="", decision="ask")
        with client.database() as db:
            for i in range(22):
                db.execute("INSERT INTO checks VALUES(?,?,?,?,?,?,?,?)", (str(uuid4()),
                    (now - timedelta(minutes=i+1)).isoformat(), "codex-cli", "PreToolUse", "evaluated", "ask", None, 0))
            for ident, age, decision in (("old", 31, "ask"), ("allow", 0, "allow"), ("deny", 0, "deny")):
                db.execute("INSERT INTO checks VALUES(?,?,?,?,?,?,?,?)", (ident,
                    (now - timedelta(days=age)).isoformat(), "codex-cli", "PreToolUse", "evaluated", decision, None, 0))
        first = client.post("guardrails/denials", window)
        second = client.post("guardrails/denials", {**window, "cursor": first["next_cursor"]})
        assert len(first["items"]) == 20 and len(second["items"]) == 3 and second["next_cursor"] == ""
        assert len({row["id"] for row in first["items"] + second["items"]}) == 23
        assert "captured action" not in json.dumps(first)
        legacy = client.post("guardrails/check", dict(id=second["items"][0]["id"], decision="ask"))
        assert legacy["actions"] == [] and legacy["evidence"]["assessment"] is None
        assert legacy["evidence"]["decision_basis"] == {}
        for ident in ("old", "allow", "deny", str(uuid4())):
            with pytest.raises(ValueError, match="not found"):
                client.post("guardrails/check", dict(id=ident, decision="ask"))
        with pytest.raises(ValueError):
            client.post("guardrails/denials", {**window, "cursor": "invalid"})
        detail = client.post("guardrails/check", dict(id=body["request_id"], decision="ask"))
        assert detail["evidence"]["assessment"]["score"] == 65
        assert detail["evidence"]["decision_basis"]["risk_settings"]["ask_threshold"] == 60
        client.scope = "another-enrollment"
        hidden = client.post("guardrails/check", dict(id=body["request_id"], decision="ask"))
        assert hidden["actions"] == [] and hidden["evidence"]["assessment"] is None
        with client.database() as db:
            snapshot = db.execute("SELECT evidence FROM check_details").fetchone()[0]
            for _ in range(1000):
                ident = str(uuid4())
                db.execute("INSERT INTO checks VALUES(?,?,?,?,?,?,?,?)", (ident, now.isoformat(),
                    "codex-cli", "PreToolUse", "evaluated", "ask", None, 0))
                db.execute("INSERT INTO check_details VALUES(?,?,?)", (ident, client.scope, snapshot))
        client.check({**body, "request_id": str(uuid4())}, time.monotonic() + 10)
        with client.database() as db:
            assert db.execute("SELECT count(*) FROM check_details").fetchone()[0] == 1000
            assert not db.execute("SELECT * FROM check_details WHERE id=?", (body["request_id"],)).fetchall()
            # The delete trigger also works for older sensor versions after rollback.
            db.execute("DELETE FROM checks")
            assert not db.execute("SELECT * FROM check_details").fetchall()
            db.execute("CREATE TRIGGER unavailable_details BEFORE INSERT ON check_details BEGIN SELECT RAISE(ABORT,'unavailable'); END")
        result = client.check({**body, "request_id": str(uuid4())}, time.monotonic() + 10)
        assert result["evaluated_decision"] == "ask" and result["returned_decision"] == "allow"
        assert client.post("guardrails/check", dict(id=result["id"], decision="ask"))["actions"] == []
        assert len(remote.requests) == 3
    finally:
        client.close()


@pytest.mark.parametrize("mode", ["free", "api_key"])
@pytest.mark.parametrize("failure,reason", [
    ("timeout", "timeout"), ("exhausted", "credits_exhausted"), ("redirect", "service_unavailable"),
    ("invalid", "invalid_response"), ("capture_disabled", "capture_disabled"),
    ("connection", "connection_failed"), ("authentication", "authentication_failed"),
    ("rate_limit", "rate_limited"), ("service", "service_unavailable"), ("unscored", "unscored"),
    ("unexpected", "unknown"), ("diagnostics_write", "unknown"),
])
def test_free_check_failures_preserve_service_status_and_allow_native_action(tmp_path, monkeypatch, failure, reason, mode):
    cfg = free_config(tmp_path, mode)
    remote = Service(cfg)
    actual = free_runtime.FreeClient
    monkeypatch.setattr(free_runtime, "FreeClient", lambda config: actual(config, transport=httpx.MockTransport(remote)))
    sensor = runtime.Sensor(cfg)
    try:
        sensor.heartbeat_once()
        protection = sensor.status()["cloud_protection"]
        assert protection["state"] == "active" if mode == "free" else protection is None
        remote.requests.clear()
        remote.failure = failure
        if failure == "diagnostics_write":
            remote.failure = "timeout"
            with sensor.client.database() as db:
                db.execute("""CREATE TRIGGER reject_diagnostics BEFORE INSERT ON check_failures
                    BEGIN SELECT RAISE(ABORT,'private-storage-detail'); END""")
        if failure == "capture_disabled":
            sensor.capture["tool_input"] = False
        result = sensor.hooks.evaluate(dict(hook_event_name="PreToolUse", session_id="test", tool_name="Bash",
            tool_input={"command": "rm -rf /tmp/test"}), "claude-code")
        assert result["decision"] == "allow" and not result["output"]
        summary = sensor.client.summary(1)
        assert summary["summary"]["completed"] == 0 and summary["summary"]["unavailable"] == 1
        assert summary["recent"][0]["failure_reason"] == reason
        assert "private-" not in json.dumps(summary)
        with sensor.client.database() as db:
            row = db.execute("SELECT reason FROM check_failures").fetchone()
            assert (row[0] if row else None) == (None if failure == "diagnostics_write" else reason)
        assert sensor.status()["cloud_protection"] == protection
        assert len(remote.requests) == (0 if failure == "capture_disabled" else 1)
        remote.failure = None
        sensor.heartbeat_once()
        assert sensor.status()["cloud_protection"] is not None if mode == "free" else sensor.status()["cloud_protection"] is None
    finally:
        sensor.client.close()
        sensor.hook_clients.close()
        sensor.telemetry.close()
        sensor.spool.close()


@pytest.mark.parametrize("failure,reason", [
    ("missing", "evidence_unavailable"), ("truncated", "evidence_truncated"),
    ("oversized", "evidence_too_large"), ("expired", "timeout"), ("late", "timeout"),
])
def test_free_local_failures_retain_safe_reasons_across_restart(tmp_path, monkeypatch, failure, reason):
    from types import SimpleNamespace

    cfg = free_config(tmp_path)
    remote = Service(cfg)
    actual_clock, clock = time.monotonic(), [time.monotonic()]
    monkeypatch.setattr(free_runtime, "time", SimpleNamespace(time=time.time, monotonic=lambda: clock[0]))

    def service(request):
        response = remote(request)
        if failure == "late":
            clock[0] += 10
        return response

    body = dict(request_id=str(uuid4()), product="codex-cli", hook_event="PreToolUse", availability="available",
                actions=[{"kind": "command", "command": {"text": "private-command"}}])
    if failure == "missing":
        body["actions"] = []
    elif failure == "truncated":
        body["availability"] = "content_truncated"
    elif failure == "oversized":
        body["actions"] = [{"kind": "command", "command": {"text": "private-command" * 100}} for _ in range(20)]
    deadline = actual_clock - 1 if failure == "expired" else actual_clock + 1
    client = free_runtime.FreeClient(cfg, transport=httpx.MockTransport(service))
    try:
        with pytest.raises(ValueError):
            client.check(body, deadline)
        result = client.summary(1)
        assert result["recent"][0]["failure_reason"] == reason
        assert result["summary"]["completed"] == 0 and result["summary"]["unavailable"] == 1
        assert "private-command" not in json.dumps(result)
        assert len(remote.requests) == (1 if failure == "late" else 0)
    finally:
        client.close()
    resumed = free_runtime.FreeClient(cfg, transport=httpx.MockTransport(service))
    try:
        assert resumed.summary(1)["recent"] == result["recent"]
        with pytest.raises(ValueError, match="already attempted"):
            resumed.check(body, actual_clock + 20)
        assert len(remote.requests) == (1 if failure == "late" else 0)
    finally:
        resumed.close()


def test_free_failure_history_upgrades_without_changing_legacy_writes_or_inventing_reasons(tmp_path):
    cfg = free_config(tmp_path)
    path = tmp_path / "data/free-checks.sqlite3"
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(path) as db:
        db.execute("""CREATE TABLE checks (id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
            product TEXT NOT NULL, hook_event TEXT NOT NULL, status TEXT NOT NULL,
            decision TEXT, billing TEXT, deadline REAL NOT NULL)""")
        db.execute("INSERT INTO checks VALUES(?,?,?,?,?,?,?,?)",
                   ("old", now, "codex-cli", "PreToolUse", "unavailable", None, None, 0))
    for _ in range(2):
        client = free_runtime.FreeClient(cfg, transport=httpx.MockTransport(Service(cfg)))
        try:
            with client.database() as db:
                # An older sensor must still be able to write after rollback.
                db.execute("INSERT OR IGNORE INTO checks VALUES(?,?,?,?,?,?,?,?)",
                           ("expired", now, "codex-cli", "PreToolUse", "pending", None, None, 0))
                db.execute("INSERT OR REPLACE INTO check_failures VALUES(?,?)", ("old", "private-unsafe-reason"))
            recent = {row["id"]: row for row in client.summary(1)["recent"]}
            assert recent["old"]["failure_reason"] == "unknown"
            assert recent["expired"]["failure_reason"] == "outcome_unknown"
            assert "private-" not in json.dumps(recent)
        finally:
            client.close()
    # The retention trigger also runs when an older sensor removes history.
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM checks")
        assert db.execute("SELECT count(*) FROM check_failures").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM attempts").fetchone()[0] == 1


def test_free_service_status_tracks_outages_exhaustion_recovery_and_staleness(tmp_path, monkeypatch):
    cfg = free_config(tmp_path)
    remote = Service(cfg)
    actual = free_runtime.FreeClient
    monkeypatch.setattr(free_runtime, "FreeClient", lambda config: actual(config, transport=httpx.MockTransport(remote)))
    sensor = runtime.Sensor(cfg)
    try:
        sensor.heartbeat_once()
        assert sensor.status()["cloud_protection"]["state"] == "active"
        remote.failure = "timeout"
        sensor.heartbeat_once()
        assert sensor.heartbeat_error
        assert sensor.status()["cloud_protection"]["state"] == "unavailable"
        remote.failure = None
        for state in ("exhausted", "unavailable", "available"):
            remote.status = state
            sensor.heartbeat_once()
            protection = sensor.status()["cloud_protection"]
            assert protection["state"] == ("active" if state == "available" else state)
            assert not sensor.heartbeat_error
            sensor.capture["tool_input"] = False
            result = sensor.hooks.evaluate(dict(hook_event_name="PreToolUse", session_id="test", tool_name="Bash",
                tool_input={"command": "ls"}), "claude-code")
            assert result["decision"] == "allow" and not result["output"]
            assert sensor.status()["cloud_protection"] == protection
        sensor.cloud_protection["checked_at"] = time.time() - 181
        assert sensor.status()["cloud_protection"]["state"] == "unavailable"
    finally:
        sensor.client.close()
        sensor.hook_clients.close()
        sensor.telemetry.close()
        sensor.spool.close()


@pytest.mark.parametrize("mode", ["free", "api_key", "organization"])
def test_offline_inventory_collects_locally_but_organization_waits_for_heartbeat(tmp_path, monkeypatch, mode):
    from openaidr.sensor import inventory_service, local_posture
    from test_hooks_setup import sensor_config

    monkeypatch.setattr(inventory_service.sys, "platform", "linux")
    cfg = sensor_config(tmp_path) if mode == "organization" else free_config(tmp_path, mode)
    requests = []
    offline = True

    def remote(request):
        requests.append(request.url.path)
        if offline:
            raise httpx.ConnectError("offline", request=request)
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(remote)
    original_http, original_free = httpx.Client, free_runtime.FreeClient
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original_http(**kwargs, transport=transport))
    monkeypatch.setattr(free_runtime, "FreeClient", lambda config: original_free(config, transport=transport))
    stamp = datetime.now(timezone.utc).isoformat()
    native = Mock(return_value=dict(schema_version=1, platform="linux", collected_at=stamp,
        sources=[dict(source="linux-desktop", status="ok")], applications=[dict(source="linux-desktop",
            identifier="cursor", name="Cursor", kind="application", path="/apps/cursor")]))
    components = Mock(return_value=dict(schema_version=1, platform="linux", collected_at=stamp,
        roots=[dict(source="openaidr-cli", root="/cli", scope="user", status="ok", components=[
            dict(key="codex", identifier="npm:@openai/codex", name="Codex", kind="application", path="/cli/codex")])]))
    monkeypatch.setattr(inventory_service, "collect_inventory", native)
    monkeypatch.setattr(inventory_service.component_inventory, "collect_inventory", components)
    sensor = runtime.Sensor(cfg)
    try:
        sensor.heartbeat_once()
        assert sensor.heartbeat_error and sensor.last_heartbeat is None and not sensor.disabled
        sensor.inventory.sync_once()
        sensor.component_inventory.sync_once()
        assert native.call_count == components.call_count == (0 if mode == "organization" else 1)
        assert len(requests) == 1
        if mode == "organization":
            offline = False
            sensor.heartbeat_once()
            sensor.inventory.sync_once()
            sensor.component_inventory.sync_once()
            assert native.call_count == components.call_count == 1
            assert requests[-2:] == ["/ingest/v1/inventory/applications", "/ingest/v1/inventory/snapshots"]
        else:
            cached = local_posture.read(cfg)
            assert cached["groups"]["apps"]["total"] == 2 and cached["collected_at"] == stamp
            assert cached["coverage"]["status"] == "complete" and len(requests) == 1
        for service in (sensor.inventory, sensor.component_inventory):
            service.state["force_refresh"] = True
        sensor.pause_device()
        sensor.inventory.sync_once()
        sensor.component_inventory.sync_once()
        sensor.disabled = False
        stopped = Event()
        stopped.set()
        sensor.inventory.sync_once(stopped)
        sensor.component_inventory.sync_once(stopped)
        assert native.call_count == components.call_count == 1
    finally:
        sensor.client.close()
        sensor.hook_clients.close()
        sensor.telemetry.close()
        sensor.spool.close()


def test_lost_assessment_is_not_replayed_after_restart_and_stale_config_preserves_mode(tmp_path):
    cfg = free_config(tmp_path)
    stale = Config.load(cfg.path)
    remote = Service(cfg, failure="timeout")
    body = dict(request_id=str(uuid4()), product="codex-cli", hook_event="PreToolUse", availability="available",
                actions=[{"kind": "command", "command": {"text": "ls"}}])
    for _ in range(2):
        client = free_runtime.FreeClient(Config.load(cfg.path), transport=httpx.MockTransport(remote))
        try:
            with pytest.raises(ValueError):
                client.check(body, time.monotonic() + 1)
        finally:
            client.close()
    assert len(remote.requests) == 1
    cfg.pop("connection_mode")
    cfg.update(server_url="https://org.example", sensor_id=str(uuid4()), sensor_token="org-secret")
    cfg.save()
    stale["log_level"] = "debug"
    stale.save()
    assert "connection_mode" not in Config.load(cfg.path)
    assert Config.load(cfg.path)["sensor_token"] == "org-secret"


def test_multiple_mapped_actions_are_bounded_and_sent_in_one_assessment(tmp_path):
    cfg = free_config(tmp_path)
    remote = Service(cfg)
    client = free_runtime.FreeClient(cfg, transport=httpx.MockTransport(remote))
    try:
        reply = client.check(dict(request_id=str(uuid4()), product="claude-code", hook_event="PreToolUse",
            availability="available", actions=[{"kind": "command", "command": {"text": "ls"}},
                {"kind": "file.read", "file": {"path": "/tmp/example"}}]), time.monotonic() + 1)
        assert reply["returned_decision"] == "allow"
        sent = json.loads(remote.requests[0].content)["state"]["target_event"]
        assert len(sent["mapped_actions"]) == 2 and len(remote.requests) == 1
    finally:
        client.close()


def test_expired_unavailable_history_cannot_disable_checks_or_replay_unknown_dispatch(tmp_path):
    cfg = free_config(tmp_path)
    remote = Service(cfg)
    client = free_runtime.FreeClient(cfg, transport=httpx.MockTransport(remote))
    unknown = str(uuid4())
    old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
    with client.database() as db:
        db.execute("INSERT INTO attempts VALUES(?,NULL)", (unknown,))
        db.execute("INSERT INTO checks VALUES(?,?,?,?,?,?,?,?)",
                   (unknown, old, "claude-code", "PreToolUse", "unavailable", None, None, 0))
        db.execute("INSERT INTO check_failures VALUES(?,?)", (unknown, "timeout"))
        db.execute("""WITH RECURSIVE rows(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM rows WHERE n<100000)
            INSERT INTO checks SELECT CAST(n AS TEXT),?,'claude-code','PreToolUse','unavailable',NULL,NULL,0 FROM rows""", (old,))
    body = dict(request_id=str(uuid4()), product="claude-code", hook_event="PreToolUse", availability="available",
                actions=[{"kind": "command", "command": {"text": "ls"}}])
    try:
        assert client.check(body, time.monotonic() + 2)["returned_decision"] == "allow"
        assert client.summary(30)["summary"]["completed"] == 1
        with client.database() as db:
            assert db.execute("SELECT count(*) FROM checks").fetchone()[0] == 1
            assert db.execute("SELECT count(*) FROM check_failures").fetchone()[0] == 0
            assert db.execute("SELECT billing FROM attempts WHERE id=?", (unknown,)).fetchone()[0] is None
        with pytest.raises(ValueError, match="already attempted"):
            client.check({**body, "request_id": unknown}, time.monotonic() + 1)
        assert len(remote.requests) == 1
    finally:
        client.close()


@pytest.mark.parametrize("mode", ["free", "api_key"])
def test_free_telemetry_projects_usage_locally_without_remote_exports(tmp_path, mode):
    cfg = free_config(tmp_path, mode)
    telemetry = Telemetry(cfg)
    telemetry.http.close()
    requests = []
    telemetry.http = httpx.Client(transport=httpx.MockTransport(lambda request: requests.append(request)))
    payload = {"resourceLogs": [{"resource": {"attributes": [
        {"key": "service.name", "value": {"stringValue": "claude-code"}}]}, "scopeLogs": [{"logRecords": [{
        "timeUnixNano": str(time.time_ns()), "body": {"stringValue": "claude_code.api_request"}, "attributes": [
            {"key": "event.name", "value": {"stringValue": "api_request"}},
            {"key": "model", "value": {"stringValue": "claude-sonnet-4-5"}},
            {"key": "input_tokens", "value": {"intValue": "100"}},
            {"key": "output_tokens", "value": {"intValue": "25"}}]}]}]}]}
    try:
        telemetry.accept("logs", json.dumps(payload).encode(), "application/json")
        assert telemetry.forward_once()
        assert telemetry.queue.status()["queue_depth"] == 0
        assert telemetry.processed_locally == 1 and telemetry.forwarded == 0
        assert requests == []
        summary = usage.overview(cfg, 1)
        assert summary["summary"]["calls"] == 1
    finally:
        telemetry.close()


@pytest.mark.parametrize("mode", ["free", "api_key"])
def test_switch_to_organization_uses_normal_transport_and_preserves_free_identity(tmp_path, monkeypatch, mode):
    cfg = free_config(tmp_path, mode)
    saved = (tmp_path / "data/free-enrollment.json").read_bytes()
    free_token = cfg["sensor_token"]
    requests = []
    tenant, sensor_id = str(uuid4()), str(uuid4())

    def organization(request):
        requests.append(request)
        assert request.url.host == "organization.example"
        assert free_token not in request.headers.get("authorization", "")
        if request.url.path.endswith("/enroll"):
            return httpx.Response(200, json=dict(sensor_id=sensor_id, sensor_token="organization-token",
                                                 tenant={"id": tenant, "name": "Organization"}))
        assert request.headers["authorization"] == "Bearer organization-token"
        return httpx.Response(200, json={})

    original = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(organization), **kwargs))
    runtime.enroll(cfg, "https://organization.example", "enrollment-token", tenant_id=tenant)
    connected = Config.load(cfg.path)
    assert "connection_mode" not in connected and connected["sensor_id"] == sensor_id
    assert (tmp_path / "data/free-enrollment.json").read_bytes() == saved
    client = runtime.Client.from_config(connected)
    try:
        client.post("heartbeat", {})
    finally:
        client.close()
    assert len(requests) == 2


@pytest.mark.parametrize("mode", ["free", "api_key"])
def test_desktop_free_action_persists_identity_then_installs_service_and_agent_hooks(tmp_path, monkeypatch, mode):
    from openaidr.sensor import bridge
    from test_sensor_free_enrollment import Service as EnrollmentService

    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"))
    cfg.save()
    key = "oasc_" + uuid4().hex + "." + "k" * 43
    tenant = str(uuid4())
    remote = EnrollmentService(cfg) if mode == "free" else Service({"sensor_token": key, "tenant_id": tenant})
    original = httpx.AsyncClient

    def transport(**options):
        options["transport"] = httpx.MockTransport(remote)
        return original(**options)

    monkeypatch.setattr(httpx, "AsyncClient", transport)
    state, operations = {"running": False}, []

    def manage(action, config, **options):
        if action == "status":
            return "running" if state["running"] else "not installed"
        assert action == "install" and options["match_version"] is True
        connected = Config.load(config.path)
        assert connected["connection_mode"] == mode and connected["telemetry"]["local_token"]
        operations.append(action)
        state["running"] = True

    def live(*_):
        if not state["running"]:
            raise ConnectionError("not running")
        return {"version": bridge.app_version(), "connection_mode": mode}

    monkeypatch.setattr(bridge.service, "manage", manage)
    monkeypatch.setattr(bridge.hooks, "local_request", live)
    monkeypatch.setattr(bridge.integrations, "detect", lambda **_: {"codex_available": False, "claude_available": True})
    monkeypatch.setattr(bridge.integrations, "default_path", lambda agent, config=None: tmp_path / (agent + ".json"))
    request = {"action": "free.connect", "config_path": str(cfg.path)}
    if mode == "api_key":
        request.update(action="api-key.connect", params={"api_key": key})
    result = bridge.handle(request)
    assert result["enrolled"] and len(remote.requests) == (2 if mode == "free" else 1)
    assert Config.load(cfg.path)["sensor_token"] not in json.dumps(result)
    setup = bridge.handle({"config_path": str(cfg.path), "action": "desktop.update.setup"})
    assert all(step["ok"] for step in setup["steps"])
    assert setup["connection_mode"] == mode and setup["hooks"]["claude"]["current"]
    assert setup["telemetry"]["claude_current"] and operations == ["install"]
    assert len(remote.requests) == (2 if mode == "free" else 1)


LOCAL_RULES = """
mode: {mode}
rules:
  - id: no-force-delete
    name: Block recursive deletes
    action: deny
    reason: Recursive deletes are blocked on this device
    match: {{kinds: [command], command_regex: "^rm -rf "}}
  - id: ask-secrets
    name: Ask before reading secrets
    action: ask
    match: {{kinds: [file.read], path_glob: "/private/secrets/**"}}
"""


def write_rules(cfg, text):
    (cfg.path.parent / free_runtime.RULES_FILE).write_text(text)


def personal_sensor(tmp_path, monkeypatch, remote):
    actual = free_runtime.FreeClient
    monkeypatch.setattr(free_runtime, "FreeClient", lambda config: actual(config, transport=httpx.MockTransport(remote)))
    return runtime.Sensor(Config.load(remote.cfg.path))


def close(sensor):
    sensor.client.close()
    sensor.hook_clients.close()
    sensor.telemetry.close()
    sensor.spool.close()


def hook(sensor, tool, tool_input):
    return sensor.hooks.evaluate(dict(hook_event_name="PreToolUse", session_id="test-session", tool_name=tool,
                                      tool_input=tool_input), "claude-code")


def assessments(remote):
    return [request for request in remote.requests if request.url.path == "/v1/services/guardrail/assess"]


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_local_rules_decide_personal_checks_and_enforce_returns_them(tmp_path, monkeypatch, mode):
    cfg = free_config(tmp_path)
    write_rules(cfg, LOCAL_RULES.format(mode=mode))
    remote = Service(cfg, score=0)
    sensor = personal_sensor(tmp_path, monkeypatch, remote)
    try:
        sensor.heartbeat_once()
        denied = hook(sensor, "Bash", {"command": "rm -rf /tmp/build"})
        asked = hook(sensor, "Read", {"file_path": "/private/secrets/key"})
        allowed = hook(sensor, "Bash", {"command": "echo hello"})
        assert allowed["decision"] == "allow"
        if mode == "enforce":
            assert denied["decision"] == "deny" and denied["rule_id"] == "no-force-delete"
            assert denied["reason"] == "Recursive deletes are blocked on this device"
            assert asked["decision"] == "ask" and asked["rule_id"] == "ask-secrets"
            # A locally blocked action is not assessed; the ask and the allow are.
            assert len(assessments(remote)) == 2
        else:
            assert denied["decision"] == asked["decision"] == "allow"
            assert len(assessments(remote)) == 3
        summary = sensor.client.post("guardrails/summary", {"days": 1})
        assert summary["mode"] == mode
        assert summary["summary"]["completed"] == 3 and summary["summary"]["deny"] == 1 and summary["summary"]["ask"] == 1
        assert summary["by_mode"][mode] == summary["summary"]
        assert summary["by_mode"]["shadow" if mode == "enforce" else "enforce"]["completed"] == 0
        recent = {row["evaluated_decision"]: row for row in summary["recent"]}
        assert recent["deny"]["mode"] == mode
        assert recent["deny"]["returned_decision"] == ("deny" if mode == "enforce" else "allow")
        assert recent["allow"]["returned_decision"] == "allow"
        from openaidr.sensor import bridge

        def inspect(action, **params):
            return bridge.handle(dict(action="guardrails." + action, config_path=str(cfg.path), params=params))

        page = inspect("denials", decision="ask", days=1, until=summary["until"], cursor="")
        assert [item["mode"] for item in page["items"]] == [mode]
        detail = inspect("check", decision="ask", id=page["items"][0]["id"], scope=page["scope"], review_version=1)
        assert detail["mode"] == mode and detail["returned_decision"] == ("ask" if mode == "enforce" else "allow")
        assert detail["reason"] == "Matched OpenAIDR policy rule Ask before reading secrets"
        assert detail["evidence"]["decision_basis"]["rule_decision"] == {
            "action": "ask", "rule": {"id": "ask-secrets", "name": "Ask before reading secrets"}}
        assert detail["evidence"]["assessment"]["score"] == 0
        assert detail["evidence"]["decision"]["returned_decision"] == detail["returned_decision"]
    finally:
        close(sensor)


def test_local_rule_decisions_survive_cloud_failures_and_invalid_files_fail_open(tmp_path, monkeypatch):
    cfg = free_config(tmp_path)
    write_rules(cfg, LOCAL_RULES.format(mode="enforce"))
    remote = Service(cfg, score=0)
    sensor = personal_sensor(tmp_path, monkeypatch, remote)
    try:
        sensor.heartbeat_once()
        remote.failure = "service"
        asked = hook(sensor, "Read", {"file_path": "/private/secrets/key"})
        assert asked["decision"] == "ask" and asked["rule_id"] == "ask-secrets"
        assert hook(sensor, "Bash", {"command": "echo hello"})["decision"] == "allow"
        summary = sensor.client.summary(1)
        assert summary["summary"]["completed"] == 1 and summary["summary"]["ask"] == 1
        assert summary["summary"]["unavailable"] == 1
        assert {row["failure_reason"] for row in summary["recent"]} == {None, "service_unavailable"}
        detail = sensor.client.post("guardrails/check", dict(
            id=next(row["id"] for row in summary["recent"] if row["evaluated_decision"] == "ask"), decision="ask"))
        assert detail["returned_decision"] == "ask" and detail["evidence"]["assessment"] is None
        assert "assessment_not_retained" in detail["evidence"]["gaps"]
        remote.failure = None
        write_rules(cfg, "mode: enforce\nrules:\n  - id: broken\n    action: deny\n    match: {command_regex: '['}\n")
        assert hook(sensor, "Bash", {"command": "rm -rf /tmp/build"})["decision"] == "allow"
        summary = sensor.client.summary(1)
        assert summary["mode"] == "shadow" and summary["summary"]["unavailable"] == 2
        assert summary["recent"][0]["failure_reason"] == "policy_unavailable"
        assert len(assessments(remote)) == 2
        (cfg.path.parent / free_runtime.RULES_FILE).unlink()
        assert hook(sensor, "Bash", {"command": "rm -rf /tmp/build"})["decision"] == "allow"
        summary = sensor.client.summary(1)
        assert summary["mode"] == "shadow" and summary["summary"]["completed"] == 2
        assert summary["recent"][0]["evaluated_decision"] == "allow" and len(assessments(remote)) == 3
    finally:
        close(sensor)


def test_rules_snapshots_stay_consistent_across_reloads(tmp_path):
    path = tmp_path / free_runtime.RULES_FILE
    path.write_text(LOCAL_RULES.format(mode="enforce"))
    rules = free_runtime.LocalRules(path)
    before = rules.load()
    body = dict(product="claude-code", actions=[{"kind": "command", "command": {"text": "rm -rf /tmp/build"}}])
    assert before.mode == "enforce" and before.decide(body)["rule"]["id"] == "no-force-delete"
    assert rules.load() is before
    path.write_text("mode: shadow\nrules: []\n")
    after = rules.load()
    assert after is not before and after.mode == "shadow" and after.decide(body) == {"action": "allow"}
    # A check holding the earlier reading keeps its mode and rules together.
    assert before.mode == "enforce" and before.decide(body)["action"] == "deny"
    path.write_text("mode: enforce\nrules: [{id: broken, action: deny, match: {command_regex: '['}}]\n")
    broken = rules.load()
    assert broken.error and broken.mode == "shadow" and broken.decide(body) is None
    path.unlink()
    assert rules.load().mode == "shadow" and rules.load().decide(body) == {"action": "allow"}
