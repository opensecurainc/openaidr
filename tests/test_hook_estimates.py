"""Hook text accounting stays partial, private and separate from measured usage."""

import copy
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import threading
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from openaidr.core import hook_estimates as core
from openaidr.sensor import hook_estimates, usage
from openaidr.sensor.runtime import Sensor
from openaidr.sensor.telemetry import Telemetry
from openaidr.server.agent_cost_usage import process_pending
from openaidr.server.app import create_app
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server.hook_estimates import overview as server_overview
from test_local_usage import body, event as native_event
from test_telemetry_sensor import config
from test_telemetry_server import backend  # noqa: F401


CAPTURE = dict(prompt_text=True, response_text=True, tool_input=True, tool_output=True, redact=True, max_text_bytes=16384)


def event(kind="prompt", product="cursor", model="claude-sonnet-4-6", **extra):
    return dict(id=str(uuid4()), time=datetime.now(timezone.utc).isoformat(), kind=kind,
                agent=dict(product=product, model=model), session={"id": "session"},
                source={"collector": "hook"}, text="x" * 400, **extra)


@pytest.mark.parametrize("kind,extra,incoming,outgoing", [
    ("prompt", {}, 100, 0), ("response", {}, 0, 100),
    ("tool.result", {"tool": {"output": "界" * 4}}, 3, 0),
    ("command", {"tool": {"input": "12345"}}, 0, 2),
    ("command", {"tool": {"input": {"x": "abc"}}}, 0, 3),
])
def test_estimator_directions_and_versioned_wire(kind, extra, incoming, outgoing):
    item = core.estimate(event(kind, **extra))
    wire = core.payload([item])
    observed, = core.observations(dict(payload=wire, received_at=datetime.now(timezone.utc)))
    assert (observed["estimated_input_tokens"], observed["estimated_output_tokens"]) == (incoming, outgoing)
    assert observed["estimated_cost_usd"] == (Decimal(3) * incoming + Decimal(15) * outgoing) / 1_000_000
    assert "xxxx" not in json.dumps(wire)
    for invalid in ("NaN", "-1", "1.5", "16385", "secret-text"):
        bad = copy.deepcopy(wire)
        attrs = bad["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"]
        next(a for a in attrs if a["key"] == "estimate.input_tokens")["value"] = {"stringValue": invalid}
        assert list(core.observations(dict(payload=bad, received_at=datetime.now(timezone.utc)))) == []


def test_local_privacy_optouts_replays_and_native_usage(tmp_path):
    cfg = config(tmp_path, hook_estimates={"assumed_models": {"github-copilot": "claude-sonnet-4-6"}})
    capture = dict(CAPTURE)
    telemetry = Telemetry(cfg, capture=lambda: capture)
    first = event("command", tool={"input": "x" * 400})
    first["source"]["hook_request_id"] = "same-native-tool-call"
    mapped = dict(first, id=str(uuid4()), kind="file")
    copilot = event(product="github-copilot", model="")
    auto = event(model="auto")
    secret = event()
    secret["text"] = "api_key=sk-test-private-value"
    try:
        telemetry.estimate_hooks([first, mapped, copilot, auto, secret])
        report = hook_estimates.overview(cfg)
        assert report["summary"]["observations"] == 4
        assert report["summary"]["priced_observations"] == 3
        assert report["summary"]["assumed_model_observations"] == 1
        telemetry.estimate_hooks([first, mapped, copilot, auto, secret])
        assert telemetry.queue.status()["queue_depth"] == 1
        assert hook_estimates.overview(cfg)["summary"] == report["summary"]
        exported = []
        while batch := telemetry.queue.next():
            exported.append(batch["body"].decode())
            telemetry.queue.confirm(batch["batch_id"])
        assert "sk-test-private-value" not in "".join(exported)
        assert usage.overview(cfg, 30)["summary"]["calls"] == 0
        telemetry.accept("logs", body(datetime.now(timezone.utc), native_event("measured")), "application/json")
        assert usage.overview(cfg, 30)["summary"]["tokens"] == 1200
        assert hook_estimates.overview(cfg)["summary"] == report["summary"]
        for option in ("prompt_text", "response_text", "tool_input", "tool_output"):
            capture[option] = False
        telemetry.estimate_hooks([event(), event("response"), event("command", tool={"input": "private"}),
                                  event("tool.result", tool={"output": "private"})])
        assert hook_estimates.overview(cfg)["summary"] == report["summary"]
        capture.update(CAPTURE)
        for disabled in (["cursor", "copilot"], ["cursor", "github-copilot"]):
            cfg["telemetry"]["disabled_agents"] = disabled
            telemetry.estimate_hooks([event(), event(product="github-copilot")])
        cfg["telemetry"]["disabled_agents"] = []
        cfg["telemetry"]["hook_estimates"]["enabled"] = False
        telemetry.estimate_hooks([event()])
        cfg["telemetry"]["hook_estimates"]["enabled"] = True
        managed = event()
        managed["session"]["registration_id"] = "verified-launch"
        telemetry.estimate_hooks([event(evidence={"version": 1}), managed, event(model="auto")])
        # The ordinary Auto observation is accepted, but the managed one is not.
        assert hook_estimates.overview(cfg)["summary"]["observations"] == 5
        telemetry.paused = lambda: True
        telemetry.estimate_hooks([event()])
        assert hook_estimates.overview(cfg)["summary"]["observations"] == 5
        cfg["tenant_id"] = "different-enrollment"
        assert hook_estimates.overview(cfg)["summary"]["observations"] == 5
        cfg.pop("tenant_id")
    finally:
        telemetry.close()
    assert hook_estimates.overview(cfg)["summary"]["observations"] == 5


def test_background_shipping_estimates_real_hook_events(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    cfg["inventory"] = {"enabled": False}
    sensor = Sensor(cfg)
    sensor.capture.update(CAPTURE)
    sensor.server_config["flush_interval_s"] = .01
    stop = threading.Event()
    sent = []

    def post(path, payload):
        sent.extend(payload["events"])
        stop.set()
        return {"accepted": len(payload["events"])}

    monkeypatch.setattr(sensor.client, "post", post)
    try:
        sensor.hooks.evaluate(dict(hook_event_name="beforeSubmitPrompt", conversation_id="cursor-session",
                                   prompt="x" * 400, model="claude-sonnet-4-6"), "cursor")
        assert sensor.spool.depth > 0, (sensor.disabled, sensor.hooks.emit_actions, sensor.capture)
        assert hook_estimates.overview(cfg)["summary"]["observations"] == 0
        worker = threading.Thread(target=sensor.ship_loop, args=(stop,))
        worker.start()
        worker.join(5)
        assert not worker.is_alive()
        assert any(item["kind"] == "prompt" for item in sent)
        assert hook_estimates.overview(cfg)["summary"]["estimated_input_tokens"] == 100
        monkeypatch.setattr(hook_estimates, "collect", lambda *_: (_ for _ in ()).throw(RuntimeError("test")))
        sensor.telemetry.estimate_hooks([event()])  # Failure cannot escape into delivery.
    finally:
        stop.set()
        sensor.hook_clients.close()
        sensor.client.close()
        sensor.telemetry.close()
        sensor.spool.close()


def test_server_projection_replay_and_tenant_permissions(tmp_path, backend):
    st, server_cfg, sensor, bearer, other, other_bearer, _ = backend
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg, capture=lambda: CAPTURE)
    server_cfg.set_services("ingest,api")
    try:
        telemetry.estimate_hooks([event(), event("response"), event(product="github-copilot", model="")])
        with TestClient(create_app(server_cfg, st)) as client:
            while batch := telemetry.queue.next():
                for credential, expected in ((other_bearer, 403), (bearer, 200), (bearer, 200)):
                    result = client.post("/otlp/v1/logs", content=batch["body"], headers={
                        "Authorization": "Bearer " + credential, "Content-Type": batch["content_type"],
                    })
                    assert result.status_code == expected, result.text
                telemetry.queue.confirm(batch["batch_id"])
            assert process_pending(st)["failed"] == 0
            assert server_overview(st, sensor["tenant_id"])["summary"] == hook_estimates.overview(cfg)["summary"]
            assert server_overview(st, other["tenant_id"])["items"] == []
            assert st.scalar("SELECT count(*) FROM agent_cost_records") == 0
            assert client.get("/api/v1/costs/hook-estimates").status_code == 401
            for role, expected in (("analyst", 403), ("owner", 200)):
                user = st.create_user(sensor["tenant_id"], role + "@example.com", role, "unused", role)
                client.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], sensor["tenant_id"]))
                result = client.get("/api/v1/costs/hook-estimates")
                assert result.status_code == expected, result.text
            assert client.get("/api/v1/costs/hook-estimates?range=90d").status_code == 400
            assert client.get("/api/v1/costs/hook-estimates?range=30d").json()["summary"]["observations"] == 3
    finally:
        telemetry.close()


def test_unknown_models_and_expiry(tmp_path):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        stale = event()
        stale["time"] = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
        telemetry.estimate_hooks([stale, event(model="auto"), event(model="unlisted"), event(product="claude-code")])
        report = hook_estimates.overview(cfg)
        assert report["summary"]["observations"] == 2
        assert report["summary"]["estimated_cost_usd"] is None
        assert report["summary"]["estimated_tokens"] == 200
        with telemetry.queue.db:
            telemetry.queue.db.execute("UPDATE hook_estimates SET observed_at=1")
            hook_estimates.prune(telemetry.queue.db)
        assert hook_estimates.overview(cfg)["items"] == []
    finally:
        telemetry.close()


def test_desktop_snapshot_refresh_and_identity(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    telemetry, reader = Telemetry(cfg), usage.UsageReader()
    ticks = [0]
    monkeypatch.setattr(usage.time, "monotonic", lambda: ticks[0])
    try:
        telemetry.estimate_hooks([event()])
        result = usage.overview(cfg, 30, reader)
        assert result["summary"]["calls"] == 0
        assert result["hook_estimates"]["summary"]["observations"] == 1
        telemetry.estimate_hooks([event()])
        assert usage.overview(cfg, 30, reader)["hook_estimates"] == result["hook_estimates"]
        ticks[0] = 31
        assert usage.overview(cfg, 30, reader)["hook_estimates"]["summary"]["observations"] == 2
        with telemetry.queue.db:
            telemetry.queue.db.execute("INSERT INTO hook_estimates SELECT 'former-enrollment',application,observation_id,"
                "observed_at,model,model_source,estimated_input_tokens,estimated_output_tokens,estimated_cost_usd,modified "
                "FROM hook_estimates")
            telemetry.queue.db.execute("DELETE FROM hook_estimates WHERE scope=? AND rowid=(SELECT min(rowid) FROM hook_estimates)",
                                       (telemetry.queue.usage_scope,))
        ticks[0] = 62
        cfg["tenant_id"] = "new-enrollment"
        assert usage.overview(cfg, 30, reader)["hook_estimates"]["summary"]["observations"] == 2
    finally:
        reader.close()
        telemetry.close()


@pytest.mark.parametrize("malformed", [False, True])
def test_empty_or_failed_hook_reads_preserve_live_native_usage(tmp_path, monkeypatch, malformed):
    cfg = config(tmp_path)
    telemetry, reader = Telemetry(cfg), usage.UsageReader()
    ticks = [0]
    monkeypatch.setattr(usage.time, "monotonic", lambda: ticks[0])
    try:
        telemetry.accept("logs", body(datetime.now(timezone.utc), native_event("first")), "application/json")
        if malformed:
            with telemetry.queue.db:
                telemetry.queue.db.execute("DROP TABLE hook_estimates")
                telemetry.queue.db.execute("CREATE TABLE hook_estimates(scope TEXT)")
        report = usage.overview(cfg, 30, reader)
        assert report["summary"]["tokens"] == 1200
        assert "hook_estimates" not in report
        if malformed:
            with telemetry.queue.db:
                telemetry.queue.db.execute("DROP TABLE hook_estimates")
                hook_estimates.initialize(telemetry.queue.db)
        telemetry.estimate_hooks([event()])
        telemetry.accept("logs", body(datetime.now(timezone.utc), native_event("second")), "application/json")
        # Empty and failed estimates stay cached while native usage remains live.
        report = usage.overview(cfg, 30, reader)
        assert report["summary"]["tokens"] == 2400
        assert "hook_estimates" not in report
        ticks[0] = 31
        assert usage.overview(cfg, 30, reader)["hook_estimates"]["summary"]["observations"] == 1
    finally:
        reader.close()
        telemetry.close()
