"""Session totals remain snapshots through the real receiver and tenant API."""

from datetime import datetime, timezone
import io
import json
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

from fastapi.testclient import TestClient

from openaidr.core.agent_sessions import observations
from openaidr.sensor import antigravity_usage
from openaidr.sensor.telemetry import Telemetry
from openaidr.server.agent_cost_usage import process_pending
from openaidr.server.agent_sessions import overview
from openaidr.server.app import create_app
from openaidr.server.auth import CONSOLE_COOKIE
from test_telemetry_sensor import config
from test_telemetry_server import backend  # noqa: F401


def state(cost=0.25):
    return dict(conversation_id="conversation", conversation_title="PRIVATE-TITLE",
                email="PRIVATE-EMAIL", transcript_path="PRIVATE-PATH",
                model={"id": "not-a-session-model"},
                context_window=dict(total_input_tokens=1000, total_output_tokens=200,
                    current_usage=dict(input_tokens=900, cache_read_input_tokens=800)),
                cost=dict(total_usd=cost, subagent_usd=0.1, estimated=False))


def test_statusline_and_session_reports_preserve_snapshots(tmp_path, backend):
    st, server_cfg, sensor, bearer, other, other_bearer, _ = backend
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    stop = threading.Event()
    worker = threading.Thread(target=telemetry.receive, args=(stop,))
    worker.start()
    try:
        deadline = time.monotonic() + 3
        while telemetry.bound_address is None:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        cfg["telemetry"].pop("local_token")
        cfg["telemetry"]["listen"] = f"127.0.0.1:{telemetry.bound_address[1]}"
        cfg.save()
        command = [sys.executable, "-m", "openaidr.sensor.cli", "telemetry", "antigravity-statusline", "--config", str(cfg.path)]
        result = subprocess.run(command, input=json.dumps(state()), text=True, capture_output=True, timeout=5)
        assert (result.returncode, result.stdout, result.stderr) == (0, "", "")
        first = telemetry.queue.next()
        assert first is not None
        assert "PRIVATE-" not in first["body"].decode()
        antigravity_usage.submit(cfg.path, io.StringIO(json.dumps(state())))
        assert telemetry.queue.status()["queue_depth"] == 1
        # A correction can reduce totals. Missing cost must remain unknown.
        antigravity_usage.submit(cfg.path, io.StringIO(json.dumps(state(0.15))))
        telemetry.accept("logs", first["body"], first["content_type"])
        local = antigravity_usage.overview(cfg)
        assert len(local["items"]) == 1
        assert local["items"][0]["estimated_cost_usd"] == "0.15"
        assert local["items"][0]["input_tokens"] == 1000
        assert telemetry.queue.db.execute("SELECT count(*) FROM usage_calls").fetchone()[0] == 0
        server_cfg.set_services("ingest,api")
        with TestClient(create_app(server_cfg, st)) as client:
            while batch := telemetry.queue.next():
                for token, code in ((other_bearer, 403), (bearer, 200), (bearer, 200)):
                    response = client.post("/otlp/v1/logs", content=batch["body"], headers={
                        "Authorization": "Bearer " + token, "Content-Type": batch["content_type"],
                    })
                    assert response.status_code == code, response.text
                telemetry.queue.confirm(batch["batch_id"])
            assert process_pending(st)["failed"] == 0
            assert overview(st, sensor["tenant_id"])["items"][0]["estimated_cost_usd"] == "0.15"
            assert overview(st, other["tenant_id"])["items"] == []
            assert st.scalar("SELECT count(*) FROM agent_cost_records") == 0
            assert client.get("/api/v1/costs/agent-sessions").status_code == 401
            user = st.create_user(sensor["tenant_id"], "analyst@example.com", "Analyst", "unused", "analyst")
            client.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], sensor["tenant_id"]))
            assert client.get("/api/v1/costs/agent-sessions").status_code == 403
            owner = st.create_user(sensor["tenant_id"], "owner@example.com", "Owner", "unused", "owner")
            client.cookies.set(CONSOLE_COOKIE, st.create_session(owner["id"], sensor["tenant_id"]))
            report = client.get("/api/v1/costs/agent-sessions")
            assert report.status_code == 200, report.text
            assert report.json()["cost_kind"] == "list_price_estimate"
            assert report.json()["items"][0]["output_tokens"] == 200
            foreign = st.create_user(other["tenant_id"], "other@example.com", "Other", "unused", "owner")
            client.cookies.set(CONSOLE_COOKIE, st.create_session(foreign["id"], other["tenant_id"]))
            assert client.get("/api/v1/costs/agent-sessions").status_code == 403
        cfg["telemetry"]["disabled_agents"] = ["antigravity"]
        cfg.save()
        antigravity_usage.submit(cfg.path, io.StringIO(json.dumps(state(9))))
        assert telemetry.queue.status()["queue_depth"] == 0
        # Reports survive raw export delivery and a sensor restart.
        telemetry.queue.close()
        assert antigravity_usage.overview(cfg)["items"][0]["estimated_cost_usd"] == "0.15"
    finally:
        stop.set()
        worker.join(timeout=3)
        telemetry.close()


def test_missing_zero_invalid_and_expired_session_data(tmp_path):
    db = sqlite3.connect(":memory:")
    antigravity_usage.initialize(db)
    received = datetime.now(timezone.utc)
    for value, expected in ((0, "0"), (None, None), (-1, None), (True, None), ("NaN", None)):
        body = antigravity_usage.payload(state(value))
        event, = observations(dict(payload=body, received_at=received))
        assert event["estimated_cost_usd"] == expected
        antigravity_usage.record(db, "one", dict(payload=body, received_at=received))
    assert db.execute("SELECT count(*) FROM usage_sessions").fetchone()[0] == 1
    body["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["timeUnixNano"] = "1"
    assert list(observations(dict(payload=body, received_at=received))) == []
    db.execute("UPDATE usage_sessions SET observation_ns=1")
    antigravity_usage.prune(db)
    assert db.execute("SELECT count(*) FROM usage_sessions").fetchone()[0] == 0
    db.close()
    cfg = config(tmp_path, listen="127.0.0.1:1", local_token="local")
    for raw in (json.dumps(state()), "not-json", "x" * 65537, "[]"):
        antigravity_usage.submit(cfg.path, io.StringIO(raw))


def test_local_sessions_keep_latest_snapshot_across_enrollments(tmp_path):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        packet = antigravity_usage.payload(state())
        telemetry.accept("logs", json.dumps(packet).encode(), "application/json")
        with telemetry.queue.db:
            telemetry.queue.db.execute("INSERT INTO usage_sessions SELECT 'former-enrollment',session_id,"
                "observation_ns+1,input_tokens,output_tokens,'0.15' FROM usage_sessions")
        cfg.update(tenant_id="another-tenant", sensor_id="another-sensor")
        report = antigravity_usage.overview(cfg)
        assert len(report["items"]) == 1
        assert report["items"][0]["estimated_cost_usd"] == "0.15"
        cfg["data_dir"] = str(Path(cfg["data_dir"]) / "separate-profile")
        assert antigravity_usage.overview(cfg)["items"] == []
    finally:
        telemetry.close()
