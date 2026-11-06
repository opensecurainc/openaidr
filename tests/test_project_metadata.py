import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from openaidr.core.protocol import default_sensor_config
from openaidr.sensor import usage
from openaidr.sensor.capture import CaptureCoordinator
from openaidr.sensor.config import Config
from openaidr.sensor.project_metadata import Recovery
from openaidr.sensor.telemetry import ExportQueue


def setup_recovery(tmp_path, monkeypatch):
    from openaidr.sensor import integrations

    config = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                    server_url="https://tenant.example", sensor_id="device", tenant_id="tenant")
    capture = default_sensor_config()["capture"]
    monkeypatch.setattr(integrations, "configured_paths", lambda config, agent: [tmp_path / agent / "settings"])
    recovery = Recovery(config, lambda: capture, CaptureCoordinator(config))
    return recovery, capture


def request(recovery, sid="session", product="codex-cli"):
    report = recovery.report()
    recovery.accept(report, {"version": 1, "requests": [{"product": product, "session_id": sid}]})


def drain(recovery):
    for _ in range(1000):
        recovery.step()
        if not recovery.requests and recovery.reader is None:
            return
    raise AssertionError("Recovery did not finish")


def codex_file(tmp_path, records):
    path = tmp_path / "codex/sessions/2026/10/10/rollout-date-session.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in records))
    return path


def metadata(when, cwd="/work/first", sid="session", **extra):
    return dict(type="session_meta", timestamp=when.isoformat(), payload=dict(id=sid, cwd=cwd, **extra))


@pytest.mark.parametrize("connection_field", ["server_url", "tenant_id", "sensor_id"])
def test_recovery_incremental_restart_privacy_and_retry(tmp_path, monkeypatch, connection_field):
    recovery, capture = setup_recovery(tmp_path, monkeypatch)
    when = datetime.now(timezone.utc) - timedelta(days=1)
    queue = ExportQueue(Path(recovery.config["data_dir"]) / "telemetry.sqlite3", usage_scope=usage.identity(recovery.config))
    with queue.db:
        queue.db.execute("INSERT INTO usage_calls VALUES (?,?,?,?,?,?,?)",
                         (queue.usage_scope, "local", when.timestamp(), "model", "unknown", 1200, .1))
    queue.close()
    totals = usage.overview(recovery.config, 30)["summary"]
    path = codex_file(tmp_path, [
        metadata(when, source={"subagent": {"thread_spawn": {"parent_thread_id": "parent"}}}),
        {"type": "turn_context", "timestamp": (when - timedelta(hours=1)).isoformat(), "payload": {"cwd": "/forked/history"}},
        {"type": "response_item", "timestamp": when.isoformat(), "payload": {"text": "PRIVATE PROMPT", "cwd": "/not-metadata"}},
        {"type": "turn_context", "timestamp": (when + timedelta(minutes=1)).isoformat(), "payload": {"cwd": "/work/second"}},
    ])
    request(recovery)
    drain(recovery)
    report = recovery.report()
    assert [(row["cwd"], row["parent_id"]) for row in report["observations"]] == [
        ("/work/first", "parent"), ("/work/second", "parent"),
    ]
    assert "PRIVATE" not in json.dumps(report)
    recovery.accept(report, {})  # Older server or missing acknowledgement keeps work.
    assert recovery.report()["observations"] == report["observations"]
    report = recovery.report()
    # A worker can finish another observation while the heartbeat is in flight.
    recovery.observations.append(dict(report["observations"][-1], time=(when + timedelta(minutes=2)).isoformat()))
    recovery.accept(report, {"version": 1, "requests": []})
    assert len(recovery.observations) == 1
    report = recovery.report()
    recovery.accept(report, {"version": 1, "requests": []})
    with path.open("a") as stream:
        stream.write(json.dumps({"type": "turn_context", "timestamp": (when + timedelta(minutes=3)).isoformat(), "payload": {"cwd": "/work/third"}}))
    # A previously requested file stays current without another backend request.
    drain(recovery)
    assert recovery.report()["observations"] == []
    with path.open("a") as stream:
        stream.write("\n")
    drain(recovery)
    assert [row["cwd"] for row in recovery.report()["observations"]] == ["/work/third"]
    restarted = Recovery(recovery.config, lambda: capture, recovery.coordinator)
    request(restarted)
    drain(restarted)
    assert len(restarted.report()["observations"]) == 3
    # Re-enrollment must not forward a previous backend's pending recovery.
    restarted.requests.append({"product": "codex-cli", "session_id": "pending"})
    restarted.after = ["codex-cli", "session"]
    reader = restarted.reader = path.open("rb")
    old_scope = restarted.scope
    restarted.config[connection_field] = "https://new.example" if connection_field == "server_url" else "replacement"
    assert restarted.report() is None
    assert restarted.scope != old_scope
    assert not restarted.requests and not restarted.observations and not restarted.checkpoints and not restarted.after
    assert restarted.reader is None and reader.closed and restarted.inflight is None
    assert restarted.report()["observations"] == []
    assert usage.overview(restarted.config, 30)["summary"] == totals


def test_recovery_capture_disabled_redaction_managed_and_unrequested_files(tmp_path, monkeypatch):
    recovery, capture = setup_recovery(tmp_path, monkeypatch)
    when = datetime.now(timezone.utc) - timedelta(days=1)
    codex_file(tmp_path, [metadata(when)])
    capture["tool_input"] = False
    assert recovery.report() is None
    recovery.step()
    assert not recovery.checkpoints
    capture["tool_input"] = True
    request(recovery, "../session")
    assert not recovery.requests
    request(recovery, "missing")
    drain(recovery)
    assert not recovery.checkpoints
    request(recovery)
    drain(recovery)
    capture["tool_input"] = False
    assert recovery.report() is None
    assert not recovery.observations and not recovery.checkpoints
    capture["tool_input"] = True
    codex_file(tmp_path, [metadata(when, "/work/password=hunter22")])
    request(recovery)
    drain(recovery)
    rows = recovery.report()["observations"]
    assert len(rows) == 1 and rows[0]["cwd"] is None
    assert "hunter22" not in json.dumps(rows)
    codex_file(tmp_path, [metadata(when, source={"subagent": {"thread_spawn": {"parent_thread_id": "managed-parent"}}})])
    launch = recovery.coordinator.begin("codex-cli", capture, str(uuid4()))
    assert not recovery.coordinator.project_metadata_allowed("codex-cli", "session")
    with recovery.coordinator._db() as conn:
        conn.execute("INSERT INTO ordinary_sessions VALUES ('codex-cli','session')")
    assert recovery.coordinator.project_metadata_allowed("codex-cli", "session")
    with recovery.coordinator._db() as conn:
        conn.execute("UPDATE launches SET native_id='managed-parent' WHERE id=?", (launch.id,))
    assert not recovery.coordinator.project_metadata_allowed("codex-cli", "session", "managed-parent")
    launch._unlock()
    recovery.checkpoints.clear()
    request(recovery)
    drain(recovery)
    assert recovery.report()["observations"] == []


def test_claude_metadata_only_and_bounded_source_reads(tmp_path, monkeypatch):
    from openaidr.sensor import project_metadata

    recovery, _ = setup_recovery(tmp_path, monkeypatch)
    when = datetime.now(timezone.utc) - timedelta(days=1)
    path = tmp_path / "claude/projects/project/session.jsonl"
    path.parent.mkdir(parents=True)
    row = dict(type="assistant", sessionId="session", timestamp=when.isoformat(), cwd="C:\\work\\project", message={"content": "PRIVATE RESPONSE"})
    path.write_text("x" * 600 + "\n" + json.dumps(dict(row, sessionId="other")) + "\n" + json.dumps(row) + "\n")
    monkeypatch.setattr(project_metadata, "LINE_BYTES", 256)
    monkeypatch.setattr(project_metadata, "READ_BYTES", 512)
    request(recovery, product="claude-code")
    recovery.step()
    assert recovery.reader is not None  # A large record yields to the next tick.
    drain(recovery)
    rows = recovery.report()["observations"]
    assert len(rows) == 1 and rows[0]["cwd"] == "C:\\work\\project"
    assert "PRIVATE" not in json.dumps(rows)
