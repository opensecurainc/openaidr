"""Enrollment must reach a real HTTP transport without an empty bearer header."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from openaidr.core.protocol import default_sensor_config
from openaidr.sensor.config import Config
from openaidr.sensor.runtime import enroll


def test_enrollment_sends_token_in_body_without_empty_authorization(tmp_path):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            received.append(
                (
                    self.path,
                    self.headers.get("Authorization"),
                    json.loads(self.rfile.read(int(self.headers["Content-Length"]))),
                )
            )
            body = json.dumps(
                {
                    "sensor_id": "sensor-id",
                    "sensor_token": "issued-token",
                    "tenant": {"id": "11111111-1111-4111-8111-111111111111", "name": "Fixture"},
                    "config": default_sensor_config(),
                    "policy": {"version": 1, "rules": [{"action": "deny", "match": {"command_regex": "["}}]},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"))
    try:
        result = enroll(
            cfg, f"http://127.0.0.1:{server.server_port}", "enrollment-secret"
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert result["sensor_id"] == "sensor-id"
    assert result["policy_version"] == 1 and "policy" not in result
    assert not (tmp_path / "data/policy.json").exists()
    assert json.loads((tmp_path / "data/server-config.json").read_text())["capture"]["redact"]
    assert received[0][0] == "/ingest/v1/enroll"
    assert received[0][1] is None
    assert received[0][2]["enrollment_token"] == "enrollment-secret"
    assert received[0][2]["policy_delivery"] == "backend"
    assert "policy_actions" not in received[0][2]
    assert Config.load(cfg.path)["sensor_token"] == "issued-token"
    assert Config.load(cfg.path)["tenant_id"] == "11111111-1111-4111-8111-111111111111"


def enrolled_config(tmp_path):
    cfg = Config(
        tmp_path / "sensor.yaml",
        data_dir=str(tmp_path / "data"),
        server_url="https://original.example",
        sensor_id="old-sensor",
        sensor_token="old-token",
    )
    cfg.save()
    cache = tmp_path / "data/policy.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text('{"version": 1, "rules": [{"action": "deny"}]}')
    return cfg


def offline(*_):
    raise OSError("sensor is not running")


def test_reenrollment_rejects_running_service_before_remote_request(
    tmp_path, monkeypatch
):
    import pytest
    from openaidr.sensor import runtime

    cfg = enrolled_config(tmp_path)
    before = cfg.path.read_bytes()
    monkeypatch.setattr(
        runtime.hooks, "local_request", lambda *_: {"sensor_id": "old-sensor"}
    )
    monkeypatch.setattr(
        runtime.Client, "post", lambda *_: pytest.fail("must not contact new tenant")
    )
    with pytest.raises(ValueError, match="Stop the current sensor service"):
        runtime.enroll(cfg, "https://new.example", "new-enrollment")
    assert cfg.path.read_bytes() == before
    assert json.loads((tmp_path / "data/policy.json").read_text())["rules"] == [{"action": "deny"}]


def test_reenrollment_rejects_native_queue_without_modifying_identity_or_data(
    tmp_path, monkeypatch
):
    import pytest
    from openaidr.sensor import runtime
    from openaidr.sensor.telemetry import ExportQueue

    cfg = enrolled_config(tmp_path)
    queue = ExportQueue(tmp_path / "data/telemetry.sqlite3")
    batch_id = queue.append("logs", b"{}", "application/json", 1)
    queue.close()
    before = cfg.path.read_bytes()
    monkeypatch.setattr(runtime.hooks, "local_request", offline)
    monkeypatch.setattr(
        runtime.Client, "post", lambda *_: pytest.fail("must not contact new tenant")
    )
    with pytest.raises(ValueError, match="pending telemetry exports"):
        runtime.enroll(cfg, "https://new.example", "new-enrollment")
    assert cfg.path.read_bytes() == before
    queue = ExportQueue(tmp_path / "data/telemetry.sqlite3")
    assert queue.next()["batch_id"] == batch_id
    queue.close()


def test_reenrollment_rejects_pending_legacy_spool(tmp_path, monkeypatch):
    import pytest
    from openaidr.sensor import runtime
    from openaidr.sensor.spool import Spool

    cfg = enrolled_config(tmp_path)
    spool = Spool(tmp_path / "data/spool")
    spool.append({"id": "old-tenant-event"})
    spool.close()
    monkeypatch.setattr(runtime.hooks, "local_request", offline)
    with pytest.raises(ValueError, match="pending legacy events"):
        runtime.enroll(cfg, "https://new.example", "new-enrollment")
    spool = Spool(tmp_path / "data/spool")
    assert spool.read()["events"] == [{"id": "old-tenant-event"}]
    spool.close()


def test_empty_offline_sensor_can_reenroll(tmp_path, monkeypatch):
    from openaidr.sensor import runtime
    from openaidr.sensor.telemetry import ExportQueue
    from openaidr.sensor.spool import Spool

    cfg = enrolled_config(tmp_path)
    queue = ExportQueue(tmp_path / "data/telemetry.sqlite3")
    batch_id = queue.append("logs", b"{}", "application/json", 1)
    queue.confirm(batch_id)
    queue.close()
    spool = Spool(tmp_path / "data/spool")
    spool.append({"id": "already-delivered"})
    spool.ack(spool.read())
    spool.close()
    monkeypatch.setattr(runtime.hooks, "local_request", offline)
    monkeypatch.setattr(
        runtime.Client,
        "post",
        lambda *_: {
            "sensor_id": "new-sensor",
            "sensor_token": "new-token",
            "config": default_sensor_config(),
            "policy": {},
        },
    )
    runtime.enroll(cfg, "https://new.example", "new-enrollment")
    loaded = Config.load(cfg.path)
    assert loaded["server_url"] == "https://new.example"
    assert loaded["sensor_id"] == "new-sensor"
    assert loaded["sensor_token"] == "new-token"
    assert not (tmp_path / "data/policy.json").exists()
