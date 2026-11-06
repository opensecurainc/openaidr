"""Enrollment link parsing and the desktop bridge over a real HTTP transport."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from openaidr.core.enrollment import make_enrollment_link, parse_enrollment_link
from openaidr.sensor import bridge
from openaidr.sensor.config import Config

CODE = "oaet_" + "a" * 43
TENANT = "01000000-0000-7000-8000-000000000001"


@pytest.mark.parametrize(
    "server",
    [
        "https://tenant.example",
        "https://[::1]:8443",
        "http://localhost:8080",
        "http://127.0.0.1:8123",
    ],
)
def test_link_origin_and_code_round_trip(server):
    assert parse_enrollment_link(make_enrollment_link(server, CODE)) == (server, CODE)


@pytest.mark.parametrize(
    "link",
    [
        None,
        "",
        "x" * 8193,
        f"file:///enroll#token={CODE}",
        f"http://remote.example/enroll#token={CODE}",
        f"https://user:pass@tenant.example/enroll#token={CODE}",
        f"https://tenant.example/elsewhere#token={CODE}",
        f"https://tenant.example/enroll?token={CODE}",
        f"https://tenant.example/enroll?#token={CODE}",
        f"https://tenant.example/enroll#token={CODE}&token={CODE}",
        f"https://tenant.example/enroll#token={CODE}&ca_cert=/tmp/root.pem",
        f"https://tenant.example\\evil/enroll#token={CODE}",
        f"https://tenant.example:bad/enroll#token={CODE}",
        f"https://tenant.\nexample/enroll#token={CODE}",
        "https://tenant.example/enroll#token=incorrect",
    ],
)
def test_invalid_links_never_echo_the_secret(link):
    with pytest.raises(ValueError) as error:
        parse_enrollment_link(link)
    assert CODE not in str(error.value)


@pytest.mark.parametrize("existing", [False, True])
def test_bridge_previews_without_writes_then_enrolls_and_applies_config(tmp_path, monkeypatch, existing):
    received = []
    mode = {"auth_mode": "bearer", "tenant_id": TENANT, "response_tenant": TENANT}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append((self.path, payload, self.headers.get("Authorization")))
            tenant = {"id": mode["tenant_id"], "name": "Organization"}
            if self.path.endswith("enrollment/preview"):
                response = {
                    "tenant": tenant,
                    "auth_mode": mode["auth_mode"],
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            else:
                tenant["id"] = mode["response_tenant"]
                response = {
                    "tenant": tenant,
                    "sensor_id": "sensor-1",
                    "sensor_token": "device-only-secret",
                    "config": {"heartbeat_interval_s": 60},
                    "policy": {"version": 2, "rules": []},
                }
            data = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"))
    service = {"running": existing, "calls": []}
    if existing:
        cfg.update(server_url="https://old.example", sensor_id="old-device", sensor_token="old-token")

    def manage(action, config, **_):
        if action == "status":
            return "running" if service["running"] else "stopped"
        service["calls"].append(action)
        service["running"] = action == "start"

    def local_status(*_):
        if not service["running"]:
            raise OSError("not running")
        saved = Config.load(cfg.path)
        return dict(sensor_id=saved["sensor_id"], server_url=saved["server_url"],
                    version="0.1.0", queue_depth=0, telemetry={"queue_depth": 0})

    monkeypatch.setattr(bridge.service, "manage", manage)
    monkeypatch.setattr(bridge.service, "stop_and_wait", lambda config: manage("stop", config))
    monkeypatch.setattr(bridge.hooks, "local_request", local_status)
    cfg.save()
    before = cfg.path.read_bytes()
    link = make_enrollment_link(f"http://127.0.0.1:{server.server_port}", CODE)
    request = {"config_path": str(cfg.path), "params": {"link": link}}
    try:
        preview = bridge.handle(dict(request, action="enrollment.preview"))
        assert preview["tenant"]["id"] == TENANT
        assert CODE not in json.dumps(preview)
        assert cfg.path.read_bytes() == before
        assert not (tmp_path / "data/server-config.json").exists()
        request["params"]["tenant_id"] = "02000000-0000-7000-8000-000000000001"
        with pytest.raises(ValueError, match="organization changed"):
            bridge.handle(dict(request, action="enrollment.connect"))
        assert all(path.endswith("preview") for path, _, _ in received)
        assert service["calls"] == []
        assert cfg.path.read_bytes() == before
        request["params"]["tenant_id"] = TENANT
        mode["response_tenant"] = "02000000-0000-7000-8000-000000000001"
        with pytest.raises(ValueError, match="does not match the organization"):
            bridge.handle(dict(request, action="enrollment.connect"))
        assert cfg.path.read_bytes() == before
        assert not (tmp_path / "data/server-config.json").exists()
        assert service["running"] == existing
        mode["response_tenant"] = TENANT
        result = bridge.handle(dict(request, action="enrollment.connect"))
        assert result == {
            "sensor_id": "sensor-1",
            "tenant": {"id": TENANT, "name": "Organization"},
            "enrolled": True,
        }
        assert not list((tmp_path / "data").rglob("policy.json"))
        loaded = Config.load(cfg.path)
        assert loaded["sensor_token"] == "device-only-secret"
        assert loaded["server_url"] == preview["server_url"]
        assert (
            json.loads((tmp_path / "data/server-config.json").read_text())[
                "heartbeat_interval_s"
            ]
            == 60
        )
        assert CODE not in cfg.path.read_text()
        assert received[-1][0] == "/ingest/v1/enroll"
        assert received[-1][1]["enrollment_token"] == CODE
        assert all(auth is None for _, _, auth in received)
        assert service["calls"] == (["stop", "start", "stop", "start"] if existing else [])
        assert service["running"] == existing
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_link_bridge_uses_the_previewed_mtls_identity(tmp_path, monkeypatch):
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"))
    cfg.save()
    monkeypatch.setattr(
        bridge.Client,
        "post",
        lambda *_: {
            "tenant": {"id": TENANT, "name": "Organization"},
            "auth_mode": "mtls",
            "expires_at": "2099-01-01T00:00:00Z",
        },
    )
    received = []

    def enroll(config, server, token, **kwargs):
        received.append((server, token, kwargs))
        return {"sensor_id": "sensor-1"}

    monkeypatch.setattr(bridge, "enroll", enroll)
    bridge.handle(
        {
            "action": "enrollment.connect",
            "config_path": str(cfg.path),
            "params": {
                "link": make_enrollment_link("https://tenant.example", CODE),
                "tenant_id": TENANT,
            },
        }
    )
    assert received[0][:2] == ("https://tenant.example", CODE)
    assert received[0][2]["auth_mode"] == "mtls"
    assert received[0][2]["tenant_id"] == TENANT


@pytest.mark.parametrize("failure,target_mode", [
    (failure, mode) for mode in ("bearer", "mtls")
    for failure in ("telemetry", "legacy", "unreadable", "network", "stop", "restart", "restore", "certificate")
    if (mode == "bearer" and failure != "certificate") or (mode == "mtls" and failure != "restart")
])
def test_reconnection_preserves_identity_and_queues_on_failure(tmp_path, monkeypatch, failure, target_mode):
    import httpx
    from openaidr.sensor.spool import Spool
    from openaidr.sensor.telemetry import ExportQueue

    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                 server_url="https://old.example", sensor_id="old-device", sensor_token="old-token")
    cfg.save()
    before = cfg.path.read_bytes()
    cache = tmp_path / "data/policy.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    cached = '{"version": 1, "rules": [{"action": "deny"}]}'
    cache.write_text(cached)
    state = {"running": True, "requests": [], "actions": []}
    queue_path = tmp_path / "data/telemetry.sqlite3"
    pending_path = tmp_path / "data/credentials/pending.json"

    def manage(action, config, **_):
        if action == "status":
            return "running" if state["running"] else "stopped"
        state["actions"].append(action)
        if action == "start" and failure in ("restart", "restore"):
            raise OSError("service could not start")
        state["running"] = action == "start"

    def stop(config):
        if failure == "stop":
            raise OSError("service could not stop")
        manage("stop", config)
        # A collector or receiver can enqueue one last record during shutdown.
        if failure == "telemetry":
            queue = ExportQueue(queue_path)
            state["batch"] = queue.append("logs", b'{"old":"activity"}', "application/json", 1)
            queue.close()
        elif failure == "legacy":
            spool = Spool(tmp_path / "data/spool")
            spool.append({"id": "old-tenant-event"})
            spool.close()
        elif failure == "unreadable":
            queue_path.parent.mkdir(parents=True, exist_ok=True)
            queue_path.write_bytes(b"invalid queue retained")
        elif failure == "certificate":
            from openaidr.sensor.credentials import pending_request
            pending_request(config, "migrate", config["server_url"], TENANT,
                            config["sensor_id"], config["sensor_token"], {})
            state["pending"] = pending_path.read_bytes()

    def local_status(*_):
        if not state["running"]:
            raise OSError("not running")
        return dict(sensor_id="old-device", server_url="https://old.example",
                    version="0.1.0", queue_depth=0, telemetry={"queue_depth": 0})

    def post(client, path, body):
        state["requests"].append(path)
        if path == "enrollment/preview":
            return dict(tenant={"id": TENANT, "name": "Organization"},
                        auth_mode=target_mode, expires_at="2099-01-01T00:00:00Z")
        if failure in ("network", "restore"):
            raise httpx.ConnectError("server offline")
        return dict(sensor_id="new-device", sensor_token="new-token", tenant={"id": TENANT})

    monkeypatch.setattr(bridge.service, "manage", manage)
    monkeypatch.setattr(bridge.service, "stop_and_wait", stop)
    monkeypatch.setattr(bridge.hooks, "local_request", local_status)
    monkeypatch.setattr(bridge.Client, "post", post)
    request = {"action": "enrollment.connect", "config_path": str(cfg.path),
               "params": {"link": make_enrollment_link("https://new.example", CODE), "tenant_id": TENANT}}
    if failure == "restart":
        response = bridge.handle(request)
        assert response["enrolled"] and response["sensor_id"] == "new-device"
        assert "Retry setup" in response["service_error"]
        assert Config.load(cfg.path)["sensor_token"] == "new-token"
        assert state["requests"] == ["enrollment/preview", "enroll"]
        assert not state["running"]
        assert not cache.exists()
    else:
        with pytest.raises((ValueError, OSError, httpx.RequestError)):
            bridge.handle(request)
        assert cfg.path.read_bytes() == before
        assert cache.read_text() == cached
        assert state["running"] == (failure != "restore")
        if failure not in ("network", "restore"):
            assert state["requests"] == ["enrollment/preview"]
    assert state["actions"] == ([] if failure == "stop" else ["stop", "start"])
    if failure == "telemetry":
        queue = ExportQueue(queue_path)
        assert queue.next()["batch_id"] == state["batch"]
        queue.close()
    elif failure == "legacy":
        spool = Spool(tmp_path / "data/spool")
        assert spool.read()["events"] == [{"id": "old-tenant-event"}]
        spool.close()
    elif failure == "unreadable":
        assert queue_path.read_bytes() == b"invalid queue retained"
    elif failure == "certificate":
        assert pending_path.read_bytes() == state["pending"]


@pytest.mark.parametrize("source_mode,target_mode", [("bearer", "bearer"), ("bearer", "mtls"), ("mtls", "mtls"), ("mtls", "bearer")])
@pytest.mark.parametrize("case", ["foreground", "newer", "stopped_newer", "unreachable", "other_device", "pending"])
def test_reconnection_preflight_keeps_the_current_service_and_link(tmp_path, monkeypatch, case, source_mode, target_mode):
    from types import SimpleNamespace
    monkeypatch.setattr(bridge, "app_version", lambda: "0.1.0")

    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                 server_url="https://old.example", sensor_id="old-device", sensor_token="old-token")
    if source_mode == "mtls":
        cfg.update(auth_mode="mtls", tenant_id=TENANT, sensor_id=TENANT,
                   client_cert=str(tmp_path / "cert.pem"), client_key=str(tmp_path / "key.pem"))
    cfg.save()
    before = cfg.path.read_bytes()
    live = dict(sensor_id=cfg["sensor_id"], server_url=cfg["server_url"],
                version="0.2.0" if case == "newer" else "0.1.0", queue_depth=1 if case == "pending" else 0)
    if case == "other_device":
        live["sensor_id"] = "different-device"
    if case == "stopped_newer":
        bridge.record_service_version(cfg, "0.2.0")
    state = "stopped" if case in ("foreground", "stopped_newer") else "running"
    requests = []

    def manage(action, *_args, **_kwargs):
        assert action == "status"
        return state

    def status(*_):
        if case in ("unreachable", "stopped_newer"):
            raise OSError("offline")
        return live

    def post(client, path, body):
        assert path == "enrollment/preview"
        requests.append(path)
        return dict(tenant={"id": TENANT, "name": "Organization"},
                    auth_mode=target_mode, expires_at="2099-01-01T00:00:00Z")

    clock = iter([0, 11])
    monkeypatch.setattr(bridge, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    monkeypatch.setattr(bridge.service, "manage", manage)
    monkeypatch.setattr(bridge.service, "stop_and_wait", lambda *_: pytest.fail("must not stop the existing service"))
    monkeypatch.setattr(bridge.hooks, "local_request", status)
    monkeypatch.setattr(bridge.Client, "post", post)
    with pytest.raises(ValueError):
        bridge.handle({"action": "enrollment.connect", "config_path": str(cfg.path),
                       "params": {"link": make_enrollment_link("https://new.example", CODE), "tenant_id": TENANT}})
    assert cfg.path.read_bytes() == before
    assert requests == ["enrollment/preview"]
