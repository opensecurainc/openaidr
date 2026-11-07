"""Real numeric-IP TLS verifies private trust, SAN checks, and restart wiring."""

import json
import shutil
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from openaidr.core.protocol import default_sensor_config
from openaidr.core.enrollment import make_enrollment_link
from openaidr.sensor import bridge
from openaidr.sensor.config import Config
from openaidr.sensor.runtime import Client, Sensor, enroll
from openaidr.sensor.telemetry import Telemetry
from openaidr.sensor.tls import (
    MAX_CA_BYTES,
    read_ca_certificate,
    same_origin,
    validate_ca_certificate,
)

ENROLLMENT_TENANT = {"id": "01000000-0000-7000-8000-000000000001", "name": "Private organization"}


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl executable is required for real TLS certificate fixtures")
    path = tmp_path_factory.mktemp("tls-certs")

    def run(*args):
        subprocess.run(["openssl", *args], cwd=path, check=True, capture_output=True)

    run(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.crt",
        "-days",
        "1",
        "-subj",
        "/CN=OpenAIDR Test CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
    )
    # "named" is reachable only through a test proxy that resolves openaidr.test.
    for name, san in [("correct", "IP:127.0.0.1"), ("wrong", "IP:192.0.2.25"), ("named", "DNS:openaidr.test")]:
        run(
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            name + ".key",
            "-out",
            name + ".csr",
            "-subj",
            "/CN=OpenAIDR Test Server",
        )
        (path / (name + ".ext")).write_text(
            "subjectAltName="
            + san
            + "\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
            + "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
        )
        run(
            "x509",
            "-req",
            "-in",
            name + ".csr",
            "-CA",
            "ca.crt",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            name + ".crt",
            "-days",
            "1",
            "-extfile",
            name + ".ext",
        )
    run(
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        "device-ca.key",
        "-out",
        "device-ca.crt",
        "-days",
        "1",
        "-subj",
        "/CN=OpenAIDR Device Test CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
    )
    (path / "device.ext").write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
    )
    for name, issuer in [
        ("device", "device-ca"),
        ("untrusted-device", "ca"),
        ("expired-device", "device-ca"),
    ]:
        run(
            "req",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            name + ".key",
            "-out",
            name + ".csr",
            "-subj",
            "/CN=OpenAIDR Test Device",
        )
        if name == "expired-device":
            (path / "index.txt").touch()
            (path / "serial").write_text("01\n")
            (path / "issuer.cnf").write_text(
                "[ca]\ndefault_ca = device\n[device]\n"
                "database = index.txt\nnew_certs_dir = .\nserial = serial\n"
                "private_key = device-ca.key\ncertificate = device-ca.crt\n"
                "default_md = sha256\npolicy = identity\n"
                "[identity]\ncommonName = supplied\n"
            )
            run(
                "ca",
                "-batch",
                "-notext",
                "-config",
                "issuer.cnf",
                "-in",
                name + ".csr",
                "-out",
                name + ".crt",
                "-startdate",
                "20000101000000Z",
                "-enddate",
                "20000102000000Z",
                "-extfile",
                "device.ext",
            )
        else:
            run(
                "x509",
                "-req",
                "-in",
                name + ".csr",
                "-CA",
                issuer + ".crt",
                "-CAkey",
                issuer + ".key",
                "-CAcreateserial",
                "-out",
                name + ".crt",
                "-days",
                "1",
                "-extfile",
                "device.ext",
            )
    run(
        "pkey",
        "-in",
        "device.key",
        "-aes256",
        "-passout",
        "pass:synthetic-test-key",
        "-out",
        "encrypted.key",
    )
    return path


@pytest.fixture
def tls_servers(certificates, request, backend_hook):
    servers, threads, requests = [], [], []
    mode = getattr(request, "param", None)
    mutual = mode is not None
    status = {"mtls-401": 401, "mtls-403": 403}.get(mode, 200)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1" if mode == "mtls-hooks" else "HTTP/1.0"

        def log_message(self, *_):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            requests.append(
                (
                    self.path,
                    self.headers.get("Authorization"),
                    body,
                    self.connection.getpeercert(binary_form=True),
                )
            )
            if self.path == "/ingest/v1/enroll":
                result = {
                    "tenant": ENROLLMENT_TENANT,
                    "sensor_id": "tls-sensor",
                    "sensor_token": "issued-token",
                    "config": default_sensor_config(),
                    "policy": {"version": 1, "rules": []},
                }
            elif self.path == "/ingest/v1/enrollment/preview":
                result = {
                    "tenant": ENROLLMENT_TENANT,
                    "auth_mode": "bearer",
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            elif self.path == "/ingest/v1/heartbeat":
                result = {"disabled": False}
                if mutual:
                    result["commands"] = [
                        {
                            "id": "a2780d65-60e1-4559-acb9-42fe1fdbb1fd",
                            "type": "refresh_policy",
                        }
                    ]
            elif self.path == "/ingest/v1/events":
                result = {"accepted": len(json.loads(body)["events"])}
            elif self.path == "/ingest/v1/version":
                result = {"version": "0.2.0"}
            elif self.path == "/ingest/v1/hook-checks":
                payload = json.loads(body)
                result = backend_hook(action="deny", mode="enforce")(payload, None)
                result["request_id"] = payload["request_id"]
            else:
                result = {}
            encoded = json.dumps(result).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    urls = {}
    for name in ("correct", "wrong", "named"):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certificates / (name + ".crt"), certificates / (name + ".key")
        )
        if mutual:
            context.load_verify_locations(certificates / "device-ca.crt")
            context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        threads.append(thread)
        host = "openaidr.test" if name == "named" else "127.0.0.1"
        urls[name] = f"https://{host}:{server.server_port}"
    yield urls, requests
    for server in servers:
        server.shutdown()
        server.server_close()
    for thread in threads:
        thread.join()


def fresh_config(tmp_path):
    cfg = Config(
        tmp_path / "sensor.yaml",
        data_dir=str(tmp_path / "data"),
        telemetry={"listen": "127.0.0.1:0"},
    )
    cfg.save()
    return cfg


def test_numeric_ip_ca_enrollment_and_persisted_trust_for_all_transports(
    tmp_path, certificates, tls_servers
):
    urls, requests = tls_servers
    cfg = fresh_config(tmp_path)
    ca = read_ca_certificate(certificates / "ca.crt")
    enroll(cfg, urls["correct"], "enrollment-token", ca_certificate=ca)
    loaded = Config.load(cfg.path)
    assert loaded["ca_cert"] == str((tmp_path / "data/ca-cert.pem").resolve())
    assert Path(loaded["ca_cert"]).read_text() == ca
    client = Client(
        loaded["server_url"], loaded["sensor_token"], ca_cert=loaded["ca_cert"]
    )
    try:
        assert client.post("heartbeat", {"sensor_id": loaded["sensor_id"]}) == {
            "disabled": False
        }
        assert client.post("events", {"events": [{"id": "legacy"}]})["accepted"] == 1
    finally:
        client.close()
    telemetry = Telemetry(loaded)
    try:
        batch_id = telemetry.accept("logs", b"{}", "application/json")
        assert batch_id
        telemetry.forward_once()
        assert telemetry.queue.status()["queue_depth"] == 0
    finally:
        telemetry.close()
    assert requests[0][1] is None
    assert all(auth == "Bearer issued-token" for _, auth, _, _ in requests[1:])


def test_link_enrollment_previews_without_writes_and_persists_selected_ca(
    tmp_path, certificates, tls_servers,
):
    urls, requests = tls_servers
    cfg = fresh_config(tmp_path)
    before = cfg.path.read_bytes()
    ca = read_ca_certificate(certificates / "ca.crt")
    code = "oaet_" + "a" * 43
    params = {"link": make_enrollment_link(urls["correct"], code), "ca_certificate": ca}
    request = {"config_path": str(cfg.path), "params": params}
    preview = bridge.handle(dict(request, action="enrollment.preview"))
    assert preview["tenant"] == ENROLLMENT_TENANT
    assert ca not in json.dumps(preview) and code not in json.dumps(preview)
    assert cfg.path.read_bytes() == before
    assert not (tmp_path / "data/ca-cert.pem").exists()

    params["tenant_id"] = preview["tenant"]["id"]
    assert bridge.handle(dict(request, action="enrollment.connect"))["enrolled"]
    loaded = Config.load(cfg.path)
    assert Path(loaded["ca_cert"]).read_text() == ca
    # A later preview at the same origin uses the persisted sensor trust.
    assert bridge.preview_enrollment(loaded, params["link"])["tenant"] == ENROLLMENT_TENANT
    assert [path for path, *_ in requests] == [
        "/ingest/v1/enrollment/preview", "/ingest/v1/enrollment/preview",
        "/ingest/v1/enroll", "/ingest/v1/enrollment/preview",
    ]
    assert all(auth is None and "ca_certificate" not in json.loads(body)
               for _, auth, body, _ in requests)
    # Even a CA that could verify the new server must not follow an enrollment
    # link to a different origin without the user's explicit file selection.
    loaded["server_url"] = "https://previous.example"
    loaded.save()
    before = loaded.path.read_bytes()
    with pytest.raises(ValueError, match="Could not verify"):
        bridge.handle({"action": "enrollment.preview", "config_path": str(cfg.path),
                       "params": {"link": params["link"]}})
    assert len(requests) == 4
    assert loaded.path.read_bytes() == before
    assert Path(loaded["ca_cert"]).read_text() == ca


@pytest.mark.parametrize("failure", [
    "missing", "wrong CA", "wrong SAN", "malformed", "private key", "oversized",
])
def test_link_ca_failures_never_consume_code_or_change_identity(
    tmp_path, certificates, tls_servers, failure,
):
    urls, requests = tls_servers
    cfg = fresh_config(tmp_path)
    cfg.update(server_url="https://previous.example", sensor_id="old", sensor_token="old-token")
    cfg.save()
    before = cfg.path.read_bytes()
    ca = read_ca_certificate(certificates / "ca.crt")
    if failure == "wrong CA":
        ca = read_ca_certificate(certificates / "device-ca.crt")
    elif failure == "malformed":
        ca = "not PEM"
    elif failure == "private key":
        ca += (certificates / "ca.key").read_text()
    elif failure == "oversized":
        ca = "x" * (MAX_CA_BYTES + 1)
    server = urls["wrong" if failure == "wrong SAN" else "correct"]
    params = {"link": make_enrollment_link(server, "oaet_" + "a" * 43)}
    if failure != "missing":
        params["ca_certificate"] = ca
    for action in ("enrollment.preview", "enrollment.connect"):
        if action.endswith("connect"):
            params["tenant_id"] = ENROLLMENT_TENANT["id"]
        with pytest.raises(ValueError):
            bridge.handle({"action": action, "config_path": str(cfg.path), "params": params})
        assert cfg.path.read_bytes() == before
        assert not (tmp_path / "data/ca-cert.pem").exists()
        assert requests == []


@pytest.mark.parametrize("which,supply_ca", [("correct", False), ("wrong", True)])
def test_untrusted_and_wrong_ip_enrollment_preserve_prior_identity(
    tmp_path, certificates, tls_servers, which, supply_ca
):
    urls, requests = tls_servers
    cfg = fresh_config(tmp_path)
    before = cfg.path.read_bytes()
    ca = read_ca_certificate(certificates / "ca.crt") if supply_ca else None
    with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
        enroll(cfg, urls[which], "enrollment-token", ca_certificate=ca)
    assert cfg.path.read_bytes() == before
    assert not (tmp_path / "data/ca-cert.pem").exists()
    assert not requests


@pytest.mark.parametrize("which,supply_ca", [("correct", False), ("wrong", True)])
def test_untrusted_and_wrong_ip_forwarding_retain_queue(
    tmp_path, certificates, tls_servers, which, supply_ca
):
    urls, _ = tls_servers
    cfg = fresh_config(tmp_path)
    cfg.update(server_url=urls[which], sensor_id="s", sensor_token="token")
    if supply_ca:
        cfg["ca_cert"] = str(certificates / "ca.crt")
    telemetry = Telemetry(cfg)
    try:
        batch_id = telemetry.accept("logs", b"{}", "application/json")
        telemetry.forward_once()
        assert telemetry.queue.status()["queue_depth"] == 1
        assert "CERTIFICATE_VERIFY_FAILED" in telemetry.queue.status()["last_error"]
        telemetry.queue.retry(batch_id, "", delay=0)
        assert telemetry.queue.next()["batch_id"] == batch_id
    finally:
        telemetry.close()


def test_reenrollment_same_origin_reuses_trust_new_origin_does_not(
    tmp_path, certificates, tls_servers, monkeypatch
):
    from openaidr.sensor import runtime

    urls, _ = tls_servers
    cfg = fresh_config(tmp_path)
    ca = read_ca_certificate(certificates / "ca.crt")
    enroll(cfg, urls["correct"], "first", ca_certificate=ca)
    monkeypatch.setattr(
        runtime.hooks,
        "local_request",
        lambda *_: (_ for _ in ()).throw(OSError("offline")),
    )
    enroll(cfg, urls["correct"], "second")
    before, trust = cfg.path.read_bytes(), Path(cfg["ca_cert"]).read_bytes()
    with pytest.raises(httpx.ConnectError):
        enroll(cfg, urls["wrong"], "third")
    assert (
        cfg.path.read_bytes() == before and Path(cfg["ca_cert"]).read_bytes() == trust
    )
    # Explicit empty PEM means public roots, rather than silently keeping trust.
    with pytest.raises(httpx.ConnectError):
        enroll(cfg, urls["correct"], "third", ca_certificate="")
    assert (
        cfg.path.read_bytes() == before and Path(cfg["ca_cert"]).read_bytes() == trust
    )


@pytest.mark.parametrize(
    "invalid",
    [
        "not a certificate",
        "-----BEGIN CERTIFICATE-----\nYmFk\n-----END CERTIFICATE-----",
        pytest.param("x" * (MAX_CA_BYTES + 1), id="oversized-ca"),
        123,
    ],
)
def test_invalid_ca_is_rejected_before_config_or_trust_changes(tmp_path, invalid):
    cfg = fresh_config(tmp_path)
    before = cfg.path.read_bytes()
    with pytest.raises(ValueError):
        enroll(cfg, "https://127.0.0.1:1", "token", ca_certificate=invalid)
    assert cfg.path.read_bytes() == before
    assert not (tmp_path / "data/ca-cert.pem").exists()


def test_private_key_bundle_is_rejected(certificates):
    ca = (certificates / "ca.crt").read_text()
    key = (certificates / "ca.key").read_text()
    with pytest.raises(ValueError, match="private keys"):
        validate_ca_certificate(ca + key)
    assert validate_ca_certificate(ca + ca).count("BEGIN CERTIFICATE") == 2


def test_same_origin_normalizes_host_and_default_port():
    assert same_origin("https://HOST.EXAMPLE:443/", "https://host.example")
    assert not same_origin("https://127.0.0.1:443", "https://127.0.0.1:8443")


def test_local_config_write_failure_restores_previous_ca(
    tmp_path, certificates, tls_servers, monkeypatch
):
    from openaidr.sensor import runtime

    urls, _ = tls_servers
    cfg = fresh_config(tmp_path)
    ca = read_ca_certificate(certificates / "ca.crt")
    enroll(cfg, urls["correct"], "first", ca_certificate=ca)
    before, trust = cfg.path.read_bytes(), Path(cfg["ca_cert"]).read_bytes()
    original = dict(cfg)
    monkeypatch.setattr(
        runtime.hooks,
        "local_request",
        lambda *_: (_ for _ in ()).throw(OSError("offline")),
    )
    monkeypatch.setattr(
        Config, "save", lambda *_: (_ for _ in ()).throw(OSError("disk unavailable"))
    )
    with pytest.raises(OSError, match="disk unavailable"):
        enroll(cfg, urls["correct"], "second", ca_certificate=ca + ca)
    assert cfg.path.read_bytes() == before
    assert Path(cfg["ca_cert"]).read_bytes() == trust
    assert dict(cfg) == original


def test_public_trust_default_and_successful_explicit_clear(
    tmp_path, certificates, monkeypatch
):
    from openaidr.sensor import runtime
    from openaidr.sensor.tls import verified_context

    assert verified_context() is True
    cfg = fresh_config(tmp_path)
    cfg.update(
        server_url="https://server.example",
        sensor_id="old",
        sensor_token="old-token",
        ca_cert=str(certificates / "ca.crt"),
    )
    cfg.save()
    monkeypatch.setattr(
        runtime.hooks,
        "local_request",
        lambda *_: (_ for _ in ()).throw(OSError("offline")),
    )
    captured = []

    class StubClient:
        def __init__(self, *args, **kwargs):
            captured.append(kwargs)

        def post(self, *_):
            return {"sensor_id": "new", "sensor_token": "new-token"}

        def close(self):
            pass

    monkeypatch.setattr(runtime, "Client", StubClient)
    enroll(cfg, "https://server.example", "new-enrollment", ca_certificate="")
    assert captured[0]["ca_cert"] is None and captured[0]["ca_certificate"] is None
    assert "ca_cert" not in Config.load(cfg.path)


def test_bridge_accepts_ca_pem_and_status_omits_contents(
    tmp_path, certificates, monkeypatch
):
    from openaidr.sensor import bridge

    cfg = fresh_config(tmp_path)
    ca = read_ca_certificate(certificates / "ca.crt")
    captured = []

    def fake_enroll(*args, **kwargs):
        captured.append(kwargs)
        return {"sensor_id": "s"}

    monkeypatch.setattr(bridge, "enroll", fake_enroll)
    result = bridge.handle(
        {
            "action": "enroll",
            "config_path": str(cfg.path),
            "params": {
                "server_url": "https://192.0.2.25",
                "token": "token",
                "ca_certificate": ca,
            },
        }
    )
    assert result["enrolled"] and captured[0]["ca_certificate"] == ca
    cfg["ca_cert"] = str(certificates / "ca.crt")
    cfg.save()
    monkeypatch.setattr(bridge.service, "manage", lambda *_: "stopped")
    monkeypatch.setattr(
        bridge.hooks,
        "local_request",
        lambda *_: (_ for _ in ()).throw(OSError("offline")),
    )
    status = bridge.status(cfg)
    assert status["custom_ca"] and status["ca_cert"] == cfg["ca_cert"]
    assert "BEGIN CERTIFICATE" not in json.dumps(status)
    # The desktop's connected status shows the saved proxy route.
    assert status["network_proxy"] == {"mode": "default"}
    cfg["network"] = {"proxy": {"mode": "manual", "url": "http://proxy.example:3128", "username": "svc"}}
    assert bridge.status(cfg)["network_proxy"] == {
        "mode": "manual", "url": "http://proxy.example:3128", "bypass": [], "username": "svc"}


def mtls_config(tmp_path, certificates, url="https://127.0.0.1:1"):
    cfg = fresh_config(tmp_path)
    cfg.update(
        auth_mode="mtls",
        server_url=url,
        tenant_id="abfe11aa-b660-4dd8-9a92-0a37917ed083",
        sensor_id="40b34fbb-2c39-466d-bca5-87514c4cb85b",
        sensor_token="stale-token-must-not-be-sent",
        ca_cert=str(certificates / "ca.crt"),
        client_cert=str(certificates / "device.crt"),
        client_key=str(certificates / "device.key"),
    )
    cfg.save()
    return cfg


@pytest.mark.parametrize("tls_servers", ["mtls-hooks"], indirect=True)
def test_hook_pool_rechecks_changed_trust_keys_and_server(tmp_path, certificates, tls_servers):
    urls, requests = tls_servers
    cfg = mtls_config(tmp_path, certificates, urls["correct"])
    cfg.update(telemetry={"enabled": False}, inventory={"enabled": False})
    originals = {}
    for key in ("ca_cert", "client_cert", "client_key"):
        originals[key] = Path(cfg[key]).read_bytes()
        cfg[key] = str(tmp_path / key)
        Path(cfg[key]).write_bytes(originals[key])
    sensor = Sensor(cfg)
    payload = dict(session_id="tls-pool", hook_event_name="UserPromptSubmit", prompt="Explain a socket")

    def evaluate(expected):
        result = sensor.hooks.evaluate(payload)
        assert result["decision"] == expected
        if expected == "allow":
            assert result["output"] == {} and result["failed"]

    try:
        evaluate("deny")
        evaluate("deny")
        assert len(requests) == 2
        # Changed contents at the same path must retire a previously trusted
        # connection, even when the new trust/key material cannot authenticate.
        Path(cfg["ca_cert"]).write_bytes((certificates / "device-ca.crt").read_bytes())
        evaluate("allow")
        assert len(requests) == 2
        Path(cfg["ca_cert"]).write_bytes(originals["ca_cert"])
        evaluate("deny")
        assert len(requests) == 3
        for key, filename in (("client_cert", "untrusted-device.crt"), ("client_key", "untrusted-device.key")):
            Path(cfg[key]).write_bytes((certificates / filename).read_bytes())
        evaluate("allow")
        assert len(requests) == 3
        for key in ("client_cert", "client_key"):
            Path(cfg[key]).write_bytes(originals[key])
        evaluate("deny")
        assert len(requests) == 4
        cfg["server_url"] = urls["wrong"]
        evaluate("allow")
        assert len(requests) == 4
        cfg["server_url"] = urls["correct"]
        evaluate("deny")
        assert len(requests) == 5
        assert all(auth is None and peer_cert for _, auth, _, peer_cert in requests)
    finally:
        sensor.hook_clients.close()
        sensor.client.close()
        sensor.spool.close()


@pytest.fixture(params=["linux", "darwin"])
def sensor_environment(monkeypatch, request):
    from openaidr.sensor import bridge, inventory_service

    monkeypatch.setattr(inventory_service.sys, "platform", request.param)

    def offline(*_):
        raise OSError("synthetic sensor is not running")

    monkeypatch.setattr(bridge.hooks, "local_request", offline)
    monkeypatch.setattr(bridge, "app_version", lambda: "0.1.0")
    monkeypatch.setattr(
        inventory_service,
        "collect_inventory",
        lambda: {
            "schema_version": 1,
            "platform": "linux",
            "collected_at": "2099-01-01T00:00:00Z",
            "sources": [],
            "applications": [],
        },
    )
    monkeypatch.setattr(
        inventory_service.component_inventory,
        "collect_inventory",
        lambda *args, **kwargs: {
            "schema_version": 1,
            "platform": "darwin",
            "collected_at": "2099-01-01T00:00:00Z",
            "roots": [],
        },
    )
    return request.param


def ship_once(sensor, failure=False):
    stop = threading.Event()
    thread = threading.Thread(target=sensor.ship_loop, args=(stop,), daemon=True)
    thread.start()
    sensor.ship_wake.set()
    try:
        deadline = time.monotonic() + 5
        while not (sensor.ship["failures"] if failure else sensor.spool.depth == 0):
            assert time.monotonic() < deadline, sensor.ship
            time.sleep(0.01)
    finally:
        stop.set()
        sensor.ship_wake.set()
        thread.join(5)
    assert not thread.is_alive()


@pytest.mark.parametrize("tls_servers", ["mtls"], indirect=True)
@pytest.mark.parametrize("stale_token", [False, True])
def test_mtls_sensor_all_transports_and_restart_never_send_bearer(
    tmp_path, certificates, tls_servers, sensor_environment, stale_token
):
    from openaidr.sensor import bridge

    urls, requests = tls_servers
    cfg = mtls_config(tmp_path, certificates, urls["correct"])
    if not stale_token:
        cfg.pop("sensor_token")
        cfg.save()
    loaded = Config.load(cfg.path)
    loaded.validate()
    assert loaded.enrolled()
    sensor = Sensor(loaded)
    try:
        sensor.heartbeat_once()
        assert not sensor.heartbeat_error
        sensor.spool.append({"id": "synthetic-event"})
        ship_once(sensor)
        inventory = (
            sensor.component_inventory
            if sensor_environment == "darwin"
            else sensor.inventory
        )
        inventory.sync_once()
        assert not inventory.status()["pending"]
        sensor.telemetry.accept("logs", b"{}", "application/json")
        sensor.telemetry.forward_once()
        assert sensor.telemetry.queue.status()["queue_depth"] == 0
        assert bridge.update_check(loaded)["latest"] == "0.2.0"
    finally:
        sensor.client.close()
        sensor.telemetry.close()
        sensor.spool.close()
    assert {path for path, _, _, _ in requests} == {
        "/ingest/v1/heartbeat",
        "/ingest/v1/events",
        "/ingest/v1/commands/a2780d65-60e1-4559-acb9-42fe1fdbb1fd/ack",
        "/ingest/v1/inventory/snapshots"
        if sensor_environment == "darwin"
        else "/ingest/v1/inventory/applications",
        "/otlp/v1/logs",
        "/ingest/v1/version",
    }
    expected = ssl.PEM_cert_to_DER_cert((certificates / "device.crt").read_text())
    assert all(auth is None and peer == expected for _, auth, _, peer in requests)


@pytest.mark.parametrize(
    "failure,tls_servers",
    [
        ("wrong-server", "mtls"),
        ("unknown-server", "mtls"),
        ("untrusted-device", "mtls"),
        ("expired-device", "mtls"),
        ("denied-401", "mtls-401"),
        ("denied-403", "mtls-403"),
    ],
    indirect=["tls_servers"],
)
def test_mtls_transport_and_auth_failures_retain_queues_and_never_fall_back(
    tmp_path, certificates, tls_servers, sensor_environment, failure
):
    from openaidr.sensor import bridge
    from openaidr.sensor.inventory_service import InventoryService

    urls, requests = tls_servers
    cfg = mtls_config(
        tmp_path,
        certificates,
        urls["wrong" if failure == "wrong-server" else "correct"],
    )
    if failure == "unknown-server":
        cfg.pop("ca_cert")
    elif failure.endswith("device"):
        cfg["client_cert"] = str(certificates / (failure + ".crt"))
        cfg["client_key"] = str(certificates / (failure + ".key"))
    cfg.save()
    sensor = Sensor(cfg)
    try:
        sensor.heartbeat_once()
        assert sensor.heartbeat_error
        sensor.spool.append({"id": "retained-event"})
        if failure.startswith("denied"):
            assert sensor.disabled and sensor.ship["paused"]
        else:
            ship_once(sensor, failure=True)
        assert sensor.spool.read()["events"] == [{"id": "retained-event"}]
        inventory = InventoryService(
            cfg, sensor.client, components=sensor_environment == "darwin"
        )
        with pytest.raises(httpx.HTTPError):
            inventory.sync_once()
        assert inventory.status()["pending"]
        batch = sensor.telemetry.accept("logs", b"{}", "application/json")
        sensor.telemetry.forward_once()
        assert sensor.telemetry.queue.status()["queue_depth"] == 1
        sensor.telemetry.queue.retry(batch, "", delay=0)
        assert sensor.telemetry.queue.next()["batch_id"] == batch
        with pytest.raises(httpx.HTTPError):
            bridge.update_check(cfg)
        if failure.startswith("denied"):
            assert len(requests) == 3
            assert all(auth is None and peer for _, auth, _, peer in requests)
            assert sensor.ship["paused"]
        else:
            assert not requests
    finally:
        sensor.client.close()
        sensor.telemetry.close()
        sensor.spool.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("auth_mode", "automatic"),
        ("auth_mode", None),
        ("server_url", "http://127.0.0.1:1"),
        ("server_url", "https://127.0.0.1/api"),
        ("server_url", "https://@127.0.0.1"),
        ("server_url", "https://127.0.0.1?"),
        ("server_url", "https://127.0.0.1#"),
        ("server_url", "https://127.0.0.1\n"),
        ("tenant_id", ""),
        ("tenant_id", "other-tenant"),
        ("sensor_id", "sensor"),
        ("client_key", ""),
        ("client_cert", None),
    ],
)
def test_mtls_invalid_configuration_fails_before_transport_or_state_changes(
    tmp_path, certificates, field, value
):
    cfg = mtls_config(tmp_path, certificates)
    cfg[field] = value
    before = cfg.path.read_bytes()
    with pytest.raises(ValueError):
        cfg.validate()
    assert not cfg.enrolled()
    for build in (Client.from_config, Telemetry, Sensor):
        with pytest.raises(ValueError):
            build(cfg)
    assert cfg.path.read_bytes() == before
    assert not (tmp_path / "data/telemetry.sqlite3").exists()


@pytest.mark.parametrize(
    "failure",
    [
        "missing-key",
        "missing-cert",
        "mismatch",
        "invalid-key",
        "invalid-cert",
        "encrypted",
    ],
)
def test_mtls_unusable_credentials_fail_before_touching_existing_queue(
    tmp_path, certificates, failure
):
    from openaidr.sensor import bridge
    from openaidr.sensor.telemetry import ExportQueue

    cfg = mtls_config(tmp_path, certificates)
    invalid = tmp_path / "invalid.pem"
    invalid.write_text("invalid credential\n")
    if failure == "mismatch":
        cfg["client_key"] = str(certificates / "untrusted-device.key")
    elif failure == "encrypted":
        cfg["client_key"] = str(certificates / "encrypted.key")
    else:
        field = "client_key" if failure.endswith("key") else "client_cert"
        cfg[field] = (
            str(tmp_path / "missing.pem")
            if failure.startswith("missing")
            else str(invalid)
        )
    cfg.save()
    cfg.validate()
    assert cfg.enrolled()  # Status need not open a service-owned private key.
    queue = ExportQueue(tmp_path / "data/telemetry.sqlite3")
    batch = queue.append("logs", b"{}", "application/json", 1)
    queue.close()
    before = cfg.path.read_bytes()
    for build in (Client.from_config, Telemetry, Sensor, bridge.update_check):
        with pytest.raises(ValueError, match="cannot load mTLS"):
            build(cfg)
    assert cfg.path.read_bytes() == before
    queue = ExportQueue(tmp_path / "data/telemetry.sqlite3")
    assert queue.next()["batch_id"] == batch
    queue.close()


def test_mtls_reenrollment_cannot_downgrade_or_modify_identity_and_queues(
    tmp_path, certificates
):
    from openaidr.sensor.telemetry import ExportQueue
    from openaidr.sensor.spool import Spool

    cfg = mtls_config(tmp_path, certificates)
    queue = ExportQueue(tmp_path / "data/telemetry.sqlite3")
    batch = queue.append("logs", b"{}", "application/json", 1)
    queue.close()
    spool = Spool(tmp_path / "data/spool")
    spool.append({"id": "retained"})
    spool.close()
    before = cfg.path.read_bytes()
    with pytest.raises(ValueError, match="cannot fall back to bearer"):
        enroll(cfg, "https://other.example", "enrollment-token")
    assert cfg.path.read_bytes() == before
    queue = ExportQueue(tmp_path / "data/telemetry.sqlite3")
    assert queue.next()["batch_id"] == batch
    queue.close()
    spool = Spool(tmp_path / "data/spool")
    assert spool.read()["events"] == [{"id": "retained"}]
    spool.close()


@pytest.mark.parametrize("tls_servers", ["mtls"], indirect=True)
def test_missing_client_certificate_is_rejected_by_real_tls(tls_servers, certificates):
    urls, requests = tls_servers
    client = Client(
        urls["correct"], "legacy-token", ca_cert=str(certificates / "ca.crt")
    )
    try:
        with pytest.raises(httpx.TransportError):
            client.post("heartbeat", {})
        assert not requests
    finally:
        client.close()


@pytest.mark.parametrize("tls_servers", ["mtls"], indirect=True)
def test_mtls_keeps_httpx_environment_server_trust(
    tmp_path, certificates, tls_servers, monkeypatch
):
    urls, requests = tls_servers
    cfg = mtls_config(tmp_path, certificates, urls["correct"])
    cfg.pop("ca_cert")
    monkeypatch.setenv("SSL_CERT_FILE", str(certificates / "ca.crt"))
    client = Client.from_config(cfg)
    try:
        assert client.post("version", {})["version"] == "0.2.0"
        assert requests[0][1] is None
    finally:
        client.close()
