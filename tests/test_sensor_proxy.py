"""Sensor traffic through a manually configured HTTP(S) proxy (real TLS, real CONNECT)."""

import base64
import json
import logging
import select
import socket
import socketserver
import threading
import time
import uuid

import pytest

from openaidr.sensor import network_proxy, proxy_credentials
from openaidr.sensor.config import Config
from openaidr.sensor.runtime import Client, Sensor, enroll
from openaidr.sensor.telemetry import Telemetry
from openaidr.sensor.tls import read_ca_certificate

from test_telemetry_sensor_tls import certificates, mtls_config, tls_servers  # noqa: F401

PROMPT = dict(session_id="proxy", hook_event_name="UserPromptSubmit", prompt="Explain a socket")


class Proxy:
    """CONNECT proxy that resolves every host to loopback, like a proxy-only network."""

    def __init__(self, *, auth=None, stall=False, delay=0.0, redirect_port=None):
        self.log, self.seen = [], bytearray()
        proxy = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sock, data = self.request, b""
                while b"\r\n\r\n" not in data:
                    chunk = sock.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
                headers = {k.strip().lower(): v.strip() for k, v in (h.split(":", 1) for h in head[1:] if ":" in h)}
                proxy.seen.extend(data)
                proxy.log.append((head[0], headers.get("proxy-authorization")))
                if stall:
                    time.sleep(30)
                    return
                time.sleep(delay)
                if auth and headers.get("proxy-authorization") != "Basic " + base64.b64encode(auth.encode()).decode():
                    sock.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
                    return
                port = redirect_port or int(head[0].split()[1].rsplit(":", 1)[1])
                upstream = socket.create_connection(("127.0.0.1", port))
                sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                try:
                    while True:
                        readable, _, _ = select.select([sock, upstream], [], [], 10)
                        if not readable:
                            return
                        for source in readable:
                            chunk = source.recv(65536)
                            if not chunk:
                                return
                            if source is upstream:
                                time.sleep(delay)
                                sock.sendall(chunk)
                            else:
                                proxy.seen.extend(chunk)
                                upstream.sendall(chunk)
                except OSError:
                    return
                finally:
                    upstream.close()

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = allow_reuse_address = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def connects(self):
        return [line for line, _ in self.log if line.startswith("CONNECT ")]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def make_proxy():
    made = []

    def factory(**kwargs):
        made.append(Proxy(**kwargs))
        return made[-1]

    yield factory
    for proxy in made:
        proxy.close()


@pytest.fixture
def store(monkeypatch):
    """In-memory credential store at the OS boundary."""
    saved = {}
    monkeypatch.setattr(proxy_credentials, "_backend", lambda: (
        saved.get, lambda account, password: saved.__setitem__(account, password),
        lambda account: saved.pop(account, None)))
    monkeypatch.setattr(proxy_credentials, "is_root", lambda: False)
    return saved


def dead_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def configure(tmp_path, certificates, url, proxy_url, **proxy):
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"), server_url=url,
                 ca_cert=str(certificates / "ca.crt"), sensor_id=str(uuid.uuid4()), sensor_token="issued-token",
                 telemetry={"enabled": False, "listen": "127.0.0.1:0"}, inventory={"enabled": False})
    cfg.save()
    network_proxy.save(cfg, {"mode": "manual", "url": proxy_url, **proxy}, proxy.pop("password", None))
    return Config.load(cfg.path)


def test_settings_validation_messages():
    assert network_proxy.validate_url(" HTTPS://Proxy.Example.com:8443/ ") == "https://proxy.example.com:8443"
    for value, message in [("socks5://p:1080", "http:// or https://"), ("http://u:p@p:1", "separately"),
                           ("http://p:1/path", "Remove the path"), ("", "Enter a proxy URL"),
                           ("http://p:99999", "Enter a URL such as")]:
        with pytest.raises(ValueError, match=message):
            network_proxy.validate_url(value)
    assert network_proxy.validate_bypass("A.example.com, .corp.example; 10.0.0.1 [::1]") == [
        "a.example.com", "*.corp.example", "10.0.0.1", "::1"]
    with pytest.raises(ValueError, match="not a host name"):
        network_proxy.validate_bypass(["bad host!"])
    settings = network_proxy.validate({"mode": "manual", "url": "http://p:3128", "bypass": ["*.corp.example"]})
    assert network_proxy.bypasses(settings, "https://a.corp.example/x")
    assert network_proxy.bypasses(settings, "https://corp.example/x")
    assert network_proxy.bypasses(settings, "http://localhost:8080/")
    assert not network_proxy.bypasses(settings, "https://evilcorp.example/x")


def test_every_backend_transport_uses_the_configured_proxy(tmp_path, certificates, tls_servers, make_proxy,
                                                           monkeypatch):
    urls, requests = tls_servers
    proxy = make_proxy()
    # An explicit setting ignores proxy environment variables.
    monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{dead_port()}")
    monkeypatch.setenv("NO_PROXY", "openaidr.test")
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"), telemetry={"listen": "127.0.0.1:0"})
    cfg.save()
    network_proxy.save(cfg, {"mode": "manual", "url": proxy.url})
    enroll(cfg, urls["named"], "enrollment-token", ca_certificate=read_ca_certificate(certificates / "ca.crt"))
    cfg = Config.load(cfg.path)
    client = Client.from_config(cfg)
    try:
        assert client.post("heartbeat", {"sensor_id": cfg["sensor_id"]}) == {"disabled": False}
    finally:
        client.close()
    telemetry = Telemetry(cfg)
    try:
        assert telemetry.accept("logs", b"{}", "application/json")
        telemetry.forward_once()
        assert telemetry.queue.status()["queue_depth"] == 0
    finally:
        telemetry.close()
    sensor = Sensor(cfg)
    try:
        assert sensor.hooks.evaluate(PROMPT)["decision"] == "deny"  # a timely Enforce deny still applies
        assert sensor.status()["network_proxy"] == {"mode": "manual", "url": proxy.url, "bypass": []}
    finally:
        sensor.hook_clients.close()
        sensor.client.close()
        sensor.spool.close()
    port = urls["named"].rsplit(":", 1)[1]
    assert proxy.connects() and set(proxy.connects()) == {f"CONNECT openaidr.test:{port} HTTP/1.1"}
    assert [path for path, *_ in requests] == ["/ingest/v1/enroll", "/ingest/v1/heartbeat", "/otlp/v1/logs",
                                               "/ingest/v1/hook-checks"]
    # TLS is end to end: the proxy never sees the bearer token or request content.
    assert b"issued-token" not in proxy.seen and b"Explain a socket" not in proxy.seen


def test_direct_mode_ignores_environment_and_absent_block_keeps_it(tmp_path, certificates, tls_servers, monkeypatch):
    urls, _ = tls_servers
    monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{dead_port()}")
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"), server_url=urls["correct"],
                 ca_cert=str(certificates / "ca.crt"), sensor_token="issued-token")
    cfg.save()
    with pytest.raises(Exception):
        Client.from_config(cfg).post("version", {})  # historical behavior honors the environment
    network_proxy.save(cfg, {"mode": "direct"})
    client = Client.from_config(Config.load(cfg.path))
    try:
        assert client.post("version", {})["version"] == "0.2.0"
    finally:
        client.close()


def test_bypass_and_loopback_connect_directly(tmp_path, certificates, tls_servers, make_proxy):
    urls, _ = tls_servers
    proxy = make_proxy()
    cfg = configure(tmp_path, certificates, urls["correct"], proxy.url, bypass=["internal.example"])
    client = Client.from_config(cfg)
    try:
        assert client.post("version", {})["version"] == "0.2.0"
    finally:
        client.close()
    assert proxy.connects() == []


def test_tunnel_to_another_identity_fails_without_sending_credentials(tmp_path, certificates, tls_servers,
                                                                       make_proxy):
    urls, requests = tls_servers
    proxy = make_proxy(redirect_port=int(urls["correct"].rsplit(":", 1)[1]))
    cfg = configure(tmp_path, certificates, urls["named"], proxy.url)
    client = Client.from_config(cfg)
    try:
        with pytest.raises(Exception) as failure:
            client.post("version", {})
    finally:
        client.close()
    assert network_proxy.describe_error(failure.value)[0] == "certificate_untrusted"
    assert requests == [] and b"issued-token" not in proxy.seen


def test_basic_auth_uses_the_credential_store_and_never_leaks(tmp_path, certificates, tls_servers, make_proxy,
                                                               store, caplog):
    urls, _ = tls_servers
    secret = "s3cr3t-proxy-pass"
    proxy = make_proxy(auth=f"svc:{secret}")
    caplog.set_level(logging.DEBUG)
    cfg = configure(tmp_path, certificates, urls["named"], proxy.url, username="svc", password=secret)
    assert store == {f"svc@127.0.0.1:{proxy.url.rsplit(':', 1)[1]}": secret}
    text = cfg.path.read_text()
    assert secret not in text and "revision: 1" in text
    client = Client.from_config(cfg)
    try:
        assert client.post("version", {})["version"] == "0.2.0"
    finally:
        client.close()
    assert proxy.log[-1][1].startswith("Basic ")
    result = network_proxy.test_connection(cfg, {"mode": "manual", "url": proxy.url, "username": "svc"}, "wrong")
    assert result["kind"] == "proxy_auth_required" and not result["ok"]
    assert network_proxy.public_status(cfg) == {"mode": "manual", "url": proxy.url, "bypass": [],
                                                "username": "svc", "password_saved": True}
    assert secret not in caplog.text and secret not in json.dumps(result)
    network_proxy.clear(cfg)
    assert store == {} and "network" not in Config.load(cfg.path)


def test_connection_test_reports_success_without_saving(tmp_path, certificates, tls_servers, make_proxy):
    urls, _ = tls_servers
    proxy = make_proxy()
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"), server_url=urls["named"],
                 ca_cert=str(certificates / "ca.crt"), sensor_token="issued-token")
    cfg.save()
    result = network_proxy.test_connection(cfg, {"mode": "manual", "url": proxy.url})
    assert result["ok"] and result["message"].startswith("Reached the OpenAIDR server through the proxy in ")
    unreachable = network_proxy.test_connection(cfg, {"mode": "manual", "url": f"http://127.0.0.1:{dead_port()}"})
    assert unreachable["kind"] == "proxy_unreachable"
    assert "network" not in Config.load(cfg.path)


@pytest.mark.parametrize("failure", ["refused", "stalled", "auth_required", "slow"])
@pytest.mark.parametrize("owner", [None, "sensor"])
def test_proxy_failures_fail_open_within_the_hook_deadline(tmp_path, certificates, tls_servers, make_proxy,
                                                          store, failure, owner):
    urls, _ = tls_servers
    proxy_url = {"refused": lambda: f"http://127.0.0.1:{dead_port()}",
                 "stalled": lambda: make_proxy(stall=True).url,
                 "auth_required": lambda: make_proxy(auth="svc:pw").url,
                 "slow": lambda: make_proxy(delay=1.2).url}[failure]()
    cfg = configure(tmp_path, certificates, urls["named"], proxy_url)
    sensor = Sensor(cfg)
    kwargs = {}
    if owner:
        kwargs = dict(timeout_owner=owner, execution_id=uuid.uuid4().hex, started_ns=time.time_ns(),
                      deadline_ns=time.time_ns() + 2_100_000_000)
    try:
        started = time.monotonic()
        result = sensor.hooks.evaluate(PROMPT, **kwargs)
        elapsed = time.monotonic() - started
    finally:
        sensor.hook_clients.close()
        sensor.client.close()
        sensor.spool.close()
    assert result == {"decision": "allow", "claude_code": {}, "output": {}, "failed": True}
    assert elapsed < 2.1


def test_root_installs_reject_proxy_passwords(monkeypatch, tmp_path):
    monkeypatch.setattr(proxy_credentials, "is_root", lambda: True)
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"))
    with pytest.raises(ValueError, match="system-wide installations"):
        network_proxy.save(cfg, {"mode": "manual", "url": "http://p:3128", "username": "svc"}, "pw")
    assert not cfg.path.exists()


def test_free_mode_transport_reaches_the_server_through_the_proxy(tmp_path, certificates, tls_servers, make_proxy):
    import asyncio
    import ssl

    import httpx

    urls, requests = tls_servers
    proxy = make_proxy()
    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"))
    assert network_proxy.async_transport(cfg, "https://api.opensecura.ai") is None  # unchanged without a setting
    network_proxy.save(cfg, {"mode": "manual", "url": proxy.url, "bypass": ["api.internal.example"]})
    assert network_proxy.async_transport(cfg, "https://api.internal.example") is None
    trust = ssl.create_default_context(cafile=str(certificates / "ca.crt"))
    transport = network_proxy.async_transport(cfg, urls["named"], trust)

    async def twice():
        # Free-mode helpers reuse one transport across clients that close it.
        for _ in range(2):
            async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
                assert (await client.post(urls["named"] + "/ingest/v1/version", json={})).json()["version"] == "0.2.0"

    asyncio.run(twice())
    assert len(proxy.connects()) == 2 and len(requests) == 2


def test_bridge_proxy_actions_save_restart_and_route_without_exposing_passwords(tmp_path, store, monkeypatch):
    from openaidr.sensor import bridge

    restarts = []
    monkeypatch.setattr(bridge, "status", lambda config: {"running": True, "foreground": False})
    monkeypatch.setattr(bridge.service, "manage", lambda action, config, **_: restarts.append(action))
    path = tmp_path / "sensor.yaml"
    Config(path, data_dir=str(tmp_path / "data")).save()

    def call(action, **params):
        return bridge.handle({"action": action, "config_path": str(path), "params": params})

    assert call("proxy.status") == {"mode": "default"}
    saved = call("proxy.save", mode="manual", url="http://proxy.example:3128", username="svc@corp",
                 password="p@ss:w/rd", bypass=["internal.example"])
    assert saved == {"mode": "manual", "url": "http://proxy.example:3128", "bypass": ["internal.example"],
                     "username": "svc@corp", "password_saved": True}
    assert restarts == ["restart"] and "p@ss" not in path.read_text()
    assert call("proxy.route", url="https://releases.opensecura.ai/openaidr/rollout-v2.json") == {
        "proxy": "http://svc%40corp:p%40ss%3Aw%2Frd@proxy.example:3128"}
    with pytest.raises(ValueError, match="unsupported proxy route"):
        call("proxy.route", url="https://attacker.example/")
    with pytest.raises(ValueError, match="unknown action parameter"):
        call("proxy.save", mode="direct", server_url="https://attacker.example")
    with pytest.raises(ValueError, match="http:// or https://"):
        call("proxy.save", mode="manual", url="socks5://proxy.example:1080")
    monkeypatch.setattr(bridge, "status", lambda config: {"running": False})
    assert call("proxy.save", mode="direct") == {"mode": "direct"} and restarts == ["restart"]
    assert store == {}  # replacing the authenticated proxy removed its password
    assert call("proxy.route", url="https://releases.opensecura.ai/openaidr/rollout-v2.json") == {"proxy": None}
