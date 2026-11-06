"""Exercise the desktop runtime bridge with real files and HTTP enrollment."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tarfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from openaidr.sensor import bridge, local_runtime as runtime, removal
from openaidr.sensor.config import Config

TENANT = "01000000-0000-7000-8000-000000000001"
TOKEN = "oaet_" + "a" * 43


def test_bundled_runtime_contains_only_production_api_endpoints():
    pattern = re.compile(rb'https://api[^/\s"\x27]*\.opensecura\.ai')
    origins = set()
    with tarfile.open(runtime.ARCHIVE) as archive:
        assert "src/openaidr/sensor/local_runtime_source.tar.gz" not in archive.getnames()
        for member in archive:
            if not member.isfile():
                continue
            data = archive.extractfile(member).read()
            if member.name.endswith(".whl"):
                with zipfile.ZipFile(io.BytesIO(data)) as wheel:
                    for name in wheel.namelist():
                        origins.update(pattern.findall(wheel.read(name)))
            else:
                origins.update(pattern.findall(data))
    assert origins == {b"https://api.opensecura.ai"}


def test_runtime_bundle_does_not_retain_an_older_embedded_archive(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[1] / "scripts/bundle_local_runtime.py"
    monkeypatch.syspath_prepend(str(script.parent))
    source_commit = runpy.run_path(str(script))["SOURCE"]
    source, output = tmp_path / "source.tar.gz", tmp_path / "bundle.tar.gz"
    files = {"README.md": b"Public runtime", "src/openaidr/server/intelligence.py": b"# production routing",
             "src/openaidr/sensor/local_runtime_source.tar.gz": b"obsolete embedded source"}
    with tarfile.open(source, "w:gz") as archive:
        for path, data in files.items():
            member = tarfile.TarInfo(f"openaidr-{source_commit}/{path}")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    result = subprocess.run([sys.executable, str(script), str(source), str(output)],
                            check=True, capture_output=True, text=True)
    first = output.read_bytes()
    assert result.stdout.strip() == hashlib.sha256(first).hexdigest()
    with tarfile.open(output) as archive:
        assert set(archive.getnames()) == {"README.md", "src/openaidr/server/intelligence.py"}
        assert archive.extractfile("src/openaidr/server/intelligence.py").read() == files["src/openaidr/server/intelligence.py"]
    subprocess.run([sys.executable, str(script), str(source), str(output)], check=True, capture_output=True)
    assert output.read_bytes() == first


@pytest.fixture
def local(tmp_path, monkeypatch):
    config = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"))
    fixture = dict(running=False, owned=False, remote=False, failure=False, log=[], docker_log=[], engine=True, password="existing-secret")
    monkeypatch.setattr(runtime.docker_setup, 'desktop', lambda: None)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.reply({"mode": "local", "password_login": fixture["running"]})

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or "{}")
            fixture["log"].append((self.path, payload))
            if self.path.endswith("auth/login"):
                valid = payload["password"] == fixture["password"]
                self.reply({}, 200 if valid else 401,
                           fixture.get("cookie", "openaidr_session=oass_" + "a" * 43 + "; Path=/; HttpOnly; SameSite=Lax") if valid else None)
            elif self.path.endswith("auth/logout"):
                self.reply({})
            elif self.path.endswith("enrollment-links"):
                self.reply({"enrollment_url": fixture.get("enrollment_origin", runtime.ORIGIN) + "/enroll#token=" + TOKEN})
            elif self.path.endswith("enrollment/preview"):
                self.reply({"tenant": {"id": TENANT, "name": "Local workspace"}, "auth_mode": "bearer", "expires_at": "2099-01-01T00:00:00Z"})
            else:
                self.reply({"sensor_id": "sensor-1", "sensor_token": "device-only-secret", "tenant": {"id": TENANT, "name": "Local workspace"}, "config": {}})

        def reply(self, data, code=200, cookie=None):
            data = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Match the IPv4 listener instead of trying localhost's IPv6 address first.
    monkeypatch.setattr(runtime, "ORIGIN", f"http://{server.server_address[0]}:{server.server_port}")
    monkeypatch.setattr(runtime.shutil, "which", lambda _: sys.executable)

    def docker(args, **kwargs):
        fixture['docker_log'].append(args)
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert not any(key.startswith(("OPENAIDR_", "COMPOSE_", "DOCKER_CONTEXT")) for key in kwargs["env"])
        value = ""
        if args[1:3] == ["context", "inspect"]:
            value = [{"Endpoints": {"docker": {"Host": "ssh://other-host" if fixture["remote"] else "unix:///test.sock"}}}]
        elif 'info' in args and (not fixture['engine'] or args[2] == fixture.get('unavailable_host')):
            return subprocess.CompletedProcess(args, 1, b'')
        elif "ps" in args:
            value = "container-id" if fixture["owned"] and (fixture["running"] or "--all" in args) else ""
        elif "inspect" in args:
            value = [{"State": {"Running": True}, "NetworkSettings": {"Ports": {"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}}}]
        elif "build" in args:
            if fixture["failure"]:
                raise subprocess.TimeoutExpired(args, 1800)
        elif "stop" in args:
            fixture["running"] = False
        elif "up" in args:
            env = dict(line.split("=", 1) for line in (runtime.directory(config) / ".env").read_text().splitlines())
            fixture.update(owned=True, running=True, password=env["OPENAIDR_ADMIN_PASSWORD"])
        return subprocess.CompletedProcess(args, 0, (value if isinstance(value, str) else json.dumps(value)).encode())

    monkeypatch.setattr(runtime.subprocess, "run", docker)
    fixture["call"] = lambda action, **params: bridge.handle({"action": "local-runtime." + action, "config_path": str(config.path), "params": params})
    try:
        yield config, fixture
    finally:
        server.shutdown(); server.server_close(); thread.join()


def test_new_runtime_preserves_secrets_on_retry_and_enrolls_over_http(local, monkeypatch):
    config, fixture = local
    monkeypatch.setenv("OPENAIDR_BIND_ADDRESS", "0.0.0.0")
    call = fixture["call"]
    assert call("check")["docker_ready"]
    fixture["failure"] = True
    with pytest.raises(ValueError, match="did not finish"):
        call("prepare")
    before = runtime.credentials(config)
    fixture["failure"] = False
    assert call("prepare") == {"prepared": True}
    assert runtime.credentials(config) == before
    assert hashlib.sha256(runtime.ARCHIVE.read_bytes()).hexdigest() == runtime.ARCHIVE_SHA256
    if os.name != "nt":
        assert (runtime.directory(config) / ".env").stat().st_mode & 0o777 == 0o600
    assert "OPENAIDR_BIND_ADDRESS=127.0.0.1" in (runtime.directory(config) / ".env").read_text()
    assert call("start")["running"]
    assert call("connect")["enrolled"]
    assert Config.load(config.path)["server_url"] == runtime.ORIGIN
    assert Config.load(config.path)["tenant_id"] == TENANT
    assert call("check")["connected"]
    assert before["password"] not in json.dumps(call("check"))
    enrollments = sum(path.endswith('/enroll') for path, _ in fixture["log"])
    assert call("connect")["enrolled"]
    assert sum(path.endswith('/enroll') for path, _ in fixture["log"]) == enrollments
    fixture["log"].clear()
    handoff = call("dashboard")
    assert handoff["managed"] and handoff["session"] == "oass_" + "a" * 43
    assert len(handoff["nonce"]) == 43
    assert call("dashboard")["nonce"] != handoff["nonce"]
    assert before["password"] not in json.dumps(handoff)
    assert [path for path, _ in fixture["log"]] == ["/api/v1/auth/login"] * 2


def test_existing_runtime_requires_authorization_and_cannot_redirect_enrollment(local):
    config, fixture = local
    fixture["running"] = True
    call = fixture["call"]
    assert call("dashboard") == {"managed": False}
    assert not fixture["log"]
    assert call("check")["existing"] and not call("check")["managed"]
    with pytest.raises(ValueError, match="already exists"):
        call("prepare")
    for password in ("", "wrong"):
        with pytest.raises(ValueError, match="password"):
            call("connect", password=password)
        assert not config.path.exists()
    fixture["enrollment_origin"] = "https://other.example"
    with pytest.raises(ValueError, match="different server"):
        call("connect", password=fixture["password"])
    assert not config.path.exists()
    del fixture["enrollment_origin"]
    assert call("connect", password=fixture["password"])["enrolled"]


def test_remote_context_and_unknown_bridge_parameters_are_rejected(local):
    _, fixture = local
    fixture["remote"] = True
    call = fixture["call"]
    assert not call("check")["docker_ready"]
    with pytest.raises(ValueError, match="remote Docker engine"):
        call("prepare")
    for action in ("check", "docker-setup", "prepare", "start", "connect", "credentials", "dashboard"):
        with pytest.raises(ValueError, match="unknown action parameter"):
            call(action, server_url="https://other.example")


@pytest.mark.parametrize("cookie", [None, "openaidr_session=invalid; Path=/",
    "openaidr_session=oass_" + "a" * 43 + "; Domain=127.0.0.1; Path=/",
    "openaidr_session=oass_" + "a" * 43 + "; Path=/other",
    "openaidr_session=oass_" + "a" * 43 + "; Path=/; Secure"])
def test_dashboard_rejects_invalid_session_without_exposing_credentials(local, cookie):
    config, fixture = local
    call = fixture["call"]
    call("prepare")
    call("start")
    fixture["cookie"] = cookie
    with pytest.raises(ValueError, match="Could not sign in") as error:
        call("dashboard")
    assert runtime.credentials(config)["password"] not in str(error.value)


def test_dashboard_requires_owned_runtime_and_valid_saved_password(local):
    _, fixture = local
    call = fixture["call"]
    call("prepare")
    call("start")
    fixture["owned"] = False
    with pytest.raises(ValueError, match="Start your local runtime"):
        call("dashboard")
    assert not fixture["log"]
    fixture.update(owned=True, password="changed-password")
    with pytest.raises(ValueError, match="Could not sign in"):
        call("dashboard")


def test_mac_start_selects_local_desktop_without_changing_remote_context(local, monkeypatch, tmp_path):
    config, fixture = local
    fixture.update(remote=True, engine=False)
    monkeypatch.setattr(runtime.docker_setup.sys, 'platform', 'darwin')
    monkeypatch.setattr(runtime.docker_setup.platform, 'machine', lambda: 'arm64')
    monkeypatch.setattr(runtime.docker_setup, 'desktop', lambda: tmp_path / 'Docker.app')
    monkeypatch.setattr(runtime.docker_setup, 'desktop_host', lambda: 'unix:///Users/example/.docker/run/docker.sock')
    native = []

    def start(args, **kwargs):
        native.append(args)
        fixture['engine'] = True

    monkeypatch.setattr(runtime.docker_setup, 'native', start)
    assert fixture['call']('check')['docker_action'] == 'start'
    assert fixture['call']('docker-setup')['docker_ready']
    assert native == [['/usr/bin/open', '-a', str(tmp_path / 'Docker.app')]]
    fixture['call']('prepare')
    assert runtime.state(config)['docker_host'] == runtime.docker_setup.desktop_host()
    assert all('ssh://other-host' not in args and 'use' not in args for args in fixture['docker_log'])


def test_saved_engine_is_not_replaced_by_another_ready_engine(local, monkeypatch, tmp_path):
    config, fixture = local
    fixture['call']('prepare')
    fixture['unavailable_host'] = 'unix:///test.sock'
    monkeypatch.setattr(runtime.docker_setup.sys, 'platform', 'darwin')
    monkeypatch.setattr(runtime.docker_setup.platform, 'machine', lambda: 'arm64')
    monkeypatch.setattr(runtime.docker_setup, 'desktop', lambda: tmp_path / 'Docker.app')
    monkeypatch.setattr(runtime.docker_setup, 'native', lambda *a, **k: pytest.fail('Must preserve the selected engine'))
    assert fixture['call']('check')['docker_action'] == 'manual'
    with pytest.raises(ValueError, match='not responding'):
        fixture['call']('docker-setup')
    assert runtime.state(config)['docker_host'] == 'unix:///test.sock'


def test_docker_start_timeout_is_retryable_and_does_not_create_runtime(local, monkeypatch, tmp_path):
    config, fixture = local
    fixture['engine'] = False
    monkeypatch.setattr(runtime.docker_setup.sys, 'platform', 'darwin')
    monkeypatch.setattr(runtime.docker_setup.platform, 'machine', lambda: 'arm64')
    monkeypatch.setattr(runtime.docker_setup, 'desktop', lambda: tmp_path / 'Docker.app')
    monkeypatch.setattr(runtime.docker_setup, 'native', lambda *a, **k: None)
    with monkeypatch.context() as clock:
        from itertools import count
        elapsed = count(0, 181)
        clock.setattr(runtime.time, 'monotonic', lambda: next(elapsed))
        with pytest.raises(ValueError, match='not ready'):
            fixture['call']('docker-setup')
    assert not (runtime.directory(config) / 'state.json').exists()
    fixture['engine'] = True
    assert fixture['call']('docker-setup')['docker_ready']


@pytest.mark.parametrize("extracted", [False, True])
def test_publication_cleanup_preserves_previous_runtime_identity_and_data(local, monkeypatch, extracted):
    config, fixture = local
    fixture["call"]("prepare")
    root = runtime.directory(config)
    before = json.loads((root / "state.json").read_text())
    previous = runtime.SOURCE
    marker = root / "source" / "retained-data-marker"
    marker.write_text("keep existing source")
    if not extracted:
        shutil.rmtree(root / "source")
    monkeypatch.setattr(runtime, "SOURCE", "new-reviewed-source")
    monkeypatch.setattr(runtime, "COMPATIBLE_SOURCES", (previous,))
    monkeypatch.setattr(runtime, "SOURCE_TIME", "1800000000")
    fixture["call"]("prepare")
    saved = runtime.state(config)
    assert saved["env"]["POSTGRES_PASSWORD"] == before["env"]["POSTGRES_PASSWORD"]
    assert saved["env"]["OPENAIDR_FREE_SECRET"] == before["env"]["OPENAIDR_FREE_SECRET"]
    if extracted:
        assert saved == before and marker.read_text() == "keep existing source"
    else:
        assert saved["source"] == saved["env"]["OPENAIDR_BUILD_COMMIT"] == "new-reviewed-source"
        assert saved["env"]["OPENAIDR_COMMIT_TIMESTAMP"] == "1800000000"
    assert fixture["call"]("start")["running"]


@pytest.mark.parametrize("upgraded", [False, True])
def test_reinstall_restarts_retained_runtime_before_restoring_collection(local, monkeypatch, upgraded):
    config, fixture = local
    for action in ("prepare", "start", "connect"):
        fixture["call"](action)
    before = (runtime.directory(config) / "state.json").read_bytes()
    config = Config.load(config.path)
    monkeypatch.setattr(removal.service.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(removal, "is_root", lambda: False)
    removal.marker(config).write_text(json.dumps({
        "state": "complete", "errors": [], "preferences": {"hooks": [], "telemetry": []},
    }))
    runtime.cleanup(config)
    assert not fixture["running"]
    fixture["engine"] = False
    with pytest.raises(ValueError, match="not responding"):
        removal.resume(config)
    assert removal.marker(config).exists()
    fixture["engine"] = True
    if upgraded:
        monkeypatch.setattr(runtime, "SOURCE", "new-desktop-source")
        monkeypatch.setattr(runtime, "COMPATIBLE_SOURCES", ())
        with pytest.raises(ValueError, match="configuration is unavailable"):
            runtime.start(config)
    assert removal.resume(config)["resumed"]
    assert fixture["running"] and runtime.connected(config)
    assert fixture["call"]("dashboard")["managed"]
    assert fixture["call"]("credentials")["password"] == fixture["password"]
    assert (runtime.directory(config) / "state.json").read_bytes() == before
