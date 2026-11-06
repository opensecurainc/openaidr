"""Real managed CLI fixtures. No replacement adapter, executor, or gate lives here.

The receiver is the real app on TCP with a real PostgreSQL schema. Only external
inference and the user's native environment are synthetic. Native baselines use
the same saved configuration as the production managed CLI acceptance tests.
"""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import dataclass
import errno
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import sys
from threading import Condition, Event, Lock, Thread
from types import SimpleNamespace
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

import httpx
import pytest
import uvicorn

try:
    import pty
    import termios
except ImportError:
    pty = termios = None

from openaidr.sensor.config import Config as SensorConfig
from openaidr.server import auth
from openaidr.server.app import create_app
from openaidr.server.config import Config
from test_inline_guardrail import Provider as JevProvider
from test_store import sensor, tenant

from managed_cli_provider import AnthropicFixtureProxy, FakeProvider, Text, TOKENS


ROOT = Path(__file__).resolve().parents[1]
PINS = {
    "codex": {
        "path": "/opt/homebrew/Caskroom/codex/0.160.0/bin/codex",
        "version": "codex-cli 0.160.0",
        "sha256": "112fae7a5a1223e673c8a1791d32338f37df8b527ff1159bb8adac6c4dbf1b4b",
    },
    "claude": {
        "path": "/Users/panhu/.local/share/claude/versions/2.1.287",
        "version": "2.1.287 (Claude Code)",
        "sha256": "6eab8333fe2121553100d8f40bfada384a3e989b94f947e18ba6677a6fcb41ea",
    },
}


def pinned_binary(product):
    pin = PINS[product]
    binary = Path(pin["path"])
    if not binary.is_file():
        pytest.skip(f"Pinned native client is not installed: {pin['version']}")
    with binary.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    assert actual == pin["sha256"], "Native test pin changed"
    version = subprocess.check_output(
        [str(binary), "--version"], text=True, timeout=10
    ).strip()
    assert version == pin["version"], "Native test version changed"
    return binary


class _ReceiverServer(uvicorn.Server):
    """Expose a startup barrier without replacing the application lifespan."""

    def __init__(self, config):
        super().__init__(config)
        self.listening = Event()

    async def startup(self, sockets=None):
        await super().startup(sockets=sockets)
        self.listening.set()


@contextmanager
def live_receiver(db, monkeypatch):
    """Shape matches existing HTTP helpers, but every request crosses real TCP."""
    own_tenant, other_tenant = tenant(db), tenant(db)
    password = "synthetic-fixture-password"
    password_hash = auth.hash_password(password)
    users = {
        "admin": db.create_user(
            own_tenant["id"], "admin@example.test", "Admin", password_hash, "owner"
        ),
        "owner": db.create_user(
            own_tenant["id"], "owner@example.test", "Owner", password_hash, "viewer"
        ),
        "foreign": db.create_user(
            other_tenant["id"],
            "foreign@example.test",
            "Foreign",
            password_hash,
            "owner",
        ),
    }
    sensors = {
        "sensor": sensor(db, own_tenant["id"]),
        "peer_sensor": sensor(db, own_tenant["id"]),
        "foreign_sensor": sensor(db, other_tenant["id"]),
    }
    provider = JevProvider()
    with ExitStack() as cleanup, monkeypatch.context() as patch:
        tmp_path = Path(cleanup.enter_context(TemporaryDirectory(prefix="intelligence-managed-")))
        listener = cleanup.enter_context(socket.socket())
        listener.bind(("127.0.0.1", 0))
        base_url = f"http://127.0.0.1:{listener.getsockname()[1]}"
        from intelligence_fixture import intelligence_service
        api = cleanup.enter_context(intelligence_service(patch, tmp_path, own_tenant["id"],
                                                         provider.handle, guardrail_key="synthetic-guardrail-key"))
        cfg = Config(
            database_url=db.url,
            public_url=base_url,
            cost_processing=False,
            inline_guardrails=True,
            **api.config,
        )
        cfg.set_services("api,ingest")
        app = create_app(cfg, db)
        server = _ReceiverServer(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                log_level="error",
                access_log=False,
                proxy_headers=False,
                lifespan="on",
                timeout_graceful_shutdown=5,
            )
        )
        failures = []

        def run():
            try:
                server.run(sockets=[listener])
            except BaseException as exc:
                failures.append(exc)
                server.listening.set()

        thread = Thread(target=run, name="pr9-real-receiver", daemon=True)
        thread.start()
        try:
            assert server.listening.wait(10), "Real receiver startup timed out"
            assert not failures and server.started, "Real receiver failed to start"
            client = cleanup.enter_context(
                httpx.Client(base_url=base_url, trust_env=False, timeout=15)
            )
            headers = {}
            for name, user in users.items():
                if name == "foreign":
                    headers[name] = {"Cookie": auth.CONSOLE_COOKIE + "=" + db.create_session(user["id"], user["tenant_id"]),
                                     auth.CSRF_HEADER: "1", "Origin": base_url}
                    continue
                # Exercise real login and CSRF, not direct auth-session insertion.
                login = client.post(
                    "/api/v1/auth/login",
                    json={"email": user["email"], "password": password},
                    headers={auth.CSRF_HEADER: "1", "Origin": base_url},
                )
                assert login.status_code == 200, login.text
                headers[name] = {
                    "Cookie": auth.CONSOLE_COOKIE
                    + "="
                    + client.cookies.get(auth.CONSOLE_COOKIE),
                    auth.CSRF_HEADER: "1",
                    "Origin": base_url,
                }
                client.cookies.clear()
            headers.update(
                {
                    name: {"Authorization": "Bearer " + token}
                    for name, (_, token, _) in sensors.items()
                }
            )
            assert app.state.service.inline_guardrail is not None
            yield SimpleNamespace(
                db=db,
                app=app,
                client=client,
                cfg=cfg,
                provider=provider,
                headers=headers,
                users=users,
                sensors=sensors,
                tenant=own_tenant,
                settings=None,
                base_url=base_url,
            )
        finally:
            provider.release()
            server.should_exit = True
            thread.join(10)
            assert not thread.is_alive(), "Fixture receiver failed to stop"
            assert not failures, "Fixture receiver thread failed"


def sensor_config(system, directory, *, capture=None):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    record, token, _ = system.sensors["sensor"]
    cfg = SensorConfig(
        directory / "sensor.yaml",
        server_url=system.base_url,
        sensor_id=str(record["id"]),
        tenant_id=str(system.tenant["id"]),
        sensor_token=token,
        auth_mode="bearer",
        data_dir=str(directory / "data"),
    )
    if capture is not None:
        cfg["capture"] = capture
    cfg.save()
    return cfg.path


@contextmanager
def collector_sender(monkeypatch, config, product, patterns):
    """Real collector and sender, restricted to the synthetic user's files."""
    from openaidr.sensor import hostinfo
    from openaidr.sensor.runtime import Sensor

    daemon_config = SensorConfig(config.path, **deepcopy(dict(config)))
    daemon_config.update(
        listen="127.0.0.1:0",
        telemetry={"enabled": False},
        inventory={"enabled": False},
        component_inventory={"enabled": False},
        collectors={
            "backfill": True,
            product.replace("-", "_"): {"enabled": True, "paths": patterns},
        },
    )
    with monkeypatch.context() as patch:
        patch.setattr(hostinfo, "homes", lambda: [])
        sensor = Sensor(daemon_config)
    stop, errors = Event(), []

    def send():
        try:
            sensor.ship_loop(stop)
        except BaseException as exc:
            errors.append(exc)

    worker = Thread(target=send, name="managed-collector-sender", daemon=True)
    worker.start()
    try:
        yield sensor
    finally:
        stop.set()
        sensor.ship_wake.set()
        worker.join(5)
        sensor.offsets.flush()
        sensor.spool.close()
        sensor.client.close()
        assert not worker.is_alive() and not errors


class ResponseGate:
    def __init__(self, suffix, *, drop=False):
        self.suffix, self.drop = suffix, drop
        self.entered, self.release = Event(), Event()
        self.claimed = False


class ReceiverRelay:
    """A network fault fixture that holds replies after the real DB commit.

    Records contain route/status only. This never simulates a receiver decision
    or modifies authentication; revocation tests change real receiver state.
    """

    def __init__(self, upstream):
        parsed = urlsplit(upstream)
        assert parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
        self.upstream = upstream
        self.condition = Condition()
        self.lock = Lock()
        self.gates, self.records, self.failures = [], [], []
        self.unavailable = False
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler())
        self.server.daemon_threads = True
        self.thread = Thread(
            target=self.server.serve_forever, name="pr9-receiver-relay", daemon=True
        )

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def hold_response(self, suffix, *, drop=False):
        gate = ResponseGate(suffix, drop=drop)
        with self.lock:
            self.gates.append(gate)
        return gate

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        for gate in self.gates:
            gate.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        assert not self.thread.is_alive()
        assert not self.failures, "Receiver relay failed"

    def handler(self):
        relay = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                route = urlsplit(self.path)
                length = int(self.headers.get("Content-Length", "0"))
                if (
                    route.scheme
                    or route.netloc
                    or route.query
                    or not route.path.startswith("/ingest/v1/")
                    or not 0 <= length <= 8 << 20
                ):
                    self.send_error(403)
                    return
                if relay.unavailable:
                    self.send_response(503)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"{}")
                    self.close_connection = True
                    return
                try:
                    headers = {
                        key: value
                        for key, value in self.headers.items()
                        if key.lower()
                        not in {
                            "host",
                            "content-length",
                            "connection",
                            "proxy-authorization",
                        }
                    }
                    with httpx.Client(trust_env=False, timeout=15) as client:
                        response = client.post(
                            relay.upstream + route.path,
                            content=self.rfile.read(length),
                            headers=headers,
                        )
                    with relay.condition:
                        relay.records.append(
                            {
                                "method": "POST",
                                "path": route.path,
                                "status": response.status_code,
                            }
                        )
                        relay.condition.notify_all()
                    with relay.lock:
                        gate = next(
                            (
                                item
                                for item in relay.gates
                                if not item.claimed and route.path.endswith(item.suffix)
                            ),
                            None,
                        )
                        if gate:
                            gate.claimed = True
                    if gate:
                        gate.entered.set()
                        if not gate.release.wait(15):
                            raise TimeoutError("Receiver reply gate was not released")
                        if gate.drop:
                            self.close_connection = True
                            return
                    self.send_response(response.status_code)
                    self.send_header(
                        "Content-Type",
                        response.headers.get("Content-Type", "application/json"),
                    )
                    self.send_header("Content-Length", str(len(response.content)))
                    if "Cache-Control" in response.headers:
                        self.send_header(
                            "Cache-Control", response.headers["Cache-Control"]
                        )
                    self.end_headers()
                    self.wfile.write(response.content)
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True
                except BaseException as exc:
                    relay.failures.append(exc)
                    self.close_connection = True

        return Handler


class ObservedProcess:
    """Observe actual child bytes, including non-line-delimited stderr/progress."""

    def __init__(
        self,
        argv,
        *,
        cwd,
        env,
        artifact_dir,
        limit=16 << 20,
        controlling_terminal=False,
        interactive=False,
    ):
        self.artifact_dir = Path(artifact_dir)
        self.artifact_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.condition = Condition()
        self.buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self.closed = set()
        self.errors = []
        self.terminal = None
        inherited = []
        if controlling_terminal:
            if pty is None:
                pytest.skip("native managed terminal fixture requires POSIX")
            self.terminal, slave = pty.openpty()
            attributes = termios.tcgetattr(slave)
            attributes[3] &= ~termios.ECHO
            termios.tcsetattr(slave, termios.TCSANOW, attributes)
            inherited.append(slave)
            # Establish a controlling terminal in a fresh child interpreter.
            # Avoid unsafe preexec_fn callbacks in this threaded HTTP fixture.
            argv = [
                sys.executable,
                "-c",
                (
                    "import fcntl,os,sys,termios; "
                    "fcntl.ioctl(int(sys.argv[1]),termios.TIOCSCTTY,0); "
                    "os.execv(sys.argv[2],sys.argv[2:])"
                ),
                str(slave),
                *argv,
            ]
        self.process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=slave if interactive else subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            pass_fds=inherited,
        )
        for fd in inherited:
            os.close(fd)
        if self.terminal is not None:
            self.buffers["terminal"] = bytearray()
        self.readers = []
        for channel in self.buffers:
            fd = (
                self.terminal
                if channel == "terminal"
                else getattr(self.process, channel).fileno()
            )

            def read(name=channel, source=fd):
                try:
                    while data := os.read(source, 65536):
                        with self.condition:
                            if len(self.buffers[name]) + len(data) > limit:
                                raise RuntimeError(
                                    "Fixture child output exceeded its bound"
                                )
                            self.buffers[name].extend(data)
                            self.condition.notify_all()
                except BaseException as exc:
                    if not (
                        name == "terminal"
                        and isinstance(exc, OSError)
                        and exc.errno == errno.EIO
                    ):
                        self.errors.append(exc)
                finally:
                    with self.condition:
                        self.closed.add(name)
                        self.condition.notify_all()

            reader = Thread(target=read, name="pr9-child-" + channel, daemon=True)
            reader.start()
            self.readers.append(reader)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def send(self, data):
        if self.process.stdin is None:
            self.send_terminal(data)
            return
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def send_json(self, value):
        self.send(json.dumps(value).encode() + b"\n")

    def send_terminal(self, data):
        assert self.terminal is not None
        os.write(self.terminal, data)

    def output(self, channel="stdout"):
        with self.condition:
            return bytes(self.buffers[channel])

    def records(self):
        # Partial records are not silently treated as display content.
        return [json.loads(line) for line in self.output().split(b"\n")[:-1] if line]

    def wait_record(self, predicate, timeout=30):
        found = []

        def ready():
            found[:] = [record for record in self.records() if predicate(record)]
            return bool(found or self.errors or "stdout" in self.closed)

        with self.condition:
            assert self.condition.wait_for(ready, timeout), (
                "Native protocol barrier timed out"
            )
            assert not self.errors and found, (
                "Native child closed before the protocol barrier"
            )
            return found[-1]

    def wait_bytes(self, value, *, channel="stdout", timeout=30):
        with self.condition:
            assert self.condition.wait_for(
                lambda: (
                    value in self.buffers[channel]
                    or self.errors
                    or channel in self.closed
                ),
                timeout,
            ), "Child display barrier timed out"
            assert value in self.buffers[channel] and not self.errors

    def crash(self):
        # Snapshot only this fixture's descendants before killing the wrapper.
        # Native clients create their own process groups. Cleanup here does not
        # assert that the product contains detached native descendants.
        parents = [
            tuple(map(int, line.split()))
            for line in subprocess.check_output(
                ["ps", "-axo", "pid=,ppid="],
                text=True,
                timeout=5,
            ).splitlines()
            if line.strip()
        ]
        owned = {self.process.pid}
        while added := {pid for pid, parent in parents if parent in owned} - owned:
            owned.update(added)
        self.process.kill()
        self.process.wait(timeout=5)
        for pid in owned - {self.process.pid}:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def close(self):
        try:
            if self.process.stdin is not None:
                self.process.stdin.close()
        except (BrokenPipeError, ValueError):
            pass
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            # Only our fixture-owned process group. This is cleanup, not a
            # product guarantee about detached native descendants.
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
        for reader in self.readers:
            reader.join(3)
            assert not reader.is_alive(), "Fixture child retained an output pipe"
        if self.terminal is not None:
            os.close(self.terminal)
        for name in self.buffers:
            if name == "terminal":
                # Registration challenges can be displayed only here. The test
                # can use one in memory, but it never becomes a raw artifact.
                self.buffers[name].clear()
                continue
            path = self.artifact_dir / (name + ".raw")
            path.write_bytes(self.output(name))
            path.chmod(0o600)
        assert not self.errors, "Fixture child reader failed"


@dataclass
class NativeProfile:
    product: str
    binary: Path
    workspace: Path
    config: Path
    env: dict
    provider: FakeProvider
    artifact_dir: Path
    settings: dict
    proxy: object = None

    def assert_settings_unchanged(self):
        for path, value in self.settings.items():
            assert path.read_bytes() == value, "Native saved settings were modified"

    def terminate_native(self, child):
        candidates = [
            str(self.binary),
            str(Path(self.env["PATH"].split(":")[0]) / self.product),
        ]
        native = []
        for row in subprocess.check_output(
            ["ps", "-axo", "pid=,ppid=,command="], text=True, timeout=5
        ).splitlines():
            pid, parent, command = row.strip().split(maxsplit=2)
            if int(parent) == child.process.pid and any(
                command == path or command.startswith(path + " ") for path in candidates
            ):
                native.append(int(pid))
        assert len(native) == 1, "Expected this fixture's one actual native child"
        os.kill(native[0], signal.SIGTERM)

    def probe_legacy_observer(self, sensor_config_path):
        from openaidr.guardrail.hook_bridge import ENVIRONMENT_KEY

        directory = Path(SensorConfig.load(sensor_config_path)["data_dir"])
        bridges = list((directory / "managed").glob("launch-*/*-bridge.json"))
        assert len(bridges) == 1
        malformed = self.artifact_dir / "invalid-sensor.yaml"
        malformed.write_text("[not valid yaml")
        nonce = b"PRIVATE_LEGACY_OBSERVER_941682"
        payload = nonce + b"x" * ((4 << 20) + 1)
        command = [
            str(ROOT / ".venv/bin/openaidr-sensor"),
            "hook",
            "PreToolUse",
            "--agent",
            self.product,
            "--config",
            str(malformed),
        ]
        environment = {**self.env, ENVIRONMENT_KEY: str(bridges[0])}
        completed = subprocess.run(
            command,
            input=payload,
            capture_output=True,
            env=environment,
            cwd=self.workspace,
            timeout=5,
            check=True,
        )
        assert json.loads(completed.stdout) == {} and not completed.stderr
        assert all(
            nonce not in path.read_bytes()
            for path in directory.rglob("*")
            if path.is_file()
        )
        environment[ENVIRONMENT_KEY] = str(self.artifact_dir / "missing-bridge.json")
        denied = subprocess.run(
            command,
            input=b"{}",
            capture_output=True,
            env=environment,
            cwd=self.workspace,
            timeout=5,
            check=True,
        )
        assert (
            json.loads(denied.stdout)["hookSpecificOutput"]["permissionDecision"]
            == "deny"
        )

    def install_existing_hooks(self, sensor_config_path):
        """A synthetic user with existing daemon and unrelated native hooks."""
        from openaidr.sensor import hooks

        script = self.artifact_dir / "user_hook.py"
        log = self.artifact_dir / "user-hooks.jsonl"
        script.write_text(
            "import json,sys\n"
            "value=json.load(sys.stdin)\n"
            "with open(sys.argv[1],'a') as output:\n"
            " output.write(json.dumps({'event':value.get('hook_event_name'),'tool':value.get('tool_name')})+'\\n')\n"
            "print('{}')\n"
        )
        handler = {
            "type": "command",
            "command": shlex.join([sys.executable, str(script), str(log)]),
            "timeout": 10,
        }
        group = {"hooks": [handler]}
        executable = str(ROOT / ".venv/bin/openaidr-sensor")
        if self.product == "codex":
            hook_path, config_path = (
                self.config / "hooks.json",
                self.config / "config.toml",
            )
            hook_path.write_text(
                json.dumps({"hooks": {"PreToolUse": [group], "PostToolUse": [group]}})
            )
            with config_path.open("a") as stream:
                for event in ("PreToolUse", "PostToolUse"):
                    key = f"{hook_path}:{hooks.CODEX_EVENT_LABELS[event]}:0:0"
                    stream.write(
                        "\n[hooks.state."
                        + json.dumps(key)
                        + "]\ntrusted_hash="
                        + json.dumps(hooks.codex_hook_hash(event, group, handler))
                        + "\n"
                    )
            hooks.install_codex(
                hook_path,
                executable,
                config_toml=config_path,
                config_path=sensor_config_path,
            )
            self.settings.update(
                {
                    hook_path: hook_path.read_bytes(),
                    config_path: config_path.read_bytes(),
                }
            )
        else:
            config_path = self.config / "settings.json"
            values = json.loads(config_path.read_text())
            values["hooks"] = {"PreToolUse": [group], "PostToolUse": [group]}
            config_path.write_text(json.dumps(values))
            hooks.install(
                config_path, executable, agent="claude", config_path=sensor_config_path
            )
            self.settings[config_path] = config_path.read_bytes()
        return log

    def baseline(self):
        args = (
            [str(self.binary), "app-server", "--stdio"]
            if self.product == "codex"
            else [
                str(self.binary),
                "-p",
                "--verbose",
                "--input-format",
                "stream-json",
                "--output-format",
                "stream-json",
                "--permission-prompt-tool",
                "stdio",
            ]
        )
        return ObservedProcess(
            args,
            cwd=self.workspace,
            env=self.env,
            artifact_dir=self.artifact_dir / "native",
        )

    def baseline_catalog(self):
        """Record unmediated native schemas under the identical user profile."""
        script = self.provider.turns
        self.provider.turns = [[Text("NATIVE_CATALOG_BASELINE")]]
        try:
            with self.baseline() as child:
                if self.product == "codex":
                    child.send_json(
                        {
                            "id": "init",
                            "method": "initialize",
                            "params": {
                                "clientInfo": {
                                    "name": "native_fixture",
                                    "version": "1",
                                },
                                "capabilities": {"experimentalApi": True},
                            },
                        }
                    )
                    assert "result" in child.wait_record(
                        lambda item: item.get("id") == "init"
                    )
                    child.send_json({"method": "initialized"})
                    child.send_json(
                        {
                            "id": "thread",
                            "method": "thread/start",
                            "params": {"cwd": str(self.workspace)},
                        }
                    )
                    started = child.wait_record(
                        lambda item: item.get("id") == "thread"
                    )["result"]
                    child.send_json(
                        {
                            "id": "turn",
                            "method": "turn/start",
                            "params": {
                                "threadId": started["thread"]["id"],
                                "input": [
                                    {
                                        "type": "text",
                                        "text": "NATIVE_BASELINE_PROMPT",
                                        "text_elements": [],
                                    }
                                ],
                            },
                        }
                    )
                    done = child.wait_record(
                        lambda item: item.get("method") == "turn/completed"
                    )
                    assert done["params"]["turn"]["status"] == "completed"
                    assert started["approvalPolicy"] == "on-request"
                    assert started["sandbox"]["type"] == "readOnly"
                else:
                    child.send_json(
                        {
                            "type": "control_request",
                            "request_id": "init",
                            "request": {"subtype": "initialize"},
                        }
                    )
                    child.send_json(
                        {
                            "type": "user",
                            "message": {
                                "role": "user",
                                "content": "NATIVE_BASELINE_PROMPT",
                            },
                            "session_id": "",
                        }
                    )
                    done = child.wait_record(lambda item: item.get("type") == "result")
                    assert done["is_error"] is False
                child.wait_bytes(b"NATIVE_CATALOG_BASELINE")
            assert len(self.provider.model_requests) == 1
            return self.provider.model_requests[0]["body"]
        finally:
            self.provider.turns = script
            self.provider.requests.clear()
            self.provider.model_requests.clear()
            self.provider.auxiliary_requests.clear()
            self.provider.headers.clear()
            self.provider.stream_started.clear()

    def managed(
        self,
        config_path,
        *,
        controlling_terminal=True,
        native_args=(),
        reconcile=False,
        interactive=False,
    ):
        # This deliberately invokes only the production entry point. There is
        # no fixture adapter fallback when the PR9 command is unavailable.
        args = [
            str(ROOT / ".venv/bin/openaidr"),
            "managed",
            self.product,
            "--config",
            str(config_path),
            "--cwd",
            str(self.workspace),
        ]
        if reconcile:
            args.append("--reconcile")
        if native_args:
            args.extend(["--", *native_args])
        return ObservedProcess(
            args,
            cwd=self.workspace,
            env=self.env,
            artifact_dir=self.artifact_dir / "managed",
            controlling_terminal=controlling_terminal,
            interactive=interactive,
        )


@contextmanager
def native_profile(directory, product, *, turns=None, split_first=False, builtin=False):
    """A synthetic *user* profile, with native permissions and tools unchanged."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    binary = pinned_binary(product)
    home, config, workspace, scratch, binaries = [
        directory / name for name in ("home", "config", "workspace", "tmp", "bin")
    ]
    for path in (home, config, workspace, scratch, binaries):
        path.mkdir(mode=0o700)
    (binaries / product).symlink_to(binary)
    env = {
        "PATH": str(binaries) + ":/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home),
        "USER": "fixture",
        "TERM": "dumb",
        "TMPDIR": str(scratch),
        "NO_PROXY": "127.0.0.1,localhost",
    }
    turns = turns or [[Text("PR9_NATIVE_FINAL_NONCE")]]
    with ExitStack() as cleanup:
        proxy = None
        if product == "codex":
            # This saved synthetic provider is the same native configuration in
            # baseline and managed runs, not a launcher-imposed replacement.
            provider = cleanup.enter_context(
                FakeProvider(
                    directory / "provider",
                    turns,
                    product=product,
                    split_first=split_first,
                )
            )
            path = config / "config.toml"
            if builtin:
                path.write_text(
                    f'model="gpt-6.1-sol"\nopenai_base_url="{provider.base_url}/v1"\n'
                )
                (config / "auth.json").write_text(
                    json.dumps({"OPENAI_API_KEY": TOKENS[product]})
                )
            else:
                path.write_text(
                    'model="gpt-6.1-sol"\nmodel_provider="configured_fixture"\nmodel_reasoning_effort="medium"\n'
                    '[model_providers.configured_fixture]\nname="Synthetic user provider"\n'
                    f'base_url="{provider.base_url}/v1"\n'
                    'wire_api="responses"\nrequires_openai_auth=false\nsupports_websockets=false\n'
                    'env_key="FIXTURE_CODEX_API_KEY"\nhttp_headers={"X-User-Literal"="PR9_NATIVE_LITERAL"}\n'
                    'env_http_headers={"X-User-Env"="FIXTURE_CODEX_HEADER"}\nquery_params={"fixture_version"="1"}\n'
                )
            env.update(
                CODEX_HOME=str(config),
                FIXTURE_CODEX_API_KEY=TOKENS[product],
                FIXTURE_CODEX_HEADER="PR9_NATIVE_ENV",
            )
            sink = provider.base_url
            settings = {path: path.read_bytes()}
        else:
            provider = cleanup.enter_context(
                FakeProvider(
                    directory / "provider",
                    turns,
                    product=product,
                    split_first=split_first,
                )
            )
            cert, key = directory / "cert.pem", directory / "key.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-subj",
                    "/CN=api.anthropic.com",
                    "-addext",
                    "subjectAltName=DNS:api.anthropic.com",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            key.chmod(0o600)
            proxy = AnthropicFixtureProxy(provider, cert, key)
            cleanup.callback(proxy.close)
            path = config / "settings.json"
            path.write_text(
                json.dumps(
                    {
                        "model": "claude-sonnet-4-6",
                        "env": {"FIXTURE_CONFIG_NONCE": "PR9_NATIVE_ENV"},
                    }
                )
            )
            (config / ".claude.json").write_text(
                json.dumps({"hasCompletedOnboarding": True})
            )
            env.update(
                CLAUDE_CONFIG_DIR=str(config),
                ANTHROPIC_API_KEY=TOKENS[product],
                NODE_EXTRA_CA_CERTS=str(cert),
                SSL_CERT_FILE=str(cert),
            )
            sink = proxy.url
            settings = {path: path.read_bytes()}
        env.update(HTTP_PROXY=sink, HTTPS_PROXY=sink, ALL_PROXY=sink)
        profile = NativeProfile(
            product,
            binary,
            workspace,
            config,
            env,
            provider,
            directory,
            settings,
            proxy,
        )
        try:
            yield profile
        finally:
            provider.stream_release.set()
            profile.assert_settings_unchanged()
