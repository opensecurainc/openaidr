"""Ordinary hooks use backend decisions and silently allow unavailable checks."""

import copy
import json
import os
from pathlib import Path
import threading
import time
import uuid
from types import SimpleNamespace

import pytest

from openaidr.sensor import hook_runtime, hooks
from openaidr.sensor.config import Config
from openaidr.sensor.runtime import hook_actions


@pytest.mark.parametrize("capture_input", [True, False])
@pytest.mark.parametrize("product", ["codex-cli", "claude-code"])
def test_hook_directory_metadata_with_transcript_collection(tmp_path, backend_hook, capture_input, product):
    from openaidr.sensor.runtime import Sensor

    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                 server_url="http://127.0.0.1:9", sensor_id=str(uuid.uuid4()), sensor_token="test",
                 collectors={product.replace("-", "_"): {"enabled": True}})
    sensor = Sensor(cfg)
    try:
        sensor.capture["tool_input"] = capture_input
        sensor.hooks.check = backend_hook()
        common = {"session_id": "root", "cwd": "/work/project", "hook_event_name": "SessionStart"}
        sensor.hooks.evaluate(common, product)
        sensor.hooks.evaluate({**common, "hook_event_name": "PreToolUse", "tool_name": "Bash",
                              "tool_input": {"command": "echo secret-input"}}, product)
        events = sensor.spool.read()["events"]
        assert [e["kind"] for e in events] == ["session.start", "hook.decision"]
        assert all(e["session"] == {"id": "root", **({"cwd": "/work/project"} if capture_input else {})} for e in events)
        assert "secret-input" not in json.dumps(events)
    finally:
        sensor.client.close()
        sensor.hook_clients.close()
        sensor.telemetry.close()
        sensor.spool.close()


def test_codex_subagent_hooks_record_explicit_parent_without_guessing_child_directory(tmp_path):
    emitted = []
    server = hooks.HookServer("127.0.0.1:0", tmp_path / "sock", emitted.append, lambda: {}, {}, emit_actions=False)
    common = {"session_id": "parent", "cwd": "/parent/workspace", "agent_id": "child"}
    for event in ("SubagentStart", "SubagentStop"):
        assert server.evaluate({**common, "hook_event_name": event}, "codex-cli")["decision"] == "allow"
    assert [e["kind"] for e in emitted] == ["session.start", "session.end"]
    assert all(e["session"] == {"id": "child", "parent_id": "parent"} for e in emitted)
    assert {"SubagentStart", "SubagentStop"} <= hooks.CODEX_EVENTS.keys()


@pytest.mark.parametrize("capture_input", [True, False])
def test_subagent_hook_keeps_managed_capture_restrictions(tmp_path, capture_input):
    from openaidr.guardrail.journal import Journal
    from openaidr.sensor.runtime import Sensor

    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                 server_url="http://127.0.0.1:9", sensor_id=str(uuid.uuid4()), sensor_token="test")
    sensor = Sensor(cfg)
    epoch = str(uuid.uuid4())
    capture = {**sensor.capture, "prompt_text": False, "tool_input": False}
    launch = sensor.managed_capture.begin("codex-cli", capture, epoch)
    binding = {"server_url": cfg["server_url"], "tenant_id": str(uuid.uuid4()),
               "sensor_id": cfg["sensor_id"], "product": "codex-cli", "session_id": "parent",
               "registration_id": None, "epoch_id": epoch}
    journal = Journal(tmp_path / "data" / "managed" / epoch, binding)
    try:
        launch.publish(journal)
        sensor.capture["tool_input"] = capture_input
        sensor.hooks.evaluate({"hook_event_name": "SubagentStart", "session_id": "parent",
                               "cwd": "/work/private", "agent_id": "child"}, "codex-cli")
        sensor.emit({"kind": "prompt", "agent": {"product": "codex-cli"},
                     "session": {"id": "child"}, "source": {"collector": "hook"},
                     "text": "private child prompt"})
        assert sensor.spool.read() is None
        child = sensor.managed_capture.route("codex-cli", "child")
        assert child is not None
        child_journal = Journal(child["journal"], json.loads(child["binding"]))
        try:
            retained = json.dumps(child_journal.pending())
            assert "private child prompt" not in retained
            assert "/work/private" not in retained
        finally:
            child_journal.close()
    finally:
        journal.close()
        launch.end()
        sensor.client.close()
        sensor.hook_clients.close()
        sensor.telemetry.close()
        sensor.spool.close()


@pytest.mark.parametrize("product,event,shape", [
    ("codex-cli", "PreToolUse", "permission"),
    ("claude-code", "PreToolUse", "permission"),
    ("codex-cli", "UserPromptSubmit", "block"),
    ("claude-code", "UserPromptSubmit", "block"),
    ("codex-cli", "PostToolUse", "block"),
    ("claude-code", "PostToolUse", "replacement"),
])
@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_backend_decisions_at_native_boundaries(tmp_path, backend_hook, product, event, shape, mode):
    emitted = []
    check = backend_hook(action="deny", mode=mode)
    server = hooks.HookServer("127.0.0.1:0", tmp_path / "sock", emitted.append, lambda: {}, {}, check=check)
    payload = {"session_id": "s", "hook_event_name": event, "tool_name": "Bash",
               "tool_input": {"command": "ls"}, "prompt": "inspect files",
               "tool_response": {"stdout": "original content", "stderr": "", "interrupted": False, "isImage": False}}
    result = server.evaluate(payload, product, result_supported=True, execution_id=uuid.uuid4().hex)
    assert check.requests[0]["hook_event"] == event
    assert result["decision"] == ("allow" if mode == "shadow" else "deny")
    decision = emitted[-1]["hook"]
    assert decision["decision"] == result["decision"]
    assert decision["evaluated_decision"] == "deny"
    assert decision["delivery"] == "pending" and server.stats["denied"] == 0
    output = result["output"]
    if mode == "shadow":
        assert output == {}
    elif shape == "permission":
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    elif shape == "block":
        assert output == {"decision": "block", "reason": "Test policy reason"}
    else:
        assert output["hookSpecificOutput"]["updatedToolOutput"] == {
            "stdout": "Test policy reason", "stderr": "", "interrupted": False, "isImage": False,
        }
    assert "original content" not in json.dumps(output)


@pytest.mark.parametrize("failure", ["missing", "exception", "mode", "version", "identity", "deadline", "unknown_result", "failed_tool"])
@pytest.mark.parametrize("product", ["claude-code", "workbuddy"])
def test_unavailable_backend_never_becomes_native_restriction(tmp_path, backend_hook, failure, product):
    reply = backend_hook(action="deny")

    def check(request, deadline):
        if failure == "exception":
            raise TimeoutError("private error")
        result = reply(request, deadline)
        if failure == "mode":
            result["mode"] = "shadow"
        elif failure == "version":
            result["policy_version"] = "1"
        elif failure == "identity":
            result["id"] = "not-a-uuid"
        return result

    emitted = []
    server = hooks.HookServer("127.0.0.1:0", tmp_path / "sock", emitted.append, lambda: {}, {},
                              check=None if failure == "missing" else check)
    event = {"unknown_result": "PostToolUse", "failed_tool": "PostToolUseFailure"}.get(failure, "PreToolUse")
    result = server.evaluate({"session_id": "s", "hook_event_name": event, "tool_name": "Bash",
                              "tool_input": {"command": "rm -rf /"}, "tool_response": "unknown schema"}, product,
                             deadline_ns=time.time_ns() - 1 if failure == "deadline" else None)
    assert result == {"decision": "allow", "claude_code": {}, "output": {}, "failed": True}
    assert emitted[-1]["hook"]["decision"] == "allow"
    assert "evaluated_decision" not in emitted[-1]["hook"]
    if failure in ("unknown_result", "failed_tool"):
        assert reply.requests[-1]["availability"] == "unsupported_boundary"


def test_slow_backend_does_not_serialize_other_hooks(tmp_path, backend_hook):
    entered, release = threading.Event(), threading.Event()
    reply = backend_hook(action="deny")

    def check(request, deadline):
        if request["session_id"] == "slow":
            entered.set()
            assert release.wait(3)
        return reply(request, deadline)

    server = hooks.HookServer("127.0.0.1:0", tmp_path / "sock", lambda _: None, lambda: {}, {}, check=check)
    payload = {"session_id": "slow", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}
    worker = threading.Thread(target=server.evaluate, args=(payload,), daemon=True)
    worker.start()
    try:
        assert entered.wait(1)
        assert server.evaluate(dict(payload, session_id="fast"))["decision"] == "deny"
    finally:
        release.set()
        worker.join(3)


@pytest.mark.parametrize("action", ["allow", "deny"])
@pytest.mark.parametrize("elapsed", [0.7, 0.95])
def test_caller_deadline_reserves_delivery_and_discards_late_decisions(tmp_path, monkeypatch, backend_hook, action, elapsed):
    clock = [100.0]
    monkeypatch.setattr(hooks, "time", SimpleNamespace(
        monotonic=lambda: clock[0], perf_counter=lambda: clock[0],
        time_ns=lambda: int(clock[0] * 1e9),
    ))
    reply = backend_hook(action=action)
    deadlines = []

    def check(request, deadline):
        deadlines.append(deadline)
        clock[0] += elapsed
        return reply(request, deadline)

    server = hooks.HookServer("127.0.0.1:0", tmp_path / "sock", lambda _: None, lambda: {}, {}, check=check)
    result = server.evaluate(
        {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}},
        started_ns=99_600_000_000, deadline_ns=101_000_000_000,
    )
    assert deadlines == [pytest.approx(100.9)]
    if elapsed == 0.95:
        assert result == {"decision": "allow", "claude_code": {}, "output": {}, "failed": True}
    else:
        assert result["decision"] == action and not result.get("failed")
        assert bool(result["output"]) == (action == "deny")


@pytest.mark.parametrize("event,category", [("PreToolUse", "tool_input"), ("UserPromptSubmit", "prompt_text"), ("PostToolUse", "tool_output")])
@pytest.mark.parametrize("restriction", ["disabled", "redacted", "truncated", "none"])
def test_remote_capture_sends_permitted_evidence_with_explicit_gaps(event, category, restriction):
    capture = dict(prompt_text=True, tool_input=True, tool_output=True, raw=False, redact=True, max_text_bytes=1024)
    if restriction == "disabled":
        capture[category] = False
    if restriction == "truncated":
        capture["max_text_bytes"] = 3
    text = "password=top-secret-password" if restriction == "redacted" else "echo public"
    action = {"kind": {"PreToolUse": "command", "UserPromptSubmit": "prompt", "PostToolUse": "tool.result"}[event],
              "session": {"id": "s", "cwd": "/repo"}, "agent": {"product": "codex-cli"}}
    if event == "PreToolUse":
        action.update(command={"text": text}, tool={"name": "Bash", "input": {"command": text}})
    elif event == "PostToolUse":
        action["tool"] = {"name": "Bash", "output": text}
    else:
        action["text"] = text
    request = {"product": "codex-cli", "hook_event": event, "availability": "available", "actions": [action]}
    original = copy.deepcopy(request)
    availability, actions = hook_actions(request, capture)
    assert request == original
    if restriction == "none":
        assert availability == "available" and actions
    else:
        assert availability == {"disabled": "capture_disabled", "redacted": "content_redacted", "truncated": "content_truncated"}[restriction]
        if restriction == "disabled":
            assert actions == []
        else:
            assert actions
            assert "sk-" + "a" * 48 not in json.dumps(actions)


@pytest.mark.skipif(os.name == "nt", reason="Capability fixture uses POSIX executables")
def test_result_capability_binds_installed_version_and_native_executable(tmp_path, monkeypatch):
    cfg = Config(tmp_path / "config", data_dir=str(tmp_path / "data"))
    cfg.save()
    native = tmp_path / "codex"
    native.write_text("#!/bin/sh\necho codex-cli 0.160.0\n")
    native.chmod(0o700)
    monkeypatch.setattr(hooks.shutil, "which", lambda _: str(native))
    hooks.record_result_capability(cfg.path, "codex")
    parent = SimpleNamespace(exe=lambda: str(native), parent=lambda: None)
    monkeypatch.setattr(hooks.psutil, "Process", lambda: SimpleNamespace(parent=lambda: parent))
    assert hooks.result_capable(cfg, "codex")
    native.write_text("#!/bin/sh\necho codex-cli 0.9.0\n")
    assert not hooks.result_capable(cfg, "codex")
    hooks.record_result_capability(cfg.path, "codex")
    assert not hooks.result_capable(cfg, "codex")
    native.write_text("#!/bin/sh\necho unknown\n")
    hooks.record_result_capability(cfg.path, "codex")
    assert not hooks.result_capable(cfg, "codex")


@pytest.mark.skipif(os.name == "nt", reason="npm capability fixture uses POSIX executables")
def test_npm_codex_capability_checks_wrapper_and_native_binary(tmp_path, monkeypatch):
    import shutil
    import subprocess

    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed to test the official npm package resolver")
    system, arch = subprocess.check_output([node, "-p", "process.platform + ':' + process.arch"], text=True).strip().split(":")
    cpu = {"x64": "x86_64", "arm64": "aarch64"}[arch]
    target = {"linux": f"{cpu}-unknown-linux-musl", "darwin": f"{cpu}-apple-darwin"}[system]
    packages = tmp_path / "node_modules" / "@openai"
    package = packages / "codex"
    launcher = package / "bin" / "codex.js"
    launcher.parent.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": "@openai/codex"}))
    launcher.write_text("#!/usr/bin/env node\nconsole.log('codex-cli 0.160.0');\n")
    launcher.chmod(0o700)
    platform_package = packages / f"codex-{system}-{arch}"
    native = platform_package / "vendor" / target / "bin" / "codex"
    native.parent.mkdir(parents=True)
    (platform_package / "package.json").write_text("{}")
    native.write_text("#!/bin/sh\necho codex-cli 0.160.0\n")
    native.chmod(0o700)
    cfg = Config(tmp_path / "config", data_dir=str(tmp_path / "data"))
    cfg.save()
    real_which = shutil.which
    monkeypatch.setattr(hooks.shutil, "which", lambda name: str(launcher) if name == "codex" else real_which(name))
    parent = SimpleNamespace(exe=lambda: str(native), parent=lambda: None)
    monkeypatch.setattr(hooks.psutil, "Process", lambda: SimpleNamespace(parent=lambda: parent))
    hooks.record_result_capability(cfg.path, "codex")
    assert hooks.result_capable(cfg, "codex")
    launcher.write_text(launcher.read_text() + "// replaced wrapper\n")
    assert not hooks.result_capable(cfg, "codex")
    hooks.record_result_capability(cfg.path, "codex")
    assert hooks.result_capable(cfg, "codex")
    native.write_text("#!/bin/sh\necho codex-cli 0.161.0\n")
    assert not hooks.result_capable(cfg, "codex")
    hooks.record_result_capability(cfg.path, "codex")
    assert not hooks.result_capable(cfg, "codex"), "Mismatched wrapper and native versions must be unavailable"
    (platform_package / "package.json").unlink()
    hooks.record_result_capability(cfg.path, "codex")
    assert not hooks.result_capable(cfg, "codex"), "Unknown package layouts must be unavailable"


@pytest.mark.parametrize("mode", ["shadow", "enforce", "unavailable", "capture_disabled", "home_redacted", "home_truncated"])
def test_sensor_backend_wire_contract(tmp_path, backend_hook, mode, monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from httpcore._sync import http11
    from openaidr.sensor.runtime import Sensor

    requests = []
    peers = []
    clock = [0.0]
    monkeypatch.setattr(http11, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    class Backend(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((body, self.headers.get("Authorization")))
            peers.append(self.client_address)
            unavailable = mode not in ("shadow", "enforce")
            reply = {"error": {"code": "unavailable"}}
            if not unavailable:
                reply = backend_hook(action="deny", mode=mode)(body, None)
                reply["request_id"] = body["request_id"]
            data = json.dumps(reply).encode()
            self.send_response(503 if unavailable else 200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    backend = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    worker = threading.Thread(target=backend.serve_forever, daemon=True)
    worker.start()
    cfg = Config(tmp_path / "config", server_url=f"http://127.0.0.1:{backend.server_port}",
                 sensor_id="s", sensor_token="test-token", data_dir=str(tmp_path / "data"),
                 telemetry={"enabled": False}, inventory={"enabled": False})
    cache = Path(cfg["data_dir"]) / "policy.json"
    cache.parent.mkdir(parents=True)
    stored = json.dumps({"rules": [{"id": "local", "enabled": True, "action": "deny", "match": {"path_glob": "**"}}]})
    cache.write_text(stored)
    sensor = Sensor(cfg)
    if mode == "capture_disabled":
        sensor.capture["tool_input"] = False
    try:
        execution = uuid.uuid4().hex
        payload = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Read",
                   "tool_input": {"file_path": "/home/alice/public"}, "cwd": "/repo"}
        path_home = {"home_redacted": "/home/password=top-secret-password", "home_truncated": "/" + "a" * 5000}.get(mode, "/home/alice")
        # The first connection survives 119 idle seconds, then expires after
        # another 121. Each request must still obtain a fresh policy decision.
        for idle in (0, 119, 121):
            clock[0] += idle
            result = sensor.hooks.evaluate(payload, execution_id=execution, path_home=path_home)
            assert result["decision"] == ("deny" if mode == "enforce" else "allow")
            assert bool(result["output"]) == (mode == "enforce")
        assert cache.read_text() == stored
        assert len(requests) == 3
        assert len({body["request_id"] for body, _ in requests}) == 3
        if mode in ("shadow", "enforce"):
            assert peers[0] == peers[1] and peers[2] != peers[1]
        for body, authorization in requests:
            assert authorization == "Bearer test-token"
            assert 1 <= body["timeout_ms"] <= 1800
            assert str(uuid.UUID(body["request_id"])) == body["request_id"]
            assert body["product"] == "claude-code" and body["session_id"] == "s"
            suppressed = {"capture_disabled": "capture_disabled", "home_redacted": "content_redacted", "home_truncated": "content_truncated"}
            if mode in suppressed:
                assert body["availability"] == suppressed[mode] and body["actions"] == []
                assert "path_home" not in body and "/home/alice/public" not in json.dumps(body)
            else:
                assert body["actions"][0]["file"]["path"] == "/home/alice/public"
                assert body["path_home"] == "/home/alice"
                assert "source" not in body["actions"][0]
    finally:
        sensor.hook_clients.close()
        sensor.spool.close()
        sensor.client.close()
        backend.shutdown()
        backend.server_close()
        worker.join(2)


@pytest.fixture
def pooled_hook_backend(tmp_path, backend_hook):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from openaidr.sensor.runtime import Sensor

    state = SimpleNamespace(requests=[], connections=set(), changed=threading.Condition(),
                            hold={}, entered={})

    class Backend(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            with state.changed:
                state.connections.add(self.client_address)
                state.changed.notify_all()

        def finish(self):
            try:
                super().finish()
            finally:
                with state.changed:
                    state.connections.discard(self.client_address)
                    state.changed.notify_all()

        def log_message(self, *_):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state.requests.append((body, self.headers.get("Authorization"), self.client_address))
            session = body["session_id"]
            if session in state.hold:
                state.entered[session].set()
                state.hold[session].wait(3)
            reply = backend_hook(action="deny", mode="enforce")(body, None)
            reply["request_id"] = body["request_id"]
            data = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    class Server(ThreadingHTTPServer):
        request_queue_size = 16

    backend = Server(("127.0.0.1", 0), Backend)
    worker = threading.Thread(target=backend.serve_forever, daemon=True)
    worker.start()
    cfg = Config(tmp_path / "config", server_url=f"http://127.0.0.1:{backend.server_port}",
                 sensor_id="s", sensor_token="old-token", data_dir=str(tmp_path / "data"),
                 telemetry={"enabled": False}, inventory={"enabled": False})
    sensor = Sensor(cfg)
    try:
        yield sensor, state
    finally:
        for hold in state.hold.values():
            hold.set()
        sensor.hook_clients.close()
        sensor.spool.close()
        sensor.client.close()
        backend.shutdown()
        backend.server_close()
        worker.join(2)


def test_hook_pool_bounds_deadlines_and_shutdown(pooled_hook_backend):
    from concurrent.futures import ThreadPoolExecutor

    sensor, state = pooled_hook_backend
    payload = dict(hook_event_name="UserPromptSubmit", prompt="Explain a socket")
    for i in range(8):
        state.hold[str(i)] = threading.Event()
        state.entered[str(i)] = threading.Event()
    with ThreadPoolExecutor(max_workers=8) as workers:
        pending = [workers.submit(sensor.hooks.evaluate, dict(payload, session_id=str(i))) for i in range(8)]
        try:
            assert all(entered.wait(1) for entered in state.entered.values())
            started = time.monotonic()
            execution = uuid.uuid4().hex
            result = sensor.hooks.evaluate(dict(payload, session_id="overflow"),
                                           execution_id=execution, deadline_ns=time.time_ns() + 100_000_000)
            assert result["decision"] == "allow" and result["output"] == {} and result["failed"]
            assert time.monotonic() - started < .5
            assert len(state.requests) == 8 and len(state.connections) == 8
            sensor.pending_hook_decisions.complete({"hook": {
                "execution_id": execution, "outcome": "failed", "exit_code": 22,
            }})
            receipts = [e for e in sensor.spool.read()["events"] if e["source"]["collector"] == "hook-delivery"]
            assert len(receipts) == 1
            assert receipts[0]["hook"] == {"delivery_status": "timed_out", "delivered_decision": "allow"}
        finally:
            for hold in state.hold.values():
                hold.set()
        assert all(request.result(timeout=2)["decision"] == "deny" for request in pending)
    with state.changed:
        assert state.changed.wait_for(lambda: len(state.connections) == 4, timeout=1)
    sensor.hook_clients.close()
    with state.changed:
        assert state.changed.wait_for(lambda: not state.connections, timeout=1)
    result = sensor.hooks.evaluate(dict(payload, session_id="closed"))
    assert result["decision"] == "allow" and result["output"] == {} and result["failed"]
    assert len(state.requests) == 8


@pytest.mark.parametrize("slow_setup", [False, True])
def test_hook_pool_rotates_without_blocking_other_hooks(pooled_hook_backend, monkeypatch, slow_setup):
    from concurrent.futures import ThreadPoolExecutor
    from openaidr.sensor import runtime

    sensor, state = pooled_hook_backend
    payload = dict(hook_event_name="UserPromptSubmit", prompt="Explain a socket")
    state.hold["slow"] = threading.Event()
    state.entered["slow"] = threading.Event()
    setup_entered, setup_release = threading.Event(), threading.Event()
    client_options = runtime.client_options

    def options(config):
        if slow_setup and config.get("sensor_token") == "new-token":
            setup_entered.set()
            setup_release.wait(3)
        return client_options(config)

    monkeypatch.setattr(runtime, "client_options", options)
    # Neither hook may wait for the heartbeat client's lock or the slow reply.
    with ThreadPoolExecutor(max_workers=2) as workers, sensor.client.lock:
        slow = workers.submit(sensor.hooks.evaluate, dict(payload, session_id="slow"))
        try:
            assert state.entered["slow"].wait(1)
            fast = workers.submit(sensor.hooks.evaluate, dict(payload, session_id="fast"))
            assert fast.result(timeout=1)["decision"] == "deny"
            with sensor.lock:
                sensor.config["sensor_token"] = "new-token"
            rotated = workers.submit(sensor.hooks.evaluate, dict(payload, session_id="rotated"))
            if slow_setup:
                assert setup_entered.wait(1)
                state.hold["slow"].set()
                assert slow.result(timeout=1)["decision"] == "deny"
                setup_release.set()
            assert rotated.result(timeout=1)["decision"] == "deny"
        finally:
            setup_release.set()
            state.hold["slow"].set()
        assert slow.result(timeout=1)["decision"] == "deny"
    by_session = {body["session_id"]: (auth, peer) for body, auth, peer in state.requests}
    assert by_session["slow"][0] == by_session["fast"][0] == "Bearer old-token"
    assert by_session["rotated"][0] == "Bearer new-token"
    assert len({peer for _, peer in by_session.values()}) == 3
    with state.changed:
        assert state.changed.wait_for(lambda: len(state.connections) == 1, timeout=1)


def test_receipts_use_the_durable_spool_without_waiting_for_network(tmp_path, monkeypatch):
    from openaidr.sensor.runtime import Sensor
    from openaidr.sensor.spool import Spool

    cfg = Config(tmp_path / "config", server_url="https://backend.example", sensor_id="s", sensor_token="token",
                 data_dir=str(tmp_path / "data"), telemetry={"enabled": False}, inventory={"enabled": False})
    sensor = Sensor(cfg)
    def unavailable(*args, **kwargs):
        pytest.fail("receipt collection must not call the backend")

    monkeypatch.setattr(sensor.client, "post", unavailable)
    event = {"kind": "hook.decision", "agent": {"product": "codex-cli"}, "session": {"id": "s"},
             "hook": {"check_id": str(uuid.uuid4()), "request_id": str(uuid.uuid4()),
                      "decision": "deny", "delivery": "delivered"}}
    try:
        sensor.delivered_hook_decision(event)
        assert sensor.hooks.stats["denied"] == 1
        batch = sensor.spool.read()
        decision, receipt = batch["events"]
        assert decision["hook"]["decision"] == "deny"
        assert receipt["source"] == {"collector": "hook-delivery", "hook_request_id": event["hook"]["request_id"]}
        assert receipt["hook"] == {"delivery_status": "delivered", "delivered_decision": "deny"}
        sensor.spool.close()
        reopened = Spool(sensor.spool.path)
        try:
            assert reopened.read()["events"] == batch["events"]
            reopened.ack(batch)
            assert reopened.depth == 0
        finally:
            reopened.close()
    finally:
        sensor.spool.close()
        sensor.client.close()


def test_client_network_timeout_records_request_without_backend_id(pooled_hook_backend):
    sensor, state = pooled_hook_backend
    state.hold["late"] = threading.Event()
    state.entered["late"] = threading.Event()
    execution = uuid.uuid4().hex
    started = time.monotonic()
    result = sensor.hooks.evaluate(
        {"session_id": "late", "hook_event_name": "UserPromptSubmit", "prompt": "Explain a socket"},
        execution_id=execution, deadline_ns=time.time_ns() + 500_000_000,
    )
    assert state.entered["late"].is_set()
    assert time.monotonic() - started < 1
    assert result == {"decision": "allow", "claude_code": {}, "output": {}, "failed": True}
    request = state.requests[0][0]
    sensor.pending_hook_decisions.complete({"hook": {"execution_id": execution, "outcome": "failed", "exit_code": 22}})
    receipts = [e for e in sensor.spool.read()["events"] if e["source"]["collector"] == "hook-delivery"]
    assert len(receipts) == 1
    assert receipts[0]["source"]["hook_request_id"] == request["request_id"]
    assert receipts[0]["hook"] == {"delivery_status": "timed_out", "delivered_decision": "allow"}


@pytest.mark.parametrize("duration", [1.8, 2.1])
@pytest.mark.parametrize("timeout_owner", ["agent", "sensor"])
def test_delivery_deadline_does_not_cancel_backend_transport(pooled_hook_backend, duration, timeout_owner):
    from concurrent.futures import ThreadPoolExecutor

    sensor, state = pooled_hook_backend
    state.hold["agent"] = threading.Event()
    state.entered["agent"] = threading.Event()
    completed = threading.Event()
    emit = sensor.hooks.emit

    def record(event):
        emit(event)
        if event["kind"] == "hook.decision":
            completed.set()

    sensor.hooks.emit = record
    started = time.time_ns()
    budget_ns = 2_100_000_000 if timeout_owner == "sensor" else 2_000_000_000
    with ThreadPoolExecutor(max_workers=1) as worker:
        result = worker.submit(
            sensor.hooks.evaluate,
            {"session_id": "agent", "hook_event_name": "UserPromptSubmit", "prompt": "Explain a socket"},
            started_ns=started, deadline_ns=started + budget_ns,
            execution_id=uuid.uuid4().hex, timeout_owner=timeout_owner,
        )
        assert state.entered["agent"].wait(1)
        time.sleep(duration)
        assert result.done() == (timeout_owner == "sensor" and duration > 2)
        assert not completed.is_set(), "Backend request must remain active after the delivery deadline"
        state.hold["agent"].set()
        response = result.result(timeout=2)
        assert completed.wait(2)
    if duration > 2:
        assert response == {"decision": "allow", "claude_code": {}, "output": {}, "failed": True}
        sensor.pending_hook_decisions.flush()
        receipt, = [e for e in sensor.spool.read()["events"] if e["source"]["collector"] == "hook-delivery"]
        assert receipt["hook"]["delivery_status"] == "timed_out"
    else:
        assert response["decision"] == "deny" and not response.get("failed")


@pytest.mark.skipif(os.name == "nt", reason="POSIX native launcher")
@pytest.mark.parametrize("completion", ["timely", "late", "cancelled"])
@pytest.mark.parametrize("action", ["allow", "deny"])
def test_native_hook_reports_timely_and_late_decisions(tmp_path, monkeypatch, backend_hook, completion, action):
    import tempfile
    from hook_process import run_hook
    from openaidr.sensor.runtime import Sensor
    from test_hooks_setup import hook_receipts, start_listener, wait_for

    monkeypatch.setattr(hooks, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(hooks, "is_root", lambda: False)
    monkeypatch.delenv("OPENAIDR_MANAGED_BRIDGE", raising=False)
    monkeypatch.delenv("OPENAIDR_SENSOR_CONFIG", raising=False)
    if completion == "timely" and action == "allow":
        import select
        import socket
        import socketserver

        write = socketserver._SocketWriter.write
        def close_after_headers(stream, data):
            if not data:
                # A 204 client may close after headers, before an empty body write.
                assert select.select([stream._sock], [], [], 2)[0]
                assert stream._sock.recv(1, socket.MSG_PEEK) == b""
            return write(stream, data)
        monkeypatch.setattr(socketserver._SocketWriter, "write", close_after_headers)

    with tempfile.TemporaryDirectory(dir="/tmp", prefix="hook-receipt-") as directory:
        cfg = Config(tmp_path / "config", data_dir=directory, sensor_id=str(uuid.uuid4()),
                     server_url="http://127.0.0.1:9", sensor_token="test",
                     telemetry={"enabled": False}, inventory={"enabled": False})
        cfg.save()
        sensor = Sensor(cfg)
        sensor.hooks.listen = "127.0.0.1:0"
        reply = backend_hook(action=action)
        release, finished = threading.Event(), threading.Event()
        requests = []

        def evaluate(request, deadline):
            requests.append(request)
            assert deadline - time.monotonic() > 2, "Resource limit must not cancel the agent's wait"
            if completion != "timely":
                assert release.wait(5)
                if completion == "late":
                    time.sleep(0.1)  # Finish after both agent and launcher start timestamps.
                else:
                    assert time.monotonic() - started < 2
            return reply(request, deadline)

        emit = sensor.hooks.emit
        def stage(event):
            emit(event)
            if event["kind"] == "hook.decision":
                finished.set()

        sensor.hooks.emit = stage
        sensor.hooks.check = evaluate
        health = tmp_path / "health"
        command = hooks.command_line("/unused/sensor", "PreToolUse", "codex", cfg.path, health_dir=health)
        stop, runner = start_listener(sensor.hooks)
        try:
            wait_for(sensor.hooks.socket_path.stat)
            started = time.monotonic()
            result = run_hook(["/bin/sh", "-c", command], text=True,
                              timeout=0.3 if completion == "cancelled" else 3,
                              input=json.dumps({"session_id": "s", "tool_name": "Bash",
                                                "tool_input": {"command": "echo ok"}}))
            failed = completion != "timely"
            assert result.timed_out == (completion == "cancelled")
            if failed:
                assert result.stdout == ""
                if completion == "late":
                    assert 2 <= time.monotonic() - started < 2.5
                    assert (result.returncode, result.stderr) == (0, "")
                    assert not finished.is_set(), "Backend work must outlive the silent allow"
                    measurement, = hook_receipts(health)
                    assert measurement["hook"]["outcome"] == "failed"
                    sensor.pending_hook_decisions.complete(measurement)
                else:
                    assert not list(health.glob("*.agent")), "Killed launcher cannot supply a receipt"
                release.set()
                assert finished.wait(2)
                if completion == "cancelled":
                    # The watchdog isolates its worker group. Killing only the
                    # agent group can leave the local connection alive briefly;
                    # no receipt means unconfirmed, not successful enforcement.
                    sensor.pending_hook_decisions.flush()
                    assert not any(e["source"]["collector"] == "hook-delivery"
                                   for e in sensor.spool.read()["events"])
                    assert sensor.pending_hook_decisions.entries
                    return
                sensor.pending_hook_decisions.flush()
            else:
                assert (result.returncode, result.stderr) == (0, "")
                if action == "deny":
                    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
                else:
                    assert result.stdout == ""
                # Keep this receipt case well inside the native deadline; the
                # late case above covers a backend that outlives the launcher.
                assert finished.wait(2)
                # A timely evaluation without its delivery receipt stays unconfirmed.
                sensor.pending_hook_decisions.flush()
                assert not any(e["source"]["collector"] == "hook-delivery" for e in sensor.spool.read()["events"])
                measurement, = hook_receipts(health)
                sensor.pending_hook_decisions.complete(measurement)
            events = sensor.spool.read()["events"]
            receipts = [e for e in events if e["source"]["collector"] == "hook-delivery"]
            assert len(receipts) == 1
            assert receipts[0]["source"]["hook_request_id"] == reply.requests[0]["request_id"]
            assert receipts[0]["hook"] == {
                "delivery_status": {"late": "timed_out", "timely": "delivered"}[completion],
                "delivered_decision": "allow" if failed else action,
            }
            if failed:
                runtime, = [e for e in events if e["source"]["collector"] == "hook-runtime"]
                assert runtime["hook"]["outcome"] == "failed"
                assert "exit_code" not in runtime["hook"], "Do not invent a process exit status"
                assert runtime["hook"]["failure_reason"] == (
                    "deadline_expired" if completion == "late" else "delivery_failed"
                )
                # Replayed disk evidence must use the same runtime ID as the
                # sensor's failure, so the backend counts this run once.
                execution = runtime["hook"]["execution_id"]
                (health / f"codex.PreToolUse.1900000000.22.{execution}.agent").touch()
                recorded = []
                hook_runtime.collect(health, recorded.append, sensor_id=cfg["sensor_id"])
                assert recorded[0]["id"] == runtime["id"]
            sensor.pending_hook_decisions.flush()
            assert len([e for e in sensor.spool.read()["events"] if e["source"]["collector"] == "hook-delivery"]) == 1
        finally:
            release.set()
            stop.set()
            runner.join(5)
            sensor.hook_clients.close()
            sensor.client.close()
            sensor.spool.close()


@pytest.mark.skipif(os.name == "nt", reason="Unix socket listener")
def test_disconnected_hook_records_failure_without_waiting_for_delivery(tmp_path, backend_hook):
    import socket
    import tempfile
    from urllib.parse import urlencode
    from test_hooks_setup import start_listener, wait_for

    entered, release, disconnected = threading.Event(), threading.Event(), threading.Event()
    decisions, receipts = [], []
    reply = backend_hook(action="deny")

    def check(request, deadline):
        entered.set()
        assert release.wait(4)
        return reply(request, deadline)

    def record(receipt):
        receipts.append(receipt)
        disconnected.set()

    with tempfile.TemporaryDirectory(dir="/tmp", prefix="hook-disconnect-") as directory:
        server = hooks.HookServer("127.0.0.1:0", Path(directory) / "sensor.sock",
                                  decisions.append, lambda: {}, {}, check=check, disconnected=record)
        stop, runner = start_listener(server)
        try:
            wait_for(server.socket_path.stat)
            started = time.time_ns()
            execution = uuid.uuid4().hex
            query = urlencode({"started": started, "deadline": started + 1_400_000_000,
                               "execution": execution, "timeout_owner": "sensor"})
            payload = json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": "test"}).encode()
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(str(server.socket_path))
                client.sendall((f"POST /v1/hooks/codex/native?{query} HTTP/1.1\r\n"
                                f"Host: localhost\r\nContent-Type: application/json\r\n"
                                f"Content-Length: {len(payload)}\r\n\r\n").encode() + payload)
                assert entered.wait(1)
            release.set()
            assert disconnected.wait(2)
            assert receipts == [{"hook": {"execution_id": execution, "outcome": "failed"}}]
            assert decisions[-1]["hook"]["delivery"] == "pending"
        finally:
            release.set()
            stop.set()
            runner.join(5)


def test_unbound_managed_session_never_uses_ordinary_backend(tmp_path, monkeypatch):
    from openaidr.sensor import runtime

    cfg = Config(tmp_path / "config", server_url="https://backend.example", sensor_id="s", sensor_token="token",
                 data_dir=str(tmp_path / "data"), telemetry={"enabled": False}, inventory={"enabled": False})
    sensor = runtime.Sensor(cfg)
    launch = sensor.managed_capture.begin("codex-cli", sensor.capture, str(uuid.uuid4()))

    def unexpected_transport(*args, **kwargs):
        pytest.fail("managed session content must not reach the ordinary transport")

    monkeypatch.setattr(runtime, "client_options", unexpected_transport)
    try:
        result = sensor.hooks.evaluate({"session_id": "unbound", "hook_event_name": "UserPromptSubmit",
                                        "prompt": "managed private content"}, "codex-cli")
        assert result["output"] == {} and result["decision"] == "allow" and result["failed"]
    finally:
        launch.end(started=False)
        sensor.spool.close()
        sensor.client.close()
