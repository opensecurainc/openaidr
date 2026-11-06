"""Retired launch commands and retained managed records through real receiver HTTP."""

from contextlib import closing
import json
import os
from pathlib import Path
import socketserver
import sqlite3
import subprocess
import sys
import threading

import pytest

from openaidr.core.event import new_id
from openaidr.core.protocol import default_sensor_config
from openaidr.sensor.config import Config
from managed_cli_fixtures import live_receiver, sensor_config
from test_approvals import sensor_post
from test_inline_guardrail import browser
from test_session_aggregation import registered
from test_store import db as db


BOUNDARIES = {
    "prompt": ["prompt"],
    "tool_call": ["tool.call", "command", "file.read", "file.write", "network"],
    "tool_output": ["tool.result"],
    "assistant_response": ["response"],
}


@pytest.fixture
def receiver(db, monkeypatch):
    with live_receiver(db, monkeypatch) as system:
        yield system


@pytest.mark.parametrize("product", ["codex", "claude"])
def test_new_managed_launches_redirect_to_installed_hooks_before_side_effects(
    monkeypatch, capsys, product
):
    from openaidr.sensor.cli import main

    def no_config(*args, **kwargs):
        raise AssertionError("retired launches must not read sensor configuration")

    monkeypatch.setattr(Config, "load", no_config)
    assert main(["managed", product, "--config", "/missing/sensor.yaml", "--", "--native-option"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "retired" in output.err
    assert "openaidr setup" in output.err
    assert "start codex or claude normally" in output.err
    assert "--reconcile" in output.err


@pytest.mark.parametrize("authorization_denied", [False, True])
def test_reconciliation_ignores_cached_rules_and_preserves_retained_records(
    receiver, tmp_path, authorization_denied
):
    from openaidr.guardrail.journal import Journal
    from openaidr.sensor.capture import CaptureCoordinator
    from openaidr.sensor.cli import main
    from test_inline_guardrail import event
    from test_managed_foundation import binding as journal_binding

    registration = registered(receiver)
    config_path = sensor_config(receiver, tmp_path / "sensor")
    config = Config.load(config_path)
    coordinator = CaptureCoordinator(config)
    capture = default_sensor_config()["capture"]
    captured = coordinator.begin(
        "codex-cli", capture, registration["delivery_epoch"], registration["id"]
    )
    directory = Path(config["data_dir"]) / "managed" / registration["delivery_epoch"]
    binding = {**journal_binding(receiver, registration), "server_url": receiver.base_url}
    target = event(registration)
    logical_id = target["evidence"]["logical_id"]
    with closing(Journal(directory, binding)) as journal:
        captured.publish(journal)
        captured.verify(sensor_post(receiver, f"session-registrations/{registration['id']}/status"))
        journal.prepare(logical_id, "hmac-sha256-v1:" + "a" * 64, target, {}, "deny")
        # Historical cached rules can be unreadable and must remain untouched.
        for key in ("policy", "context_policy"):
            journal.connection.execute("INSERT INTO metadata VALUES(?,?)", (key, b"invalid cached policy"))
        if authorization_denied:
            journal.deny_authorization()
    captured.end()
    old_caches = [Path(config["data_dir"]) / name for name in ("policy.json", "managed-config.json")]
    for path in old_caches:
        path.write_bytes(b"invalid cached policy")
        path.chmod(0o600)

    command = ["managed", "codex", "--config", str(config_path), "--reconcile"]
    receiver.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", config["sensor_id"])
    assert main(command) == 1
    with closing(Journal(directory, binding)) as journal:
        assert journal.pending()
    assert receiver.db.scalar("SELECT count(*) FROM session_delivery_receipts") == 0
    receiver.db.execute("UPDATE sensors SET disabled=false WHERE id=$1", config["sensor_id"])
    for _ in range(2):
        assert main(command) == 0
    with closing(Journal(directory, binding)) as journal:
        assert journal.action(logical_id)["outcome"] == "not_executed"
        assert not journal.pending()
        assert journal.closing()["reason"] == "process_exit"
        assert not journal.authorization()["denied"]
        for key in ("policy", "context_policy"):
            assert journal.connection.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()[0] == b"invalid cached policy"
    assert all(path.read_bytes() == b"invalid cached policy" for path in old_caches)
    assert receiver.db.scalar("SELECT count(*) FROM session_delivery_receipts") > 0
    assert receiver.db.scalar("SELECT count(*) FROM session_registrations") == 1
    assert receiver.db.scalar("SELECT count(*) FROM guardrail_releases") == 0
    assert receiver.db.scalar("SELECT count(*) FROM inline_guardrail_checks") == 0
    assert not receiver.provider.requests

    # An enrollment change cannot relabel or upload the retained session.
    peer, token, _ = receiver.sensors["peer_sensor"]
    config.update(sensor_id=str(peer["id"]), sensor_token=token)
    config.save()
    before = receiver.db.scalar("SELECT count(*) FROM session_delivery_receipts")
    assert main(command) == 0
    assert receiver.db.scalar("SELECT count(*) FROM session_delivery_receipts") == before
    with closing(Journal(directory, binding)) as journal:
        assert journal.binding == binding


def selected_policy(system, action="allow", boundary=None):
    rules = (
        []
        if action == "allow"
        else [
            {
                "id": "managed-native-boundary",
                "name": "Fixture native boundary",
                "enabled": True,
                "action": action,
                "reason": "Explicit fixture policy",
                "match": {
                    "kinds": BOUNDARIES[boundary]
                    if boundary
                    else [kind for kinds in BOUNDARIES.values() for kind in kinds]
                },
            }
        ]
    )
    response = browser(system, "PUT", "response/policy", {"rules": rules})
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("module", [
    "openaidr.guardrail.hook_bridge", "openaidr.sensor.managed.hook_bridge",
])
def test_captured_hook_commands_keep_private_bridge_decisions_after_upgrade(tmp_path, module):
    from openaidr.guardrail.hook_bridge import ENVIRONMENT_KEY, denied

    received = []

    class Bridge(socketserver.StreamRequestHandler):
        def handle(self):
            message = json.loads(self.rfile.readline())
            received.append(message)
            self.wfile.write(json.dumps({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": message["payload"]["fixture_decision"],
            }}).encode() + b"\n")

    path = tmp_path / "bridge.json"
    environment = {**os.environ, ENVIRONMENT_KEY: str(path)}

    def run(decision):
        result = subprocess.run(
            [sys.executable, "-m", module, "codex", "PreToolUse"],
            input=json.dumps({"fixture_decision": decision}), text=True,
            capture_output=True, timeout=5, check=True, env=environment,
        )
        assert result.stderr == ""
        return json.loads(result.stdout)

    with socketserver.TCPServer(("127.0.0.1", 0), Bridge) as server:
        path.write_text(json.dumps({
            "agent": "codex", "token": "private-fixture-token", "port": server.server_address[1],
        }))
        path.chmod(0o600)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for decision in ("allow", "deny"):
                assert run(decision)["hookSpecificOutput"]["permissionDecision"] == decision
                assert received[-1] == {
                    "token": "private-fixture-token", "agent": "codex", "event": "PreToolUse",
                    "payload": {"fixture_decision": decision}, "owned": True,
                }
        finally:
            server.shutdown()
            thread.join(5)
    path.unlink()
    assert run("allow") == denied("PreToolUse")


@pytest.mark.parametrize(
    "case", ["valid", "malformed", "oversized", "unknown_encoding", "large_window"]
)
def test_native_compressed_request_enforces_decoded_and_window_byte_bounds(case):
    from openaidr.guardrail.native import NativeError
    from openaidr.guardrail.transport import MAX_BODY, request_payload

    zstd = pytest.importorskip("zstandard")
    value = {"model": "synthetic", "input": "private fixture"}
    raw = json.dumps(value).encode()
    if case in ("valid", "large_window"):
        window_log = 20 if case == "valid" else 26
        params = zstd.ZstdCompressionParameters.from_level(1, window_log=window_log)
        compressor = zstd.ZstdCompressor(compression_params=params).compressobj()
        encoded = compressor.compress(raw) + compressor.flush()
        assert zstd.get_frame_parameters(encoded).window_size == 1 << window_log
        if case == "valid":
            # The library's actual max_window_size unit is bytes. This frame
            # fails if an implementation mistakenly configures the bound in KiB.
            assert request_payload(encoded, "zstd") == value
            assert request_payload(raw, "identity") == value
        else:
            assert 1 << window_log > MAX_BODY
            with pytest.raises(zstd.ZstdError):
                request_payload(encoded, "zstd")
    elif case == "malformed":
        with pytest.raises(zstd.ZstdError):
            request_payload(b"not a zstd frame", "zstd")
    elif case == "oversized":
        # Multiple valid frames share one decoded-body budget.
        compressor = zstd.ZstdCompressor()
        encoded = compressor.compress(b" " * (MAX_BODY // 2)) + compressor.compress(
            b" " * (MAX_BODY // 2) + raw
        )
        with pytest.raises(NativeError, match="oversized_native_body"):
            request_payload(encoded, "zstd")
    else:
        with pytest.raises(NativeError, match="unsupported_native_encoding"):
            request_payload(raw, "gzip")


def test_managed_bootstrap_uses_active_device_scope_without_daemon_side_effects(
    receiver,
):
    selected = selected_policy(receiver, "ask", "tool_call")
    sensor = receiver.sensors["sensor"][0]
    command = receiver.db.queue_command(receiver.tenant["id"], sensor["id"], "flush")
    activity = receiver.db.one(
        "SELECT * FROM sensor_activity WHERE sensor_id=$1", sensor["id"]
    )
    pending = receiver.db.one("SELECT * FROM sensor_commands WHERE id=$1", command)
    response = receiver.client.post(
        "/ingest/v1/managed-bootstrap", json={}, headers=receiver.headers["sensor"]
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    value = response.json()
    assert set(value) == {"version", "tenant_id", "sensor_id", "capture", "policy"}
    assert (
        value["version"] == 1
        and value["tenant_id"] == receiver.tenant["id"]
        and value["sensor_id"] == sensor["id"]
    )
    assert value["capture"] == default_sensor_config()["capture"]
    assert value["policy"]["version"] == selected["version"]
    assert value["policy"]["rules"][0]["action"] == "ask"
    assert set(value["policy"]["actions"]) == {"allow", "ask", "deny", "warn"}
    for payload in (
        {"tenant_id": receiver.users["foreign"]["tenant_id"]},
        {"sensor_id": receiver.sensors["peer_sensor"][0]["id"]},
        [],
    ):
        assert (
            receiver.client.post(
                "/ingest/v1/managed-bootstrap",
                json=payload,
                headers=receiver.headers["sensor"],
            ).status_code
            == 400
        )
    for who in ("owner", "foreign"):
        assert (
            receiver.client.post(
                "/ingest/v1/managed-bootstrap", json={}, headers=receiver.headers[who]
            ).status_code
            == 401
        )
    foreign = receiver.client.post(
        "/ingest/v1/managed-bootstrap",
        json={},
        headers=receiver.headers["foreign_sensor"],
    )
    assert foreign.status_code == 403
    assert (
        receiver.db.one(
            "SELECT * FROM sensor_activity WHERE sensor_id=$1", sensor["id"]
        )
        == activity
    )
    assert (
        receiver.db.one("SELECT * FROM sensor_commands WHERE id=$1", command) == pending
    )
    assert receiver.db.scalar("SELECT count(*) FROM session_registrations") == 0
    assert receiver.db.scalar("SELECT count(*) FROM events") == 0
    assert not receiver.provider.requests
    receiver.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", sensor["id"])
    assert receiver.client.post(
        "/ingest/v1/managed-bootstrap", json={}, headers=receiver.headers["sensor"]
    ).status_code in (401, 403)


def test_managed_otlp_parks_only_bound_records_preserves_usage_and_never_promotes_offline_history(
    receiver, tmp_path
):
    from openaidr.sensor.capture import CaptureCoordinator, LAUNCH_ATTRIBUTE
    from openaidr.guardrail.journal import Journal
    from openaidr.sensor.telemetry import Telemetry
    from openaidr.core.telemetry import attributes, records
    from test_managed_foundation import binding as journal_binding
    from test_telemetry_server import attribute, tool_export

    registration = registered(receiver)
    config_path = sensor_config(receiver, tmp_path / "wrapper")
    config = Config.load(config_path)
    capture = {
        **default_sensor_config()["capture"],
        **{
            key: False
            for key in (
                "prompt_text",
                "response_text",
                "tool_input",
                "tool_output",
                "raw",
            )
        },
    }
    coordinator = CaptureCoordinator(config)
    launch = coordinator.begin(
        "codex-cli", capture, registration["delivery_epoch"], registration["id"]
    )
    journal = Journal(
        Path(config["data_dir"]) / "managed" / registration["delivery_epoch"],
        {**journal_binding(receiver, registration), "server_url": receiver.base_url},
    )
    launch.publish(journal)
    stale = Config(config.path, **dict(config))
    stale.pop("tenant_id")
    stale["telemetry"] = {
        "enabled": True,
        "listen": "127.0.0.1:0",
        "local_token": "private-local-fixture-token",
        "capture_prompts": True,
        "capture_tool_details": True,
    }
    secret = "WRAPPER_DISABLED_OTLP_682491"

    def native_export(native_id, launch_id, content=secret):
        payload = tool_export(native_id, [content])
        resource = payload["resourceLogs"][0]
        if launch_id:
            resource["resource"]["attributes"].append(
                attribute(LAUNCH_ATTRIBUTE, launch_id)
            )
        resource["scopeLogs"][0]["logRecords"][-1]["attributes"] += [
            attribute("output", content),
            attribute("user_prompt", content),
            {"key": "input_tokens", "value": {"intValue": "17"}},
            attribute("openaidr.session.registration_id", new_id()),
        ]
        return payload

    telemetry = Telemetry(stale)
    try:
        mixed = native_export(registration["external_id"], launch.id)
        unrelated = "unrelated-" + new_id()
        mixed["resourceLogs"] += native_export(unrelated, None, "echo ordinary")[
            "resourceLogs"
        ]
        telemetry.accept("logs", json.dumps(mixed).encode(), "application/json")
        rows = telemetry.queue.db.execute(
            "SELECT * FROM exports ORDER BY seq"
        ).fetchall()
        assert len(rows) == 2 and rows[0]["managed_launch"] == launch.id
        assert secret.encode() not in rows[0]["body"]
        assert telemetry.forward_once() is True
        assert telemetry.forward_once() is False
        assert receiver.db.scalar("SELECT count(*) FROM telemetry_exports") == 1
        assert (
            receiver.db.scalar(
                "SELECT count(*) FROM events WHERE body->'session'->>'id'=$1",
                registration["external_id"],
            )
            == 0
        )
        assert (
            receiver.db.scalar(
                "SELECT count(*) FROM events WHERE body->'session'->>'id'=$1 AND body->'session' ? 'registration_id'",
                unrelated,
            )
            == 0
        )
    finally:
        telemetry.close()
    telemetry = Telemetry(stale)
    try:
        assert telemetry.forward_once() is False
        verified = sensor_post(
            receiver, f"session-registrations/{registration['id']}/status"
        )
        launch.verify(verified)
        assert telemetry.forward_once() is True
        assert telemetry.queue.status()["queue_depth"] == 0
        stored = receiver.db.many("SELECT payload,translated_at FROM telemetry_exports")
        assert len(stored) == 2 and all(
            row["translated_at"] is not None for row in stored
        )
        assert secret not in json.dumps(stored, default=str)
        managed = [
            attrs
            for row in stored
            for _, _, item in records("logs", row["payload"])
            if (attrs := attributes(item.get("attributes"))).get("conversation.id")
            == registration["external_id"]
        ]
        assert any(item.get("input_tokens") == "17" for item in managed)
        events = receiver.db.many(
            "SELECT body FROM events WHERE body->'session'->>'id'=$1",
            registration["external_id"],
        )
        assert events and all(
            row["body"]["session"]["registration_id"] == registration["id"]
            for row in events
        )
        assert receiver.db.scalar("SELECT count(*) FROM inline_guardrail_events") == 0
        assert not receiver.provider.requests
        child_id = "nested-" + new_id()
        telemetry.accept(
            "logs",
            json.dumps(native_export(child_id, launch.id)).encode(),
            "application/json",
        )
        assert telemetry.forward_once() is False
        child_export = telemetry.queue.db.execute(
            "SELECT body FROM exports WHERE managed_session=?", (child_id,)
        ).fetchone()[0]
        assert secret.encode() not in child_export
        assert b"openaidr.session.registration_id" not in child_export
        assert (
            receiver.db.scalar(
                "SELECT count(*) FROM events WHERE body->'session'->>'id'=$1", child_id
            )
            == 0
        )
        # A known tenant mismatch does not inherit the absent-tenant exception.
        foreign = Config(config.path, **dict(stale))
        foreign["tenant_id"] = receiver.users["foreign"]["tenant_id"]
        foreign_telemetry = Telemetry(foreign)
        try:
            foreign_telemetry.accept(
                "logs",
                json.dumps(
                    native_export(registration["external_id"], launch.id)
                ).encode(),
                "application/json",
            )
            assert foreign_telemetry.forward_once() is False
        finally:
            foreign_telemetry.close()
        assert telemetry.forward_once() is True
        assert telemetry.queue.status()["queue_depth"] == 1
    finally:
        telemetry.close()
        journal.close()
        launch.end()
    offline = {
        **registration,
        "id": None,
        "external_id": "offline-" + new_id(),
        "delivery_epoch": new_id(),
    }
    offline_launch = coordinator.begin("codex-cli", capture, offline["delivery_epoch"])
    with closing(
        Journal(
            Path(config["data_dir"]) / "managed" / offline["delivery_epoch"],
            {**journal_binding(receiver, offline), "server_url": receiver.base_url},
        )
    ) as local:
        offline_launch.publish(local)
        telemetry = Telemetry(stale)
        try:
            telemetry.accept(
                "logs",
                json.dumps(
                    native_export(offline["external_id"], offline_launch.id)
                ).encode(),
                "application/json",
            )
        finally:
            telemetry.close()
    offline_launch.end()
    before = receiver.db.scalar("SELECT count(*) FROM telemetry_exports")
    for _ in range(2):
        restarted = Telemetry(stale)
        try:
            assert restarted.forward_once() is False
            assert restarted.queue.status()["queue_depth"] >= 1
        finally:
            restarted.close()
    assert receiver.db.scalar("SELECT count(*) FROM telemetry_exports") == before
