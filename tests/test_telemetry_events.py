"""Translation of stored OTLP log records into normalized detection events."""

import json
import uuid
import pytest

from openaidr.core.event import validate_event
from openaidr.server.telemetry_events import event_id, translate_export
from openaidr.core.telemetry import decode_export, encode_export, flatten_records, scrub_export

EXPORT = "0192b4c2-6a3e-7f10-8f7a-1c9d2e3f4a5b"
SENSOR = {"id": "sensor", "tenant_id": "tenant", "hostname": "sensor-host"}


def attr(key, value):
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    return {"key": key, "value": {"stringValue": value}}


def record(name, attrs, time="1700000000123456789", body=None):
    return {
        "timeUnixNano": time,
        "eventName": name,
        "body": {"stringValue": body if body is not None else name},
        "attributes": [attr(k, v) for k, v in attrs.items()],
    }


def logs(service, records, resource_extra=None):
    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        attr("service.name", service),
                        attr("service.version", "1.2.3"),
                        attr("host.name", "devbox"),
                    ]
                    + [attr(k, v) for k, v in (resource_extra or {}).items()]
                },
                "scopeLogs": [{"scope": {"name": "agent"}, "logRecords": records}],
            }
        ]
    }


def codex_tool(tool, arguments, session="conv-1", **extra):
    attrs = {"conversation.id": session, "tool_name": tool, "success": True}
    attrs["duration_ms"] = 42
    if arguments is not None:
        attrs["arguments"] = (
            arguments if isinstance(arguments, str) else json.dumps(arguments)
        )
    attrs.update(extra)
    return record("codex.tool_result", attrs)


def claude_tool(tool, parameters, session="sess-1", **extra):
    attrs = {
        "session.id": session,
        "tool_name": tool,
        "success": False,
        "duration_ms": "7",
        "user.email": "dev@example.com",
        "model": "claude-test",
        "app.version": "2.0.0",
    }
    if parameters is not None:
        attrs["tool_parameters"] = (
            parameters if isinstance(parameters, str) else json.dumps(parameters)
        )
    attrs.update(extra)
    return record("claude_code.tool_result", attrs)


def translate(payload):
    events = translate_export(EXPORT, SENSOR, "logs", payload, "2026-01-01T00:00:00Z")
    for event in events:
        assert validate_event(event) == "", event
        assert event["source"] == "otlp"
        assert event["export"]["id"] == EXPORT and event["export"]["signal"] == "logs"
    return events


def test_codex_exec_command_becomes_command_event():
    payload = logs(
        "codex-cli",
        [
            codex_tool(
                "exec_command",
                {"cmd": "rm -rf /srv/data", "workdir": "/srv/app"},
                call_id="call-1",
            )
        ],
        {"user.account_id": "acct-9", "model": "gpt-test"},
    )
    (event,) = translate(payload)
    assert event["kind"] == "command"
    assert event["command"] == {"text": "rm -rf /srv/data", "cwd": "/srv/app"}
    # The agent's call id is an identifier, kept so a hook observation of the
    # same call can be joined with this record; arguments never are.
    assert event["tool"] == {
        "name": "exec_command",
        "call_id": "call-1",
        "success": True,
        "duration_ms": 42,
    }
    assert event["agent"] == {
        "product": "codex-cli",
        "version": "1.2.3",
        "model": "gpt-test",
        "account": "acct-9",
    }
    assert event["session"] == {"id": "conv-1"}
    assert event["host"] == {"hostname": "devbox", "user": ""}
    assert event["time"] == "2023-11-14T22:13:20.123456Z"
    assert event["event_name"] == "codex.tool_result"
    assert event["export"]["record"] == 0
    assert "arguments" not in event and "attributes" not in event
    # The call id appears once, under tool; no other attribute is copied.
    assert json.dumps(event).count("call-1") == 1
    assert "call_id" not in json.dumps(
        translate(logs("codex-cli", [codex_tool("shell", {"cmd": "ls"})]))
    )


@pytest.mark.parametrize("media", ["application/json", "application/x-protobuf"])
def test_codex_source_location_labels_preserve_semantic_events_and_privacy(media):
    # Codex 0.159 supplies both the Rust tracing source label and event.name.
    payload = logs("codex_exec", [
        record("event otel/src/events/session_telemetry.rs:500", {
            "event.name": "codex.user_prompt", "conversation.id": "conv-1",
            "prompt_length": 32, "prompt": "private prompt content",
        }, body="private prompt content"),
        record("event otel/src/tool_result.rs:54", {
            "event.name": "codex.tool_result", "conversation.id": "conv-1",
            "tool_name": "exec_command", "call_id": "call-1",
            "arguments": json.dumps({"cmd": "./orbitctl refresh rt-17", "workdir": "/srv/app"}),
            "success": True,
        }),
        record("event otel/src/events/session_telemetry.rs:1103", {
            "event.name": "codex.sse_event", "conversation.id": "conv-1",
            "api_response_body": "private API content",
        }),
    ])
    decoded = decode_export("logs", encode_export("logs", payload, media), media)
    cleaned = scrub_export("logs", decoded, capture_tool_details=True)
    prompt, command = translate(cleaned)
    assert prompt["event_name"] == "codex.user_prompt"
    assert prompt["prompt"] == {"length": 32} and "text" not in prompt
    assert command["event_name"] == "codex.tool_result"
    assert command["kind"] == "command"
    assert command["command"] == {"text": "./orbitctl refresh rt-17", "cwd": "/srv/app"}
    assert command["tool"]["call_id"] == "call-1"
    assert command["export"]["record"] == 1
    assert "private prompt content" not in json.dumps(cleaned)
    assert "private API content" not in json.dumps(cleaned)


def test_codex_shell_list_command_is_joined_with_shlex():
    payload = logs(
        "codex-cli",
        [codex_tool("shell", {"command": ["bash", "-lc", "echo 'a b'"]})],
    )
    (event,) = translate(payload)
    assert event["kind"] == "command"
    assert event["command"]["text"] == "bash -lc 'echo '\"'\"'a b'\"'\"''"


@pytest.mark.parametrize("native_capture,prompt_capture", [(False, True), (True, False), (True, True)])
def test_codex_helper_prompt_keeps_permitted_text_and_capture_limits(native_capture, prompt_capture):
    prompt = "  Generate a title: password=hunter22\n" + "é" * 100
    payload = logs("codex-app-server", [record(
        "event otel/src/events/session_telemetry.rs:1179",
        {"event.name": "codex.user_prompt", "conversation.id": "ephemeral-helper",
         "prompt_length": len(prompt), "prompt": prompt, "api_request_body": "private API body"},
    )])
    cleaned = scrub_export("logs", payload, capture_prompts=native_capture, capture={
        "prompt_text": prompt_capture, "response_text": True, "tool_input": True,
        "tool_output": True, "max_text_bytes": 80,
    })
    (event,) = translate(cleaned)
    assert event["prompt"] == {"length": len(prompt)}
    assert "hunter22" not in json.dumps(cleaned)
    assert "private API body" not in json.dumps(cleaned)
    if native_capture and prompt_capture:
        assert event["text"].startswith("  Generate a title: password=[REDACTED:")
        assert "é" in event["text"] and len(event["text"].encode()) <= 80
    else:
        assert "text" not in event


@pytest.mark.parametrize("prompt", [None, "", " \n", "[REDACTED]", "<redacted>", {"text": "unsupported"}])
def test_codex_helper_prompt_does_not_display_absent_or_redacted_text(prompt):
    (event,) = translate(logs("codex-app-server", [record("codex.user_prompt", {
        "conversation.id": "ephemeral-helper", "prompt_length": 458, "prompt": prompt,
    })]))
    assert event["prompt"] == {"length": 458}
    assert "text" not in event


def test_claude_bash_with_tool_parameters():
    payload = logs(
        "claude-code",
        [
            claude_tool(
                "Bash",
                {"bash_command": "git push --force origin main", "description": "x"},
                error="exit 128",
            )
        ],
    )
    (event,) = translate(payload)
    assert event["kind"] == "command"
    assert event["command"] == {"text": "git push --force origin main"}
    assert event["tool"] == {"name": "Bash", "success": False, "duration_ms": 7}
    assert event["error"] == "exit 128"
    # Claude Code's `bash_command` is only the first word; the whole command
    # line in `full_command` (or `tool_input.command`) is what detection needs.
    (full,) = translate(
        logs(
            "claude-code",
            [
                claude_tool(
                    "Bash",
                    {"bash_command": "for", "full_command": "for f in *; do rm -rf \"$f\"; done"},
                    tool_use_id="toolu_01",
                    tool_input=json.dumps({"command": "for f in *; do rm -rf \"$f\"; done"}),
                )
            ],
        )
    )
    assert full["command"] == {"text": 'for f in *; do rm -rf "$f"; done'}
    assert full["tool"]["call_id"] == "toolu_01"
    (only_input,) = translate(
        logs(
            "claude-code",
            [claude_tool("Bash", None, tool_input=json.dumps({"command": "git status --short"}))],
        )
    )
    assert only_input["command"] == {"text": "git status --short"}
    # A non-text `command` does not hide a usable `cmd`.
    (shadowed,) = translate(
        logs(
            "codex-cli",
            [codex_tool("exec_command", {"command": {"args": []}, "cmd": "rm -rf /srv/data"})],
        )
    )
    assert shadowed["kind"] == "command"
    assert shadowed["command"] == {"text": "rm -rf /srv/data"}
    assert event["agent"] == {
        "product": "claude-code",
        "version": "1.2.3",
        "model": "claude-test",
        "account": "dev@example.com",
    }
    assert event["host"]["user"] == ""


@pytest.mark.parametrize(
    "record_attrs,resource_attrs,sensor_attrs,os_user,account",
    [
        (
            {"user.email": "dev@example.com", "os.user": "alice"},
            {},
            {},
            "alice",
            "dev@example.com",
        ),
        (
            {"user.email": "dev@example.com"},
            {"os.user": "alice"},
            {"user": "daemon"},
            "alice",
            "dev@example.com",
        ),
        (
            {"os.user": "bob"},
            {"os.user": "alice", "user.email": "dev@example.com"},
            {},
            "bob",
            "dev@example.com",
        ),
        (
            {"user.email": "dev@example.com"},
            {},
            {"user": "alice"},
            "alice",
            "dev@example.com",
        ),
        ({"user.id": "account-1"}, {}, {"username": "alice"}, "alice", "account-1"),
        ({"user.name": "login-name"}, {}, {}, "", "login-name"),
        ({"os.user": "alice"}, {}, {}, "alice", ""),
        (
            {"os.user": False, "user.email": 123},
            {"os.user": "alice", "user.account_uuid": "account-2"},
            {},
            "alice",
            "123",
        ),
        ({"os.user": "", "user.email": ""}, {}, {}, "", ""),
    ],
)
def test_os_username_and_agent_account_are_separate(
    record_attrs, resource_attrs, sensor_attrs, os_user, account
):
    payload = logs(
        "codex-cli",
        [codex_tool("exec_command", {"cmd": "pwd"}, **record_attrs)],
        resource_attrs,
    )
    (event,) = translate_export(EXPORT, {**SENSOR, **sensor_attrs}, "logs", payload)
    assert event["host"]["user"] == os_user
    assert event["agent"].get("account", "") == account


def test_read_and_edit_tools_map_to_file_events():
    payload = logs(
        "claude-code",
        [
            claude_tool("Read", {"file_path": "/work/.env"}),
            claude_tool("Edit", {"file_path": "/work/app.py", "old_string": "a"}),
            claude_tool("Write", {"file_path": "/etc/hosts", "content": "x"}),
            claude_tool("Glob", {"pattern": "**/*.pem", "path": "/work"}),
            claude_tool("Grep", {"pattern": "secret"}),
        ],
    )
    events = translate(payload)
    assert [e["kind"] for e in events] == [
        "file.read",
        "file.write",
        "file.write",
        "file.read",
        "tool.call",
    ]
    assert events[0]["file"] == {"path": "/work/.env"}
    assert events[1]["file"] == {"path": "/work/app.py", "op": "edit"}
    assert events[2]["file"] == {"path": "/etc/hosts", "op": "write"}
    assert events[3]["file"] == {"path": "/work/**/*.pem"}
    assert events[4]["tool"]["name"] == "Grep" and "file" not in events[4]
    assert [e["export"]["record"] for e in events] == [0, 1, 2, 3, 4]


def test_apply_patch_emits_one_write_per_file():
    patch = (
        "*** Begin Patch\n*** Update File: src/app.py\n@@\n-a\n+b\n"
        "*** Add File: src/new.py\n+x\n*** Delete File: old.txt\n*** End Patch\n"
    )
    payload = logs("codex-cli", [codex_tool("apply_patch", {"input": patch})])
    events = translate(payload)
    assert [(e["kind"], e["file"]) for e in events] == [
        ("file.write", {"path": "src/app.py", "op": "patch"}),
        ("file.write", {"path": "src/new.py", "op": "patch"}),
        ("file.write", {"path": "old.txt", "op": "delete"}),
    ]
    assert all(e["export"]["record"] == 0 for e in events)
    assert len({e["id"] for e in events}) == 3
    assert events[0]["id"] == event_id(EXPORT, 0)
    assert events[1]["id"] == event_id(EXPORT, 0, 1)
    empty = translate(logs("codex-cli", [codex_tool("apply_patch", {"input": "?"})]))
    assert [e["kind"] for e in empty] == ["tool.call"]


def test_web_tools_map_to_network_events():
    payload = logs(
        "claude-code",
        [
            claude_tool("WebFetch", {"url": "https://Example.com:8443/doc?q=1"}),
            claude_tool("WebSearch", {"query": "how to exfiltrate"}),
        ],
    )
    fetch, search = translate(payload)
    assert fetch["kind"] == "network"
    assert fetch["network"] == {
        "url": "https://Example.com:8443/doc?q=1",
        "host": "example.com",
    }
    assert search["kind"] == "tool.call" and "network" not in search
    assert "how to exfiltrate" not in json.dumps(search)


def test_unknown_redacted_and_malformed_arguments_become_tool_calls():
    payload = logs(
        "codex-cli",
        [
            codex_tool("mcp__github__create_issue", {"title": "x"}),
            codex_tool("exec_command", "[REDACTED]"),
            codex_tool("exec_command", "{not json"),
            codex_tool("exec_command", None),
            codex_tool("Bash", {"timeout": 5}),
        ],
    )
    events = translate(payload)
    assert [e["kind"] for e in events] == ["tool.call"] * 5
    assert events[0]["tool"]["name"] == "mcp__github__create_issue"
    assert all("command" not in e for e in events)
    assert "[REDACTED]" not in json.dumps(events)


def test_decisions_prompts_and_bookkeeping_records():
    payload = logs(
        "claude-code",
        [
            record(
                "claude_code.api_request",
                {"session.id": "s", "model": "m", "input_tokens": 12},
            ),
            record(
                "claude_code.tool_decision",
                {"session.id": "s", "tool_name": "Bash", "decision": "reject"},
            ),
            record(
                "claude_code.user_prompt",
                {"session.id": "s", "prompt_length": 27, "prompt": "never copied"},
                body="[REDACTED]",
            ),
            record("claude_code.api_error", {"session.id": "s", "error": "boom"}),
            record("codex.conversation_starts", {"conversation.id": "s"}),
        ],
    )
    events = translate(payload)
    assert [(e["kind"], e["export"]["record"]) for e in events] == [
        ("hook.decision", 1),
        ("prompt", 2),
    ]
    decision, prompt = events
    assert decision["tool"] == {"name": "Bash"}
    assert decision["hook"] == {"decision": "reject"}
    assert prompt["prompt"] == {"length": 27}
    assert "never copied" not in json.dumps(events)
    assert "text" not in prompt


def test_records_without_session_are_skipped_and_time_falls_back():
    payload = logs(
        "some-other-agent",
        [
            record("agent.tool_result", {"tool_name": "Bash"}),
            record(
                "agent.tool_result",
                {"thread.id": "thr-1", "tool_name": "Bash"},
                time="0",
            ),
        ],
    )
    (event,) = translate(payload)
    assert event["export"]["record"] == 1
    assert event["session"]["id"] == "thr-1"
    assert event["agent"]["product"] == "unknown"
    assert event["time"] == "2026-01-01T00:00:00Z"
    assert event["kind"] == "tool.call"


def test_event_name_from_attribute_or_body_and_sensor_hostname():
    payload = {
        "resourceLogs": [
            {
                "resource": {"attributes": [attr("service.name", "codex-cli")]},
                "scopeLogs": [
                    {
                        "logRecords": [
                            {
                                "body": {"stringValue": "codex.tool_result"},
                                "attributes": [
                                    attr("conversation.id", "c"),
                                    attr("tool_name", "read_file"),
                                    attr("arguments", json.dumps({"path": "/x"})),
                                ],
                            },
                            {
                                "body": {"stringValue": "ignored"},
                                "attributes": [
                                    attr("event.name", "codex.tool_result"),
                                    attr("conversation.id", "c"),
                                    attr("tool", "list_dir"),
                                    attr("arguments", json.dumps({"dir_path": "/y"})),
                                ],
                            },
                        ]
                    }
                ],
            }
        ]
    }
    first, second = translate(payload)
    assert first["kind"] == "file.read" and first["file"]["path"] == "/x"
    assert second["kind"] == "file.read" and second["file"]["path"] == "/y"
    assert first["host"] == {"hostname": "sensor-host", "user": ""}
    assert first["agent"] == {"product": "codex-cli"}


def test_ids_are_deterministic_and_indices_match_flatten_records():
    payload = logs("codex-cli", [codex_tool("exec_command", {"cmd": "ls"})])
    payload["resourceLogs"].append(
        logs("claude-code", [claude_tool("Read", {"file_path": "/a"})])["resourceLogs"][
            0
        ]
    )
    first, second = translate(payload), translate(payload)
    assert first == second
    assert first[0]["id"] == str(
        uuid.uuid5(uuid.UUID("3f8b6a54-9d1e-4c2b-9b0e-7a1c5d2e8f40"), f"{EXPORT}:0")
    )
    rows = flatten_records("logs", payload)
    for event in first:
        row = rows[event["export"]["record"]]
        assert row["event_name"] == event["event_name"]
        assert row["attributes"]["tool_name"] == event["tool"]["name"]
    assert translate_export("other", SENSOR, "logs", payload)[0]["id"] != first[0]["id"]


def test_other_signals_produce_nothing():
    assert translate_export(EXPORT, SENSOR, "metrics", {"resourceMetrics": []}) == []
    assert translate_export(EXPORT, SENSOR, "traces", {"resourceSpans": []}) == []
    assert translate_export(EXPORT, SENSOR, "logs", {}) == []
