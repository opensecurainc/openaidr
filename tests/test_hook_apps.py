"""Native app contracts, installation, and real local hook transport."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import uuid

import pytest

from openaidr.core.hook_protocol import APP_EVENTS, PRODUCTS, normalize
from openaidr.core.toolmap import map_tool
from openaidr.sensor import hook_opencode, hook_runtime, hooks
from hook_process import run_hook
from test_hook_client import local_hook_sensor  # noqa: F401

detect_apps = hooks.detect_apps
native_settings_path = hooks.settings_path
PAYLOADS = {
    "workbuddy": {"session_id": "s", "cwd": "/project", "tool_name": "Bash",
                  "tool_input": {"command": "echo café"}, "tool_use_id": "call-1"},
    "copilot": {"sessionId": "s", "cwd": "/project", "toolName": "bash", "toolArgs": '{"command":"echo café"}'},
    "cursor": {"conversation_id": "s", "hook_event_name": "preToolUse", "cwd": "/project",
               "tool_name": "Shell", "tool_input": {"command": "echo café"}, "tool_use_id": "call-1"},
    "antigravity": {"conversationId": "s", "workspacePaths": ["/project"], "stepIdx": 0,
                    "toolCall": {"name": "run_command", "args": {"CommandLine": "echo café", "Cwd": "/project"}}},
    "hermes": {"session_id": "s", "cwd": "/project", "tool_name": "terminal",
               "tool_input": {"command": "echo café"}, "extra": {"tool_call_id": "call-1"}},
    "opencode": {"session_id": "s", "cwd": "/project", "tool_name": "bash",
                 "tool_input": {"command": "echo café"}, "tool_use_id": "call-1"},
}


def installed_command(path, agent, event="PreToolUse"):
    if agent == "opencode":
        return hook_opencode.read(path)["commands"][event]
    entries = hooks.groups(hooks.load_settings(path), event, agent)
    return next(handler["command"] for entry in entries for handler in entry["hooks"] if hooks.our_handler(handler))


@pytest.mark.parametrize("agent", APP_EVENTS)
def test_install_repair_remove_preserves_user_hooks(tmp_path, sensor_executable, agent):
    path = tmp_path / ("openaidr.js" if agent == "opencode" else "hooks.json")
    other = {"type": "command", "command": "user-validator", "timeout": 20}
    original = ({"personal": {"PreToolUse": [{"hooks": [other]}]},
                 "openaidr": {"PreToolUse": [{"matcher": "Read", "hooks": [other]}]}}
                if agent == "antigravity" else {"version": 1, "hooks": {"preToolUse": [other], "otherEvent": [other]}})
    if agent != "opencode":
        path.write_text(json.dumps(original))
    hooks.install(path, sensor_executable, agent)
    first = path.read_text()
    assert hooks.installed(path, agent) and hooks.present(path, agent)
    assert hooks.current(None, agent, path)
    assert hooks.executables(agent, path) == {sensor_executable}
    hooks.install(path, sensor_executable, agent)
    assert path.read_text() == first
    hooks.uninstall(path, agent)
    assert not hooks.present(path, agent) and not hooks.installed(path, agent)
    if agent == "opencode":
        assert not path.exists()
        path.write_text("// A personal plugin already uses this path\n")
        with pytest.raises(ValueError, match="unrelated plugin"):
            hooks.install(path, sensor_executable, agent)
        hooks.uninstall(path, agent)
        assert path.read_text() == "// A personal plugin already uses this path\n"
    else:
        assert json.loads(path.read_text()) == original


@pytest.mark.parametrize("agent", APP_EVENTS)
@pytest.mark.parametrize("decision", ["allow", "deny", "ask", "warn", "shadow", "unavailable"])
@pytest.mark.parametrize("transport", ["tcp", "socket"])
def test_installed_launcher_uses_actual_listener(local_hook_sensor, tmp_path, backend_hook, monkeypatch, agent, decision, transport):
    if transport == "socket" and os.name == "nt":
        pytest.skip("Windows uses authenticated TCP")
    config, server, events = local_hook_sensor
    monkeypatch.setattr(hooks, "native_socket", lambda _: str(server.socket_path) if transport == "socket" else None)
    executable = Path(sys.executable).with_name("openaidr.exe" if os.name == "nt" else "openaidr")
    assert executable.is_file()
    path = tmp_path / ("openaidr.js" if agent == "opencode" else "hooks.json")
    hooks.install(path, str(executable), agent, config_path=config.path)
    backend = backend_hook(action="deny" if decision == "shadow" else decision,
                           mode="shadow" if decision == "shadow" else "enforce")
    server.check = None if decision == "unavailable" else backend
    env = {key: value for key, value in os.environ.items() if not key.startswith("OPENAIDR_")}
    result = run_hook(shlex.split(installed_command(path, agent)), input=json.dumps(PAYLOADS[agent]),
                      text=True, env=env, timeout=hooks.hook_timeout("PreToolUse", agent))
    assert result.returncode == 0 and not result.timed_out and result.stderr == "", result
    if decision in ("allow", "warn", "shadow", "unavailable"):
        assert result.stdout == ""
    else:
        output = json.loads(result.stdout)
        if agent == "copilot":
            assert output["permissionDecision"] == decision
        elif agent == "cursor":
            assert output["permission"] == "deny"
        elif agent == "hermes":
            assert output == {"action": "approve" if decision == "ask" else "block", "message": "Test policy reason"}
        elif agent == "workbuddy":
            assert output == {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                              "permissionDecision": decision, "permissionDecisionReason": "Test policy reason"}}
        else:
            assert output["decision"] == ("force_ask" if agent == "antigravity" and decision == "ask" else "deny")
    if decision != "unavailable":
        request = backend.requests[-1]
        assert request["product"] == PRODUCTS[agent] and request["session_id"] == "s"
        assert request["actions"][0]["command"]["text"] == "echo café"
        assert request["actions"][0]["session"]["cwd"] == "/project"


@pytest.mark.parametrize("agent", APP_EVENTS)
def test_observation_boundaries_cannot_restrict(tmp_path, backend_hook, agent):
    backend = backend_hook(action="deny")

    def check(request, deadline):
        reply = backend(request, deadline)
        assert request["availability"] == "unsupported_boundary"
        reply["returned_decision"] = "allow"
        return reply

    server = hooks.HookServer("127.0.0.1:0", tmp_path / "sock", lambda _: None, lambda: {}, {}, check=check)
    p = {**PAYLOADS[agent], "hook_event_name": "PostToolUse"}
    assert server.evaluate(p, PRODUCTS[agent], result_supported=True)["output"] == {}
    if agent in ("copilot", "opencode", "hermes", "workbuddy"):
        p.update(hook_event_name="UserPromptSubmit", prompt="inspect files")
        assert server.evaluate(p, PRODUCTS[agent])["output"] == {}


@pytest.mark.parametrize("product,name,args,kind,target", [
    ("workbuddy", "Bash", {"command": "echo test"}, "command", "echo test"),
    ("workbuddy", "PowerShell", {"command": "Get-Item ."}, "command", "Get-Item ."),
    ("workbuddy", "Read", {"file_path": "/secret"}, "file.read", "/secret"),
    ("workbuddy", "Edit", {"file_path": "/new"}, "file.write", "/new"),
    ("workbuddy", "WebFetch", {"url": "https://example.test/a"}, "network", "https://example.test/a"),
    ("hermes-agent", "terminal", {"command": "echo test"}, "command", "echo test"),
    ("hermes-agent", "read_file", {"path": "/secret"}, "file.read", "/secret"),
    ("hermes-agent", "write_file", {"path": "/new"}, "file.write", "/new"),
    ("hermes-agent", "patch", {"path": "/existing"}, "file.write", "/existing"),
    ("hermes-agent", "patch", {"mode": "patch", "patch": "*** Begin Patch\n*** Delete File: /old\n*** End Patch"}, "file.write", "/old"),
    ("github-copilot", "powershell", {"command": "Get-Item ."}, "command", "Get-Item ."),
    ("github-copilot", "view", {"path": "secret.txt"}, "file.read", "secret.txt"),
    ("github-copilot", "create", {"path": "new.txt"}, "file.write", "new.txt"),
    ("cursor", "Read", {"path": "secret.txt"}, "file.read", "secret.txt"),
    ("cursor", "StrReplace", {"path": "new.txt"}, "file.write", "new.txt"),
    ("cursor", "Delete", {"path": "old.txt"}, "file.write", "old.txt"),
    ("antigravity", "view_file", {"AbsolutePath": "/secret"}, "file.read", "/secret"),
    ("antigravity", "write_to_file", {"TargetFile": "/new"}, "file.write", "/new"),
    ("antigravity", "multi_replace_file_content", {"TargetFile": "/new"}, "file.write", "/new"),
    ("opencode", "read", {"filePath": "/secret"}, "file.read", "/secret"),
    ("opencode", "write", {"filePath": "/new"}, "file.write", "/new"),
    ("opencode", "apply_patch", {"patchText": "*** Begin Patch\n*** Delete File: /old\n*** End Patch"}, "file.write", "/old"),
    ("antigravity", "read_url_content", {"Url": "https://example.test/a"}, "network", "https://example.test/a"),
    ("opencode", "webfetch", {"url": "https://example.test/a"}, "network", "https://example.test/a"),
])
def test_native_tools_preserve_targets(product, name, args, kind, target):
    original = copy.deepcopy(args)
    action, = map_tool(product, name, args)
    assert action["kind"] == kind
    assert target in json.dumps(action) and args == original
    assert map_tool(product, "unknown_tool", args) == [{"kind": "tool.call"}]


def test_normalization_preserves_results_errors_and_ambiguous_workspaces():
    p = normalize("github-copilot", {"toolResult": {"textResultForLlm": "raw result"}})
    assert p["tool_response"] == "raw result"
    p = normalize("antigravity", {**PAYLOADS["antigravity"], "hook_event_name": "PostToolUse", "error": "raw error"})
    assert p["hook_event_name"] == "PostToolUseFailure" and p["error"] == "raw error"
    for product, roots in (("cursor", "workspace_roots"), ("antigravity", "workspacePaths")):
        assert "cwd" not in normalize(product, {roots: ["/one", "/two"]})


def test_hermes_yaml_install_preserves_settings_and_native_consent(tmp_path, sensor_executable, monkeypatch):
    import yaml

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    path = native_settings_path("hermes")
    assert path == tmp_path / "config.yaml"
    original = {"model": {"default": "personal-model"}, "hooks_auto_accept": False,
                "hooks": {"pre_tool_call": [{"command": "personal-check", "fail_closed": True}]}}
    path.write_text(yaml.safe_dump(original))
    approval_path = tmp_path / "shell-hooks-allowlist.json"
    approval_path.write_text(json.dumps({"approvals": [{"event": "pre_tool_call", "command": "personal-check"}]}))
    hooks.install(path, sensor_executable, "hermes")
    assert hooks.installed(path, "hermes") and hooks.current(None, "hermes", path)
    assert hooks.status({"hermes": path})["hermes"]["approval_pending"]
    assert json.loads(approval_path.read_text())["approvals"] == [{"event": "pre_tool_call", "command": "personal-check"}]
    approved = {"approvals": [{"event": native, "command": installed_command(path, "hermes", event)}
                              for event, native in APP_EVENTS["hermes"].items()]}
    approval_path.write_text(json.dumps(approved))
    assert not hooks.status({"hermes": path})["hermes"]["approval_pending"]
    if os.name != "nt":
        updated = tmp_path / "updated user's build" / "openaidr-sensor"
        updated.parent.mkdir()
        reply = {"action": "block", "message": "Updated sensor"}
        updated.write_text("#!/bin/sh\nprintf '%s' " + shlex.quote(json.dumps(reply)) + "\n")
        updated.chmod(0o700)
        consent = approval_path.read_bytes()
        for executable, expected in ((str(updated), reply), (sensor_executable, None)):
            hooks.install(path, executable, "hermes")
            assert all(installed_command(path, "hermes", event) == entry["command"]
                       for event, entry in zip(APP_EVENTS["hermes"], approved["approvals"]))
            assert hooks.current(None, "hermes", path)
            assert hooks.executables("hermes", path) == {executable}
            assert not hooks.status({"hermes": path})["hermes"]["approval_pending"]
            assert approval_path.read_bytes() == consent
            # The already-approved command uses the updated sensor, then the rollback.
            result = run_hook(shlex.split(approved["approvals"][0]["command"]), input="{}", text=True,
                              env={**os.environ, "PATH": ""})
            assert not result.timed_out and (result.returncode, result.stderr) == (0, "")
            assert (json.loads(result.stdout) if result.stdout else None) == expected
    settings = yaml.safe_load(path.read_text())
    settings["hooks"]["pre_tool_call"][-1]["fail_closed"] = True
    path.write_text(yaml.safe_dump(settings))
    assert not hooks.installed(path, "hermes")
    hooks.install(path, sensor_executable, "hermes")
    assert hooks.installed(path, "hermes")
    approved["approvals"].pop()
    approval_path.write_text(json.dumps(approved))
    hooks.install(path, sensor_executable, "hermes")
    assert hooks.status({"hermes": path})["hermes"]["approval_pending"]
    hooks.uninstall(path, "hermes")
    assert yaml.safe_load(path.read_text()) == original
    assert json.loads(approval_path.read_text()) == approved


@pytest.mark.skipif(os.name == "nt", reason="POSIX Hermes launcher migration")
def test_hermes_migrates_hashed_launchers_without_granting_consent(tmp_path, sensor_executable):
    path = tmp_path / "config.yaml"
    hooks.install(path, sensor_executable, "hermes")
    settings = hooks.load_settings(path)
    legacy_scripts, approvals = {}, []
    for event, native in APP_EVENTS["hermes"].items():
        handler, = settings["hooks"][native]
        parts = shlex.split(handler["command"])
        runner = Path(parts[4])
        script = runner.read_text()
        legacy = runner.parent.parent / hashlib.sha256(script.encode()).hexdigest() / "guardrail.sh"
        legacy.parent.mkdir(exist_ok=True)
        legacy.write_text(script)
        parts[4], parts[8] = str(legacy), sensor_executable
        handler["command"] = shlex.join(parts)
        legacy_scripts[legacy] = script
        approvals.append({"event": native, "command": handler["command"]})
    path.write_text(hooks.settings_text(path, settings))
    approval_path = tmp_path / "shell-hooks-allowlist.json"
    consent = json.dumps({"approvals": approvals})
    approval_path.write_text(consent)
    assert hooks.installed(path, "hermes") and hooks.hermes_approved(path)
    assert not hooks.current(None, "hermes", path)

    hooks.install(path, sensor_executable, "hermes")
    assert hooks.installed(path, "hermes") and hooks.current(None, "hermes", path)
    assert hooks.status({"hermes": path})["hermes"]["approval_pending"]
    assert approval_path.read_text() == consent
    assert all(legacy.read_text() == script for legacy, script in legacy_scripts.items())
    assert all(len(entries) == 1 for entries in hooks.load_settings(path)["hooks"].values())
    hooks.uninstall(path, "hermes")
    assert not hook_runtime.directory(path).exists()
    assert approval_path.read_text() == consent


def test_hermes_maps_every_network_and_patch_target():
    urls = ["https://example.test/one", "https://other.test/two"]
    actions = map_tool("hermes-agent", "web_extract", {"urls": urls})
    assert [action["network"]["url"] for action in actions] == urls
    patch = "*** Begin Patch\n*** Delete File: /one\n*** Add File: /two\n+text\n*** End Patch"
    actions = map_tool("hermes-agent", "patch", {"mode": "patch", "path": "/unused", "patch": patch})
    assert [action["file"]["path"] for action in actions] == ["/one", "/two"]


@pytest.mark.parametrize("capture_content", [False, True])
@pytest.mark.parametrize("agent", ["hermes", "workbuddy"])
def test_app_activity_uses_native_fields_and_capture_controls(tmp_path, backend_hook, capture_content, agent):
    from openaidr.sensor.config import Config
    from openaidr.sensor.runtime import Sensor

    sensor = Sensor(Config(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                           server_url="http://127.0.0.1:9", sensor_id=str(uuid.uuid4()), sensor_token="test"))
    try:
        sensor.hooks.check = backend_hook()
        sensor.capture.update({key: capture_content for key in ("prompt_text", "response_text", "tool_input", "tool_output")})
        common = {**PAYLOADS[agent], "tool_input": {"command": "echo private-input"}}
        for event, extra, native in (
            ("UserPromptSubmit", {"user_message": "private-prompt", "model": "test-model"}, {"prompt": "private-prompt"}),
            ("PreToolUse", {"tool_call_id": "call-1"}, {}),
            ("PostToolUse", {"tool_call_id": "call-1", "result": "private-result", "status": "success"}, {"tool_response": "private-result"}),
            ("Stop", {"assistant_response": "private-response"}, {"last_assistant_message": "private-response"}),
        ):
            sensor.hooks.evaluate({**common, "hook_event_name": APP_EVENTS[agent][event],
                                   **({"extra": extra} if agent == "hermes" else native)}, PRODUCTS[agent])
        events = sensor.spool.read()["events"]
        serialized = json.dumps(events)
        for value in ("private-prompt", "private-result", "private-response"):
            assert (value in serialized) is capture_content
        command = next(event for event in events if event["kind"] == "command")
        assert ("input" in command["tool"]) is capture_content
        assert all(event["agent"]["product"] == PRODUCTS[agent] for event in events)
        if capture_content:
            assert {event["kind"] for event in events} >= {"prompt", "response", "command", "tool.result"}
            assert next(event for event in events if event["kind"] == "tool.result")["tool"]["call_id"] == "call-1"
    finally:
        sensor.client.close()
        sensor.hook_clients.close()
        sensor.telemetry.close()
        sensor.spool.close()


def test_app_homes_detection_and_disabled_settings(tmp_path, monkeypatch, sensor_executable):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    for key in ("COPILOT_HOME", "OPENCODE_CONFIG_DIR", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(key, raising=False)
    assert native_settings_path("copilot") == tmp_path / ".copilot/hooks/openaidr.json"
    assert native_settings_path("antigravity") == tmp_path / ".gemini/config/hooks.json"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert native_settings_path("opencode") == tmp_path / "xdg/opencode/plugins/openaidr.js"
    monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(tmp_path / "custom"))
    assert native_settings_path("opencode") == tmp_path / "custom/plugins/openaidr.js"
    monkeypatch.setattr(shutil, "which", lambda _: None)
    monkeypatch.setattr(os, "access", lambda *_: False)
    monkeypatch.setattr(sys, "platform", "linux")
    (tmp_path / ".gemini/config").mkdir(parents=True)
    assert not detect_apps()["antigravity"]
    monkeypatch.setattr(shutil, "which", lambda name: "/custom/agy" if name == "agy" else None)
    assert detect_apps()["antigravity"]
    monkeypatch.setattr(shutil, "which", lambda _: None)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    monkeypatch.setattr(sys, "platform", "win32")
    for name in ("cursor-agent", "agy/bin"):
        (tmp_path / "Local" / name).mkdir(parents=True)
    assert detect_apps()["cursor"] and detect_apps()["antigravity"]
    monkeypatch.setattr(sys, "platform", "linux")
    (tmp_path / ".gemini/antigravity-cli").mkdir()
    (tmp_path / ".vscode/extensions/github.copilot-chat-1").mkdir(parents=True)
    assert detect_apps()["antigravity"] and detect_apps()["copilot"]
    path = tmp_path / "antigravity.json"
    path.write_text(json.dumps({"openaidr": {"enabled": False}}))
    hooks.install(path, sensor_executable, "antigravity")
    assert json.loads(path.read_text())["openaidr"]["enabled"] is False
    assert not hooks.installed(path, "antigravity")
    hooks.install(path, sensor_executable, "antigravity", explicit=True)
    assert json.loads(path.read_text())["openaidr"]["enabled"] is True


@pytest.mark.parametrize("agent", APP_EVENTS)
def test_setup_installs_new_apps_once_and_respects_opt_out(tmp_path, monkeypatch, sensor_executable, agent):
    from openaidr.sensor import bridge, service
    from test_hooks_setup import sensor_config

    config = sensor_config(tmp_path)
    monkeypatch.setattr(service, "staged_executable", lambda: sensor_executable)
    monkeypatch.setattr(service, "manage", lambda *_, **__: "running")
    monkeypatch.setattr(hooks, "local_request", lambda *_: {"version": bridge.app_version()})
    monkeypatch.setattr(hooks, "detect_apps", lambda config=None: {name: name == agent for name in APP_EVENTS})
    monkeypatch.setattr(bridge.integrations, "detect", lambda **_: {"claude_available": False, "codex_available": False})
    result = bridge.handle({"action": "setup", "config_path": str(config.path)})
    installed = [step for step in result["steps"] if step["step"] == "hooks.install"]
    assert len(installed) == 1 and installed[0]["agents"] == [agent] and installed[0]["ok"]
    assert not any(step["step"] == "telemetry.install" for step in result["steps"])
    assert result["hooks"][agent]["current"] is (agent != "hermes")
    assert result["hooks"][agent]["available"]
    assert bridge.handle({"action": "setup", "config_path": str(config.path)})["steps"] == []
    hooks.uninstall(hooks.settings_path(agent), agent, config_path=config.path)
    hooks.set_opt_out(config, agent, True)
    result = bridge.handle({"action": "setup", "config_path": str(config.path)})
    assert result["steps"] == [] and result["hooks"][agent]["opted_out"]
    assert not hooks.present(agent=agent)


def test_workbuddy_profiles_settings_and_native_disablement(tmp_path, monkeypatch, sensor_executable):
    from test_hooks_setup import sensor_config

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("WORKBUDDY_CONFIG_DIR")
    domestic, international = tmp_path / ".workbuddy", tmp_path / ".workbuddy-ai"
    with monkeypatch.context() as detection:
        detection.setattr(shutil, "which", lambda _: None)
        detection.setattr(os, "access", lambda *_: False)
        assert not detect_apps()["workbuddy"]
        domestic.mkdir()
        assert native_settings_path("workbuddy") == domestic / "settings.json"
        assert detect_apps()["workbuddy"]
        international.mkdir()
        assert native_settings_path("workbuddy") == international / "settings.json"
    custom = tmp_path / "custom profile"
    config = sensor_config(tmp_path)
    monkeypatch.setenv("WORKBUDDY_CONFIG_DIR", " " + str(custom) + " ")
    hooks.remember_homes(config)
    monkeypatch.delenv("WORKBUDDY_CONFIG_DIR")
    assert native_settings_path("workbuddy", config) == custom / "settings.json"
    for root in (domestic, international, custom):
        root.mkdir(exist_ok=True)
        path = root / "settings.json"
        original = {"env": {"PERSONAL": "kept"}, "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "personal-check"}]}]}}
        path.write_text(json.dumps(original))
        hooks.install(path, sensor_executable, "workbuddy")
        assert hooks.installed(path, "workbuddy")
        # An explicit PowerShell shell makes WorkBuddy start only PowerShell 7,
        # which rejected every action on stock Windows. Setup leaves the shell
        # to WorkBuddy and repairs handlers written with it.
        ours = lambda: [handler for event in hooks.load_settings(path)["hooks"].values() for entry in event
                        for handler in entry["hooks"] if hooks.our_handler(handler)]
        assert ours() and not any("shell" in handler for handler in ours())
        legacy = hooks.load_settings(path)
        for handler in (h for event in legacy["hooks"].values() for entry in event for h in entry["hooks"]):
            if hooks.our_handler(handler):
                handler["shell"] = "powershell"
        path.write_text(json.dumps(legacy))
        assert not hooks.installed(path, "workbuddy")
        hooks.install(path, sensor_executable, "workbuddy")
        assert hooks.installed(path, "workbuddy") and not any("shell" in handler for handler in ours())
        for key in ("disableAllHooks", "allowManagedHooksOnly"):
            installed = hooks.load_settings(path)
            path.write_text(json.dumps({**installed, key: True}))
            hooks.install(path, sensor_executable, "workbuddy", explicit=True)
            assert hooks.load_settings(path)[key] is True
            assert not hooks.installed(path, "workbuddy")
            path.write_text(json.dumps(installed))
        hooks.uninstall(path, "workbuddy")
        assert hooks.load_settings(path) == original
        assert not hook_runtime.directory(path).exists()


def test_workbuddy_hooks_fail_open_without_a_startable_windows_shell(tmp_path, monkeypatch, sensor_executable):
    # WorkBuddy rejects every action whose hook shell cannot start, so setup
    # must only leave OpenAIDR hooks where WorkBuddy's own shell choice starts.
    from openaidr.sensor import workbuddy
    from test_hooks_setup import sensor_config

    tools, system = tmp_path / "tools", tmp_path / "Windows"
    tools.mkdir()
    monkeypatch.setattr(workbuddy, "WINDOWS", True)
    monkeypatch.setenv("PATH", str(tools))
    monkeypatch.setenv("SYSTEMROOT", str(system))
    monkeypatch.setattr(hooks, "detect_apps", lambda config=None: {agent: agent == "workbuddy" for agent in hooks.APP_EVENTS})

    def shell(path, code):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"#!/bin/sh\nexit {code}\n")
        path.chmod(0o755)

    def unavailable():
        monkeypatch.setattr(workbuddy, "_shell_cache", None)
        return workbuddy.hook_shell_unavailable()

    config = sensor_config(tmp_path)
    path = hooks.settings_path("workbuddy", config)
    path.parent.mkdir(parents=True, exist_ok=True)
    original = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "personal-check"}]}]}}
    path.write_text(json.dumps(original))

    # No Git Bash and no PowerShell: automatic setup adds nothing, an explicit
    # request explains why, and status keeps setup from retrying.
    assert unavailable()
    hooks.install(path, sensor_executable, "workbuddy", config_path=config.path)
    assert hooks.load_settings(path) == original
    with pytest.raises(ValueError, match="cannot start Git Bash or PowerShell"):
        hooks.install(path, sensor_executable, "workbuddy", config_path=config.path, explicit=True)
    state = hooks.status(config=config)["workbuddy"]
    assert state["shell_unavailable"] and not state["available"] and not state["installed"]

    # Windows PowerShell on PATH (or in System32) is used when Git Bash is absent.
    shell(tools / "powershell", 0)
    assert not unavailable()
    hooks.install(path, sensor_executable, "workbuddy", config_path=config.path)
    assert hooks.installed(path, "workbuddy")
    assert hooks.status(config=config)["workbuddy"]["available"]
    assert not hooks.remove_unstartable_workbuddy(path, config.path)

    # WorkBuddy uses Git Bash first and does not fall back when it cannot
    # start, for example under application control. Remove only our hooks.
    shell(tmp_path / "Git" / "cmd" / "git", 0)
    shell(tmp_path / "Git" / "bin" / "bash.exe", 1)
    monkeypatch.setenv("PATH", os.pathsep.join([str(tools), str(tmp_path / "Git" / "cmd")]))
    assert unavailable()
    assert hooks.remove_unstartable_workbuddy(path, config.path)
    assert hooks.load_settings(path) == original and not hooks.opted_out(config, "workbuddy")
    shell(tmp_path / "Git" / "bin" / "bash.exe", 0)
    assert not unavailable()
    hooks.install(path, sensor_executable, "workbuddy", config_path=config.path)
    assert hooks.installed(path, "workbuddy")


def test_copilot_timeout_override_and_disable_all_hooks(tmp_path, sensor_executable):
    path = tmp_path / ".copilot/hooks/openaidr.json"
    hooks.install(path, sensor_executable, "copilot")
    settings = json.loads(path.read_text())
    settings["hooks"]["preToolUse"][0]["timeoutSec"] = 99
    path.write_text(json.dumps(settings))
    assert not hooks.current(None, "copilot", path)
    hooks.install(path, sensor_executable, "copilot")
    assert hooks.current(None, "copilot", path)
    (path.parent.parent / "settings.json").write_text('{"disableAllHooks": true}')
    assert not hooks.installed(path, "copilot") and not hooks.current(None, "copilot", path)


def test_opencode_plugin_executes_and_only_throws_for_valid_denial(tmp_path):
    node = shutil.which("node")
    assert node, "Node.js is required to verify the OpenCode plugin"
    plugin = tmp_path / "openaidr.mjs"
    script = "process.stdin.resume(); process.stdin.on('end',()=>process.stdout.write(process.env.TEST_REPLY || ''));"
    config = {"timeout": 3, "invocations": {event: [node, "-e", script] for event in APP_EVENTS["opencode"]}}
    plugin.write_text(hook_opencode.render(config))
    runner = tmp_path / "check.mjs"
    runner.write_text('''
import assert from "node:assert/strict";
import { OpenAIDR } from "./openaidr.mjs";
const hooks = await OpenAIDR({ directory: "/project" });
const input = { sessionID: "s", callID: "c", tool: "bash" };
for (const response of ["", "invalid", "null", "[]", '{"decision":"allow"}', '{"decision":"deny"}']) {
  process.env.TEST_REPLY = response;
  await hooks["tool.execute.before"](input, { args: { command: "echo test" } });
}
process.env.TEST_REPLY = '{"decision":"deny","reason":"Test denial"}';
await assert.rejects(hooks["tool.execute.before"](input, { args: {} }), /Test denial/);
await hooks["tool.execute.after"](input, { output: "raw result" });
await hooks["chat.message"](input, { parts: [{ type: "text", text: "raw prompt" }] });
await hooks.event({ event: { type: "session.created", properties: { info: { id: "s" } } } });
''')
    result = subprocess.run([node, str(runner)], text=True, capture_output=True, timeout=15)
    assert result.returncode == 0 and result.stdout == "" and result.stderr == "", result
    config["timeout"] = 0.1
    config["invocations"]["PreToolUse"] = [node, "-e", "setTimeout(()=>console.log('{\"decision\":\"deny\",\"reason\":\"late\"}'),1000)"]
    plugin.write_text(hook_opencode.render(config))
    result = subprocess.run([node, "--input-type=module", "-e",
                             "const {OpenAIDR}=await import(" + json.dumps(plugin.as_uri()) + ");"
                             "const hooks=await OpenAIDR({directory:'/project'});"
                             "await hooks['tool.execute.before']({sessionID:'s',tool:'bash'},{args:{}});"],
                            capture_output=True, timeout=3)
    assert result.returncode == 0 and result.stdout == b"" and result.stderr == b"", result
