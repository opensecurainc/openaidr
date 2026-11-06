"""Hook installation edge cases: partial files, malformed files, trust, and setup safety."""

import hashlib
import json
import os
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import tomlkit

from openaidr.sensor import bridge, cli, hook_runtime, hooks, service
from openaidr.sensor.config import Config
from openaidr.core.policy import Policy
from hook_process import run_hook


# Claude/Codex schema and telemetry fixtures below stay specific to those agents.
# New native schemas and transports are exercised in test_hook_apps.py.
LEGACY_AGENTS = ("claude", "codex")

# The real path helpers, captured before the autouse fixture replaces them.
REAL_SETTINGS_PATH, REAL_CODEX_CONFIG_PATH = hooks.settings_path, hooks.codex_config_path


def codex_files(tmp_path):
    return tmp_path / "hooks.json", tmp_path / "config.toml"


def sensor_config(tmp_path):
    cfg = Config(
        tmp_path / "sensor.yaml",
        data_dir=str(tmp_path / "data"),
        server_url="https://remote.example",
        sensor_id="sensor-id",
        sensor_token="remote-token",
        telemetry={"listen": "127.0.0.1:0"},
    )
    cfg.save()
    return cfg


def hook_receipts(directory, count=1):
    recorded = []
    deadline = time.monotonic() + 2
    while len(recorded) < count:
        hook_runtime.collect(directory, recorded.append, sensor_id="sensor-id")
        assert time.monotonic() < deadline, "detached hook receipt was not recorded"
        if len(recorded) < count:
            time.sleep(0.01)
    return recorded


def runtime_removed(path):
    # Runtime removal is detached so it never extends the agent's wait. It
    # waits for the hook's process group to end, then removes the directory.
    deadline = time.monotonic() + 2
    while path.exists():
        assert time.monotonic() < deadline, "detached hook runtime was not removed"
        time.sleep(0.01)
    return True


@pytest.mark.parametrize("windows,command,owned", [
    (False, "openaidr hook PreToolUse", True),
    (False, "'/Applications/OpenAIDR.app/Contents/MacOS/openaidr' hook PreToolUse", True),
    (False, "openaidr-sensor hook PreToolUse", True),
    (False, "/custom/openaidr-sensor-new hook PreToolUse", True),
    (False, "/custom/openaidr-helper hook PreToolUse", False),
    (False, "/openaidr/bin/user-hook hook PreToolUse", False),
    (False, "openaidr-server hook PreToolUse", False),
    (False, "openaidr setup", False),
    (True, r'"C:\Program Files\OpenAIDR\openaidr.exe" hook PreToolUse', True),
    (True, r'"C:\Program Files\OpenAIDR\OPENAIDR.EXE" hook PreToolUse', True),
    (True, r'"C:\Program Files\OpenAIDR\openaidr-sensor.exe" hook PreToolUse', True),
    (True, r'"C:\Program Files\openaidr\user-hook.exe" hook PreToolUse', False),
    (True, r'"C:\Program Files\OpenAIDR\openaidr-service.exe" hook PreToolUse', False),
])
def test_hook_ownership_recognizes_canonical_and_legacy_commands_only(monkeypatch, windows, command, owned):
    monkeypatch.setattr(hooks, "os", SimpleNamespace(name="nt" if windows else "posix"))
    assert hooks.our_handler({"type": "command", "command": command}) is owned


@pytest.mark.parametrize("agent", hooks.AGENTS)
@pytest.mark.parametrize("executable_name", ["openaidr", "openaidr-sensor"])
def test_missing_hook_executable_fails_open_silently(tmp_path, agent, executable_name):
    command = hooks.command_line(str(tmp_path / "missing" / executable_name), "PreToolUse", agent)
    result = subprocess.run(["/bin/sh", "-c", command], input="{}", text=True, capture_output=True,
                            timeout=3, env={**os.environ, "PATH": ""})
    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")
    recorded = hook_receipts(hook_runtime.directory(hooks.settings_path(agent)))
    assert len(recorded) == 1
    assert recorded[0]["hook"] == {"hook_event": "PreToolUse", "exit_code": 127, "outcome": "failed",
                                    "execution_id": recorded[0]["hook"]["execution_id"]}
    assert len(recorded[0]["hook"]["execution_id"]) == 32


@pytest.mark.parametrize("agent", hooks.AGENTS)
@pytest.mark.parametrize("failure", ["crash", "interpreter", "permission", "timeout"])
def test_hook_launch_failures_discard_output_and_record_outcomes(tmp_path, agent, failure):
    executable = tmp_path / "openaidr-sensor"
    if failure == "interpreter":
        executable.write_text("#!/missing/interpreter\n")
    elif failure == "timeout":
        executable.write_text("#!/bin/sh\nprintf 'partial output'\nexec sleep 10\n")
    else:
        executable.write_text("#!/bin/sh\nprintf 'partial output'\nprintf 'private error' >&2\nexit 2\n")
    executable.chmod(0o600 if failure == "permission" else 0o700)
    command = hooks.command_line(str(executable), "PreToolUse", agent)
    result = run_hook(["/bin/sh", "-c", command], input="{}", text=True, timeout=3)
    assert (result.stdout, result.stderr) == ("", "")
    assert result.returncode == 0 and not result.timed_out
    directory = hook_runtime.directory(hooks.settings_path(agent))
    recorded = hook_receipts(directory)
    assert all(p.stat().st_size == 0 for p in directory.iterdir() if p.is_file())
    assert len(recorded) == 1 and recorded[0]["hook"]["outcome"] == "failed"
    assert "partial output" not in json.dumps(recorded) and "private error" not in json.dumps(recorded)
    hook_runtime.collect(directory, recorded.append, sensor_id="sensor-id")
    assert len(recorded) == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX native launcher")
@pytest.mark.parametrize("failure", ["missing", "syntax", "directory", "fifo"])
@pytest.mark.parametrize("agent", ["codex", "hermes"])
def test_unavailable_guardrail_script_fails_open_without_partial_output(tmp_path, failure, agent):
    command = hook_runtime.command(["/bin/cat"], tmp_path / "health", agent, "PreToolUse")
    runner = Path(shlex.split(command)[4])
    if failure == "syntax":
        runner.write_text("#!/bin/sh\nprintf 'partial decision'\nprintf 'private error' >&2\nif\n")
    else:
        runner.unlink()
        if failure == "directory":
            runner.mkdir()
        elif failure == "fifo":
            os.mkfifo(runner)
    started = time.monotonic()
    result = subprocess.run(["/bin/sh", "-c", command], input="{}", text=True, capture_output=True, timeout=3)
    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")
    assert time.monotonic() - started < 3


@pytest.mark.skipif(os.name == "nt", reason="POSIX native launcher")
def test_guardrail_script_records_failed_native_output_delivery(tmp_path):
    health = tmp_path / "health"
    command = hook_runtime.command(["/bin/echo", '{"permissionDecision":"deny"}'], health, "codex", "PreToolUse")
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    try:
        result = subprocess.run(["/bin/sh", "-c", command], input="{}", text=True,
                                stdout=write_fd, stderr=subprocess.PIPE, timeout=3)
    finally:
        os.close(write_fd)
    assert (result.returncode, result.stderr) == (0, "")
    receipt, = hook_receipts(health)
    assert receipt["hook"]["outcome"] == "failed"
    assert not any("permissionDecision" in path.name or "deny" in path.name for path in health.iterdir())


@pytest.mark.parametrize("decision", ["allow", "deny"])
@pytest.mark.parametrize("temp_variable", ["TMPDIR", "TMP", "TEMP", None])
def test_hook_launcher_preserves_stdin_decisions_and_quoted_paths(tmp_path, decision, temp_variable):
    directory = tmp_path / "user's $(touch unexpected) install"
    directory.mkdir()
    executable = directory / "openaidr-sensor"
    executable.write_text('#!/bin/sh\nprintf "%s" "$TMPDIR" > runtime.path\ncat\nprintf diagnostic >&2\n')
    executable.chmod(0o700)
    scratch = directory / "temp"
    scratch.mkdir()
    unusable = tmp_path / "not-a-directory"
    unusable.touch()
    env = {**os.environ, "TMPDIR": str(tmp_path / "missing"), "TMP": str(unusable),
           "TEMP": str(tmp_path / "also-missing")}
    if temp_variable:
        env[temp_variable] = str(scratch)
    payload = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision}}
    command = hooks.command_line(str(executable), "PreToolUse", "codex", health_dir=directory / "health")
    runner = Path(shlex.split(command)[4])
    assert runner.name == "guardrail.sh" and len(command) < 1024
    assert hook_runtime.arguments(command)[1]
    # Older sensors still recognize their handlers from the inline layout.
    assert shlex.split(command)[8:] == ["openaidr", *hook_runtime.arguments(command)[0][1:]]
    assert hook_runtime.arguments(command)[0][0] == str(executable)
    result = subprocess.run(["/bin/sh", "-c", command], input=json.dumps(payload), text=True,
                            capture_output=True, timeout=3, cwd=tmp_path, env=env)
    assert result.returncode == 0 and result.stderr == ""
    assert json.loads(result.stdout) == payload
    runtime = Path((tmp_path / "runtime.path").read_text())
    assert runtime.parent.resolve() == (scratch if temp_variable else Path("/tmp")).resolve()
    assert runtime_removed(runtime)
    assert not (tmp_path / "unexpected").exists()
    recorded = hook_receipts(directory / "health")
    assert len(recorded) == 1 and recorded[0]["hook"]["outcome"] == "succeeded"


@pytest.mark.parametrize("agent,event,seconds", [("claude", "PreToolUse", 3), ("codex", "PreToolUse", 3),
                                                ("codex", "SessionEnd", 3)])
# A sensor that ignores TERM, like a bootloader still deleting its extraction,
# must not keep the launcher from removing its runtime.
@pytest.mark.parametrize("on_term", ["", "trap '' TERM\n"], ids=["exits", "ignores-term"])
def test_hook_timeout_stops_a_packaged_sensors_child_process(tmp_path, agent, event, seconds, on_term):
    executable = tmp_path / "openaidr-sensor"
    executable.write_text(
        "#!/bin/sh\n" + on_term +
        'runtime=$(/usr/bin/mktemp -d "$TMPDIR/_MEI.XXXXXXXX")\n'
        'printf runtime > "$runtime/payload"\n'
        'printf "%s" "$runtime" > runtime.path\n'
        "/bin/sleep 20 &\nprintf '%s' $! > child.pid\nwait\n"
    )
    executable.chmod(0o700)
    command = hooks.command_line(str(executable), event, agent)
    started = time.monotonic()
    result = run_hook(["/bin/sh", "-c", command], input="{}", text=True,
                            timeout=seconds, cwd=tmp_path)
    assert time.monotonic() - started < seconds
    assert not result.timed_out and (result.returncode, result.stdout, result.stderr) == (0, "", "")
    extraction = Path((tmp_path / "runtime.path").read_text())
    assert runtime_removed(extraction.parent)
    child = int((tmp_path / "child.pid").read_text())
    deadline = time.monotonic() + 2
    while True:
        state = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(child)], text=True, capture_output=True)
        if not state.stdout.strip() or state.stdout.strip().startswith("Z"):
            break
        assert time.monotonic() < deadline, "timed-out hook child is still running"
        time.sleep(0.01)


def test_hook_reporting_failure_does_not_affect_the_agent(tmp_path, sensor_executable):
    unwritable = tmp_path / "not-a-directory"
    unwritable.touch()
    command = hooks.command_line(sensor_executable, "Stop", "codex", health_dir=tmp_path / "health")
    runner = Path(shlex.split(command)[4])
    config = hook_runtime.posix_config(runner.read_text())
    config["directory"] = str(unwritable / "health")
    runner.write_text(hook_runtime.posix_script(config))
    result = subprocess.run(["/bin/sh", "-c", command], input="{}", text=True, capture_output=True, timeout=3)
    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")
    full = tmp_path / "full"
    full.mkdir()
    for index in range(hook_runtime.MAX_RECORDS):
        (full / str(index)).touch()
    command = hooks.command_line(sensor_executable, "Stop", "codex", health_dir=full)
    result = subprocess.run(["/bin/sh", "-c", command], input="{}", text=True, capture_output=True, timeout=3)
    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")
    assert len([p for p in full.iterdir() if p.is_file()]) == hook_runtime.MAX_RECORDS


def test_hook_measurements_replay_with_stable_ids_and_ship_on_heartbeat(tmp_path, monkeypatch):
    from openaidr.sensor.runtime import Sensor

    directory = hook_runtime.directory(hooks.settings_path("codex"))
    directory.mkdir()
    (directory / "codex.PreToolUse.1790982000.127.ABCDEF").touch()
    recorded = []

    def interrupted(event):
        recorded.append(event)
        raise RuntimeError("spool write interrupted")

    hook_runtime.collect(directory, interrupted, sensor_id="sensor-id")
    assert len(list(directory.iterdir())) == 1
    hook_runtime.collect(directory, interrupted, sensor_id="another-sensor")
    assert recorded[0]["id"] != recorded[1]["id"]
    cfg = sensor_config(tmp_path)
    sensor = Sensor(cfg)
    monkeypatch.setattr(sensor.client, "post", lambda *_: {})
    try:
        sensor.heartbeat_once()
        queued = sensor.spool.read()["events"]
        assert len(queued) == 1 and queued[0]["id"] == recorded[0]["id"]
        assert queued[0]["hook"]["outcome"] == "failed"
        assert queued[0]["source"]["collector"] == "hook-runtime"
        assert not list(directory.iterdir())
        sensor.heartbeat_once()
        assert sensor.spool.depth == 1
    finally:
        if sensor.telemetry:
            sensor.telemetry.close()
        sensor.spool.close()
        sensor.client.close()


@pytest.mark.parametrize("agent", hooks.AGENTS)
def test_real_hook_connection_and_configuration_errors_are_silent(tmp_path, agent, monkeypatch):
    cfg = sensor_config(tmp_path)
    # No listener accepts connections addressed to port zero. Then fail config parsing.
    cfg["listen"] = "127.0.0.1:0"
    cfg.save()
    monkeypatch.delenv("OPENAIDR_MANAGED_BRIDGE", raising=False)
    executable = str(Path(sys.executable).parent / "openaidr-sensor")
    command = hooks.command_line(executable, "PreToolUse", agent, cfg.path)
    for malformed in (False, True):
        if malformed:
            cfg.path.write_text("[invalid: yaml")
        result = subprocess.run(["/bin/sh", "-c", command], input="{}", text=True, capture_output=True, timeout=10)
        assert (result.returncode, result.stdout, result.stderr) == (0, "", "")
    recorded = hook_receipts(hook_runtime.directory(hooks.settings_path(agent)), count=2)
    assert len(recorded) == 2 and all(e["hook"]["outcome"] == "failed" for e in recorded)


@pytest.mark.parametrize("decision,timeout", [("allow", ""), ("deny", ""), ("ask", ""),
                                             ("deny", "evaluation"), ("deny", "exit"), ("deny", "policy")])
@pytest.mark.parametrize("executable_name", ["openaidr", "openaidr-sensor"])
def test_installed_hook_reports_only_delivered_decisions(tmp_path, monkeypatch, decision, timeout, backend_hook, executable_name):
    import socket
    from openaidr.sensor.runtime import Sensor

    cfg = sensor_config(tmp_path)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        cfg["listen"] = f"127.0.0.1:{reservation.getsockname()[1]}"
    cfg.save()
    sensor = Sensor(cfg)
    sensor.capture["tool_input"] = False
    monkeypatch.setattr(sensor.client, "post", lambda *_: {})
    monkeypatch.delenv("OPENAIDR_MANAGED_BRIDGE", raising=False)
    evaluate = backend_hook(action=decision)
    release, entered, staged, stop = (threading.Event() for _ in range(4))

    def backend(request, deadline):
        if timeout == "evaluation":
            entered.set()
            assert release.wait(5)
        elif timeout == "policy":
            raise ValueError("backend evaluation unavailable")
        return evaluate(request, deadline)

    sensor.hooks.check = backend
    emit = sensor.hooks.emit

    def track_decision(event):
        emit(event)
        if event["kind"] == "hook.decision":
            staged.set()

    sensor.hooks.emit = track_decision
    runner = threading.Thread(target=sensor.hooks.run, args=(stop,), daemon=True)
    runner.start()
    try:
        deadline = time.monotonic() + 3
        while True:
            try:
                hooks.local_request(cfg, "GET", "/healthz")
                break
            except Exception:
                assert time.monotonic() < deadline
                time.sleep(0.01)
        # Install after the daemon has started, outside both default settings
        # paths. A different service HOME must still find its completion record.
        path = tmp_path / "custom-agent-home" / "settings.json"
        executable = str(Path(sys.executable).parent / executable_name)
        if timeout == "exit":
            import shlex

            hanging = tmp_path / "hanging-openaidr-sensor"
            hanging.write_text(f'#!/bin/sh\n{shlex.quote(executable)} "$@"\nexec /bin/sleep 20\n')
            hanging.chmod(0o700)
            executable = str(hanging)
        hooks.install(path, executable, "claude", config_path=cfg.path)
        command = json.loads(path.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        monkeypatch.setattr(hooks, "settings_path", lambda *_: tmp_path / "service-home" / "hooks.json")
        payload = {"session_id": "session", "tool_name": "Bash", "tool_input": {"command": "echo private"}}
        if timeout == "policy":
            payload["tool_input"]["command"] = "a" * 100_000 + "!"
        result = run_hook(["/bin/sh", "-c", command], input=json.dumps(payload), text=True,
                                timeout=3)
        assert not result.timed_out
        assert (result.returncode, result.stderr) == (0, "")
        assert not any(e["kind"] == "hook.decision" for e in sensor.spool.read()["events"])
        assert sensor.hooks.stats["denied"] == sensor.hooks.stats["asked"] == 0
        if timeout:
            assert result.stdout == ""
            # Collect failure before evaluation finishes to cover that race.
            sensor.heartbeat_once()
            assert (entered if timeout == "evaluation" else staged).is_set()
            if timeout == "evaluation":
                time.sleep(0.1)  # Cross the timestamp captured after native process startup.
            release.set()
            assert staged.wait(3)
        else:
            output = json.loads(result.stdout or "{}")
            assert output.get("hookSpecificOutput", {}).get("permissionDecision", "allow") == decision
        # Enabling capture later must not reveal data omitted when observed.
        sensor.capture["tool_input"] = True
        receipt_deadline = time.monotonic() + 3
        while True:
            sensor.heartbeat_once()
            events = sensor.spool.read()["events"]
            measurements = [e for e in events if e["source"]["collector"] == "hook-runtime"]
            if measurements:
                break
            assert time.monotonic() < receipt_deadline
            time.sleep(0.01)
        assert len({e["id"] for e in measurements}) == 1
        if measurements:
            assert measurements[0]["hook"]["outcome"] == ("failed" if timeout else "succeeded")
        decisions = [e for e in events if e["kind"] == "hook.decision"]
        assert len(decisions) == (0 if timeout else 1)
        if decisions:
            assert decisions[0]["hook"]["delivery"] == "delivered"
            assert decisions[0]["hook"]["execution_id"] == measurements[0]["hook"]["execution_id"]
            assert "tool" not in decisions[0]
        assert sensor.hooks.stats["denied"] == (1 if decision == "deny" and not timeout else 0)
        assert sensor.hooks.stats["asked"] == (1 if decision == "ask" and not timeout else 0)
        assert not any(p.is_file() for p in hook_runtime.directory(path).iterdir())
        if timeout == "policy":
            sensor.hooks.check = backend_hook(action="deny")
            recovered = subprocess.run(["/bin/sh", "-c", command], input=json.dumps(payload), text=True,
                                       capture_output=True, timeout=4)
            assert recovered.returncode == 0 and recovered.stderr == ""
            assert json.loads(recovered.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    finally:
        release.set()
        stop.set()
        runner.join(5)
        if sensor.telemetry:
            sensor.telemetry.close()
        sensor.spool.close()
        sensor.client.close()


def test_a_missing_managed_event_is_not_installed_for_either_agent(tmp_path, sensor_executable):
    claude = tmp_path / "settings.json"
    hooks.install(claude, sensor_executable, "claude")
    assert hooks.installed(claude, "claude")
    settings = json.loads(claude.read_text())
    del settings["hooks"]["UserPromptSubmit"]
    claude.write_text(json.dumps(settings))
    assert not hooks.installed(claude, "claude")
    assert hooks.status({"claude": claude})["claude"] == {"installed": False, "partial": True}

    path, config_toml = codex_files(tmp_path)
    hooks.install_codex(path, sensor_executable, config_toml)
    assert hooks.codex_trusted(path, config_toml)
    settings = json.loads(path.read_text())
    del settings["hooks"]["PostToolUse"]
    path.write_text(json.dumps(settings))
    # The remaining hooks are still trusted, but results would be lost.
    assert not hooks.installed(path, "codex")
    assert not hooks.codex_trusted(path, config_toml)
    # One trust entry missing is also not trusted.
    hooks.install_codex(path, sensor_executable, config_toml)
    document = tomlkit.parse(config_toml.read_text())
    del document["hooks"]["state"][f"{path}:user_prompt_submit:0:0"]
    config_toml.write_text(tomlkit.dumps(document))
    assert hooks.installed(path, "codex") and not hooks.codex_trusted(path, config_toml)


@pytest.mark.parametrize("command_form", ["path", "posix_quotes", "windows_quotes"])
@pytest.mark.parametrize("executable_name", ["openaidr", "openaidr-sensor"])
def test_hook_status_resolves_executables_without_running_commands(
    tmp_path, monkeypatch, sensor_executable, command_form, executable_name
):
    path = tmp_path / "settings.json"
    named = Path(sensor_executable).with_name(executable_name)
    if named != Path(sensor_executable):
        named.symlink_to(sensor_executable)
    if command_form == "path":
        monkeypatch.setenv("PATH", str(Path(sensor_executable).parent))
        executable = executable_name
    else:
        quoted = tmp_path / "user's install" / executable_name
        quoted.parent.mkdir()
        quoted.symlink_to(sensor_executable)
        executable = str(quoted)
        if command_form == "windows_quotes":
            monkeypatch.setattr(hooks, "os", SimpleNamespace(name="nt"))
    hooks.install(path, executable)
    if command_form == "windows_quotes":
        for entries in json.loads(path.read_text())["hooks"].values():
            assert len(entries[0]["hooks"][0]["command"]) < 8191

    def no_execution(*args, **kwargs):
        raise AssertionError("status must not execute a hook command")

    monkeypatch.setattr(subprocess, "run", no_execution)
    assert hooks.installed(path)
    Path(sensor_executable).unlink()
    assert not hooks.installed(path)
    if command_form == "windows_quotes":
        import base64

        truncated = f"# {hook_runtime.MARKER}\n$hook = ConvertFrom-Json '"
        encoded = base64.b64encode(truncated.encode("utf-16-le")).decode()
        settings = json.loads(path.read_text())
        for entries in settings["hooks"].values():
            entries[0]["hooks"][0]["command"] = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}"
        path.write_text(json.dumps(settings))
        assert not hooks.installed(path)


@pytest.mark.parametrize("failure", ["missing", "corrupt"])
def test_unavailable_windows_launcher_remains_owned_for_repair(tmp_path, monkeypatch, failure):
    monkeypatch.setattr(hooks, "os", SimpleNamespace(name="nt"))
    path = tmp_path / "settings.json"
    hooks.install(path, r"C:\Program Files\OpenAIDR\openaidr.exe")
    for runner in (hook_runtime.directory(path) / "launchers").glob("*.ps1"):
        if failure == "missing":
            runner.unlink()
        else:
            runner.write_text("invalid launcher")
    assert hooks.present(path)
    assert not hooks.installed(path)
    hooks.uninstall(path)
    assert not hooks.present(path)


@pytest.mark.parametrize("agent", ["claude", "codex"])
@pytest.mark.parametrize("previous_client", ["powershell", "native"])
@pytest.mark.parametrize("previous_seconds", [2, 3])
def test_windows_native_client_upgrade_repair_and_uninstall(tmp_path, monkeypatch, agent, previous_client, previous_seconds):
    monkeypatch.setattr(hooks, "os", SimpleNamespace(name="nt"))
    path = tmp_path / "hooks.json"
    sensor = tmp_path / "user's & installation" / "openaidr.exe"
    sensor.parent.mkdir()
    sensor.write_text("sensor")
    sensor.chmod(0o755)
    config = Config(tmp_path / "config with ’ $ %.yaml")
    config.save()
    client = sensor.with_name("openaidr-hook.exe")
    if previous_client == "native":
        client.write_bytes(b"compiled hook")
    config_toml = tmp_path / "config.toml"

    def install():
        if agent == "codex":
            hooks.install_codex(path, str(sensor), config_toml, config.path)
        else:
            hooks.install(path, str(sensor), agent, config.path)

    with monkeypatch.context() as older:
        older.setattr(hooks, "WINDOWS_AGENT_HOOK_TIMEOUT_SECONDS", previous_seconds)
        older.setattr(hook_runtime, "AGENT_HOOK_TIMEOUT_SECONDS", previous_seconds)
        install()
        old = json.loads(path.read_text())["hooks"]["PreToolUse"][0]
        assert hooks.available(old, "PreToolUse", agent)
    old_runners = {p: p.read_bytes() for p in (hook_runtime.directory(path) / "launchers").iterdir()}
    client.write_bytes(b"compiled hook")
    assert not hooks.available(old, "PreToolUse", agent)
    install()
    settings = json.loads(path.read_text())
    for event in hooks.managed_events(agent):
        handler, = settings["hooks"][event][0]["hooks"]
        assert handler["timeout"] == (3 if agent == "codex" and event == "SessionEnd" else 5)
        runner = Path(bytes.fromhex(handler["command"].split()[-1]).decode())
        assert json.loads(runner.read_text())["seconds"] == 3
    if agent == "codex":
        assert hooks.codex_trusted(path, config_toml)
    # Already-running agents retain their original command and deadline.
    assert all(p.read_bytes() == content for p, content in old_runners.items())
    group = settings["hooks"]["PreToolUse"][0]
    command = group["hooks"][0]["command"]
    if previous_client == "native" and previous_seconds == 3:
        assert command == old["hooks"][0]["command"]
    assert "powershell" not in command.lower()
    assert hooks.available(group, "PreToolUse", agent)
    assert hook_runtime.arguments(command, windows=True)[0] == hooks.command_args(str(sensor), "PreToolUse", agent, config.path)
    descriptor = Path(bytes.fromhex(command.split()[-1]).decode())
    descriptor.write_text("invalid")
    assert hooks.present(path) and not hooks.available(group, "PreToolUse", agent)
    install()
    assert hooks.installed(path, agent)
    unrelated = descriptor.parent / "unrelated.json"
    unrelated.write_text("{}")
    hooks.uninstall(path, agent)
    assert not hooks.present(path) and unrelated.exists()
    assert not list(descriptor.parent.glob("*.ps1"))
    assert list(descriptor.parent.glob("*.json")) == [unrelated]


@pytest.mark.parametrize(
    "content",
    [
        {"hooks": None},
        {"hooks": []},
        {"hooks": {"PreToolUse": 5}},
        {"hooks": {"PreToolUse": [{"hooks": 5}]}},
        {"hooks": {"PreToolUse": [{"hooks": [{"command": None}]}]}},
        {"hooks": {"PreToolUse": ["text", 3, None]}},
    ],
)
def test_malformed_hook_files_read_as_not_installed_and_are_not_overwritten(
    tmp_path, content, sensor_executable
):
    claude = tmp_path / "settings.json"
    path, config_toml = codex_files(tmp_path)
    for target in (claude, path):
        target.write_text(json.dumps(content))
    state = hooks.status({"claude": claude, "codex": path, "codex_config": config_toml})
    assert state["claude"]["installed"] is False and state["codex"]["trusted"] is False
    shape_ok = isinstance(content["hooks"], dict) and not isinstance(
        content["hooks"].get("PreToolUse"), int
    )
    if shape_ok:
        hooks.install(claude, sensor_executable, "claude")
        hooks.install_codex(path, sensor_executable, config_toml)
        assert hooks.installed(claude, "claude") and hooks.codex_trusted(path, config_toml)
    else:
        for agent, target in (("claude", claude), ("codex", path)):
            with pytest.raises(ValueError):
                hooks.install(target, sensor_executable, agent)
            assert json.loads(target.read_text()) == content
        assert not config_toml.exists()


def test_codex_home_is_canonicalized_like_codex(tmp_path, monkeypatch):
    real = tmp_path / "real-home"
    real.mkdir()
    link = tmp_path / "linked-home"
    link.symlink_to(real)
    monkeypatch.setenv("CODEX_HOME", str(link))
    assert hooks.codex_home() == real.resolve()
    monkeypatch.delenv("CODEX_HOME")
    assert hooks.codex_home() == Path.home() / ".codex"


def test_reinstall_and_uninstall_keep_the_users_own_trusted_hooks(tmp_path, sensor_executable):
    path, config_toml = codex_files(tmp_path)
    hooks.install_codex(path, sensor_executable, config_toml)
    # The user adds their own PreToolUse hook after ours and trusts it.
    settings = json.loads(path.read_text())
    mine = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/bin/true", "timeout": 5}]}
    settings["hooks"]["PreToolUse"].append(mine)
    path.write_text(json.dumps(settings))
    digest = hooks.codex_hook_hash("PreToolUse", mine, mine["hooks"][0])
    document = tomlkit.parse(config_toml.read_text())
    document["hooks"]["state"][f"{path}:pre_tool_use:1:0"] = {"trusted_hash": digest}
    config_toml.write_text(tomlkit.dumps(document))

    hooks.install_codex(path, "/new/place/openaidr-sensor", config_toml)
    settings = json.loads(path.read_text())
    assert settings["hooks"]["PreToolUse"][1] == mine
    state = tomlkit.parse(config_toml.read_text())["hooks"]["state"]
    assert state[f"{path}:pre_tool_use:1:0"]["trusted_hash"] == digest
    assert hooks.codex_trusted(path, config_toml)

    hooks.uninstall_codex(path, config_toml)
    settings = json.loads(path.read_text())
    assert settings["hooks"] == {"PreToolUse": [mine]}
    state = tomlkit.parse(config_toml.read_text())["hooks"]["state"]
    # Their hook moved to index 0; its trust moved with it.
    assert dict(state) == {f"{path}:pre_tool_use:0:0": {"trusted_hash": digest}}


def test_an_inline_hooks_table_fails_before_hooks_json_changes(tmp_path, sensor_executable):
    path, config_toml = codex_files(tmp_path)
    path.write_text('{"hooks": {}}')
    config_toml.write_text('model = "o3"\nhooks = { SessionStart = [] }\n')
    with pytest.raises(ValueError, match="inline table"):
        hooks.install_codex(path, sensor_executable, config_toml)
    assert path.read_text() == '{"hooks": {}}'
    assert config_toml.read_text() == 'model = "o3"\nhooks = { SessionStart = [] }\n'


def test_opt_out_is_applied_to_the_config_file_as_it_is_now(tmp_path):
    cfg = sensor_config(tmp_path)
    stale = Config.load(cfg.path)
    fresh = Config.load(cfg.path)
    fresh["telemetry"] = {**fresh["telemetry"], "disabled_agents": ["codex"]}
    fresh.save()
    hooks.set_opt_out(stale, "codex", True)
    saved = Config.load(cfg.path)
    assert saved["telemetry"]["disabled_agents"] == ["codex"]
    assert saved["hooks"] == {"disabled_agents": ["codex"]}
    assert stale["hooks"] == {"disabled_agents": ["codex"]}


def test_hook_install_writes_an_absolute_config_and_honors_the_environment(
    tmp_path, monkeypatch, isolated_hook_paths, sensor_executable
):
    monkeypatch.delenv("WORKBUDDY_CONFIG_DIR", raising=False)
    cfg = sensor_config(tmp_path)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    command = hooks.command_line(sensor_executable, "Stop", "codex", "sensor.yaml")
    assert hook_runtime.arguments(command)[0][-3:] == ["--config", str(cfg.path.resolve()), "Stop"]
    monkeypatch.setenv("OPENAIDR_SENSOR_CONFIG", str(cfg.path))
    monkeypatch.setattr(service, "executable", lambda: sensor_executable)
    assert cli.main(["hook", "install", "--agent", "codex"]) == 0
    written = json.loads(hooks.settings_path("codex").read_text())["hooks"]["Stop"][0]["hooks"][0]
    assert not written.get("async") and written["timeout"] == (5 if os.name == "nt" else 3)
    assert hook_runtime.arguments(written["command"]) == (
        [sensor_executable, "hook", "--agent", "codex", "--config", str(cfg.path.resolve()), "Stop"], True,
    )
    # The opt-out record lands in the same config the hooks read.
    assert cli.main(["hook", "uninstall", "--agent", "codex"]) == 0
    assert Config.load(cfg.path)["hooks"] == {"disabled_agents": ["codex"]}


def test_a_multi_file_patch_is_denied_when_any_file_matches(tmp_path, backend_hook):
    policy = Policy(
        policy={
            "rules": [
                # The warn matches the first file; the deny on a later file still decides.
                {"id": "docs", "enabled": True, "action": "warn", "match": {"path_glob": "README.md"}},
                {"id": "env", "enabled": True, "action": "deny", "match": {"path_glob": "**/.env"}},
            ]
        }
    )
    emitted = []
    server = hooks.HookServer(
        "127.0.0.1:0", tmp_path / "sock", emitted.append, lambda: {}, {}, True, check=backend_hook(policy)
    )
    patch = "*** Begin Patch\n*** Update File: README.md\n@@\n-a\n+b\n*** Update File: app/.env\n@@\n-x\n+y\n*** End Patch"
    decision = server.evaluate(
        {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "apply_patch", "tool_use_id": "c", "tool_input": {"command": patch}},
        "codex-cli",
    )
    assert decision["output"]["hookSpecificOutput"]["permissionDecision"] == "deny"
    writes = [e["file"]["path"] for e in emitted if e["kind"] == "file.write"]
    assert writes == ["README.md", "app/.env"]
    assert emitted[-1]["kind"] == "hook.decision" and emitted[-1]["hook"]["rule_id"] == "env"


def start_listener(server):
    stop = threading.Event()
    runner = threading.Thread(target=server.run, args=(stop,), daemon=True)
    runner.start()
    return stop, runner


def wait_for(request):
    deadline = time.monotonic() + 3
    while True:
        try:
            return request()
        except (httpx.TransportError, OSError):
            assert time.monotonic() < deadline
            time.sleep(0.01)


@pytest.mark.parametrize("unix_server", [True, False], ids=["unix", "no-unix-server"])
def test_loopback_listener_requires_the_account_token_and_rejects_browsers(
    tmp_path, monkeypatch, unix_server,
):
    import socket
    import socketserver

    if not unix_server:
        # Windows has no Unix server class; every request must still be handled.
        monkeypatch.delattr(socketserver, "UnixStreamServer", raising=False)
    cfg = sensor_config(tmp_path)
    cfg["telemetry"]["local_token"] = "account-token"
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        cfg["listen"] = f"127.0.0.1:{port}"
    # Every local account, and any web page, can reach loopback TCP.
    server = hooks.HookServer(
        cfg["listen"], tmp_path / "elsewhere.sock",
        lambda _: None, lambda: {"status": "private"}, {}, True, token="account-token",
    )
    stop, runner = start_listener(server)
    try:
        url = "http://" + cfg["listen"]
        hook = url + "/v1/hooks/claude-code?event=SessionStart"
        event = {"session_id": "s", "source": "startup"}
        response = wait_for(lambda: httpx.get(url + "/v1/status", trust_env=False))
        assert response.status_code == 401
        assert httpx.post(hook, json=event, trust_env=False).status_code == 401
        token = {"Authorization": "Bearer account-token"}
        for headers, body in (
            # A cross-origin page, and a same-origin page after DNS rebinding.
            ({"Origin": "https://attacker.example"}, None),
            ({"Host": f"attacker.example:{port}"}, None),
            ({"Host": "127.0.0.1:1"}, None),
            # A simple form post that a browser sends without preflight.
            ({"Content-Type": "text/plain"}, json.dumps(event)),
        ):
            sent = httpx.post(hook, headers={**token, **headers}, trust_env=False,
                              **({"content": body} if body else {"json": event}))
            assert sent.status_code == 403, headers
        assert server.stats["received"] == 0
        # The hook command reads the token from the private sensor config.
        assert hooks.local_request(cfg, "GET", "/v1/status") == {"status": "private"}
        assert hooks.local_request(cfg, "POST", "/v1/hooks/claude-code?event=SessionStart",
                                   content=json.dumps(event),
                                   headers={"Content-Type": "application/json"}) is not None
        assert server.stats["received"] == 1
    finally:
        stop.set()
        runner.join(5)


@pytest.mark.skipif(os.name == "nt", reason="Unix sockets are not used on Windows")
@pytest.mark.parametrize("tcp_occupied", [False, True])
@pytest.mark.parametrize("stale_socket", [False, True])
def test_private_socket_needs_no_token_but_still_rejects_browsers(
    tmp_path, backend_hook, tcp_occupied, stale_socket,
):
    import socket
    import tempfile

    cfg = sensor_config(tmp_path)
    # A short directory keeps the socket path within the platform limit.
    with tempfile.TemporaryDirectory(dir="/tmp") as short, socket.socket() as reservation:
        cfg["data_dir"] = short
        reservation.bind(("127.0.0.1", 0))
        cfg["listen"] = f"127.0.0.1:{reservation.getsockname()[1]}"
        if not tcp_occupied:
            reservation.close()
        server = hooks.HookServer(
            cfg["listen"], Path(short) / "sensor.sock",
            lambda _: None, lambda: {"status": "private"}, {}, True, token="account-token",
        )
        if stale_socket:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
                stale.bind(str(server.socket_path))
        stop, runner = start_listener(server)
        try:
            transport = httpx.HTTPTransport(uds=str(server.socket_path))
            with httpx.Client(transport=transport, trust_env=False) as client:
                status = wait_for(lambda: client.get("http://localhost/v1/status"))
                assert status.json() == {"status": "private"}
                assert server.socket_path.stat().st_mode & 0o777 == 0o600
                # The socket is restricted to the sensor account, so no token is needed.
                assert hooks.local_request(cfg, "GET", "/v1/status") == {"status": "private"}
                rejected = client.get("http://127.0.0.1/v1/status",
                                      headers={"Origin": "https://attacker.example"})
                assert rejected.status_code == 403
                for decision in ("allow", "deny"):
                    server.check = backend_hook(action=decision)
                    response = client.post(
                        "http://localhost/v1/hooks/claude-code/native",
                        params={"event": "PreToolUse", "execution": "abcdef123456",
                                "deadline": str(time.time_ns() + 1_500_000_000)},
                        json={"session_id": "s", "tool_name": "Bash", "tool_input": {"command": "ls"}},
                    )
                    if decision == "allow":
                        assert response.status_code == 204 and response.content == b""
                    else:
                        assert response.status_code == 200
                        assert response.json()["hookSpecificOutput"]["permissionDecision"] == "deny"
        finally:
            stop.set()
            runner.join(5)
        assert not runner.is_alive()
        assert not server.socket_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="Unix sockets are not used on Windows")
@pytest.mark.parametrize("existing", ["live-socket", "file", "symlink"])
def test_hook_listener_preserves_existing_live_socket_and_other_paths(tmp_path, existing):
    import socket
    import tempfile

    with tempfile.TemporaryDirectory(dir="/tmp") as short, socket.socket() as reservation:
        sock = Path(short) / "sensor.sock"
        reservation.bind(("127.0.0.1", 0))
        listen = f"127.0.0.1:{reservation.getsockname()[1]}"
        runner = None
        if existing == "live-socket":
            first = hooks.HookServer("127.0.0.1:0", sock, lambda _: None, lambda: {}, {})
            stop, runner = start_listener(first)
            wait_for(sock.stat)
        elif existing == "file":
            sock.write_text("existing contents")
        else:
            target = Path(short) / "target"
            target.write_text("existing contents")
            sock.symlink_to(target)
        before = sock.lstat()
        second = hooks.HookServer(listen, sock, lambda _: None, lambda: {}, {})
        try:
            with pytest.raises(OSError, match="No hook listener could start"):
                second.run(threading.Event())
            assert os.path.samestat(before, sock.lstat())
            if existing == "live-socket":
                transport = httpx.HTTPTransport(uds=str(sock))
                with httpx.Client(transport=transport, trust_env=False) as client:
                    assert client.get("http://localhost/healthz").status_code == 200
            else:
                assert sock.read_text() == "existing contents"
        finally:
            if runner is not None:
                stop.set()
                runner.join(5)
                assert not runner.is_alive()


@pytest.mark.parametrize("transport", ["windows", "no-unix-server", "unix-bind-error"])
def test_hook_listener_reports_total_bind_failure(tmp_path, monkeypatch, transport):
    import socket
    import socketserver

    if transport == "windows":
        monkeypatch.setattr(hooks, "os", SimpleNamespace(name="nt"))
    elif transport == "no-unix-server":
        monkeypatch.delattr(socketserver, "UnixStreamServer", raising=False)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        server = hooks.HookServer(
            f"127.0.0.1:{reservation.getsockname()[1]}", tmp_path / "missing" / "sensor.sock",
            lambda _: None, lambda: {}, {},
        )
        with pytest.raises(OSError, match="No hook listener could start"):
            server.run(threading.Event())


@pytest.mark.skipif(os.name == "nt", reason="Unix sockets are not used on Windows")
def test_hook_listener_closes_private_socket_when_permissions_fail(tmp_path, monkeypatch):
    import socket
    import socketserver
    import tempfile

    chmod, close = Path.chmod, socketserver.UnixStreamServer.server_close
    closed = []
    with tempfile.TemporaryDirectory(dir="/tmp") as short:
        sock = Path(short) / "sensor.sock"

        def fail_permissions(path, mode, *args, **kwargs):
            if path == sock:
                raise PermissionError("test socket permissions")
            return chmod(path, mode, *args, **kwargs)

        def track_close(server):
            close(server)
            closed.append(server)

        monkeypatch.setattr(Path, "chmod", fail_permissions)
        monkeypatch.setattr(socketserver.UnixStreamServer, "server_close", track_close)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            listen = f"127.0.0.1:{reservation.getsockname()[1]}"
        server = hooks.HookServer(listen, sock, lambda _: None, lambda: {}, {}, token="account-token")
        stop, runner = start_listener(server)
        try:
            url = "http://" + listen + "/healthz"
            assert wait_for(lambda: httpx.get(url, trust_env=False)).status_code == 401
            assert httpx.get(url, headers={"Authorization": "Bearer account-token"},
                             trust_env=False).status_code == 200
            assert len(closed) == 1 and closed[0].socket.fileno() == -1
            assert not sock.exists()
        finally:
            stop.set()
            runner.join(5)
        assert not runner.is_alive()


@pytest.mark.skipif(os.name == "nt", reason="Native transport uses a private Unix socket")
@pytest.mark.parametrize("timeout_owner,launcher_budget_ns", [
    (None, 1_400_000_000), (None, 2_000_000_000), ("agent", 2_000_000_000), ("agent", 3_000_000_000),
    ("sensor", 1_000_000_000), ("sensor", 1_400_000_000), ("sensor", 2_100_000_000),
])
def test_native_socket_returns_only_valid_timely_agent_output(tmp_path, backend_hook, timeout_owner, launcher_budget_ns):
    import base64
    import socket
    import tempfile

    emitted = []
    with tempfile.TemporaryDirectory(dir="/tmp") as short, socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        listen = f"127.0.0.1:{reservation.getsockname()[1]}"
        reservation.close()
        sock = Path(short) / "sensor.sock"
        server = hooks.HookServer(listen, sock, emitted.append, lambda: {}, {}, token="secret")
        stop, runner = start_listener(server)
        try:
            wait_for(sock.stat)
            transport = httpx.HTTPTransport(uds=str(sock))
            with httpx.Client(transport=transport, base_url="http://localhost", trust_env=False) as client:
                for product in ("claude-code", "codex-cli"):
                    route = hooks.ROUTES[product]
                    payload = {"session_id": "s", "tool_name": "Bash", "tool_input": {"command": "ls"}}
                    query = {"event": "PreToolUse", "execution": "abcdef123456"}
                    if timeout_owner:
                        query["timeout_owner"] = timeout_owner
                    for action, mode, expected in (("allow", "enforce", "allow"),
                                                  ("deny", "shadow", "allow"),
                                                  ("deny", "enforce", "deny"),
                                                  ("ask", "enforce", "deny" if product == "codex-cli" else "ask")):
                        reply = backend_hook(action=action, mode=mode)
                        remaining = []

                        def check(request, deadline):
                            remaining.append(deadline - time.monotonic())
                            return reply(request, deadline)

                        server.check = check
                        # Older launchers keep their budgets. Newer ones separate
                        # backend resource limits from the delivery deadline.
                        started = time.time_ns() - 300_000_000
                        query.update(started=str(started), deadline=str(started + launcher_budget_ns))
                        home = "/Users/native user-é"
                        response = client.post(route + "/native", params=query, json=payload,
                                               headers={"X-OpenAIDR-Home": base64.b64encode(home.encode()).decode()})
                        if expected == "allow":
                            assert response.status_code == 204 and response.content == b""
                        else:
                            assert response.status_code == 200
                            assert response.json()["hookSpecificOutput"]["permissionDecision"] == expected
                            assert "output" not in response.json()
                        if timeout_owner:
                            assert 2 < remaining[-1] <= 10
                        else:
                            assert 0 < remaining[-1] <= 1.0
                        assert reply.requests[-1]["path_home"] == home
                        assert emitted[-1]["hook"]["delivery"] == "pending"
                    # Existing clients keep their response envelope.
                    legacy = client.post(route, params=query, json=payload)
                    assert legacy.status_code == 200 and "output" in legacy.json()
                    server.check = backend_hook(action="invalid")
                    assert client.post(route + "/native", params=query, json=payload).status_code == 503
                    assert client.post(route + "/native", params=query, json={}).status_code == 503
                    assert client.post(route + "/native", params=query, content=b"{",
                                       headers={"Content-Type": "application/json"}).status_code == 400
                    before = len(emitted)
                    query["deadline"] = str(time.time_ns() - 1)
                    assert client.post(route + "/native", params=query, json=payload).status_code == (
                        400 if timeout_owner == "agent" else 503
                    )
                    assert len(emitted) == before
                # Native output is available only on the private socket, even
                # when a TCP client knows the account token.
                blocked = httpx.post("http://" + listen + route + "/native", json=payload,
                                     headers={"Authorization": "Bearer secret"}, trust_env=False)
                assert blocked.status_code == 403
        finally:
            stop.set()
            runner.join(5)


@pytest.mark.parametrize("platform,budget_ns,timeout_owner", [
    (platform, budget, owner)
    for platform, budget in (("posix", 1_400_000_000), ("posix", 2_000_000_000),
                             ("nt", 1_000_000_000), ("posix", 2_100_000_000), ("nt", 2_100_000_000))
    for owner in (None, "agent", "sensor")
    # Agent-owned Windows requests now use the small client, exercised against
    # a real listener in test_hook_client.py instead of this legacy HTTP mock.
    if not (platform == "nt" and owner == "agent")
])
def test_packaged_hook_preserves_launcher_start_and_work_budget(tmp_path, monkeypatch, capsys, platform, budget_ns, timeout_owner):
    from io import BytesIO
    from urllib.parse import parse_qs, urlsplit

    cfg = sensor_config(tmp_path)
    environment = dict(os.environ)
    environment.pop("OPENAIDR_MANAGED_BRIDGE", None)
    environment.update(OPENAIDR_HOOK_WRAPPED="1", OPENAIDR_HOOK_EXECUTION_ID="abcdef123456",
                       OPENAIDR_HOOK_STARTED_NS="99600000000",
                       OPENAIDR_HOOK_DEADLINE_NS=str(99_600_000_000 + budget_ns))
    if timeout_owner:
        environment["OPENAIDR_HOOK_TIMEOUT_OWNER"] = timeout_owner
        if timeout_owner == "agent":
            environment["OPENAIDR_HOOK_DEADLINE_NS"] = "101600000000"
    else:
        environment.pop("OPENAIDR_HOOK_TIMEOUT_OWNER", None)
    monkeypatch.setattr(cli, "os", SimpleNamespace(**(vars(os) | dict(name=platform, environ=environment))))
    monkeypatch.setattr(cli, "STARTED_NS", 99_900_000_000)
    monkeypatch.setattr(cli, "time", SimpleNamespace(time_ns=lambda: 100_000_000_000))
    monkeypatch.setattr(cli, "sys", SimpleNamespace(stdin=SimpleNamespace(buffer=BytesIO(b"{}"))))
    requests = []

    def local_request(config, method, url, **kwargs):
        requests.append((parse_qs(urlsplit(url).query), kwargs["timeout"]))
        return {"decision": "allow", "output": {}}

    monkeypatch.setattr(hooks, "local_request", local_request)
    assert cli.main(["hook", "PreToolUse", "--config", str(cfg.path)]) == 0
    query, timeout = requests[0]
    assert query["started"] == ["99600000000"]
    if timeout_owner == "agent":
        assert query["deadline"] == ["101600000000"]
        assert query["timeout_owner"] == ["agent"]
        assert timeout is None
    else:
        expected_budget = min(budget_ns, 1_400_000_000) if platform == "posix" and not timeout_owner else budget_ns
        assert query["deadline"] == [str(99_600_000_000 + expected_budget)]
        assert timeout == pytest.approx(expected_budget / 1e9 - 0.45)
        assert query.get("timeout_owner") == ([timeout_owner] if timeout_owner else None)
    assert capsys.readouterr() == ("", "")


@pytest.mark.skipif(os.name == "nt", reason="macOS launcher uses Unix sockets and system curl")
@pytest.mark.parametrize("agent", LEGACY_AGENTS)
def test_socket_launcher_bypasses_packaged_startup_and_preserves_decisions(
    tmp_path, monkeypatch, backend_hook, agent,
):
    import tempfile

    monkeypatch.setattr(hooks, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(hooks, "is_root", lambda: False)
    monkeypatch.delenv("OPENAIDR_MANAGED_BRIDGE", raising=False)
    monkeypatch.delenv("OPENAIDR_SENSOR_CONFIG", raising=False)
    executable = tmp_path / "openaidr-sensor"
    marker = tmp_path / "python-started"
    executable.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexec /bin/sleep 10\n")
    executable.chmod(0o700)
    home = tmp_path / "user's é $(touch unexpected)"
    home.mkdir()
    # curl must not read agent/project configuration or route content through
    # an environment proxy. No event data may land in the configured output.
    (home / ".curlrc").write_text(f'output = "{tmp_path / "leaked"}"\n')
    env = {**os.environ, "HOME": str(home), "CURL_HOME": str(home),
           "http_proxy": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1", "PATH": ""}
    with tempfile.TemporaryDirectory(prefix="hook-'", dir="/tmp") as short:
        cfg = sensor_config(tmp_path)
        cfg["data_dir"] = short
        cfg.save()
        health = tmp_path / "health"
        command = hooks.command_line(str(executable), "PreToolUse", agent, cfg.path, health_dir=health)
        assert hook_runtime.arguments(command)[1]
        delivered = []
        pending = hook_runtime.PendingDecisions(delivered.append)
        server = hooks.HookServer("127.0.0.1:0", Path(short) / "sensor.sock",
                                  pending.stage, lambda: {}, {})
        stop, runner = start_listener(server)
        try:
            wait_for(server.socket_path.stat)
            for action, mode in (("allow", "enforce"), ("deny", "shadow"), ("deny", "enforce"),
                                 ("ask", "enforce"), ("warn", "enforce"), ("invalid", "enforce")):
                server.check = backend_hook(action=action, mode=mode)
                payload = {"session_id": "s", "tool_name": "Bash", "tool_input": {"command": "echo café"}}
                started = time.monotonic()
                result = subprocess.run(["/bin/sh", "-c", command], input=json.dumps(payload), text=True,
                                        capture_output=True, timeout=3, env=env, cwd=tmp_path)
                assert time.monotonic() - started < 1
                assert (result.returncode, result.stderr) == (0, "")
                assert server.check.requests[-1]["path_home"] == str(home)
                if action in ("allow", "invalid") or mode == "shadow":
                    assert result.stdout == ""
                elif action == "warn":
                    assert json.loads(result.stdout) == {"systemMessage": "OpenAIDR warning: Test policy reason"}
                else:
                    expected = "deny" if agent == "codex" else action
                    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == expected
                assert delivered == [], "A response alone cannot confirm delivery"
                receipt, = hook_receipts(health)
                assert receipt["hook"]["outcome"] == ("failed" if action == "invalid" else "succeeded")
                pending.complete(receipt)
                assert len(delivered) == (0 if action == "invalid" else 1)
                if delivered:
                    assert delivered[0]["hook"]["execution_id"] == receipt["hook"]["execution_id"]
                    assert delivered[0]["hook"]["delivery"] == "delivered"
                    if Path("/usr/bin/perl").exists():
                        assert 0 <= delivered[0]["hook"]["e2e_ms"] < 1000
                delivered.clear()
            for payload in ("{", json.dumps({}), " " * ((4 << 20) + 1)):
                result = subprocess.run(["/bin/sh", "-c", command], input=payload, text=True,
                                        capture_output=True, timeout=3, env=env)
                assert (result.returncode, result.stdout, result.stderr) == (0, "", "")
                assert hook_receipts(health)[0]["hook"]["outcome"] == "failed"
        finally:
            stop.set()
            runner.join(5)
        # A stopped sensor remains a silent, measured failure.
        result = subprocess.run(["/bin/sh", "-c", command], input="{}", text=True,
                                capture_output=True, timeout=3, env=env)
        assert (result.returncode, result.stdout, result.stderr) == (0, "", "")
        assert hook_receipts(health)[0]["hook"]["outcome"] == "failed"
        assert not marker.exists() and not (tmp_path / "unexpected").exists() and not (tmp_path / "leaked").exists()
        # Managed observers and explicit runtime config overrides must keep
        # their CLI handling rather than submitting an ordinary socket check.
        output = '{"decision":"block","reason":"existing CLI response"}'
        executable.write_text(f"#!/bin/sh\nprintf '%s' {shlex.quote(output)}\n")
        for variable in ("OPENAIDR_MANAGED_BRIDGE", "OPENAIDR_SENSOR_CONFIG"):
            fallback = subprocess.run(["/bin/sh", "-c", command], input="{}", text=True,
                                      capture_output=True, timeout=3, env={**env, variable: "/private/config"})
            assert (fallback.returncode, fallback.stdout.strip(), fallback.stderr) == (0, output, "")


@pytest.mark.skipif(os.name == "nt", reason="macOS launcher uses Unix sockets and system curl")
def test_socket_launcher_bounds_slow_checks_without_delaying_other_calls(tmp_path, monkeypatch, backend_hook):
    import concurrent.futures
    import tempfile

    monkeypatch.setattr(hooks, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(hooks, "is_root", lambda: False)
    monkeypatch.delenv("OPENAIDR_MANAGED_BRIDGE", raising=False)
    monkeypatch.delenv("OPENAIDR_SENSOR_CONFIG", raising=False)
    entered, release = threading.Event(), threading.Event()
    check = backend_hook(action="deny")

    def backend(request, deadline):
        if request["session_id"] == "slow":
            entered.set()
            assert release.wait(4)
        return check(request, deadline)

    with tempfile.TemporaryDirectory(dir="/tmp") as short:
        cfg = sensor_config(tmp_path)
        cfg["data_dir"] = short
        cfg.save()
        health = tmp_path / "health"
        command = hooks.command_line("/missing/openaidr", "PreToolUse", "codex", cfg.path, health_dir=health)
        server = hooks.HookServer("127.0.0.1:0", Path(short) / "sensor.sock",
                                  lambda _: None, lambda: {}, {}, check=backend)
        stop, runner = start_listener(server)

        def run(session):
            payload = {"session_id": session, "tool_name": "Bash", "tool_input": {"command": "ls"}}
            started = time.monotonic()
            result = run_hook(["/bin/sh", "-c", command], input=json.dumps(payload), text=True,
                                    timeout=3)
            assert not result.timed_out
            assert (result.returncode, result.stderr) == (0, "")
            assert time.monotonic() - started < 3
            return result.stdout

        try:
            wait_for(server.socket_path.stat)
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                slow = pool.submit(run, "slow")
                assert entered.wait(1)
                fast = [pool.submit(run, name) for name in ("fast-1", "fast-2")]
                for future in fast:
                    assert json.loads(future.result(timeout=1))["hookSpecificOutput"]["permissionDecision"] == "deny"
                assert slow.result(timeout=3) == ""
                receipts = hook_receipts(health, count=3)
                assert sorted(e["hook"]["outcome"] for e in receipts) == ["failed", "succeeded", "succeeded"]
        finally:
            release.set()
            stop.set()
            runner.join(5)


@pytest.mark.skipif(os.name == "nt", reason="macOS launcher uses Unix sockets and system curl")
@pytest.mark.parametrize("agent", LEGACY_AGENTS)
def test_socket_result_replacement_requires_probed_client_ancestry(tmp_path, monkeypatch, backend_hook, agent):
    import tempfile

    monkeypatch.setattr(hooks, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(hooks, "is_root", lambda: False)
    monkeypatch.delenv("OPENAIDR_MANAGED_BRIDGE", raising=False)
    monkeypatch.delenv("OPENAIDR_SENSOR_CONFIG", raising=False)
    reply = backend_hook(action="deny")

    def check(request, deadline):
        result = reply(request, deadline)
        if request["availability"] == "unsupported_boundary":
            result["returned_decision"] = "allow"
        return result

    with tempfile.TemporaryDirectory(dir="/tmp") as short:
        cfg = sensor_config(tmp_path)
        cfg["data_dir"] = short
        cfg.save()
        command = hooks.command_line("/missing/openaidr", "PostToolUse", agent, cfg.path,
                                     health_dir=tmp_path / "health")
        server = hooks.HookServer("127.0.0.1:0", Path(short) / "sensor.sock", lambda _: None,
                                  lambda: {}, {}, check=check)
        stop, runner = start_listener(server)
        try:
            wait_for(server.socket_path.stat)
            # The real shell ancestor stands in for an installed native agent;
            # cat is not in the caller's ancestry. No process lookup is mocked.
            for binary, supported in (("/bin/bash", True), ("/bin/cat", False)):
                (Path(short) / (agent + "-hook-capability.json")).write_text(json.dumps({
                    "version": [2, 1, 285] if agent == "claude" else [0, 160, 0],
                    "executable": hooks.executable_identity(binary),
                }))
                payload = {"session_id": "s", "tool_name": "Bash", "tool_use_id": "call",
                           "tool_response": {"stdout": "private result", "stderr": "",
                                             "interrupted": False, "isImage": False}}
                result = subprocess.run(["/bin/sh", "-c", command], input=json.dumps(payload), text=True,
                                        capture_output=True, timeout=3)
                assert (result.returncode, result.stderr) == (0, "")
                assert reply.requests[-1]["availability"] == ("available" if supported else "unsupported_boundary")
                if not supported:
                    assert result.stdout == ""
                elif agent == "codex":
                    assert json.loads(result.stdout)["decision"] == "block"
                else:
                    assert json.loads(result.stdout)["hookSpecificOutput"]["updatedToolOutput"]["stdout"] == "Test policy reason"
        finally:
            stop.set()
            runner.join(5)


@pytest.mark.skipif(os.name == "nt", reason="macOS hook migration")
@pytest.mark.parametrize("agent", LEGACY_AGENTS)
def test_install_repairs_legacy_socket_and_changed_data_directory(tmp_path, monkeypatch, sensor_executable, agent):
    import tempfile

    monkeypatch.setattr(hooks, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(hooks, "is_root", lambda: False)
    with tempfile.TemporaryDirectory(dir="/tmp") as short:
        cfg = sensor_config(tmp_path)
        cfg["data_dir"] = short
        cfg.save()
        path = hooks.settings_path(agent)
        with monkeypatch.context() as legacy:
            legacy.setattr(hooks, "native_socket", lambda _: None)
            hooks.install(path, sensor_executable, agent, config_path=cfg.path)
            assert hooks.current(cfg.path, agent, path)
        previous = json.loads(path.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert not hooks.current(cfg.path, agent, path)
        hooks.install(path, sensor_executable, agent, config_path=cfg.path)
        assert hooks.current(cfg.path, agent, path)
        assert Path(shlex.split(previous)[4]).is_file(), "Existing sessions retain a usable launcher path"
        if agent == "codex":
            assert hooks.codex_trusted(path, hooks.codex_config_path())
        cfg["data_dir"] = str(Path(short) / "new")
        cfg.save()
        assert not hooks.current(cfg.path, agent, path)
        hooks.install(path, sensor_executable, agent, config_path=cfg.path)
        assert hooks.current(cfg.path, agent, path)
        # Moving to a path that needs TCP must also invalidate a socket launcher.
        cfg["data_dir"] = str(tmp_path / ("long" * 30))
        cfg.save()
        assert not hooks.current(cfg.path, agent, path)
        hooks.install(path, sensor_executable, agent, config_path=cfg.path)
        assert hooks.current(cfg.path, agent, path)


@pytest.mark.parametrize("source,destination,denied", [
    ("notes.txt", ".env", ".env"),
    ("app/.env", "notes.txt", "app/.env"),
    ("notes.txt", "renamed notes.txt", None),
])
def test_patch_renames_check_both_paths_and_preserve_hook_evidence(tmp_path, source, destination, denied, backend_hook):
    policy = Policy(policy={"rules": [
        {"id": "docs", "enabled": True, "action": "warn", "match": {"path_glob": "README.md"}},
        {"id": "env", "enabled": True, "action": "deny", "match": {"kinds": ["file.write"], "path_glob": "**/.env"}},
    ]})
    emitted = []
    server = hooks.HookServer("127.0.0.1:0", tmp_path / "sock", emitted.append, lambda: {}, {}, True, check=backend_hook(policy))
    patch = ("*** Begin Patch\n*** Update File: README.md\n@@\n-old\n+new\n"
             f"*** Update File: {source}\n*** Move to: {destination}\n@@\n-old\n+new\n"
             "*** Update File: draft.txt\n*** Move to: final.txt\n@@\n-old\n+new\n*** End Patch")
    decision = server.evaluate({"session_id": "s", "hook_event_name": "PreToolUse",
                               "tool_name": "apply_patch", "tool_use_id": "rename",
                               "tool_input": {"command": patch}}, "codex-cli")
    assert decision["decision"] == ("deny" if denied else "warn")
    assert [e["file"] for e in emitted if e["kind"] == "file.write"] == [
        {"path": "README.md", "op": "edit"},
        {"path": source, "op": "rename"}, {"path": destination, "op": "rename"},
        {"path": "draft.txt", "op": "rename"}, {"path": "final.txt", "op": "rename"},
    ]
    assert all(e["tool"] == {"name": "apply_patch", "call_id": "rename", "input": {"command": patch}} for e in emitted if e["kind"] != "hook.decision")
    assert emitted[-1]["kind"] == "hook.decision"
    assert emitted[-1]["hook"]["rule_id"] == ("env" if denied else "docs")


def test_server_hook_commands_take_an_agent(tmp_path, monkeypatch, isolated_hook_paths, sensor_executable):
    from openaidr.sensor.runtime import Sensor

    cfg = sensor_config(tmp_path)
    # Inside the Windows Scheduled Task this process is the windowless build,
    # which cannot answer an agent; hooks must name the staged console sensor.
    windowless = str(tmp_path / "bin" / "openaidr-sensor-service.exe")
    monkeypatch.setattr(service, "executable", lambda: windowless)
    monkeypatch.setattr(service, "staged_executable", lambda: sensor_executable)
    sensor = Sensor(cfg)
    try:
        acks = sensor.apply(
            {
                "commands": [
                    {"id": "1", "type": "install_hook", "params": {"agent": "codex"}},
                    {"id": "2", "type": "install_hook"},
                    {"id": "3", "type": "uninstall_hook", "params": {"agent": "bogus"}},
                ]
            }
        )
    finally:
        if sensor.telemetry:
            sensor.telemetry.close()
        sensor.spool.close()
        sensor.client.close()
    assert [ack["status"] for _, ack in acks] == ["applied", "applied", "failed"]
    state = hooks.status()
    assert state["codex"]["installed"] and state["codex"]["trusted"]
    assert state["claude"]["installed"]
    for agent in LEGACY_AGENTS:
        commands = [
            hook_runtime.arguments(handler["command"])[0][0]
            for event in hooks.managed_events(agent)
            for entry in hooks.groups(hooks.load_settings(hooks.settings_path(agent)), event)
            for handler in entry["hooks"]
        ]
        assert commands and set(commands) == {sensor_executable}


def test_setup_references_a_newer_staged_service_without_replacing_it(
    tmp_path, monkeypatch, isolated_hook_paths
):
    cfg = sensor_config(tmp_path)
    bundle = tmp_path / "App.app" / "openaidr-sensor"
    bundle.parent.mkdir()
    bundle.write_bytes(b"older bundled sensor")
    staged = tmp_path / "stable" / "bin" / "openaidr-sensor"
    staged.parent.mkdir(parents=True)
    staged.write_bytes(b"newer staged sensor")
    staged.chmod(0o755)
    monkeypatch.setattr(service.sys, "frozen", True, raising=False)
    monkeypatch.setattr(service.sys, "executable", str(bundle))
    monkeypatch.setattr(service.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(service, "base_dir", lambda: tmp_path / "stable")
    assert service.staged_executable() == str(staged.resolve())

    def no_copy():
        raise AssertionError("setup must not stage the bundled sensor for hooks")

    monkeypatch.setattr(service, "stable_executable", no_copy)
    monkeypatch.setattr(bridge, "app_version", lambda: "0.1.0")
    monkeypatch.setattr(bridge.service, "manage", lambda action, config: "running")
    # The running service is newer than this app's bundle.
    monkeypatch.setattr(bridge.hooks, "local_request", lambda *_: {"version": "0.2.0"})
    monkeypatch.setattr(
        bridge.integrations,
        "detect",
        lambda home=None, config=None: {"codex_available": True, "claude_available": True},
    )
    monkeypatch.setattr(bridge.integrations, "default_path", lambda agent, config=None: tmp_path / (agent + ".cfg"))
    result = bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    steps = {(step["step"], tuple(step.get("agents") or ()), step["ok"]) for step in result["steps"]}
    assert ("hooks.install", ("codex",), True) in steps
    assert ("hooks.install", ("claude",), True) in steps
    assert staged.read_bytes() == b"newer staged sensor"
    command = json.loads(hooks.settings_path("claude").read_text())["hooks"]["Stop"][0]["hooks"][0]["command"]
    assert hook_runtime.arguments(command)[0][:2] == [str(staged.resolve()), "hook"]


@pytest.mark.parametrize("damage", ["missing_event", "missing_executable", "not_executable", "directory", "broken_symlink", "legacy_command", "inline_launcher", "hashed_launcher", "missing_launcher", "corrupt_launcher", "default_config", "previous_config", "matcher", "async", "async_stop", "asyncRewake", "short_timeout", "long_timeout", "missing_timeout", "lifecycle_timeout", "handler_type", "condition"])
def test_setup_repairs_unavailable_hooks_for_both_agents(
    tmp_path, monkeypatch, isolated_hook_paths, sensor_executable, damage
):
    cfg = sensor_config(tmp_path)
    legacy_scripts = {}
    affected_agents = ("claude",) if damage in ("condition", "asyncRewake") else LEGACY_AGENTS
    if damage in ("async_stop", "hashed_launcher"):
        affected_agents = ("codex",)
    monkeypatch.setattr(service, "staged_executable", lambda: sensor_executable)
    monkeypatch.setattr(bridge.service, "manage", lambda action, config: "running")
    monkeypatch.setattr(bridge.hooks, "local_request", lambda *_: {"version": bridge.app_version()})
    monkeypatch.setattr(
        bridge.integrations,
        "detect",
        lambda home=None, config=None: {"codex_available": True, "claude_available": True},
    )
    monkeypatch.setattr(bridge.integrations, "default_path", lambda agent, config=None: tmp_path / (agent + ".cfg"))
    bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    assert bridge.handle({"action": "setup", "config_path": str(cfg.path)})["steps"] == []
    if damage in ("default_config", "previous_config"):
        previous = tmp_path / "previous sensor.yaml" if damage == "previous_config" else None
        for agent in LEGACY_AGENTS:
            hooks.install(hooks.settings_path(agent), sensor_executable, agent, config_path=previous)
        assert all(hooks.status()[agent]["installed"] for agent in LEGACY_AGENTS)
        assert hooks.status()["codex"]["trusted"]
    elif damage in ("legacy_command", "inline_launcher"):
        for agent in LEGACY_AGENTS:
            path = hooks.settings_path(agent)
            settings = json.loads(path.read_text())
            for entries in settings["hooks"].values():
                for entry in entries:
                    for handler in entry["hooks"]:
                        parts, _ = hook_runtime.arguments(handler["command"])
                        if damage == "inline_launcher":
                            runner = Path(shlex.split(handler["command"])[4])
                            config = hook_runtime.posix_config(runner.read_text())
                            handler["command"] = shlex.join([
                                "/bin/sh", "-c", hook_runtime.POSIX, hook_runtime.MARKER,
                                config["directory"], str(config["seconds"]), agent, config["event"], *parts,
                            ])
                            assert hook_runtime.arguments(handler["command"]) == (parts, False)
                        else:
                            handler["command"] = shlex.join(parts)
            path.write_text(json.dumps(settings))
        assert all(not state["installed"] for state in hooks.status().values())
    elif damage == "hashed_launcher":
        path = hooks.settings_path("codex")
        settings = json.loads(path.read_text())
        for entries in settings["hooks"].values():
            handler = entries[0]["hooks"][0]
            runner = Path(shlex.split(handler["command"])[4])
            script = runner.read_text()
            legacy = runner.parent.parent / hashlib.sha256(script.encode()).hexdigest() / "guardrail.sh"
            legacy.parent.mkdir(exist_ok=True)
            legacy.write_text(script)
            legacy_scripts[legacy] = script
            handler["command"] = hook_runtime.posix_launcher(legacy, hook_runtime.posix_config(script))
            runner.unlink()
        path.write_text(json.dumps(settings))
        assert hooks.installed(path, "codex")
        config_toml = hooks.codex_config_path()
        document = tomlkit.parse(config_toml.read_text())
        for key, (_, digest) in hooks.codex_trust_entries(path, settings).items():
            document["hooks"]["state"][key]["trusted_hash"] = digest
        config_toml.write_text(tomlkit.dumps(document))
        assert hooks.codex_trusted(path, hooks.codex_config_path())
    elif damage in ("missing_launcher", "corrupt_launcher"):
        for agent in LEGACY_AGENTS:
            path = hooks.settings_path(agent)
            settings = json.loads(path.read_text())
            command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            runner = Path(shlex.split(command)[4])
            if damage == "missing_launcher":
                runner.unlink()
            else:
                runner.write_text(runner.read_text() + "\nprintf 'unexpected output'\n")
        assert all(not state["installed"] for state in hooks.status().values())
    elif damage in ("matcher", "async", "async_stop", "asyncRewake", "short_timeout", "long_timeout", "missing_timeout", "lifecycle_timeout", "handler_type", "condition"):
        for agent in affected_agents:
            path = hooks.settings_path(agent)
            settings = json.loads(path.read_text())
            event = "SessionStart" if damage == "lifecycle_timeout" else "Stop" if damage == "async_stop" else "PreToolUse"
            entry = settings["hooks"][event][0]
            if damage == "matcher":
                entry["matcher"] = "Read"
            elif damage == "missing_timeout":
                del entry["hooks"][0]["timeout"]
            else:
                entry["hooks"][0].update({
                    "async": {"async": True},
                    "async_stop": {"async": True},
                    "asyncRewake": {"asyncRewake": True},
                    "short_timeout": {"timeout": 2},
                    "long_timeout": {"timeout": 10},
                    "lifecycle_timeout": {"timeout": 10},
                    "handler_type": {"type": "prompt"},
                    "condition": {"if": "Bash(git *)"},
                }[damage])
            path.write_text(json.dumps(settings))
        assert all(not hooks.status()[agent]["installed"] for agent in affected_agents)
    elif damage == "missing_event":
        for agent, event in (("claude", "UserPromptSubmit"), ("codex", "PostToolUse")):
            path = hooks.settings_path(agent)
            settings = json.loads(path.read_text())
            del settings["hooks"][event]
            path.write_text(json.dumps(settings))
    else:
        old = tmp_path / "old install" / "openaidr-sensor"
        old.parent.mkdir()
        old.write_bytes(Path(sensor_executable).read_bytes())
        old.chmod(0o755)
        for agent in LEGACY_AGENTS:
            hooks.install(hooks.settings_path(agent), str(old), agent)
        assert all(hooks.status()[agent]["installed"] for agent in LEGACY_AGENTS)
        if damage == "not_executable":
            old.chmod(0o644)
        else:
            old.unlink()
            if damage == "directory":
                old.mkdir()
            elif damage == "broken_symlink":
                old.symlink_to(tmp_path / "removed-sensor")
        assert all(not state["installed"] for state in hooks.status().values())
        assert not hooks.status()["codex"]["trusted"]
    before = bridge.handle({"action": "status", "config_path": str(cfg.path)})
    assert all(not before["hooks"][agent]["current"] for agent in affected_agents)
    result = bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    assert result["restart_required"] is True
    assert all(result["hooks"][agent]["current"] for agent in LEGACY_AGENTS)
    assert [(s["step"], s["agents"]) for s in result["steps"]] == [
        ("hooks.install", [agent]) for agent in ("codex", "claude") if agent in affected_agents
    ]
    assert result["hooks"]["claude"]["installed"] and result["hooks"]["codex"]["trusted"]
    assert all(legacy.read_text() == script for legacy, script in legacy_scripts.items())
    for agent in LEGACY_AGENTS:
        settings = json.loads(hooks.settings_path(agent).read_text())
        for event, entries in settings["hooks"].items():
            for entry in entries:
                for handler in entry["hooks"]:
                    assert handler["timeout"] == (5 if os.name == "nt" and (agent, event) != ("codex", "SessionEnd") else 3)
                    parts, quiet = hook_runtime.arguments(handler["command"])
                    assert quiet and parts[parts.index("--config") + 1] == str(cfg.path.resolve())
    assert bridge.handle({"action": "setup", "config_path": str(cfg.path)})["steps"] == []


def test_setup_keeps_ignored_matchers_and_reports_disabled_claude_hooks(
    tmp_path, monkeypatch, isolated_hook_paths, sensor_executable
):
    cfg = sensor_config(tmp_path)
    monkeypatch.setattr(service, "staged_executable", lambda: sensor_executable)
    monkeypatch.setattr(bridge.service, "manage", lambda action, config: "running")
    monkeypatch.setattr(bridge.hooks, "local_request", lambda *_: {"version": bridge.app_version()})
    monkeypatch.setattr(bridge.integrations, "detect", lambda home=None, config=None: {"codex_available": True, "claude_available": True})
    monkeypatch.setattr(bridge.integrations, "default_path", lambda agent, config=None: tmp_path / (agent + ".cfg"))
    bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    unchanged = {}
    for agent in LEGACY_AGENTS:
        path = hooks.settings_path(agent)
        settings = json.loads(path.read_text())
        for event in ("UserPromptSubmit", "Stop"):
            settings["hooks"][event][0]["matcher"] = "Read"
        if agent == "codex":
            # Unknown Claude-only fields do not change Codex execution or trust.
            settings["hooks"]["PreToolUse"][0]["hooks"][0].update(
                {"if": "Bash(git *)", "asyncRewake": True}
            )
        path.write_text(json.dumps(settings))
        unchanged[path] = path.read_bytes()
    # Codex normalizes ignored matchers out of its trust hash, so the original
    # trust still applies and neither agent needs a settings rewrite.
    assert hooks.codex_trusted()
    result = bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    assert all(result["hooks"][agent]["current"] for agent in LEGACY_AGENTS)
    assert result["steps"] == []
    assert all(path.read_bytes() == original for path, original in unchanged.items())
    path = hooks.settings_path("claude")
    settings = json.loads(path.read_text())
    settings["disableAllHooks"] = True
    path.write_text(json.dumps(settings))
    before = path.read_bytes()
    for action in ("status", "setup", "setup"):
        result = bridge.handle({"action": action, "config_path": str(cfg.path)})
        assert result["hooks"]["claude"] == {
            "installed": False, "partial": False, "disabled": True,
            "current": False, "opted_out": False,
            "available": True, "config_path": str(path), "config_exists": True,
            "control_events": ["UserPromptSubmit", "PreToolUse", "PostToolUse"],
        }
        assert not any(step["step"] == "hooks.install" for step in result.get("steps", []))
        assert path.read_bytes() == before
    settings["disableAllHooks"] = False
    path.write_text(json.dumps(settings))
    result = bridge.handle({"action": "status", "config_path": str(cfg.path)})
    assert result["hooks"]["claude"]["current"]
    assert not result["hooks"]["claude"].get("disabled")


@pytest.mark.parametrize("matcher", [None, "Read", {}, [], True, 42])
def test_setup_checks_ignored_matcher_types(
    tmp_path, monkeypatch, isolated_hook_paths, sensor_executable, matcher
):
    cfg = sensor_config(tmp_path)
    monkeypatch.setattr(service, "staged_executable", lambda: sensor_executable)
    monkeypatch.setattr(bridge.service, "manage", lambda action, config: "running")
    monkeypatch.setattr(bridge.hooks, "local_request", lambda *_: {"version": bridge.app_version()})
    monkeypatch.setattr(bridge.integrations, "detect", lambda home=None, config=None: {"codex_available": True, "claude_available": True})
    monkeypatch.setattr(bridge.integrations, "default_path", lambda agent, config=None: tmp_path / (agent + ".cfg"))
    bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    user_group = {"hooks": [{"type": "command", "command": "/usr/bin/true"}]}
    original = {}
    for agent in LEGACY_AGENTS:
        path = hooks.settings_path(agent)
        settings = json.loads(path.read_text())
        for event in ("UserPromptSubmit", "Stop"):
            settings["hooks"][event][0]["matcher"] = matcher
        settings["hooks"]["PreToolUse"].append(user_group)
        path.write_text(json.dumps(settings))
        original[path] = path.read_bytes()
    valid = matcher is None or isinstance(matcher, str)
    before = bridge.handle({"action": "status", "config_path": str(cfg.path)})
    for state in (before["hooks"][agent] for agent in LEGACY_AGENTS):
        assert state["installed"] is valid
        assert state["current"] is valid
    assert before["hooks"]["codex"]["trusted"] is valid
    result = bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    assert all(result["hooks"][agent]["current"] for agent in LEGACY_AGENTS)
    assert result["hooks"]["codex"]["trusted"]
    assert bool(result["steps"]) is not valid
    for path, content in original.items():
        settings = json.loads(path.read_text())
        assert user_group in settings["hooks"]["PreToolUse"]
        if valid:
            assert path.read_bytes() == content


@pytest.mark.parametrize("event", ["Stop", "PermissionRequest", "PreCompact", "PostCompact", "SubagentStart", "SubagentStop", "Interrupt"])
def test_setup_preserves_invalid_user_owned_codex_matcher(
    tmp_path, monkeypatch, isolated_hook_paths, sensor_executable, event
):
    cfg = sensor_config(tmp_path)
    monkeypatch.setattr(service, "staged_executable", lambda: sensor_executable)
    monkeypatch.setattr(bridge.service, "manage", lambda action, config: "running")
    monkeypatch.setattr(bridge.hooks, "local_request", lambda *_: {"version": bridge.app_version()})
    monkeypatch.setattr(bridge.integrations, "detect", lambda home=None, config=None: {"codex_available": True, "claude_available": True})
    monkeypatch.setattr(bridge.integrations, "default_path", lambda agent, config=None: tmp_path / (agent + ".cfg"))
    bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    path = hooks.settings_path("codex")
    settings = json.loads(path.read_text())
    group = settings["hooks"].setdefault(event, [{"hooks": []}])[0]
    group["matcher"] = {}
    group["hooks"].append({"type": "command", "command": "/usr/bin/true"})
    path.write_text(json.dumps(settings))
    original = {target: target.read_bytes() for target in (path, hooks.codex_config_path())}
    result = bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    assert not result["hooks"]["codex"]["current"]
    assert not result["hooks"]["codex"]["installed"]
    assert not result["hooks"]["codex"]["trusted"]
    failure = next(step for step in result["steps"] if step["step"] == "hooks.install")
    assert not failure["ok"] and "matcher must be a string or null" in failure["error"]
    assert all(target.read_bytes() == content for target, content in original.items())


def mixed_group(ours_command):
    """A group the user extended: our handler plus their own."""
    return {
        "matcher": "Bash",
        "hooks": [
            {"type": "command", "command": ours_command, "timeout": 10},
            {"type": "command", "command": "/usr/local/bin/audit-bash", "timeout": 5},
        ],
    }


@pytest.mark.parametrize("executable_name", ["openaidr", "openaidr-sensor-new"])
def test_claude_reinstall_and_uninstall_keep_a_users_handler_in_a_shared_group(tmp_path, sensor_executable, executable_name):
    path = tmp_path / "settings.json"
    hooks.install(path, sensor_executable, "claude")
    settings = json.loads(path.read_text())
    ours_command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    settings["hooks"]["PreToolUse"] = [mixed_group(ours_command)]
    path.write_text(json.dumps(settings))
    user_handler = mixed_group(ours_command)["hooks"][1]

    new = tmp_path / executable_name
    new.symlink_to(sensor_executable)
    hooks.install(path, str(new), "claude")
    groups_now = json.loads(path.read_text())["hooks"]["PreToolUse"]
    # The user's handler keeps its group and matcher; ours is a separate group.
    assert groups_now[0] == {"matcher": "Bash", "hooks": [user_handler]}
    assert [hook_runtime.arguments(h["command"])[0] for h in groups_now[1]["hooks"]] == [
        [str(new), "hook", "PreToolUse"]
    ]
    assert hooks.installed(path, "claude")

    hooks.uninstall(path, "claude")
    assert json.loads(path.read_text())["hooks"] == {
        "PreToolUse": [{"matcher": "Bash", "hooks": [user_handler]}]
    }


def test_codex_reinstall_and_uninstall_keep_a_users_handler_and_its_trust(tmp_path, sensor_executable):
    path, config_toml = codex_files(tmp_path)
    hooks.install_codex(path, sensor_executable, config_toml)
    settings = json.loads(path.read_text())
    ours_command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    group = mixed_group(ours_command)
    settings["hooks"]["PreToolUse"] = [group]
    path.write_text(json.dumps(settings))
    user_handler = group["hooks"][1]
    user_digest = hooks.codex_hook_hash("PreToolUse", group, user_handler)
    document = tomlkit.parse(config_toml.read_text())
    state = document["hooks"]["state"]
    # The user trusted their handler at position 0:1 in /hooks.
    state[f"{path}:pre_tool_use:0:1"] = {"trusted_hash": user_digest}
    config_toml.write_text(tomlkit.dumps(document))

    hooks.install_codex(path, "/new/openaidr", config_toml)
    groups_now = json.loads(path.read_text())["hooks"]["PreToolUse"]
    assert groups_now[0] == {"matcher": "Bash", "hooks": [user_handler]}
    state = tomlkit.parse(config_toml.read_text())["hooks"]["state"]
    # Their trust moved with the handler to 0:0; ours is recorded at 1:0.
    assert state[f"{path}:pre_tool_use:0:0"]["trusted_hash"] == user_digest
    assert f"{path}:pre_tool_use:0:1" not in state
    assert state[f"{path}:pre_tool_use:1:0"]["trusted_hash"] == hooks.codex_hook_hash(
        "PreToolUse", groups_now[1], groups_now[1]["hooks"][0]
    )
    assert hooks.codex_trusted(path, config_toml)

    hooks.uninstall_codex(path, config_toml)
    assert json.loads(path.read_text())["hooks"] == {
        "PreToolUse": [{"matcher": "Bash", "hooks": [user_handler]}]
    }
    assert dict(tomlkit.parse(config_toml.read_text())["hooks"]["state"]) == {
        f"{path}:pre_tool_use:0:0": {"trusted_hash": user_digest}
    }


def test_the_installer_never_trusts_a_users_handler(tmp_path, sensor_executable):
    path, config_toml = codex_files(tmp_path)
    hooks.install_codex(path, sensor_executable, config_toml)
    settings = json.loads(path.read_text())
    settings["hooks"]["Stop"][0]["hooks"].append(
        {"type": "command", "command": "/usr/local/bin/untrusted", "timeout": 5}
    )
    path.write_text(json.dumps(settings))
    entries = hooks.codex_trust_entries(path, settings)
    assert f"{path}:stop:0:1" not in entries
    hooks.install_codex(path, sensor_executable, config_toml)
    state = tomlkit.parse(config_toml.read_text())["hooks"]["state"]
    assert all("untrusted" not in json.dumps(dict(v)) for v in state.values())
    groups_now = json.loads(path.read_text())["hooks"]["Stop"]
    assert groups_now[0]["hooks"] == [{"type": "command", "command": "/usr/local/bin/untrusted", "timeout": 5}]
    assert f"{path}:stop:0:0" not in state


def test_reinstall_keeps_trust_codex_recorded_for_an_unchanged_definition(tmp_path, sensor_executable):
    path, config_toml = codex_files(tmp_path)
    hooks.install_codex(path, sensor_executable, config_toml)
    key = f"{path}:pre_tool_use:0:0"
    ours = tomlkit.parse(config_toml.read_text())["hooks"]["state"][key]["trusted_hash"]
    # After a Codex release changes its hash rules, the user trusts the hook
    # again in /hooks and Codex records its own value for our handler.
    foreign = "sha256:" + "ab" * 32
    document = tomlkit.parse(config_toml.read_text())
    document["hooks"]["state"][key]["trusted_hash"] = foreign
    config_toml.write_text(tomlkit.dumps(document))
    assert hooks.codex_trusted(path, config_toml)
    assert not hooks.status({"codex": path, "codex_config": config_toml})["codex"].get("disabled")

    hooks.install_codex(path, sensor_executable, config_toml)
    state = tomlkit.parse(config_toml.read_text())["hooks"]["state"]
    assert state[key]["trusted_hash"] == foreign
    assert hooks.codex_trusted(path, config_toml)
    # Editing a hashed field of our handler makes that recorded hash stale:
    # Codex would ask for review, so status must not report it trusted.
    edited = json.loads(path.read_text())
    edited["hooks"]["PreToolUse"][0]["hooks"][0]["statusMessage"] = "Checking"
    path.write_text(json.dumps(edited))
    assert not hooks.codex_trusted(path, config_toml)
    hooks.install_codex(path, sensor_executable, config_toml)
    assert tomlkit.parse(config_toml.read_text())["hooks"]["state"][key]["trusted_hash"] == ours
    assert hooks.codex_trusted(path, config_toml)
    # A changed definition needs new trust, so the installer records its digest.
    hooks.install_codex(path, sensor_executable, config_toml, config_path=tmp_path / "other sensor.yaml")
    state = tomlkit.parse(config_toml.read_text())["hooks"]["state"]
    assert state[key]["trusted_hash"] not in (foreign, ours)
    assert state[key]["trusted_hash"] == hooks.codex_hook_hash(
        "PreToolUse", json.loads(path.read_text())["hooks"]["PreToolUse"][0],
        json.loads(path.read_text())["hooks"]["PreToolUse"][0]["hooks"][0],
    )
    # Trust is still required for every handler of ours.
    del state[f"{path}:stop:0:0"]["trusted_hash"]
    config_toml.write_text(tomlkit.dumps(tomlkit.parse(config_toml.read_text()) | {"hooks": {"state": state}}))
    assert not hooks.codex_trusted(path, config_toml)


@pytest.mark.skipif(os.name == "nt", reason="POSIX stable launcher")
def test_codex_stable_commands_follow_runtime_updates_and_rollback(tmp_path, sensor_executable):
    path, config_toml = codex_files(tmp_path)
    old = Path(sensor_executable)
    updated = tmp_path / "updated user's build" / "openaidr-sensor"
    updated.parent.mkdir()
    for executable, decision in ((old, "allow"), (updated, "deny")):
        reply = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision}}
        executable.write_text("#!/bin/sh\nprintf '%s' " + shlex.quote(json.dumps(reply)) + "\n")
        executable.chmod(0o700)
    original = old.read_bytes()
    hooks.install_codex(path, str(old), config_toml)
    settings = path.read_bytes()
    commands = {event: entries[0]["hooks"][0]["command"]
                for event, entries in json.loads(settings)["hooks"].items()}
    for event, command in commands.items():
        assert Path(shlex.split(command)[4]).parent.name == f"codex-{event}"
        assert str(old) not in command
        assert hooks.our_handler({"command": command})
    # Keep the value recorded by Codex even if its hash normalization changes.
    key = f"{path}:pre_tool_use:0:0"
    document = tomlkit.parse(config_toml.read_text())
    document["hooks"]["state"][key]["trusted_hash"] = "sha256:" + "ab" * 32
    config_toml.write_text(tomlkit.dumps(document))
    trusted = config_toml.read_bytes()
    for executable, decision in ((updated, "deny"), (old, "allow")):
        hooks.install_codex(path, str(executable), config_toml)
        assert path.read_bytes() == settings and config_toml.read_bytes() == trusted
        assert hooks.installed(path, "codex") and hooks.current(None, "codex", path)
        assert hooks.codex_trusted(path, config_toml)
        assert hooks.executables("codex", path) == {str(executable)}
        assert old.read_bytes() == original
        # A session retains the original command, then runs the selected build.
        result = run_hook(shlex.split(commands["PreToolUse"]), input="{}", text=True,
                          timeout=3, env={**os.environ, "PATH": ""})
        assert not result.timed_out and (result.returncode, result.stderr) == (0, "")
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == decision


def test_setup_reports_hooks_disabled_in_codex_without_rewriting_them(
    tmp_path, monkeypatch, isolated_hook_paths, sensor_executable
):
    cfg = sensor_config(tmp_path)
    monkeypatch.setattr(service, "staged_executable", lambda: sensor_executable)
    monkeypatch.setattr(bridge.service, "manage", lambda action, config: "running")
    monkeypatch.setattr(bridge.hooks, "local_request", lambda *_: {"version": bridge.app_version()})
    monkeypatch.setattr(bridge.integrations, "detect", lambda home=None, config=None: {"codex_available": True, "claude_available": True})
    monkeypatch.setattr(bridge.integrations, "default_path", lambda agent, config=None: tmp_path / (agent + ".cfg"))
    bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    path, config_toml = hooks.settings_path("codex"), hooks.codex_config_path()
    # The user turns our PreToolUse hook off in Codex's /hooks browser.
    key = f"{path}:pre_tool_use:0:0"
    document = tomlkit.parse(config_toml.read_text())
    document["hooks"]["state"][key]["enabled"] = False
    config_toml.write_text(tomlkit.dumps(document))
    before = (path.read_bytes(), config_toml.read_bytes())
    for action in ("status", "setup", "setup"):
        result = bridge.handle({"action": action, "config_path": str(cfg.path)})
        state = dict(result["hooks"]["codex"])
        profiles = state.pop("profiles")
        assert len(profiles) == 1 and profiles[0]["disabled"] and not profiles[0]["trusted"]
        assert state == {
            "installed": True, "partial": False, "trusted": False, "disabled": True,
            "current": False, "opted_out": False,
            "available": True, "config_path": str(path), "config_exists": True,
            "control_events": ["UserPromptSubmit", "PreToolUse", "PostToolUse"],
        }
        assert result["hooks"]["claude"]["current"]
        assert cli.hook_summary({"hooks_installed": result["hooks"]}).endswith("Codex disabled in Codex /hooks")
        assert not any(step["step"] == "hooks.install" for step in result.get("steps", []))
        assert (path.read_bytes(), config_toml.read_bytes()) == before
    # An automatic repair that races the user's choice keeps it.
    hooks.install(path, sensor_executable, "codex", config_path=cfg.path)
    assert tomlkit.parse(config_toml.read_text())["hooks"]["state"][key]["enabled"] is False
    # An explicit reinstall is the user asking for the hooks back.
    hooks.install(path, sensor_executable, "codex", config_path=cfg.path, explicit=True)
    state = tomlkit.parse(config_toml.read_text())["hooks"]["state"]
    assert "enabled" not in state[key]
    result = bridge.handle({"action": "status", "config_path": str(cfg.path)})
    assert result["hooks"]["codex"]["current"] and result["hooks"]["codex"]["trusted"]
    assert not result["hooks"]["codex"].get("disabled")


def test_setup_recovers_an_interrupted_codex_reenable(
    tmp_path, monkeypatch, isolated_hook_paths, sensor_executable
):
    from openaidr.sensor import settings_files

    cfg = sensor_config(tmp_path)
    monkeypatch.setattr(service, "staged_executable", lambda: sensor_executable)
    monkeypatch.setattr(bridge.service, "manage", lambda action, config: "running")
    monkeypatch.setattr(bridge.hooks, "local_request", lambda *_: {"version": bridge.app_version()})
    monkeypatch.setattr(bridge.integrations, "detect", lambda home=None, config=None: {"codex_available": True, "claude_available": True})
    monkeypatch.setattr(bridge.integrations, "default_path", lambda agent, config=None: tmp_path / (agent + ".cfg"))
    bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    path, config_toml = hooks.settings_path("codex"), hooks.codex_config_path()
    key = f"{path}:pre_tool_use:0:0"
    document = tomlkit.parse(config_toml.read_text())
    document["hooks"]["state"][key]["enabled"] = False
    config_toml.write_text(tomlkit.dumps(document))

    canonical = tmp_path / "openaidr"
    canonical.symlink_to(sensor_executable)
    monkeypatch.setattr(service, "staged_executable", lambda: str(canonical))
    # Re-enabling with the new command stops after publishing its pending record.
    original = settings_files.atomic_write

    def crash(target, text, **kwargs):
        if Path(target) == config_toml.resolve():
            raise RuntimeError("stopped")
        return original(target, text, **kwargs)

    monkeypatch.setattr(settings_files, "atomic_write", crash)
    with pytest.raises(RuntimeError):
        hooks.install(path, str(canonical), "codex", config_path=cfg.path, explicit=True)
    monkeypatch.setattr(settings_files, "atomic_write", original)
    assert hooks.codex_pending_path(path).exists()
    # The pending update takes precedence over the disabled classification,
    # so automatic setup runs its recovery and completes the re-enable.
    result = bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    assert any(step["step"] == "hooks.install" and step["ok"] for step in result["steps"])
    assert not hooks.codex_pending_path(path).exists()
    assert "enabled" not in tomlkit.parse(config_toml.read_text())["hooks"]["state"][key]
    assert result["hooks"]["codex"]["current"] and not result["hooks"]["codex"].get("disabled")
    assert hooks.executables("codex", path) == {str(canonical)}


@pytest.mark.parametrize("hashable", [True, False])
@pytest.mark.parametrize("rename", [True, False])
def test_automatic_repair_keeps_disablement_when_our_handler_leaves_a_shared_group(tmp_path, sensor_executable, hashable, rename):
    path, config_toml = codex_files(tmp_path)
    hooks.install_codex(path, sensor_executable, config_toml)
    # The user adds a handler to our PreToolUse group and disables ours.
    document = json.loads(path.read_text())
    document["hooks"]["PreToolUse"][0]["hooks"].append({"type": "command", "command": "user-hook"})
    if not hashable:
        # A malformed field must not hide our handler's position or choice.
        document["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = "bad"
    path.write_text(json.dumps(document))
    config = tomlkit.parse(config_toml.read_text())
    config["hooks"]["state"][f"{path}:pre_tool_use:0:0"]["enabled"] = False
    # Codex recorded its own hash for our unchanged handler.
    foreign = "sha256:" + "ef" * 32
    config["hooks"]["state"][f"{path}:pre_tool_use:0:0"]["trusted_hash"] = foreign
    config_toml.write_text(tomlkit.dumps(config))
    # Repair splits the group: the user's handler stays, ours moves to a new group.
    if rename:
        canonical = tmp_path / "openaidr"
        canonical.symlink_to(sensor_executable)
        sensor_executable = str(canonical)
    hooks.install_codex(path, sensor_executable, config_toml)
    groups_now = json.loads(path.read_text())["hooks"]["PreToolUse"]
    assert groups_now[0]["hooks"] == [{"type": "command", "command": "user-hook"}]
    assert hooks.our_handler(groups_now[1]["hooks"][0])
    state = tomlkit.parse(config_toml.read_text())["hooks"]["state"]
    assert state[f"{path}:pre_tool_use:1:0"]["enabled"] is False
    # The user's handler now at our old position does not inherit our record.
    assert f"{path}:pre_tool_use:0:0" not in state
    assert hooks.codex_disabled(path, config_toml)
    if hashable and (not rename or os.name != "nt"):
        # The moved handler is unchanged, so the trust Codex recorded for it
        # at the old position moves with it. POSIX runtime renames now keep
        # the same stable command too.
        assert state[f"{path}:pre_tool_use:1:0"]["trusted_hash"] == foreign
    else:
        assert state[f"{path}:pre_tool_use:1:0"]["trusted_hash"] == hooks.codex_hook_hash(
            "PreToolUse", groups_now[1], groups_now[1]["hooks"][0]
        )
    # An explicit install turns it back on at its new position.
    hooks.install_codex(path, sensor_executable, config_toml, explicit=True)
    state = tomlkit.parse(config_toml.read_text())["hooks"]["state"]
    assert "enabled" not in state[f"{path}:pre_tool_use:1:0"]
    assert hooks.codex_trusted(path, config_toml)


def test_first_upgrade_keeps_codex_trust_for_an_unchanged_definition(tmp_path, sensor_executable):
    path, config_toml = codex_files(tmp_path)
    hooks.install_codex(path, sensor_executable, config_toml)
    # An install from before the digest record, after Codex re-recorded trust.
    hooks.codex_record_path(path).unlink()
    key = f"{path}:pre_tool_use:0:0"
    foreign = "sha256:" + "cd" * 32
    document = tomlkit.parse(config_toml.read_text())
    document["hooks"]["state"][key]["trusted_hash"] = foreign
    config_toml.write_text(tomlkit.dumps(document))
    assert not hooks.codex_trusted(path, config_toml)
    # One automatic repair starts the record and keeps Codex's hash.
    hooks.install_codex(path, sensor_executable, config_toml)
    assert tomlkit.parse(config_toml.read_text())["hooks"]["state"][key]["trusted_hash"] == foreign
    assert hooks.codex_record_path(path).exists()
    assert hooks.codex_trusted(path, config_toml)


def test_custom_agent_directories_are_recorded_for_the_service_and_desktop(
    tmp_path, monkeypatch, sensor_executable
):
    monkeypatch.delenv("WORKBUDDY_CONFIG_DIR", raising=False)
    from openaidr.sensor import removal

    monkeypatch.setattr(hooks, "settings_path", REAL_SETTINGS_PATH)
    monkeypatch.setattr(hooks, "codex_config_path", REAL_CODEX_CONFIG_PATH)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    claude_dir, codex_dir = tmp_path / "custom claude", tmp_path / "custom codex"
    claude_dir.mkdir()
    codex_dir.mkdir()
    cfg = sensor_config(tmp_path)
    monkeypatch.setenv("OPENAIDR_SENSOR_CONFIG", str(cfg.path))
    monkeypatch.setattr(service, "executable", lambda: sensor_executable)
    monkeypatch.setattr(service, "staged_executable", lambda: sensor_executable)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude_dir))
    monkeypatch.setenv("CODEX_HOME", str(codex_dir))

    # A shell with the variables installs where the agents' sessions load hooks.
    assert cli.main(["hook", "install", "--agent", "all"]) == 0
    claude_settings, codex_hooks = claude_dir / "settings.json", codex_dir / "hooks.json"
    assert hooks.installed(claude_settings, "claude") and hooks.installed(codex_hooks, "codex")
    assert hooks.codex_trusted(codex_hooks, codex_dir / "config.toml")
    assert not (home / ".claude").exists() and not (home / ".codex").exists()
    assert Config.load(cfg.path)["hooks"]["homes"] == {
        "claude": str(claude_dir.resolve()), "codex": str(codex_dir.resolve()),
    }

    # The background service and desktop app run without those variables.
    monkeypatch.delenv("CLAUDE_CONFIG_DIR")
    monkeypatch.delenv("CODEX_HOME")
    config = Config.load(cfg.path)
    # Telemetry setup targets the same files as the hooks.
    from openaidr.sensor import integrations
    assert integrations.default_path("claude", config) == claude_settings.resolve()
    assert integrations.default_path("codex", config) == (codex_dir / "config.toml").resolve()
    assert integrations.default_path("claude") == home / ".claude/settings.json"
    assert not hooks.status()["claude"]["installed"]
    state = hooks.status(config=config)
    assert state["claude"]["installed"] and state["codex"]["trusted"]
    monkeypatch.setattr(bridge.service, "manage", lambda action, config: "running")
    monkeypatch.setattr(bridge.hooks, "local_request", lambda *_: {"version": bridge.app_version()})
    monkeypatch.setattr(bridge.integrations, "detect",
                        lambda home=None, config=None: {"codex_available": True, "claude_available": True})
    monkeypatch.setattr(bridge.integrations, "default_path", lambda agent, config=None: tmp_path / (agent + ".cfg"))
    result = bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    assert not any(step["step"] == "hooks.install" for step in result["steps"])
    assert result["hooks"]["claude"]["current"] and result["hooks"]["codex"]["current"]
    assert not (home / ".claude").exists() and not (home / ".codex").exists()

    # Desktop removal finds the hooks in the recorded directories.
    for agent in LEGACY_AGENTS:
        removal.remove_hooks(config, agent)
    assert not hooks.coverage(claude_settings, "claude") and not hooks.coverage(codex_hooks, "codex")
    assert not hooks.codex_state(hooks.load_codex_config(codex_dir / "config.toml"))

    # Setting a variable back to the default directory clears its record.
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude"))
    hooks.remember_homes(config)
    assert Config.load(cfg.path)["hooks"]["homes"] == {"codex": str(codex_dir.resolve())}


def test_setup_detects_agents_by_recorded_directory_without_a_discoverable_binary(
    tmp_path, monkeypatch, sensor_executable
):
    from openaidr.sensor import integrations

    monkeypatch.setattr(hooks, "settings_path", REAL_SETTINGS_PATH)
    monkeypatch.setattr(hooks, "codex_config_path", REAL_CODEX_CONFIG_PATH)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    claude_dir, codex_dir = tmp_path / "custom claude", tmp_path / "custom codex"
    claude_dir.mkdir()
    codex_dir.mkdir()
    cfg = sensor_config(tmp_path)
    monkeypatch.setenv("OPENAIDR_SENSOR_CONFIG", str(cfg.path))
    monkeypatch.setattr(service, "executable", lambda: sensor_executable)
    monkeypatch.setattr(service, "staged_executable", lambda: sensor_executable)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude_dir))
    monkeypatch.setenv("CODEX_HOME", str(codex_dir))
    assert cli.main(["hook", "install", "--agent", "all"]) == 0
    # The hooks go missing, so setup must repair them.
    for agent, path in (("claude", claude_dir / "settings.json"), ("codex", codex_dir / "hooks.json")):
        hooks.uninstall(path, agent, codex_dir / "config.toml" if agent == "codex" else None)

    # The desktop and service see neither the variables nor a shell PATH, and
    # neither agent has a default directory or a binary in a known location.
    monkeypatch.delenv("CLAUDE_CONFIG_DIR")
    monkeypatch.delenv("CODEX_HOME")
    which = integrations.shutil.which
    monkeypatch.setattr(integrations.shutil, "which",
                        lambda name, *args, **kwargs: None if name in (*hooks.AGENTS, "workbuddy") else which(name, *args, **kwargs))
    real = integrations.detect
    monkeypatch.setattr(integrations, "detect",
                        lambda home=None, config=None: real(home, directories=(), config=config))
    assert integrations.detect() == {"codex_available": False, "claude_available": False, "workbuddy_available": True}
    config = Config.load(cfg.path)
    assert integrations.detect(config=config) == {"codex_available": True, "claude_available": True, "workbuddy_available": True}

    monkeypatch.setattr(bridge.service, "manage", lambda action, config: "running")
    monkeypatch.setattr(bridge.hooks, "local_request", lambda *_: {"version": bridge.app_version()})
    result = bridge.handle({"action": "setup", "config_path": str(cfg.path)})
    repaired = [step for step in result["steps"] if step["step"] == "hooks.install"]
    assert sorted(agent for step in repaired for agent in step["agents"]) == ["claude", "codex"]
    assert all(step["ok"] for step in repaired)
    assert hooks.installed(claude_dir / "settings.json", "claude")
    assert hooks.codex_trusted(codex_dir / "hooks.json", codex_dir / "config.toml")
    assert result["hooks"]["claude"]["current"] and result["hooks"]["codex"]["current"]
    assert not (home / ".claude").exists() and not (home / ".codex").exists()


def test_a_running_sensor_uses_directories_recorded_after_it_started(tmp_path, monkeypatch, sensor_executable):
    from openaidr.sensor.runtime import Sensor

    monkeypatch.setattr(hooks, "settings_path", REAL_SETTINGS_PATH)
    monkeypatch.setattr(hooks, "codex_config_path", REAL_CODEX_CONFIG_PATH)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setattr(service, "staged_executable", lambda: sensor_executable)
    cfg = sensor_config(tmp_path)
    sensor = Sensor(cfg)
    try:
        # A CLI command in another shell records a custom Claude Code directory.
        custom = tmp_path / "custom claude"
        custom.mkdir()
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(custom))
        hooks.remember_homes(Config.load(cfg.path))
        monkeypatch.delenv("CLAUDE_CONFIG_DIR")
        acks = sensor.apply({"commands": [{"id": "1", "type": "install_hook", "params": {"agent": "claude"}}]})
        assert [ack["status"] for _, ack in acks] == ["applied"]
        assert hooks.installed(custom / "settings.json", "claude")
        assert not (home / ".claude").exists()
        assert sensor.status()["hooks_installed"]["claude"]["installed"]
    finally:
        if sensor.telemetry:
            sensor.telemetry.close()
        sensor.spool.close()
        sensor.client.close()


@pytest.mark.parametrize("agent", ["claude", "codex", "hermes"])
def test_uninstall_removes_only_this_agents_launcher_state(tmp_path, sensor_executable, agent):
    cfg = sensor_config(tmp_path)
    path = hooks.settings_path(agent)
    hooks.install(path, sensor_executable, agent, config_path=cfg.path)
    health = hook_runtime.directory(path)
    assert health.absolute() in hook_runtime.registered_directories(cfg)
    other = "codex" if agent == "claude" else "claude"
    health.mkdir(exist_ok=True)
    ours = health / f"{agent}.PreToolUse.1759600000.0.abcdef123456"
    theirs = health / f"{other}.Stop.1759600000.0.abcdef654321"
    unrelated = health / "notes.txt"
    for file in (ours, theirs, unrelated):
        file.write_text("")
    # Both launcher formats can remain after upgrades or shared installations.
    for product in (agent, other):
        for windows in (False, True):
            hook_runtime.command(["openaidr-sensor", "hook", "Stop"], health, product, "Stop", windows=windows)
    runners = {agent: [], other: []}
    for runner in (health / "launchers").rglob("*"):
        if runner.is_file():
            parse = hook_runtime.windows_config if runner.suffix == ".ps1" else hook_runtime.posix_config
            runners[parse(runner.read_text())["agent"]].append(runner)
    assert all(len(paths) >= 2 for paths in runners.values())
    sibling = next(p for p in runners[agent] if p.name == "guardrail.sh").parent / "keep.txt"
    sibling.write_text("another application")
    unrelated_runner = health / "launchers" / "unrelated" / "guardrail.sh"
    unrelated_runner.parent.mkdir()
    unrelated_runner.write_text("#!/bin/sh\nprintf 'user hook'\n")

    hooks.uninstall(path, agent, config_path=cfg.path)
    assert not hooks.present(path, agent)
    assert not ours.exists() and not any(p.exists() for p in runners[agent])
    # Another agent's records and files we did not create are kept, so the
    # directory stays registered for collection.
    assert theirs.exists() and unrelated.exists() and all(p.exists() for p in runners[other])
    assert sibling.read_text() == "another application" and unrelated_runner.exists()
    assert health.absolute() in hook_runtime.registered_directories(cfg)

    theirs.unlink()
    unrelated.unlink()
    for runner in runners[other]:
        runner.unlink()
        if runner.name == "guardrail.sh":
            runner.parent.rmdir()
    sibling.unlink()
    sibling.parent.rmdir()
    unrelated_runner.unlink()
    unrelated_runner.parent.rmdir()
    hooks.uninstall(path, agent, config_path=cfg.path)
    assert not health.exists()
    assert health.absolute() not in hook_runtime.registered_directories(cfg)


def test_cli_installs_the_staged_executable_and_service_uninstall_warns(tmp_path, monkeypatch, capsys, sensor_executable):
    cfg = sensor_config(tmp_path)
    monkeypatch.setattr(service, "staged_executable", lambda: "/stable/bin/openaidr")
    monkeypatch.setattr(service, "hook_executable", lambda: sensor_executable)
    monkeypatch.setattr(service, "executable", lambda: "/transient/App.app/openaidr-sensor")
    assert cli.main(["hook", "install", "--agent", "claude", "--config", str(cfg.path)]) == 0
    handler = json.loads(hooks.settings_path("claude").read_text())["hooks"]["PreToolUse"][0]["hooks"][0]
    assert hook_runtime.arguments(handler["command"])[0][0] == sensor_executable

    calls = []
    monkeypatch.setattr(service, "manage", lambda action, config, **_: calls.append(action))
    capsys.readouterr()
    assert cli.main(["uninstall", "--config", str(cfg.path)]) == 0
    err = capsys.readouterr().err
    assert calls == ["uninstall"]
    assert "still connected to claude-code" in err and "codex-cli" not in err
    assert "hook uninstall --agent all" in err and "telemetry remove --agent all" in err

    # A missing hook executable still leaves hooks behind; removal clears them.
    Path(sensor_executable).unlink()
    assert cli.main(["hook", "uninstall", "--agent", "all", "--config", str(cfg.path)]) == 0
    capsys.readouterr()
    assert cli.main(["uninstall", "--config", str(cfg.path)]) == 0
    assert "warning" not in capsys.readouterr().err
