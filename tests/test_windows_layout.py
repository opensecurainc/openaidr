"""Filesystem migration with only Task Scheduler mocked."""

import json
import os
from pathlib import Path
import subprocess

import pytest
import tomlkit
import yaml

from openaidr.sensor import hooks, windows_layout as layout, windows_task


@pytest.fixture
def installation(tmp_path, monkeypatch):
    environ = {"LOCALAPPDATA": str(tmp_path)}
    old, new, recovery = layout.paths(environ)
    old.mkdir()
    recovery.mkdir(parents=True)
    (recovery / "desktop-update.json").write_text(json.dumps({
        "pending": {"install_started": True, "release": {"layout": 2}},
    }))
    config = {"sensor_id": "same-device", "sensor_token": "same-enrollment",
              "data_dir": str(old / "data"), "client_key": str(old / "data/key.pem"),
              "ca_cert": str(tmp_path / "custom-ca.pem")}
    (old / "sensor.yaml").write_text(yaml.safe_dump(config))
    (old / "data").mkdir()
    (old / "data/key.pem").write_bytes(b"private key")
    (old / "data/queue.db").write_bytes(b"queued bytes mentioning OpenAIDR Sensor")
    (old / "desktop-update").mkdir()
    (old / "desktop-update/desktop-installation-id").write_bytes(b"same-cohort")
    runtime = new.parent / "app/runtime"
    runtime.mkdir(parents=True)
    (runtime / "runtime.json").write_text(json.dumps({"name": "test-build", "version": "0.2.0"}))
    (runtime / "openaidr.exe").write_bytes(b"runtime")
    (runtime / "openaidr-service.exe").write_bytes(b"service")
    task = {"installed": True, "running": True, "state": "Running", "drift": [],
            "execute": str(old / "runtime/previous/openaidr-service.exe")}
    calls = []
    monkeypatch.setattr(windows_task, "state", lambda: task.copy())
    monkeypatch.setattr(windows_task, "configured_config", lambda: old / "sensor.yaml")
    monkeypatch.setattr(windows_task, "stop", lambda: calls.append("stop"))
    monkeypatch.setattr(windows_task, "start", lambda: calls.append("start"))
    monkeypatch.setattr(windows_task, "relocate", lambda *args: calls.append(("relocate", args)))
    monkeypatch.setattr(windows_task, "_powershell", lambda script: None)
    return environ, old, new, recovery, task, calls


def test_direct_migration_without_a_recovery_transaction_keeps_state(installation):
    environ, old, new, recovery, task, calls = installation
    (recovery / "desktop-update.json").unlink()
    with pytest.raises(ValueError, match="through the app"):
        layout.migrate(environ=environ)
    assert old.exists() and not new.exists() and not calls


def test_preflight_is_read_only_and_rejects_custom_tasks(installation):
    environ, old, new, recovery, task, calls = installation
    assert layout.preflight(environ=environ) == task
    assert not calls and not new.exists() and not (recovery / "sensor-migration.json").exists()
    task["drift"] = ["principal"]
    with pytest.raises(ValueError, match="custom"):
        layout.preflight(environ=environ)
    assert old.exists() and not calls


def test_preflight_keeps_machine_enrollment_selected(installation):
    environ, old, new, recovery, task, calls = installation
    machine = old.parent / "ProgramData/OpenAIDR/sensor.yaml"
    machine.parent.mkdir(parents=True)
    machine.write_bytes((old / "sensor.yaml").read_bytes())
    old.joinpath("sensor.yaml").unlink()
    environ["ProgramData"] = str(machine.parent.parent)
    task["installed"] = False
    with pytest.raises(ValueError, match="per-user"):
        layout.preflight(environ=environ)
    assert machine.is_file() and old.is_dir() and not new.exists() and not calls


@pytest.mark.parametrize("disabled", [False, True])
def test_migration_preserves_enrollment_queue_identity_and_user_disable(installation, disabled):
    environ, old, new, recovery, task, calls = installation
    if disabled:
        task.update(state="Disabled", running=False)
    layout.migrate(environ=environ)
    assert not old.exists()
    values = yaml.safe_load((new / "sensor.yaml").read_text())
    assert values["sensor_id"] == "same-device" and values["sensor_token"] == "same-enrollment"
    assert values["data_dir"] == str(new / "data")
    assert values["client_key"] == str(new / "data/key.pem")
    assert values["ca_cert"] == str(new.parent.parent / "custom-ca.pem")
    assert (new / "data/queue.db").read_bytes() == b"queued bytes mentioning OpenAIDR Sensor"
    assert (new / "desktop-update/desktop-installation-id").read_bytes() == b"same-cohort"
    assert (new / "runtime/test-build/.complete").is_file()
    assert calls[-1][1][-1]["state"] == task["state"]
    assert "start" not in calls
    before = list(calls)
    layout.migrate(environ=environ)
    assert calls == before
    assert layout.state_root(environ) == new


def test_migration_resumes_after_move_before_journal_write(installation, monkeypatch):
    environ, old, new, recovery, task, calls = installation
    write = layout.atomic_write
    def interrupted(path, data):
        if Path(path).name == "sensor-migration.json" and not old.exists():
            raise OSError("power loss")
        write(path, data)
    monkeypatch.setattr(layout, "atomic_write", interrupted)
    with pytest.raises(OSError, match="power loss"):
        layout.migrate(environ=environ)
    assert new.exists() and not old.exists()
    monkeypatch.setattr(layout, "atomic_write", write)
    layout.migrate(environ=environ)
    assert yaml.safe_load((new / "sensor.yaml").read_text())["data_dir"] == str(new / "data")
    assert json.loads((recovery / "sensor-migration.json").read_text())["complete"]


def test_migration_resumes_after_task_handoff_before_completion(installation, monkeypatch):
    environ, old, new, recovery, task, calls = installation
    relocate = windows_task.relocate
    def interrupted(*args):
        relocate(*args)
        monkeypatch.setattr(windows_task, "configured_config", lambda: new / "sensor.yaml")
        raise OSError("process interrupted")
    monkeypatch.setattr(windows_task, "relocate", interrupted)
    with pytest.raises(OSError, match="process interrupted"):
        layout.migrate(environ=environ)
    assert not json.loads((recovery / "sensor-migration.json").read_text())["complete"]
    monkeypatch.setattr(windows_task, "relocate", relocate)
    layout.migrate(environ=environ)
    assert json.loads((recovery / "sensor-migration.json").read_text())["complete"]
    assert calls.count("stop") == 2


@pytest.mark.parametrize("damage", ["dual", "link", "custom-task"])
def test_migration_rejects_ambiguous_or_unsafe_state_before_stopping(installation, damage):
    environ, old, new, recovery, task, calls = installation
    before = (old / "sensor.yaml").read_bytes()
    if damage == "dual":
        new.mkdir()
        (new / "keep").write_bytes(b"other data")
    elif damage == "link":
        if os.name == "nt":
            subprocess.run(["cmd", "/c", "mklink", "/J", str(old / "data/link"), str(recovery)], check=True, capture_output=True)
        else:
            (old / "data/link").symlink_to(recovery, target_is_directory=True)
    else:
        task["drift"] = ["principal"]
    with pytest.raises(ValueError):
        layout.migrate(environ=environ)
    assert not calls
    assert (old / "sensor.yaml").read_bytes() == before


@pytest.mark.parametrize("task_state", ["Running", "Ready", "Disabled"])
@pytest.mark.parametrize("failure", ["rename", "stop-processes"])
def test_failed_move_restores_task_enablement_and_resumes_only_running_service(
    installation, monkeypatch, task_state, failure,
):
    environ, old, new, recovery, task, calls = installation
    task.update(state=task_state, running=task_state == "Running")
    rename = Path.rename
    blocked = True
    def stop():
        calls.append("stop")
        task.update(state="Disabled", running=False)
    def powershell(script):
        if blocked and failure == "stop-processes" and "Get-CimInstance" in script:
            raise windows_task.TaskError("runtime is active")
        if "Enable-ScheduledTask" in script:
            calls.append("enable")
            task.update(state="Ready")
        if "Start-ScheduledTask" in script:
            calls.append("start")
            task.update(state="Running", running=True)
    def locked(path, target):
        if blocked and failure == "rename" and path == old:
            raise PermissionError("runtime is active")
        return rename(path, target)
    monkeypatch.setattr(windows_task, "stop", stop)
    monkeypatch.setattr(windows_task, "_powershell", powershell)
    monkeypatch.setattr(Path, "rename", locked)
    with pytest.raises((PermissionError, windows_task.TaskError), match="runtime is active"):
        layout.migrate(environ=environ)
    assert old.is_dir() and not new.exists()
    assert task["state"] == task_state
    assert ("enable" in calls) is (task_state != "Disabled")
    assert ("start" in calls) is (task_state == "Running")
    blocked = False
    layout.migrate(environ=environ)
    assert new.is_dir()
    assert calls[-1][0] == "relocate"
    assert calls[-1][1][-1]["state"] == task_state



@pytest.mark.parametrize("changed", ["execute", "drift"])
def test_failed_move_does_not_enable_a_changed_task(installation, monkeypatch, changed):
    environ, old, new, recovery, task, calls = installation
    def locked(path, target):
        task[changed] = "another-program.exe" if changed == "execute" else ["principal"]
        raise PermissionError("runtime is active")
    monkeypatch.setattr(Path, "rename", locked)
    scripts = []
    monkeypatch.setattr(windows_task, "_powershell", scripts.append)
    with pytest.raises(windows_task.TaskError, match="task changed"):
        layout.migrate(environ=environ)
    assert old.is_dir() and not new.exists()
    assert not any("Enable-ScheduledTask" in script for script in scripts)

def test_hook_registration_failure_keeps_the_service_handed_off(installation, monkeypatch):
    environ, old, new, recovery, task, calls = installation
    hooks.install_codex(hooks.settings_path("codex"), str(old / "runtime/previous/openaidr.exe"),
                        hooks.codex_config_path(), config_path=old / "sensor.yaml")
    def unavailable(*args, **kwargs):
        raise PermissionError("agent settings are locked")
    monkeypatch.setattr(hooks, "install", unavailable)
    with pytest.raises(PermissionError, match="agent settings are locked"):
        layout.migrate(environ=environ)
    assert new.is_dir() and not old.exists()
    assert calls[-1][0] == "relocate"
    assert calls[-1][1][1] == new / "sensor.yaml"
    assert calls[-1][1][-1]["running"]
    assert not json.loads((recovery / "sensor-migration.json").read_text())["complete"]


@pytest.mark.parametrize("agent", ["claude", "codex"])
@pytest.mark.parametrize("disabled", [False, True])
def test_migration_retargets_unavailable_owned_hooks_and_preserves_opt_out(installation, agent, disabled):
    environ, old, new, recovery, task, calls = installation
    path = hooks.settings_path(agent)
    other = {"type": "command", "command": "unrelated-tool hook", "timeout": 10}
    command = hooks.command_line(str(old / "runtime/previous/openaidr.exe"), "PreToolUse",
                                agent, old / "sensor.yaml", health_dir=path.parent)
    path.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [
        {"type": "command", "command": command, "timeout": hooks.hook_timeout("PreToolUse", agent)}, other,
    ]}]}}))
    if disabled:
        config = yaml.safe_load((old / "sensor.yaml").read_text())
        config["hooks"] = {"disabled_agents": [agent]}
        (old / "sensor.yaml").write_text(yaml.safe_dump(config))
    before = path.read_bytes()
    assert not hooks.status()[agent]["installed"]
    layout.migrate(environ=environ)
    if disabled:
        assert path.read_bytes() == before
    else:
        entries = hooks.load_settings(path)["hooks"]["PreToolUse"]
        handlers = [handler for entry in entries for handler in entry["hooks"]]
        assert other in handlers
        managed = [handler["command"] for handler in handlers if hooks.our_handler(handler)]
        assert managed
        for command in managed:
            arguments, _ = hooks.hook_runtime.arguments(command, windows=os.name == "nt")
            assert Path(arguments[0]) == new / "runtime/test-build/openaidr.exe"
            assert Path(arguments[arguments.index("--config") + 1]) == new / "sensor.yaml"


def test_migration_keeps_codex_event_disablement_while_retargeting_active_events(installation):
    environ, old, new, recovery, task, calls = installation
    path, config_toml = hooks.settings_path("codex"), hooks.codex_config_path()
    hooks.install_codex(path, str(old / "runtime/previous/openaidr.exe"), config_toml,
                        config_path=old / "sensor.yaml")
    document = tomlkit.parse(config_toml.read_text())
    disabled_key = f"{path}:pre_tool_use:0:0"
    document["hooks"]["state"][disabled_key]["enabled"] = False
    config_toml.write_text(tomlkit.dumps(document))
    layout.migrate(environ=environ)
    state = hooks.codex_state(hooks.load_codex_config(config_toml))
    assert state[disabled_key]["enabled"] is False
    assert all(value.get("enabled") is not False for key, value in state.items() if key != disabled_key)
    for entries in hooks.load_settings(path)["hooks"].values():
        for entry in entries:
            for handler in entry["hooks"]:
                arguments, _ = hooks.hook_runtime.arguments(handler["command"], windows=os.name == "nt")
                assert Path(arguments[0]) == new / "runtime/test-build/openaidr.exe"
                assert Path(arguments[arguments.index("--config") + 1]) == new / "sensor.yaml"


@pytest.mark.parametrize("disabled", [False, True])
def test_task_relocation_preserves_registered_trigger_and_enabled_state(tmp_path, monkeypatch, disabled):
    old, new = tmp_path / "old/sensor.yaml", tmp_path / "new/sensor.yaml"
    console = tmp_path / "runtime/openaidr.exe"
    console.parent.mkdir()
    console.with_name("openaidr-service.exe").write_bytes(b"service")
    previous = {"installed": True, "running": not disabled, "state": "Disabled" if disabled else "Running", "drift": []}
    monkeypatch.setattr(windows_task, "state", lambda: previous)
    monkeypatch.setattr(windows_task, "configured_config", lambda: old)
    scripts = []
    monkeypatch.setattr(windows_task, "_powershell", scripts.append)
    windows_task.relocate(old, new, console, previous)
    assert "Set-ScheduledTask" in scripts[0]
    assert "Register-ScheduledTask" not in scripts[0]
    assert ("Start-ScheduledTask" in scripts[0]) is not disabled
    assert ("Disable-ScheduledTask" in scripts[0]) is disabled
    monkeypatch.setattr(windows_task, "configured_config", lambda: tmp_path / "unrelated.yaml")
    with pytest.raises(windows_task.TaskError):
        windows_task.relocate(old, new, console, previous)
    assert len(scripts) == 1
