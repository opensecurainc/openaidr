import errno
import io
import json
import time
import plistlib
import subprocess
from pathlib import Path

import pytest

from openaidr.sensor import bridge, hooks, integrations, local_runtime, removal, service
from openaidr.sensor.config import Config
from openaidr.sensor.telemetry import settings

REAL_CODEX_PATHS = hooks.codex_paths


@pytest.fixture
def installation(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(hooks, "codex_config_path", lambda config=None: tmp_path / ".codex/config.toml")
    monkeypatch.setattr(hooks, "settings_path", lambda agent="claude", config=None: tmp_path / (".claude/settings.json" if agent == "claude" else f".{agent}/hooks.json"))
    monkeypatch.setattr(service.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(removal, "is_root", lambda: False)
    managed = tmp_path / "Library/Application Support/OpenAIDR"
    config = Config(managed / "sensor.yaml", data_dir=str(managed / "data"),
                    server_url="https://tenant.example", sensor_id="sensor-1", sensor_token="secret",
                    telemetry={"listen": "127.0.0.1:4318", "disabled_agents": ["claude"]})
    config.save()
    settings(config, persist_token=True)
    for agent in integrations.AGENTS:
        path = integrations.default_path(agent)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('model = "original"\n' if agent == "codex" else '{"theme":"original"}')
    integrations.install(config)
    for agent in hooks.AGENTS:
        hooks.install(hooks.settings_path(agent), "/fake/openaidr-sensor", agent, config_path=config.path)
    config = Config.load(config.path)
    config["telemetry"]["disabled_agents"] = ["claude"]
    config.save()
    path = tmp_path / "Library/LaunchAgents/openaidr-sensor.plist"
    path.parent.mkdir(parents=True)
    document = service.launchd_document(config, "/fake/openaidr-sensor")
    document["Label"] = service.LEGACY_NAME
    path.write_bytes(plistlib.dumps(document))
    state = {"loaded": True, "stop_error": False, "alive": False, "queries_fail": False,
             "process_error": False, "started": "Sun Oct  4 01:23:45 2026"}

    def run(args, **kwargs):
        if args[0] == "/bin/ps":
            assert args == ["/bin/ps", "-p", "45678", "-o", "lstart="]
            assert kwargs["env"]["LC_ALL"] == "C"
            if state["process_error"]:
                return subprocess.CompletedProcess(args, 2, stdout="", stderr="failed")
            alive = state["loaded"] or state["alive"]
            return subprocess.CompletedProcess(args, 0 if alive else 1, stdout=state["started"] if alive else "")
        if args[1] == "print":
            if args[-1].endswith("/openaidr"):
                return subprocess.CompletedProcess(args, 113, stdout="", stderr="")
            code = 1 if state["queries_fail"] else 0 if state["loaded"] else 113
            return subprocess.CompletedProcess(args, code, stdout=f"pid = 45678\narguments = {{\n/fake/openaidr-sensor\nrun\n--config\n{config.path.resolve()}\n}}\n", stderr="")
        assert args[1] == "bootout"
        if state["stop_error"]:
            raise subprocess.CalledProcessError(1, args)
        state["loaded"] = False
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(service, "_run", run)
    monkeypatch.setattr(bridge, "live_status", lambda *_: None)
    return config, path, state


@pytest.fixture
def local_docker(installation, monkeypatch):
    """Model Docker's external CLI with two independent Compose projects."""
    config, _, _ = installation
    root = local_runtime.directory(config)
    root.mkdir()
    (root / "state.json").write_text(json.dumps({
        "source": "previous-desktop-version", "docker_host": "unix:///saved-docker.sock",
        "env": {"OPENAIDR_ADMIN_PASSWORD": "retained-secret"},
    }))
    project = local_runtime.project(config)
    resources = {kind: {"owned-" + kind: project, "other-" + kind: "separate-runtime"}
                 for kind in ("container", "volume", "network")}
    resources["image"] = {project + "-" + name + ":latest": project for name in ("server", "dashboard")}
    resources["image"]["postgres:16"] = "shared"
    fixture = dict(resources=resources, running=set(resources["container"]), calls=[], fail=None, sticky=False)
    monkeypatch.setattr(local_runtime.docker_setup, "executable", lambda: "/test/docker")

    def run(args, **kwargs):
        assert args[:3] == ["/test/docker", "--host", "unix:///saved-docker.sock"]
        assert kwargs["stdin"] == subprocess.DEVNULL
        operation = args[3:]
        fixture["calls"].append(operation)
        if operation[:2] == ["network", "rm"]:
            if fixture["fail"] == "network timeout":
                raise subprocess.TimeoutExpired(args, kwargs["timeout"])
            if fixture["fail"] == "network unavailable":
                raise OSError("Docker stopped after deleting the database")
        failed = fixture["fail"] == operation[0] or fixture["fail"] == " ".join(operation[:2])
        if failed:
            return subprocess.CompletedProcess(args, 1, b"")
        result = []
        if operation[0] == "ps":
            selector = operation[operation.index("--filter") + 1]
            assert selector.startswith("label=com.docker.compose.project=")
            owner = selector.split("=", 2)[2]
            result = [name for name, label in resources["container"].items()
                      if label == owner and ("--all" in operation or name in fixture["running"])]
        elif operation[0] == "stop":
            assert all(resources["container"][name] == project for name in operation[3:])
            if not fixture["sticky"]:
                fixture["running"].difference_update(operation[3:])
        elif operation[0] == "rm":
            for name in operation[1:]:
                assert resources["container"][name] == project and name not in fixture["running"]
                del resources["container"][name]
        elif operation[0] in ("volume", "network", "image"):
            kind = operation[0]
            if operation[1] == "ls":
                selector = operation[operation.index("--filter") + 1]
                if kind == "image":
                    result = [name for name in resources[kind] if "reference=" + name == selector]
                else:
                    result = [name for name, owner in resources[kind].items()
                              if "label=com.docker.compose.project=" + owner == selector]
            else:
                assert operation[1] == "rm"
                for name in operation[2:]:
                    assert resources[kind][name] == project
                    del resources[kind][name]
        else:
            assert operation[0] == "info" or operation == ["compose", "version", "--short"]
        return subprocess.CompletedProcess(args, 0, "\n".join(result).encode())

    monkeypatch.setattr(local_runtime.subprocess, "run", run)
    return fixture


def test_uninstall_stops_only_owned_runtime_and_keeps_database(installation, local_docker):
    config, _, _ = installation
    before = {kind: dict(rows) for kind, rows in local_docker["resources"].items()}
    assert removal.remove(config)["desktop_removal"]["state"] == "complete"
    assert local_docker["running"] == {"other-container"}
    assert local_docker["resources"] == before
    assert "retained-secret" in (local_runtime.directory(config) / "state.json").read_text()
    assert removal.remove(config)["desktop_removal"]["state"] == "complete"


@pytest.mark.parametrize("failure", ["stop", "info", "sticky"])
def test_runtime_stop_failure_keeps_uninstall_pending_and_retryable(installation, local_docker, failure):
    config, _, sensor = installation
    local_docker["fail"] = failure
    local_docker["sticky"] = failure == "sticky"
    result = removal.remove(config)["desktop_removal"]
    assert result["state"] == "pending" and "local runtime" in result["errors"][0]
    assert not sensor["loaded"]
    assert all(not hooks.installed(agent=agent) for agent in hooks.AGENTS)
    assert (local_runtime.directory(config) / "state.json").exists()
    local_docker.update(fail=None, sticky=False)
    assert removal.remove(config)["desktop_removal"]["state"] == "complete"


@pytest.mark.parametrize("interrupted_setup", [False, True])
def test_separately_installed_runtime_is_not_touched(installation, monkeypatch, interrupted_setup):
    config, _, _ = installation
    config["server_url"] = local_runtime.ORIGIN
    config.save()
    if interrupted_setup:
        root = local_runtime.directory(config)
        root.mkdir()
        (root / "state.json.lock").touch()
    monkeypatch.setattr(removal, "default_path", lambda: config.path)
    monkeypatch.setattr(local_runtime.docker_setup, "executable", lambda: pytest.fail("Must not touch separately installed Docker runtimes"))
    assert removal.remove(config)["desktop_removal"]["state"] == "complete"
    removal.resume(config)
    assert removal.purge(config)["desktop_removal"]["data_deleted"]


@pytest.mark.parametrize("case", ["linked", "missing", "remote"])
def test_runtime_cleanup_rejects_unverified_ownership(installation, local_docker, case):
    config, _, _ = installation
    root = local_runtime.directory(config)
    if case == "linked":
        external = root.with_name("external-runtime")
        root.rename(external)
        root.symlink_to(external, target_is_directory=True)
    elif case == "missing":
        (root / "state.json").unlink()
        (root / ".env").write_text("private credentials")
    else:
        saved = json.loads((root / "state.json").read_text())
        saved["docker_host"] = "ssh://another-machine"
        (root / "state.json").write_text(json.dumps(saved))
    assert removal.remove(config)["desktop_removal"]["state"] == "pending"
    assert local_docker["running"] == {"owned-container", "other-container"}
    assert not local_docker["calls"]


@pytest.mark.parametrize("failure", ["rm", "volume rm", "network rm", "image rm", "network timeout", "network unavailable"])
def test_runtime_deletion_failure_keeps_credentials_and_retries(installation, local_docker, monkeypatch, failure):
    config, _, _ = installation
    monkeypatch.setattr(removal, "default_path", lambda: config.path)
    assert removal.remove(config)["desktop_removal"]["state"] == "complete"
    local_docker["fail"] = failure
    with pytest.raises(ValueError, match="Docker") as error:
        removal.purge(config)
    assert "Saved data is kept" not in str(error.value)
    if failure.startswith("network"):
        assert set(local_docker["resources"]["volume"].values()) == {"separate-runtime"}
    saved = json.loads(removal.marker(config).read_text())
    assert saved["data_deletion_started"] and not saved["data_deleted"]
    assert not saved.get("local_runtime_deleted")
    assert (local_runtime.directory(config) / "state.json").exists()
    assert config.path.exists()
    with pytest.raises(ValueError, match="Finish deleting"):
        removal.resume(config)
    local_docker["fail"] = None
    assert removal.purge(config)["desktop_removal"]["data_deleted"]
    assert not local_runtime.directory(config).exists()
    assert all(set(rows.values()) <= {"separate-runtime", "shared"} for rows in local_docker["resources"].values())


def test_removal_stops_collection_restores_settings_and_retains_data(installation):
    config, path, state = installation
    queue = Path(config["data_dir"]) / "queued-private-records"
    queue.parent.mkdir(exist_ok=True)
    queue.write_text("retained records")
    from openaidr.sensor import hook_runtime

    health = [hook_runtime.directory(hooks.settings_path(agent)) for agent in hooks.AGENTS]
    assert set(health) <= hook_runtime.registered_directories(config)
    for directory, agent in zip(health, hooks.AGENTS):
        directory.mkdir(exist_ok=True)
        (directory / f"{agent}.Stop.1759600000.0.abcdef123456").touch()
    result = removal.remove(config)["desktop_removal"]
    assert result["state"] == "complete"
    assert result["errors"] == []
    assert not state["loaded"] and not path.exists()
    # Launcher measurements and their registry entries leave with the hooks.
    assert not any(directory.exists() for directory in health)
    assert not set(health) & hook_runtime.registered_directories(config)
    assert queue.read_text() == "retained records"
    assert Config.load(config.path)["sensor_token"] == "secret"
    assert integrations.load(integrations.default_path("codex"), "codex")["model"] == "original"
    assert integrations.load(integrations.default_path("claude"), "claude")["theme"] == "original"
    assert all(not hooks.installed(agent=agent) for agent in hooks.AGENTS)
    with pytest.raises(ValueError, match="removal was requested"):
        bridge.setup(config)
    # Retrying is safe and keeps the pre-removal choices for deliberate setup.
    assert removal.remove(config)["desktop_removal"]["state"] == "complete"
    removal.resume(config)
    resumed = Config.load(config.path)
    assert resumed["telemetry"]["disabled_agents"] == ["claude"]
    assert resumed["hooks"]["disabled_agents"] == []
    assert removal.marker(config).exists()  # Native side clears this last.


def test_removal_preserves_edits_and_disconnects_remaining_exporters(installation):
    config, _, _ = installation
    path = integrations.default_path("claude")
    document = json.loads(path.read_text())
    document["env"]["OTEL_EXPORTER_OTLP_ENDPOINT"] += "/edited"
    document["theme"] = "changed"
    path.write_text(json.dumps(document))
    result = removal.remove(config)["desktop_removal"]
    assert result["state"] == "complete"
    assert result["errors"] == []
    remaining = json.loads(path.read_text())
    assert remaining["theme"] == "changed"
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" not in remaining.get("env", {})
    assert removal.remove(config)["desktop_removal"]["state"] == "complete"


@pytest.mark.parametrize("record", ["edited", "missing", "restores_local"])
def test_removal_disconnects_all_codex_signals_without_losing_other_settings(installation, record):
    config, _, _ = installation
    path = integrations.default_path("codex")
    document = integrations.load(path, "codex")
    document["model"] = "user-choice"
    document["otel"]["environment"] = "keep"
    document["otel"]["log_user_prompt"] = True
    document["otel"]["trace_exporter"] = {
        "otlp-http": {"endpoint": "http://127.0.0.1:4318/v1/traces"},
    }
    for field in ("exporter", "metrics_exporter"):
        document["otel"][field]["otlp-http"].setdefault("headers", {})["Authorization"] = "Bearer changed"
    path.write_text('# Keep this comment\n' + integrations.serialize(document, "codex"))
    if record == "missing":
        integrations.manifest_path(config).unlink()
    elif record == "restores_local":
        state = integrations.manifest(config)
        for field in ("exporter", "metrics_exporter"):
            value = integrations.plain(document["otel"][field])
            state[str(path)]["fields"]["otel." + field].update(
                present=True, previous=value, installed=value,
            )
        integrations.manifest_path(config).write_text(json.dumps(state))

    for _ in range(2):
        result = removal.remove(config)["desktop_removal"]
        assert result["state"] == "complete"
        assert result["errors"] == []
        remaining = integrations.load(path, "codex")
        assert remaining["model"] == "user-choice"
        assert remaining["otel"] == {"environment": "keep", "log_user_prompt": True}
        assert "# Keep this comment" in path.read_text()
        assert "codex" in Config.load(config.path)["telemetry"]["disabled_agents"]


@pytest.mark.parametrize("agent", ["codex", "claude"])
@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:43180", "https://collector.example"])
def test_removal_preserves_exporters_for_other_collectors(installation, agent, endpoint):
    config, _, _ = installation
    path = integrations.default_path(agent)
    document = integrations.load(path, agent)
    if agent == "codex":
        for field in ("exporter", "metrics_exporter", "trace_exporter"):
            document["otel"][field] = {"otlp-http": {"endpoint": endpoint + "/v1/logs"}}
    else:
        for field in ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"):
            document["env"][field] = endpoint
    path.write_text(integrations.serialize(document, agent))
    result = removal.remove(config)["desktop_removal"]
    assert result["state"] == "complete"
    assert result["errors"] == []
    remaining = integrations.load(path, agent)
    if agent == "codex":
        assert all(remaining["otel"][field] == document["otel"][field]
                   for field in ("exporter", "metrics_exporter", "trace_exporter"))
    else:
        assert all(remaining["env"][field] == endpoint
                   for field in ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"))


def test_removal_without_undo_disconnects_claude_without_disabling_other_collectors(installation):
    config, _, _ = installation
    path = integrations.default_path("claude")
    document = integrations.load(path, "claude")
    document["env"]["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] = "https://collector.example/v1/logs"
    document["env"]["OTEL_METRICS_EXPORTER"] = "otlp,console"
    path.write_text(integrations.serialize(document, "claude"))
    integrations.manifest_path(config).unlink()

    result = removal.remove(config)["desktop_removal"]
    assert result["state"] == "complete"
    assert result["errors"] == []
    env = integrations.load(path, "claude")["env"]
    assert env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] == "https://collector.example/v1/logs"
    assert env["OTEL_LOGS_EXPORTER"] == "otlp"
    assert env["OTEL_METRICS_EXPORTER"] == "console"
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" not in env
    assert "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT" not in env


def test_removal_reports_exporter_write_failure_and_recovers_on_retry(installation, monkeypatch):
    from openaidr.sensor import settings_files

    config, _, _ = installation
    path = integrations.default_path("codex")
    integrations.manifest_path(config).unlink()
    original = settings_files.atomic_write

    def fail(target, *args, **kwargs):
        if target == path:
            raise PermissionError("Cannot write agent settings")
        return original(target, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(settings_files, "atomic_write", fail)
        result = removal.remove(config)["desktop_removal"]
        assert result["state"] == "pending"
        assert any("Cannot restore codex-cli telemetry" in error for error in result["errors"])
        assert integrations.managed_present(config, "codex", path)
    assert removal.remove(config)["desktop_removal"]["state"] == "complete"
    assert not integrations.managed_present(config, "codex", path)


@pytest.mark.parametrize("failure", ["stop_error", "queries_fail", "process_error", "alive"])
def test_failed_shutdown_never_reports_removal_complete(installation, monkeypatch, failure):
    config, path, state = installation
    state[failure] = True
    if failure == "alive":
        times = iter([0, 31, 32, 63])
        monkeypatch.setattr(removal.time, "monotonic", lambda: next(times))
    result = removal.remove(config)["desktop_removal"]
    assert result["state"] == "pending" and result["errors"]
    assert path.exists()
    assert removal.marker(config).exists()
    if failure == "alive":
        # launchd can forget the job before its child exits. Retrying must
        # still wait for the original process, not claim the job is gone.
        assert removal.remove(config)["desktop_removal"]["state"] == "pending"


def test_retry_does_not_wait_for_a_different_process_using_the_saved_pid(installation, monkeypatch):
    config, path, state = installation
    state["alive"] = True
    times = iter([0, 31, 32])
    monkeypatch.setattr(removal.time, "monotonic", lambda: next(times))
    assert removal.remove(config)["desktop_removal"]["state"] == "pending"
    saved = json.loads(removal.marker(config).read_text())
    assert saved["sensor_process"] == {"pid": 45678, "started": state["started"]}
    state["started"] = "Sun Oct  4 01:24:45 2026"
    result = removal.remove(config)["desktop_removal"]
    assert result["state"] == "complete" and "sensor_process" not in result
    assert not path.exists() and state["alive"]  # The unrelated process is untouched.


@pytest.mark.parametrize("record", ['{', 'null', 'false', '[]', '{}',
    '{"state":"complete","errors":[],"preferences":{"hooks":[],"telemetry":"claude"}}',
    '{"state":"complete","errors":[],"preferences":{"hooks":[],"telemetry":["unknown"]}}'])
def test_damaged_record_refuses_resume_but_removal_recovers_current_choices(installation, record):
    config, path, state = installation
    removal.marker(config).write_text(record)
    original = config.path.read_bytes()
    with pytest.raises(ValueError, match="Retry removal before setting up again"):
        removal.resume(config)
    assert config.path.read_bytes() == original
    assert removal.marker(config).read_text() == record
    assert state["loaded"] and path.exists()
    assert removal.remove(config)["desktop_removal"]["state"] == "complete"
    removal.resume(config)
    assert Config.load(config.path)["telemetry"]["disabled_agents"] == ["claude"]
    assert Config.load(config.path)["hooks"]["disabled_agents"] == []


def test_unreadable_record_can_be_replaced_without_resuming_collection(installation, monkeypatch):
    config, _, _ = installation
    removal.remove(config)
    current = Config.load(config.path)
    before = config.path.read_bytes()
    read_text = Path.read_text

    def read(path, *args, **kwargs):
        if path == removal.marker(config):
            raise PermissionError("cannot read record")
        return read_text(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_text", read)
        with pytest.raises(ValueError, match="Retry removal before setting up again"):
            removal.resume(config)
        assert config.path.read_bytes() == before
        assert removal.remove(config)["desktop_removal"]["state"] == "complete"
    removal.resume(config)
    restored = Config.load(config.path)
    assert restored["hooks"] == current["hooks"]
    assert restored["telemetry"] == current["telemetry"]


def test_removal_rejects_other_config_and_manual_sensor(installation, monkeypatch):
    config, path, state = installation
    document = plistlib.loads(path.read_bytes())
    document["ProgramArguments"][-1] = "/another/sensor.yaml"
    path.write_bytes(plistlib.dumps(document))
    result = removal.remove(config)["desktop_removal"]
    assert result["state"] == "pending" and state["loaded"]
    assert "another configuration" in result["errors"][0]
    document = service.launchd_document(config, "/fake/openaidr-sensor")
    document["Label"] = service.LEGACY_NAME
    path.write_bytes(plistlib.dumps(document))
    monkeypatch.setattr(bridge, "live_status", lambda *_: {"version": "1.0.0"})
    result = removal.remove(config)["desktop_removal"]
    assert result["state"] == "pending"
    assert "manually started" in result["errors"][0]


@pytest.mark.parametrize("agent,unknown_event", [(agent, False) for agent in hooks.AGENTS]
                         + [(agent, True) for agent in ("claude", "copilot", "antigravity")])
def test_removal_keeps_hooks_owned_by_a_different_sensor(installation, agent, unknown_event):
    config, _, _ = installation
    path = hooks.settings_path(agent)
    hooks.install(path, "/fake/openaidr-sensor", agent, config_path=config.path.parent / "another.yaml")
    key = "openaidr" if agent == "antigravity" else "hooks"
    if unknown_event:
        document = hooks.load_settings(path)
        event = hooks.APP_EVENTS.get(agent, {}).get("PreToolUse", "PreToolUse")
        entries = document[key][event]
        # Antigravity lifecycle hooks are flat; tool hooks have matcher groups.
        if agent == "antigravity":
            entries = [handler for entry in entries for handler in entry["hooks"]]
        document[key] = {"OtherEvent": entries}
        path.write_text(json.dumps(document))
    assert hooks.present(path, agent)
    original = path.read_text() if agent == "opencode" else hooks.load_settings(path)[key]
    result = removal.remove(config)["desktop_removal"]
    assert result["state"] == "pending"
    assert any("another sensor configuration" in error for error in result["errors"])
    assert (path.read_text() if agent == "opencode" else hooks.load_settings(path)[key]) == original


def test_removal_attempts_all_codex_profiles_and_restores_choices_after_retry(installation, monkeypatch):
    config, _, _ = installation
    monkeypatch.setattr(hooks, "codex_paths", REAL_CODEX_PATHS)
    paths = [Path.home() / name / "hooks.json" for name in (".codex", ".codex-account2", ".codex-account3")]
    for path in paths[1:]:
        path.parent.mkdir()
        path.with_name("config.toml").write_text('model = "preserved"\n')
        hooks.install(path, "/fake/openaidr-sensor", "codex", config_path=config.path,
                      config_toml=path.with_name("config.toml"))
    hooks.install(paths[0], "/fake/openaidr-sensor", "codex", config_path=config.path.parent / "other.yaml")
    foreign = paths[0].read_bytes()
    recoverable = paths[1].read_bytes()
    paths[1].write_text("invalid hook settings")
    result = removal.remove(config)["desktop_removal"]
    assert result["state"] == "pending"
    errors = "\n".join(result["errors"])
    assert "another sensor configuration" in errors
    assert str(paths[0]) in errors and str(paths[1]) in errors
    assert paths[0].read_bytes() == foreign
    assert paths[1].read_text() == "invalid hook settings"
    assert not hooks.present(paths[2], "codex")
    assert hooks.opted_out(Config.load(config.path), "codex")

    # Preserve the ownership boundary until the operator fixes both conflicts.
    hooks.uninstall(paths[0], "codex", config_path=config.path.parent / "other.yaml")
    paths[1].write_bytes(recoverable)
    assert removal.remove(config)["desktop_removal"]["state"] == "complete"
    assert all(not hooks.present(path, "codex") for path in paths)
    removal.resume(config)
    restored = Config.load(config.path)
    assert not hooks.opted_out(restored, "codex")
    assert not (restored.get("hooks") or {}).get("disabled_codex_profiles")


@pytest.mark.parametrize("system, root", [("Linux", False), ("Darwin", True)])
def test_unsupported_removal_does_not_change_any_settings(installation, monkeypatch, system, root):
    config, path, state = installation
    monkeypatch.setattr(service.platform, "system", lambda: system)
    monkeypatch.setattr(removal, "is_root", lambda: root)
    original = config.path.read_bytes()
    for action in (removal.remove, removal.resume, removal.purge):
        with pytest.raises(ValueError, match="macOS installation only"):
            action(config)
    assert config.path.read_bytes() == original
    assert path.exists() and state["loaded"]
    assert not removal.marker(config).exists()


@pytest.fixture
def purge_installation(installation, monkeypatch):
    config, path, state = installation
    monkeypatch.setattr(removal, "default_path", lambda: config.path)
    removal.remove(config)
    return config, path, state


def test_purge_deletes_managed_records_and_preserves_barriers_and_external_files(purge_installation, local_docker):
    config, _, _ = purge_installation
    deleted_token = settings(config)["local_token"]
    root = config.path.parent
    external = root.parent / (root.name + "-external")
    external.mkdir()
    (external / "keep").write_text("unrelated")
    (root / "linked-records").symlink_to(external, target_is_directory=True)
    for name in ("desktop-updater.lock", "desktop-operation.lock"):
        (root / name).touch()
    locks = {name: (root / name).stat().st_ino for name in ("sensor.yaml.lock", "desktop-updater.lock", "desktop-operation.lock")}
    data = Path(config["data_dir"])
    data.mkdir(exist_ok=True)
    (data / "activity.sqlite3").write_text("private activity")
    (root / "credentials").mkdir(exist_ok=True)
    (root / "credentials/client.key").write_text("private enrollment")
    result = bridge.handle({"action": "desktop.purge", "config_path": str(config.path)})["desktop_removal"]
    assert result["data_deleted"] is True
    assert result["preferences"] == {"hooks": [], "telemetry": []}
    assert set(p.name for p in root.iterdir()) == {removal.MARKER, *locks}
    assert all(set(rows.values()) <= {"separate-runtime", "shared"} for rows in local_docker["resources"].values())
    assert all((root / name).stat().st_ino == inode for name, inode in locks.items())
    assert (external / "keep").read_text() == "unrelated"
    assert removal.purge(Config.load(config.path))["desktop_removal"]["data_deleted"]
    with pytest.raises(ValueError, match="removal was requested"):
        bridge.setup(Config.load(config.path))
    removal.resume(Config.load(config.path))
    assert not Config.load(config.path).get("sensor_token")
    assert not settings(Config.load(config.path)).get("local_token")
    assert settings(Config.load(config.path), persist_token=True)["local_token"] != deleted_token


@pytest.mark.parametrize("case", ["custom_config", "external_data", "linked_data", "pending", "running", "linked_root", "mounted"])
def test_purge_rejects_unsafe_paths_and_unfinished_removal(purge_installation, monkeypatch, case):
    config, _, state = purge_installation
    original = config.path.read_bytes()
    external = config.path.parent.parent / (config.path.parent.name + "-retained")
    external.mkdir()
    (external / "keep").write_text("retained")
    if case == "custom_config":
        monkeypatch.setattr(removal, "default_path", lambda: config.path.parent / "other.yaml")
    elif case in ("external_data", "linked_data"):
        data = external
        if case == "linked_data":
            data = config.path.parent / "linked-data"
            data.symlink_to(external, target_is_directory=True)
        config["data_dir"] = str(data)
        config.save()
        original = config.path.read_bytes()
    elif case == "pending":
        saved = json.loads(removal.marker(config).read_text())
        saved["state"] = "pending"
        removal.marker(config).write_text(json.dumps(saved))
    elif case == "running":
        monkeypatch.setattr(bridge, "live_status", lambda _: {"running": True})
    elif case == "mounted":
        monkeypatch.setattr(removal.os.path, "ismount", lambda path: Path(path) == config.path.parent)
    else:
        linked = external / "linked"
        linked.symlink_to(config.path.parent, target_is_directory=True)
        config = Config.load(linked / "sensor.yaml")
        monkeypatch.setattr(removal, "default_path", lambda: config.path)
    with pytest.raises(ValueError):
        removal.purge(config)
    assert config.path.read_bytes() == original or case == "running"
    assert (external / "keep").read_text() == "retained"
    assert not json.loads(removal.marker(config).read_text()).get("data_deleted")


@pytest.mark.parametrize("failure", ["permission", "concurrent_writer"])
def test_purge_failure_keeps_marker_and_can_retry_after_config_is_deleted(purge_installation, local_docker, monkeypatch, capsys, failure):
    config, _, _ = purge_installation
    root = config.path.parent
    data = root / "data"
    data.mkdir(exist_ok=True)
    secret_name = "private-tenant-token"
    (data / secret_name).write_text("private record")
    monkeypatch.setenv("OPENAIDR_REMOVAL_PROGRESS", "1")
    original = removal.os.unlink if failure == "permission" else removal.os.rmdir

    def fail(path, **kwargs):
        if str(path) == (secret_name if failure == "permission" else "data"):
            config.path.unlink(missing_ok=True)
            if failure == "permission":
                raise PermissionError(errno.EACCES, "private error message", path)
            # Real ENOTEMPTY from a separately created file, not an inferred race.
            (data / "concurrent-file").write_text("new record")
        return original(path, **kwargs)

    fail.__name__ = "unlink" if failure == "permission" else "rmdir"
    monkeypatch.setattr(removal.os, fail.__name__, fail)
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO(json.dumps({"action":"desktop.purge", "config_path":str(config.path)})))
    bridge.main()
    output = capsys.readouterr()
    response = json.loads(output.out)
    assert not response["ok"] and "incomplete" in response["error"]
    records = [json.loads(line.removeprefix("OPENAIDR_REMOVAL ")) for line in output.err.splitlines()]
    diagnostic = next(record for record in records if record["event"] == "failed")
    assert diagnostic["stage"] == "deletion"
    assert diagnostic["operation"] == fail.__name__
    assert diagnostic["errno"] == (errno.EACCES if failure == "permission" else errno.ENOTEMPTY)
    assert diagnostic["error_type"] == ("PermissionError" if failure == "permission" else "OSError")
    assert diagnostic["path"].startswith("data/entry-") if failure == "permission" else diagnostic["path"] == "data"
    assert diagnostic["ms"] >= 0
    assert all(value not in output.out + output.err for value in (secret_name, "private record", "private error message", str(root), "sensor_token"))
    saved = json.loads(removal.marker(config).read_text())
    assert saved["data_deletion_started"] and not saved["data_deleted"]
    assert saved["local_runtime_deleted"]
    local_docker["fail"] = "info"  # Docker is no longer needed after successful runtime deletion.
    assert not config.path.exists()
    with pytest.raises(ValueError):
        removal.resume(Config.load(config.path))
    monkeypatch.setattr(removal.os, fail.__name__, original)
    assert removal.purge(Config.load(config.path))["desktop_removal"]["data_deleted"]
    assert not data.exists()


@pytest.mark.parametrize("file_count", [100, 20000])
def test_purge_reports_measured_phases_on_disposable_tree(purge_installation, monkeypatch, capsys, file_count):
    config, _, _ = purge_installation
    root = config.path.parent
    for index in range(file_count):
        directory = root / "fixture" / str(index // 100)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / str(index)).write_bytes(b"x" * 64)
    inventory = [path for path in root.rglob("*") if path.is_file()]
    total_bytes = sum(path.stat().st_size for path in inventory)
    monkeypatch.setenv("OPENAIDR_REMOVAL_PROGRESS", "1")
    started = time.monotonic()
    assert removal.purge(config)["desktop_removal"]["data_deleted"]
    elapsed = round((time.monotonic() - started) * 1000)
    records = [json.loads(line.removeprefix("OPENAIDR_REMOVAL ")) for line in capsys.readouterr().err.splitlines()]
    completed = [record for record in records if record["event"] == "complete"]
    assert {record["stage"] for record in completed} == {"validation", "configuration_lock", "scan", "services", "integrations", "deletion", "record"}
    assert all(record["ms"] >= 0 for record in completed)
    assert next(record["files"] for record in completed if record["stage"] == "scan") == len(inventory)
    print(json.dumps({"fixture_files":file_count, "inventory_files":len(inventory), "bytes":total_bytes,
                      "elapsed_ms":elapsed, "phases":completed}))


def test_purge_does_not_follow_a_root_replaced_during_deletion(purge_installation, monkeypatch):
    config, _, _ = purge_installation
    root = config.path.parent
    moved = root.with_name("original-folder")
    outside = root.with_name("unrelated-folder")
    outside.mkdir()
    (outside / "sensor.yaml").write_text("unrelated credentials")
    original = removal.os.listdir

    def replace(descriptor):
        root.rename(moved)
        root.symlink_to(outside, target_is_directory=True)
        return original(descriptor)

    monkeypatch.setattr(removal.os, "listdir", replace)
    try:
        with pytest.raises(ValueError, match="incomplete"):
            removal.purge(config)
        assert (outside / "sensor.yaml").read_text() == "unrelated credentials"
        assert not json.loads((moved / removal.MARKER).read_text())["data_deleted"]
    finally:
        root.unlink()
        moved.rename(root)
