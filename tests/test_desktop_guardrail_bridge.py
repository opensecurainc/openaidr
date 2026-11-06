"""Desktop guardrail controls use real isolated agent files and bounded transport."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from openaidr.sensor import bridge, hooks, integrations, removal, service, usage
from openaidr.sensor.config import Config
from openaidr.sensor.telemetry import ExportQueue
from test_hooks_setup import REAL_SETTINGS_PATH, REAL_CODEX_CONFIG_PATH, sensor_config

REAL_CODEX_PATHS = hooks.codex_paths


@pytest.mark.parametrize("shared_config", [False, True])
def test_codex_profiles_discovery_setup_controls_and_removal(tmp_path, monkeypatch, sensor_executable, shared_config):
    home = tmp_path / "home"
    profiles = [home / name for name in (".codex", ".codex-account2", ".codex-account3")]
    for index, profile in enumerate(profiles):
        profile.mkdir(parents=True)
        config_toml = profile / "config.toml"
        if shared_config and index:
            config_toml.symlink_to(profiles[0] / "config.toml")
        else:
            config_toml.write_text('model = "preserved"\n')
    (home / ".codexbar").mkdir()
    (home / ".codex-alias").symlink_to(profiles[1], target_is_directory=True)
    cfg = sensor_config(tmp_path)
    cfg["telemetry"]["enabled"] = False
    cfg.save()
    for variable, _, _ in hooks.HOMES.values():
        if variable:
            monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(hooks.Path, "home", lambda: home)
    monkeypatch.setattr(hooks, "settings_path", REAL_SETTINGS_PATH)
    monkeypatch.setattr(hooks, "codex_config_path", REAL_CODEX_CONFIG_PATH)
    monkeypatch.setattr(hooks, "codex_paths", REAL_CODEX_PATHS)
    monkeypatch.setattr(integrations, "detect", lambda **kwargs: {"codex_available": True, "claude_available": False})
    monkeypatch.setattr(service, "hook_executable", lambda: sensor_executable)
    monkeypatch.setattr(service, "staged_executable", lambda: sensor_executable)
    monkeypatch.setattr(service, "manage", lambda *args, **kwargs: "running")
    monkeypatch.setattr(hooks, "local_request", lambda *args, **kwargs: {})

    def call(action, **params):
        return bridge.handle({"action": action, "config_path": str(cfg.path), "params": params})

    paths = [profile / "hooks.json" for profile in profiles]
    assert list(hooks.codex_paths(cfg)) == paths
    assert len(integrations.configured_paths(cfg, "codex")) == (1 if shared_config else 3)
    assert not any(row["installed"] for row in bridge.status(cfg)["hooks"]["codex"]["profiles"])
    installed = bridge.setup(cfg)["hooks"]["codex"]["profiles"]
    assert [row["config_path"] for row in installed] == list(map(str, paths))
    assert all(row["installed"] and row["trusted"] and row["current"] for row in installed)
    assert not (home / ".codexbar" / "hooks.json").exists()
    assert (profiles[1] / "config.toml").is_symlink() is shared_config
    assert all('model = "preserved"' in (profile / "config.toml").read_text() for profile in profiles)

    # Only the selected profile changes, even when trust lives in one shared file.
    target = str(paths[1])
    assert call("guardrails.configuration", agent="codex", profile=target) == {"path": target}
    call("guardrails.configure", agent="codex", profile=target, enabled=False)
    repaired = bridge.setup(Config.load(cfg.path))["hooks"]["codex"]["profiles"]
    assert [row["installed"] for row in repaired] == [True, False, True]
    assert [row["opted_out"] for row in repaired] == [False, True, False]
    call("guardrails.configure", agent="codex", profile=target, enabled=True)
    assert all(row["trusted"] for row in hooks.codex_profiles(Config.load(cfg.path)))
    for profile in (str(home / ".codexbar" / "hooks.json"), str(tmp_path / "other"), "../hooks.json", []):
        with pytest.raises(ValueError, match="detected Codex profile"):
            call("guardrails.configure", agent="codex", profile=profile, enabled=True)
    with pytest.raises(ValueError, match="detected Codex profile"):
        call("guardrails.configuration", agent="claude", profile=target)

    call("guardrails.configure", agent="codex", profile=str(paths[0]), enabled=False)
    call("guardrails.configure", agent="codex", enabled=True)
    assert not any(row["opted_out"] for row in hooks.codex_profiles(Config.load(cfg.path)))

    # A legacy agent-wide opt-out remains effective for the other profiles.
    hooks.set_opt_out(cfg, "codex", True)
    call("guardrails.configure", agent="codex", profile=target, enabled=True)
    assert [row["opted_out"] for row in hooks.codex_profiles(Config.load(cfg.path))] == [True, False, True]
    removal.remove_hooks(cfg, "codex")
    assert all(not hooks.present(path, "codex") for path in paths)
    assert all('model = "preserved"' in (profile / "config.toml").read_text() for profile in profiles)


@pytest.mark.parametrize("agent", hooks.AGENTS)
def test_desktop_guardrail_setup_preserves_profiles_and_opt_out(tmp_path, monkeypatch, sensor_executable, agent):
    cfg = sensor_config(tmp_path)
    profile = tmp_path / "custom profile" / agent
    cfg["hooks"] = {"homes": {agent: str(profile)}}
    cfg.save()
    for variable, _, _ in hooks.HOMES.values():
        if variable:
            monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(hooks, "settings_path", REAL_SETTINGS_PATH)
    monkeypatch.setattr(hooks, "codex_config_path", REAL_CODEX_CONFIG_PATH)
    # Every agent home is isolated, including those inspected by bridge.status.
    monkeypatch.setattr(hooks.Path, "home", lambda: tmp_path / "home")
    monkeypatch.setattr(hooks, "detect_apps", lambda config=None: {key: key == agent for key in hooks.APP_EVENTS})
    monkeypatch.setattr(integrations, "detect", lambda **kwargs: {"claude_available": agent == "claude", "codex_available": agent == "codex"})
    monkeypatch.setattr(service, "hook_executable", lambda: sensor_executable)
    monkeypatch.setattr(service, "manage", lambda *args, **kwargs: "stopped")
    monkeypatch.setattr(hooks, "local_request", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("offline")))
    path = hooks.settings_path(agent, cfg)

    def call(action, **params):
        return bridge.handle({"action": action, "config_path": str(cfg.path), "params": {"agent": agent, **params}})

    with pytest.raises(ValueError, match="does not exist"):
        call("guardrails.configuration")
    installed = call("guardrails.configure", enabled=True)["hooks"][agent]
    assert installed["installed"] and installed["available"] and not installed["opted_out"]
    assert installed["config_exists"] and installed["config_path"] == str(path)
    assert call("guardrails.configuration") == {"path": str(path.resolve())}
    assert "PreToolUse" in installed["control_events"]
    if agent == "hermes":
        assert installed["approval_pending"] and not hooks.hermes_approved(path)
    removed = call("guardrails.configure", enabled=False)["hooks"][agent]
    assert not removed["installed"] and removed["opted_out"]
    assert hooks.opted_out(Config.load(cfg.path), agent)
    repaired = call("guardrails.configure", enabled=True)["hooks"][agent]
    assert repaired["installed"] and not repaired["opted_out"]
    for params in ({"enabled": "yes"}, {"enabled": True, "path": str(tmp_path / "other")},
                   {"enabled": True, "agent": "all"}, {"enabled": True, "command": "run"}):
        with pytest.raises(ValueError):
            call("guardrails.configure", **params)


def test_guardrail_summary_transport_errors_and_identity(tmp_path, monkeypatch):
    cfg = sensor_config(tmp_path)
    state = {"code": 200, "body": {"days": 1, "summary": {"completed": 4}}}
    requests = []

    def server(request):
        assert request.headers["authorization"] == "Bearer remote-token"
        requests.append((request.url.path, json.loads(request.content)))
        return httpx.Response(state["code"], json=state["body"])

    original = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(server)))

    def call(**params):
        return bridge.handle({"action": "guardrails.summary", "config_path": str(cfg.path), "params": params})

    result = call(days=1)
    assert result["supported"] and result["summary"]["completed"] == 4
    assert result["sensor_id"] == cfg["sensor_id"] and result["server_url"] == cfg["server_url"]
    assert "remote-token" not in json.dumps(result)
    call(days=30)
    assert requests == [("/ingest/v1/guardrails/summary", {"days": 1}), ("/ingest/v1/guardrails/summary", {"days": 30})]
    for params in ({"days": True}, {"days": 7}, {"sensor_id": "other"}, {"server_url": "https://other.test"}):
        with pytest.raises(ValueError):
            call(**params)
    assert len(requests) == 2
    state["code"] = 404
    assert call()["supported"] is False
    for code in (401, 403, 500):
        state["code"] = code
        with pytest.raises(ValueError, match="Could not read guardrail activity"):
            call()
    state.update(code=200, body=[])
    with pytest.raises(ValueError, match="Invalid guardrail activity response"):
        call()
    cfg.pop("sensor_token"); cfg.save()
    with pytest.raises(ValueError):
        call()


@pytest.mark.parametrize("connection_field", ["server_url", "tenant_id", "sensor_id"])
def test_denial_reviews_bind_enrollment_and_validate_before_transport(tmp_path, monkeypatch, connection_field):
    from uuid import uuid4
    from openaidr.sensor.usage import identity

    cfg = sensor_config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope=identity(cfg))
    with queue.db:
        queue.db.execute("INSERT INTO usage_calls VALUES (?,?,?,?,?,?,?)",
                         (queue.usage_scope, "local", (datetime.now(timezone.utc) - timedelta(seconds=1)).timestamp(),
                          "model", "unknown", 1200, .1))
    queue.close()
    totals = usage.overview(cfg, 30)["summary"]
    calls, state = [], {"status": 200}
    def server(request):
        calls.append((request.url.path, json.loads(request.content)))
        assert request.headers["authorization"] == "Bearer remote-token"
        return httpx.Response(state["status"], json={"items": [], "next_cursor": ""})
    original = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(server)))
    def call(action, **params):
        return bridge.handle({"action": "guardrails." + action, "config_path": str(cfg.path), "params": params})
    window = dict(days=1, until="2026-10-29T00:00:00Z", cursor="")
    result = call("denials", **window)
    scope = identity(cfg)
    assert result["scope"] == scope
    review = dict(id=str(uuid4()), scope=scope, label="false_positive", note="Expected action")
    call("check", id=review["id"], scope=scope)
    call("review", **review)
    assert calls[-1] == ("/ingest/v1/guardrails/review", {k:v for k,v in review.items() if k != "scope"})
    versioned = {**review, "review_version": 1, "label": "insufficient_context", "evidence_sha256": "b" * 64,
                 "expected_revision": 2, "request_id": str(uuid4())}
    call("review", **versioned)
    assert calls[-1] == ("/ingest/v1/guardrails/review", {k:v for k,v in versioned.items() if k != "scope"})
    for changes in ({"review_version": True}, {"review_version": 2}, {"expected_revision": -1},
                    {"expected_revision": True}, {"evidence_sha256": "invalid"}, {"request_id": "invalid"}):
        with pytest.raises(ValueError):
            call("review", **{**versioned, **changes})
    with pytest.raises(ValueError):
        call("review", **{**review, "label": "insufficient_context"})
    for changes in ({"scope": "old"}, {"id": "../check"}, {"label": "allow"}, {"note": "x" * 2001}, {"sensor_id": "other"}):
        with pytest.raises(ValueError):
            call("review", **{**review, **changes})
    assert len(calls) == 4
    state["status"] = 404
    assert call("denials", **window)["supported"] is False
    with pytest.raises(ValueError, match="Could not save"):
        call("review", **review)
    count = len(calls)
    cfg[connection_field] = "https://new.example" if connection_field == "server_url" else str(uuid4())
    cfg.save()
    with pytest.raises(ValueError, match="connection changed"):
        call("check", id=review["id"], scope=scope)
    with pytest.raises(ValueError, match="connection changed"):
        call("review", **review)
    with pytest.raises(ValueError, match="connection changed"):
        call("review", **versioned)
    assert len(calls) == count
    assert identity(cfg) != scope
    assert usage.overview(cfg, 30)["summary"] == totals
