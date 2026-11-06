"""Fixed posture reads bind to saved enrollment and preserve unavailable states."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest

from openaidr.sensor import bridge, inventory_service, local_posture, usage
from openaidr.sensor.config import Config
from test_hooks_setup import sensor_config


def test_posture_transport_identity_and_errors(tmp_path, monkeypatch):
    cfg = sensor_config(tmp_path)
    state = {"code": 200, "body": {
        "schema_version": 1, "collected_at": None,
        "groups": {key: {"items": [], "total": 0, "truncated": False}
                   for key in ("apps", "components", "skills")},
        "coverage": {"status": "unavailable", "sources": []},
        "sensor_id": "untrusted", "server_url": "https://untrusted.invalid", "scope": "untrusted",
        "sensor_token": "must-not-be-projected",
    }}
    requests = []

    def server(request):
        requests.append(request)
        if state["code"] == "timeout":
            raise httpx.ReadTimeout("private transport details", request=request)
        return httpx.Response(state["code"], json=state["body"])

    original = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(server)))

    def call(**params):
        return bridge.handle({"action": "posture.summary", "config_path": str(cfg.path), "params": params})

    result = call()
    assert result["supported"] is True
    assert result["coverage"]["status"] == "unavailable"
    assert (result["sensor_id"], result["server_url"], result["scope"]) == (
        cfg["sensor_id"], cfg["server_url"].rstrip("/"), usage.identity(cfg))
    assert "sensor_token" not in result
    request = requests[-1]
    assert request.url.path == "/ingest/v1/posture/summary" and json.loads(request.content) == {}
    assert request.headers["Authorization"] == "Bearer " + cfg["sensor_token"]
    assert request.extensions["timeout"]["read"] == 5
    for params in ({"sensor_id": "other"}, {"tenant_id": "other"}, {"path": "/tmp"}, {"refresh": True}):
        with pytest.raises(ValueError, match="unknown action parameter"):
            call(**params)
    assert len(requests) == 1
    state["code"] = 404
    assert call() == {"supported": False, "reason": "server_unavailable", "sensor_id": cfg["sensor_id"],
                      "server_url": cfg["server_url"].rstrip("/"), "scope": usage.identity(cfg)}
    for code in (401, 403, 500, "timeout"):
        state["code"] = code
        with pytest.raises(ValueError, match="Could not read device posture") as error:
            call()
        assert "private" not in str(error.value)
    state["code"] = 200
    for malformed in ([], {}, {**result, "schema_version": True}, {**result, "groups": {}},
                      {**result, "coverage": None}, {**result, "collected_at": 123},
                      {key: value for key, value in result.items() if key != "collected_at"}):
        state["body"] = malformed
        with pytest.raises(ValueError, match="Invalid device posture response"):
            call()


def test_posture_reads_without_starting_scans_or_sending_inventory_in_personal_modes(tmp_path, monkeypatch):
    cfg = sensor_config(tmp_path)
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: pytest.fail("Personal mode must not contact inventory"))
    for mode in ("free", "api_key"):
        cfg["connection_mode"] = mode
        cfg.save()
        before = cfg.path.read_bytes()
        result = bridge.handle({"action": "posture.summary", "config_path": str(cfg.path)})
        assert result["supported"] and result["source"] == "local"
        assert result["coverage"]["status"] == "unavailable" and result["collected_at"] is None
        assert cfg.path.read_bytes() == before
    cfg["sensor_id"] = ""
    cfg.save()
    with pytest.raises(ValueError, match="not enrolled"):
        bridge.handle({"action": "posture.summary", "config_path": str(cfg.path)})
    assert not Config.load(cfg.path).enrolled()


@pytest.mark.parametrize("mode", ["free", "api_key"])
def test_posture_consent_is_explicit_account_bound_and_local(tmp_path, monkeypatch, mode):
    from openaidr.sensor import posture_assessments

    cfg = sensor_config(tmp_path)
    cfg["connection_mode"] = mode
    cfg.save()
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: pytest.fail("Consent must not contact a service"))
    scope = usage.identity(cfg)

    def call(**params):
        return bridge.handle({"action": "posture.configure", "config_path": str(cfg.path), "params": params})

    assert not posture_assessments.enabled(Config.load(cfg.path))
    for invalid in ({}, {"automatic": "true", "scope": scope}, {"automatic": True, "scope": ""},
                    {"automatic": True, "scope": scope, "server_url": "https://other"}):
        with pytest.raises(ValueError):
            call(**invalid)
    for automatic in (True, False):
        assert call(automatic=automatic, scope=scope) == {"enabled": automatic, "scope": scope}
        assert posture_assessments.enabled(Config.load(cfg.path)) is automatic
    call(automatic=True, scope=scope)
    changed = Config.load(cfg.path)
    changed["tenant_id"] = "another-tenant"
    changed.save()
    assert not posture_assessments.enabled(Config.load(cfg.path))
    before = cfg.path.read_bytes()
    for automatic in (True, False):
        with pytest.raises(ValueError, match="connection changed"):
            call(automatic=automatic, scope=scope)
        assert cfg.path.read_bytes() == before
    changed["connection_mode"] = "organization"
    changed.save()
    with pytest.raises(ValueError, match="connection changed"):
        call(automatic=True, scope=usage.identity(changed))


def test_unreadable_receipts_preserve_consent_and_allow_pause(tmp_path):
    from openaidr.sensor import posture_assessments

    cfg = sensor_config(tmp_path)
    cfg.update(connection_mode="free")
    cfg.save()
    scope = usage.identity(cfg)
    posture_assessments.configure(cfg, True, scope)
    ledger = Path(cfg["data_dir"]) / "posture-assessments.sqlite3"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_bytes(b"Unusable receipt storage")
    request = dict(action="posture.summary", config_path=str(cfg.path))
    assert bridge.handle(request)["assessments"] == dict(enabled=True, state="unavailable", billing=None, usage=None)
    assert bridge.handle(dict(action="posture.configure", config_path=str(cfg.path),
                              params=dict(automatic=False, scope=scope)))["enabled"] is False
    assert bridge.handle(request)["assessments"]["enabled"] is False


def local_snapshot(*, count=1, path="/installed", age=0):
    roots = []
    for source, kind in (("osquery-apps", "application"), ("osquery-npm-packages", "package"),
                         ("openaidr-skills", "skill"), ("openaidr-mcp-servers", "mcp_server")):
        roots.append(dict(source=source, root="/" + source, scope="user", status="ok", message="",
            environment="PRIVATE-ENVIRONMENT", components=[dict(key=str(index), identifier="com.openai.codex" if kind == "application" else "example",
                name="Codex" if kind == "application" else f"{kind}-{index:04d}", kind=kind,
                path=path + str(index), version="1", metadata={"description": "<literal evidence>", "token": "PRIVATE-TOKEN"})
                for index in range(count)], relationships=[]))
    return dict(schema_version=1, platform="darwin", roots=roots,
                collected_at=(datetime.now(timezone.utc) - timedelta(hours=age)).isoformat())


@pytest.mark.parametrize("mode", ["free", "api_key"])
def test_local_posture_projects_private_cache_and_preserves_unknowns(tmp_path, monkeypatch, mode):
    monkeypatch.setattr(inventory_service.sys, "platform", "darwin")
    cfg = sensor_config(tmp_path)
    cfg.update(connection_mode=mode, tenant_id="local-account")
    cfg.save()
    sample = local_snapshot()
    sample["roots"][0]["components"].extend([
        dict(key="helper", identifier="com.anthropic.claude-code-url-handler", name="Claude Code URL Handler", kind="application"),
        dict(key="unknown", identifier="example.unknown", name="Unknown AI App", kind="application"),
    ])
    sample["roots"].append(dict(source="openaidr-cli", root="/bin", scope="system", status="ok", components=[
        dict(key="real", identifier="npm:@anthropic-ai/claude-code", name="claude", kind="application"),
        dict(key="unidentified", identifier="executable:codex", name="Codex", kind="application"),
    ]))
    sample["roots"][2]["status"] = "partial"
    sample["roots"][2]["message"] = "PRIVATE-PATH-ERROR"
    scan = Mock(return_value=sample)
    monkeypatch.setattr(inventory_service.component_inventory, "collect_inventory", scan)
    client = Mock()
    client.post.side_effect = AssertionError("No inventory or bundle upload")
    service = inventory_service.InventoryService(cfg, client, components=True)
    service.sync_once()
    # Even retained server scan flags cannot trigger skill body uploads locally.
    service.state.update(skill_scanning=True, bundles_sent=False)
    service.sync_once()
    before = service.path.read_bytes()
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: pytest.fail("Posture must use the local cache"))
    monkeypatch.setattr(inventory_service.component_inventory, "collect_inventory", lambda *args, **kwargs: pytest.fail("Posture read must not scan"))
    result = bridge.handle({"action": "posture.summary", "config_path": str(cfg.path)})
    assert result["source"] == "local" and result["supported"]
    assert result["scope"] == usage.identity(cfg) and service.path.read_bytes() == before
    assert {name: group["total"] for name, group in result["groups"].items()} == dict(apps=2, components=2, skills=1)
    assert {item["product"] for item in result["groups"]["apps"]["items"]} == {"codex", "claude-code"}
    rows = [row for group in result["groups"].values() for row in group["items"]]
    assert {row["approval_status"] for row in rows} == {"unavailable"}
    assert all(row["assessment_status"] in ("disabled", "unsupported") for row in rows)
    assert all(not row["findings"] for row in rows)
    assert result["coverage"]["status"] == "partial" and result["groups"]["skills"]["items"][0]["attention"]
    assert "PRIVATE-" not in json.dumps(result) and "<literal evidence>" in json.dumps(result)
    assert scan.call_count == 1
    client.post.assert_not_called()
    cfg["inventory"] = {"components": {"enabled": False}}
    assert local_posture.read(cfg)["coverage"]["status"] == "unavailable"
    cfg["inventory"] = {"enabled": False}
    cfg.save()
    disabled = bridge.handle({"action": "posture.summary", "config_path": str(cfg.path)})
    assert disabled["coverage"]["status"] == "unavailable" and disabled["collected_at"] is None
    assert all(group["total"] == 0 for group in disabled["groups"].values())


def test_local_posture_bounds_output_and_exposes_stale_or_unusable_scans(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory_service.sys, "platform", "darwin")
    cfg = sensor_config(tmp_path)
    cfg.update(connection_mode="api_key", tenant_id="local-account")
    cfg.save()
    sample = local_snapshot(count=205, path="/" + "界" * 1500, age=7)
    scan = Mock(return_value=sample)
    monkeypatch.setattr(inventory_service.component_inventory, "collect_inventory", scan)
    service = inventory_service.InventoryService(cfg, None, components=True)
    service.sync_once()
    result = local_posture.read(cfg)
    assert result["coverage"]["status"] == "partial"
    assert {name: group["total"] for name, group in result["groups"].items()} == dict(apps=205, components=410, skills=205)
    assert all(group["truncated"] and 0 < len(group["items"]) <= 200 for group in result["groups"].values())
    assert len(json.dumps(result, ensure_ascii=True).encode()) <= local_posture.MAX_BYTES
    assert all("界" * 1500 in row["path"] for group in result["groups"].values() for row in group["items"])
    # A changed scan scope must never reuse observations from the old roots.
    cfg["inventory"] = {"components": {"include_default_roots": False}}
    assert all(group["total"] == 0 for group in local_posture.read(cfg)["groups"].values())
    cfg.pop("inventory")
    service.path.write_text('{"snapshot":2}')
    invalid = local_posture.read(cfg)
    assert invalid["coverage"]["status"] == "unavailable"
    assert all(group["total"] == 0 for group in invalid["groups"].values())
