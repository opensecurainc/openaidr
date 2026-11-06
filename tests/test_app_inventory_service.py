import json
import os
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from openaidr.sensor import inventory_service
from openaidr.sensor.config import Config


@pytest.fixture(autouse=True)
def native_platform(monkeypatch):
    monkeypatch.setattr(inventory_service.sys, "platform", "linux")


def report(age=0):
    return {
        "schema_version": 1,
        "platform": "linux",
        "collected_at": (
            datetime.now(timezone.utc) - timedelta(seconds=age)
        ).isoformat(),
        "sources": [{"source": "linux-dpkg", "status": "ok", "message": ""}],
        "applications": [{"name": "test-app", "path": "/private/location"}],
    }


def config(tmp_path, **values):
    return Config(
        tmp_path / "config.yaml",
        data_dir=str(tmp_path),
        sensor_id="sensor-a",
        server_url="https://tenant.example",
        **values,
    )


def test_retry_cached_snapshot_across_restart_without_rescanning(tmp_path, monkeypatch):
    scan = Mock(return_value=report())
    monkeypatch.setattr(inventory_service, "collect_inventory", scan)
    client = Mock()
    client.post.side_effect = OSError("offline")
    service = inventory_service.InventoryService(config(tmp_path), client)
    with pytest.raises(OSError, match="offline"):
        service.sync_once()
    assert service.status()["pending"]
    cached = json.loads(service.path.read_text())
    assert cached["snapshot"] == scan.return_value
    if os.name != "nt":
        assert service.path.stat().st_mode & 0o777 == 0o600

    client.post.side_effect = None
    restarted = inventory_service.InventoryService(config(tmp_path), client)
    restarted.sync_once()
    restarted.sync_once()
    assert scan.call_count == 1
    assert client.post.call_count == 2
    assert client.post.call_args.args == ("inventory/applications", cached["snapshot"])
    assert not restarted.status()["pending"]
    assert restarted.status()["last_sent_at"]
    assert "/private/location" not in json.dumps(restarted.status())


def test_expired_pending_snapshot_is_delivered_before_a_failed_rescan(
    tmp_path, monkeypatch
):
    original = report(age=400)
    failed = report()
    failed["applications"] = []
    failed["sources"][0].update(status="error", message="package database unavailable")
    scan = Mock(side_effect=[original, failed])
    monkeypatch.setattr(inventory_service, "collect_inventory", scan)
    client = Mock()
    client.post.side_effect = OSError("offline")
    cfg = config(tmp_path, inventory={"interval_s": 300})
    service = inventory_service.InventoryService(cfg, client)
    with pytest.raises(OSError, match="offline"):
        service.sync_once()
    restarted = inventory_service.InventoryService(cfg, client)
    with pytest.raises(OSError, match="offline"):
        restarted.sync_once()
    assert scan.call_count == 1
    assert json.loads(restarted.path.read_text())["snapshot"] == original

    client.post.reset_mock(side_effect=True)
    restarted.sync_once()
    assert scan.call_count == 2
    assert [call.args[1] for call in client.post.call_args_list] == [original, failed]
    assert not restarted.status()["pending"]


def test_expired_snapshot_is_refreshed_and_reenrollment_discards_cache(
    tmp_path, monkeypatch
):
    scan = Mock(side_effect=[report(age=400), report(), report()])
    monkeypatch.setattr(inventory_service, "collect_inventory", scan)
    cfg = config(tmp_path, inventory={"interval_s": 300})
    service = inventory_service.InventoryService(cfg, Mock())
    service.sync_once()
    service.sync_once()
    assert scan.call_count == 2
    cfg["sensor_id"] = "sensor-b"
    new_sensor = inventory_service.InventoryService(cfg, Mock())
    assert new_sensor.status()["collected_at"] is None
    new_sensor.sync_once()
    assert scan.call_count == 3


def test_paused_disabled_and_stopped_inventory_does_not_scan_or_send(
    tmp_path, monkeypatch
):
    scan = Mock(return_value=report())
    monkeypatch.setattr(inventory_service, "collect_inventory", scan)
    client = Mock()
    service = inventory_service.InventoryService(
        config(tmp_path), client, paused=lambda: True
    )
    service.sync_once()
    disabled = inventory_service.InventoryService(
        config(tmp_path, inventory={"enabled": False}), client
    )
    disabled.sync_once()
    stop = threading.Event()
    stop.set()
    running = inventory_service.InventoryService(config(tmp_path), client)
    running.sync_once(stop)
    scan.assert_not_called()
    client.post.assert_not_called()
    assert not service.path.exists()


def test_disable_during_scan_prevents_upload_and_cache(tmp_path, monkeypatch):
    paused = False

    def scan():
        nonlocal paused
        paused = True
        return report()

    monkeypatch.setattr(inventory_service, "collect_inventory", scan)
    client = Mock()
    service = inventory_service.InventoryService(
        config(tmp_path), client, paused=lambda: paused
    )
    service.sync_once()
    client.post.assert_not_called()
    assert not service.path.exists()


def test_shutdown_during_scan_prevents_upload_and_cache(tmp_path, monkeypatch):
    stop = threading.Event()

    def scan():
        stop.set()
        return report()

    monkeypatch.setattr(inventory_service, "collect_inventory", scan)
    client = Mock()
    service = inventory_service.InventoryService(config(tmp_path), client)
    service.sync_once(stop)
    client.post.assert_not_called()
    assert not service.path.exists()


def test_scan_failure_does_not_stop_other_sensor_workers(tmp_path, monkeypatch):
    stop = threading.Event()

    def fail():
        stop.set()
        raise OSError("inventory unavailable")

    monkeypatch.setattr(inventory_service, "collect_inventory", fail)
    client = Mock()
    service = inventory_service.InventoryService(config(tmp_path), client)
    service.run(stop)
    assert service.status()["last_error"] == "inventory unavailable"
    client.post.assert_not_called()


def test_failed_cache_write_does_not_send_unpersisted_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory_service, "collect_inventory", lambda: report())
    monkeypatch.setattr(
        inventory_service, "atomic_write", Mock(side_effect=OSError("disk full"))
    )
    client = Mock()
    service = inventory_service.InventoryService(config(tmp_path), client)
    with pytest.raises(OSError, match="disk full"):
        service.sync_once()
    client.post.assert_not_called()


@pytest.mark.parametrize("contents", ["[]", "null", "{invalid", '{"snapshot": 2}'])
def test_invalid_cache_is_replaced_by_fresh_scan(tmp_path, monkeypatch, contents):
    (tmp_path / "application-inventory.json").write_text(contents)
    scan = Mock(return_value=report())
    monkeypatch.setattr(inventory_service, "collect_inventory", scan)
    inventory_service.InventoryService(config(tmp_path), Mock()).sync_once()
    scan.assert_called_once()


@pytest.mark.parametrize(
    "options",
    [
        None,
        [],
        {"enabled": "false"},
        {"interval_s": True},
        {"interval_s": 0},
        {"interval_s": 604801},
    ],
)
def test_invalid_inventory_settings_are_rejected(options):
    with pytest.raises(ValueError):
        inventory_service.settings({"inventory": options})


def test_local_inventory_cli_needs_no_enrollment(tmp_path, monkeypatch, capsys):
    from openaidr.sensor import cli, inventory

    sample = report()
    monkeypatch.setattr(inventory, "collect_inventory", lambda: sample)
    monkeypatch.setattr(
        Config, "load", Mock(side_effect=AssertionError("must not load enrollment"))
    )
    assert cli.main(["inventory", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == sample


@pytest.mark.parametrize(
    "source",
    [
        "osquery-apps",
        "osquery-npm-packages",
        "openaidr-skills",
        "openaidr-mcp-servers",
        "openaidr-plugins",
        "openaidr-cli",
    ],
)
def test_component_retry_and_scope_change_without_a_second_macos_collector(
    tmp_path, monkeypatch, source
):
    monkeypatch.setattr(inventory_service.sys, "platform", "darwin")
    sample = report()
    sample.pop("applications")
    sample.pop("sources")
    sample["platform"] = "darwin"
    sample["roots"] = [
        {
            "source": source,
            "root": "/private/project",
            "scope": "project",
            "environment": "/private/project",
            "user": "",
            "status": "ok",
            "components": [],
            "relationships": [],
        }
    ]
    scan = Mock(return_value=sample)
    monkeypatch.setattr(
        inventory_service.component_inventory, "collect_inventory", scan
    )
    native_scan = Mock(side_effect=AssertionError("must not run native collection"))
    monkeypatch.setattr(inventory_service, "collect_inventory", native_scan)
    client = Mock()

    def post(path, body):
        if path == "inventory/snapshots":
            raise OSError("404: older server")

    client.post.side_effect = post
    cfg = config(tmp_path)
    legacy_cache = tmp_path / "application-inventory.json"
    legacy_cache.write_text(
        json.dumps(
            {
                "identity": [cfg["server_url"], cfg["sensor_id"]],
                "snapshot": report(),
                "acknowledged": False,
            }
        )
    )
    cached = legacy_cache.read_text()
    components = inventory_service.InventoryService(cfg, client, components=True)
    legacy = inventory_service.InventoryService(cfg, client)
    with pytest.raises(OSError, match="older server"):
        components.sync_once()
    legacy.sync_once()
    assert not legacy.status()["enabled"]
    assert legacy_cache.read_text() == cached
    native_scan.assert_not_called()
    assert client.post.call_count == 1
    assert not legacy.status()["pending"] and components.status()["pending"]
    assert "/private/project" not in json.dumps(components.status())
    assert components.status()["coverage"] == dict(
        ok=1, partial=0, error=0, unavailable=0
    )
    if os.name != "nt":
        assert components.path.stat().st_mode & 0o777 == 0o600
    client.post.side_effect = None
    restarted = inventory_service.InventoryService(cfg, client, components=True)
    restarted.sync_once()
    scan.assert_called_once()
    assert client.post.call_args.args == ("inventory/snapshots", sample)
    assert not restarted.status()["pending"]

    option = {
        "osquery-apps": "app_roots",
        "openaidr-mcp-servers": "mcp_configs",
        "openaidr-plugins": "plugin_roots",
        "openaidr-cli": "bin_roots",
    }.get(source, "skill_roots")
    cfg["inventory"] = {"components": {option: ["/private/other-location"]}}
    changed = inventory_service.InventoryService(cfg, client, components=True)
    assert changed.status()["collected_at"] is None
    changed.sync_once()
    assert scan.call_count == 2
    assert scan.call_args.args[1] == []


@pytest.mark.parametrize(
    "pause", ["disabled", "paused", "stopped", "unsupported", "mid_scan"]
)
def test_component_collection_obeys_sensor_lifecycle(tmp_path, monkeypatch, pause):
    monkeypatch.setattr(
        inventory_service.sys, "platform", "freebsd" if pause == "unsupported" else "darwin"
    )
    stop = threading.Event()
    cfg = config(tmp_path, inventory={"components": {"enabled": pause != "disabled"}})
    client = Mock()

    def scan(*args, **kwargs):
        assert not kwargs["cancelled"]()
        stop.set()
        assert kwargs["cancelled"]()
        return {"roots": []}

    collector = Mock(side_effect=scan)
    monkeypatch.setattr(
        inventory_service.component_inventory, "collect_inventory", collector
    )
    service = inventory_service.InventoryService(
        cfg, client, components=True, paused=lambda: pause == "paused"
    )
    if pause == "stopped":
        stop.set()
    service.sync_once(stop)
    assert collector.call_count == (1 if pause == "mid_scan" else 0)
    client.post.assert_not_called()
    assert not service.path.exists()


@pytest.mark.parametrize("mode", ["free", "api_key"])
def test_personal_inventory_stays_local_across_restart_and_honors_scope(tmp_path, monkeypatch, mode):
    sample = report()
    sample["applications"][0].update(source="linux-dpkg", identifier="cursor", name="Cursor", kind="application")
    scan = Mock(return_value=sample)
    monkeypatch.setattr(inventory_service, "collect_inventory", scan)
    cfg = config(tmp_path, connection_mode=mode, tenant_id="tenant-a")
    client = Mock()
    client.post.side_effect = AssertionError("Local inventory must not upload")
    service = inventory_service.InventoryService(cfg, client)
    service.sync_once()
    assert service.options == {"enabled": True, "interval_s": 21600}
    assert not service.status()["pending"] and service.status()["last_sent_at"] is None
    restarted = inventory_service.InventoryService(cfg, client)
    restarted.sync_once()
    assert scan.call_count == 1 and restarted.state["snapshot"] == scan.return_value
    from openaidr.sensor.local_posture import read

    assert read(cfg)["groups"]["apps"]["items"][0]["product"] == "cursor"
    assert service.path.stat().st_mode & 0o777 == 0o600 if os.name != "nt" else True
    for field, value in (("tenant_id", "tenant-b"), ("sensor_id", "sensor-b"),
                         ("server_url", "https://other.example"), ("connection_mode", "organization")):
        changed = inventory_service.InventoryService({**cfg, field: value}, client)
        assert not changed.state
    disabled = inventory_service.InventoryService({**cfg, "inventory": {"enabled": False}}, client)
    disabled.sync_once()
    assert not disabled.state and scan.call_count == 1
    client.post.assert_not_called()
