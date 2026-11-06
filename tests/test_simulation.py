"""Simulation profiles and their production ingestion boundaries."""

import asyncio
import copy
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import threading
import time
from uuid import uuid4

import httpx
import psycopg
from psycopg.conninfo import make_conninfo
import pytest
import uvicorn
import yaml
from starlette.responses import JSONResponse

from openaidr.core.event import now, validate_event
from openaidr.sensor.config import Config
from openaidr.core.files import atomic_write
from openaidr.sensor import simulation
from openaidr.server.app import create_app
from openaidr.server.config import Config as ServerConfig
from openaidr.server.store import Store
from openaidr.server.agent_cost_usage import process_pending
from openaidr.server.auth import CONSOLE_COOKIE


def component_snapshot():
    root = dict(
        source="osquery-apps",
        root="/Users/alice/Applications",
        scope="user",
        user="alice",
        environment="",
        status="ok",
        message="",
        relationships=[],
    )
    root["components"] = [
        dict(
            key=name,
            identifier=name,
            name=name,
            version="1.0",
            kind="application",
            ecosystem="",
            evidence="installed",
            path=f"/Users/alice/Applications/{name}.app",
            metadata={},
        )
        for name in ["Claude", "Codex", *[f"Application {i}" for i in range(20)]]
    ]
    root["relationships"] = [
        dict(
            **{
                "from": dict(source=root["source"], root=root["root"], key="Claude"),
                "to": dict(source=root["source"], root=root["root"], key="Codex"),
            },
            kind="configured_with",
            evidence="configured",
            path="/Users/alice/config.json",
        )
    ]
    return dict(schema_version=1, collected_at=now(), platform="darwin", roots=[root])


def source_config(tmp_path, tenant=None):
    cfg = Config(
        tmp_path / "sensor.yaml",
        data_dir=str(tmp_path),
        server_url="http://127.0.0.1:9000",
        tenant_id=tenant or str(uuid4()),
        sensor_id=str(uuid4()),
        sensor_token="real-device-token",
    )
    cfg.save()
    atomic_write(
        tmp_path / "component-inventory.json",
        json.dumps(
            dict(
                identity=[cfg["server_url"], cfg["sensor_id"], {}],
                snapshot=component_snapshot(),
            )
        ),
    )
    return cfg


def configure(source, **overrides):
    values = dict(
        enabled=True,
        name="Simulation test",
        server_url="http://127.0.0.1:9001",
        tenant_id=str(uuid4()),
        enrollment_token="oaet_test",
    )
    values.update(overrides)
    atomic_write(Path(source["data_dir"]) / "simulation.yaml", yaml.safe_dump(values))
    return values


def test_profiles_are_stable_valid_and_keep_references_and_users_consistent():
    from openaidr.server.component_inventory import validate_snapshot

    snapshot = component_snapshot()
    before = copy.deepcopy(snapshot)
    fleet = str(uuid4())
    variants = set()
    for index in range(100):
        first = simulation.inventory(snapshot, fleet, index)
        second = simulation.inventory(snapshot, fleet, index)
        first.pop("collected_at")
        second.pop("collected_at")
        assert first == second
        assert "alice" not in json.dumps(first)
        first["collected_at"] = now()
        validate_snapshot(str(uuid4()), first)
        names = {c["name"] for c in first["roots"][0]["components"]}
        assert ("Claude" in names) == ("claude-code" in simulation.products(index))
        assert ("Codex" in names) == ("codex-cli" in simulation.products(index))
        if first["roots"][0]["relationships"]:
            assert {"Claude", "Codex"} <= names
        variants.add(tuple(sorted(names)))
        events, _ = simulation.activity(fleet, index, 0, str(uuid4()), "darwin")
        assert all(not validate_event(event) for event in events)
        assert events[1]["tool"]["call_id"] == events[2]["tool"]["call_id"]
    assert len(variants) > 90
    assert snapshot == before


def test_configuration_requires_opt_in_separate_identity_and_loopback(
    tmp_path, monkeypatch
):
    source = source_config(tmp_path)
    configure(source)
    monkeypatch.delenv("OPENAIDR_DEVICE_SIMULATION", raising=False)
    assert simulation.status(source) == {"enabled": False}
    with pytest.raises(ValueError, match="development builds"):
        simulation.Fleet(source)
    monkeypatch.setenv("OPENAIDR_DEVICE_SIMULATION", "1")
    assert simulation.status(source)["configured"]
    for url in (
        "https://tenant.example",
        "http://127.0.0.1.evil.example",
        "http://127.0.0.1/path",
        "http://user@127.0.0.1",
    ):
        configure(source, server_url=url)
        with pytest.raises(ValueError):
            simulation.Fleet(source)
    configure(source, tenant_id=source["tenant_id"])
    with pytest.raises(ValueError, match="separate"):
        simulation.Fleet(source)
    configure(source)
    (tmp_path / "simulation.yaml").chmod(0o644)
    with pytest.raises(ValueError, match="permissions"):
        simulation.Fleet(source)
    assert not (tmp_path / "simulation/fleet.json").exists()


@pytest.fixture
def backend(tmp_path, monkeypatch):
    url = os.environ.get("OPENAIDR_TEST_DATABASE_URL")
    if not url:
        pytest.skip("OPENAIDR_TEST_DATABASE_URL is not configured")
    schema = "simulation_" + uuid4().hex
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
    store = Store(make_conninfo(url, options=f"-c search_path={schema}"))
    store.migrate()
    tenant = store.bootstrap_tenant("Simulation test", "simulation")
    other = store.bootstrap_tenant("Real devices", "real")
    source = source_config(tmp_path, other["tenant"]["id"])
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    configure(
        source,
        server_url=origin,
        tenant_id=tenant["tenant"]["id"],
        enrollment_token=tenant["enrollment_token"],
    )
    # The test drains costs explicitly; a background worker can hold the last row.
    cfg = ServerConfig(database_url=store.url, cost_processing=False)
    cfg.set_services("ingest,api")
    app = create_app(cfg, store)
    faults = {}

    @app.middleware("http")
    async def lost_ack(request, call_next):
        response = await call_next(request)
        if request.url.path == "/ingest/v1/events" and faults.pop(
            "drop_event_ack", False
        ):
            return JSONResponse({}, status_code=503)
        return response

    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [listener]}, daemon=True
    )
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started
    monkeypatch.setenv("OPENAIDR_DEVICE_SIMULATION", "1")
    try:
        yield source, store, origin, tenant, other, faults
    finally:
        server.should_exit = True
        thread.join(10)
        listener.close()
        store.close()
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(f"DROP SCHEMA {schema} CASCADE")


def test_hundred_devices_reach_real_apis_and_restart_without_new_identities(backend):
    source, store, origin, tenant, other, faults = backend
    faults["drop_event_ack"] = True
    original = source.path.read_bytes()

    def stop_after_round(summary):
        if summary["records_sent"] >= 500:
            fleet.stop.set()

    fleet = simulation.Fleet(source, stop_after_round)
    asyncio.run(asyncio.wait_for(fleet.run(), 30))
    assert fleet.summary["enrolled"] == 100
    assert fleet.summary["inventories_sent"] == 100
    assert fleet.summary["errors"] == 1
    assert len({d["id"] for d in fleet.saved["devices"].values()}) == 100
    assert (
        store.scalar(
            "SELECT count(*) FROM sensors WHERE tenant_id=$1", tenant["tenant"]["id"]
        )
        == 100
    )
    assert (
        store.scalar(
            "SELECT count(DISTINCT username) FROM agents WHERE tenant_id=$1",
            tenant["tenant"]["id"],
        )
        == 100
    )
    assert store.scalar("SELECT count(DISTINCT sensor_id) FROM inventory_roots") == 100
    assert store.scalar("SELECT count(*) FROM telemetry_exports") >= 100
    assert (
        store.scalar("SELECT count(*) FROM events WHERE export_id IS NULL")
        + store.scalar("SELECT sum(record_count) FROM telemetry_exports")
        == fleet.summary["records_sent"]
    )
    for _ in range(3):
        processed = process_pending(store)
        assert processed["failed"] == 0
        if processed["exports"] == 0:
            break
    assert (
        store.scalar("SELECT count(DISTINCT user_name) FROM agent_cost_records") == 100
    )
    assert store.scalar("SELECT count(*) FROM agent_cost_records WHERE NOT demo") == 0
    assert source.path.read_bytes() == original
    assert (fleet.path.stat().st_mode & 0o077) == 0
    saved = copy.deepcopy(fleet.saved)
    second = simulation.Fleet(
        source,
        lambda summary: second.stop.set() if summary["records_sent"] >= 500 else None,
    )
    assert second.saved == saved
    asyncio.run(asyncio.wait_for(second.run(), 30))
    assert second.saved == saved
    assert (
        store.scalar(
            "SELECT count(*) FROM sensors WHERE tenant_id=$1", tenant["tenant"]["id"]
        )
        == 100
    )

    # A token cannot submit another simulated device's inventory or escape its tenant.
    first, last = fleet.saved["devices"]["0"], fleet.saved["devices"]["99"]
    with httpx.Client(base_url=origin, trust_env=False) as client:
        payload = dict(component_snapshot(), sensor_id=last["id"])
        assert (
            client.post(
                "/ingest/v1/inventory/snapshots",
                json=payload,
                headers={"Authorization": "Bearer " + first["token"]},
            ).status_code
            == 403
        )
        for account, expected in ((tenant, True), (other, False)):
            user = store.create_user(
                account["tenant"]["id"],
                str(uuid4()) + "@example.invalid",
                "Analyst",
                "unused",
                "analyst",
            )
            client.cookies.set(
                CONSOLE_COOKIE,
                store.create_session(user["id"], account["tenant"]["id"]),
            )
            response = client.get("/api/v1/agents?limit=50")
            assert response.status_code == 200
            assert bool(response.json()["items"]) is expected
            if expected:
                rows = response.json()["items"]
                cursor = response.json()["next_cursor"]
                while cursor:
                    data = client.get(
                        "/api/v1/agents", params={"limit": 50, "cursor": cursor}
                    ).json()
                    rows.extend(data["items"])
                    cursor = data["next_cursor"]
                assert len({row["host"]["user"] for row in rows}) == 100
                assert len({row["id"] for row in rows}) == len(rows)


def test_wrong_tenant_token_stops_after_one_registration_without_sending_data(backend):
    source, store, origin, tenant, other, _ = backend
    configure(
        source,
        server_url=origin,
        tenant_id=tenant["tenant"]["id"],
        enrollment_token=other["enrollment_token"],
    )
    fleet = simulation.Fleet(source)
    with pytest.raises(ValueError, match="different tenant"):
        asyncio.run(asyncio.wait_for(fleet.run(), 15))
    assert store.scalar("SELECT count(*) FROM sensors") == 1
    assert (
        store.scalar(
            "SELECT sum(uses) FROM enrollment_tokens WHERE tenant_id=$1",
            other["tenant"]["id"],
        )
        == 1
    )
    assert fleet.saved["devices"] == {}
    for table in ("events", "inventory_roots", "telemetry_exports"):
        assert store.scalar(f"SELECT count(*) FROM {table}") == 0


def test_cli_worker_rejects_a_second_process_and_stops_on_parent_eof(backend):
    source, *_ = backend
    # Override only the default config location, leaving CLI and worker behavior real.
    command = [
        sys.executable,
        "-c",
        "import sys; from pathlib import Path; from openaidr.sensor import config, cli; "
        "config.default_path = lambda: Path(sys.argv[1]); "
        "sys.exit(cli.main(['simulate-devices']))",
        str(source.path),
    ]
    worker = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert select.select([worker.stdout], [], [], 10)[0]
        assert json.loads(worker.stdout.readline())["state"] == "starting"
        duplicate = subprocess.run(
            command, input="", capture_output=True, text=True, timeout=10
        )
        assert duplicate.returncode == 1
        assert "already running" in json.loads(duplicate.stdout)["error"]
        worker.stdin.close()
        worker.stdin = None
        output, errors = worker.communicate(timeout=7)
        assert worker.returncode == 0, errors
        assert json.loads(output.splitlines()[-1])["state"] == "stopped"
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait(timeout=5)
