"""Real PostgreSQL dashboard counts, identity boundaries, and owner setup."""

import io
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.conninfo import make_conninfo

from openaidr.server.app import create_app
from openaidr.server.agent_cost_usage import process_pending
from openaidr.server.auth import CONSOLE_COOKIE, check_password, hash_password
from openaidr.server.cli import main
from openaidr.server.config import Config
from openaidr.server.store import Store, new_id
from openaidr.core.telemetry import count_records


def cost_payload(service, when, events, label="eventName"):
    data = payload("logs", service, 0, demo=False)
    data["resourceLogs"][0]["scopeLogs"][0]["logRecords"] = [
        {
            "timeUnixNano": str(
                int((when + timedelta(seconds=index)).timestamp() * 1e9)
            ),
            "eventName": name,
            "body": {"stringValue": "PRIVATE-PROMPT-MUST-NOT-LEAVE"},
            "attributes": [
                {"key": key, "value": {"stringValue": str(value)}}
                for key, value in attrs.items()
            ],
        }
        for index, (name, attrs) in enumerate(events)
    ]
    for item in data["resourceLogs"][0]["scopeLogs"][0]["logRecords"]:
        if label == "body":
            item["body"] = {"stringValue": item.pop("eventName")}
        elif label == "attribute":
            item["attributes"].append(
                {"key": "event.name", "value": {"stringValue": item.pop("eventName")}}
            )
    return data


def payload(signal, service, count, demo=True):
    resource = {
        "attributes": [
            {"key": "service.name", "value": {"stringValue": service}},
            {"key": "openaidr.demo", "value": {"boolValue": demo}},
        ]
    }
    if signal == "logs":
        return {
            "resourceLogs": [
                {
                    "resource": resource,
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "body": {
                                        "stringValue": "TOP-SECRET-NOT-FOR-DASHBOARD"
                                    }
                                }
                                for _ in range(count)
                            ]
                        }
                    ],
                }
            ]
        }
    if signal == "metrics":
        return {
            "resourceMetrics": [
                {
                    "resource": resource,
                    "scopeMetrics": [
                        {
                            "metrics": [
                                {
                                    "name": "tokens.cumulative",
                                    "sum": {
                                        "aggregationTemporality": 2,
                                        "isMonotonic": True,
                                        "dataPoints": [
                                            {"asInt": "90000000"} for _ in range(count)
                                        ],
                                    },
                                }
                            ]
                        }
                    ],
                }
            ]
        }
    return {
        "resourceSpans": [
            {
                "resource": resource,
                "scopeSpans": [
                    {"spans": [{"name": "demo-span"} for _ in range(count)]}
                ],
            }
        ]
    }


@pytest.fixture
def dashboard(request, tmp_path, monkeypatch):
    url = os.environ.get("OPENAIDR_TEST_DATABASE_URL")
    if not url:
        pytest.skip("OPENAIDR_TEST_DATABASE_URL is not configured")
    schema = "dashboard_" + uuid4().hex
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
    with monkeypatch.context() as initial_schema:
        if getattr(request, "param", None) == "before_partitions":
            # Start on ordinary tables; later migrations must see the full set.
            # Current enrollment reads the independent sensor capability columns.
            from openaidr.server import store

            migrations = tmp_path / "migrations"
            migrations.mkdir()
            for path in Path(store.__file__).with_name("migrations").glob("*.sql"):
                if int(path.name.split("_")[0]) < 50 or path.name in ("0071_sensor_policy_delivery.sql", "0074_sensor_health.sql", "0078_dashboard_role_tags.sql", "0082_device_identity.sql", "0089_endpoint_signed_in_user.sql"):
                    (migrations / path.name).symlink_to(path)
            initial_schema.setattr(store, "__file__", str(tmp_path / "store.py"))
        st = Store(make_conninfo(url, options=f"-c search_path={schema}"))
        st.migrate()
    tenant = st.bootstrap_tenant("Demo", "demo")
    other = st.bootstrap_tenant("Other", "other")
    sensor, token, _ = st.enroll_sensor(
        {
            "enrollment_token": tenant["enrollment_token"],
            "hostname": "linux-demo",
            "os": "linux",
            "arch": "amd64",
        }
    )
    remote, _, _ = st.enroll_sensor(
        {"enrollment_token": other["enrollment_token"], "hostname": "other-device"}
    )
    offline, _, _ = st.enroll_sensor(
        {"enrollment_token": tenant["enrollment_token"], "hostname": "old-device"}
    )
    disabled, _, _ = st.enroll_sensor(
        {"enrollment_token": tenant["enrollment_token"], "hostname": "disabled-device"}
    )
    st.execute(
        "UPDATE sensor_activity SET last_heartbeat_at=now()-interval '10 minutes' WHERE sensor_id=$1",
        offline["id"],
    )
    st.update_sensor(sensor["tenant_id"], disabled["id"], disabled=True)
    user = st.create_tenant_owner(
        sensor["tenant_id"],
        "demo@example.com",
        "Demo Owner",
        hash_password("initial-password"),
    )
    cfg = Config(database_url=st.url, tenant_id=sensor["tenant_id"], cost_processing=False)
    cfg.set_services("ingest,api")
    client = TestClient(create_app(cfg, st), headers={"X-OpenAIDR-CSRF": "1"})
    # Accounting assertions represent separate 30-second dashboard refreshes.
    # Cache coalescing and expiry have their own integration coverage.
    from itertools import count

    refresh_times = count(step=30)
    client.app.state.service.cost_cache.clock = lambda: next(refresh_times)
    result = client.post(
        "/api/v1/auth/login",
        json={"email": user["email"], "password": "initial-password"},
    )
    assert result.status_code == 200, result.text
    try:
        yield st, cfg, client, sensor, token, remote
    finally:
        client.close()
        st.close()
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(f"DROP SCHEMA {schema} CASCADE")


def populate(st, sensor, remote):
    combined = payload("logs", "codex-cli", 2)
    combined["resourceLogs"] += payload("logs", "claude-code", 3, demo=False)[
        "resourceLogs"
    ]
    batch = new_id()
    st.ingest_telemetry(
        sensor, "logs", batch, combined, count_records("logs", combined)
    )
    for signal, service, number in [
        ("metrics", "codex-cli", 4),
        ("traces", "claude-code", 1),
    ]:
        data = payload(signal, service, number)
        st.ingest_telemetry(sensor, signal, new_id(), data, count_records(signal, data))
    old = new_id()
    st.ingest_telemetry(sensor, "logs", old, payload("logs", "codex-cli", 7), 7)
    st.execute(
        "UPDATE telemetry_exports SET received_at=now()-interval '2 days' WHERE batch_id=$1",
        old,
    )
    st.ingest_telemetry(
        remote, "logs", new_id(), payload("logs", "other-service", 9), 9
    )
    return batch


def test_overview_real_counts_filters_devices_and_metadata(dashboard):
    st, cfg, client, sensor, token, remote = dashboard
    shared_batch = populate(st, sensor, remote)
    heartbeat = client.post(
        "/ingest/v1/heartbeat",
        json={"queue_depth": 7, "telemetry_queue_depth": 3, "sensor_version": "0.1.0",
              "cpu_percent": 132.5, "memory_rss_bytes": 32 * 1024**2},
        headers={"Authorization": "Bearer " + token},
    )
    assert heartbeat.status_code == 200, heartbeat.text
    health = client.get("/api/v1/sensors/health")
    assert health.status_code == 200, health.text
    health_devices = health.json()["items"]
    assert len(health_devices) == 3
    current = next(row for row in health_devices if row["id"] == sensor["id"])
    assert current["status"] == "online"
    assert current["telemetry_queue_depth"] == 3
    assert current["cpu_percent"] == 132.5 and current["memory_rss_bytes"] == 32 * 1024**2
    assert all(row["id"] != remote["id"] for row in health_devices)
    result = client.get("/api/v1/telemetry/overview")
    assert result.status_code == 200, result.text
    data = result.json()
    summary = data["summary"]
    assert {
        k: summary[k]
        for k in ("exports", "records", "log_records", "metric_points", "spans")
    } == {"exports": 3, "records": 10, "log_records": 5, "metric_points": 4, "spans": 1}
    assert summary["devices"] == 3
    assert (
        summary["online_devices"]
        == summary["offline_devices"]
        == summary["disabled_devices"]
        == 1
    )
    assert len(data["activity"]) == 24
    statuses = client.get("/api/v1/guardrail/devices")
    assert statuses.status_code == 200, statuses.text
    assert {row["id"]: row for row in statuses.json()["items"]} == {
        row["id"]: {key: row[key] for key in ("id", "hostname", "label", "status")}
        for row in data["devices"]
    }
    assert sum(row["exports"] for row in data["activity"]) == 3
    assert sum(row["metric_points"] for row in data["activity"]) == 4
    assert data["available_services"] == ["claude-code", "codex-cli"]
    services = {row["name"]: row for row in data["services"]}
    assert services["codex-cli"]["log_records"] == 2
    assert services["claude-code"]["log_records"] == 3
    device = next(row for row in data["devices"] if row["id"] == sensor["id"])
    assert device["queue_depth"] == 7 and device["queue_depth_kind"] == "legacy_events"
    assert device["telemetry_queue_depth"] == 3
    assert device["cpu_percent"] == 132.5
    assert device["memory_rss_bytes"] == 32 * 1024**2
    assert device["sensor_version"] == "0.1.0" and device["latest_export_at"]
    assert all(
        row["telemetry_queue_depth"] is None and row["cpu_percent"] is None
        and row["memory_rss_bytes"] is None
        for row in data["devices"]
        if row["id"] != sensor["id"]
    )
    shared = next(
        row for row in data["recent_exports"] if row["batch_id"] == shared_batch
    )
    assert shared["demo"] is False
    assert shared["record_count"] == shared["total_record_count"] == 5
    assert "TOP-SECRET-NOT-FOR-DASHBOARD" not in result.text
    assert "payload" not in result.text and "token" not in result.text
    filtered = client.get(
        "/api/v1/telemetry/overview", params={"service": "codex-cli"}
    ).json()
    assert filtered["summary"]["exports"] == 2 and filtered["summary"]["records"] == 6
    assert filtered["summary"]["log_records"] == 2
    assert filtered["summary"]["metric_points"] == 4
    assert filtered["available_services"] == data["available_services"]
    assert len(filtered["devices"]) == 1
    matched = next(
        row for row in filtered["recent_exports"] if row["batch_id"] == shared_batch
    )
    assert matched["record_count"] == 2 and matched["total_record_count"] == 5
    assert matched["service_names"] == ["codex-cli"] and matched["demo"] is True
    week = client.get("/api/v1/telemetry/overview", params={"range": "7d"}).json()
    assert week["summary"]["records"] == 17 and len(week["activity"]) == 28
    month = client.get("/api/v1/telemetry/overview", params={"range": "30d"}).json()
    assert month["summary"]["records"] == 17 and len(month["activity"]) == 30


def test_auth_isolation_empty_state_and_pagination(dashboard):
    st, cfg, client, sensor, _, remote = dashboard
    empty = client.get("/api/v1/telemetry/overview").json()
    assert empty["summary"]["exports"] == empty["summary"]["records"] == 0
    assert empty["summary"]["last_export_at"] is None
    assert empty["services"] == empty["recent_exports"] == []
    populate(st, sensor, remote)
    anonymous = TestClient(create_app(cfg, st))
    assert anonymous.get("/api/v1/telemetry/overview").status_code == 401
    assert anonymous.get("/api/v1/telemetry/exports").status_code == 401
    assert anonymous.get("/api/v1/sensors/health").status_code == 401
    foreign = st.create_user(
        remote["tenant_id"], "foreign@example.com", "Foreign", "unused", "viewer"
    )
    anonymous.cookies.set(
        CONSOLE_COOKIE, st.create_session(foreign["id"], remote["tenant_id"])
    )
    assert anonymous.get("/api/v1/telemetry/overview").status_code == 403
    assert anonymous.get("/api/v1/telemetry/exports").status_code == 403
    assert anonymous.get("/api/v1/sensors/health").status_code == 403
    own = st.get_user_by_email("demo@example.com")
    st.update_user(sensor["tenant_id"], own["id"], role="viewer")
    assert client.get("/api/v1/telemetry/overview").status_code == 200
    # The same endpoint remains scoped when used by a multi-tenant API server.
    cfg.tenant_id = ""
    multi = TestClient(create_app(cfg, st))
    multi.cookies.set(
        CONSOLE_COOKIE, st.create_session(foreign["id"], remote["tenant_id"])
    )
    own_other = multi.get("/api/v1/telemetry/overview").json()
    assert own_other["summary"]["records"] == 9
    assert own_other["available_services"] == ["other-service"]
    assert client.get("/api/v1/telemetry/exports").status_code == 403
    st.update_user(sensor["tenant_id"], own["id"], roles=["it_admin"])
    first = client.get("/api/v1/telemetry/exports", params={"limit": 1}).json()
    second = client.get(
        "/api/v1/telemetry/exports", params={"limit": 1, "cursor": first["next_cursor"]}
    ).json()
    assert first["next_cursor"] and first["items"][0]["id"] != second["items"][0]["id"]
    for query in ({"range": "bad"}, {"cursor": "broken"}, {"limit": "-1"}):
        assert client.get("/api/v1/telemetry/exports", params=query).status_code == 400
    injection = client.get(
        "/api/v1/telemetry/overview", params={"service": "codex-cli' OR 1=1 --"}
    ).json()
    assert injection["summary"]["records"] == 0
    assert injection["devices"] == []
    assert client.post("/api/v1/auth/logout", json={}).status_code == 204
    assert client.get("/api/v1/telemetry/overview").status_code == 401


def test_summary_upgrade_backfill_and_queries_without_payload_parsing(dashboard):
    from itertools import count
    from openaidr.server.telemetry_dashboard import backfill_summaries

    st, _, client, sensor, _, remote = dashboard
    # Recreate the previous schema and its exports, then run the real migration.
    st.execute("DROP TRIGGER telemetry_resource_summary_on_write ON telemetry_exports")
    st.execute("DROP FUNCTION set_telemetry_resource_summary()")
    st.execute("DROP FUNCTION telemetry_resource_summary(text,jsonb)")
    st.execute("ALTER TABLE telemetry_exports DROP COLUMN resource_summary")
    st.execute("DELETE FROM schema_migrations WHERE version=49")
    populate(st, sensor, remote)
    repeated = payload("logs", "codex-cli", 1)
    repeated["resourceLogs"] += payload("logs", "codex-cli", 4, demo=False)["resourceLogs"]
    repeated["resourceLogs"] += payload("logs", "", 2)["resourceLogs"]
    st.ingest_telemetry(sensor, "logs", new_id(), repeated, 7)
    st.ingest_telemetry(sensor, "logs", new_id(), {}, 0)
    assert st.migrate() == ["0049_telemetry_resource_summaries.sql"]
    assert st.scalar("SELECT count(*) FROM telemetry_exports WHERE resource_summary IS NOT NULL") == 0

    # An old writer's unchanged INSERT also produces a summary after migration.
    batch = new_id()
    data = payload("metrics", "codex-cli", 2)
    assert st.ingest_telemetry(sensor, "metrics", batch, data, 2)
    assert not st.ingest_telemetry(sensor, "metrics", batch, data, 2)
    assert st.scalar("SELECT resource_summary FROM telemetry_exports WHERE batch_id=$1", batch) == [
        {"service": "codex-cli", "records": 2, "demo": True},
    ]
    clock = count(step=30)
    client.app.state.service.telemetry_cache.clock = lambda: next(clock)
    before = client.get("/api/v1/telemetry/overview").json()
    filtered = client.get("/api/v1/telemetry/overview?service=codex-cli").json()
    assert before["summary"]["records"] == 19
    assert filtered["summary"]["records"] == 13
    assert set(before["available_services"]) == {"(unknown)", "claude-code", "codex-cli"}
    assert next(s for s in before["services"] if s["name"] == "codex-cli")["log_records"] == 7

    # A locked export cannot stall the backfill or make it exceed its batch size.
    with st.transaction() as gate:
        locked = st.scalar("""SELECT id FROM telemetry_exports
            WHERE tenant_id=$1 AND resource_summary IS NULL
            ORDER BY received_at DESC,id DESC LIMIT 1 FOR UPDATE""", sensor["tenant_id"], conn=gate)
        assert backfill_summaries(st, sensor["tenant_id"], 1) == 1
        assert st.scalar("SELECT resource_summary IS NULL FROM telemetry_exports WHERE id=$1", locked)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert sum(pool.map(lambda _: backfill_summaries(st, sensor["tenant_id"], 1), range(3))) == 3
    # The API worker resumes the remaining legacy rows and stops with the app.
    with TestClient(client.app):
        deadline = time.monotonic() + 5
        while st.scalar("SELECT count(*) FROM telemetry_exports WHERE tenant_id=$1 AND resource_summary IS NULL", sensor["tenant_id"]):
            assert time.monotonic() < deadline, "summary worker did not finish the remaining rows"
            time.sleep(0.01)
    assert st.scalar("SELECT resource_summary IS NULL FROM telemetry_exports WHERE tenant_id=$1", remote["tenant_id"])
    assert "TOP-SECRET" not in str(st.many("SELECT resource_summary FROM telemetry_exports"))

    # Fail any attempt to compute from raw payloads. Reads must use persisted
    # metadata even for service filters, older exports, and recent-export lists.
    st.execute("""CREATE OR REPLACE FUNCTION telemetry_resource_summary(signal text,payload jsonb)
        RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
        BEGIN RAISE EXCEPTION 'dashboard reparsed a raw payload'; END; $$""")
    after = client.get("/api/v1/telemetry/overview")
    assert after.status_code == 200, after.text
    after_filtered = client.get("/api/v1/telemetry/overview?service=codex-cli")
    assert after_filtered.status_code == 200, after_filtered.text
    for key in ("summary", "services", "available_services", "devices", "recent_exports"):
        assert after.json()[key] == before[key]
        assert after_filtered.json()[key] == filtered[key]
    assert client.get("/api/v1/telemetry/overview?range=7d").json()["summary"]["records"] == 26
    assert client.get("/api/v1/telemetry/exports?service=codex-cli").status_code == 200


def test_overview_cache_coalesces_http_refreshes_and_expires(dashboard):
    st, cfg, client, sensor, _, remote = dashboard
    populate(st, sensor, remote)
    clock = [0.0]
    client.app.state.service.telemetry_cache.clock = lambda: clock[0]
    barrier = Barrier(8)

    def read():
        barrier.wait(timeout=5)
        result = client.get("/api/v1/telemetry/overview")
        assert result.status_code == 200, result.text
        return result.json()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: read(), range(8)))
    assert all(result == results[0] for result in results)
    assert results[0]["summary"]["records"] == 10
    st.ingest_telemetry(sensor, "logs", new_id(), payload("logs", "new-service", 2), 2)
    assert client.get("/api/v1/telemetry/overview").json() == results[0]
    # Filters and time ranges must not reuse another key's snapshot.
    filtered = client.get("/api/v1/telemetry/overview?service=new-service").json()
    assert filtered["summary"]["records"] == 2
    assert client.get("/api/v1/telemetry/overview?range=7d").json()["summary"]["records"] == 19
    clock[0] = 30
    refreshed = client.get("/api/v1/telemetry/overview").json()
    assert refreshed["summary"]["records"] == 12
    assert refreshed["generated_at"] != results[0]["generated_at"]
    # Two authorized tenants using the same service instance cannot share entries.
    cfg.tenant_id = ""
    foreign = st.create_user(remote["tenant_id"], "foreign@example.com", "Foreign", "unused", "viewer")
    other_client = TestClient(client.app)
    other_client.cookies.set(CONSOLE_COOKIE, st.create_session(foreign["id"], remote["tenant_id"]))
    try:
        other = other_client.get("/api/v1/telemetry/overview").json()
        assert other["summary"]["records"] == 9
        assert other["available_services"] == ["other-service"]
    finally:
        other_client.close()
    # Authentication still runs on every cache hit.
    assert client.post("/api/v1/auth/logout", json={}).status_code == 204
    assert client.get("/api/v1/telemetry/overview").status_code == 401


def test_overview_capacity_keeps_data_connections_available(dashboard):
    st, _, client, _, _, _ = dashboard
    with ThreadPoolExecutor(max_workers=2) as pool:
        with st.transaction() as gate:
            gate.execute("LOCK TABLE telemetry_exports IN ACCESS EXCLUSIVE MODE")
            pending = [pool.submit(client.get, "/api/v1/telemetry/overview", params={"range": r})
                       for r in ("24h", "7d")]
            deadline = time.monotonic() + 5
            while st.scalar("""SELECT count(*) FROM pg_locks
                    WHERE relation='telemetry_exports'::regclass AND NOT granted""") < 2:
                assert time.monotonic() < deadline, "overview queries did not reach the database"
                time.sleep(0.01)
            excess = client.get("/api/v1/telemetry/overview?range=30d")
            assert excess.status_code == 503
            assert client.get("/api/v1/sensors").status_code == 200
            health = client.get("/api/v1/sensors/health")
            assert health.status_code == 200, health.text
            sensor = health.json()["items"][0]
            assert client.get(f"/api/v1/sensors/{sensor['id']}/metrics").status_code == 200
        assert all(request.result(timeout=5).status_code == 200 for request in pending)
    assert client.get("/api/v1/telemetry/overview?range=30d").status_code == 200


@pytest.mark.parametrize("endpoint", ["overview", "exports"])
def test_telemetry_timeout_releases_connection_and_allows_retry(dashboard, monkeypatch, endpoint):
    from openaidr.server import telemetry_dashboard

    st, _, client, _, _, _ = dashboard
    monkeypatch.setattr(telemetry_dashboard, "STATEMENT_TIMEOUT_MS", 100)
    st.pools["data"].resize(1, 1)
    original_timeout = st.scalar("SHOW statement_timeout")
    original_jit = st.scalar("SHOW jit")
    # Use a separate connection so the only application connection is the reader.
    with psycopg.connect(st.url) as gate:
        gate.execute("LOCK TABLE telemetry_exports IN ACCESS EXCLUSIVE MODE")
        started = time.monotonic()
        result = client.get(f"/api/v1/telemetry/{endpoint}")
        assert result.status_code == 503, result.text
        assert time.monotonic() - started < 3
        assert st.scalar("SHOW statement_timeout") == original_timeout
        assert st.scalar("SHOW jit") == original_jit
        assert st.scalar("SELECT 1") == 1
    assert client.get(f"/api/v1/telemetry/{endpoint}").status_code == 200


def test_telemetry_reads_do_not_compile_even_above_the_jit_cost_threshold(dashboard):
    from openaidr.server.telemetry_dashboard import _read_transaction

    st = dashboard[0]
    st.pools["data"].resize(1, 1)
    original_jit = st.scalar("SHOW jit")
    with _read_transaction(st) as conn:
        conn.execute("SET LOCAL jit_above_cost=0")
        plan = conn.execute("EXPLAIN (ANALYZE, FORMAT JSON) "
                            "SELECT sum(n) FROM generate_series(1,10) n").fetchone()["QUERY PLAN"][0]
        assert "JIT" not in plan
    assert st.scalar("SHOW jit") == original_jit


@pytest.mark.parametrize("label", ["eventName", "attribute", "body"])
@pytest.mark.parametrize(("service", "prefix"), [
    ("claude-code", "claude_code."), ("claude-code-desktop", ""), ("cowork", ""),
])
def test_agent_costs_reconcile_ranges_filters_and_native_usage(dashboard, label, service, prefix):
    st, _, client, sensor, _, remote = dashboard
    now = st.scalar("SELECT now()")
    empty = client.get("/api/v1/costs/agents").json()
    assert empty["summary"]["cost_usd"] is None
    assert empty["summary"]["calls"] == 0
    common = {
        "session.id": "session",
        "prompt.id": "prompt",
        "os.user": "alice",
        "user.email": "account@example.com",
        "model": "claude-sonnet-5",
    }
    logs = cost_payload(
        service,
        now - timedelta(minutes=10),
        [
            (
                prefix + "api_request",
                {
                    **common,
                    "request_id": "one",
                    "cost_usd": "0.125",
                    "input_tokens": 1000,
                    "output_tokens": 200,
                    "cache_read_tokens": 600,
                    "cache_creation_tokens": 100,
                },
            ),
            (
                prefix + "tool_result",
                {**common, "tool_name": "Edit", "cwd": "/work/console"},
            ),
            (
                prefix + "api_request",
                {
                    **common,
                    "request_id": "two",
                    "cost_usd": "0.25",
                    "input_tokens": 2000,
                    "output_tokens": 400,
                },
            ),
        ],
        label=label,
    )
    # Delivery replay in a new batch and another tenant must not inflate totals.
    for device in (sensor, sensor, remote):
        st.ingest_telemetry(device, "logs", new_id(), logs, 3)
    codex = cost_payload(
        "codex-cli",
        now - timedelta(minutes=5),
        [
            (
                "codex.user_prompt",
                {"conversation.id": "codex-session", "cwd": "/work/backend"},
            ),
            (
                "codex.sse_event",
                {
                    "conversation.id": "codex-session",
                    "model": "gpt-6-astra",
                    "event.kind": "response.completed",
                    "input_token_count": 1000,
                    "cached_token_count": 600,
                    "cache_write_token_count": 100,
                    "output_token_count": 200,
                },
            ),
            (
                "codex.tool_result",
                {"conversation.id": "codex-session", "tool_name": "spawn_agent"},
            ),
            (
                "codex.tool_result",
                {
                    "conversation.id": "codex-session",
                    "tool_name": "exec_command",
                    "vcs.repository.name": "upstream-repo",
                    "arguments": '{"cmd":"git status","workdir":"/work/backend"}',
                },
            ),
        ],
        label=label,
    )
    st.ingest_telemetry(sensor, "logs", new_id(), codex, 4)
    # A stale event delivered today belongs in its original time window.
    old = cost_payload(
        service,
        now - timedelta(days=2),
        [
            (
                prefix + "api_request",
                {
                    **common,
                    "request_id": "old",
                    "cost_usd": "1",
                    "input_tokens": 10,
                    "output_tokens": 20,
                },
            ),
        ],
        label=label,
    )
    st.ingest_telemetry(sensor, "logs", new_id(), old, 1)
    unknown = cost_payload(
        "codex-cli",
        now - timedelta(minutes=3),
        [
            (
                "codex.sse_event",
                {
                    "event.kind": "response.completed",
                    "model": "custom-model",
                    "input_token_count": 100,
                    "output_token_count": 10,
                },
            ),
        ],
        label=label,
    )
    st.ingest_telemetry(sensor, "logs", new_id(), unknown, 1)
    st.ingest_telemetry(
        sensor, "metrics", new_id(), payload("metrics", "codex-cli", 10), 10
    )
    st.ingest_telemetry(
        sensor, "traces", new_id(), payload("traces", "claude-code", 10), 10
    )
    assert client.get("/api/v1/costs/agents").json()["processing"]["pending_exports"] > 0
    assert process_pending(st)["failed"] == 0
    response = client.get("/api/v1/costs/agents")
    assert response.status_code == 200, response.text
    assert "PRIVATE-PROMPT" not in response.text
    assert "account@example.com" not in response.text
    data = response.json()
    for options in data["available_filters"].values():
        assert options == sorted(options)
    summary = data["summary"]
    assert summary["calls"] == 4
    assert summary["tokens"] == 5610
    assert summary["priced_calls"] == 3 and summary["unpriced_calls"] == 1
    assert summary["cost_usd"] == pytest.approx(0.38985)
    for key in ("series", "by_user", "by_model", "by_project", "by_activity"):
        assert sum(row["calls"] for row in data[key]) == 4
        assert sum(row["cost_usd"] or 0 for row in data[key]) == pytest.approx(
            summary["cost_usd"]
        )
    assert {row["name"] for row in data["by_activity"]} == {
        "Coding",
        "Delegation",
        "Unattributed",
    }
    assert {row["name"] for row in data["by_project"]} == {
        "console",
        "backend",
        "Unattributed",
    }
    for dimension, value in {
        "user": "alice",
        "model": "claude-sonnet-5",
        "project": "console",
        "activity": "Coding",
    }.items():
        filtered = client.get("/api/v1/costs/agents", params={dimension: value}).json()
        assert filtered["summary"]["calls"] == 2
        assert filtered["summary"]["cost_usd"] == 0.375
    assert (
        client.get("/api/v1/costs/agents", params={"model": "custom-model"}).json()[
            "summary"
        ]["cost_usd"]
        is None
    )
    for window, buckets in (("7d", 8), ("30d", 31)):
        longer = client.get("/api/v1/costs/agents", params={"range": window}).json()
        assert longer["summary"]["calls"] == 5
        assert longer["summary"]["cost_usd"] == pytest.approx(1.38985)
        assert len(longer["series"]) == buckets


@pytest.mark.parametrize("dashboard", ["before_partitions"], indirect=True)
def test_agent_cost_projection_upgrade_and_indexed_reads(dashboard):
    st, _, client, sensor, _, _ = dashboard
    st.execute("DROP TABLE agent_cost_records")
    st.execute(
        "ALTER TABLE telemetry_exports DROP COLUMN costs_processed_at, DROP COLUMN costs_retry_at, DROP COLUMN costs_reattribute"
    )
    st.execute("DELETE FROM schema_migrations WHERE version IN (19,23)")
    now = st.scalar("SELECT now()")
    from psycopg.types.json import Jsonb

    # Seed an export from the old receiver without invoking the new partition
    # provisioning and identity protocol before migration 0050 exists.
    st.execute("""INSERT INTO telemetry_exports
        (id,tenant_id,sensor_id,signal,batch_id,payload_sha256,record_count,payload)
        VALUES ($1,$2,$3,'logs',$4,'legacy',1,$5)""",
        new_id(), sensor["tenant_id"], sensor["id"], new_id(), Jsonb(cost_payload(
            "claude-code",
            now - timedelta(minutes=5),
            [("claude_code.api_request", {"cost_usd": "0.5"})],
        )),
    )
    assert st.migrate() == [
        "0019_agent_cost_usage.sql", "0023_agent_cost_project_folders.sql",
        *sorted(path.name for path in (Path(__file__).parents[1] / "src/openaidr/server/migrations").glob("*.sql")
                if int(path.name.split("_")[0]) >= 50 and path.name not in ("0071_sensor_policy_delivery.sql", "0074_sensor_health.sql", "0078_dashboard_role_tags.sql", "0082_device_identity.sql", "0089_endpoint_signed_in_user.sql")),
    ]
    assert st.migrate() == []
    assert process_pending(st) == {"exports": 1, "failed": 0}
    # The read path must work after the raw payload is archived.
    st.execute("UPDATE telemetry_exports SET payload='{}'::jsonb")
    st.execute("""INSERT INTO agent_cost_records
        SELECT tenant_id,md5(g.n::text),NULL,export_record,happened_at-interval '60 days',
               session_key,explicit_context,context_key,is_prompt,is_usage,user_name,model,
               direct_project,direct_activity,project,activity,cost_usd,price_source,price_date,
               tokens,input_tokens,output_tokens,cache_read_tokens,cache_write_tokens,demo
        FROM agent_cost_records CROSS JOIN generate_series(1,5000) g(n)""")
    st.execute("ANALYZE agent_cost_records")
    plan = st.many(
        """EXPLAIN SELECT sum(cost_usd) FROM agent_cost_records
        WHERE tenant_id=$1 AND is_usage AND happened_at>=$2 AND happened_at<$3""",
        sensor["tenant_id"],
        now - timedelta(days=1),
        now,
    )
    assert "agent_cost_records_time_idx" in "\n".join(row["QUERY PLAN"] for row in plan)
    data = client.get("/api/v1/costs/agents").json()
    assert data["summary"]["calls"] == 1 and data["summary"]["cost_usd"] == 0.5
    assert data["processing"]["pending_exports"] == 0


def test_agent_cost_projection_late_context_and_failed_export_recovery(dashboard):
    st, _, client, sensor, _, remote = dashboard
    now = st.scalar("SELECT now()")

    def send(device, minutes, name, attrs):
        data = cost_payload(
            "claude-code", now - timedelta(minutes=minutes), [(name, attrs)]
        )
        st.ingest_telemetry(device, "logs", new_id(), data, 1)
        return data

    call = send(
        sensor,
        10,
        "claude_code.api_request",
        {"session.id": "late", "cost_usd": "0.75"},
    )
    assert process_pending(st)["exports"] == 1
    first = client.get("/api/v1/costs/agents").json()
    assert first["by_activity"][0]["name"] == "Unattributed"
    # Tool metadata alone cannot establish an implicit prompt boundary.
    send(
        sensor,
        9,
        "claude_code.tool_result",
        {"session.id": "late", "tool_name": "Edit", "cwd": "/project"},
    )
    process_pending(st)
    assert (
        client.get("/api/v1/costs/agents").json()["by_project"][0]["name"]
        == "Unattributed"
    )
    send(sensor, 11, "claude_code.user_prompt", {"session.id": "late"})
    process_pending(st)
    attributed = client.get("/api/v1/costs/agents").json()
    assert attributed["by_project"][0]["name"] == "project"
    assert attributed["by_activity"][0]["name"] == "Coding"
    # A late intermediate prompt splits the prior context without changing cost.
    send(sensor, 9.5, "claude_code.user_prompt", {"session.id": "late"})
    process_pending(st)
    split = client.get("/api/v1/costs/agents").json()
    assert split["by_project"][0]["name"] == "Unattributed"
    assert split["summary"] == attributed["summary"]
    # Replayed deliveries and concurrent workers remain idempotent.
    for _ in range(8):
        st.ingest_telemetry(sensor, "logs", new_id(), call, 1)
    st.ingest_telemetry(remote, "logs", new_id(), call, 1)
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: process_pending(st), range(3)))
    assert sum(result["failed"] for result in results) == 0
    assert client.get("/api/v1/costs/agents").json()["summary"]["cost_usd"] == 0.75
    assert st.scalar("SELECT count(*) FROM agent_cost_records WHERE is_usage") == 2
    # Rehearse an interrupted projection with an invalid retained payload.
    batch = new_id()
    st.ingest_telemetry(sensor, "logs", batch, call, 1)
    st.execute(
        "UPDATE telemetry_exports SET payload='[]'::jsonb WHERE batch_id=$1", batch
    )
    assert process_pending(st) == {"exports": 0, "failed": 1}
    assert process_pending(st) == {"exports": 0, "failed": 0}
    assert (
        client.get("/api/v1/costs/agents").json()["processing"]["pending_exports"] == 1
    )
    from psycopg.types.json import Jsonb

    st.execute(
        "UPDATE telemetry_exports SET payload=$2,costs_retry_at=NULL WHERE batch_id=$1",
        batch,
        Jsonb(call),
    )
    assert process_pending(st) == {"exports": 1, "failed": 0}
    assert client.get("/api/v1/costs/agents").json()["summary"]["calls"] == 1
    metadata = st.scalar(
        "SELECT jsonb_agg(to_jsonb(r))::text FROM agent_cost_records r"
    )
    assert "PRIVATE-PROMPT" not in metadata
    assert "tool_name" not in metadata


def test_agent_cost_folder_upgrade_preserves_usage_and_tenant_scope(dashboard, monkeypatch):
    from openaidr.server import agent_costs

    st, _, client, sensor, _, remote = dashboard
    now = st.scalar("SELECT now()") - timedelta(minutes=5)
    usage = {
        "conversation.id": "shared-session",
        "event.kind": "response.completed",
        "model": "gpt-6-astra",
        "input_token_count": 100,
        "output_token_count": 20,
    }
    # Rehearse retained history from the parser that kept cwd paths and missed workdir.
    with monkeypatch.context() as old:
        old.setattr(agent_costs, "project", lambda attrs: attrs.get("cwd", ""))
        for device, folder in ((sensor, "openaidr"), (remote, "other")):
            directory = (
                {"workdir": "/Users/alice/openaidr/.worktree/costs/dashboard"}
                if folder == "openaidr" else {"cwd": "/work/other"}
            )
            events = [
                ("codex.user_prompt", {"conversation.id": "shared-session"}),
                ("codex.sse_event", usage),
                ("codex.tool_result", {
                    "conversation.id": "shared-session", "tool_name": "exec_command",
                    "arguments": json.dumps({"cmd": "git status", **directory}),
                }),
            ]
            for offset, event in enumerate(events):
                data = cost_payload("codex-cli", now + timedelta(seconds=offset), [event])
                st.ingest_telemetry(device, "logs", new_id(), data, 1)
            # A duplicate export must not take ownership of the original tool record.
            st.ingest_telemetry(device, "logs", new_id(), data, 1)
        assert process_pending(st) == {"exports": 8, "failed": 0}
    st.execute("UPDATE agent_cost_records SET cost_usd=99,price_date='2000-01-01' WHERE is_usage")
    snapshot_sql = """SELECT tenant_id,event_key,cost_usd,price_source,price_date,tokens,
        input_tokens,output_tokens,cache_read_tokens,cache_write_tokens
        FROM agent_cost_records WHERE is_usage ORDER BY tenant_id,event_key"""
    before = st.many(snapshot_sql)
    summary = client.get("/api/v1/costs/agents").json()["summary"]
    assert client.get("/api/v1/costs/agents").json()["by_project"][0]["name"] == "Unattributed"
    assert st.scalar("SELECT project FROM agent_cost_records WHERE tenant_id=$1 AND is_usage", remote["tenant_id"]) == "/work/other"
    # Archived usage still inherits refreshed tool metadata from its persisted context.
    st.execute("""UPDATE telemetry_exports e SET payload='{}'::jsonb
        WHERE e.tenant_id=$1 AND EXISTS (SELECT 1 FROM agent_cost_records r
        WHERE r.tenant_id=e.tenant_id AND r.export_id=e.id AND r.is_usage)""", sensor["tenant_id"])
    st.execute("ALTER TABLE telemetry_exports DROP COLUMN costs_reattribute")
    st.execute("DELETE FROM schema_migrations WHERE version=23")
    assert st.migrate() == ["0023_agent_cost_project_folders.sql"]
    assert st.migrate() == []
    assert client.get("/api/v1/costs/agents").json()["processing"]["pending_exports"] == 2
    assert process_pending(st, sensor["tenant_id"]) == {"exports": 2, "failed": 0}
    attributed = client.get("/api/v1/costs/agents", params={"project": "dashboard"}).json()
    assert attributed["summary"] == summary
    assert attributed["available_filters"]["project"] == ["dashboard"]
    assert attributed["by_project"][0]["name"] == "dashboard"
    assert attributed["processing"]["pending_exports"] == 0
    assert st.scalar("SELECT project FROM agent_cost_records WHERE tenant_id=$1 AND is_usage", remote["tenant_id"]) == "/work/other"
    assert process_pending(st, remote["tenant_id"]) == {"exports": 3, "failed": 0}
    assert st.scalar("SELECT project FROM agent_cost_records WHERE tenant_id=$1 AND is_usage", remote["tenant_id"]) == "other"
    assert st.many(snapshot_sql) == before
    assert not st.scalar("SELECT count(*) FROM telemetry_exports WHERE costs_reattribute")
    assert process_pending(st) == {"exports": 0, "failed": 0}


def test_cowork_project_attribution_does_not_use_code_sessions(dashboard):
    from openaidr.server import agent_projects

    st, _, _, sensor, _, _ = dashboard
    when = st.scalar("SELECT now()") - timedelta(minutes=10)
    st.ingest_batch(sensor, [{
        "id": new_id(), "time": when.isoformat(), "kind": "session.start",
        "agent": {"product": "claude-code"},
        "session": {"id": "shared-session", "cwd": "/work/code-project"},
    }])
    for service in ("claude-code", "cowork"):
        packet = cost_payload(service, when + timedelta(seconds=1), [
            ("api_request", {"session.id": "shared-session", "request_id": "shared-request",
             "model": "claude-opus-5-5", "input_tokens": 100, "output_tokens": 20, "cost_usd": ".01"}),
        ])
        st.ingest_telemetry(sensor, "logs", new_id(), packet, 1)
    assert process_pending(st)["failed"] == 0
    agent_projects.process_pending(st)
    assert st.scalar("SELECT count(*) FROM agent_project_sessions WHERE pending") == 0
    assert {row["project"]: row["calls"] for row in st.many(
        "SELECT project,count(*) AS calls FROM agent_cost_records WHERE is_usage GROUP BY project"
    )} == {"code-project": 1, "Unattributed": 1}
    assert {row["product"] for row in st.many("SELECT product FROM agent_project_sessions")} == {
        "claude-code", "cowork",
    }


def test_project_metadata_heartbeat_repairs_history_without_replaying_usage(dashboard, tmp_path, monkeypatch):
    from openaidr.server import agent_projects
    from openaidr.sensor import integrations
    from openaidr.sensor.config import Config as SensorConfig
    from openaidr.sensor.runtime import Sensor

    st, _, client, device, token, remote = dashboard
    when = st.scalar("SELECT now()") - timedelta(minutes=30)
    for sensor, sid, minute, extra in [
        (device, "parent", -1, {}), (device, "parent", 1, {}),
        (device, "parent", 11, {}), (device, "child", 2, {}),
        (device, "parent", 21, {}),
        (device, "child", 12, {"project.name": "explicit"}),
        (remote, "parent", 1, {}),
        *[(device, f"!unsupported-{index}", 1, {}) for index in range(4)],
    ]:
        st.ingest_telemetry(sensor, "logs", new_id(), cost_payload("codex-app-server",
            when + timedelta(minutes=minute), [("codex.sse_event", {
                "conversation.id": sid, "event.kind": "response.completed", "model": "gpt-6-astra",
                "input_token_count": 100, "output_token_count": 20, **extra,
            })]), 1)
    process_pending(st)
    while agent_projects.process_pending(st):
        pass
    snapshot_sql = """SELECT tenant_id,event_key,happened_at,tokens,input_tokens,output_tokens,
        cache_read_tokens,cache_write_tokens,cost_usd,price_source,price_date
        FROM agent_cost_records WHERE is_usage ORDER BY tenant_id,event_key"""
    before = st.many(snapshot_sql)
    total = client.get("/api/v1/costs/agents").json()["summary"]
    event_count = st.scalar("SELECT count(*) FROM events")
    home = tmp_path / "extra-account"
    folder = home / "sessions/2026/10/10"
    folder.mkdir(parents=True)
    for sid, records in {
        "parent": [
            {"type": "session_meta", "timestamp": when.isoformat(), "payload": {"id": "parent", "cwd": "/work/old", "instructions": "PRIVATE"}},
            {"type": "turn_context", "timestamp": (when + timedelta(minutes=10)).isoformat(), "payload": {"cwd": "/work/new"}},
            {"type": "turn_context", "timestamp": (when + timedelta(minutes=20)).isoformat(), "payload": {"cwd": "/work/password=hunter22"}},
        ],
        "child": [{"type": "session_meta", "timestamp": (when + timedelta(minutes=1)).isoformat(), "payload": {
            "id": "child", "source": {"subagent": {"thread_spawn": {"parent_thread_id": "parent"}}},
        }}],
    }.items():
        (folder / f"rollout-date-{sid}.jsonl").write_text("".join(json.dumps(row) + "\n" for row in records))
    monkeypatch.setattr(integrations, "configured_paths", lambda config, agent: [tmp_path / "default-account/config.toml"])
    config = SensorConfig(tmp_path / "sensor.yaml", server_url="http://localhost", sensor_id=str(device["id"]),
        tenant_id=str(device["tenant_id"]), sensor_token=token, data_dir=str(tmp_path / "data"),
        telemetry={"enabled": False}, inventory={"enabled": False}, collectors={"cowork": {"enabled": False}})
    sensor = Sensor(config)
    (tmp_path / "data/hook-health-directories.json").write_text(json.dumps([str(home / "openaidr-hook-health")]))
    sent = []

    def post(path, body):
        sent.append(body)
        response = client.post("/ingest/v1/" + path, json=body, headers={"Authorization": "Bearer " + token})
        assert response.status_code == 200, response.text
        return response.json()

    sensor.client.post = post
    try:
        assert sensor.collectors == []
        sensor.heartbeat_once()
        assert not sensor.heartbeat_error
        assert sensor.project_metadata.requests, sent
        for _ in range(50):
            sensor.project_metadata.step()
        sensor.heartbeat_once()
        assert not sensor.heartbeat_error
        assert "PRIVATE" not in json.dumps(sent)
        assert "hunter22" not in json.dumps(sent)
        count = st.scalar("SELECT count(*) FROM agent_project_evidence")
        assert count == 4
        post("heartbeat", sent[-1])  # Lost response can cause an identical delivery.
        assert st.scalar("SELECT count(*) FROM agent_project_evidence") == count
        while agent_projects.process_pending(st):
            pass
        result = client.get("/api/v1/costs/agents").json()
        assert result["summary"] == total
        assert {row["name"]: row["calls"] for row in result["by_project"]} == {
            "old": 2, "new": 1, "explicit": 1, "Unattributed": 6,
        }
        assert st.many(snapshot_sql) == before
        assert st.scalar("SELECT count(*) FROM events") == event_count
        assert st.scalar("SELECT project FROM agent_cost_records WHERE tenant_id=$1 AND is_usage", remote["tenant_id"]) == "Unattributed"
        # A claimed sensor ID cannot direct metadata at the other tenant/device.
        post("heartbeat", {"sensor_id": str(remote["id"]), "project_metadata": {
            "version": 1, "observations": [{"product": "codex-cli", "session_id": "remote-only",
                "time": when.isoformat(), "cwd": "/wrong"}],
        }})
        assert st.scalar("SELECT count(*) FROM agent_project_evidence") == count
        st.update_sensor(device["tenant_id"], device["id"], disabled=True)
        reply = post("heartbeat", sent[-1])
        assert "project_metadata" not in reply
    finally:
        sensor.client.close()
        sensor.spool.close()


def test_agent_project_directories_children_and_late_changes(dashboard):
    from openaidr.server import agent_projects
    from openaidr.server.agent_cost_summaries import overview, rebuild_pending

    st, _, _, device, _, remote = dashboard
    now = st.scalar("SELECT now()") - timedelta(minutes=30)

    def event(sensor, session, minutes, product="codex-cli"):
        st.ingest_batch(sensor, [{"id": new_id(), "time": (now + timedelta(minutes=minutes)).isoformat(),
            "kind": "session.start", "agent": {"product": product}, "session": session}])

    def call(sensor, session, minutes, **extra):
        st.ingest_telemetry(sensor, "logs", new_id(), cost_payload("codex-app-server",
            now + timedelta(minutes=minutes), [("codex.sse_event", {
                "conversation.id": session, "event.kind": "response.completed", "model": "gpt-6-astra",
                "input_token_count": 100, "output_token_count": 20, **extra,
            })]), 1)

    event(device, {"id": "parent", "cwd": "/work/alpha/"}, 0)
    event(device, {"id": "child", "parent_id": "parent"}, 1)
    event(device, {"id": "grandchild", "parent_id": "child"}, 2)
    event(remote, {"id": "parent", "cwd": "/work/foreign"}, 0)
    peer = st.one("SELECT * FROM sensors WHERE tenant_id=$1 AND hostname='old-device'", device["tenant_id"])
    event(peer, {"id": "parent", "cwd": "/work/peer"}, 0)
    event(device, {"id": "parent", "cwd": "/work/claude"}, 0, "claude-code")
    event(device, {"id": "cycle-a", "parent_id": "cycle-b"}, 0)
    event(device, {"id": "cycle-b", "parent_id": "cycle-a"}, 0)
    for sensor, sid, minute, attrs in [
        (device, "child", 3, {}), (device, "grandchild", 7, {}),
        (device, "child", 8, {"project.name": "Explicit"}),
        (remote, "child", 3, {}), (device, "unlinked", 3, {}),
        (device, "cycle-a", 3, {}), (device, "parent", -1, {}),
    ]:
        call(sensor, sid, minute, **attrs)
    barrier = Barrier(2)

    def drain():
        barrier.wait()
        process_pending(st)
        while agent_projects.process_pending(st):
            pass

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(drain) for _ in range(2)]
        for future in futures:
            future.result(timeout=20)
    before = overview(st, device["tenant_id"])
    assert {r["name"]: r["calls"] for r in before["by_project"]} == {
        "alpha": 2, "Explicit": 1, "Unattributed": 3,
    }
    assert overview(st, remote["tenant_id"])["by_project"][0]["name"] == "Unattributed"
    rebuild_pending(st)
    # Late metadata changes only calls at or after the observed directory change.
    event(device, {"id": "parent", "cwd": r"C:\work\beta"}, 5)
    while agent_projects.process_pending(st):
        pass
    after = overview(st, device["tenant_id"])
    assert after["summary"] == before["summary"]
    assert {r["name"]: r["calls"] for r in after["by_project"]} == {
        "alpha": 1, "beta": 1, "Explicit": 1, "Unattributed": 3,
    }
    rebuild_pending(st)
    assert overview(st, device["tenant_id"])["by_project"] == after["by_project"]
    # Own directory evidence wins over a parent, and starts at its observation.
    event(device, {"id": "child", "cwd": "/work/repo/.worktree/task"}, 6)
    while agent_projects.process_pending(st):
        pass
    assert {r["name"]: r["calls"] for r in overview(st, device["tenant_id"])["by_project"]} == {
        "alpha": 1, "task": 1, "Explicit": 1, "Unattributed": 3,
    }


def test_agent_project_backfill_archived_usage_and_ambiguous_evidence(dashboard, monkeypatch):
    from openaidr.server import agent_projects

    st, _, client, device, _, _ = dashboard
    now = st.scalar("SELECT now()") - timedelta(minutes=10)
    # Simulate an old sensor and server that recorded cwd but did not project it.
    with monkeypatch.context() as old:
        old.setattr(agent_projects, "observe", lambda *args: None)
        st.ingest_batch(device, [{"id": new_id(), "time": now.isoformat(), "kind": "session.start",
            "agent": {"product": "claude-code"}, "session": {"id": "legacy", "cwd": "/work/legacy"}}])
    st.ingest_telemetry(device, "logs", new_id(), cost_payload("claude-code", now + timedelta(minutes=1), [
        ("claude_code.api_request", {"session.id": "legacy", "cost_usd": "0.5"}),
    ]), 1)
    process_pending(st)
    st.execute("UPDATE telemetry_exports SET payload='{}'::jsonb")
    st.execute("DROP TABLE agent_project_sessions,agent_project_evidence")
    st.execute("ALTER TABLE agent_cost_records DROP COLUMN session_project")
    st.execute("DROP INDEX agent_cost_records_session_usage_idx")
    st.execute("DELETE FROM schema_migrations WHERE version=68")
    assert st.migrate() == ["0068_agent_project_evidence.sql"]
    assert st.migrate() == []
    snapshot = st.one("SELECT cost_usd,tokens,price_source,price_date FROM agent_cost_records WHERE is_usage")
    while agent_projects.process_pending(st):
        pass
    assert client.get("/api/v1/costs/agents").json()["by_project"][0]["name"] == "legacy"
    # Equally timed conflicting observations must not choose an arbitrary project.
    st.ingest_batch(device, [{"id": new_id(), "time": now.isoformat(), "kind": "session.start",
        "agent": {"product": "claude-code"}, "session": {"id": "legacy", "cwd": "/work/conflict"}}])
    while agent_projects.process_pending(st):
        pass
    assert client.get("/api/v1/costs/agents").json()["by_project"][0]["name"] == "Unattributed"
    assert st.one("SELECT cost_usd,tokens,price_source,price_date FROM agent_cost_records WHERE is_usage") == snapshot


def test_agent_project_backfill_uses_snapshot_only_without_retained_directory_evidence(dashboard, monkeypatch):
    from openaidr.server import agent_projects

    st, _, client, device, _, _ = dashboard
    now = st.scalar("SELECT now()") - timedelta(minutes=10)
    with monkeypatch.context() as old:
        old.setattr(agent_projects, "observe", lambda *args: None)
        for sid, minute, cwd in [("late", 2, "/work/new"), ("late", 0, "/work/old"),
                                 ("snapshot", 2, "/work/snapshot")]:
            st.ingest_batch(device, [{"id": new_id(), "time": (now + timedelta(minutes=minute)).isoformat(),
                "kind": "session.start", "agent": {"product": "codex-cli"},
                "session": {"id": sid, "cwd": cwd}}])
    # The old session snapshot reflects arrival order, not event time.
    assert st.scalar("SELECT cwd FROM agent_sessions WHERE external_id='late'") == "/work/old"
    st.execute("DELETE FROM events WHERE body#>>'{session,id}'='snapshot'")
    for sid, minute in [("late", 1), ("late", 3), ("snapshot", 1), ("snapshot", 3)]:
        st.ingest_telemetry(device, "logs", new_id(), cost_payload("codex-app-server",
            now + timedelta(minutes=minute), [("codex.sse_event", {
                "conversation.id": sid, "event.kind": "response.completed", "model": "gpt-6-astra",
                "input_token_count": 100, "output_token_count": 20,
            })]), 1)
    process_pending(st)
    st.execute("UPDATE agent_project_sessions SET backfill=true")
    while agent_projects.process_pending(st):
        pass
    assert {r["name"]: r["calls"] for r in client.get("/api/v1/costs/agents").json()["by_project"]} == {
        "old": 1, "new": 1, "snapshot": 1, "Unattributed": 1,
    }


def test_agent_cost_worker_processes_new_usage_for_bound_tenant(dashboard):
    import time

    st, cfg, _, sensor, _, remote = dashboard
    cfg.cost_processing = True
    with TestClient(create_app(cfg, st)):
        now = st.scalar("SELECT now()")
        data = cost_payload(
            "claude-code",
            now - timedelta(minutes=1),
            [
                ("claude_code.api_request", {"cost_usd": "0.25"}),
            ],
        )
        for device in (sensor, remote):
            st.ingest_telemetry(device, "logs", new_id(), data, 1)
        deadline = time.monotonic() + 10
        while (
            not st.scalar("SELECT count(*) FROM agent_cost_records")
            and time.monotonic() < deadline
        ):
            time.sleep(0.02)
        assert (
            st.scalar(
                "SELECT count(*) FROM agent_cost_records WHERE tenant_id=$1",
                sensor["tenant_id"],
            )
            == 1
        )
        assert (
            st.scalar(
                "SELECT count(*) FROM agent_cost_records WHERE tenant_id=$1",
                remote["tenant_id"],
            )
            == 0
        )
        assert (
            st.scalar(
                "SELECT count(*) FROM telemetry_exports WHERE tenant_id=$1 AND costs_processed_at IS NULL",
                remote["tenant_id"],
            )
            == 1
        )


@pytest.mark.parametrize(("model", "tier", "quote"), [
    ("gpt-6-astra", "default", .002),
    ("codex-auto-review", "default", 0),
    ("gpt-6-astra", "ultrafast", .012),
    ("gpt-6.1-sol", "ultrafast", .0024),
    ("gpt-6-sol", "fast", .0008),
    ("gpt-5.6-sol", "flex", .0004),
    ("gpt-5.6-luna", "priority", .000088),
])
def test_agent_cost_repricing_requires_explicit_tenant_command(
    dashboard, monkeypatch, capsys, model, tier, quote
):
    st, _, client, sensor, _, remote = dashboard
    now = st.scalar("SELECT now()")
    usage = cost_payload(
        "codex-cli",
        now - timedelta(minutes=1),
        [
            (
                "codex.sse_event",
                {
                    "event.kind": "response.completed",
                    "model": model,
                    "service_tier": tier,
                    "auth_mode": "Chatgpt",
                    "input_token_count": 100,
                    "output_token_count": 20,
                },
            ),
            ("codex.sse_event", {
                "event.kind": "response.completed", "model": model,
                "service_tier": tier,
                "auth_mode": "Chatgpt", "cost_usd": "0.25",
                "input_token_count": 100, "output_token_count": 20,
            }),
        ],
    )
    for device in (sensor, remote):
        st.ingest_telemetry(device, "logs", new_id(), usage, 2)
    process_pending(st)
    expected = client.get("/api/v1/costs/agents").json()["summary"]
    assert expected["priced_calls"] == 2
    assert expected["cost_usd"] == pytest.approx(0.25 + quote)
    old_cost = 99 if model == "gpt-6-astra" and tier == "default" else None
    st.execute(
        "UPDATE agent_cost_records SET price_date='2026-09-30',cost_usd=$1,price_source=$2 "
        "WHERE is_usage AND price_source<>'reported'",
        old_cost, "unpriced" if old_cost is None else "calculated",
    )
    from openaidr.server.agent_cost_summaries import queue_rebuild

    for device in (sensor, remote):
        queue_rebuild(st, device["tenant_id"])
    assert process_pending(st)["exports"] == 0
    assert client.get("/api/v1/costs/agents").json()["summary"]["cost_usd"] == (old_cost or 0) + 0.25
    # An explicit reprice also takes precedence over a pending metadata refresh.
    st.execute("UPDATE telemetry_exports SET costs_processed_at=NULL,costs_reattribute=true")
    monkeypatch.setenv("OPENAIDR_DATABASE_URL", st.url)
    monkeypatch.delenv("OPENAIDR_TENANT_ID", raising=False)
    assert main(["telemetry", "costs", "--reprice"]) == 1
    assert "TENANT_ID is required" in capsys.readouterr().err
    monkeypatch.setenv("OPENAIDR_TENANT_ID", sensor["tenant_id"])
    assert main(["telemetry", "costs", "--reprice", "--limit", "1"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "exports": 1, "failed": 0, "pending_summary_hours": 0, "pending_project_sessions": 0,
    }
    assert client.get("/api/v1/costs/agents").json()["summary"] == expected
    assert client.get("/api/v1/costs/agents/summary").json()["summary"] == expected
    assert (
        st.scalar(
            "SELECT cost_usd FROM agent_cost_records WHERE tenant_id=$1 AND is_usage AND price_source<>'reported'",
            remote["tenant_id"],
        )
        == old_cost
    )
    assert st.scalar("SELECT count(*) FROM agent_cost_records WHERE price_source='reported' AND cost_usd=0.25") == 2
    assert main(["telemetry", "costs", "--reprice"]) == 0
    assert json.loads(capsys.readouterr().out)["exports"] == 0


def test_retired_detection_cost_route_preserves_auth_boundaries(dashboard):
    st, cfg, client, sensor, _, remote = dashboard
    endpoint = "/api/v1/costs/detections"
    assert client.get(endpoint).status_code == 410
    with TestClient(create_app(cfg, st)) as anonymous:
        assert anonymous.get(endpoint).status_code == 401
        for device, role in ((remote, "viewer"), (sensor, "analyst")):
            actor = st.create_user(device["tenant_id"], role + "@costs.example.invalid", role, "unused", role)
            anonymous.cookies.set(CONSOLE_COOKIE, st.create_session(actor["id"], device["tenant_id"]))
            assert anonymous.get(endpoint).status_code == 403


def test_agent_costs_auth_tenant_boundaries_and_validation(dashboard):
    st, cfg, client, sensor, _, remote = dashboard
    now = st.scalar("SELECT now()")
    logs = cost_payload(
        "claude-code",
        now - timedelta(minutes=5),
        [
            ("claude_code.api_request", {"cost_usd": "999", "model": "private-model"}),
        ],
    )
    st.ingest_telemetry(remote, "logs", new_id(), logs, 1)
    process_pending(st)
    assert client.get("/api/v1/costs/agents").json()["summary"]["calls"] == 0
    with TestClient(create_app(cfg, st)) as anonymous:
        assert anonymous.get("/api/v1/costs/agents").status_code == 401
        foreign = st.create_user(
            remote["tenant_id"], "foreign@example.com", "Foreign", "unused", "viewer"
        )
        anonymous.cookies.set(
            CONSOLE_COOKIE, st.create_session(foreign["id"], remote["tenant_id"])
        )
        assert anonymous.get("/api/v1/costs/agents").status_code == 403
        cfg.tenant_id = ""
        other = anonymous.get("/api/v1/costs/agents")
        assert other.status_code == 200
        assert other.json()["summary"]["cost_usd"] == 999
    own = st.get_user_by_email("demo@example.com")
    st.update_user(sensor["tenant_id"], own["id"], role="viewer")
    assert client.get("/api/v1/costs/agents").status_code == 200
    for params in ({"range": "all"}, {"user": "x" * 1025}):
        assert client.get("/api/v1/costs/agents", params=params).status_code == 400
    owner, repository = "team" * 150, "repository" * 60
    username = "user" * 300
    st.execute("UPDATE sensors SET username=$1 WHERE id=$2", username, sensor["id"])
    st.ingest_telemetry(
        sensor,
        "logs",
        new_id(),
        cost_payload(
            "claude-code",
            now - timedelta(minutes=1),
            [
                (
                    "claude_code.api_request",
                    {
                        "cost_usd": "0.5",
                        "vcs.owner.name": owner,
                        "vcs.repository.name": repository,
                    },
                ),
            ],
        ),
        1,
    )
    process_pending(st)
    options = client.get("/api/v1/costs/agents").json()["available_filters"]
    for dimension, expected in {
        "project": f"{owner}/{repository}",
        "user": username,
    }.items():
        label = options[dimension][0]
        filtered = client.get("/api/v1/costs/agents", params={dimension: label})
        assert filtered.status_code == 200, filtered.text
        assert label == expected[:1024]
        assert filtered.json()["summary"]["cost_usd"] == 0.5


def test_heartbeat_queue_omission_and_validation(dashboard):
    st, _, client, sensor, token, _ = dashboard
    headers = {"Authorization": "Bearer " + token}
    for value in (-1, "five", True, 1.5, 9223372036854775808):
        assert (
            client.post(
                "/ingest/v1/heartbeat",
                json={"telemetry_queue_depth": value},
                headers=headers,
            ).status_code
            == 400
        )
    for body, expected in [
        ({"telemetry_queue_depth": 0}, 0),
        ({"telemetry_queue_depth": 9}, 9),
        ({}, None),
    ]:
        assert (
            client.post("/ingest/v1/heartbeat", json=body, headers=headers).status_code
            == 200
        )
        assert (
            st.scalar(
                "SELECT telemetry_queue_depth FROM sensor_activity WHERE sensor_id=$1", sensor["id"]
            )
            == expected
        )


def test_policy_delivery_requires_a_fresh_report_on_the_latest_heartbeat(dashboard):
    st, _, client, sensor, token, remote = dashboard
    headers = {"Authorization": "Bearer " + token}
    st.record_heartbeat(remote["id"], {"policy_delivery": "backend"})
    # Exercise each HTTP projection on every transition, without cached overview data.
    clock = [0]
    client.app.state.service.telemetry_cache.clock = lambda: clock[0]

    def assert_delivery(expected):
        clock[0] += 30
        for endpoint, collection in (
            ("/api/v1/sensors", "items"),
            ("/api/v1/sensors/health", "items"),
            ("/api/v1/telemetry/overview", "devices"),
            (f"/api/v1/sensors/{sensor['id']}", None),
        ):
            response = client.get(endpoint)
            assert response.status_code == 200, response.text
            rows = response.json()[collection] if collection else [response.json()]
            assert all(row["id"] != remote["id"] for row in rows)
            current = next(row for row in rows if row["id"] == sensor["id"])
            assert current["policy_delivery"] == expected
        assert st.get_sensor(remote["tenant_id"], remote["id"])["policy_delivery"] == "backend"

    assert_delivery(None)
    assert client.get(f"/api/v1/sensors/{remote['id']}").status_code == 404
    # Unknown fields from older or future clients remain valid heartbeats.
    for report in ({}, {"policy_delivery": None}, {"policy_delivery": "future"},
                   {"policy_delivery": ["backend"]}, {"policy_delivery": True}):
        response = client.post("/ingest/v1/heartbeat", json={
            "policy_delivery": "backend", "sensor_id": remote["id"],
        }, headers=headers)
        assert response.status_code == 200, response.text
        assert "policy" not in response.json()
        assert_delivery("backend")
        response = client.post("/ingest/v1/heartbeat", json=report, headers=headers)
        assert response.status_code == 200, response.text
        assert "rules" in response.json()["policy"]
        assert_delivery(None)

    st.record_heartbeat(sensor["id"], {"policy_delivery": "backend"})
    # An older backend leaves the new columns untouched during a rolling deploy.
    st.execute("UPDATE sensor_activity SET last_heartbeat_at=now() WHERE sensor_id=$1", sensor["id"])
    assert_delivery(None)
    st.record_heartbeat(sensor["id"], {"policy_delivery": "backend"})
    assert_delivery("backend")
    st.execute("""UPDATE sensor_activity
        SET last_heartbeat_at=now()-interval '91 seconds',
            policy_delivery_reported_at=now()-interval '91 seconds'
        WHERE sensor_id=$1""", sensor["id"])
    assert_delivery(None)

    # Previously queued compatibility commands remain deliverable and acknowledgeable.
    command = st.queue_command(sensor["tenant_id"], sensor["id"], "refresh_policy")
    response = client.post("/ingest/v1/heartbeat", json={"policy_delivery": "backend"}, headers=headers)
    assert response.status_code == 200, response.text
    assert any(row["id"] == command and row["type"] == "refresh_policy" for row in response.json()["commands"])
    assert client.post(f"/ingest/v1/commands/{command}/ack", json={"status": "applied"}, headers=headers).status_code == 204
    assert st.get_command(sensor["tenant_id"], sensor["id"], command)["status"] == "applied"


def test_sensor_metrics_validation_and_older_sensor_compatibility(dashboard):
    st, _, client, sensor, token, remote = dashboard
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    invalid = {
        "cpu_percent": [-1, True, "12", [], {}, float("nan"), float("inf"), 1000001, 10**400],
        "memory_rss_bytes": [-1, True, "12", 1.5, [], {}, 9223372036854775808],
    }
    for field, values in invalid.items():
        for value in values:
            response = client.post("/ingest/v1/heartbeat", content=json.dumps({field: value}), headers=headers)
            assert response.status_code == 400, response.text
    for values in [
        {"cpu_percent": 125.5, "memory_rss_bytes": 42 * 1024**2},
        {"cpu_percent": 0, "memory_rss_bytes": 0},
        {"cpu_percent": None, "memory_rss_bytes": None},
        {},
    ]:
        response = client.post("/ingest/v1/heartbeat", json={"sensor_id": remote["id"], **values}, headers=headers)
        assert response.status_code == 200, response.text
        latest = client.get(f"/api/v1/sensors/{sensor['id']}/metrics").json()["latest"]
        assert latest["cpu_percent"] == values.get("cpu_percent")
        assert latest["memory_rss_bytes"] == values.get("memory_rss_bytes")
    assert st.scalar("SELECT cpu_percent FROM sensor_activity WHERE sensor_id=$1", remote["id"]) is None
    assert st.scalar("SELECT count(*) FROM sensor_resource_samples WHERE sensor_id=$1", remote["id"]) == 0


def test_sensor_memory_peak_24h_samples_missing_zero_and_tenant_scope(dashboard):
    st, _, client, sensor, token, remote = dashboard
    path = "/api/v1/sensors/health"
    initial = client.get(path).json()["items"]
    assert all(row["max_memory_rss_bytes_24h"] is None for row in initial)
    older = next(row for row in initial if row["hostname"] == "old-device")
    disabled = next(row for row in initial if row["hostname"] == "disabled-device")
    deleted, _, _ = st.enroll_sensor({
        "enrollment_token": st.create_enrollment_token(sensor["tenant_id"])["token"],
        "hostname": "deleted-device",
    })
    response = client.post(
        "/ingest/v1/heartbeat", json={"memory_rss_bytes": 135_000_000},
        headers={"Authorization": "Bearer " + token},
    )
    assert response.status_code == 200, response.text
    now = st.scalar("SELECT now()")
    base = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    for sensor_id, when, memory in [
        (sensor["id"], base, 2_680_000_000),
        (sensor["id"], base + timedelta(minutes=1), 10_000_000),
        (sensor["id"], now - timedelta(hours=24, minutes=1), 8_000_000_000),
        (sensor["id"], now + timedelta(hours=1), 9_000_000_000),
        (older["id"], now - timedelta(hours=24, minutes=1), 4_000_000_000),
        (disabled["id"], now - timedelta(hours=23, minutes=59), 0),
        (disabled["id"], base, None),
        (remote["id"], base, 16_000_000_000),
        (deleted["id"], base, 32_000_000_000),
    ]:
        st.execute(
            "INSERT INTO sensor_resource_samples(sensor_id,sampled_at,memory_rss_bytes) VALUES($1,$2,$3)",
            sensor_id, when, memory,
        )
    st.delete_sensor(sensor["tenant_id"], deleted["id"])
    rows = {row["id"]: row for row in client.get(path).json()["items"]}
    assert len(rows) == 3
    current = rows[str(sensor["id"])]
    assert current["memory_rss_bytes"] == 135_000_000
    assert current["max_memory_rss_bytes_24h"] == 2_680_000_000
    assert rows[older["id"]]["max_memory_rss_bytes_24h"] is None
    assert rows[disabled["id"]]["max_memory_rss_bytes_24h"] == 0
    history = client.get(f"/api/v1/sensors/{sensor['id']}/metrics").json()
    assert max(row["memory_rss_bytes"] for row in history["samples"]) < current["max_memory_rss_bytes_24h"]
    st.execute("UPDATE sensor_activity SET last_heartbeat_at=now()-interval '10 minutes' WHERE sensor_id=$1", sensor["id"])
    offline = next(row for row in client.get(path).json()["items"] if row["id"] == str(sensor["id"]))
    assert offline["status"] == "offline"
    assert offline["max_memory_rss_bytes_24h"] == 2_680_000_000
    own = st.get_user_by_email("demo@example.com")
    st.update_user(sensor["tenant_id"], own["id"], role="viewer")
    assert client.get(path).status_code == 403
    st.update_user(sensor["tenant_id"], own["id"], roles=["it_admin"])
    assert client.get(path).status_code == 200
    client.cookies.clear()
    assert client.get(path).status_code == 401


def test_sensor_metrics_history_buckets_tenant_scope_and_retention(dashboard):
    from openaidr.server.sensor_metrics import prune

    st, _, client, sensor, token, remote = dashboard
    path = f"/api/v1/sensors/{sensor['id']}/metrics"
    assert client.get(path).json()["samples"] == []
    headers = {"Authorization": "Bearer " + token}
    for cpu in [10, 150]:
        response = client.post("/ingest/v1/heartbeat", json={"cpu_percent": cpu, "memory_rss_bytes": 8 * 1024**2}, headers=headers)
        assert response.status_code == 200, response.text
    latest = st.one("SELECT * FROM sensor_activity WHERE sensor_id=$1", sensor["id"])
    last_sample = st.one("SELECT * FROM sensor_resource_samples WHERE sensor_id=$1 ORDER BY sampled_at DESC LIMIT 1", sensor["id"])
    assert last_sample["sampled_at"] == latest["last_heartbeat_at"].replace(second=0, microsecond=0)
    assert last_sample["cpu_percent"] == 150

    base = st.scalar("SELECT date_trunc('hour',now()) - interval '1 hour'")
    for sensor_id, when, cpu, memory in [
        (sensor["id"], base, 10, 2 * 1024**2),
        (sensor["id"], base + timedelta(minutes=1), 30, 4 * 1024**2),
        (sensor["id"], base + timedelta(minutes=10), None, 0),
        (sensor["id"], base - timedelta(days=31), 999, 999),
        (remote["id"], base, 888, 888),
        (remote["id"], base - timedelta(days=31), 888, 888),
    ]:
        st.execute("INSERT INTO sensor_resource_samples(sensor_id,sampled_at,cpu_percent,memory_rss_bytes) VALUES($1,$2,$3,$4)", sensor_id, when, cpu, memory)
    result = client.get(path).json()
    assert result["bucket_seconds"] == 300
    assert result["samples"][0] == {"time": base.isoformat().replace("+00:00", "Z"), "cpu_percent": 20, "memory_rss_bytes": 3 * 1024**2}
    assert result["samples"][1]["cpu_percent"] is None
    assert result["samples"][1]["memory_rss_bytes"] == 0
    assert len(result["samples"]) <= 4
    assert result["latest"]["status"] == "online"
    st.execute("UPDATE sensor_activity SET last_heartbeat_at=now()-interval '10 minutes' WHERE sensor_id=$1", sensor["id"])
    stale = client.get(path).json()["latest"]
    assert stale["status"] == "offline" and stale["cpu_percent"] == 150
    st.update_sensor(sensor["tenant_id"], sensor["id"], disabled=True)
    assert client.get(path).json()["latest"]["status"] == "disabled"
    for range_name in ("1h", "6h", "24h", "7d", "30d"):
        response = client.get(path, params={"range": range_name})
        assert response.status_code == 200, response.text
        assert len(response.json()["samples"]) <= 361
        assert all(row["cpu_percent"] not in (888, 999) for row in response.json()["samples"])
    assert client.get(path, params={"range": "all"}).status_code == 400
    assert client.get(f"/api/v1/sensors/{remote['id']}/metrics").status_code == 404
    assert client.get(f"/api/v1/sensors/{uuid4()}/metrics").status_code == 404
    assert client.get("/api/v1/sensors/invalid/metrics").status_code == 400
    own = st.get_user_by_email("demo@example.com")
    st.update_user(sensor["tenant_id"], own["id"], role="viewer")
    assert client.get(path).status_code == 403
    st.update_user(sensor["tenant_id"], own["id"], roles=["it_admin"])
    assert client.get(path).status_code == 200
    denied = client.get(f"/api/v1/sensors/{remote['id']}/metrics")
    assert denied.status_code == 404
    assert denied.json() == {"error": {"code": "not_found", "message": "not found"}}
    assert prune(st, sensor["tenant_id"]) == 1
    assert prune(st) == 1
    st.execute(
        """INSERT INTO sensor_resource_samples(sensor_id,sampled_at)
           SELECT $1::uuid,now()-interval '31 days'-n*interval '1 minute'
           FROM generate_series(1,10001) n""",
        sensor["id"],
    )
    assert prune(st, sensor["tenant_id"]) == 10000
    assert prune(st, sensor["tenant_id"]) == 1
    assert prune(st, sensor["tenant_id"]) == 0
    assert client.get(path).json()["samples"] == result["samples"]
    st.execute("UPDATE sensors SET deleted_at=now() WHERE id=$1", sensor["id"])
    assert client.get(path).status_code == 404
    client.cookies.clear()
    assert client.get(path, headers=headers).status_code == 401


def test_bound_owner_cli_creates_without_resetting(dashboard, monkeypatch, capsys):
    st, _, _, sensor, _, remote = dashboard
    monkeypatch.setenv("OPENAIDR_DATABASE_URL", st.url)
    monkeypatch.setenv("OPENAIDR_TENANT_ID", sensor["tenant_id"])
    monkeypatch.setenv("OPENAIDR_REQUIRE_TENANT", "true")
    command = [
        "tenant",
        "user",
        "create",
        "--email",
        "owner@example.com",
        "--name",
        "Owner",
        "--password-stdin",
        "--json",
    ]
    monkeypatch.setattr("sys.stdin", io.StringIO("a-private-password\n"))
    assert main(command) == 0
    output = capsys.readouterr()
    created = json.loads(output.out)
    assert created["tenant_id"] == sensor["tenant_id"] and created["role"] == "owner"
    assert "a-private-password" not in output.out + output.err
    monkeypatch.setattr("sys.stdin", io.StringIO("a-different-password\n"))
    assert main(command) == 1
    assert "no credentials were changed" in capsys.readouterr().err
    assert check_password(
        st.get_user_by_email("owner@example.com")["password_hash"], "a-private-password"
    )
    monkeypatch.delenv("OPENAIDR_TENANT_ID")
    assert main(command) == 1
    assert "OPENAIDR_TENANT_ID" in capsys.readouterr().err
    assert (
        st.scalar(
            "SELECT count(*) FROM tenant_users WHERE tenant_id=$1 AND email='owner@example.com'",
            remote["tenant_id"],
        )
        == 0
    )


def test_export_payload_is_analyst_evidence_scoped_to_the_tenant(dashboard):
    st, cfg, client, sensor, token, remote = dashboard
    shared_batch = populate(st, sensor, remote)
    listed = client.get("/api/v1/telemetry/exports?range=7d").json()["items"]
    shared = next(item for item in listed if item["batch_id"] == shared_batch)
    assert "payload" not in shared and "TOP-SECRET" not in json.dumps(listed)

    detail = client.get(f"/api/v1/telemetry/exports/{shared['id']}")
    assert detail.status_code == 200, detail.text
    export = detail.json()
    assert export["id"] == shared["id"] and export["signal"] == "logs"
    assert export["batch_id"] == shared_batch and export["hostname"] == "linux-demo"
    assert export["service_names"] == ["claude-code", "codex-cli"]
    assert export["demo"] is False and len(export["payload_sha256"]) == 64
    # The canonical payload is returned intact, including log bodies.
    assert export["payload"]["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0][
        "body"
    ] == {"stringValue": "TOP-SECRET-NOT-FOR-DASHBOARD"}
    assert len(export["records"]) == export["record_count"] == 5
    assert {row["service"] for row in export["records"]} == {"codex-cli", "claude-code"}
    assert export["records"][0]["kind"] == "log"
    assert export["records"][0]["body"] == "TOP-SECRET-NOT-FOR-DASHBOARD"
    audit = client.get("/api/v1/audit").json()["items"]
    assert [
        (entry["action"], entry["target_id"], entry["details"]["signal"])
        for entry in audit
        if entry["action"] == "telemetry_export.read"
    ] == [("telemetry_export.read", shared["id"], "logs")]

    # Another tenant's export is not found, and malformed IDs are rejected.
    foreign = st.scalar(
        "SELECT id FROM telemetry_exports WHERE sensor_id=$1", remote["id"]
    )
    assert client.get(f"/api/v1/telemetry/exports/{foreign}").status_code == 404
    assert client.get("/api/v1/telemetry/exports/not-a-uuid").status_code == 400

    # Security Leadership cannot inspect exports or their payload contents.
    st.create_user(
        sensor["tenant_id"],
        "viewer@example.com",
        "Viewer",
        hash_password("viewer-password"),
        "viewer",
    )
    viewer = TestClient(create_app(cfg, st), headers={"X-OpenAIDR-CSRF": "1"})
    assert (
        viewer.post(
            "/api/v1/auth/login",
            json={"email": "viewer@example.com", "password": "viewer-password"},
        ).status_code
        == 200
    )
    assert viewer.get("/api/v1/telemetry/exports?range=7d").status_code == 403
    denied = viewer.get(f"/api/v1/telemetry/exports/{shared['id']}")
    assert denied.status_code == 403, denied.text
    viewer.close()


@pytest.mark.parametrize("product", ["claude-code", "codex-app-server"])
def test_derived_events_index_into_export_records(dashboard, product):
    st, cfg, client, sensor, token, remote = dashboard
    populate(st, sensor, remote)
    # Bodies without event names produce no detection events.
    assert client.get("/api/v1/events").json()["items"] == []
    session = "conv-dashboard"
    prefix = "codex" if product == "codex-app-server" else "claude_code"
    attributes = lambda pairs: [
        {"key": key, "value": {"stringValue": value}} for key, value in pairs
    ]
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": attributes([("service.name", product)])
                },
                "scopeLogs": [
                    {
                        "logRecords": [
                            {
                                "timeUnixNano": "1700000000000000000",
                                "eventName": prefix + ".user_prompt",
                                "body": {"stringValue": "[REDACTED]"},
                                "attributes": attributes(
                                    [("session.id", session), ("prompt_length", "9"),
                                     ("prompt", "Plan task" if prefix == "codex" else "[REDACTED]")]
                                ),
                            },
                            {
                                "timeUnixNano": "1700000001000000000",
                                "eventName": prefix + ".tool_result",
                                "body": {"stringValue": prefix + ".tool_result"},
                                "attributes": attributes(
                                    [
                                        ("session.id", session),
                                        ("tool_name", "Read"),
                                        (
                                            "tool_parameters",
                                            json.dumps({"file_path": "/work/.env"}),
                                        ),
                                    ]
                                ),
                            },
                        ]
                    }
                ],
            }
        ]
    }
    batch = new_id()
    result = client.post(
        "/otlp/v1/logs",
        json=payload,
        headers={"Authorization": "Bearer " + token, "X-OpenAIDR-Batch-Id": batch},
    )
    assert result.status_code == 200, result.text
    events = client.get("/api/v1/events", params={"source": "otlp"}).json()["items"]
    assert sorted(event["kind"] for event in events) == ["file.read", "prompt"]
    export_id = {event["export"]["id"] for event in events}.pop()
    detail = client.get(f"/api/v1/telemetry/exports/{export_id}").json()
    assert detail["batch_id"] == batch
    for event in events:
        row = detail["records"][event["export"]["record"]]
        assert row["event_name"] == event["event_name"]
        assert row["time"] == event["time"]
    read = next(event for event in events if event["kind"] == "file.read")
    assert read["file"] == {"path": "/work/.env"} and read["tool"]["name"] == "Read"
    assert read["host"]["hostname"] == "linux-demo"
    prompt = next(event for event in events if event["kind"] == "prompt")
    assert prompt["prompt"] == {"length": 9}
    if prefix == "codex":
        assert prompt["text"] == "Plan task"
        stored = client.get("/api/v1/events", params={
            "session_id": prompt["session_id"], "kind": "prompt", "source": "otlp", "limit": 1,
        }).json()["items"]
        assert stored[0]["text"] == "Plan task"
    else:
        assert "text" not in prompt
    overview = client.get("/api/v1/telemetry/overview").json()
    assert overview["summary"]["log_records"] == 7


def test_sensor_health_detects_upload_faults_with_live_heartbeats_and_recovers(dashboard):
    import copy

    st, _, client, sensor, token, remote = dashboard
    headers = {"Authorization": "Bearer " + token}
    report = dict(
        version=1,
        activity=dict(upload_failed=False, stalled_for_s=0, last_success_at=None, dropped=0),
        telemetry=dict(enabled=True, listening=True, upload_failed=False,
                       stalled_for_s=0, last_success_at=None),
        collectors_failed=0,
    )
    clock = [0]
    client.app.state.service.telemetry_cache.clock = lambda: clock[0]

    def send(value, activity=0, telemetry=0):
        response = client.post('/ingest/v1/heartbeat', headers=headers, content=json.dumps({
            'health_report': value, 'queue_depth': activity, 'telemetry_queue_depth': telemetry,
            'sensor_id': remote['id'],  # authenticated device owns the report
        }))
        assert response.status_code == 200, response.text

    def check(status, codes=(), connection='online'):
        clock[0] += 30
        for endpoint, key in (('/api/v1/sensors/health', 'items'),
                              ('/api/v1/sensors', 'items'),
                              ('/api/v1/telemetry/overview', 'devices')):
            response = client.get(endpoint)
            assert response.status_code == 200, response.text
            rows = response.json()[key]
            assert all(row['id'] != remote['id'] for row in rows)
            row = next(row for row in rows if row['id'] == sensor['id'])
            assert row['status'] == connection
            assert row['health']['status'] == status
            assert {reason['code'] for reason in row['health']['reasons']} == set(codes)
            assert 'health_report' not in row
        assert st.get_sensor(remote['tenant_id'], remote['id'])['health']['status'] == 'unknown'
        return row

    send(None, activity=1234)
    assert check('unknown')['queue_depth'] == 1234
    broken = copy.deepcopy(report)
    broken['activity'].update(upload_failed=True, stalled_for_s=300,
                              last_success_at='2026-10-11T12:00:00-07:00')
    # Unknown fields are never persisted, even PostgreSQL-invalid secret text.
    broken['exception'] = 'TOKEN\x00SECRET\ud800'
    send(broken, activity=1234)
    row = check('needs_attention', ('activity_upload_failed', 'activity_stalled'))
    assert row['telemetry_queue_depth'] == 0 and row['health']['stale'] is False
    assert row['health']['report']['activity']['last_success_at'] == '2026-10-11T19:00:00+00:00'
    assert 'SECRET' not in repr(st.get_sensor(sensor['tenant_id'], sensor['id'])['health'])

    send(report, activity=5)  # ordinary buffered activity is not a stalled queue
    check('healthy')
    for group, field, value, code in (
        ('activity', 'dropped', 3, 'activity_dropped'),
        ('telemetry', 'upload_failed', True, 'telemetry_upload_failed'),
        ('telemetry', 'listening', False, 'telemetry_not_listening'),
        ('telemetry', 'stalled_for_s', 300, 'telemetry_stalled'),
        (None, 'collectors_failed', 1, 'collector_failed'),
    ):
        broken = copy.deepcopy(report)
        (broken[group] if group else broken)[field] = value
        send(broken, telemetry=1)
        check('needs_attention', (code,))
    report['telemetry'].update(enabled=False, listening=False)
    send(report)
    check('healthy')
    for previous_report in (report, broken, None):
        send(previous_report)
        st.execute("UPDATE sensor_activity SET last_heartbeat_at=now()-interval '91 seconds', health_reported_at=now()-interval '91 seconds' WHERE sensor_id=$1", sensor['id'])
        health = check('unknown', connection='offline')['health']
        assert health['stale'] is True
        assert health['report'] == previous_report
    st.update_sensor(sensor['tenant_id'], sensor['id'], disabled=True)
    check('disabled', connection='disabled')
    st.update_sensor(sensor['tenant_id'], sensor['id'], disabled=False)
    send(report)
    check('healthy')
    # An older server in a rolling deployment does not refresh diagnostics.
    st.execute('UPDATE sensor_activity SET last_heartbeat_at=now() WHERE sensor_id=$1', sensor['id'])
    assert check('unknown')['health']['report'] is None
    for value in (None, {'version': 2}):
        send(report)
        send(value)
        assert check('unknown')['health']['report'] is None
    assert client.get(f"/api/v1/sensors/{remote['id']}").status_code == 404


def test_invalid_sensor_diagnostics_preserve_liveness_commands_and_policy(dashboard):
    import copy

    st, _, client, sensor, token, _ = dashboard
    headers = {'Authorization': 'Bearer ' + token}
    valid = dict(version=1, collectors_failed=0,
                 activity=dict(upload_failed=False, stalled_for_s=0, last_success_at=None, dropped=0),
                 telemetry=dict(enabled=True, listening=True, upload_failed=False, stalled_for_s=0, last_success_at=None))
    command = st.queue_command(sensor['tenant_id'], sensor['id'], 'refresh_policy')
    policy = st.save_policy(sensor['tenant_id'], [])
    malformed = ['invalid report', [], {'version': 1}]
    for key, value in [('upload_failed', 'yes'), ('stalled_for_s', -1),
                       ('stalled_for_s', True), ('stalled_for_s', 10**30),
                       ('last_success_at', '\x00\ud800'), ('last_success_at', '2026-10-11'),
                       ('dropped', float('inf'))]:
        report = copy.deepcopy(valid)
        report['activity'][key] = value
        malformed.append(report)
    for index, report in enumerate(malformed):
        assert client.post('/ingest/v1/heartbeat', headers=headers, json={'health_report': valid}).status_code == 200
        st.execute("UPDATE sensor_activity SET last_heartbeat_at=now()-interval '91 seconds' WHERE sensor_id=$1", sensor['id'])
        body = {'health_report': report, 'policy_version': 0}
        if index % 2:
            body['policy_delivery'] = 'backend'
        result = client.post('/ingest/v1/heartbeat', headers=headers,
                             content=json.dumps(body))
        assert result.status_code == 200, result.text
        reply = result.json()
        assert reply['disabled'] is False
        assert any(item['id'] == command for item in reply['commands'])
        if index % 2:
            assert reply['policy_version'] == policy['version'] and 'policy' not in reply
        else:
            assert reply['policy']['version'] == policy['version']
        current = st.get_sensor(sensor['tenant_id'], sensor['id'])
        assert current['status'] == 'online'
        assert current['health']['status'] == 'unknown' and current['health']['report'] is None
    st.update_sensor(sensor['tenant_id'], sensor['id'], disabled=True)
    result = client.post('/ingest/v1/heartbeat', headers=headers, json={'health_report': []})
    assert result.status_code == 200 and result.json()['disabled'] is True
    assert any(item['id'] == command for item in result.json()['commands'])
    assert client.post('/ingest/v1/heartbeat', headers=headers,
                       json={'health_report': [], 'cpu_percent': -1}).status_code == 400


def test_sensor_upload_failure_is_discoverable_from_authenticated_fleet_api(dashboard, tmp_path):
    import httpx
    import threading
    from openaidr.sensor.config import Config as SensorConfig
    from openaidr.sensor.runtime import Sensor

    _, _, browser, registered, token, _ = dashboard
    sensor = Sensor(SensorConfig(tmp_path / 'sensor.yaml',
        server_url='https://backend.example', sensor_id=registered['id'], sensor_token=token,
        data_dir=str(tmp_path / 'data'), telemetry={'enabled': False}, inventory={'enabled': False}))
    sensor.server_config['flush_interval_s'] = 0
    sensor.spool.append({'id': new_id(), 'time': '2026-10-12T07:00:00Z', 'kind': 'sensor'})
    broken = True
    stop = threading.Event()
    clock = [0.0]
    sensor.health.clock = lambda: clock[0]

    def remote(request):
        if request.url.path.endswith('/events'):
            stop.set()
            if broken:
                return httpx.Response(500, json={'error': 'private upstream failure'})
        reply = browser.post(request.url.path, content=request.content,
                             headers={'Authorization': 'Bearer ' + token})
        return httpx.Response(reply.status_code, content=reply.content)

    sensor.client.http.close()
    sensor.client.http = httpx.Client(transport=httpx.MockTransport(remote))

    def visible():
        sensor.heartbeat_once()
        assert sensor.last_heartbeat and not sensor.heartbeat_error
        rows = browser.get('/api/v1/sensors/health').json()['items']
        return next(row for row in rows if row['id'] == registered['id'])

    try:
        assert visible()['health']['status'] == 'healthy'
        sensor.ship_wake.set()
        sensor.ship_loop(stop)
        row = visible()
        assert row['status'] == 'online' and row['queue_depth'] == 1
        assert row['health']['status'] == 'needs_attention'
        assert [r['code'] for r in row['health']['reasons']] == ['activity_upload_failed']
        assert 'backend.example' not in json.dumps(row['health'])
        clock[0] += 300
        assert {r['code'] for r in visible()['health']['reasons']} == {'activity_upload_failed', 'activity_stalled'}
        broken = False
        stop.clear()
        sensor.ship_wake.set()
        sensor.ship_loop(stop)
        row = visible()
        assert row['queue_depth'] == 0 and sensor.spool.depth == 0
        assert row['health']['status'] == 'healthy' and row['health']['reasons'] == []
        assert row['health']['report']['activity']['last_success_at']
        # A subsequent idle period does not accumulate a stall.
        clock[0] += 600
        assert visible()['health']['report']['activity']['stalled_for_s'] == 0
    finally:
        sensor.hook_clients.close()
        sensor.client.close()
        sensor.spool.close()
