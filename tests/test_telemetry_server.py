"""Tenant-authenticated canonical OTLP ingestion and durable retry guarantees."""

import gzip
import json
import os
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from google.rpc.status_pb2 import Status
from psycopg.conninfo import make_conninfo

from openaidr.server.app import create_app
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server.config import PLATFORM_AVAILABLE, Config, from_env
from openaidr.server.detect import Engine
from openaidr.server.store import Store, new_id, now
from openaidr.server.telemetry_events import event_id
from openaidr.core.telemetry import encode_export, decode_export, MAX_BODY_BYTES


def export(signal, service="claude-code"):
    resource = {
        "attributes": [
            {"key": "service.name", "value": {"stringValue": service}},
            {"key": "tenant.id", "value": {"stringValue": "untrusted-other-tenant"}},
        ]
    }
    if signal == "logs":
        return {
            "resourceLogs": [
                {
                    "resource": resource,
                    "scopeLogs": [
                        {
                            "scope": {"name": "coding-agent"},
                            "logRecords": [
                                {
                                    "timeUnixNano": "1700000000123456789",
                                    "body": {"stringValue": "session active"},
                                    "severityNumber": 9,
                                }
                            ],
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
                                    "name": "tokens",
                                    "sum": {
                                        "aggregationTemporality": 2,
                                        "isMonotonic": True,
                                        "dataPoints": [
                                            {
                                                "asInt": "42",
                                                "timeUnixNano": "1700000000123456789",
                                            }
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
                    {
                        "spans": [
                            {
                                "traceId": "0123456789abcdef0123456789abcdef",
                                "spanId": "0123456789abcdef",
                                "name": "tool.call",
                                "startTimeUnixNano": "1700000000123456789",
                                "endTimeUnixNano": "1700000001123456789",
                            }
                        ]
                    }
                ],
            }
        ]
    }


@pytest.fixture
def backend():
    url = os.environ.get("OPENAIDR_TEST_DATABASE_URL")
    if not url:
        pytest.skip("OPENAIDR_TEST_DATABASE_URL is not configured")
    schema = "otlp_" + uuid4().hex
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
    st = Store(make_conninfo(url, options=f"-c search_path={schema}"))
    st.migrate()
    one = st.bootstrap_tenant("Company A", "company-a")
    two = st.bootstrap_tenant("Company B", "company-b")
    sensor, token, tenant = st.enroll_sensor(
        {"enrollment_token": one["enrollment_token"], "hostname": "one"}
    )
    other, other_token, _ = st.enroll_sensor(
        {"enrollment_token": two["enrollment_token"], "hostname": "two"}
    )
    cfg = Config(database_url=st.url, tenant_id=tenant["id"], require_tenant=True)
    cfg.set_services("ingest")
    yield st, cfg, sensor, token, other, other_token, two
    st.close()
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA {schema} CASCADE")


@pytest.mark.parametrize("route", ["events", "logs"])
def test_partition_contention_returns_retryable_error_and_recovers(backend, route):
    st, cfg, sensor, token, *_ = backend
    day = now().date() + timedelta(days=1)
    # Today exists, but missing tomorrow must trigger real partition creation.
    for root in ("events", "telemetry_exports"):
        relation = root + "_" + sensor["tenant_id"].replace("-", "") + "_" + day.strftime("%Y%m%d")
        st.execute(psycopg.sql.SQL("DROP TABLE {}").format(psycopg.sql.Identifier(relation)).as_string())
    st.execute("DELETE FROM telemetry_partition_days WHERE tenant_id=$1 AND storage_day=$2", sensor["tenant_id"], day)
    headers = {"Authorization": "Bearer " + token}
    if route == "events":
        path = "/ingest/v1/events"
        payload = {"events": [{"id": new_id(), "time": now().isoformat(), "kind": "sensor",
                               "agent": {"product": "codex-cli"}}]}
    else:
        path = "/otlp/v1/logs"
        payload = export("logs")
        headers["X-OpenAIDR-Batch-Id"] = new_id()
    with TestClient(create_app(cfg, st)) as client:
        with psycopg.connect(st.url) as blocker:
            blocker.execute("SELECT pg_advisory_xact_lock(684021562)")
            result = client.post(path, json=payload, headers=headers)
            assert result.status_code == 503, result.text
            if route == "events":
                assert result.headers["Retry-After"] == "1"
            assert st.scalar("SELECT count(*) FROM events") == 0
            assert st.scalar("SELECT count(*) FROM telemetry_exports") == 0
        result = client.post(path, json=payload, headers=headers)
        assert result.status_code == 200, result.text
        retry = client.post(path, json=payload, headers=headers)
        assert retry.status_code == 200, retry.text
        if route == "events":
            assert result.json()["accepted"] == 1, result.text
            assert retry.json()["duplicates"] == 1
        else:
            assert result.headers["X-OpenAIDR-Duplicate"] == "false"
            assert retry.headers["X-OpenAIDR-Duplicate"] == "true"


@pytest.mark.parametrize("signal", ["logs", "metrics", "traces"])
@pytest.mark.parametrize("media", ["application/json", "application/x-protobuf"])
def test_canonical_persistence_and_retry_after_restart(backend, signal, media):
    st, cfg, sensor, token, *_ = backend
    payload = export(signal)
    encoded = encode_export(signal, payload, media)
    batch = new_id()
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": media,
        "Content-Encoding": "gzip",
        "X-OpenAIDR-Batch-Id": batch,
    }
    with TestClient(create_app(cfg, st)) as client:
        result = client.post(
            "/otlp/v1/" + signal, content=gzip.compress(encoded), headers=headers
        )
        assert result.status_code == 200, result.text
        assert result.headers["content-type"] == media
        assert result.headers["x-openaidr-duplicate"] == "false"
        assert result.content == (b"{}" if media == "application/json" else b"")
    # New app and new Store connection prove retries survive process lifetime.
    with (
        closing(Store(st.url)) as restarted_store,
        TestClient(create_app(cfg, restarted_store)) as restarted,
    ):
        result = restarted.post(
            "/otlp/v1/" + signal, content=gzip.compress(encoded), headers=headers
        )
        assert result.status_code == 200
        assert result.headers["x-openaidr-duplicate"] == "true"
        changed = encode_export(signal, export(signal, "changed-service"), media)
        conflict = restarted.post(
            "/otlp/v1/" + signal, content=gzip.compress(changed), headers=headers
        )
        assert conflict.status_code == 409
        if media == "application/x-protobuf":
            assert Status.FromString(conflict.content).code == 6
    row = st.one("SELECT * FROM telemetry_exports WHERE batch_id=$1", batch)
    assert row["tenant_id"] == sensor["tenant_id"]
    assert row["sensor_id"] == sensor["id"]
    assert row["payload"] == decode_export(signal, encoded, media)
    assert row["service_names"] == ["claude-code"]
    assert int(row["first_event_unix_nano"]) == 1700000000123456789
    assert row["record_count"] == 1
    assert st.scalar("SELECT count(*) FROM telemetry_exports") == 1


def test_authentication_boundary_and_disabled_tenant(backend):
    st, cfg, sensor, token, other, other_token, other_bootstrap = backend
    client = TestClient(create_app(cfg, st))
    data = export("logs")
    assert client.post("/otlp/v1/logs", json=data).status_code == 401
    assert (
        client.post(
            "/otlp/v1/logs", json=data, headers={"Authorization": "Bearer invalid"}
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/otlp/v1/logs",
            json=data,
            headers={"Authorization": "Bearer " + other_token},
        ).status_code
        == 403
    )
    result = client.post(
        "/ingest/v1/enroll",
        json={
            "enrollment_token": other_bootstrap["enrollment_token"],
            "hostname": "attempt",
        },
    )
    assert result.status_code == 401
    assert (
        st.scalar("SELECT count(*) FROM sensors WHERE tenant_id=$1", other["tenant_id"])
        == 1
    )
    for endpoint in ("heartbeat", "events"):
        assert (
            client.post(
                "/ingest/v1/" + endpoint,
                json={},
                headers={"Authorization": "Bearer " + other_token},
            ).status_code
            == 403
        )
    st.update_sensor(sensor["tenant_id"], sensor["id"], disabled=True)
    headers = {"Authorization": "Bearer " + token}
    assert client.post("/otlp/v1/logs", json=data, headers=headers).status_code == 403
    st.update_sensor(sensor["tenant_id"], sensor["id"], disabled=False)
    st.update_tenant(sensor["tenant_id"], status="suspended")
    assert client.post("/otlp/v1/logs", json=data, headers=headers).status_code == 403
    assert st.scalar("SELECT count(*) FROM telemetry_exports") == 0


def test_validation_limits_errors_and_service_selection(backend):
    st, cfg, _, token, *_ = backend
    client = TestClient(create_app(cfg, st))
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    for body, changes, status in [
        (b"{", {}, 400),
        (b"{}", {"X-OpenAIDR-Batch-Id": "bad"}, 400),
        (b"{}", {"Content-Type": "text/plain"}, 415),
        (b"{}", {"Content-Encoding": "br"}, 415),
        (gzip.compress(b" " * (MAX_BODY_BYTES + 1)), {"Content-Encoding": "gzip"}, 413),
        (b" " * (MAX_BODY_BYTES + 1), {}, 413),
    ]:
        result = client.post(
            "/otlp/v1/logs", content=body, headers={**headers, **changes}
        )
        assert result.status_code == status, result.text
        assert isinstance(result.json()["code"], int)
    assert client.post("/otlp/v1/no-such-signal", json={}).status_code == 404
    assert client.get("/otlp/v1/logs").status_code == 404
    cfg.set_services("api")
    disabled = TestClient(create_app(cfg, st))
    assert disabled.post("/otlp/v1/logs", json={}, headers=headers).status_code == 404
    assert st.scalar("SELECT count(*) FROM telemetry_exports") == 0


def test_simultaneous_retries_insert_once(backend):
    st, cfg, sensor, token, *_ = backend
    payload, batch = export("logs"), new_id()
    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(
            executor.map(
                lambda _: st.ingest_telemetry(sensor, "logs", batch, payload, 1),
                range(12),
            )
        )
    assert sum(results) == 1
    assert st.scalar("SELECT count(*) FROM telemetry_exports") == 1


def test_tenant_bootstrap_cli_and_binding(backend, monkeypatch, capsys):
    from openaidr.server.cli import main

    st, cfg, sensor, *_ = backend
    monkeypatch.setenv("OPENAIDR_DATABASE_URL", st.url)
    monkeypatch.setenv("OPENAIDR_REQUIRE_TENANT", "true")
    monkeypatch.delenv("OPENAIDR_TENANT_ID", raising=False)
    assert (
        main(
            [
                "tenant",
                "bootstrap",
                "--name",
                "Company A",
                "--slug",
                "company-a",
                "--json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["tenant_id"] == sensor["tenant_id"]
    assert result["enrollment_token"].startswith("oaet_")
    assert st.scalar("SELECT count(*) FROM tenants WHERE slug=$1", "company-a") == 1
    assert main(["serve"]) == 1
    assert "required for this dedicated backend" in capsys.readouterr().err


def test_secret_files_and_strict_config(tmp_path, monkeypatch):
    database = tmp_path / "database"
    database.write_text("postgresql://example/db\n")
    tenant = tmp_path / "tenant"
    tenant.write_text(str(uuid4()) + "\n")
    monkeypatch.delenv("OPENAIDR_DATABASE_URL", raising=False)
    monkeypatch.setenv("OPENAIDR_DATABASE_URL_FILE", str(database))
    monkeypatch.setenv("OPENAIDR_TENANT_ID_FILE", str(tenant))
    monkeypatch.setenv("OPENAIDR_SERVICES", "ingest")
    cfg = from_env()
    cfg.validate()
    assert cfg.database_url == "postgresql://example/db"
    cfg.set_services("ingest,api,detect")
    cfg.validate()
    if PLATFORM_AVAILABLE:
        # The admin service exists only with the private platform package.
        cfg.set_services("all")
        with pytest.raises(ValueError, match="ingest, api and detect"):
            cfg.validate()
        cfg.set_services("admin")
        with pytest.raises(ValueError, match="ingest, api and detect"):
            cfg.validate()
    monkeypatch.setenv("OPENAIDR_DATABASE_URL", "postgresql://other/db")
    with pytest.raises(ValueError, match="only one"):
        from_env()


def test_bound_console_cannot_read_or_revoke_other_tenant_session(backend):
    from openaidr.server.auth import CONSOLE_COOKIE

    st, cfg, _, _, other, *_ = backend
    user = st.create_user(
        other["tenant_id"], "other@example.com", "Other", "unused", "owner"
    )
    token = st.create_session(user["id"], other["tenant_id"])
    cfg.set_services("api")
    client = TestClient(create_app(cfg, st))
    client.cookies.set(CONSOLE_COOKIE, token)
    assert client.get("/api/v1/auth/me").status_code == 403
    assert client.post(
        "/api/v1/auth/logout", json={}, headers={"X-OpenAIDR-CSRF": "1"}
    ).status_code == 403
    assert st.get_session(token)["tenant"]["id"] == other["tenant_id"]


def attribute(key, value):
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    return {"key": key, "value": {"stringValue": str(value)}}


def tool_export(session, commands, service="codex-cli"):
    """A Codex logs export with one tool_result per command, plus bookkeeping."""
    records = [
        {
            "timeUnixNano": "1700000000000000000",
            "eventName": "codex.api_request",
            "body": {"stringValue": "codex.api_request"},
            "attributes": [attribute("conversation.id", session)],
        }
    ]
    for index, command in enumerate(commands):
        records.append(
            {
                "timeUnixNano": str(1700000001000000000 + index * 1_000_000_000),
                "eventName": "codex.tool_result",
                "body": {"stringValue": "codex.tool_result"},
                "attributes": [
                    attribute("conversation.id", session),
                    attribute("tool_name", "exec_command"),
                    attribute("success", True),
                    attribute(
                        "arguments", json.dumps({"cmd": command, "workdir": "/srv/app"})
                    ),
                ],
            }
        )
    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        attribute("service.name", service),
                        attribute("host.name", "devbox"),
                        attribute("user.email", "dev@example.com"),
                    ]
                },
                "scopeLogs": [{"scope": {"name": "codex"}, "logRecords": records}],
            }
        ]
    }


def test_logs_export_becomes_events_and_findings_linked_to_the_export(backend):
    st, cfg, sensor, token, *_ = backend
    cfg.set_services("ingest,api,detect")
    tenant = sensor["tenant_id"]
    user = st.create_user(tenant, "analyst@example.com", "Analyst", "unused", "analyst")
    client = TestClient(create_app(cfg, st))
    client.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], tenant))
    batch = new_id()
    headers = {"Authorization": "Bearer " + token, "X-OpenAIDR-Batch-Id": batch}
    payload = tool_export("conv-42", ["ls -la", "rm -rf /srv/data"])
    result = client.post("/otlp/v1/logs", json=payload, headers=headers)
    assert result.status_code == 200, result.text
    export = st.one(
        "SELECT id,translated_at FROM telemetry_exports WHERE batch_id=$1", batch
    )
    assert export["translated_at"] is not None

    rows = st.many(
        "SELECT id,kind,export_id,export_record,command_text,session_id,agent_id FROM events WHERE tenant_id=$1 ORDER BY export_record",
        tenant,
    )
    assert [(row["kind"], row["export_record"]) for row in rows] == [
        ("command", 1),
        ("command", 2),
    ]
    assert {row["export_id"] for row in rows} == {export["id"]}
    assert rows[1]["command_text"] == "rm -rf /srv/data"
    assert rows[0]["id"] == event_id(export["id"], 1)
    assert rows[0]["session_id"] and rows[0]["agent_id"]

    listed = client.get("/api/v1/events", params={"source": "otlp"})
    assert listed.status_code == 200, listed.text
    items = listed.json()["items"]
    assert len(items) == 2
    assert all(item["source"] == "otlp" for item in items)
    assert all(item["export"]["id"] == export["id"] for item in items)
    assert {item["export"]["record"] for item in items} == {1, 2}
    assert items[0]["export"]["signal"] == "logs"
    assert items[0]["agent"]["product"] == "codex-cli"
    assert items[0]["host"] == {"hostname": "devbox", "user": ""}
    assert items[0]["agent"]["account"] == "dev@example.com"
    assert "arguments" not in listed.text and "attributes" not in listed.text
    assert (
        client.get("/api/v1/events", params={"source": "collector"}).json()["items"]
        == []
    )
    assert client.get("/api/v1/events", params={"source": "bogus"}).status_code == 400
    session_events = client.get(
        f"/api/v1/sessions/{rows[0]['session_id']}/events"
    ).json()["items"]
    assert [item["export"]["record"] for item in session_events] == [1, 2]
    agent = client.get(f"/api/v1/agents/{rows[0]['agent_id']}").json()
    assert agent["events_total"] == 2 and agent["sessions_total"] == 1

    # Retrying the identical export creates no duplicate events.
    retry = client.post("/otlp/v1/logs", json=payload, headers=headers)
    assert retry.status_code == 200 and retry.headers["x-openaidr-duplicate"] == "true"
    assert st.scalar("SELECT count(*) FROM events WHERE tenant_id=$1", tenant) == 2
    assert (
        st.scalar(
            "SELECT events_total FROM sensor_activity WHERE sensor_id=$1", sensor["id"]
        )
        == 2
    )

    # The detection engine, bound to this tenant, reads the derived events.
    engine = Engine(st, tenant_id=tenant)
    assert engine.tick() >= 1
    findings = client.get("/api/v1/findings").json()["items"]
    assert [f["rule_id"] for f in findings] == ["destructive-command"]
    detail = client.get(f"/api/v1/findings/{findings[0]['id']}")
    assert detail.status_code == 200, detail.text
    evidence = detail.json()["events"]
    assert [e["export"] for e in evidence] == [
        {"id": export["id"], "record": 2, "signal": "logs"}
    ]
    assert (
        evidence[0]["source"] == "otlp" and evidence[0]["command"]["cwd"] == "/srv/app"
    )
    assert detail.json()["finding"]["product"] == "codex-cli"
    assert detail.json()["finding"]["host"]["hostname"] == "devbox"
    assert detail.json()["finding"]["host"]["user"] == ""
    assert detail.json()["finding"]["account"] == "dev@example.com"
    assert engine.tick() == 0
    assert client.get("/api/v1/system/status").status_code == 403
    st.update_user(tenant, user["id"], roles=["it_admin", "security_analyst"])
    status = client.get("/api/v1/system/status").json()
    detect = next(row for row in status["services"] if row["name"] == "detect")
    assert detect["lag_events"] == 0

    # Deleting the export keeps the events but clears their link.
    st.execute("DELETE FROM telemetry_exports WHERE id=$1", export["id"])
    assert st.scalar("SELECT count(*) FROM events WHERE export_id IS NULL") == 2


@pytest.mark.parametrize("upgrade", [False, True])
def test_findings_preserve_accounts_under_os_usernames(backend, upgrade):
    st, cfg, sensor, token, other, *_ = backend
    tenant = sensor["tenant_id"]
    st.execute("UPDATE sensors SET username='panhu' WHERE id=$1", sensor["id"])
    sensor = st.get_sensor_by_token(token)

    def resource(session, account, os_user=None):
        item = tool_export(session, ["rm -rf /srv/data"])["resourceLogs"][0]
        item["resource"]["attributes"] = [
            attribute("service.name", "codex-cli"),
            attribute("host.name", "same-host"),
            attribute("user.email", account),
        ]
        if os_user is not None:
            item["resource"]["attributes"].append(attribute("os.user", os_user))
        return item

    first = resource("work", "work@example.com", "panhu")
    # Protobuf permits default/empty keys, omitted by canonical JSON.
    first["resource"]["attributes"].append({"value": {"stringValue": "keyless"}})
    first["scopeLogs"][0]["logRecords"][1]["attributes"].append(
        {"value": {"stringValue": "keyless"}}
    )
    personal = resource("personal", "personal@example.com")["scopeLogs"][0]
    personal["logRecords"][1]["attributes"].append(
        attribute("user.email", "personal@example.com")
    )
    first["scopeLogs"].append(personal)
    payload = {
        "resourceLogs": [
            first,
            resource("shared-login", "work@example.com", "bob"),
            resource("sensor-fallback", "other@example.com"),
            resource("os-only", "", "carol"),
        ]
    }
    assert st.ingest_telemetry(sensor, "logs", new_id(), payload, 10)
    assert st.ingest_telemetry(
        other,
        "logs",
        new_id(),
        {"resourceLogs": [resource("foreign", "work@example.com")]},
        2,
    )
    collector = {
        "id": new_id(),
        "time": "2023-11-14T22:13:21Z",
        "kind": "command",
        "agent": {"product": "codex-cli"},
        "session": {"id": "collector", "cwd": "/srv/app"},
        "host": {"hostname": "same-host", "user": "panhu"},
        "source": {"collector": "hook"},
        "command": {"text": "rm -rf /srv/data", "cwd": "/srv/app"},
    }
    st.ingest_batch(sensor, [collector])
    assert st.scalar("SELECT count(*) FROM agents WHERE tenant_id=$1", tenant) == 3
    assert Engine(st).tick() == 7
    st.execute("UPDATE findings SET status='triaged',resolution='Keep investigation'")
    exports = st.many(
        "SELECT id,payload,payload_sha256 FROM telemetry_exports ORDER BY id"
    )
    links = st.many("SELECT id,agent_id,session_id,event_ids FROM findings ORDER BY id")

    if upgrade:
        # Recreate the old mixed identity fields and schema, then upgrade.
        st.execute("""UPDATE events SET body = jsonb_set(
            body #- '{agent,account}', '{host,user}', COALESCE(
                body #> '{agent,account}', body #> '{host,user}'))
            WHERE body->>'source'='otlp'""")
        st.execute("UPDATE findings SET username=account WHERE account<>''")
        st.execute("ALTER TABLE findings DROP COLUMN account")
        st.execute("DELETE FROM schema_migrations WHERE version=13")
        assert st.migrate() == ["0013_os_user_attribution.sql"]
        assert st.migrate() == []

    cfg.set_services("ingest,api")
    client = TestClient(create_app(cfg, st))
    user = st.create_user(tenant, "analyst@example.com", "Analyst", "unused", "analyst")
    client.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], tenant))
    findings = client.get("/api/v1/findings").json()["items"]
    assert sorted((f["host"]["user"], f["account"]) for f in findings) == [
        ("bob", "work@example.com"),
        ("carol", ""),
        ("panhu", ""),
        ("panhu", "other@example.com"),
        ("panhu", "personal@example.com"),
        ("panhu", "work@example.com"),
    ]
    assert all(
        f["status"] == "triaged" and f["resolution"] == "Keep investigation"
        for f in findings
    )
    for finding in findings:
        detail = client.get(f"/api/v1/findings/{finding['id']}").json()
        (event,) = detail["events"]
        assert event["host"]["user"] == finding["host"]["user"]
        assert event["agent"].get("account", "") == finding["account"]
    foreign = st.list_findings(other["tenant_id"])[0][0]
    assert foreign["host"]["user"] == "" and foreign["account"] == "work@example.com"
    assert client.get(f"/api/v1/findings/{foreign['id']}").status_code == 404
    assert (
        st.many("SELECT id,payload,payload_sha256 FROM telemetry_exports ORDER BY id")
        == exports
    )
    assert (
        st.many("SELECT id,agent_id,session_id,event_ids FROM findings ORDER BY id")
        == links
    )
    assert st.get_event(tenant, collector["id"])["body"] == collector


def test_live_events_deliver_collector_prompts_and_tool_output_in_arrival_order(
    backend,
):
    st, cfg, sensor, token, *_ = backend
    cfg.set_services("ingest,api")
    tenant = sensor["tenant_id"]
    user = st.create_user(tenant, "analyst@example.com", "Analyst", "unused", "analyst")
    client = TestClient(create_app(cfg, st))
    client.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], tenant))
    headers = {"Authorization": "Bearer " + token}

    def event(kind, **fields):
        return {
            "id": new_id(),
            "time": "2026-09-29T10:00:00Z",
            "kind": kind,
            "agent": {"product": "codex-cli", "version": "0.99.0"},
            "session": {"id": "thread-1", "cwd": "/srv/app"},
            "source": {"collector": "hook"},
            **fields,
        }

    prompt = event("prompt", text="list the files")
    result = client.post(
        "/ingest/v1/events", json={"events": [prompt]}, headers=headers
    )
    assert result.status_code == 200 and result.json()["accepted"] == 1

    live = client.get("/api/v1/events/live")
    assert live.status_code == 200, live.text
    first = live.json()
    assert [item["text"] for item in first["items"]] == ["list the files"]
    assert first["items"][0]["source"] == {"collector": "hook"}
    assert first["items"][0]["session"]["id"] == "thread-1"
    assert first["cursor"] and first["more"] is False

    call = event(
        "command",
        tool={"name": "shell", "call_id": "call-1", "input": {"command": ["ls"]}},
        command={"text": "ls", "cwd": "/srv/app"},
    )
    output = event(
        "tool.result",
        tool={"name": "shell", "call_id": "call-1", "output": "README.md\nsrc"},
    )
    result = client.post(
        "/ingest/v1/events", json={"events": [call, output]}, headers=headers
    )
    assert result.json()["accepted"] == 2
    update = client.get("/api/v1/events/live", params={"after": first["cursor"]})
    assert update.status_code == 200, update.text
    items = [i for i in update.json()["items"] if i["id"] != prompt["id"]]
    assert [item["kind"] for item in items] == ["command", "tool.result"]
    assert items[0]["command"]["text"] == "ls"
    assert items[1]["tool"]["output"] == "README.md\nsrc"
    assert update.json()["cursor"] != first["cursor"]
    again = client.get("/api/v1/events/live", params={"after": update.json()["cursor"]}).json()
    assert again["cursor"] == update.json()["cursor"] and again["more"] is False
    assert {i["id"] for i in again["items"]} <= {prompt["id"], call["id"], output["id"]}
    only = client.get(
        "/api/v1/events/live",
        params={"after": first["cursor"], "kind": "tool.result", "product": "codex-cli"},
    ).json()["items"]
    assert [item["id"] for item in only] == [output["id"]]


def test_backfill_translates_pending_exports_once(backend):
    st, cfg, sensor, token, other, other_token, _ = backend
    tenant = sensor["tenant_id"]
    st.execute("UPDATE sensors SET username='alice' WHERE id=$1", sensor["id"])
    payload = tool_export("conv-7", ["git push --force origin main"])
    batch = new_id()
    assert st.ingest_telemetry(sensor, "logs", batch, payload, 2)
    # Simulate an export stored by a server version without translation.
    st.execute("DELETE FROM events WHERE tenant_id=$1", tenant)
    st.execute(
        "UPDATE telemetry_exports SET translated_at=NULL WHERE batch_id=$1", batch
    )
    # Exports without translatable records are marked and never revisited.
    empty = new_id()
    assert st.ingest_telemetry(sensor, "logs", empty, export("logs"), 1)
    st.execute(
        "UPDATE telemetry_exports SET translated_at=NULL WHERE batch_id=$1", empty
    )
    assert st.ingest_telemetry(sensor, "metrics", new_id(), export("metrics"), 1)
    foreign = new_id()
    assert st.ingest_telemetry(
        other, "logs", foreign, tool_export("conv-x", ["rm -rf ~"]), 2
    )
    st.execute("DELETE FROM events WHERE tenant_id=$1", other["tenant_id"])
    st.execute(
        "UPDATE telemetry_exports SET translated_at=NULL WHERE batch_id=$1", foreign
    )

    assert st.translate_untranslated_exports(tenant, limit=1) == {
        "exports": 1,
        "events": 1,
    }
    assert st.translate_untranslated_exports(tenant) == {"exports": 1, "events": 0}
    assert st.translate_untranslated_exports(tenant) == {"exports": 0, "events": 0}
    assert (
        st.scalar(
            "SELECT count(*) FROM telemetry_exports WHERE tenant_id=$1 AND translated_at IS NULL",
            tenant,
        )
        == 0
    )
    rows = st.many(
        "SELECT export_id,export_record,command_text,body FROM events WHERE tenant_id=$1",
        tenant,
    )
    assert len(rows) == 1 and rows[0]["export_record"] == 1
    assert rows[0]["command_text"] == "git push --force origin main"
    assert rows[0]["body"]["host"]["user"] == "alice"
    assert rows[0]["body"]["agent"]["account"] == "dev@example.com"
    assert rows[0]["export_id"] == st.scalar(
        "SELECT id FROM telemetry_exports WHERE batch_id=$1", batch
    )
    # The other tenant is untouched by a tenant-scoped backfill, then handled by
    # the engine's unscoped backfill on its next tick.
    assert (
        st.scalar("SELECT count(*) FROM events WHERE tenant_id=$1", other["tenant_id"])
        == 0
    )
    engine = Engine(st)
    assert engine.tick() >= 2
    assert (
        st.scalar("SELECT count(*) FROM events WHERE tenant_id=$1", other["tenant_id"])
        == 1
    )
    assert (
        st.scalar("SELECT count(*) FROM telemetry_exports WHERE translated_at IS NULL")
        == 0
    )
    assert st.scalar("SELECT count(*) FROM findings") == 2
    # A bound engine only processes its tenant.
    st.execute("DELETE FROM findings")
    st.execute("DELETE FROM detect_cursors")
    assert Engine(st, tenant_id=tenant).tick() == 1
    assert st.scalar("SELECT DISTINCT tenant_id FROM findings") == tenant


def test_translate_cli(backend, monkeypatch, capsys):
    from openaidr.server.cli import main

    st, cfg, sensor, *_ = backend
    monkeypatch.setenv("OPENAIDR_DATABASE_URL", st.url)
    monkeypatch.setenv("OPENAIDR_TENANT_ID", sensor["tenant_id"])
    monkeypatch.setenv("OPENAIDR_SERVICES", "ingest,api,detect")
    batch = new_id()
    assert st.ingest_telemetry(
        sensor, "logs", batch, tool_export("c", ["ls", "pwd"]), 3
    )
    st.execute("DELETE FROM events")
    st.execute("UPDATE telemetry_exports SET translated_at=NULL")
    assert main(["telemetry", "translate"]) == 0
    assert capsys.readouterr().out.strip() == "translated 1 exports into 2 events"
    assert main(["telemetry", "translate", "--limit", "5"]) == 0
    assert capsys.readouterr().out.strip() == "translated 0 exports into 0 events"


def test_version_route_requires_a_bound_sensor_and_reports_the_package_version(
    backend,
):
    from openaidr import __version__, build_info

    st, cfg, sensor, token, other, other_token, _ = backend
    client = TestClient(create_app(cfg, st))
    assert client.post("/ingest/v1/version", json={}).status_code == 401
    assert client.get("/ingest/v1/version").status_code == 404
    assert (
        client.post(
            "/ingest/v1/version",
            json={},
            headers={"Authorization": "Bearer " + other_token},
        ).status_code
        == 403
    )
    result = client.post(
        "/ingest/v1/version", json={}, headers={"Authorization": "Bearer " + token}
    )
    assert result.status_code == 200, result.text
    assert result.json() == {"version": __version__, "build": build_info.current()}
