"""Real headless processes, native OTLP wire messages, and restart recovery."""

import gzip
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import time
from uuid import uuid4

import httpx
import psycopg
from psycopg.conninfo import make_conninfo
import pytest
import yaml
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
    ExportMetricsServiceRequest,
)
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)

from openaidr.server.store import Store


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def eventually(check, description):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (httpx.TransportError, sqlite3.OperationalError):
            pass
        time.sleep(0.1)
    pytest.fail("timed out: " + description)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_headless_delivery_and_crash_recovery(tmp_path):
    database = os.environ.get("OPENAIDR_TEST_DATABASE_URL")
    if not database:
        pytest.skip("OPENAIDR_TEST_DATABASE_URL is not configured")
    schema = "headless_" + uuid4().hex
    with psycopg.connect(database, autocommit=True) as connection:
        connection.execute(f"CREATE SCHEMA {schema}")
    store = Store(make_conninfo(database, options=f"-c search_path={schema}"))
    server_url = f"http://127.0.0.1:{unused_port()}"
    receiver = f"127.0.0.1:{unused_port()}"
    status_url = f"http://127.0.0.1:{unused_port()}"
    config_path = tmp_path / "sensor.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "data_dir": str(tmp_path / "data"),
                "listen": status_url.removeprefix("http://"),
                "telemetry": {"listen": receiver},
            }
        )
    )
    # Isolate this test from real server configuration, preserving other env vars.
    env = {
        key: val for key, val in os.environ.items() if not key.startswith("OPENAIDR_")
    }
    env.update(
        OPENAIDR_DATABASE_URL=store.url,
        OPENAIDR_SERVICES="ingest",
        OPENAIDR_LISTEN=server_url.removeprefix("http://"),
        OPENAIDR_PUBLIC_URL=server_url,
        OPENAIDR_REQUIRE_TENANT="true",
    )
    binary = os.environ.get("OPENAIDR_TEST_SENSOR_BINARY")
    sensor_command = (
        [str(Path(binary).resolve())]
        if binary
        else [sys.executable, "-m", "openaidr.sensor.cli"]
    )
    server_command = [sys.executable, "-m", "openaidr.server.cli"]
    processes, logs = [], []

    def run(command, *args):
        result = subprocess.run(
            [*command, *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    def launch(command, *args):
        log = (tmp_path / f"process-{len(processes)}.log").open("w")
        logs.append(log)
        process = subprocess.Popen(
            [*command, *args], env=env, stdout=log, stderr=subprocess.STDOUT
        )
        processes.append(process)
        return process

    try:
        bootstrap = json.loads(
            run(
                server_command,
                "tenant",
                "bootstrap",
                "--name",
                "Smoke",
                "--slug",
                "smoke",
                "--json",
            )
        )
        env["OPENAIDR_TENANT_ID"] = bootstrap["tenant_id"]
        server = launch(server_command, "serve")
        with httpx.Client(timeout=1) as client:
            eventually(
                lambda: client.get(server_url + "/readyz").status_code == 200,
                "backend readiness",
            )
            run(
                sensor_command,
                "enroll",
                "--config",
                str(config_path),
                "--server",
                server_url,
                "--token",
                bootstrap["enrollment_token"],
                "--host-kind",
                "server",
            )
            run(
                sensor_command,
                "telemetry",
                "configure",
                "--config",
                str(config_path),
                "--codex-config",
                str(tmp_path / "codex.toml"),
                "--claude-settings",
                str(tmp_path / "claude.json"),
                "--json",
            )
            config = yaml.safe_load(config_path.read_text())
            sensor = launch(sensor_command, "run", "--config", str(config_path))
            headers = {}

            def ready():
                # The service creates its control token at startup. Telemetry
                # configuration no longer creates or distributes that credential.
                token = yaml.safe_load(config_path.read_text())["telemetry"].get("local_token")
                if not token:
                    return False
                headers["Authorization"] = "Bearer " + token
                return client.get(status_url + "/v1/status", headers=headers).status_code == 200

            eventually(ready, "sensor readiness")
            record = {
                "eventName": "codex.user_prompt",
                "body": {"stringValue": "private-prompt-must-not-persist"},
                "attributes": [
                    {
                        "key": "prompt",
                        "value": {"stringValue": "private-prompt-must-not-persist"},
                    }
                ],
            }
            payload = {
                "resourceLogs": [
                    {
                        "resource": {
                            "attributes": [
                                {
                                    "key": "tenant.id",
                                    "value": {"stringValue": "spoofed-tenant"},
                                }
                            ]
                        },
                        "scopeLogs": [{"logRecords": [record]}],
                    }
                ]
            }
            logs_url = f"http://{receiver}/v1/logs"
            eventually(
                lambda: client.post(logs_url, content=b"bad json", headers={"Content-Type": "application/json"}).status_code == 400,
                "OTLP receiver readiness",
            )
            assert (
                client.post(logs_url, json=payload).status_code == 200
            )

            metrics = ExportMetricsServiceRequest()
            metric = metrics.resource_metrics.add().scope_metrics.add().metrics.add()
            metric.name = "claude_code.token.usage"
            metric.sum.aggregation_temporality = 1
            metric.sum.data_points.add(as_int=9007199254740993)
            response = client.post(
                f"http://{receiver}/v1/metrics",
                content=metrics.SerializeToString(),
                headers={"Content-Type": "application/x-protobuf"},
            )
            assert response.status_code == 200
            traces = ExportTraceServiceRequest()
            traces.resource_spans.add().scope_spans.add().spans.add(
                trace_id=bytes.fromhex("0123456789abcdef" * 2),
                span_id=bytes.fromhex("0123456789abcdef"),
                name="codex.tool_call",
                start_time_unix_nano=1700000000000000001,
                end_time_unix_nano=1700000000000000010,
            )
            assert (
                client.post(
                    f"http://{receiver}/v1/traces",
                    content=gzip.compress(traces.SerializeToString()),
                    headers={
                        "Authorization": "Bearer stale-agent-token",
                        "Content-Type": "application/x-protobuf",
                        "Content-Encoding": "gzip",
                    },
                ).status_code
                == 200
            )
            count = lambda: store.scalar("SELECT count(*) FROM telemetry_exports")
            eventually(lambda: count() == 2, "logs and metrics persisted")
            rows = store.many(
                "SELECT tenant_id,sensor_id,signal,payload FROM telemetry_exports"
            )
            assert {row["signal"] for row in rows} == {"logs", "metrics"}
            assert all(row["tenant_id"] == bootstrap["tenant_id"] for row in rows)
            assert all(row["sensor_id"] == config["sensor_id"] for row in rows)
            stored = json.dumps(rows)
            assert "private-prompt-must-not-persist" not in stored
            assert "9007199254740993" in stored
            assert "0123456789abcdef0123456789abcdef" not in stored
            eventually(
                lambda: (
                    client.get(status_url + "/v1/status", headers=headers).json()["telemetry"][
                        "queue_depth"
                    ]
                    == 0
                ),
                "initial exports acknowledged",
            )

            # Acknowledge locally while the tenant is unavailable, then crash.
            stop(server)
            assert (
                client.post(logs_url, json=payload).status_code == 200
            )
            queue_path = tmp_path / "data" / "telemetry.sqlite3"
            with sqlite3.connect(queue_path) as queue:
                queued = queue.execute(
                    "SELECT batch_id,body,content_type FROM exports"
                ).fetchone()
            assert queued is not None
            batch_id, body, content_type = queued
            assert b"private-prompt-must-not-persist" not in body
            sensor.kill()
            sensor.wait(timeout=5)
            sensor = launch(sensor_command, "run", "--config", str(config_path))
            eventually(ready, "sensor restarted offline")
            assert (
                client.get(status_url + "/v1/status", headers=headers).json()["telemetry"]["queue_depth"]
                == 1
            )
            server = launch(server_command, "serve")
            eventually(
                lambda: client.get(server_url + "/readyz").status_code == 200,
                "backend restarted",
            )
            eventually(lambda: count() == 3, "offline export recovered")
            eventually(
                lambda: (
                    client.get(status_url + "/v1/status", headers=headers).json()["telemetry"][
                        "queue_depth"
                    ]
                    == 0
                ),
                "queue drained",
            )
            retry = client.post(
                server_url + "/otlp/v1/logs",
                content=body,
                headers={
                    "Authorization": "Bearer " + config["sensor_token"],
                    "Content-Type": content_type,
                    "X-OpenAIDR-Batch-Id": batch_id,
                },
            )
            assert retry.status_code == 200
            assert retry.headers["X-OpenAIDR-Duplicate"] == "true"
            assert count() == 3
    finally:
        for process in reversed(processes):
            stop(process)
        for log in logs:
            log.close()
        store.close()
        with psycopg.connect(database, autocommit=True) as connection:
            connection.execute(f"DROP SCHEMA {schema} CASCADE")
