"""Native Cursor deltas through ingestion, retry, retention and tenant reports."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import time

import pytest
from fastapi.testclient import TestClient

from openaidr.core.telemetry import encode_export
from openaidr.server import cursor_costs, telemetry_retention
from openaidr.server.agent_cost_usage import process_pending
from openaidr.server.app import create_app
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server.store import new_id
from test_telemetry_server import backend  # noqa: F401


def payload():
    end = time.time_ns() - 2 * 10**9
    point = dict(timeUnixNano=str(end), startTimeUnixNano=str(end - 60 * 10**9), asDouble=0.25,
                 attributes=[dict(key="cursor.model.name", value=dict(stringValue="Auto"))])
    return dict(resourceMetrics=[dict(
        resource=dict(attributes=[dict(key="service.name", value=dict(stringValue="cursor")),
                                  dict(key="cursor.team.id", value=dict(intValue="42")),
                                  dict(key="cursor.user.email", value=dict(stringValue="private@example.com"))]),
        scopeMetrics=[dict(scope=dict(name="cursor.telemetry"), metrics=[dict(
            name="cursor.cost.usage", unit="USD", sum=dict(isMonotonic=True, aggregationTemporality=1,
                dataPoints=[point, deepcopy(point)]))])])])


def test_cursor_deltas_retry_retention_and_reports(backend):
    st, cfg, sensor, token, other, other_token, _ = backend
    tenant = sensor["tenant_id"]
    batch = new_id()
    body = encode_export("metrics", payload(), "application/x-protobuf")
    headers = {"Authorization": "Bearer " + token, "X-OpenAIDR-Batch-Id": batch,
               "Content-Type": "application/x-protobuf"}
    # Start with retained telemetry on the previous schema, then apply the
    # additive projection without resetting existing request accounting.
    st.execute("DROP TABLE cursor_cost_points")
    st.execute("DROP INDEX telemetry_exports_cursor_cost_pending,telemetry_exports_cursor_cost_tenant_pending")
    st.execute("DELETE FROM schema_migrations WHERE version=117")
    with TestClient(create_app(cfg, st)) as client:
        assert client.post("/otlp/v1/metrics", content=body, headers={**headers, "Authorization": "Bearer " + other_token}).status_code == 403
        assert client.post("/otlp/v1/metrics", content=body).status_code == 401
        for _ in range(2):
            result = client.post("/otlp/v1/metrics", content=body, headers=headers)
            assert result.status_code == 200, result.text
        assert st.migrate() == ["0117_cursor_cost_metrics.sql"]
        assert st.migrate() == []
        assert cursor_costs.overview(st, tenant)["pending_exports"] == 1
        assert cursor_costs.overview(st, tenant)["items"] == []
        day = st.scalar("SELECT storage_day FROM telemetry_exports WHERE batch_id=$1", batch)
        # Isolate the new accounting retention guard from summary backfill.
        st.execute("UPDATE telemetry_exports SET resource_summary='{}'::jsonb WHERE batch_id=$1", batch)
        with st.transaction() as conn:
            assert telemetry_retention._drop(st, tenant, day, conn) is False
        st.execute("""CREATE FUNCTION fail_cursor_projection() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'test projection failure'; END $$""")
        st.execute("CREATE TRIGGER fail_cursor_projection BEFORE INSERT ON cursor_cost_points FOR EACH ROW EXECUTE FUNCTION fail_cursor_projection()")
        assert process_pending(st) == {"exports": 0, "failed": 1}
        assert st.scalar("SELECT count(*) FROM cursor_cost_points") == 0
        assert st.scalar("SELECT costs_retry_at IS NOT NULL FROM telemetry_exports WHERE batch_id=$1", batch)
        st.execute("DROP TRIGGER fail_cursor_projection ON cursor_cost_points")
        st.execute("UPDATE telemetry_exports SET costs_retry_at=NULL WHERE batch_id=$1", batch)
        assert process_pending(st) == {"exports": 1, "failed": 0}
        row, = cursor_costs.overview(st, tenant)["items"]
        assert row["points"] == 2 and row["estimated_usd"] == "0.50"
        assert row["team_id"] == 42 and row["model"] == "Auto"
        assert st.scalar("SELECT count(*) FROM agent_cost_records") == 0
        assert cursor_costs.overview(st, other["tenant_id"])["items"] == []
        st.execute("UPDATE telemetry_exports SET costs_processed_at=NULL WHERE batch_id=$1", batch)
        assert process_pending(st)["failed"] == 0
        assert cursor_costs.overview(st, tenant)["items"][0]["estimated_usd"] == "0.50"
        with st.transaction() as conn:
            assert telemetry_retention._drop(st, tenant, day, conn)
        st.execute("DELETE FROM telemetry_export_keys WHERE batch_id=$1", batch)
        # Allow this test's current-day partition to be created again after
        # explicitly retiring it; production retention removes only old days.
        st.execute("DELETE FROM telemetry_partition_days WHERE tenant_id=$1 AND storage_day=$2", tenant, day)
        assert client.post("/otlp/v1/metrics", content=body, headers=headers).status_code == 200
        assert process_pending(st)["failed"] == 0
        assert cursor_costs.overview(st, tenant)["items"][0]["estimated_usd"] == "0.50"
        enrollment = st.bootstrap_tenant("Company A", "company-a")
        mirror, mirror_token, _ = st.enroll_sensor({"enrollment_token": enrollment["enrollment_token"], "hostname": "mirror"})
        assert client.post("/otlp/v1/metrics", content=body, headers={**headers, "Authorization": "Bearer " + mirror_token}).status_code == 200
        assert process_pending(st)["failed"] == 0
        rows = cursor_costs.overview(st, tenant)["items"]
        assert len(rows) == 2 and {str(r["sensor_id"]) for r in rows} == {sensor["id"], mirror["id"]}
        assert all(r["estimated_usd"] == "0.50" for r in rows)
    cfg.set_services("api")
    with TestClient(create_app(cfg, st)) as client:
        path = "/api/v1/costs/cursor-estimates"
        assert client.get(path).status_code == 401
        for role, code in (("analyst", 403), ("owner", 200)):
            user = st.create_user(tenant, role + "@example.com", role, "unused", role)
            client.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], tenant))
            response = client.get(path)
            assert response.status_code == code, response.text
        assert response.json()["corrections_applied"] is False
        assert "private@example.com" not in response.text
        for window, days in [("24h", 1), ("7d", 7), ("30d", 30)]:
            response = client.get(path + "?range=" + window)
            assert response.status_code == 200
            data = response.json()
            assert data["range"] == window
            assert datetime.fromisoformat(data["until"]) - datetime.fromisoformat(data["since"]) == timedelta(days=days)
            assert len(data["items"]) == 2
            assert all(row["estimated_usd"] == "0.50" for row in data["items"])
        assert client.get(path + "?range=90d").status_code == 400
        assert client.get(path + "?range=all").status_code == 400
        foreign = st.create_user(other["tenant_id"], "owner@other.com", "Other", "unused", "owner")
        client.cookies.set(CONSOLE_COOKIE, st.create_session(foreign["id"], other["tenant_id"]))
        assert client.get(path).status_code == 403


@pytest.mark.parametrize("case", ["zero", "cumulative", "unit", "missing", "negative", "flagged", "old", "future", "unknown_start"])
def test_only_supported_usd_deltas_become_estimates(case):
    data = payload()
    metric = data["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]
    point = metric["sum"]["dataPoints"][0]
    metric["sum"]["dataPoints"] = [point]
    if case == "zero":
        point["asDouble"] = 0
    elif case == "cumulative":
        metric["sum"]["aggregationTemporality"] = 2
    elif case == "unit":
        metric["unit"] = "cents"
    elif case == "missing":
        del point["asDouble"]
    elif case == "negative":
        point["asDouble"] = -1
    elif case == "flagged":
        point["flags"] = 1
    elif case in ("old", "future"):
        point["timeUnixNano"] = str(time.time_ns() + (3600 if case == "future" else -31 * 86400) * 10**9)
        point.pop("startTimeUnixNano")
    else:
        point.pop("startTimeUnixNano")
    rows = list(cursor_costs.points(dict(id="export", batch_id="batch", sensor_id="sensor", tenant_id="tenant",
                                        payload=data, received_at=datetime.now(timezone.utc))))
    assert len(rows) == (1 if case in ("zero", "unknown_start") else 0)
    if case == "zero":
        assert rows[0][-1] == 0
