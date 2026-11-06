from openaidr.server.database_diagnostics import deltas, query_label, QUERY_COUNTERS, TABLES
from openaidr.server.config import Config
import pytest


def test_counter_resets_missing_baselines_and_safe_query_labels():
    original = dict(calls=10, total_exec_time=20, shared_blks_hit=40, shared_blks_read=2)
    current = dict(calls=12, total_exec_time=25, shared_blks_hit=50, shared_blks_read=2)
    measured, skipped = deltas({"same": original, "reset": original},
                               {"same": current, "reset": {**current, "calls": 1}, "new": current}, QUERY_COUNTERS)
    assert measured == [dict(calls=2, total_exec_time=5, shared_blks_hit=10, shared_blks_read=0)]
    assert skipped == 2
    assert query_label("UPDATE agents SET first_seen=$1,last_seen=$2") == "Update agent statistics"
    assert query_label("UPDATE events SET risk=$1 WHERE id IN (SELECT id FROM risk_assessment_usage)") == "Claim risk assessment work"
    for statement, label in [("SELECT 'secret'", "Read query"), ("ALTER USER alice PASSWORD 'secret'", "Other statement"),
                             ("/* secret */ SELECT 1", "Other statement"), (None, "Other statement")]:
        assert query_label(statement) == label
    assert TABLES.fullmatch("events_" + "a" * 32 + "_20261007")
    assert not TABLES.fullmatch("customer_private_data")


def test_diagnostics_configuration_requires_a_bound_tenant():
    config = Config(database_url="postgresql://localhost/test", database_diagnostics=True)
    config.set_services("api")
    with pytest.raises(ValueError, match="tenant-bound"):
        config.validate()
    config.validate(allow_unbound=True)
    config.tenant_id = "01000000-0000-7000-8000-000000000001"
    config.validate()


def test_source_headers_are_allowlisted_and_route_values_are_removed():
    from openaidr.server.query_sources import request_source

    source = request_source("GET", "/api/v1/sessions/private-record/detection?token=secret", {
        "x-openaidr-page": "/administration/server", "x-openaidr-card": "database-health",
    })
    assert source.page == "Server Health" and source.card == "Database health"
    assert source.endpoint == "GET /api/v1/sessions/:id/detection"
    for page in ("/administration/app", "/administration/sensors"):
        source = request_source("GET", "/api/v1/sensors/health", {"x-openaidr-page": page})
        assert source.page == "App Health"
    for page in ("/costs/openaidr", "/costs/detections"):
        source = request_source("GET", "/api/v1/costs/detections", {"x-openaidr-page": page})
        assert source.page == "Credits & Usage"
    for headers in ({}, {"x-openaidr-page": "/private-name?token=secret", "x-openaidr-card": "secret"}):
        source = request_source("GET", "/api/v1/users/private-name", headers)
        assert not source.page and not source.card
        assert "private-name" not in source.endpoint
    source = request_source("POST", "/ingest/v1/events", {
        "x-openaidr-page": "/administration/server", "x-openaidr-card": "database-health",
    })
    assert not source.page and not source.card


def test_source_window_expiry_limits_and_failed_calls(monkeypatch):
    from openaidr.server import query_sources as sources

    clock = [1000.0]
    monkeypatch.setattr(sources, "monotonic", lambda: clock[0])
    monkeypatch.setattr(sources, "MAX_OBSERVATIONS", 3)
    collector = sources.QuerySources()
    first, second = sources.Source(page="Overview"), sources.Source(job="Risk assessment")
    assert not collector.active()
    assert collector.read()["items"] == []
    for source, failed in ((first, False), (second, False), (first, True)):
        collector.record("app:test", "Read query", source, 10, failed, clock[0])
    rows = collector.read()["items"]
    assert [(r["calls"], r["failures"], r["total_time_ms"]) for r in rows] == [(2, 1, 20), (1, 0, 10)]
    collector.record("app:test", "Read query", second, 10, False, clock[0])
    assert collector.read()["dropped_observations"] == 1
    with collector.lock:
        collector.record("app:test", "Read query", second, 10, False, clock[0])
    assert collector.read()["status"] == "limited"
    # Keep the lease alive while every observation ages out of the window.
    for _ in range(7):
        clock[0] += 50
        result = collector.read()
    assert not result["items"] and result["window_seconds"] == 300
    clock[0] += 61
    assert not collector.active()
    assert collector.read()["dropped_observations"] == 0
    collector.record("app:old", "Read query", first, 999, False, 1000)
    assert not collector.read()["items"]
    collector.clear()
    assert not collector.active()
