"""Real accounting and sensor-authenticated desktop usage boundaries."""

from datetime import timedelta, timezone
import json

from fastapi.testclient import TestClient
from psycopg.conninfo import conninfo_to_dict, make_conninfo
import pytest

from openaidr.core.telemetry import decode_export, encode_export
from openaidr.sensor import bridge
from openaidr.sensor.telemetry import Telemetry
from openaidr.server.agent_cost_usage import process_pending
from openaidr.server.desktop_usage import overview
from openaidr.server.store import Store, new_id
from test_telemetry_dashboard import dashboard, cost_payload  # noqa: F401
from test_telemetry_sensor import config as sensor_config


def report(st, sensor, effort, calls=20, model="example-model", when=None):
    when = when or st.scalar("SELECT now()") - timedelta(hours=1)
    attrs = {"model": model, "cost_usd": "0.25", "input_tokens": "100", "output_tokens": "50"}
    if effort is not None:
        attrs["effort"] = effort
    st.ingest_telemetry(sensor, "logs", new_id(), cost_payload("claude-code", when, [
        ("claude_code.api_request", {**attrs, "request_id": new_id()}) for _ in range(calls)
    ]), calls)


def test_desktop_usage_auth_accounting_and_company_cohort(dashboard):
    st, _, client, sensor, token, remote = dashboard
    headers = {"Authorization": "Bearer " + token}
    endpoint = "/ingest/v1/usage/summary"
    assert client.post(endpoint, json={"days": 30}).status_code == 401
    for params in ({"days": True}, {"days": 365}, {"sensor_id": remote["id"]}, {"tenant_id": remote["tenant_id"]}):
        assert client.post(endpoint, json=params, headers=headers).status_code == 400
    report(st, sensor, "high")
    report(st, sensor, None, calls=4)
    report(st, remote, "low", calls=100)
    assert process_pending(st)["failed"] == 0
    result = client.post(endpoint, json={"days": 30}, headers=headers)
    assert result.status_code == 200, result.text
    assert result.headers["cache-control"] == "no-store"
    result = result.json()
    assert result["summary"]["calls"] == 24
    assert result["summary"]["tokens"] == 3600
    assert result["summary"]["cost_usd"] == 6
    assert sum(day["tokens"] for day in result["series"]) == 3600
    assert len(result["series"]) == 30
    assert {row["name"]: row["calls"] for row in result["by_reasoning_effort"]} == {"high": 20, "unknown": 4}
    assert result["baseline"]["status"] == "insufficient_data"
    assert result["history_incomplete"] is False

    enrollment = st.create_enrollment_token(sensor["tenant_id"])
    for index in range(5):
        peer, _, _ = st.enroll_sensor({"enrollment_token": enrollment["token"], "hostname": f"peer-{index}"})
        report(st, peer, "medium", calls=4)
        assert process_pending(st)["failed"] == 0
        baseline = overview(st, sensor, 7)["baseline"]
        assert baseline["status"] == ("available" if index == 4 else "insufficient_data")
    assert baseline["own_high_share"] == 1
    assert baseline["company_high_share"] == 0
    assert baseline["peer_calls"] == 20 and baseline["peer_devices"] == 5
    assert baseline["own_coverage"] == 20 / 24
    assert "suggest_lower_effort" not in baseline
    st.execute("UPDATE agent_cost_records SET model='Unattributed' WHERE tenant_id=$1", sensor["tenant_id"])
    assert overview(st, sensor, 7)["baseline"]["status"] == "insufficient_data"

    # Migration 0051 backfills existing accounting on partitioned storage.
    st.execute("UPDATE agent_cost_records SET sensor_id=NULL WHERE tenant_id=$1", sensor["tenant_id"])
    assert overview(st, sensor, 30)["history_incomplete"] is True
    st.execute("ALTER TABLE agent_cost_records DROP COLUMN sensor_id, DROP COLUMN reasoning_effort")
    st.execute("DELETE FROM schema_migrations WHERE version=51")
    assert st.migrate() == ["0051_desktop_usage_effort.sql"]
    assert overview(st, sensor, 30)["summary"] == result["summary"]
    assert process_pending(st)["failed"] == 0
    restored = overview(st, sensor, 30)
    assert restored["summary"] == result["summary"]
    assert restored["by_reasoning_effort"] == result["by_reasoning_effort"]
    assert restored["history_incomplete"] is False
    st.execute("DELETE FROM telemetry_exports WHERE tenant_id=$1", sensor["tenant_id"])
    assert overview(st, sensor, 30)["summary"] == result["summary"]
    st.update_sensor(sensor["tenant_id"], sensor["id"], disabled=True)
    assert client.post(endpoint, json={"days": 7}, headers=headers).status_code == 403


def test_desktop_usage_keeps_utc_buckets_with_non_utc_database(dashboard):
    st, _, _, sensor, _, _ = dashboard
    today = st.scalar("SELECT now()").astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    for days in (7, 30):
        report(st, sensor, "high", calls=1, when=today - timedelta(days=days - 1) + timedelta(hours=1))
    assert process_pending(st)["failed"] == 0
    for zone in ("America/Los_Angeles", "Asia/Tokyo"):
        params = conninfo_to_dict(st.url)
        params["options"] += f" -c TimeZone={zone}"
        zoned = Store(make_conninfo(**params))
        try:
            assert zoned.scalar("SHOW TimeZone") == zone
            for days in (7, 30):
                result = overview(zoned, sensor, days)
                first = result["series"][0]
                assert first["date"] == (today - timedelta(days=days - 1)).date().isoformat()
                assert first["tokens"] == 150
                assert sum(day["tokens"] for day in result["series"]) == (150 if days == 7 else 300)
        finally:
            zoned.close()


@pytest.mark.parametrize("effort_key", ["reasoning_effort", "model_reasoning_effort"])
def test_effort_is_reported_per_request_and_unknown_stays_unpriced(dashboard, effort_key):
    st, _, _, sensor, _, _ = dashboard
    when = st.scalar("SELECT now()") - timedelta(hours=1)
    events = []
    for effort in ("low", "HIGH", "xhigh", "none", "auto", "future", "", "4000"):
        events.append(("codex.sse_event", {
            "event.kind": "response.completed", "model": "unknown-model", "response_id": new_id(),
            "input_token_count": "100", "output_token_count": "20", effort_key: effort,
            "reasoning_token_count": "10",
        }))
    st.ingest_telemetry(sensor, "logs", new_id(), cost_payload("codex", when, events), len(events))
    assert process_pending(st)["failed"] == 0
    result = overview(st, sensor, 7)
    assert result["summary"] == dict(calls=8, priced_calls=0, tokens=960, cost_usd=None)
    assert {row["name"]:row["calls"] for row in result["by_reasoning_effort"]} == {
        "low":1, "high":1, "xhigh":1, "none":1, "auto":1, "unknown":3,
    }


@pytest.mark.parametrize("media", ["application/json", "application/x-protobuf"])
def test_codex_native_event_names_reach_local_and_server_usage(dashboard, tmp_path, media):
    st, _, client, sensor, token, _ = dashboard
    when = st.scalar("SELECT now()") - timedelta(hours=1)
    attrs = {
        "event.kind": "response.completed", "model": "gpt-6-astra",
        "conversation.id": "codex-session", "model_reasoning_effort": "high",
        "input_token_count": "1000", "output_token_count": "200",
        "cached_token_count": "600", "cache_write_token_count": "100",
        "access_token": "credential-must-not-leave",
    }
    # Codex 0.161.0 emits a tracing source location in eventName, with its
    # semantic event name in event.name and numeric counters as strings.
    payload = cost_payload("codex-app-server", when, [
        *[("codex.sse_event", {**attrs, "model_reasoning_effort": effort})
          for effort in ["xhigh"] * 5 + ["low"] * 3],
        ("codex.sse_event", {**attrs, "event.kind": "response.output_text.delta"}),
        ("codex.sse_event", {**attrs, "input_token_count": "credential-must-not-leave"}),
    ], label="attribute")
    for item in payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]:
        item["eventName"] = "event otel/src/events/session_telemetry.rs:1105"
    reviews = cost_payload("codex-app-server", when, [
        ("codex.sse_event", {
            **attrs, "model": "codex-auto-review", "auth_mode": auth,
            "response_id": f"review-{index}",
        }) for index, auth in enumerate(("Chatgpt", "ApiKey", "Chatgpt"))
    ])["resourceLogs"]
    # Receipt time alone cannot establish eligibility for the free rate.
    del reviews[0]["scopeLogs"][0]["logRecords"][-1]["timeUnixNano"]
    payload["resourceLogs"] += reviews
    payload["resourceLogs"] += cost_payload("claude-code", when, [
        ("claude_code.api_request", {
            "model": "claude-opus-5-5", "input_tokens": "100",
            "output_tokens": "50", "cost_usd": "0.25",
        }) for _ in range(9)
    ])["resourceLogs"]

    cfg = sensor_config(tmp_path)
    cfg.update(sensor_id=sensor["id"], tenant_id=sensor["tenant_id"], sensor_token=token)
    cfg.save()
    telemetry = Telemetry(cfg)
    telemetry.http.close()
    telemetry.http = TestClient(client.app)
    try:
        packet = encode_export("logs", payload, media)
        # A rebatch of the same native records must not count usage twice.
        for _ in range(2):
            telemetry.accept("logs", packet, media)
            queued = telemetry.queue.next()
            clean = decode_export("logs", queued["body"], media)
            assert "credential-must-not-leave" not in json.dumps(clean)
            assert telemetry.forward_once()
            assert telemetry.queue.status()["queue_depth"] == 0
        local = bridge.handle({
            "action": "usage.summary", "config_path": str(cfg.path), "params": {"days": 7},
        })
    finally:
        telemetry.close()
    assert process_pending(st)["failed"] == 0
    response = client.post("/ingest/v1/usage/summary", json={"days": 7},
                           headers={"Authorization": "Bearer " + token})
    assert response.status_code == 200, response.text
    remote = response.json()
    assert (local["summary"]["calls"], remote["summary"]["calls"]) == (20, 20)
    for result in (local, remote):
        models = {row["name"]: row for row in result["by_model"]}
        assert models["gpt-6-astra"]["calls"] == 8
        assert models["gpt-6-astra"]["tokens"] == 9600
        assert models["gpt-6-astra"]["cost_usd"] == pytest.approx(.1188)
        assert models["claude-opus-5-5"]["calls"] == 9
        assert models["codex-auto-review"]["calls"] == 3
        assert models["codex-auto-review"]["priced_calls"] == 1
        assert models["codex-auto-review"]["cost_usd"] == 0
        assert models["codex-auto-review"]["tokens"] == 3600
        assert result["summary"]["priced_calls"] == 18
        assert result["summary"]["tokens"] == 14550
        efforts = {row["name"]: row for row in result["by_reasoning_effort"]}
        assert {name: row["calls"] for name, row in efforts.items()} == {"xhigh": 5, "low": 3, "high": 3, "unknown": 9}
        assert efforts["xhigh"]["cost_usd"] == pytest.approx(.07425)
        assert efforts["low"]["cost_usd"] == pytest.approx(.04455)
        assert efforts["unknown"]["cost_usd"] == pytest.approx(2.25)
    for endpoint in ("/api/v1/costs/agents", "/api/v1/costs/agents/summary"):
        result = client.get(endpoint, params={"model": "codex-auto-review"}).json()
        assert result["summary"]["calls"] == 3
        assert result["summary"]["priced_calls"] == 1
        assert result["summary"]["unpriced_calls"] == 2
        assert result["summary"]["cost_usd"] == 0
        assert result["summary"]["tokens"] == 3600
