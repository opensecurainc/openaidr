"""Desktop alert bridge preserves identity and never accepts execution parameters."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from openaidr.sensor import bridge, usage
from openaidr.sensor.config import Config
from openaidr.sensor.telemetry import ExportQueue


@pytest.mark.parametrize("connection_field", ["server_url", "tenant_id", "sensor_id"])
def test_alert_bridge_transport_receipts_and_connection_switch(tmp_path, monkeypatch, connection_field):
    cfg = Config(tmp_path / "sensor.yaml", server_url="https://tenant.example", sensor_id=str(uuid4()),
                 tenant_id=str(uuid4()), sensor_token="test-token", data_dir=str(tmp_path / "data"))
    cfg.save()
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope=usage.identity(cfg))
    with queue.db:
        queue.db.execute("INSERT INTO usage_calls VALUES (?,?,?,?,?,?,?)",
                         (queue.usage_scope, "local", (datetime.now(timezone.utc) - timedelta(seconds=1)).timestamp(),
                          "model", "unknown", 1200, .1))
    queue.close()
    totals = usage.overview(cfg, 30)["summary"]
    ident = str(uuid4())
    row = {"id": ident, "title": "Upgrade LiteLLM", "message": "Use the project environment.",
           "command": 'python -m pip install --upgrade "litellm==1.106.2"',
           "created_at": "2026-10-22T10:00:00Z", "expires_at": "2026-11-21T10:00:00Z",
           "received_at": None, "acknowledged_at": None}
    requests = []
    state = {"code": 200, "body": {"items": [row]}}

    def server(request):
        assert request.headers["authorization"] == "Bearer test-token"
        requests.append((request.url.path, json.loads(request.content)))
        return httpx.Response(state["code"], json=state["body"])

    original = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(server)))

    def call(action, **params):
        return bridge.handle({"action": action, "config_path": str(cfg.path), "params": params})

    inbox = call("alerts.list")
    assert inbox["supported"] and inbox["items"][0]["command"] == row["command"]
    assert "test-token" not in json.dumps(inbox)
    assert requests == [("/ingest/v1/alerts", {})]
    state["body"] = {"items": [{"alert_id": ident, "received_at": row["created_at"], "acknowledged_at": None}]}
    call("alerts.received", ids=[ident], scope=inbox["scope"])
    call("alerts.acknowledge", id=ident, scope=inbox["scope"])
    assert requests[-2:] == [("/ingest/v1/alerts/received", {"ids": [ident]}),
                            (f"/ingest/v1/alerts/{ident}/acknowledge", {})]
    count = len(requests)
    for params in ({"id": "../../commands"}, {"id": ident, "command": "run me"}, {"id": ident, "scope": "wrong"}):
        with pytest.raises(ValueError):
            call("alerts.acknowledge", **({"scope": inbox["scope"]} | params))
    with pytest.raises(ValueError):
        call("alerts.list", server_url="https://foreign.example")
    cfg[connection_field] = "https://new.example" if connection_field == "server_url" else str(uuid4())
    cfg.save()
    for action, params in (("alerts.received", {"ids": [ident]}), ("alerts.acknowledge", {"id": ident})):
        with pytest.raises(ValueError, match="connection changed"):
            call(action, scope=inbox["scope"], **params)
    assert len(requests) == count
    assert usage.identity(cfg) != inbox["scope"]
    assert usage.overview(cfg, 30)["summary"] == totals
    state["code"] = 404
    assert call("alerts.list")["supported"] is False
    for code in (401, 403, 500):
        state["code"] = code
        with pytest.raises(ValueError, match="Could not update alerts"):
            call("alerts.list")
    state.update(code=200, body={"items": [{**row, "command": []}]})
    with pytest.raises(ValueError, match="Invalid alert inbox"):
        call("alerts.list")
