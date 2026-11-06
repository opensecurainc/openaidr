"""Customer credit reads preserve tenant scope and never expose provider costs."""

from contextlib import closing
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from openaidr_api_client.client import SyncIntelligenceClient
from openaidr.server import auth, credits
from openaidr.server.app import create_app
from openaidr.server.store import new_id
from test_model_keys import settings_system  # noqa: F401
from test_store import db  # noqa: F401


def snapshot(tenant, *, status="active"):
    until = datetime.now(timezone.utc).replace(microsecond=0)
    summary = {"credits_charged": "0.025000", "operations": 2,
               "pending_operations": 1, "unrated_operations": 0}
    return {
        "schema_version": 1, "tenant_id": tenant, "status": status,
        "rate_version": "test-rate-v1", "credits_per_usd": "100",
        "since": (until - timedelta(days=30)).isoformat(), "until": until.isoformat(),
        "bucket_seconds": 86400,
        "balance": {"available": "99.965000", "reserved": "0.010000"},
        "summary": summary,
        "by_service": [{"service": "guardrail", **summary}],
        "series": [{"time": until.replace(hour=0, minute=0, second=0).isoformat(),
                    **summary, "by_service": [{"service": "guardrail", **summary}]}],
    }


def configured(system):
    return replace(system.cfg, intelligence_origin="https://intelligence.example.com",
                   intelligence_api_key="oati_" + "a" * 32 + "." + "b" * 43)


def connect(monkeypatch, handler):
    monkeypatch.setattr(credits, "SyncIntelligenceClient", SimpleNamespace(from_connection=lambda connection:
                        SyncIntelligenceClient.from_connection(connection, transport=httpx.MockTransport(handler))))


def test_credit_reads_enforce_roles_tenant_and_range_without_repricing_history(settings_system, monkeypatch):
    s = settings_system
    cfg = configured(s)
    value = snapshot(cfg.tenant_id)
    received = []
    s.db.execute("""INSERT INTO model_usage(id,tenant_id,attempt,purpose,provider,model,cost_usd)
                  VALUES($1,$2,1,'assistant','private-provider','private-model',3.25)""", new_id(), cfg.tenant_id)

    def receiver(request):
        assert request.method == "GET" and request.url.path == "/v1/credits"
        assert dict(request.url.params) == {"range": "30d"}
        assert request.headers["authorization"] == "Bearer " + cfg.intelligence_api_key
        received.append(request)
        return httpx.Response(200, json=value)

    connect(monkeypatch, receiver)
    analyst = s.db.create_user(cfg.tenant_id, "analyst@example.test", "Analyst", "unused", "analyst")
    analyst_cookie = {"Cookie": auth.CONSOLE_COOKIE + "=" + s.db.create_session(analyst["id"], cfg.tenant_id)}
    path = "/api/v1/credits?range=30d"
    with closing(TestClient(create_app(cfg, s.db))) as client:
        assert client.get(path).status_code == 401
        assert client.get(path, headers=analyst_cookie).status_code == 403
        assert client.get("/api/v1/credits?range=7d", headers=s.headers["admin"]).status_code == 400
        assert received == []
        for role in ("admin", "viewer"):
            result = client.get(path, headers=s.headers[role])
            assert result.status_code == 200 and result.headers["cache-control"] == "no-store"
            assert result.json() == value
            assert "private-provider" not in result.text and "private-model" not in result.text
            assert "cost_usd" not in result.text and "tokens" not in result.text
    assert len(received) == 2
    assert s.db.scalar("SELECT cost_usd FROM model_usage WHERE tenant_id=$1", cfg.tenant_id) == 3.25
    assert s.db.scalar("SELECT count(*) FROM model_usage WHERE tenant_id=$1", cfg.tenant_id) == 1


def test_credit_failures_are_unavailable_without_private_error_or_local_cost_fallback(settings_system, monkeypatch):
    s = settings_system
    cfg = configured(s)
    valid = snapshot(cfg.tenant_id)
    other = {**valid, "tenant_id": new_id()}
    private = {**valid, "provider": "private-provider", "model": "private-model", "cost_usd": "1.25"}
    bad_amount = deepcopy(valid)
    bad_amount["balance"]["available"] = "NaN"
    replies = [httpx.Response(200, json=other), httpx.Response(200, json=private),
               httpx.Response(200, json=bad_amount),
               httpx.Response(302, headers={"Location": "https://other.example.com"}),
               httpx.Response(503, json={"error": cfg.intelligence_api_key})]
    connect(monkeypatch, lambda request: replies.pop(0))
    with closing(TestClient(create_app(cfg, s.db))) as client:
        for _ in range(len(replies)):
            response = client.get("/api/v1/credits?range=30d", headers=s.headers["admin"])
            result = response.json()
            assert response.status_code == 200 and result["status"] == "unavailable"
            assert result["tenant_id"] == cfg.tenant_id
            assert result["balance"] == {"available": None, "reserved": None}
            assert result["summary"]["credits_charged"] is None
            assert result["by_service"] == result["series"] == []
            assert cfg.intelligence_api_key not in response.text and "private-" not in response.text


def test_missing_or_mismatched_connection_never_requests_customer_credit(settings_system, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("An unavailable or mismatched connection made an API call")

    connect(monkeypatch, unexpected)
    s = settings_system
    with closing(TestClient(create_app(s.cfg, s.db))) as client:
        response = client.get("/api/v1/credits", headers=s.headers["admin"])
        assert response.status_code == 200 and response.json()["status"] == "unavailable"
    assert credits.overview(new_id(), configured(s))["status"] == "unavailable"
