"""Tenant persistence and billing through the authenticated application receiver."""

import asyncio
from decimal import Decimal
import json
from uuid import uuid4

import httpx
import pytest

from openaidr_api.threat_intel import keys
from openaidr.server import application_classifier as classifier
from openaidr_api_client.client import IntelligenceClient, Unavailable
from test_app_inventory_server import inventory
from intelligence_service_fixtures import application_service as service
from test_application_classification import app, post, snapshot, REVIEW, response


@pytest.fixture
def connected(inventory, service, tmp_path, monkeypatch):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    tenant = sensor["tenant_id"]
    path = tmp_path / "tenant.key"
    key_id = keys.issue(service.db, tenant, path)
    cfg.tenant_id = tenant
    cfg.intelligence_origin = "https://intelligence.example.test"
    cfg.intelligence_api_key = path.read_text().strip()
    cfg.openai_api_key = ""
    requests, mutation = [], {}
    upstream = httpx.ASGITransport(app=service.app)
    original = IntelligenceClient.from_connection

    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            requests.append(request)
            result = await upstream.handle_async_request(request)
            body = await result.aread()
            if mutation:
                value = json.loads(body)
                for key, val in mutation.items():
                    if key == "stale_claim":
                        st.execute("UPDATE application_classifications SET claim_token=$1", str(uuid4()))
                    else:
                        value[key] = val
                return httpx.Response(result.status_code, json=value)
            return httpx.Response(result.status_code, content=body, headers=result.headers)

    monkeypatch.setattr(IntelligenceClient, "from_connection", classmethod(
        lambda cls, connection: original(connection, transport=Transport())))
    service.provider.body = response()
    assert post(client, token, snapshot([app("opencode", name="OpenCode")])).status_code == 200
    return st, cfg, client, sensor, token, key_id, requests, mutation, service


@pytest.mark.parametrize("variant", ["completed", "parse_error", "unknown_usage", "timeout", "revoked", "bad_binding", "bad_receipt", "bad_result", "stale_claim"])
def test_selected_service_preserves_tenant_projection_fencing_and_costs(connected, variant):
    st, cfg, client, sensor, token, key_id, requests, mutation, service = connected
    tenant = sensor["tenant_id"]
    if variant == "parse_error":
        service.provider.body = response(sources=["https://uncited.example/"])
    elif variant == "unknown_usage":
        del service.provider.body["usage"]
    elif variant == "timeout":
        service.provider.error = httpx.ReadTimeout("private detail")
    elif variant == "revoked":
        assert keys.revoke(service.db, key_id)
    elif variant == "bad_binding":
        mutation["evidence_hash"] = "0" * 64
    elif variant == "bad_receipt":
        mutation["usage"] = {"answer": "private answer body"}
    elif variant == "bad_result":
        mutation["result"] = {"needs_attention": False}
    elif variant == "stale_claim":
        mutation["stale_claim"] = True
    assert not cfg.openai_api_key
    assert client.get(REVIEW).json()["classifier_configured"] is True
    assert asyncio.run(classifier.run_once(st, cfg, tenant))
    assert len(requests) == 1 and requests[0].url.path == "/v1/apps/assess"
    forwarded = json.loads(requests[0].content)
    assert set(forwarded) == {"evidence", "evidence_hash"}
    assert all(set(row) == {"name", "publisher", "ecosystem", "source", "identifier"} for row in forwarded["evidence"])
    assert all(value not in json.dumps(forwarded) for value in ("/opt", "first", tenant))
    stored = st.one("SELECT * FROM application_classifications WHERE tenant_id=$1", tenant)
    billed = st.one("SELECT * FROM model_usage WHERE purpose='asset_management'")
    assert billed["tenant_id"] == tenant
    succeeded = variant in ("completed", "unknown_usage", "stale_claim")
    assert billed["status"] == ("completed" if succeeded else "error")
    known = variant in ("completed", "parse_error", "bad_result", "stale_claim")
    assert billed["cost_usd"] == (Decimal("0.0100655") if known else None)
    assert billed["input_tokens"] == (200 if known else None)
    if variant in ("completed", "unknown_usage"):
        assert stored["needs_attention"] and stored["assessment"]["capability_score"] == 75
        assert stored["sources"] == ["https://example.test/product"]
        assert stored["claim_token"] is None and not stored["last_error"]
        row = client.get(REVIEW).json()["items"][0]
        assert row["approval_status"] == "monitoring" and row["classification_status"] == "complete"
    else:
        assert stored["checked_at"] is None and stored["assessment"] is None
        if variant != "stale_claim":
            assert stored["last_error"] == "classification_unavailable" and stored["claim_token"] is None
    assert len(service.provider.requests) == (0 if variant == "revoked" else 1)
    assert st.scalar("SELECT count(*) FROM model_usage") == 1


@pytest.mark.parametrize("limit", ["provider", "service"])
def test_service_tenant_binding_and_rate_backoff_apply_before_claims(connected, limit):
    st, cfg, client, sensor, token, _, requests, _, service = connected
    assert not asyncio.run(classifier.run_once(st, cfg, str(uuid4())))
    assert not requests and st.scalar("SELECT count(*) FROM application_classifications") == 0
    tenant = sensor["tenant_id"]
    post(client, token, snapshot([app("one"), app("two"), app("three")], offset=1))
    service.provider.status, service.provider.text = 429, "private provider rate limit"
    service.provider.headers = {"retry-after": "7200"}
    admission = service.app.state.apps_admission
    if limit == "service":
        assert all(admission.enter(tenant) for _ in range(8))

    async def exercise():
        cooldowns = {}
        assert await classifier.run_once(st, cfg, tenant, cooldowns)
        assert len(cooldowns) == 1
        assert next(iter(cooldowns.values())) > asyncio.get_running_loop().time() + (7000 if limit == "provider" else 50)
        assert all(cfg.intelligence_api_key not in key for key in cooldowns)
        assert not await classifier.run_once(st, cfg, tenant, cooldowns)
        assert st.scalar("SELECT count(*) FROM application_classifications WHERE claim_token IS NOT NULL") == 0
        assert st.scalar("SELECT count(*) FROM application_classifications WHERE last_error=''") == 2
    try:
        asyncio.run(exercise())
    finally:
        if limit == "service":
            for _ in range(8):
                admission.leave(tenant)
    assert len(requests) == 1 and len(service.provider.requests) == (1 if limit == "provider" else 0)


def test_selected_service_capacity_is_limited_before_leases(connected, monkeypatch):
    st, cfg, client, sensor, token, _, requests, _, service = connected
    cfg.application_classification_concurrency = 100
    post(client, token, snapshot([app(f"app-{i}") for i in range(12)], offset=1))
    classifier.refresh_inventory(st, sensor["tenant_id"])
    original = IntelligenceClient.request
    entered = 0

    async def exercise():
        nonlocal entered
        gate, all_entered, stop = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def wait_at_service(self, *args):
            nonlocal entered
            entered += 1
            if entered == 8:
                all_entered.set()
            await gate.wait()
            return await original(self, *args)
        monkeypatch.setattr(IntelligenceClient, "request", wait_at_service)
        running = asyncio.create_task(classifier.run(st, cfg, stop))
        try:
            await asyncio.wait_for(all_entered.wait(), 5)
            assert st.scalar("SELECT count(*) FROM application_classifications WHERE claim_token IS NOT NULL") == 8
            assert st.scalar("SELECT count(*) FROM model_usage") == 8
            stop.set()
        finally:
            stop.set()
            gate.set()
            await asyncio.wait_for(running, 10)
        assert entered == 8
    asyncio.run(exercise())
    assert len(requests) == 8 and len(service.provider.requests) == 8


def test_legacy_threat_only_connection_cannot_admit_application_work(inventory, monkeypatch):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    cfg.tenant_id = sensor["tenant_id"]
    cfg.threat_intel_origin = "https://legacy.example.test"
    cfg.threat_intel_api_key = "oati_" + "a" * 32 + "." + "b" * 43
    cfg.openai_api_key = "private-direct-key"
    cfg.intelligence_origin = cfg.intelligence_api_key = ""
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", lambda *args:
                        pytest.fail("Legacy credentials must not admit provider work"))
    with pytest.raises(ValueError, match="legacy threat-only"):
        asyncio.run(classifier.run_once(st, cfg, sensor["tenant_id"]))
    assert st.scalar("SELECT count(*) FROM model_usage") == 0


@pytest.mark.parametrize("header,expected", [("7200", "7200"), ("x" * 81, None)])
def test_transport_retains_bounded_retry_metadata_without_error_bodies(header, expected):
    requests = []
    def provider(request):
        requests.append(request)
        return httpx.Response(429, text="private error body", headers={"Retry-After": header})
    async def exercise():
        client = IntelligenceClient("https://intelligence.example.test", "oati_" + "a" * 32 + "." + "b" * 43,
                                    str(uuid4()), transport=httpx.MockTransport(provider))
        try:
            with pytest.raises(Unavailable) as error:
                await client.request("/v1/apps/assess", {}, 1024, 1)
            assert error.value.status_code == 429 and error.value.retry_after == expected
            assert "private" not in str(error.value) and len(requests) == 1
        finally:
            await client.aclose()
    asyncio.run(exercise())
