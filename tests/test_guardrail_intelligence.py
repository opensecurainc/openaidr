"""Selected-service HTTP boundaries with real tenant storage and local policy."""

from openaidr_api.providers import guardrail as provider_scoring

import asyncio
import json
from dataclasses import replace

import httpx
import pytest

from openaidr_api_client import client as intelligence
from openaidr.server import model_keys
from openaidr.server.config import Config
from openaidr.server.guardrail import scoring
from openaidr.server.guardrail.clients import AsyncGuardrailClients, BackgroundGuardrailClients
from openaidr_api_client.clients.guardrail import result
from test_store import db, tenant, sensor
from test_risk import reply
from test_risk_store import event
from test_hook_policy import system as hook_system
from test_inline_guardrail import system as inline_system
from test_gateways import system as gateway_system


TOKEN = "oati_" + "a" * 32 + "." + "b" * 43
USAGE = {"model": scoring.MODEL, "input_tokens": 2000, "output_tokens": 20}
STATE = {"target_event": {"kind": "command", "command": {"text": "git status"}}}


def assessed(score=0):
    return {**provider_scoring.parse_assessment(reply("none" if score == 0 else "secret_exfiltration", score / 25)),
            "usage": dict(USAGE)}


class Service:
    def __init__(self, cfg, tenant_id, monkeypatch):
        cfg.tenant_id = tenant_id
        cfg.intelligence_origin = "https://intelligence.example.test"
        cfg.intelligence_api_key = TOKEN
        self.cfg = cfg
        self.requests = []
        self.response = assessed()
        self.status = 200
        self.delay = 0
        original = intelligence.IntelligenceClient.__init__

        def initialize(client, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(self.handle)
            original(client, *args, **kwargs)

        monkeypatch.setattr(intelligence.IntelligenceClient, "__init__", initialize)

    async def handle(self, request):
        assert request.headers["authorization"] == "Bearer " + self.cfg.intelligence_api_key
        assert str(request.url) == self.cfg.intelligence_origin + "/v1/guardrail/assess"
        payload = json.loads(request.content)
        assert set(payload) == {"state", "company_policy", "timeout_ms"}
        assert 1 <= payload["timeout_ms"] <= 10000
        self.requests.append(payload)
        await asyncio.sleep(self.delay)
        return httpx.Response(self.status, json=self.response)


@pytest.mark.parametrize("mutation", [
    {"score": True}, {"score": float("nan")}, {"score": 101}, {"level": "critical"},
    {"category": "unknown"}, {"rubric_version": True}, {"rubric_version": 2},
    {"model": "other"}, {"assessed_at": "not a timestamp"}, {"assessed_at": "2026-10-26"},
    {"decision": "deny"}, {"status": "unscored"},
])
def test_untrusted_reply_cannot_add_a_decision_or_corrupt_score(mutation):
    with pytest.raises(scoring.JevError, match="invalid_response") as error:
        result({**assessed(), **mutation})
    assert error.value.usage == USAGE


def test_error_receipts_fractional_retry_and_unknown_usage_are_preserved():
    payload = {"status": "error", "reason": "provider_unavailable", "retryable": True,
               "retry_after": 30.125, "usage": dict(USAGE)}
    with pytest.raises(scoring.JevError) as caught:
        result(payload)
    assert caught.value.code == "provider_unavailable" and caught.value.retryable
    assert caught.value.retry_after == 30.125 and caught.value.usage == USAGE
    unknown = {"model": None, "input_tokens": None, "output_tokens": None}
    assert result({**assessed(), "usage": unknown})["usage"] == unknown
    invalid = {**assessed(), "usage": {**USAGE, "input_tokens": True}}
    with pytest.raises(scoring.JevError) as caught:
        result(invalid)
    assert caught.value.usage is None


def test_sync_async_and_background_pool_keep_identity_and_never_bypass(db, monkeypatch, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from test_intelligence_connection import certificate

    own, other = tenant(db)["id"], tenant(db)["id"]
    cfg = Config()
    service = Service(cfg, own, monkeypatch)
    monkeypatch.setattr(provider_scoring, "JevClient", lambda *_: pytest.fail("direct sync provider bypass"))
    monkeypatch.setattr(provider_scoring, "AsyncJevClient", lambda *_: pytest.fail("direct async provider bypass"))
    sync = model_keys.TenantGuardrailClient(db, own, cfg)
    assert sync.available() and sync.assess(STATE)["status"] == "scored"
    first_digest = sync.used_key_digest
    pool = BackgroundGuardrailClients()
    try:
        assert model_keys.TenantGuardrailClient(db, own, cfg, clients=pool).assess(STATE)["usage"] == USAGE
    finally:
        pool.close()

    async def exercise():
        clients = AsyncGuardrailClients()
        adapter = model_keys.TenantAsyncGuardrailClient(db, own, cfg, clients=clients)
        try:
            assert (await adapter.assess(STATE, timeout=.8))["status"] == "scored"
            assert service.requests[-1]["timeout_ms"] <= 800
            await adapter.assess(STATE)
            assert clients.created == 1 and clients.reused == 1
            cfg.intelligence_origin = "https://hosted.example.test"
            await adapter.assess(STATE)
            cfg.intelligence_api_key = TOKEN.replace("b", "c")
            await adapter.assess(STATE)
            assert clients.created == 3 and adapter.key_digest() != first_digest
            trust = tmp_path / "trust.pem"
            cfg.intelligence_ca_file = str(trust)
            for name in ("first authority", "rotated authority"):
                trust.write_bytes(certificate(name, ec.generate_private_key(ec.SECP256R1()))
                                  .public_bytes(serialization.Encoding.PEM))
                await adapter.assess(STATE)
            assert clients.created == 5
            foreign = model_keys.TenantAsyncGuardrailClient(db, other, cfg, clients=clients)
            assert not foreign.available()
            before = len(service.requests)
            with pytest.raises(scoring.JevError):
                await foreign.assess(STATE)
            with pytest.raises(scoring.JevError):
                await clients.assess(other, intelligence.Connection.from_config(cfg), STATE)
            assert len(service.requests) == before
            service.status = 503
            with pytest.raises(scoring.JevError, match="provider_unavailable"):
                await adapter.assess(STATE)
            service.status, service.delay = 200, .2
            with pytest.raises(scoring.JevError, match="connection_failed"):
                await adapter.assess(STATE, timeout=.01)
        finally:
            await clients.aclose()

    asyncio.run(exercise())
    legacy = replace(cfg, intelligence_origin="", intelligence_api_key="",
                     threat_intel_origin=cfg.intelligence_origin, threat_intel_api_key=cfg.intelligence_api_key)
    with pytest.raises(ValueError, match="Replace legacy"):
        model_keys.guardrail_credential(db, own, legacy)


def test_hooks_and_cowork_keep_local_shadow_enforce_and_failure_semantics(hook_system, monkeypatch):
    from test_hook_policy import browser, check, configure, payload, policy
    from test_cowork_server import connection, hook, native

    s = hook_system
    service = Service(s.cfg, s.tenant["id"], monkeypatch)
    s.cfg.jev_api_key = ""
    policy(s, "deny")
    shadow = check(s, payload())
    assert shadow["evaluated_decision"] == "deny" and shadow["returned_decision"] == "allow"
    configure(s, "enforce")
    denied = check(s, payload())
    assert denied["returned_decision"] == "deny" and denied["delivery_status"] == "unconfirmed"
    conn = connection(s)
    assert hook(s, conn, native()).json()["hookSpecificOutput"]["permissionDecision"] == "deny"
    # A classifier failure does not erase an independently valid static rule.
    service.status = 503
    assert check(s, payload())["returned_decision"] == "deny"
    policy(s, "allow")
    failed = check(s, payload())
    assert failed["returned_decision"] == "allow" and failed["assessment"]["status"] == "unavailable"
    assert hook(s, conn, native()).json() == {}
    assert not s.provider.requests
    assert s.db.scalar("SELECT count(*) FROM ordinary_hook_deliveries") == 0
    assert len(service.requests) == 6
    assert all(request["timeout_ms"] <= 10000 for request in service.requests)
    assert browser(s, "GET", "hook-decisions?classified=true").status_code == 200


def test_inline_selected_service_allows_denies_and_fails_open(inline_system, monkeypatch):
    from test_inline_guardrail import check, configure, managed, payload, policy

    s = inline_system
    service = Service(s.cfg, s.tenant["id"], monkeypatch)
    s.cfg.jev_api_key = ""
    configure(s, timeout_ms=500)
    policy(s)
    registration = managed(s)
    assert check(s, payload(s, registration))["decision"]["action"] == "allow"
    service.response = assessed(100)
    assert check(s, payload(s, registration))["decision"]["action"] == "block"
    service.response["decision"] = "deny"
    assert check(s, payload(s, registration))["decision"]["action"] == "allow"
    service.response, service.delay = assessed(100), .6
    assert check(s, payload(s, registration))["decision"]["action"] == "allow"
    assert not s.provider.requests
    assert all(request["timeout_ms"] <= 500 for request in service.requests)
    assert s.db.scalar("SELECT count(*) FROM model_usage WHERE input_tokens=2000") == 3


def test_gateway_selected_service_records_advice_separately_from_enforcement(gateway_system, monkeypatch):
    from test_gateways import create, settings, machine, payload, enable_risk

    s = gateway_system
    service = Service(s.cfg, s.tenant["id"], monkeypatch)
    s.cfg.jev_api_key = ""
    gateway, headers, _ = create(s)
    gateway = settings(s, gateway, capture_content=True)
    enable_risk(s)
    assert machine(s, "checks", headers, payload()).json()["returned_decision"] == "allow"
    service.response = assessed(100)
    shadow = machine(s, "checks", headers, payload()).json()
    assert shadow["evaluated_decision"] == "deny" and shadow["returned_decision"] == "allow"
    settings(s, gateway, mode="enforce")
    denied = machine(s, "checks", headers, payload()).json()
    assert denied["evaluated_decision"] == denied["returned_decision"] == "deny"
    service.status = 503
    request = payload()
    failed = machine(s, "checks", headers, request)
    assert failed.status_code == 503
    stored = s.db.one("SELECT * FROM gateway_requests WHERE request_id=$1", request["request_id"])
    assert stored["status"] == "unavailable" and stored["returned_decision"] is None
    assert not s.provider.requests
    assert all(request["timeout_ms"] < 2000 for request in service.requests)


def test_background_scoring_needs_no_local_guardrail_key(db, monkeypatch):
    own = tenant(db)["id"]
    cfg = Config()
    service = Service(cfg, own, monkeypatch)
    monkeypatch.setattr(provider_scoring, "JevClient", lambda *_: pytest.fail("direct sync provider bypass"))
    monkeypatch.setattr(provider_scoring, "AsyncJevClient", lambda *_: pytest.fail("direct async provider bypass"))
    source, _, _ = sensor(db, own)
    evidence = event()
    db.ingest_batch(source, [evidence])
    worker = scoring.RiskWorker(db, None, own,
        client_for_tenant=lambda tid: model_keys.TenantGuardrailClient(db, tid, cfg))
    assert worker.tick() and db.get_event(own, evidence["id"])["risk"]["status"] == "scored"
    rejected = event()
    db.ingest_batch(source, [rejected])
    service.response = {"status": "error", "reason": "authentication_failed", "retryable": True,
                        "retry_after": 30.125, "usage": dict(USAGE)}
    assert worker.tick()
    assert worker.blocked_keys[own] == model_keys.TenantGuardrailClient(db, own, cfg).key_digest()
    receipt = db.one("SELECT * FROM model_usage WHERE event_id=$1", rejected["id"])
    assert receipt["status"] == "error" and receipt["input_tokens"] == USAGE["input_tokens"]
    service.cfg.intelligence_origin = "https://replacement.example.test"
    service.response = assessed()
    next_event = event()
    db.ingest_batch(source, [next_event])
    assert worker.tick() and not worker.blocked_keys
    assert db.get_event(own, next_event["id"])["risk"]["status"] == "scored"
