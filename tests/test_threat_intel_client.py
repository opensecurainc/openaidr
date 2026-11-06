"""Gateway contract, tenant binding, and fail-open checks at HTTP boundaries."""

import asyncio
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import httpx
from openaidr_api.providers import web_risk as provider_links
import pytest
from fastapi.testclient import TestClient

from openaidr.server import hook_policy, malicious_links, osv
from openaidr_api_client.clients import threat_intel
from openaidr.server.app import create_app
from openaidr.server.config import Config, from_env
from test_store import db, sensor, tenant
from test_hook_policy import payload

ORIGIN = "https://intel.example.com"
TOKEN = "oati_" + "a" * 32 + "." + "b" * 43
TENANT = str(uuid4())
URL = "https://malware.example.com/"
QUERY = {"package": {"ecosystem": "npm", "name": "example"}, "version": "1.0.0"}


def url_result():
    stamp = datetime.now(timezone.utc)
    return {"provider": "google_web_risk", "status": "matched", "checked": 1, "skipped": 0, "failed": 0,
            "matches": [{"url": URL, "threat_types": ["MALWARE"], "expires_at": (stamp + timedelta(minutes=5)).isoformat()}],
            "reasons": [], "checked_at": stamp.isoformat()}


def package_result():
    stamp = datetime.now(timezone.utc) - timedelta(hours=23)
    return {"provider": "OSV", "results": [{"query": QUERY, "status": "complete", "findings": [],
            "checked_at": stamp.isoformat(), "expires_at": (stamp + osv.REFRESH).isoformat(), "reason": ""}]}


def client(handler, tenant_id=TENANT):
    return threat_intel.ThreatIntelClient(ORIGIN, TOKEN, tenant_id, transport=httpx.MockTransport(handler))


def test_configuration_is_complete_tenant_bound_and_uses_secret_files(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAIDR_THREAT_INTEL_API_KEY", raising=False)
    monkeypatch.delenv("OPENAIDR_THREAT_INTEL_API_KEY_FILE", raising=False)
    monkeypatch.delenv("OPENAIDR_THREAT_INTEL_ORIGIN", raising=False)
    assert not from_env().threat_intel_origin and not from_env().threat_intel_api_key
    secret = tmp_path / "key"
    secret.write_text(TOKEN + "\n")
    monkeypatch.setenv("OPENAIDR_THREAT_INTEL_API_KEY_FILE", str(secret))
    monkeypatch.setenv("OPENAIDR_THREAT_INTEL_ORIGIN", ORIGIN)
    assert from_env().threat_intel_api_key == TOKEN
    assert TOKEN not in repr(from_env())
    monkeypatch.setenv("OPENAIDR_THREAT_INTEL_API_KEY", TOKEN)
    with pytest.raises(ValueError, match="only one"):
        from_env()
    for origin, key, binding in (("http://intel.example.com", TOKEN, TENANT), (ORIGIN + "/", TOKEN, TENANT),
                                 (ORIGIN, "", TENANT), ("", TOKEN, TENANT), (ORIGIN, TOKEN, ""),
                                 ("https://user:pass@intel.example.com", TOKEN, TENANT)):
        cfg = Config(database_url="unused", threat_intel_origin=origin, threat_intel_api_key=key, tenant_id=binding)
        cfg.set_services("ingest,detect")
        with pytest.raises(ValueError, match="Intelligence"):
            cfg.validate()
    cfg = Config(database_url="unused", threat_intel_origin=ORIGIN, threat_intel_api_key=TOKEN, tenant_id=TENANT)
    cfg.set_services("ingest,detect")
    with pytest.raises(ValueError, match="legacy threat-only"):
        cfg.validate()
    cfg.intelligence_origin, cfg.intelligence_api_key = ORIGIN, TOKEN
    cfg.validate()


def test_url_gateway_preserves_local_privacy_limits_and_rejects_cross_tenant_access():
    requests = []

    def handle(request):
        requests.append(request)
        assert request.url == ORIGIN + "/v1/urls/check"
        assert request.headers["authorization"] == "Bearer " + TOKEN
        assert json.loads(request.content) == {"urls": [URL]}
        return httpx.Response(200, json=url_result())

    async def run():
        gateway = client(handle)
        try:
            actions = [{"text": URL + " https://internal.local/private https://public.example.com/?token=secret"}]
            result = await gateway.assess(TENANT, actions, "content_truncated")
            assert result["status"] == "matched" and result["skipped"] == 2
            assert result["reasons"] == ["content_truncated", "urls_skipped"]
            assert malicious_links.restriction(result)["action"] == "deny"
            wrong = await gateway.assess(str(uuid4()), actions)
            assert wrong["status"] == "unavailable" and wrong["matches"] == []
            assert len(requests) == 1
            empty = await gateway.assess(TENANT, [{"text": "https://internal.local/private"}])
            assert empty["status"] == "unavailable" and len(requests) == 1
        finally:
            await gateway.aclose()

    asyncio.run(run())


@pytest.mark.parametrize("failure", ["unrequested", "expired", "unknown_type", "counts", "future", "malformed", "oversized", "redirect", "unavailable", "timeout"])
def test_url_gateway_failures_never_restrict_or_fall_back(failure, monkeypatch):
    calls = []

    async def handle(request):
        calls.append(request)
        value = url_result()
        if failure == "unrequested":
            value["matches"][0]["url"] = "https://unrelated.example.com/"
        elif failure == "expired":
            value["matches"][0]["expires_at"] = "2000-01-01T00:00:00Z"
        elif failure == "unknown_type":
            value["matches"][0]["threat_types"] = ["UNKNOWN"]
        elif failure == "counts":
            value["checked"] = 2
        elif failure == "future":
            value["checked_at"] = "2999-01-01T00:00:00Z"
        elif failure == "malformed":
            value = {"error": "private provider body"}
        elif failure == "oversized":
            return httpx.Response(200, content=b" " * 65537)
        elif failure == "redirect":
            return httpx.Response(307, headers={"Location": "https://webrisk.googleapis.com/"})
        elif failure == "unavailable":
            return httpx.Response(503, text="private provider body")
        elif failure == "timeout":
            await asyncio.Event().wait()
        return httpx.Response(200, json=value)

    async def run():
        gateway = client(handle)
        try:
            result = await gateway.assess(TENANT, [{"text": URL}])
            assert result["status"] == "unavailable" and result["failed"] == 1
            assert malicious_links.restriction(result) is None and "private provider body" not in str(result)
            assert len(calls) == 1 and calls[0].url.host == "intel.example.com"
        finally:
            await gateway.aclose()

    monkeypatch.setattr(malicious_links, "LOOKUP_TIMEOUT", 0.03)
    asyncio.run(run())


def test_package_validation_preserves_original_cache_time_and_partial_status():
    original = package_result()
    other = {"package": {"ecosystem": "PyPI", "name": "example"}, "version": "1.0"}
    original["results"].append({"query": other, "status": "unavailable", "findings": [],
                                "checked_at": None, "expires_at": None, "reason": "upstream details"})

    def handle(request):
        assert request.url == ORIGIN + "/v1/packages/check"
        assert json.loads(request.content) == {"packages": [
            {"ecosystem": "npm", "name": "example", "version": "1.0.0"},
            {"ecosystem": "pypi", "name": "example", "version": "1.0"}]}
        return httpx.Response(200, json=original)

    async def run():
        gateway = client(handle)
        try:
            values = await gateway.packages([QUERY, other])
            assert values[0]["checked_at"].isoformat() == original["results"][0]["checked_at"]
            assert values[0]["expires_at"] - datetime.now(timezone.utc) < timedelta(hours=2)
            assert values[1]["status"] == "unavailable" and values[1]["checked_at"] is None
            assert "upstream details" not in str(values)
        finally:
            await gateway.aclose()

    asyncio.run(run())


@pytest.mark.parametrize("failure", ["query", "missing", "status", "expired", "extended", "future", "finding", "unavailable_clean", "recursive", "underflow"])
def test_package_gateway_rejects_incomplete_or_mismatched_assessments(failure):
    value = package_result()
    item = value["results"][0]
    if failure == "query":
        item["query"] = {**QUERY, "version": "2.0.0"}
    elif failure == "missing":
        value["results"] = []
    elif failure == "status":
        item["status"] = "pending"
    elif failure == "expired":
        item.update(checked_at="2000-01-01T00:00:00Z", expires_at="2000-01-02T00:00:00Z")
    elif failure == "extended":
        item["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    elif failure == "future":
        item.update(checked_at="2999-01-01T00:00:00Z", expires_at="2999-01-02T00:00:00Z")
    elif failure == "finding":
        item["findings"] = [{"id": "CVE-2026-1234"}]
    elif failure == "underflow":
        item.update(checked_at="0001-01-01T00:00:00+23:59", expires_at="0001-01-02T00:00:00+23:59")
    else:
        item["status"] = "unavailable"

    def handle(request):
        if failure == "recursive":
            return httpx.Response(200, content=b'{"nested":' + b"[" * 10000 + b"0" + b"]" * 10000 + b"}")
        return httpx.Response(200, json=value)

    async def run():
        gateway = client(handle)
        try:
            with pytest.raises((osv.Unavailable, ValueError)):
                await gateway.packages([QUERY])
        finally:
            await gateway.aclose()

    asyncio.run(run())


@pytest.mark.parametrize("prefix", ["threat_intel", "intelligence"])
def test_gateway_is_wired_into_hook_enforcement_and_fail_open(db, monkeypatch, prefix):
    own = tenant(db)
    _, token, _ = sensor(db, own["id"])
    hook_policy.save_settings(db, own["id"], {"mode": "enforce", "version": 0}, {})
    db.save_policy(own["id"], [])
    cfg = Config(database_url=db.url, tenant_id=own["id"], cost_processing=False,
                 intelligence_origin=ORIGIN, intelligence_api_key=TOKEN,
                 **({"threat_intel_origin": ORIGIN, "threat_intel_api_key": TOKEN} if prefix == "threat_intel" else {}))
    cfg.set_services("ingest")
    responses, requests = [url_result(), {"invalid": "private response"}], []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json=responses.pop(0))

    original = threat_intel.ThreatIntelClient
    monkeypatch.setattr(threat_intel.ThreatIntelClient, "from_connection", lambda connection:
                        original(connection.origin, connection.api_key, connection.tenant_id,
                                 transport=httpx.MockTransport(handle)))
    monkeypatch.setattr(provider_links, "WebRiskClient", lambda *args, **kwargs: pytest.fail("Direct provider fallback"))
    with TestClient(create_app(cfg, db)) as app:
        for expected in ("deny", "allow"):
            body = payload()
            body["actions"][0]["text"] = URL
            result = app.post("/ingest/v1/hook-checks", headers={"Authorization": "Bearer " + token}, json=body)
            assert result.status_code == 200, result.text
            value = result.json()
            assert value["returned_decision"] == expected
            assert value["assessment"]["links"]["status"] == ("matched" if expected == "deny" else "unavailable")
    assert len(requests) == 2
