"""Exercise the public SDK against actual wire contracts without paid requests."""

import asyncio
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import httpx
import pytest

from aidr import AIDR, AsyncAIDR, GuardrailError, ScanError


TOKEN = "oasc_" + "a" * 32 + "." + "b" * 43
TENANT = "11111111-1111-4111-8111-111111111111"
PACKAGES = [{"ecosystem": "PyPI", "name": "Example_Library", "version": "1.0"},
            {"ecosystem": "npm", "name": "@example/library", "version": "2.0.0"}]
STATE = {"target_event": {"kind": "command", "command": {"text": "git status"}},
         "latest_prompt": None, "prior_events": [], "context_limited": True}


def receipt(request_id, service):
    return {"request_id": request_id, "service": service, "state": "settled",
            "credits_reserved": "1", "credits_charged": "1", "rate_version": "test.1"}


def package_response(request_id):
    stamp = datetime.now(timezone.utc) - timedelta(seconds=1)
    finding = {"id": "CVE-2026-12345", "aliases": ["GHSA-test"], "source_ids": ["GHSA-test"],
               "summary": "Test vulnerability", "severity": "high", "fixed_versions": ["1.1"],
               "severity_vectors": [], "url": "https://osv.dev/vulnerability/GHSA-test"}
    return {"profile": "package-vulnerabilities.1", "results": [
        {"query": {"package": {"ecosystem": "PyPI", "name": "example-library"}, "version": "1.0"},
         "status": "complete", "findings": [finding], "checked_at": stamp.isoformat(),
         "expires_at": (stamp + timedelta(days=1)).isoformat(), "reason": ""},
        {"query": {"package": {"ecosystem": "npm", "name": "@example/library"}, "version": "2.0.0"},
         "status": "unavailable", "findings": [], "checked_at": None,
         "expires_at": None, "reason": "Service assessment unavailable"},
    ], "billing": receipt(request_id, "package_vulnerabilities")}


def guardrail_response(request_id):
    return {"profile": "guardrail.1", "status": "scored", "category": "none", "score": 0,
            "level": "info", "confidence": 0.9, "category_confidence": 0.8,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
            "billing": receipt(request_id, "guardrail")}


class Transport(httpx.MockTransport):
    def __init__(self, handler):
        super().__init__(handler)
        self.closes = 0

    async def aclose(self):
        self.closes += 1


@pytest.mark.parametrize("synchronous", [False, True])
def test_public_operations_preserve_contracts_and_close_one_transport(synchronous):
    calls = []
    scan_id, guardrail_id = str(uuid4()), str(uuid4())

    def handle(request):
        calls.append(request)
        assert request.url.host == "api.opensecura.ai"
        assert request.headers["authorization"] == "Bearer " + TOKEN
        assert request.headers["x-opensecura-tenant-id"] == TENANT
        body = json.loads(request.content)
        if request.url.path == "/v1/services/packages/check":
            assert request.headers["idempotency-key"] == scan_id
            assert body == {"packages": [
                {"ecosystem": "pypi", "name": "example-library", "version": "1.0"},
                {"ecosystem": "npm", "name": "@example/library", "version": "2.0.0"}]}
            return httpx.Response(200, json=package_response(scan_id))
        assert request.url.path == "/v1/services/guardrail/assess"
        assert request.headers["idempotency-key"] == guardrail_id
        assert body == {"state": STATE, "company_policy": "Protect secrets.",
                        "timeout_ms": 5000, "max_credits": "1"}
        return httpx.Response(200, json=guardrail_response(guardrail_id))

    transport = Transport(handle)
    options = dict(api_key=TOKEN, tenant_id=TENANT, transport=transport)
    guardrail_options = dict(request_id=guardrail_id, company_policy="Protect secrets.", timeout=5, max_credits="1")

    if synchronous:
        with AIDR(**options) as client:
            scan = client.scan_dependencies(PACKAGES, request_id=scan_id)
            assessment = client.assess_guardrail(STATE, **guardrail_options)
        client.close()
        with pytest.raises(RuntimeError, match="closed"):
            client.scan_dependencies(PACKAGES, request_id=scan_id)
    else:
        async def run():
            async with AsyncAIDR(**options) as client:
                values = await asyncio.gather(
                    client.scan_dependencies(PACKAGES, request_id=scan_id),
                    client.assess_guardrail(STATE, **guardrail_options))
            await client.aclose()
            with pytest.raises(RuntimeError, match="closed"):
                await client.assess_guardrail(STATE, **guardrail_options)
            return values
        scan, assessment = asyncio.run(run())
    assert scan["billing"]["request_id"] == scan_id
    assert scan["results"][0]["findings"][0]["fixed_versions"] == ["1.1"]
    assert scan["results"][0]["checked_at"].tzinfo is not None
    assert scan["results"][1]["status"] == "unavailable"
    assert assessment["score"] == 0 and "decision" not in assessment
    assert len(calls) == 2 and transport.closes == 1


@pytest.mark.parametrize("packages", [[], PACKAGES * 13,
    [{"ecosystem": "npm", "name": "example", "version": "^1.0.0"}],
    [{"ecosystem": "pypi", "name": "example", "version": "latest"}],
    [{"ecosystem": "maven", "name": "example", "version": "1.0"}],
    [{"ecosystem": "pypi", "name": "../local", "version": "1.0"}],
])
def test_invalid_package_inputs_do_not_make_requests(packages):
    with AIDR(api_key=TOKEN, tenant_id=TENANT,
              transport=httpx.MockTransport(lambda _: pytest.fail("Unexpected request"))) as client:
        with pytest.raises(ValueError):
            client.scan_dependencies(packages, request_id=str(uuid4()))


@pytest.mark.parametrize("request_id", [None, "", "not-a-uuid", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"])
@pytest.mark.parametrize("method,value", [("scan_dependencies", PACKAGES), ("assess_guardrail", STATE)])
def test_request_identity_is_required_before_network_io(method, value, request_id):
    with AIDR(api_key=TOKEN, tenant_id=TENANT,
              transport=httpx.MockTransport(lambda _: pytest.fail("Unexpected request"))) as client:
        with pytest.raises(ValueError):
            getattr(client, method)(value, request_id=request_id)


@pytest.mark.parametrize("failure", ["rate_limit", "authentication", "redirect", "timeout", "invalid_json"])
def test_scan_transport_failure_never_retries_or_leaks_response(failure):
    calls = []

    def handle(request):
        calls.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("Private transport detail", request=request)
        if failure == "invalid_json":
            return httpx.Response(200, content=b"private response")
        status = {"rate_limit": 429, "authentication": 401, "redirect": 307}[failure]
        return httpx.Response(status, content=b"private response",
                              headers={"Retry-After": "30", "Location": "https://unrelated.example/"})

    with AIDR(api_key=TOKEN, tenant_id=TENANT, transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(ScanError) as caught:
            client.scan_dependencies(PACKAGES, request_id=str(uuid4()))
    assert len(calls) == 1 and caught.value.billing is None
    assert "private" not in str(caught.value).lower()
    if failure == "rate_limit":
        assert caught.value.status_code == 429 and caught.value.retry_after == "30"


@pytest.mark.parametrize("failure", ["wrong_package", "expired", "missing_results", "wrong_receipt", "invalid_finding"])
def test_invalid_scan_retains_only_matching_billing(failure):
    request_id = str(uuid4())
    response = package_response(request_id)
    if failure == "wrong_package":
        response["results"][0]["query"]["version"] = "9.0"
    elif failure == "expired":
        response["results"][0]["checked_at"] = "2000-01-01T00:00:00+00:00"
        response["results"][0]["expires_at"] = "2000-01-02T00:00:00+00:00"
    elif failure == "missing_results":
        response["results"] = []
    elif failure == "wrong_receipt":
        response["billing"]["request_id"] = str(uuid4())
    else:
        response["results"][0]["findings"][0]["url"] = "https://unrelated.example/"
    with AIDR(api_key=TOKEN, tenant_id=TENANT,
              transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response))) as client:
        with pytest.raises(ScanError) as caught:
            client.scan_dependencies(PACKAGES, request_id=request_id)
    assert caught.value.billing == (None if failure == "wrong_receipt" else response["billing"])


@pytest.mark.parametrize("failure", ["http_error", "timeout", "invalid_score", "wrong_receipt", "service_error"])
def test_guardrail_errors_reuse_existing_validation_and_billing(failure):
    request_id = str(uuid4())
    response = guardrail_response(request_id)
    calls = []
    if failure == "invalid_score":
        response["score"] = 99
    elif failure == "wrong_receipt":
        response["billing"]["request_id"] = str(uuid4())
    elif failure == "service_error":
        response = {"profile": "guardrail.1", "status": "error", "reason": "provider_unavailable",
                    "retryable": True, "retry_after": 30, "billing": response["billing"]}

    def handle(request):
        calls.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("Private detail", request=request)
        return httpx.Response(503 if failure == "http_error" else 200, json=response)

    with AIDR(api_key=TOKEN, tenant_id=TENANT, transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(GuardrailError) as caught:
            client.assess_guardrail(STATE, request_id=request_id)
    assert len(calls) == 1
    assert caught.value.billing == (response["billing"] if failure in ("invalid_score", "service_error") else None)


def test_unscored_guardrail_is_preserved_without_a_decision():
    request_id = str(uuid4())
    response = {**guardrail_response(request_id), "status": "unscored", "category": "unknown",
                "score": None, "level": None}
    with AIDR(api_key=TOKEN, tenant_id=TENANT,
              transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response))) as client:
        value = client.assess_guardrail(STATE, request_id=request_id)
    assert value["status"] == "unscored" and value["score"] is None and "decision" not in value


@pytest.mark.parametrize("options", [{"base_url": "http://api.example.com"},
    {"base_url": "https://api.example.com/path"}, {"api_key": "bad"}, {"tenant_id": "bad"}])
def test_invalid_connection_fails_during_construction(options):
    with pytest.raises(ValueError):
        AIDR(**{**dict(api_key=TOKEN, tenant_id=TENANT), **options})
