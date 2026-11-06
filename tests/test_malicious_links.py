"""URL privacy, bounded provider I/O, and reputation outcomes."""

import asyncio
from copy import deepcopy
import logging
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest

from openaidr.server import malicious_links as links
from openaidr_api.providers import web_risk
from openaidr_api_client.validation import web_risk as url_validation
from openaidr.server.config import from_env


BAD_URL = "https://malware.example.com/download"


class WebRiskProvider:
    def __init__(self):
        self.requests = []
        self.status = 200
        self.delay = 0
        self.payload = None
        self.expiry = time.time() + 300

    async def handle(self, request):
        self.requests.append(request)
        if self.delay:
            await asyncio.sleep(self.delay)
        payload = self.payload
        if payload is None:
            payload = ({"threat": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                                   "expireTime": datetime.fromtimestamp(self.expiry, timezone.utc).isoformat()}}
                       if request.url.params["uri"] == BAD_URL else {})
        return httpx.Response(self.status, json=payload)


def test_url_extraction_uses_only_action_content_and_preserves_url_paths():
    actions = [{
        "kind": "tool.result", "text": f"Read [this]({BAD_URL}).",
        "command": {"text": "curl https://docs.example.com/a_(b)?page=2#section"},
        "tool": {"input": {"url": BAD_URL, "authorization": "https://hidden.example.com"},
                 "output": '{"url":"https:\\/\\/docs.example.com\\/guide"}'},
        "network": {"url": "HTTPS://DOCS.EXAMPLE.COM/guide"},
        "raw": "https://raw.example.com", "session": {"cwd": "https://identity.example.com"},
    }, {"text": "https://faß.de/login https://xn--fa-hia.de/login"}]
    urls, skipped = links.extract_urls(actions)
    assert urls == [BAD_URL, "https://docs.example.com/guide", "https://docs.example.com/a_(b)?page=2",
                    "https://xn--fa-hia.de/login"]
    assert skipped == 0


@pytest.mark.parametrize("url", [
    "https://localhost/private", "http://127.0.0.1/private", "http://127.1/private",
    "http://2130706433/private", "http://[::1]/private", "http://10.0.0.1/private",
    "https://service.internal/private", "https://device.local/private", "https://example.test/private",
    "https://home.arpa/private", "https://router.home.arpa/private", "http://service.onion/private",
    "https://user:password@public.example.com/path", "https://public.example.com/?token=secret-value",
    "https://public.example.com/?X-Amz-Signature=opaque", "https://public.example.com/?code=opaque",
    "https://public.example.com/[REDACTED:token]", "https://public.example.com/%5BREDACTED:token%5D",
    "https://public.example.com:99999/path", "https://public.example.com/" + "a" * 4096,
])
def test_private_credential_redacted_and_unsupported_urls_are_not_submitted(url):
    assert links.extract_urls([{"text": url}]) == ([], 1)


def test_provider_outcomes_cache_expiry_tenant_scope_and_private_logging(monkeypatch, caplog):
    provider = WebRiskProvider()
    clock = SimpleNamespace(time=lambda: provider.expiry - 300, monotonic=time.monotonic)
    monkeypatch.setattr(web_risk, "time", clock)
    monkeypatch.setattr(url_validation, "time", clock)
    caplog.set_level(logging.INFO, logger="httpx")

    async def run():
        client = web_risk.WebRiskClient("private-api-key", transport=httpx.MockTransport(provider.handle))
        try:
            result = await client.assess("tenant-a", [{"text": BAD_URL + " https://docs.example.com/"}])
            assert result["status"] == "matched" and result["checked"] == 2
            assert result["matches"][0]["threat_types"] == ["MALWARE", "SOCIAL_ENGINEERING"]
            original = deepcopy(result)
            restriction = links.restriction(result)
            assert restriction["action"] == "deny"
            assert restriction["reason"] == "The link reputation service flagged a link for phishing, malware, or unwanted software."
            row = {"id": "event", "tenant_id": "tenant-a", "sensor_id": "sensor", "time": "2026-10-30T00:00:00Z",
                   "body": {"host": {"hostname": "Google Web Risk evidence"}}}
            finding = links.detection_finding(row, {"links": result})
            assert finding["summary"].startswith("The link reputation service flagged 1 captured URL(s)")
            assert finding["host"] == row["body"]["host"]
            assert result == original
            assert (await client.assess("tenant-a", [{"text": BAD_URL}]))["status"] == "matched"
            assert len(provider.requests) == 2
            await client.assess("tenant-b", [{"text": BAD_URL}])
            assert len(provider.requests) == 3
            clock.time = lambda: provider.expiry + 1
            expired = await client.assess("tenant-a", [{"text": BAD_URL}])
            assert expired["status"] == "unavailable" and not links.restriction(expired)
            assert not links.restriction(result)
            assert len(provider.requests) == 4
        finally:
            await client.aclose()
    asyncio.run(run())
    for request in provider.requests:
        assert request.url.host == "webrisk.googleapis.com"
        assert request.url.path == "/v1/uris:search"
        assert set(request.url.params.get_list("threatTypes")) == set(links.THREAT_TYPES)
        assert "key" not in request.url.params
        assert request.headers["x-goog-api-key"] == "private-api-key"
    assert BAD_URL not in caplog.text and "private-api-key" not in caplog.text


@pytest.mark.parametrize("status,payload", [
    (403, {"error": "secret-error-body"}), (429, {}), (503, {}), (302, {}),
    (200, {"unexpected": True}), (200, None), (200, {"threat": {"threatTypes": ["UNKNOWN"]}}),
    (200, {"threat": {"threatTypes": ["MALWARE"], "expireTime": "2020-01-01T00:00:00Z"}}),
    (200, {"threat": {"threatTypes": "MALWARE", "expireTime": "2099-01-01T00:00:00Z"}}),
    (200, {"padding": "x" * 9000}),
])
def test_provider_failures_never_become_clean_or_blocking_results(status, payload):
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(status, json=payload, headers={"location": "https://redirect.example.com/"})

    async def run():
        client = web_risk.WebRiskClient("key", transport=httpx.MockTransport(handle))
        try:
            result = await client.assess("tenant", [{"text": BAD_URL}])
            assert result["status"] == "unavailable"
            assert result["checked"] == 0 and result["failed"] == 1
            assert result["matches"] == [] and not links.restriction(result)
            assert "secret-error-body" not in str(result)
        finally:
            await client.aclose()
    asyncio.run(run())
    assert len(calls) == 1


def test_url_limit_and_capture_gaps_remain_explicit():
    provider = WebRiskProvider()

    async def run():
        client = web_risk.WebRiskClient("key", transport=httpx.MockTransport(provider.handle))
        try:
            result = await client.assess("tenant", [{"text": " ".join(
                f"https://public.example.com/{i}" for i in range(links.MAX_URLS + 3)
            )}], "content_truncated")
            assert result["status"] == "partial"
            assert result["checked"] == links.MAX_URLS and result["skipped"] == 3
            assert result["reasons"] == ["content_truncated", "urls_skipped"]
            assert len(provider.requests) == links.MAX_URLS
            assert (await client.assess("tenant", [{"text": "No link"}]))["status"] == "no_urls"
            assert (await client.assess("tenant", [], "content_redacted"))["status"] == "unavailable"
            assert (await client.assess("tenant", [{"text": "https://docs.example.com/"}]))["status"] == "not_listed"
        finally:
            await client.aclose()
    asyncio.run(run())


def test_lookup_timeout_covers_trickling_response_and_cancels_io(monkeypatch):
    monkeypatch.setattr(web_risk, "LOOKUP_TIMEOUT", 0.03)
    closed = []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            while True:
                yield b" "
                await asyncio.sleep(0.01)

        async def aclose(self):
            closed.append(True)

    async def run():
        client = web_risk.WebRiskClient("key", transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=Stream()),
        ))
        try:
            result = await client.assess("tenant", [{"text": BAD_URL}])
            assert result["status"] == "unavailable" and result["reasons"] == ["timeout"]
        finally:
            await client.aclose()
    asyncio.run(run())
    assert closed == [True]


def test_tenant_ignores_web_risk_key_environment(monkeypatch):
    for name in ("OPENAIDR_WEB_RISK_API_KEY", "OPENAIDR_WEB_RISK_API_KEY_FILE"):
        monkeypatch.setenv(name, "private-web-risk-key")
    assert "private-web-risk-key" not in repr(from_env())
    assert not hasattr(from_env(), "web_risk_api_key")
