"""Small public interface over the existing Intelligence clients."""

from functools import partial
from typing import Any

from anyio.from_thread import start_blocking_portal
import httpx
from pydantic import ValidationError

from ._vendor.openaidr_api_client.client import Connection, IntelligenceClient, Unavailable
from ._vendor.openaidr_api_client.clients.guardrail import AsyncGuardrailClient
from ._vendor.openaidr_api_client.clients.threat_intel import ThreatIntelClient
from ._vendor.openaidr_api_client.contracts.service_guardrail import GuardrailError
from ._vendor.openaidr_api_client.contracts.threat_intel import PackageRequest
from ._vendor.openaidr_api_client.validation import osv


class ScanError(Unavailable):
    """An unsuccessful scan, with any validated billing receipt retained."""

    def __init__(self, *, billing=None, status_code=None, retry_after=None, error_code=None):
        super().__init__("Dependency scan unavailable", status_code=status_code,
                         retry_after=retry_after, error_code=error_code)
        self.billing = billing


class _PackageClient(ThreatIntelClient):
    # Keep HTTP status and Retry-After instead of the legacy OSV error conversion.
    request = IntelligenceClient.request


class _GuardrailClient(AsyncGuardrailClient):
    def __init__(self, client):
        self.client = client


class AsyncAIDR:
    def __init__(self, *, api_key: str, tenant_id: str,
                 base_url: str = "https://api.opensecura.ai", ca_file: str = "",
                 transport: httpx.AsyncBaseTransport | None = None):
        connection = Connection(base_url, api_key, tenant_id, ca_file)
        self._packages = _PackageClient.from_connection(connection, transport=transport)
        self._guardrail = _GuardrailClient(self._packages)
        self._closed = False

    def _check_open(self):
        if self._closed:
            raise RuntimeError("AIDR client is closed")

    async def scan_dependencies(self, packages: list[dict[str, str]], *, request_id: str) -> dict[str, Any]:
        """Check up to 25 exact npm/PyPI versions; return results and billing."""
        self._check_open()
        if request_id is None:
            raise ValueError("A request_id is required")
        validated = PackageRequest.model_validate({"packages": packages})
        queries = [osv.package_query({"ecosystem": item.ecosystem.lower(),
                    "identifier": item.name, "version": item.version})[0] for item in validated.packages]
        if any(query is None for query in queries):
            raise ValueError("Unsupported package identity or version")
        billing = None

        async def receive(value):
            nonlocal billing
            billing = value

        try:
            results = await self._packages.packages(queries, request_id=request_id, receipt=receive)
        except (Unavailable, osv.Unavailable, httpx.HTTPError, TimeoutError, ValidationError) as error:
            raise ScanError(billing=billing, status_code=getattr(error, "status_code", None),
                            retry_after=getattr(error, "retry_after", None),
                            error_code=getattr(error, "error_code", None)) from None
        return {"results": results, "billing": billing}

    async def assess_guardrail(self, state: dict[str, Any], *, request_id: str,
                              company_policy: str = "", timeout: float | None = None,
                              max_credits: str | None = None) -> dict[str, Any]:
        """Return an advisory risk assessment; the caller controls enforcement."""
        self._check_open()
        if request_id is None:
            raise ValueError("A request_id is required")
        return await self._guardrail.assess(state, request_id=request_id, company_policy=company_policy,
                                           timeout=timeout, max_credits=max_credits)

    async def aclose(self):
        if not self._closed:
            self._closed = True
            await self._packages.aclose()

    async def __aenter__(self):
        self._check_open()
        return self

    async def __aexit__(self, *exc):
        await self.aclose()


class AIDR:
    """Synchronous access to the same async implementation on a persistent loop."""

    def __init__(self, *, api_key: str, tenant_id: str,
                 base_url: str = "https://api.opensecura.ai", ca_file: str = "",
                 transport: httpx.AsyncBaseTransport | None = None):
        self._closed = False
        self._manager = start_blocking_portal(name="aidr")
        self._portal = self._manager.__enter__()
        try:
            self._client = self._portal.call(partial(AsyncAIDR, api_key=api_key, tenant_id=tenant_id,
                base_url=base_url, ca_file=ca_file, transport=transport))
        except BaseException:
            self._manager.__exit__(None, None, None)
            raise

    def _check_open(self):
        if self._closed:
            raise RuntimeError("AIDR client is closed")

    def scan_dependencies(self, packages: list[dict[str, str]], *, request_id: str) -> dict[str, Any]:
        self._check_open()
        return self._portal.call(partial(self._client.scan_dependencies, packages, request_id=request_id))

    def assess_guardrail(self, state: dict[str, Any], *, request_id: str,
                        company_policy: str = "", timeout: float | None = None,
                        max_credits: str | None = None) -> dict[str, Any]:
        self._check_open()
        return self._portal.call(partial(self._client.assess_guardrail, state, request_id=request_id,
            company_policy=company_policy, timeout=timeout, max_credits=max_credits))

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                self._portal.call(self._client.aclose)
            finally:
                self._manager.__exit__(None, None, None)

    def __enter__(self):
        self._check_open()
        return self

    def __exit__(self, *exc):
        self.close()
