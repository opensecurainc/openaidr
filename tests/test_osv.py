"""OSV boundary tests with a real inventory database and a stub external API."""

from openaidr_api.providers import osv as provider_osv

import asyncio
import json
import time
from tempfile import TemporaryDirectory
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi.testclient import TestClient

from openaidr.server import osv
from openaidr_api.providers.osv import assess
from openaidr_api_client.clients.threat_intel import ThreatIntelClient
from intelligence_fixture import intelligence_service
from openaidr.server.app import create_app
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server.config import from_env
from test_app_inventory_server import COMPONENTS, component as base_component, inventory, root as base_root, send_components


def component(**changes):
    return base_component(ecosystem="npm", **changes)


def root(path="/env/one", **changes):
    return base_root(path, source="osquery-npm-packages", **changes)


def record(ident="GHSA-one", **overrides):
    return {
        "id": ident, "aliases": ["CVE-2026-1111"], "summary": "Example issue",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"ecosystem": "npm", "name": "example"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}],
        **overrides,
    }


def execute(st, handler, tenant=""):
    async def check(service):
        client = ThreatIntelClient.from_connection(service.connection)
        try:
            return await osv.tick(st, client, tenant)
        finally:
            await client.aclose()
    with TemporaryDirectory() as temporary, pytest.MonkeyPatch.context() as patch:
        with intelligence_service(patch, Path(temporary), tenant, handler) as service:
            return asyncio.run(check(service))


def due(st):
    st.execute("UPDATE inventory_osv_packages SET next_check_at=now()-interval '1 minute'")


@pytest.mark.parametrize("receipt_state", [None, "settled", "released"])
def test_customer_dispatch_keeps_original_claim_until_result_or_confirmed_failure(inventory, receipt_state):
    from openaidr_api_client.client import Connection
    from openaidr.server.guardrail import calls
    from openaidr.server.service_operations import ServiceOperation

    st, _, client, identities = inventory
    sensor, token, _ = identities[0]
    tenant = sensor["tenant_id"]
    assert send_components(client, token, [root(components=[component(version="1.0.0")])]).status_code == 200
    initial = osv.claim(st, tenant)[0]
    query = osv.package_query(initial)[0]
    findings = provider_osv.merge_aliases([provider_osv.advisory(record(), query)])
    osv.save(st, initial, findings)
    due(st)
    row = osv.claim(st, tenant)[0]
    connection = Connection("https://intelligence.example.test", "oati_" + "a" * 32 + "." + "b" * 43, tenant)
    operation = ServiceOperation(st, tenant, "package_vulnerabilities", connection)
    calls.begin(operation, str(row["claim_token"]), [query], "")
    if receipt_state:
        operation.capture(dict(request_id=operation.id, service="package_vulnerabilities", state=receipt_state,
                               credits_reserved="1", credits_charged="1" if receipt_state == "settled" else "0",
                               rate_version="synthetic-test"))
        calls.finish(operation, failed=receipt_state == "released")

    if receipt_state != "released":
        # Process loss before any inventory save must also prevent reclamation.
        due(st)
        assert osv.claim(st, tenant) == []

    # A missing reply or unusable result must keep cached evidence and its
    # original operation scope, even after the ordinary inventory lease expires.
    osv.save(st, row, [], "OSV check unavailable; retry scheduled")
    cached = st.one("SELECT * FROM inventory_osv_packages WHERE tenant_id=$1", tenant)
    assert cached["findings"] == findings and cached["checked_at"] == row["checked_at"]
    due(st)
    if receipt_state == "released":
        assert cached["claim_token"] is None
        assert len(osv.claim(st, tenant)) == 1
        assert st.one("SELECT * FROM service_call_intents WHERE tenant_id=$1", tenant)["outcome"] == "failed"
    else:
        assert cached["claim_token"] == row["claim_token"]
        assert "retry scheduled" not in cached["error"]
        assert osv.claim(st, tenant) == []
        assert st.one("SELECT * FROM service_call_intents WHERE tenant_id=$1", tenant)["request_id"] == operation.id
        visible = client.get(COMPONENTS).json()["items"][0]["vulnerability"]
        assert visible["status"] == "unavailable" and visible["findings"] == findings
        assert "previous request" in visible["reason"]
        # If the original worker does obtain a usable result, its matching
        # claim can still publish it. This does not dispatch another request.
        osv.save(st, row, findings)
        assert st.one("SELECT * FROM inventory_osv_packages WHERE tenant_id=$1", tenant)["claim_token"] is None


def test_legacy_package_retries_ignore_other_tenant_or_claim_dispatches(inventory):
    from openaidr_api_client.client import Connection
    from openaidr.server.guardrail import calls
    from openaidr.server.service_operations import ServiceOperation
    from uuid import uuid4

    st, _, client, identities = inventory
    sensor, token, _ = identities[0]
    other = identities[1][0]
    tenant = sensor["tenant_id"]
    assert send_components(client, token, [root(components=[component(version="1.0.0")])]).status_code == 200
    row = osv.claim(st, tenant)[0]
    for bound_tenant, scope in [(other["tenant_id"], str(row["claim_token"])), (tenant, str(uuid4()))]:
        connection = Connection("https://intelligence.example.test", "oati_" + "a" * 32 + "." + "b" * 43, bound_tenant)
        operation = ServiceOperation(st, bound_tenant, "package_vulnerabilities", connection)
        calls.begin(operation, scope, [osv.package_query(row)[0]], "")
    due(st)
    replacement = osv.claim(st, tenant)[0]
    assert replacement["claim_token"] != row["claim_token"]
    osv.save(st, row, [], "stale worker")
    assert st.one("SELECT * FROM inventory_osv_packages WHERE tenant_id=$1", tenant)["claim_token"] == replacement["claim_token"]
    osv.save(st, replacement, [], "OSV check unavailable; retry scheduled")
    assert st.one("SELECT * FROM inventory_osv_packages WHERE tenant_id=$1", tenant)["claim_token"] is None
    due(st)
    assert len(osv.claim(st, tenant)) == 1


def test_gateway_assessments_preserve_cache_age_partial_failure_and_tenant_scope(inventory):
    from datetime import datetime, timedelta, timezone
    from openaidr_api_client.clients.threat_intel import ThreatIntelClient

    st, cfg, client, identities = inventory
    own, token, _ = identities[0]
    other, other_token, _ = identities[1]
    components = [component(version="1.0.0"), component(key="healthy", version="1.0.0")]
    assert send_components(client, token, [root(components=components)]).status_code == 200
    assert send_components(client, other_token, [root(components=components)]).status_code == 200
    checked = datetime.now(timezone.utc) - timedelta(hours=23)
    expires = checked + osv.REFRESH
    calls, unavailable = [], False

    def gateway(request):
        calls.append(request)
        if unavailable:
            return httpx.Response(503, text="private upstream detail")
        results = []
        for item in json.loads(request.content)["packages"]:
            query = osv.package_query({"ecosystem": item["ecosystem"], "identifier": item["name"], "version": item["version"]})[0]
            if item["name"] == "example":
                findings = provider_osv.merge_aliases([provider_osv.advisory(record(), query)])
                results.append({"query": query, "status": "complete", "findings": findings,
                                "checked_at": checked.isoformat(), "expires_at": expires.isoformat(), "reason": ""})
            else:
                results.append({"query": query, "status": "unavailable", "findings": [],
                                "checked_at": None, "expires_at": None, "reason": "unavailable"})
        return httpx.Response(200, json={"provider": "OSV", "results": results})

    async def execute_gateway():
        intelligence = ThreatIntelClient("https://intel.example.com", "oati_" + "a" * 32 + "." + "b" * 43,
                                        own["tenant_id"], transport=httpx.MockTransport(gateway))
        try:
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: pytest.fail("Direct OSV fallback"))):
                with pytest.raises(osv.Unavailable, match="bound tenant"):
                    await osv.tick(st, intelligence, other["tenant_id"])
                return await osv.tick(st, intelligence, own["tenant_id"])
        finally:
            await intelligence.aclose()

    assert asyncio.run(execute_gateway())
    values = {row["identifier"]: row["vulnerability"] for row in client.get(COMPONENTS).json()["items"]}
    assert values["example"]["status"] == "complete" and values["example"]["findings"][0]["id"] == "CVE-2026-1111"
    assert values["healthy"]["status"] == "unavailable"
    cached = st.one("SELECT * FROM inventory_osv_packages WHERE tenant_id=$1 AND identifier='example'", own["tenant_id"])
    assert cached["checked_at"] == checked and cached["next_check_at"] == expires
    assert not st.scalar("SELECT count(*) FROM inventory_osv_packages WHERE tenant_id=$1", other["tenant_id"])
    assert not asyncio.run(execute_gateway()) and len(calls) == 1
    unavailable = True
    due(st)
    assert asyncio.run(execute_gateway()) and len(calls) == 2
    failed = next(row["vulnerability"] for row in client.get(COMPONENTS).json()["items"] if row["identifier"] == "example")
    assert failed["status"] == "unavailable" and failed["checked_at"] == values["example"]["checked_at"]
    assert failed["findings"] == values["example"]["findings"] and "private upstream detail" not in str(failed)


def test_inventory_assessments_cache_isolation_upgrade_and_unavailability(inventory):
    st, cfg, client, identities = inventory
    sensor, token, session = identities[0]
    other, other_token, other_session = identities[1]
    # Copies in different locations share one package/version assessment.
    for location in ("/one", "/two"):
        assert send_components(client, token, [root(location, components=[component(version="1.0.0")])]).status_code == 200
    assert send_components(client, other_token, [root(components=[component(version="1.0.0")])]).status_code == 200
    reads = []

    def handler(request):
        reads.append(request)
        if request.url.path.endswith("querybatch"):
            payload = json.loads(request.content)
            assert payload == {"queries": [{"package": {"ecosystem": "npm", "name": "example"}, "version": "1.0.0"}]}
            assert str(sensor["id"]) not in request.content.decode()
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-one"}, {"id": "GHSA-alias"}]}]})
        return httpx.Response(200, json=record(request.url.path.rsplit("/", 1)[1]))

    assert {row["vulnerability"]["status"] for row in client.get(COMPONENTS).json()["items"]} == {"pending"}
    assert execute(st, handler, sensor["tenant_id"])
    assert len(reads) == 3
    assessments = [row["vulnerability"] for row in client.get(COMPONENTS).json()["items"]]
    assert len(assessments) == 2 and assessments[0] == assessments[1]
    result = assessments[0]
    assert result["status"] == "complete" and result["checked_at"]
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["id"] == "CVE-2026-1111"
    assert finding["source_ids"] == ["GHSA-alias", "GHSA-one"]
    assert finding["severity"] == "high" and finding["fixed_versions"] == ["2.0.0"]
    assert not execute(st, handler, sensor["tenant_id"])
    assert len(reads) == 3
    client.cookies.set(CONSOLE_COOKIE, other_session)
    assert client.get(COMPONENTS).json()["items"][0]["vulnerability"]["status"] == "pending"
    client.cookies.set(CONSOLE_COOKIE, session)
    due(st)
    execute(st, lambda request: httpx.Response(503, text="secret provider detail"), sensor["tenant_id"])
    failed = client.get(COMPONENTS).json()["items"][0]["vulnerability"]
    assert failed["status"] == "unavailable" and failed["findings"] == result["findings"]
    assert failed["checked_at"] == result["checked_at"]
    assert "secret" not in json.dumps(failed)
    due(st)
    execute(st, lambda request: httpx.Response(200, json={"results": [{}]}), sensor["tenant_id"])
    assert client.get(COMPONENTS).json()["items"][0]["vulnerability"]["findings"] == []
    assert send_components(client, token, [root("/one", components=[component(version="2.0.0")])], 1).status_code == 200
    changed = client.get(COMPONENTS, params={"root": "/one"}).json()["items"][0]["vulnerability"]
    assert changed["status"] == "pending" and changed["checked_at"] is None
    cfg.osv_assessment = False
    assert {row["vulnerability"]["status"] for row in client.get(COMPONENTS).json()["items"]} == {"not_assessed"}
    # Existing HTTP permissions still guard the enriched inventory response.
    client.cookies.clear()
    assert client.get(COMPONENTS).status_code == 401


def test_claim_recovery_stale_and_deleted_inventory(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    send_components(client, token, [root(components=[component(version="1.0.0")])])
    first = osv.claim(st, sensor["tenant_id"])
    assert len(first) == 1 and not osv.claim(st, sensor["tenant_id"])
    due(st)
    second = osv.claim(st, sensor["tenant_id"])
    osv.save(st, second[0], [{"id": "current"}])
    osv.save(st, first[0], [{"id": "late"}])
    assert client.get(COMPONENTS).json()["items"][0]["vulnerability"]["findings"] == [{"id": "current"}]
    st.execute("UPDATE inventory_osv_packages SET checked_at=now()-interval '2 days'")
    assert client.get(COMPONENTS).json()["items"][0]["vulnerability"]["status"] == "stale"
    # A removed package is no longer queued, even if its cached result expires.
    send_components(client, token, [root(components=[])], 1)
    due(st)
    assert not osv.claim(st, sensor["tenant_id"])
    assert client.get(COMPONENTS).json()["items"] == []


def test_poisoned_package_does_not_starve_healthy_packages(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    send_components(client, token, [root(components=[component(version="1.0.0"),
        component(identifier="healthy", name="healthy", key="healthy", version="1.0.0")])])

    def handler(request):
        if request.url.path.endswith("querybatch"):
            queries = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": "GHSA-broken"}]} if query["package"]["name"] == "example" else {}
                for query in queries]})
        return httpx.Response(200, json=record("GHSA-broken", database_specific=[]))

    for _ in range(2):
        assert execute(st, handler, sensor["tenant_id"])
        results = {row["identifier"]: row["vulnerability"] for row in client.get(COMPONENTS).json()["items"]}
        assert results["healthy"]["status"] == "complete"
        assert results["healthy"]["findings"] == []
        assert results["example"]["status"] == "unavailable"
        assert results["example"]["checked_at"] is None
        due(st)


def test_competing_claims_skip_lost_rows_without_rolling_back_other_claims(inventory):
    st, cfg, client, identities = inventory
    first, second = sorted(identities, key=lambda identity: str(identity[0]["tenant_id"]))
    for sensor, token, _ in (first, second):
        send_components(client, token, [root(components=[component(version="1.0.0")])])
    osv.claim(st, second[0]["tenant_id"])
    due(st)

    def wait_for_claimers(count):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            waiting = st.one("""SELECT count(*) AS count FROM pg_stat_activity
                WHERE datname=current_database() AND wait_event_type='Lock'
                AND query LIKE '%inventory_osv_packages%'""")["count"]
            if waiting >= count:
                return
            time.sleep(0.01)
        pytest.fail("Concurrent claimers did not reach the controlled row lock")

    with ThreadPoolExecutor(max_workers=2) as pool:
        with st.transaction() as conn:
            st.many("SELECT * FROM inventory_osv_packages WHERE tenant_id=$1 FOR UPDATE", second[0]["tenant_id"], conn=conn)
            winner = pool.submit(osv.claim, st, second[0]["tenant_id"])
            wait_for_claimers(1)
            other = pool.submit(osv.claim, st)
            wait_for_claimers(2)
        won, skipped = winner.result(timeout=5), other.result(timeout=5)
    assert {str(row["tenant_id"]) for row in won} == {str(second[0]["tenant_id"])}
    assert {str(row["tenant_id"]) for row in skipped} == {str(first[0]["tenant_id"])}
    assert not osv.claim(st)


def test_osv_pagination_aliases_withdrawal_and_package_specific_fixes():
    queries = [osv.package_query({"ecosystem": "npm", "identifier": "example", "version": "1.0.0"})[0],
               osv.package_query({"ecosystem": "pypi", "identifier": "Some_Package", "version": "1.0"})[0]]
    assert queries[1]["package"] == {"ecosystem": "PyPI", "name": "some-package"}
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path.endswith("querybatch"):
            payload = json.loads(request.content)
            if len(calls) == 1:
                assert payload == {"queries": queries}
                return httpx.Response(200, json={"results": [{"next_page_token": "opaque +/="}, {}]})
            assert payload == {"queries": [dict(queries[0], page_token="opaque +/=")]}
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-one"}, {"id": "GHSA-withdrawn"}]}]})
        ident = request.url.path.rsplit("/", 1)[1]
        value = record(ident)
        value["affected"].append({"package": {"ecosystem": "npm", "name": "unrelated"},
                                  "ranges": [{"type": "SEMVER", "events": [{"fixed": "99.0.0"}]}]})
        if ident.endswith("withdrawn"):
            value["withdrawn"] = "2026-01-01T00:00:00Z"
        return httpx.Response(200, json=value)

    async def check():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await assess(client, queries)
    results = asyncio.run(check())
    assert len(results[0]) == 1 and results[1] == []
    assert results[0][0]["fixed_versions"] == ["2.0.0"]


@pytest.mark.parametrize("response", [None, {}, {"results": []}, {"results": [None]},
                                     {"results": [{"vulns": [{"id": "../escape"}]}]},
                                     {"results": [{"error": "query failed"}]},
                                     {"results": [{"next_page_token": 0}]},
                                     {"results": [{"vulns": "wrong"}]}])
def test_malformed_osv_never_becomes_a_clean_assessment(inventory, response):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    send_components(client, token, [root(components=[component(version="1.0.0")])])
    execute(st, lambda request: httpx.Response(200, json=response), sensor["tenant_id"])
    value = client.get(COMPONENTS).json()["items"][0]["vulnerability"]
    assert value["status"] == "unavailable" and value["checked_at"] is None


@pytest.mark.parametrize("row", [
    {"kind": "mcp_server", "ecosystem": "", "identifier": "example", "version": "1.0.0"},
    {"kind": "plugin", "ecosystem": "", "identifier": "example", "version": "1.0.0"},
    {"ecosystem": "npm", "identifier": "/private/path", "version": "1.0.0"},
    {"ecosystem": "npm", "identifier": "example", "version": ""},
    {"ecosystem": "npm", "identifier": "example", "version": "latest"},
    {"ecosystem": "npm", "identifier": "example", "version": "^1.0.0"},
    {"ecosystem": "npm", "identifier": "example", "version": "01.0.0"},
    {"ecosystem": "npm", "identifier": "example", "version": "1.0.0-01"},
    {"ecosystem": "pypi", "identifier": "example", "version": "1.whatever"},
])
def test_missing_or_unsupported_identity_is_not_queried(row):
    assert osv.package_query(row)[0] is None


def test_alias_transitivity_and_configuration(monkeypatch):
    query = osv.package_query({"ecosystem": "npm", "identifier": "example", "version": "1.0.0"})[0]
    values = [provider_osv.advisory(record("A", aliases=["X"]), query),
              provider_osv.advisory(record("B", aliases=["Y"]), query),
              provider_osv.advisory(record("C", aliases=["X", "Y"]), query)]
    assert len(provider_osv.merge_aliases(values)) == 1
    monkeypatch.setenv("OPENAIDR_OSV_ASSESSMENT", "false")
    assert not from_env().osv_assessment


@pytest.mark.parametrize("enabled", [True, False])
def test_background_assessment_respects_service_and_disable_switch(inventory, monkeypatch, enabled):
    st, cfg, client, identities = inventory
    cfg.set_services("detect")
    cfg.osv_assessment = enabled
    started = []

    async def worker(store, stop, tenant, *, intelligence=None, customer=False):
        assert intelligence is None and customer is False
        started.append((store, tenant))
        await stop.wait()

    monkeypatch.setattr(osv, "run", worker)
    with TestClient(create_app(cfg, st)) as running:
        assert running.get("/healthz").status_code == 200
    assert started == ([(st, cfg.tenant_id)] if enabled else [])
