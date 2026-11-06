"""Provider snapshots use real tenant storage; only the external HTTP API is fake."""

from copy import deepcopy
from datetime import timedelta
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from openaidr.server import agent_billing, copilot_billing
from openaidr.server.app import create_app
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server.cli import main
from test_telemetry_server import backend  # noqa: F401


def billing_report(product="Copilot"):
    return dict(timePeriod=dict(year=2026, month=10), usageItems=[dict(
        product=product, sku="Copilot AI Credits", model="reported-model", unitType="credits",
        pricePerUnit="0.01", grossQuantity=100, grossAmount="1.00123456789",
        discountQuantity=80, discountAmount="0.8", netQuantity=20, netAmount="0.20123456789",
        private="DO-NOT-RETAIN")], private="DO-NOT-RETAIN")


def test_billing_refreshes_and_failures_are_isolated_and_replay_safe(backend, monkeypatch, capsys):
    st, cfg, sensor, _, other, *_ = backend
    tenant = sensor["tenant_id"]
    monkeypatch.setenv("OPENAIDR_COPILOT_BILLING_TOKEN", "test-secret")
    code, data = 200, billing_report()
    requests = []

    def transport(request):
        requests.append(request)
        assert request.url.host == "api.github.com"
        assert request.url.path == "/organizations/example/settings/billing/ai_credit/usage"
        assert dict(request.url.params) == dict(year="2026", month="10")
        assert request.headers["Authorization"] == "Bearer test-secret"
        return httpx.Response(code, json=data)

    with httpx.Client(transport=httpx.MockTransport(transport)) as http:
        def sync():
            return copilot_billing.sync(st, tenant, "organization", "example", "2026-10", "ai_credit", client=http)
        assert sync()["status"] == "collected"
        assert sync()["status"] == "collected"
        rows = agent_billing.overview(st, tenant)["items"]
        assert len(rows) == 1
        assert rows[0]["report"]["net_amount"] == "0.20123456789"
        assert "DO-NOT-RETAIN" not in json.dumps(rows)
        assert agent_billing.overview(st, other["tenant_id"])["items"] == []
        assert st.scalar("SELECT count(*) FROM agent_cost_records") == 0
        saved = rows[0]
        for code in (401, 403, 429, 500, 302):
            assert sync()["error_code"] == "provider_http_" + str(code)
            current, = agent_billing.overview(st, tenant)["items"]
            assert current["status"] == "failed"
            assert current["report"] == saved["report"] and current["collected_at"] == saved["collected_at"]
        code = 200
        data = {"timePeriod": {"year": 2026, "month": 9}, "usageItems": []}
        assert sync()["error_code"] == "period_mismatch"
        data = billing_report()
        data["usageItems"][0]["netAmount"] = 0
        assert sync()["status"] == "collected"
        source = dict(provider="copilot", scope="organization", account="example", basis="ai_credit")
        agent_billing.save(st, tenant, source, "2026-10", st.scalar("SELECT now()") - timedelta(hours=1), error="old_failure")
        assert agent_billing.overview(st, tenant)["items"][0]["status"] == "collected"
        assert agent_billing.overview(st, tenant)["items"][0]["report"]["net_amount"] == "0"
    monkeypatch.setenv("OPENAIDR_DATABASE_URL", st.url)
    monkeypatch.setenv("OPENAIDR_TENANT_ID", tenant)
    assert main(["billing", "report", "--provider", "copilot"]) == 0
    assert json.loads(capsys.readouterr().out)["items"][0]["report"]["net_amount"] == "0"
    monkeypatch.delenv("OPENAIDR_COPILOT_BILLING_TOKEN")
    assert main(["billing", "sync", "--provider", "copilot", "--account", "example", "--month", "2026-10", "--billing-model", "ai_credit"]) == 1
    assert "missing_credential" in capsys.readouterr().out
    cfg.set_services("api")
    with TestClient(create_app(cfg, st)) as api:
        path = "/api/v1/costs/billing"
        assert api.get(path).status_code == 401
        for role, expected in (("analyst", 403), ("owner", 200)):
            user = st.create_user(tenant, role + "@example.com", role, "unused", role)
            api.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], tenant))
            response = api.get(path)
            assert response.status_code == expected, response.text
        assert response.json()["items"][0]["status"] == "failed"
        assert response.json()["items"][0]["report"]["net_amount"] == "0"
        foreign = st.create_user(other["tenant_id"], "owner@other.com", "Other", "unused", "owner")
        api.cookies.set(CONSOLE_COOKIE, st.create_session(foreign["id"], other["tenant_id"]))
        assert api.get(path).status_code == 403


@pytest.mark.parametrize("scope,segment", [("organization", "organizations"), ("enterprise", "enterprises"), ("user", "users")])
@pytest.mark.parametrize("basis", copilot_billing.BASES)
def test_provider_contracts(scope, segment, basis):
    def transport(request):
        assert request.url.path == f"/{segment}/example/settings/billing/{basis}/usage"
        assert request.headers["X-GitHub-Api-Version"] == "2026-03-10"
        return httpx.Response(200, json=billing_report("Copilot AI Credits" if scope == "user" and basis == "ai_credit" else "Copilot"))
    with httpx.Client(transport=httpx.MockTransport(transport)) as http:
        assert copilot_billing.fetch(scope, "example", "2026-10", basis, "test", client=http)["net_amount"] == "0.20123456789"


@pytest.mark.parametrize("value", [None, True, -1, "NaN", "Infinity", {}, "unknown"])
def test_malformed_amount_does_not_create_zero_cost(value):
    data = deepcopy(billing_report())
    data["usageItems"][0]["netAmount"] = value
    with pytest.raises(agent_billing.BillingError, match="invalid_response"):
        copilot_billing.normalize(data, "2026-10")


def test_provider_errors_are_bounded_and_do_not_expose_secrets():
    def timeout(request):
        raise httpx.ReadTimeout("private provider error", request=request)
    for handler, error in (
        (timeout, "provider_unavailable"),
        (lambda request: httpx.Response(200, content=b"private provider error"), "invalid_response"),
        (lambda request: httpx.Response(200, content=b"x" * (8 * 1024 * 1024 + 1)), "response_too_large"),
    ):
        with httpx.Client(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(agent_billing.BillingError) as raised:
                copilot_billing.fetch("organization", "example", "2026-10", "ai_credit", "private-token", client=http)
            assert str(raised.value) == error
