"""Cursor pagination and cents accounting through the tenant billing ledger."""

from copy import deepcopy
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from openaidr.server import agent_billing, cursor_billing
from openaidr.server.app import create_app
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server.cli import main
from test_telemetry_server import backend  # noqa: F401


def page(user, spend="12.3456789", overall="102.3456789"):
    return dict(subscriptionCycleStart=1790812800000, totalMembers=2, totalPages=2,
                teamMemberSpend=[dict(userId=user, spendCents=spend, overallSpendCents=overall,
                    email="DO-NOT-RETAIN", name="DO-NOT-RETAIN")])


def test_current_cycle_spend_replaces_snapshots_and_preserves_partial_failure(backend, monkeypatch, capsys):
    st, cfg, sensor, _, other, *_ = backend
    monkeypatch.setenv("OPENAIDR_CURSOR_BILLING_TOKEN", "test-key")
    pages = [page("user_one"), page("user_two", "0", "90")]
    visits = []

    def transport(request):
        assert request.url == "https://api.cursor.com/teams/spend"
        assert request.headers["Authorization"] == "Basic dGVzdC1rZXk6"
        body = json.loads(request.content)
        assert body["pageSize"] == 100 and body["sortBy"] == "user"
        visits.append(body["page"])
        return httpx.Response(200, json=pages[body["page"] - 1])

    with httpx.Client(transport=httpx.MockTransport(transport)) as http:
        def sync():
            return cursor_billing.sync(st, sensor["tenant_id"], "team-one", client=http)
        assert sync()["status"] == "collected"
        assert sync()["status"] == "collected"
        assert visits == [1, 2, 1, 2]
        row, = agent_billing.overview(st, sensor["tenant_id"], "cursor")["items"]
        assert row["report"]["on_demand_usd"] == "0.123456789"
        assert row["report"]["overall_usage_usd"] == "1.923456789"
        assert "DO-NOT-RETAIN" not in json.dumps(row)
        assert agent_billing.overview(st, other["tenant_id"], "cursor")["items"] == []
        pages[1]["subscriptionCycleStart"] += 86400000
        assert sync()["error_code"] == "snapshot_changed"
        failed, = agent_billing.overview(st, sensor["tenant_id"], "cursor")["items"]
        assert failed["report"] == row["report"] and failed["collected_at"] == row["collected_at"]
        pages[:] = [dict(subscriptionCycleStart=1793491200000, totalMembers=0, totalPages=0, teamMemberSpend=[])]
        assert sync()["status"] == "collected"
        final, = agent_billing.overview(st, sensor["tenant_id"], "cursor")["items"]
        assert final["report"]["on_demand_usd"] == "0" and final["report"]["members"] == []
        assert final["report"]["cycle_start"] != row["report"]["cycle_start"]
        original = cursor_billing.fetch
        monkeypatch.setattr(cursor_billing, "fetch", lambda token, **kwargs: original(token, client=http))
        monkeypatch.setenv("OPENAIDR_DATABASE_URL", st.url)
        monkeypatch.setenv("OPENAIDR_TENANT_ID", sensor["tenant_id"])
        args = ["billing", "sync", "--provider", "cursor", "--account-scope", "team", "--account", "team-one"]
        assert main(args) == 0
        assert json.loads(capsys.readouterr().out)["status"] == "collected"
        assert main(args + ["--month", "2026-10"]) == 1
        assert "without --month" in capsys.readouterr().err
    cfg.set_services("api")
    with TestClient(create_app(cfg, st)) as api:
        owner = st.create_user(sensor["tenant_id"], "owner@example.com", "Owner", "unused", "owner")
        api.cookies.set(CONSOLE_COOKIE, st.create_session(owner["id"], sensor["tenant_id"]))
        response = api.get("/api/v1/costs/billing?provider=cursor")
        assert response.status_code == 200, response.text
        assert response.json()["items"][0]["provider"] == "cursor"
        assert api.get("/api/v1/costs/billing?provider=copilot").json()["items"] == []


@pytest.mark.parametrize("failure", ["duplicate", "count", "pages", "negative", "missing", "forbidden"])
def test_incomplete_or_invalid_cursor_reports_cannot_look_successful(failure):
    first, second = page("user_one"), page("user_two")
    if failure == "duplicate":
        second = deepcopy(first)
    elif failure == "count":
        first["totalMembers"] = second["totalMembers"] = 3
    elif failure == "pages":
        first["totalPages"] = 101
    elif failure == "negative":
        second["teamMemberSpend"][0]["spendCents"] = -1
    elif failure == "missing":
        del second["teamMemberSpend"][0]["spendCents"]

    def transport(request):
        page_number = json.loads(request.content)["page"]
        return httpx.Response(403 if failure == "forbidden" and page_number == 2 else 200,
                              json=first if page_number == 1 else second)
    with httpx.Client(transport=httpx.MockTransport(transport)) as http:
        with pytest.raises(agent_billing.BillingError):
            cursor_billing.fetch("test", client=http)
