"""Hourly accounting, bounded reads, and cache behavior against PostgreSQL."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier, Event, Lock

import pytest

from openaidr.server.agent_cost_summaries import (
    CostCache,
    mark_dirty,
    overview,
    queue_rebuild,
    rebuild_pending,
    source,
)
from openaidr.server.agent_cost_usage import process_pending, overview as fact_overview
from openaidr.server.store import Busy, new_id
from test_telemetry_dashboard import dashboard, cost_payload  # noqa: F401


def assert_user_series(data):
    users = data["user_series"]
    assert len(users) <= 6
    for user in users:
        assert [point["time"] for point in user["series"]] == [
            point["time"] for point in data["series"]
        ]
    for total, parts in [
        (data["summary"], users),
        *((point, [user["series"][i] for user in users]) for i, point in enumerate(data["series"])),
        *((user, user["series"]) for user in users),
    ]:
        for metric in data["summary"]:
            if metric == "cost_usd" and not total["priced_calls"]:
                assert total[metric] is None
                assert all(part[metric] is None for part in parts)
            else:
                assert sum(part[metric] or 0 for part in parts) == pytest.approx(total[metric])


def test_ninety_day_range_preserves_history_filters_and_tenant_scope(dashboard):
    st, _, client, sensor, _, remote = dashboard
    now = st.scalar("SELECT now()")
    for device, days, project, cost in [
        (sensor, 1, "Recent", "1"),
        (sensor, 60, "Archive", "2"),
        (sensor, 89, "Archive", "3"),
        (sensor, 91, "Expired", "4"),
        (remote, 60, "Private", "999"),
    ]:
        st.ingest_telemetry(device, "logs", new_id(), cost_payload(
            "claude-code", now - timedelta(days=days),
            [("claude_code.api_request", {"cost_usd": cost, "project.name": project})],
        ), 1)
    process_pending(st)
    for summarized in (False, True):
        if summarized:
            rebuild_pending(st)
        response = client.get("/api/v1/costs/agents/summary?range=90d")
        assert response.status_code == 200
        data = response.json()
        assert data["range"] == "90d"
        assert datetime.fromisoformat(data["until"]) - datetime.fromisoformat(data["since"]) == timedelta(days=90)
        assert data["bucket_seconds"] == 86400
        assert len(data["series"]) == 91
        assert data["summary"]["calls"] == 3
        assert data["summary"]["cost_usd"] == 6
        assert data["summary"] == fact_overview(st, sensor["tenant_id"], "90d")["summary"]
        assert data["available_filters"]["project"] == ["Archive", "Recent"]
        assert_user_series(data)
    filtered = client.get("/api/v1/costs/agents/summary?range=90d&project=Archive").json()
    assert filtered["summary"]["calls"] == 2
    assert filtered["summary"]["cost_usd"] == 5
    assert_user_series(filtered)
    for window, names in [("7d", ["Recent"]), ("30d", ["Recent"]), ("90d", ["Archive", "Recent"])]:
        options = client.get(f"/api/v1/costs/agents/filters?range={window}&dimension=project")
        assert options.status_code == 200
        assert options.json() == {"items": names, "has_more": False}
    assert client.get("/api/v1/costs/agents/summary?range=91d").status_code == 400
    assert client.post("/api/v1/auth/logout", json={}).status_code == 204
    assert client.get("/api/v1/costs/agents/summary?range=90d").status_code == 401
    assert client.get("/api/v1/costs/agents/filters?range=90d&dimension=project").status_code == 401


def test_reasoning_effort_reconciles_filters_history_and_tenant_access(dashboard):
    st, _, client, sensor, _, remote = dashboard
    tenant = sensor["tenant_id"]
    now = st.scalar("SELECT now()")
    events = [
        ("claude_code.api_request", {
            "cost_usd": cost, "input_tokens": "10", "output_tokens": "0", "model": "shared-model",
            **({"reasoning_effort": effort} if effort is not None else {}),
        })
        for effort, cost in [
            ("low", "0.1"), ("high", "0.2"), (None, "0.3"),
            ("invalid", "0.4"), ("auto", "0"), ("none", "0.5"),
        ]
    ]
    events.append(("claude_code.api_request", {
        "model": "unpriced-model", "input_tokens": "50", "output_tokens": "0", "reasoning_effort": "xhigh",
    }))
    for device, when, records in [
        (sensor, now - timedelta(hours=2), events),
        (sensor, now - timedelta(minutes=1), [("claude_code.api_request", {
            "cost_usd": "0.6", "model": "shared-model", "model_reasoning_effort": "high",
        })]),
        (remote, now - timedelta(hours=2), [("claude_code.api_request", {
            "cost_usd": "999", "reasoning_effort": "max",
        })]),
    ]:
        st.ingest_telemetry(device, "logs", new_id(), cost_payload("claude-code", when, records), len(records))
    process_pending(st)
    for _ in range(2):
        data = overview(st, tenant)
        efforts = {row["name"]: row for row in data["by_reasoning_effort"]}
        assert set(efforts) == {"low", "high", "unknown", "auto", "none", "xhigh"}
        assert efforts["high"]["cost_usd"] == 0.8
        assert efforts["high"]["calls"] == 2
        assert efforts["unknown"]["calls"] == 2
        assert efforts["unknown"]["cost_usd"] == 0.7
        assert efforts["auto"]["cost_usd"] == 0
        assert efforts["xhigh"]["cost_usd"] is None
        assert efforts["xhigh"]["unpriced_calls"] == 1
        assert sum(row["calls"] for row in efforts.values()) == data["summary"]["calls"] == 8
        assert sum(row["cost_usd"] or 0 for row in efforts.values()) == pytest.approx(data["summary"]["cost_usd"])
        for filters in ({}, {"reasoning_effort": "high", "model": "shared-model"}, {"reasoning_effort": "unknown"}, {"reasoning_effort": "max"}):
            actual = overview(st, tenant, filters=filters)
            facts = fact_overview(st, tenant, filters=filters)
            assert actual["summary"] == facts["summary"]
            assert actual["by_reasoning_effort"] == facts["by_reasoning_effort"]
            assert_user_series(actual)
            assert sum(row["calls"] for row in actual["series"]) == actual["summary"]["calls"]
        rebuild_pending(st)
    # An upgrade invalidates already clean summaries and retains accounted usage.
    expected = overview(st, tenant)
    st.execute("DELETE FROM agent_cost_hours WHERE kind='reasoning_effort'")
    st.execute("ALTER TABLE agent_cost_hours DROP COLUMN reasoning_effort")
    st.execute("DELETE FROM schema_migrations WHERE version=63")
    assert st.migrate() == ["0063_agent_cost_reasoning_effort.sql"]
    assert st.migrate() == []
    for _ in range(2):
        actual = overview(st, tenant)
        assert actual["summary"] == expected["summary"]
        assert actual["by_reasoning_effort"] == expected["by_reasoning_effort"]
        rebuild_pending(st)
    response = client.get("/api/v1/costs/agents/summary?reasoning_effort=high&model=shared-model")
    assert response.status_code == 200
    assert response.json()["summary"]["calls"] == 2
    assert "PRIVATE-PROMPT" not in response.text
    assert client.get("/api/v1/costs/agents/summary?reasoning_effort=max").json()["summary"]["calls"] == 0
    assert client.get("/api/v1/costs/agents/filters?dimension=reasoning_effort&search=hi").json() == {
        "items": ["high", "xhigh"], "has_more": False,
    }
    assert client.post("/api/v1/auth/logout", json={}).status_code == 204
    assert client.get("/api/v1/costs/agents/summary?reasoning_effort=high&model=shared-model").status_code == 401
    assert client.get("/api/v1/costs/agents/filters?dimension=reasoning_effort&search=hi").status_code == 401


def test_hourly_upgrade_exact_boundaries_and_late_attribution(dashboard):
    st, _, client, sensor, _, _ = dashboard
    tenant = sensor["tenant_id"]
    until = st.scalar("SELECT now()").astimezone(timezone.utc)
    for minutes, price, attrs in [
        (1441, "99", {}),
        (1439, "0.1", {}),
        (121, "0.2", {"session.id": "late"}),
        (2, "0.3", {}),
        (-1, "88", {}),
    ]:
        st.ingest_telemetry(
            sensor,
            "logs",
            new_id(),
            cost_payload(
                "claude-code",
                until - timedelta(minutes=minutes),
                [
                    ("claude_code.api_request", {"cost_usd": price, **attrs}),
                ],
            ),
            1,
        )
    process_pending(st)
    # Upgrade already-projected history, including a repeated no-op migration.
    st.execute("DROP FUNCTION agent_cost_queue_changed_hours() CASCADE")
    for table in ("agent_cost_hours", "agent_cost_dirty_hours", "agent_cost_versions"):
        st.execute(f"DROP TABLE {table}")
    st.execute("DELETE FROM schema_migrations WHERE version IN (21,24,25,63)")
    assert st.migrate() == [
        "0021_agent_cost_summaries.sql", "0024_agent_cost_summary_backfill.sql",
        "0025_agent_cost_summary_retry.sql", "0063_agent_cost_reasoning_effort.sql",
    ]
    assert st.migrate() == []
    expected = fact_overview(st, tenant)
    for before_rebuild in (True, False):
        if not before_rebuild:
            assert rebuild_pending(st, tenant) > 0
            assert rebuild_pending(st, tenant) == 0
        cte, args = source(tenant, until - timedelta(days=1), until)
        with st.transaction() as conn:
            result = conn.execute(
                cte + " SELECT sum(calls) AS calls,sum(cost_usd) AS cost FROM usage",
                args,
            ).fetchone()
        assert result["calls"] == 3 and float(result["cost"]) == 0.6
        for window in ("24h", "7d", "30d"):
            actual, facts = (
                overview(st, tenant, window),
                fact_overview(st, tenant, window),
            )
            assert actual["summary"] == facts["summary"]
            assert_user_series(actual)
            for dimension in ("user", "model", "project", "activity", "reasoning_effort"):
                assert actual["by_" + dimension] == facts["by_" + dimension]
    # The pre-upgrade projector has no summary calls. Its writes after the
    # backfill snapshot must still queue hours, including previously absent ones.
    late = until - timedelta(hours=6)
    st.ingest_telemetry(
        sensor,
        "logs",
        new_id(),
        cost_payload(
            "claude-code",
            late,
            [
                ("claude_code.api_request", {"cost_usd": "1.25"}),
            ],
        ),
        1,
    )
    process_pending(st)
    late_hour = late.replace(minute=0, second=0, microsecond=0)
    assert st.scalar("SELECT bucket FROM agent_cost_dirty_hours") == late_hour
    assert overview(st, tenant)["summary"] == fact_overview(st, tenant)["summary"]
    rebuild_pending(st, tenant)
    revision = st.scalar(
        "SELECT revision FROM agent_cost_versions WHERE tenant_id=$1", tenant
    )
    st.execute(
        "UPDATE agent_cost_records SET cost_usd=2.5,happened_at=happened_at-interval '1 hour' "
        "WHERE tenant_id=$1 AND cost_usd=1.25",
        tenant,
    )
    assert {
        r["bucket"] for r in st.many("SELECT bucket FROM agent_cost_dirty_hours")
    } == {
        late_hour,
        late_hour - timedelta(hours=1),
    }
    assert (
        st.scalar("SELECT revision FROM agent_cost_versions WHERE tenant_id=$1", tenant)
        > revision
    )
    rebuild_pending(st, tenant)
    assert overview(st, tenant)["summary"] == fact_overview(st, tenant)["summary"]
    st.execute(
        "DELETE FROM agent_cost_records WHERE tenant_id=$1 AND cost_usd=2.5", tenant
    )
    assert st.scalar(
        "SELECT bucket FROM agent_cost_dirty_hours"
    ) == late_hour - timedelta(hours=1)
    assert overview(st, tenant)["summary"] == expected["summary"]
    rebuild_pending(st, tenant)
    # Both a late prompt and tool affect an already summarized historical hour.
    for minutes, name, attrs in [
        (122, "claude_code.user_prompt", {}),
        (
            120.5,
            "claude_code.tool_result",
            {"tool_name": "Edit", "cwd": "/late-project"},
        ),
    ]:
        st.ingest_telemetry(
            sensor,
            "logs",
            new_id(),
            cost_payload(
                "claude-code",
                until - timedelta(minutes=minutes),
                [
                    (name, {"session.id": "late", **attrs}),
                ],
            ),
            1,
        )
    process_pending(st)
    for _ in range(2):
        result = client.get(
            "/api/v1/costs/agents/summary?project=late-project&activity=Coding"
        ).json()
        assert result["summary"]["calls"] == 1
        assert result["summary"]["cost_usd"] == 0.2
        rebuild_pending(st, tenant)
    assert overview(st, tenant)["summary"] == expected["summary"]



def test_user_series_preserve_zero_unpriced_usage_filters_and_tenant_access(dashboard):
    st, _, _, sensor, _, remote = dashboard
    now = st.scalar("SELECT now()")
    for minutes, user, price in [
        (121, "Alice", "1.25"), (61, "Alice", None),
        (60, "Bob", "0"), (59, "Other users", None),
    ]:
        attrs = {"os.user": user, "model": "custom-model", "project.name": "Shared", "input_tokens": 10, "output_tokens": 0}
        if price is not None:
            attrs["cost_usd"] = price
        st.ingest_telemetry(sensor, "logs", new_id(), cost_payload(
            "claude-code", now - timedelta(minutes=minutes),
            [("claude_code.api_request", attrs)],
        ), 1)
    st.ingest_telemetry(remote, "logs", new_id(), cost_payload(
        "claude-code", now - timedelta(hours=2),
        [("claude_code.api_request", {"os.user": "Private", "cost_usd": "999"})],
    ), 1)
    process_pending(st)
    for summarized in (False, True):
        if summarized:
            rebuild_pending(st)
        for window in ("24h", "7d", "30d"):
            for filters in ({}, {"project": "Shared", "model": "custom-model"}, {"user": "Alice"}, {"user": "absent"}):
                data = overview(st, sensor["tenant_id"], window, filters)
                assert_user_series(data)
                assert all(user["name"] != "Private" for user in data["user_series"])
                assert data["summary"]["cost_usd"] == (None if filters.get("user") == "absent" else 1.25)
        data = overview(st, sensor["tenant_id"])
        users = {user["name"]: user for user in data["user_series"]}
        assert list(users) == ["Alice", "Bob", "Other users"]
        assert users["Alice"]["unpriced_calls"] == 1
        assert users["Bob"]["cost_usd"] == 0
        assert users["Other users"]["cost_usd"] is None
        assert any(point["calls"] and point["cost_usd"] is None for point in users["Alice"]["series"])

def test_cost_pages_search_and_cached_tenant_access(dashboard):
    st, cfg, client, sensor, _, remote = dashboard
    client.app.state.service.cost_cache.clock = lambda: 0
    now = st.scalar("SELECT now()") - timedelta(hours=2)
    records = [
        (
            "claude_code.api_request",
            {
                "cost_usd": str(index),
                "os.user": f"Person {index:03}",
                "model": {126: "jev-1.13.0", 127: "Guardrail-native", 128: "JEV-2"}.get(index, f"model-{index % 3}"),
                "project.name": f"Project {index % 2}",
            },
        )
        for index in range(130)
    ]
    st.ingest_telemetry(
        sensor,
        "logs",
        new_id(),
        cost_payload("claude-code", now, records),
        len(records),
    )
    st.ingest_telemetry(
        remote,
        "logs",
        new_id(),
        cost_payload(
            "claude-code",
            now,
            [
                (
                    "claude_code.api_request",
                    {"cost_usd": "999", "os.user": "Private tenant user", "model": "jev-private"},
                ),
            ],
        ),
        1,
    )
    process_pending(st)
    rebuild_pending(st)
    data = client.get("/api/v1/costs/agents/summary").json()
    assert data["summary"]["calls"] == 130
    assert len(data["by_user"]) == 25 and data["by_user"][0]["name"] == "Person 129"
    assert data["pagination"]["user"]["total"] == 130
    assert data["filters_truncated"]["user"]
    assert len(data["available_filters"]["user"]) == 100
    assert_user_series(data)
    assert [user["name"] for user in data["user_series"]] == [
        "Person 129", "Person 128", "Person 127", "Person 126", "Person 125", None,
    ]
    assert data["user_series"][-1]["calls"] == 125
    assert data["user_series"][-1]["cost_usd"] == sum(range(125))
    # Already-open dashboards keep the complete legacy contract during rollout.
    legacy = client.get("/api/v1/costs/agents").json()
    assert legacy["summary"] == data["summary"]
    assert len(legacy["by_user"]) == len(legacy["available_filters"]["user"]) == 130
    assert "pagination" not in legacy
    assert (
        client.get("/api/v1/costs/agents?user=Person%20129").json()["summary"]["calls"]
        == 1
    )
    names = []
    for offset in range(0, 130, 25):
        page = client.get(
            f"/api/v1/costs/agents/summary?user_offset={offset}&user_order=asc"
        ).json()
        assert page["summary"] == data["summary"]
        assert page["user_series"] == data["user_series"]
        assert page["pagination"]["user"] == {
            "offset": offset, "sort": "cost_usd", "order": "asc",
            "limit": 25, "total": 130, "maximum": 129,
        }
        names.extend(row["name"] for row in page["by_user"])
    assert names == [f"Person {index:03}" for index in range(130)]
    beyond = client.get("/api/v1/costs/agents/summary?user_offset=999").json()
    assert beyond["by_user"] == [] and beyond["pagination"]["user"]["total"] == 130
    assert beyond["user_series"] == data["user_series"]
    options = client.get(
        "/api/v1/costs/agents/filters?dimension=user&search=129"
    ).json()
    assert options == {"items": ["Person 129"], "has_more": False}
    for search in ("Guar", "gUaRdRaIl"):
        models = client.get(
            "/api/v1/costs/agents/filters", params={"dimension": "model", "search": search}
        ).json()
        assert set(models["items"]) == {"jev-1.13.0", "Guardrail-native", "JEV-2"}
        assert models["has_more"] is False
    assert set(client.get(
        "/api/v1/costs/agents/filters?dimension=model&search=jev"
    ).json()["items"]) == {"jev-1.13.0", "JEV-2"}
    assert client.get(
        "/api/v1/costs/agents/filters?dimension=model&search=Guardrail-private"
    ).json()["items"] == []
    assert client.get(
        "/api/v1/costs/agents/summary?model=jev-1.13.0"
    ).json()["summary"]["calls"] == 1
    assert (
        client.get("/api/v1/costs/agents/filters?dimension=user&search=Private").json()[
            "items"
        ]
        == []
    )
    for suffix in (
        "user_sort=cost_usd;select 1",
        "user_offset=-1",
        "user_order=sideways",
    ):
        assert client.get("/api/v1/costs/agents/summary?" + suffix).status_code == 400
    assert (
        client.get("/api/v1/costs/agents/filters?dimension=secret").status_code == 400
    )
    # Even warm cached responses must recheck the session before being served.
    assert client.post("/api/v1/auth/logout", json={}).status_code == 204
    assert client.get("/api/v1/costs/agents/summary").status_code == 401
    assert (
        client.get("/api/v1/costs/agents/filters?dimension=user&search=129").status_code
        == 401
    )


def test_cost_cache_coalesces_refreshes_and_invalidates_after_projection(dashboard):
    st, _, _, sensor, _, _ = dashboard
    tenant = sensor["tenant_id"]
    clock = [0.0]
    cache, lock, barrier = CostCache(clock=lambda: clock[0]), Lock(), Barrier(12)
    calls = 0

    def compute():
        nonlocal calls
        with lock:
            calls += 1
        return overview(st, tenant)

    def read(_):
        barrier.wait(timeout=10)
        return cache.get(st, tenant, ("24h",), compute)

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(read, range(12)))
    assert calls == 1 and all(result == results[0] for result in results)
    st.ingest_telemetry(
        sensor,
        "logs",
        new_id(),
        cost_payload(
            "claude-code",
            st.scalar("SELECT now()") - timedelta(minutes=1),
            [
                ("claude_code.api_request", {"cost_usd": "1"}),
            ],
        ),
        1,
    )
    process_pending(st)
    assert cache.get(st, tenant, ("24h",), compute)["summary"]["calls"] == 0
    clock[0] = 2
    started, release = Event(), Event()

    def refresh():
        started.set()
        assert release.wait(timeout=10)
        return compute()

    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(cache.get, st, tenant, ("24h",), refresh)
        try:
            assert started.wait(timeout=10)
            follower = pool.submit(cache.get, st, tenant, ("24h",), compute)
            assert follower.result(timeout=5)["summary"]["calls"] == 0
        finally:
            release.set()
        assert owner.result(timeout=10)["summary"]["calls"] == 1
    assert calls == 2
    clock[0] = 18
    assert cache.get(st, tenant, ("24h",), compute)["summary"]["calls"] == 1
    assert calls == 3

    # Failed computations are not retained, so retries can recover.
    def fail():
        with st.transaction() as conn:
            conn.execute("SET LOCAL statement_timeout='1ms'")
            conn.execute("SELECT pg_sleep(0.05)")

    with pytest.raises(Busy, match="timed out"):
        cache.get(st, tenant, ("failed",), fail)
    assert cache.get(st, tenant, ("failed",), compute)["summary"]["calls"] == 1


def test_summary_workers_do_not_lose_concurrent_changes(dashboard):
    st, _, _, sensor, _, _ = dashboard
    tenant = sensor["tenant_id"]
    stamp = st.scalar("SELECT now()") - timedelta(hours=2)
    barrier = Barrier(3)

    def project():
        barrier.wait(timeout=10)
        for index in range(16):
            st.ingest_telemetry(
                sensor,
                "logs",
                new_id(),
                cost_payload(
                    "claude-code",
                    stamp,
                    [
                        (
                            "claude_code.api_request",
                            {"cost_usd": "0.1", "request_id": f"concurrent-{index}"},
                        ),
                    ],
                ),
                1,
            )
            assert not process_pending(st, tenant)["failed"]

    def summarize():
        barrier.wait(timeout=10)
        for _ in range(24):
            rebuild_pending(st, tenant, 1)
            data = overview(st, tenant)
            assert (
                sum(row["calls"] for row in data["by_user"]) == data["summary"]["calls"]
            )

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(project), pool.submit(summarize), pool.submit(summarize)]
        for future in futures:
            future.result(timeout=30)
    rebuild_pending(st, tenant)
    result = overview(st, tenant)
    assert result["summary"]["calls"] == 16 and result["summary"]["cost_usd"] == 1.6
    assert st.scalar("SELECT count(*) FROM agent_cost_dirty_hours") == 0
    # Deletes queue themselves; an explicit rebuild also repairs offline restores.
    st.execute("DELETE FROM agent_cost_records WHERE tenant_id=$1", tenant)
    with pytest.raises(ValueError):
        queue_rebuild(st, "")
    queue_rebuild(st, tenant)
    assert overview(st, tenant)["summary"]["calls"] == 0
    rebuild_pending(st, tenant)
    assert st.scalar("SELECT count(*) FROM agent_cost_hours") == 0
    with st.transaction() as conn:
        mark_dirty(
            conn, tenant, [stamp.astimezone(timezone(timedelta(hours=5, minutes=30)))]
        )
    assert st.scalar("SELECT bucket FROM agent_cost_dirty_hours") == stamp.replace(
        minute=0, second=0, microsecond=0
    )


def test_large_export_bounds_queue_writes_and_preserves_duplicate_costs(dashboard):
    st, _, client, sensor, _, _ = dashboard
    tenant = sensor["tenant_id"]
    stamp = st.scalar("SELECT now()") - timedelta(hours=6)
    events = [
        ("claude_code.api_request", {
            "request_id": f"batch-{i}", "cost_usd": "0.001", "cwd": "/work/project",
        })
        for i in range(2500)
    ]
    events.append(
        ("claude_code.api_request", {"request_id": "batch-0", "cost_usd": "99"})
    )
    payload = cost_payload("claude-code", stamp, events)
    st.ingest_telemetry(sensor, "logs", new_id(), payload, len(events))
    assert process_pending(st, tenant) == {"exports": 1, "failed": 0}
    revision = st.scalar(
        "SELECT revision FROM agent_cost_versions WHERE tenant_id=$1", tenant
    )
    # Thousands of calls must not produce thousands of shared revision writes.
    assert revision < 10
    data = client.get("/api/v1/costs/agents/summary").json()
    assert data["summary"]["calls"] == 2500 and data["summary"]["cost_usd"] == 2.5
    st.ingest_telemetry(sensor, "logs", new_id(), payload, len(events))
    assert process_pending(st, tenant) == {"exports": 1, "failed": 0}
    assert (
        st.scalar("SELECT revision FROM agent_cost_versions WHERE tenant_id=$1", tenant)
        == revision
    )
    assert overview(st, tenant)["summary"] == data["summary"]
    # Folder upgrades refresh metadata in batches without replacing prices.
    st.execute(
        "UPDATE agent_cost_records SET direct_project='/work/project',project='/work/project'"
    )
    before = st.scalar("SELECT revision FROM agent_cost_versions WHERE tenant_id=$1", tenant)
    st.execute("UPDATE telemetry_exports SET costs_processed_at=NULL,costs_reattribute=true")
    assert process_pending(st, tenant) == {"exports": 2, "failed": 0}
    assert st.scalar("SELECT revision FROM agent_cost_versions WHERE tenant_id=$1", tenant) - before < 10
    refreshed = overview(st, tenant)
    assert refreshed["summary"] == data["summary"]
    assert [row["name"] for row in refreshed["by_project"]] == ["project"]


def test_timed_out_hour_defers_without_stalling_newer_summaries(dashboard, monkeypatch, capsys):
    import json
    from psycopg.errors import QueryCanceled
    from openaidr.server.cli import main

    st, _, _, sensor, _, _ = dashboard
    tenant = sensor["tenant_id"]
    oldest = (st.scalar("SELECT now()") - timedelta(hours=6)).replace(
        minute=0, second=0, microsecond=0
    )
    for hours, price in ((0, "1"), (4, "2")):
        st.ingest_telemetry(
            sensor, "logs", new_id(),
            cost_payload("claude-code", oldest + timedelta(hours=hours), [
                ("claude_code.api_request", {"cost_usd": price}),
            ]), 1,
        )
    process_pending(st, tenant)
    rebuild_pending(st, tenant)
    st.execute("UPDATE agent_cost_records SET cost_usd=cost_usd+2 WHERE is_usage")
    st.execute("""CREATE FUNCTION fail_oldest_cost_hour() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
            IF NEW.bucket=(SELECT min(bucket) FROM agent_cost_dirty_hours) THEN
                RAISE EXCEPTION 'forced aggregation timeout' USING ERRCODE='57014';
            END IF;
            RETURN NEW;
        END $$;
        CREATE TRIGGER fail_oldest_cost_hour BEFORE INSERT ON agent_cost_hours
        FOR EACH ROW EXECUTE FUNCTION fail_oldest_cost_hour()""")
    with pytest.raises(QueryCanceled, match="forced aggregation timeout"):
        rebuild_pending(st, tenant)
    # The failed hour keeps its previous atomic snapshot, while newer work
    # completes and reads include the dirty hour's current facts.
    assert st.scalar(
        "SELECT cost_usd FROM agent_cost_hours WHERE kind='summary' AND bucket>$1",
        oldest,
    ) == 4
    assert st.scalar(
        "SELECT cost_usd FROM agent_cost_hours WHERE kind='summary' AND bucket=$1",
        oldest,
    ) == 1
    assert overview(st, tenant)["summary"]["cost_usd"] == 7
    assert st.scalar("SELECT count(*) FROM agent_cost_dirty_hours") == 1
    assert st.scalar("SELECT retry_after>clock_timestamp() FROM agent_cost_dirty_hours")
    assert rebuild_pending(st, tenant) == 0
    monkeypatch.setenv("OPENAIDR_DATABASE_URL", st.url)
    monkeypatch.setenv("OPENAIDR_TENANT_ID", tenant)
    assert main(["telemetry", "costs"]) == 1
    assert json.loads(capsys.readouterr().out)["pending_summary_hours"] == 1
    st.execute("DROP FUNCTION fail_oldest_cost_hour() CASCADE")
    st.execute("UPDATE agent_cost_dirty_hours SET retry_after='-infinity'")
    assert rebuild_pending(st, tenant) == 1
    assert st.scalar("SELECT count(*) FROM agent_cost_dirty_hours") == 0
    assert overview(st, tenant)["summary"] == fact_overview(st, tenant)["summary"]


@pytest.mark.parametrize("writer", ["trigger", "rebuild"])
def test_revision_lock_precedes_hours_across_interleaved_writes(dashboard, writer):
    import time

    st, _, _, sensor, _, _ = dashboard
    tenant = sensor["tenant_id"]
    stamp = st.scalar("SELECT now()") - timedelta(hours=6)
    st.ingest_telemetry(
        sensor,
        "logs",
        new_id(),
        cost_payload(
            "claude-code",
            stamp,
            [
                ("claude_code.api_request", {"cost_usd": "1"}),
            ],
        ),
        1,
    )
    process_pending(st, tenant)
    rebuild_pending(st, tenant)
    first = stamp.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    second = first + timedelta(hours=1)
    started = Event()
    backend = []

    def other_writer():
        with st.transaction() as conn:
            conn.execute("SET LOCAL lock_timeout='5s'")
            backend.append(conn.info.backend_pid)
            started.set()
            if writer == "trigger":
                conn.execute(
                    "UPDATE agent_cost_records SET cost_usd=2 WHERE tenant_id=%s AND is_usage",
                    (tenant,),
                )
            else:
                mark_dirty(conn, tenant, [second])

    with ThreadPoolExecutor(max_workers=1) as pool:
        with st.transaction() as conn:
            conn.execute("SET LOCAL lock_timeout='2s'")
            mark_dirty(conn, tenant, [first])
            future = pool.submit(other_writer)
            assert started.wait(timeout=5)
            deadline = time.monotonic() + 5
            while (
                st.scalar(
                    "SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1",
                    backend[0],
                )
                != "Lock"
            ):
                assert time.monotonic() < deadline, (
                    "writer did not reach the version lock"
                )
                time.sleep(0.01)
            # The second writer must wait before locking this hour. Reversed
            # lock order deadlocks here because this transaction owns the version.
            mark_dirty(conn, tenant, [second])
        future.result(timeout=5)
    assert (
        st.scalar(
            "SELECT count(*) FROM agent_cost_dirty_hours WHERE tenant_id=$1", tenant
        )
        == 2
    )
    assert overview(st, tenant)["summary"]["cost_usd"] == (
        2 if writer == "trigger" else 1
    )
