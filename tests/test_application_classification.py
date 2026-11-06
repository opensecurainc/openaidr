"""Search-backed inventory against real PostgreSQL; only OpenAI is mocked."""

from openaidr_api.providers import applications as provider_classifier

import asyncio
import hashlib
import json
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest
from openaidr_api_client.validation.applications import MODEL

from openaidr.server import application_classifier as classifier, application_review
from openaidr_api.providers import application_assessment
from openaidr.server.auth import CONSOLE_COOKIE
from intelligence_fixture import api_service as api_service
from test_app_inventory_server import inventory, app as installed_app, snapshot, post, AI_APPS, INGEST

REVIEW = "/api/v1/inventory/application-review"
HEADERS = {"X-OpenAIDR-CSRF": "1"}


def test_cli_inventory_merges_packages_and_keeps_filenames_unidentified(inventory):
    from test_app_inventory_server import component, root, send_components, APPS

    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    _, other_token, other_session = identities[1]
    tenant = sensor["tenant_id"]
    launchers = root("/Users/alice/.local/bin", source="openaidr-cli", components=[
        component("hermes", identifier="pypi:hermes-agent", name="hermes-agent", kind="application", ecosystem=""),
        component("hermes-alias", identifier="pypi:hermes-agent", name="hermes-agent", kind="application", ecosystem=""),
        component("codex", identifier="executable:" + "a" * 64, name="codex", kind="application", ecosystem=""),
    ])
    packages = root(components=[component("hermes-agent")])
    assert send_components(client, token, [launchers, packages]).status_code == 200
    assert send_components(client, other_token, [launchers]).status_code == 200
    rows = client.get(REVIEW).json()["items"]
    assert len(rows) == 2
    hermes = next(item for item in rows if item["id"] == "hermes-agent")
    assert hermes["name"] == "Hermes Agent" and hermes["device_count"] == 1
    assert hermes["software_type"] == "command_line_tool" and hermes["review_required"]
    devices = client.get(REVIEW + "/hermes-agent/devices").json()["items"]
    assert len(devices) == 1 and len(devices[0]["installations"]) == 3
    unknown = next(item for item in rows if item["id"] != "hermes-agent")
    assert unknown["classification_status"] == "unknown" and not unknown["review_required"]
    assert unknown["assessment"] is None and unknown["category"] is None
    products = application_review.observed(st, tenant)
    application_review.sync(st, tenant, products)
    assert st.scalar("SELECT count(*) FROM application_classifications WHERE tenant_id=$1", tenant) == 1
    assert all(entry["category"] != "ai" for entry in client.get(APPS).json()["items"] if entry["name"] == "codex")
    assert "hermes-agent" in {item["id"] for item in client.get(AI_APPS).json()["items"]}
    client.cookies.set(CONSOLE_COOKIE, other_session)
    assert client.get(REVIEW + "/hermes-agent/devices").json()["items"][0]["id"] != sensor["id"]
    # Partial scans retain evidence; a complete empty scan removes only its root.
    launchers.update(status="partial", components=[])
    assert send_components(client, other_token, [launchers], offset=1).status_code == 200
    assert len(client.get(REVIEW).json()["items"]) == 2
    launchers["status"] = "ok"
    assert send_components(client, other_token, [launchers], offset=2).status_code == 200
    assert client.get(REVIEW).json()["items"] == []


def app(identifier, **overrides):
    return installed_app(identifier) | overrides


def assessment(levels=(3, 2, 2, 2), confidence="high"):
    source = "https://example.test/product"
    return {
        "confidence": confidence, "summary": "The documented modes permit these capabilities.",
        **{key: {"level": level, "reason": "Documented product capability.", "sources": [source] if level is not None else []}
           for key, level in zip(application_assessment.DIMENSIONS, levels, strict=True)},
        "controls": {"reason": "Approval and sandbox controls are documented; enabled settings are unknown.", "sources": [source]},
        "reputation": {"reason": "Documented security process; community evidence is limited.", "sources": [source]},
        "risk": {"score": 72, "reason": "Host execution and autonomy create elevated exposure; some evidence is incomplete.", "sources": [source]},
        "report": {
            "purpose": {"reason": "Helps users write code and run development tasks.", "sources": [source]},
            "harms": [{
                "damage": "Commands could change or delete project files.",
                "likelihood": "Higher when commands run without review; local approval settings are unknown.",
                "sources": [source],
            }] if any(level is not None for level in levels) else [],
        },
    }


def response(attention=True, **overrides):
    source = "https://example.test/product"
    return {
        "status": "completed",
        "model": MODEL, "service_tier": "default",
        "usage": {"input_tokens": 200, "output_tokens": 100,
                  "input_tokens_details": {"cached_tokens": 50, "cache_write_tokens": 0}},
        "output": [
            {"type": "web_search_call", "status": "completed",
             "action": {"type": "search", "sources": [{"url": source}]}},
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": json.dumps({
                "needs_attention": attention, "category": "coding_agent" if attention is True else "ordinary" if attention is False else None, "reason": "The official documentation describes this product.",
                "software_type": "application" if attention is not None else None,
                "display_name": "Example application" if attention is not None else None,
                "assessment": assessment() if attention is not None else assessment((None,) * 4, "low"),
                "sources": [source], **overrides,
            })}]},
        ],
    }


def test_review_devices_permissions_and_legacy_approval(inventory):
    st, cfg, client, identities = inventory
    sensor, token, session = identities[0]
    other, other_token, other_session = identities[1]
    tenant = sensor["tenant_id"]
    enrollment = st.create_enrollment_token(tenant)["token"]
    second, second_token, _ = st.enroll_sensor({"enrollment_token": enrollment, "hostname": "second device", "os": "linux"})
    apps = [app("com.anthropic.code", name="Claude Code"), app("opencode", name="OpenCode"), app("editor", name="Editor")]
    assert post(client, token, snapshot(apps + [app("opencode", name="OpenCode", path="/elsewhere/opencode")])).status_code == 200
    assert post(client, second_token, snapshot(apps[:2])).status_code == 200
    assert post(client, other_token, snapshot(apps)).status_code == 200
    rows = {row["name"]: row for row in client.get(REVIEW).json()["items"]}
    assert rows["OpenCode"]["device_count"] == 2
    assert rows["Editor"]["device_count"] == 1
    assert all(row["needs_attention"] and row["approval_status"] == "monitoring" for row in rows.values())
    ident = rows["OpenCode"]["id"]
    devices = client.get(f"{REVIEW}/{ident}/devices").json()["items"]
    assert {item["name"] for item in devices} == {"first", "second device"}
    assert {item["id"] for item in devices} == {sensor["id"], second["id"]}
    assert {entry["path"] for item in devices for entry in item["installations"]} == {"/opt/opencode", "/elsewhere/opencode"}
    path = f"{REVIEW}/{ident}/approval"
    assert client.put(path, json={"approved": True}, headers=HEADERS).status_code == 403
    st.execute("UPDATE tenant_users SET roles=ARRAY['it_admin']::text[] WHERE tenant_id=$1", tenant)
    assert client.put(path, json={"approved": True}).status_code == 403
    assert client.put(path, json={"approved": "true"}, headers=HEADERS).status_code == 400
    assert client.put(path, json={"approved": True}, headers={**HEADERS, "Origin": "https://foreign.test"}).status_code == 403
    assert client.put(path, json={"approved": True}, headers=HEADERS).status_code == 200
    assert st.scalar("SELECT details->>'before_status' FROM audit_log WHERE target_id=$1", ident) == "monitoring"
    assert client.put(AI_APPS + "/claude-code/approval", json={"approved": False}, headers=HEADERS).status_code == 200
    rows = {row["name"]: row for row in client.get(REVIEW).json()["items"]}
    assert rows["OpenCode"]["approval_status"] == "approved"
    assert rows["Claude Code"]["approval_status"] == "unapproved"
    assert client.put(path, json={"approved": False}, headers=HEADERS).status_code == 200
    client.cookies.set(CONSOLE_COOKIE, other_session)
    rows = {row["name"]: row for row in client.get(REVIEW).json()["items"]}
    assert rows["OpenCode"]["device_count"] == 1
    assert rows["OpenCode"]["approval_status"] == "monitoring"
    client.cookies.set(CONSOLE_COOKIE, session)
    st.execute("UPDATE sensors SET deleted_at=now() WHERE id=$1", second["id"])
    assert len(client.get(f"{REVIEW}/{ident}/devices").json()["items"]) == 1
    assert client.get(f"{REVIEW}/absent/devices").status_code == 404
    assert client.put(f"{REVIEW}/absent/approval", json={"approved": True}, headers=HEADERS).status_code == 404


def test_research_progress_tracks_queue_leases_retries_and_completed_evidence(inventory):
    st, _, client, identities = inventory
    sensor, token, _ = identities[0]
    tenant = sensor["tenant_id"]
    post(client, token, snapshot([app("opencode", name="OpenCode")]))

    def status():
        row, = client.get(REVIEW).json()["items"]
        return row["research_status"]

    assert status() == "queued"  # The background inventory scan has not run yet.
    application_review.sync(st, tenant, application_review.observed(st, tenant))
    item = classifier.claim(st, tenant)
    assert status() == "researching"
    st.execute("UPDATE application_classifications SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1", tenant)
    assert status() == "queued"
    item = classifier.claim(st, tenant)
    classifier.finish(st, item)
    assert status() == "retry_pending"
    st.execute("UPDATE application_classifications SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1", tenant)
    assert status() == "retry_pending"
    item = classifier.claim(st, tenant)
    assert status() == "researching"  # A retry with a live lease is in progress.
    classifier.finish(st, item, provider_classifier.parse_result(response(assessment=assessment((3, None, 2, 2)))))
    assert status() == "complete"  # Research completed even though evidence cannot support a score.
    assert client.get(REVIEW).json()["items"][0]["assessment"]["capability_score"] is None
    st.execute("UPDATE application_classifications SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1", tenant)
    assert status() == "queued"  # A scheduled refresh is due.
    item = classifier.claim(st, tenant)
    classifier.finish(st, item, provider_classifier.parse_result(response()))
    assert status() == "complete"
    st.execute("UPDATE application_classifications SET assessment_checked_at=NULL WHERE tenant_id=$1", tenant)
    assert status() == "queued"  # Legacy results still need capability enrichment.
    item = classifier.claim(st, tenant)
    assert status() == "researching"
    post(client, token, snapshot([app("opencode", name="OpenCode", publisher="Changed publisher")], offset=1))
    assert status() == "queued"  # A lease for obsolete metadata is not current research.


def test_classifier_requires_search_caches_and_fences_changes(inventory, monkeypatch, api_service):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    tenant = sensor["tenant_id"]
    assert post(client, token, snapshot([app("opencode", name="OpenCode")])).status_code == 200
    st.execute("INSERT INTO tenant_model_keys(tenant_id,kind,api_key) VALUES($1,'detection','tenant-secret')", tenant)
    st.record_heartbeat(sensor["id"], {"signed_in_user": {"name": "private-login-user", "signed_in_at": "2026-01-01T00:00:00Z"}})
    requests = []
    attention = True
    source = "https://example.test/opened-product"

    def send(request):
        requests.append(json.loads(request.content))
        assert request.headers["Authorization"] == "Bearer tenant-secret"
        payload = response(attention, sources=[source])
        payload["output"].insert(1, {
            "type": "web_search_call", "status": "completed",
            "action": {"type": "open_page", "url": source},
        })
        return httpx.Response(200, json=payload)

    api_service(cfg, cfg.tenant_id or tenant, send, openai_key="tenant-secret")
    assert asyncio.run(classifier.run_once(st, cfg, tenant))
    assert requests[0]["model"] == "gpt-6-luna"
    assert requests[0]["reasoning"] == {"effort": "low"}
    assert requests[0]["tool_choice"] == "required"
    assert requests[0]["tools"] == [{"type": "web_search", "external_web_access": True}]
    assert requests[0]["store"] is False
    assert all(value not in requests[0]["input"] for value in ("/opt", "first", "private-login-user"))
    row = client.get(REVIEW).json()["items"][0]
    assert row["needs_attention"] and row["classification_status"] == "complete"
    assert row["approval_status"] == "monitoring" and row["sources"] == [source]
    assert row["assessment"]["capability_score"] == 75 and row["assessment_status"] == "complete"
    assert st.scalar("SELECT usage->>'web_search_calls' FROM application_classifications") == "1"
    billed = st.one("SELECT * FROM model_usage WHERE purpose='asset_management'")
    assert billed["tenant_id"] == tenant and billed["status"] == "completed"
    assert billed["input_tokens"] == 200 and billed["web_search_calls"] == 1
    assert billed["cost_usd"] == Decimal("0.0100655")
    assert billed["price_quote"]["web_search_per_call"] == "0.01"
    assert st.scalar("SELECT model FROM application_classifications") == "gpt-6-luna"
    assert not asyncio.run(classifier.run_once(st, cfg, tenant))
    assert len(requests) == 1
    before = application_review.observed(st, tenant)[row["id"]]
    st.record_heartbeat(sensor["id"], {"signed_in_user": {"name": "another-private-user", "signed_in_at": "2026-01-02T00:00:00Z"}})
    after = application_review.observed(st, tenant)[row["id"]]
    assert before["evidence_hash"] == after["evidence_hash"] and before["evidence"] == after["evidence"]
    assert client.get(REVIEW).json()["items"][0]["users"] == [{"user": "another-private-user", "device_count": 1}]
    application_review.sync(st, tenant, {row["id"]: after})
    assert not asyncio.run(classifier.run_once(st, cfg, tenant)) and len(requests) == 1
    # Updates to classification evidence invalidate the result, but a version
    # upgrade alone does not repeatedly incur searches for the same product.
    assert post(client, token, snapshot([app("opencode", name="OpenCode", version="2")], offset=1)).status_code == 200
    assert not asyncio.run(classifier.run_once(st, cfg, tenant))
    st.execute("UPDATE application_classifications SET next_attempt_at=now()")
    previous = classifier.claim(st, tenant)
    assert classifier.claim(st, tenant) is None
    assert post(client, token, snapshot([app("opencode", name="Ordinary Editor")], offset=2)).status_code == 200
    application_review.sync(st, tenant, application_review.observed(st, tenant))
    classifier.finish(st, previous, provider_classifier.parse_result(response(False)))
    assert client.get(REVIEW).json()["items"][0]["classification_status"] == "pending"
    assert client.get(REVIEW).json()["items"][0]["assessment"] is None
    attention = False
    assert asyncio.run(classifier.run_once(st, cfg, tenant))
    assert client.get(REVIEW).json()["items"][0]["needs_attention"] is False
    # Removed products stop being classified; an expired worker cannot restore them.
    assert post(client, token, snapshot([], offset=3)).status_code == 200
    st.execute("UPDATE application_classification_scans SET next_scan_at=now()")
    assert not asyncio.run(classifier.run_once(st, cfg, tenant))
    assert st.scalar("SELECT count(*) FROM application_classifications") == 0
    assert st.scalar("SELECT count(*) FROM model_usage WHERE purpose='asset_management'") == 2
    assert st.scalar("SELECT sum(cost_usd) FROM model_usage WHERE purpose='asset_management'") == Decimal("0.020131")


@pytest.mark.parametrize("failure", ["timeout", "http", "refusal", "incomplete", "malformed", "accounting"])
def test_classification_bills_failed_responses_without_blocking_work(inventory, monkeypatch, api_service, failure):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    tenant = sensor["tenant_id"]
    post(client, token, snapshot([app("opencode", name="OpenCode")]))

    def send(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("unavailable")
        if failure == "http":
            return httpx.Response(429)
        payload = response()
        if failure == "refusal":
            payload["output"][1]["content"] = [{"type": "refusal", "refusal": "no"}]
        if failure == "incomplete":
            payload["status"] = "incomplete"
        if failure == "malformed":
            payload["output"][1]["content"][0]["text"] = "{"
        return httpx.Response(200, json=payload)

    api_service(cfg, cfg.tenant_id or tenant, send, openai_key="tenant-secret")
    if failure == "accounting":
        execute = st.execute

        def unavailable(query, *args, **kwargs):
            if "INSERT INTO model_usage" in query:
                raise RuntimeError("accounting unavailable")
            return execute(query, *args, **kwargs)

        monkeypatch.setattr(st, "execute", unavailable)
    assert asyncio.run(classifier.run_once(st, cfg, tenant))
    if failure == "accounting":
        assert client.get(REVIEW).json()["items"][0]["classification_status"] == "complete"
        assert st.scalar("SELECT count(*) FROM model_usage") == 0
    else:
        billed = st.one("SELECT * FROM model_usage WHERE purpose='asset_management'")
        assert billed["status"] == "error"
        assert billed["cost_usd"] == (None if failure in ("timeout", "http") else Decimal("0.0100655"))
        # A later retry is a separate billed attempt, even when its answer fails validation.
        st.execute("UPDATE application_classifications SET next_attempt_at=now()")
        assert asyncio.run(classifier.run_once(st, cfg, tenant))
        assert st.scalar("SELECT count(*) FROM model_usage") == 2


def test_unknown_failure_and_missing_credentials_never_clear_attention(inventory, monkeypatch, api_service):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    tenant = sensor["tenant_id"]
    post(client, token, snapshot([app("mystery", name="Mystery")]))
    assert not asyncio.run(classifier.run_once(st, cfg, tenant))

    async def fail(request):
        raise httpx.ReadTimeout("unavailable")

    api_service(cfg, tenant, fail, openai_key="tenant-secret")
    assert asyncio.run(classifier.run_once(st, cfg, tenant))
    row = client.get(REVIEW).json()["items"][0]
    assert row["needs_attention"] and row["classification_status"] == "unavailable"
    assert not asyncio.run(classifier.run_once(st, cfg, tenant))
    st.execute("UPDATE application_classifications SET next_attempt_at=now()")

    async def unknown(request):
        return httpx.Response(200, json=response(None, sources=[]))

    api_service(cfg, tenant, unknown, openai_key="tenant-secret")
    assert asyncio.run(classifier.run_once(st, cfg, tenant))
    row = client.get(REVIEW).json()["items"][0]
    assert row["needs_attention"] and row["classification_status"] == "unknown"
    assert row["assessment"]["capability_score"] is None and row["assessment_status"] == "needs_identification"


@pytest.mark.parametrize("concurrency,cancel", [(1, False), (8, False), (8, True)])
def test_research_pool_limits_refills_and_stops_without_duplicate_claims(inventory, monkeypatch, api_service, concurrency, cancel):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    cfg.application_classification_concurrency = concurrency
    total = concurrency + 2
    assert post(client, token, snapshot([app(f"app-{i}") for i in range(total)])).status_code == 200
    assert post(client, identities[1][1], snapshot([app("other-tenant")])).status_code == 200
    cfg.tenant_id = sensor["tenant_id"]

    async def exercise():
        started = asyncio.Queue()
        releases, seen, active = [], set(), set()
        peak = 0

        async def send(request):
            nonlocal peak
            payload = json.loads(request.content)
            assert payload["model"] == "gpt-6-luna"
            name = json.loads(payload["input"])[0]["name"]
            assert name != "other-tenant" and name not in seen
            seen.add(name)
            active.add(name)
            peak = max(peak, len(active))
            release = asyncio.Event()
            releases.append(release)
            await started.put(release)
            try:
                await release.wait()
                return httpx.Response(503 if release is releases[0] else 200, json=response())
            finally:
                active.remove(name)

        api_service(cfg, cfg.tenant_id, send, openai_key="tenant-secret")
        stop = asyncio.Event()
        running = asyncio.create_task(classifier.run(st, cfg, stop))
        try:
            async with asyncio.timeout(20):
                initial = [await started.get() for _ in range(concurrency)]
                assert len(active) == concurrency and len(seen) == concurrency
                # A failed request frees its slot while all other requests wait.
                initial[0].set()
                replacement = await started.get()
                assert len(seen) == concurrency + 1
                replacement.set()
                await started.get()
                assert len(seen) == total and peak == concurrency
                stop.set()
                if cancel:
                    running.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await running
                elif concurrency == 100:
                    # Hold accounting writes so a burst of 100 completed
                    # requests cannot consume every shared connection/thread.
                    with st.transaction() as conn:
                        conn.execute("LOCK TABLE model_usage IN ACCESS EXCLUSIVE MODE")
                        for release in releases:
                            release.set()
                        blocked = 0
                        while blocked < 4:
                            await asyncio.sleep(0.01)
                            blocked = await asyncio.to_thread(st.scalar, """SELECT count(*) FROM pg_locks
                                WHERE relation='model_usage'::regclass AND NOT granted""")
                        assert blocked == 4
                        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=client.app),
                                            base_url="http://testserver", cookies=dict(client.cookies)) as api:
                            reads, ingestion = await asyncio.wait_for(asyncio.gather(
                                api.get(REVIEW),
                                api.post(INGEST, json=snapshot([app(f"app-{i}") for i in range(total)], offset=1),
                                         headers={"Authorization": "Bearer " + token}),
                            ), timeout=3)
                        assert reads.status_code == ingestion.status_code == 200
                        assert len(reads.json()["items"]) == total
                    await running
                else:
                    for release in releases:
                        release.set()
                    await running
                assert not active
        finally:
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)

    asyncio.run(exercise())
    assert st.scalar("SELECT count(*) FROM application_classifications WHERE last_error<>''") == 1
    assert st.scalar("SELECT count(*) FROM application_classifications WHERE checked_at IS NOT NULL") == (1 if cancel else total - 1)
    assert st.scalar("SELECT count(*) FROM application_classifications WHERE claim_token IS NOT NULL") == (concurrency if cancel else 0)
    assert st.scalar("SELECT count(*) FROM model_usage WHERE completed_at IS NOT NULL") == total
    assert st.scalar("SELECT count(*) FROM model_usage WHERE status='completed'") == (1 if cancel else total - 1)
    if cancel:
        # Cancelled work is reclaimable after the existing lease, without losing
        # the successful result or bypassing the failed request's retry delay.
        assert classifier.claim(st, cfg.tenant_id) is None
        st.execute("UPDATE application_classifications SET lease_until=now()-interval '1 second' WHERE claim_token IS NOT NULL")
        reclaimed = []
        while item := classifier.claim(st, cfg.tenant_id):
            reclaimed.append(item["product_id"])
        assert len(set(reclaimed)) == concurrency


def test_rate_limit_pauses_shared_credentials_and_preserves_cached_results(inventory, monkeypatch, api_service):
    st, cfg, client, identities = inventory
    tenants = [identity[0]["tenant_id"] for identity in identities]
    for _, token, _ in identities:
        assert post(client, token, snapshot([app("one"), app("two")])).status_code == 200
    classifier.refresh_inventory(st, tenants[0])
    cached = classifier.claim(st, tenants[0])
    classifier.finish(st, cached, provider_classifier.parse_result(response()))
    st.execute("UPDATE application_classifications SET next_attempt_at=now()-interval '1 day' WHERE product_id=$1", cached["product_id"])
    requests = []

    def send(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(429, headers={"Retry-After": "7200"})
        return httpx.Response(200, json=response())

    api_service(cfg, tenants[0], send, openai_key="tenant-secret")

    async def exercise():
        cooldowns = {}
        before = asyncio.get_running_loop().time()
        assert await classifier.run_once(st, cfg, tenants[0], cooldowns)
        assert len(cooldowns) == 1
        identity = next(iter(cooldowns))
        assert cooldowns[identity] >= before + 7200
        assert not await classifier.run_once(st, cfg, tenants[0], cooldowns)
        assert not await classifier.run_once(st, cfg, tenants[1], cooldowns)
        assert len(requests) == 1
        st.execute("INSERT INTO tenant_model_keys(tenant_id,kind,api_key) VALUES($1,'detection','separate-tenant-secret')", tenants[1])
        assert not await classifier.run_once(st, cfg, tenants[1], cooldowns)
        cooldowns[identity] = before - 1
        assert await classifier.run_once(st, cfg, tenants[0], cooldowns)
        assert len(requests) == 2

    asyncio.run(exercise())
    saved = st.one("SELECT * FROM application_classifications WHERE tenant_id=$1 AND product_id=$2", tenants[0], cached["product_id"])
    assert saved["last_error"] == "classification_unavailable"
    assert saved["assessment"]["capability_score"] == 75
    assert saved["next_attempt_at"] > datetime.now(timezone.utc) + timedelta(minutes=59)


def test_provider_backoff_accepts_seconds_and_http_dates():
    assert classifier.retry_delay("7200") == 7200
    future = format_datetime(datetime.now(timezone.utc) + timedelta(minutes=5), usegmt=True)
    assert 299 <= classifier.retry_delay(future) <= 300
    for value in (None, "invalid", "nan", "inf", "-10", "1"):
        assert classifier.retry_delay(value) == 60


@pytest.mark.parametrize("case", ["no_search", "no_sources", "invented_source", "wrong_type", "refusal", "incomplete", "wrong_category", "unsafe_source", "software_type", "library_agent", "unsourced_name", "blank_name", "long_name", "control_name"])
def test_unsubstantiated_model_results_are_rejected(case):
    payload = response()
    if case == "no_search":
        payload["output"].pop(0)
    elif case == "no_sources":
        payload = response(sources=[])
    elif case == "invented_source":
        payload = response(sources=["https://invented.test"])
    elif case == "wrong_type":
        payload = response("false")
    elif case == "refusal":
        payload["output"][1]["content"] = [{"type": "refusal", "refusal": "no"}]
    elif case == "incomplete":
        payload["status"] = "incomplete"
    elif case == "wrong_category":
        payload = response(True, category="ordinary")
    elif case == "unsafe_source":
        payload = response(sources=["javascript:alert(1)"])
    elif case == "software_type":
        payload = response(software_type="safe")
    elif case == "library_agent":
        payload = response(software_type="library")
    elif case == "unsourced_name":
        payload = response(None, display_name="Invented name", sources=[])
    elif case == "blank_name":
        payload = response(display_name="  ")
    elif case == "long_name":
        payload = response(display_name="a" * 121)
    elif case == "control_name":
        payload = response(display_name="Name\nwith a newline")
    with pytest.raises(ValueError):
        provider_classifier.parse_result(payload)


@pytest.mark.parametrize("case", ["incomplete", "no_search", "missing_url", "unsafe_url", "credentials"])
def test_unverified_opened_page_sources_are_rejected(case):
    source = "https://example.test/opened-product"
    if case == "unsafe_url":
        source = "javascript:alert(1)"
    elif case == "credentials":
        source = "https://user:password@example.test/product"
    payload = response(sources=[source])
    opened = {"type": "web_search_call", "status": "completed",
              "action": {"type": "open_page", "url": source}}
    if case == "incomplete":
        opened["status"] = "in_progress"
    elif case == "no_search":
        payload["output"].pop(0)
    elif case == "missing_url":
        del opened["action"]["url"]
    payload["output"].insert(0, opened)
    with pytest.raises(ValueError):
        provider_classifier.parse_result(payload)


@pytest.mark.parametrize("levels,confidence,attention,expected", [
    ((3, 3, 3, 3), "high", True, 100),
    ((0, 0, 0, 0), "medium", False, 0),
    ((0, 1, 0, 2), "medium", True, 25),
    ((3, 2, 2, 2), "high", True, 75),
    ((None, 2, 2, 2), "high", True, None),
    ((3, 3, 3, 3), "low", True, None),
    ((3, 3, 3, 3), "high", None, None),
])
def test_capability_score_uses_supported_levels_not_category(levels, confidence, attention, expected):
    result = provider_classifier.parse_result(response(attention, assessment=assessment(levels, confidence)))
    assert result["assessment"]["capability_score"] == expected


@pytest.mark.parametrize("case", ["invented_source", "unsafe_source", "zero_without_source", "boolean_level", "out_of_range", "missing_dimension", "invented_score", "bad_confidence", "unsupported_controls", "risk_source", "missing_risk", "risk_range", "risk_boolean", "reputation_source", "missing_report", "purpose_source", "harm_source", "unsourced_harm", "long_purpose", "long_damage", "long_likelihood", "empty_likelihood", "too_many_harms"])
def test_unsupported_capability_claims_are_rejected(case):
    value = assessment()
    if case == "invented_source":
        value["file_access"]["sources"] = ["https://invented.test"]
    elif case == "unsafe_source":
        value["file_access"]["sources"] = ["javascript:alert(1)"]
    elif case == "zero_without_source":
        value["code_execution"].update(level=0, sources=[])
    elif case == "boolean_level":
        value["code_execution"]["level"] = True
    elif case == "out_of_range":
        value["autonomy"]["level"] = 4
    elif case == "missing_dimension":
        del value["file_access"]
    elif case == "invented_score":
        value["capability_score"] = 100
    elif case == "bad_confidence":
        value["confidence"] = "certain"
    elif case == "unsupported_controls":
        value["controls"]["sources"] = ["https://invented.test"]
    elif case == "risk_source":
        value["risk"]["sources"] = ["https://invented.test"]
    elif case == "missing_risk":
        value["risk"]["score"] = None
    elif case == "risk_range":
        value["risk"]["score"] = 101
    elif case == "risk_boolean":
        value["risk"]["score"] = True
    elif case == "reputation_source":
        value["reputation"]["sources"] = ["https://invented.test"]
    elif case == "missing_report":
        del value["report"]
    elif case == "purpose_source":
        value["report"]["purpose"]["sources"] = ["https://invented.test"]
    elif case == "harm_source":
        value["report"]["harms"][0]["sources"] = ["javascript:alert(1)"]
    elif case == "unsourced_harm":
        value["report"]["harms"][0]["sources"] = []
    elif case == "long_purpose":
        value["report"]["purpose"]["reason"] = "x" * 240 + " "
    elif case == "long_damage":
        value["report"]["harms"][0]["damage"] = "x" * 180 + " "
    elif case == "long_likelihood":
        value["report"]["harms"][0]["likelihood"] = "x" * 240 + " "
    elif case == "empty_likelihood":
        value["report"]["harms"][0]["likelihood"] = " "
    elif case == "too_many_harms":
        value["report"]["harms"] *= 4
    with pytest.raises(ValueError):
        provider_classifier.parse_result(response(assessment=value))


@pytest.mark.parametrize("attention,software_type,confidence,levels,expected", [
    (True, "application", "medium", (3, None, 2, 3), 72),
    (True, "command_line_tool", "high", (3, 3, 2, 3), 72),
    (True, "application", "low", (3, 3, 2, 3), None),
    (True, "application", "high", (None,) * 4, None),
    (None, None, "high", (3, 3, 2, 3), None),
    (False, "application", "high", (3, 3, 2, 3), None),
    (True, "library", "high", (3, 3, 2, 3), None),
])
def test_model_risk_preserves_supported_scores_and_adds_provisional_estimates(
    attention, software_type, confidence, levels, expected,
):
    result = provider_classifier.parse_result(response(
        attention, software_type=software_type,
        category="other_ai" if attention is True else "ordinary" if attention is False else None,
        assessment=assessment(levels, confidence),
    ))
    assert result["assessment"]["risk"]["score"] == expected
    eligible = attention is not False and software_type in (None, "application", "command_line_tool")
    provisional = eligible and expected is None
    assert result["assessment"]["risk"]["provisional_score"] == (72 if provisional else None)
    if provisional:
        assert result["assessment"]["confidence"] == "low"
        assert result["assessment"]["capability_score"] is None


@pytest.mark.parametrize("score", [0, 37, 100])
def test_metadata_only_estimate_keeps_unknown_capabilities_and_no_invented_sources(score):
    value = assessment((None,) * 4, "high")
    value["risk"].update(score=score, sources=[], reason="Provisional estimate from reported metadata; identity and capabilities are unverified.")
    result = provider_classifier.parse_result(response(None, assessment=value))["assessment"]
    assert result["confidence"] == "low" and result["capability_score"] is None
    assert result["risk"] == value["risk"] | {"score": None, "provisional_score": score}
    assert all(result[key]["level"] is None and result[key]["sources"] == [] for key in application_assessment.DIMENSIONS)


@pytest.mark.parametrize("confidence", ["high", "medium"])
def test_provisional_risk_preserves_independently_sourced_capability_confidence(confidence):
    value = assessment((3, 3, 3, 3), confidence)
    value["risk"]["sources"] = []
    result = provider_classifier.parse_result(response(assessment=value))["assessment"]
    assert result["confidence"] == confidence and result["capability_score"] == 100
    assert result["risk"]["score"] is None and result["risk"]["provisional_score"] == 72
    assert all(result[key] == value[key] for key in application_assessment.DIMENSIONS)


@pytest.mark.parametrize("legacy", ["capabilities_only", "unscored_risk", "missing_report"])
def test_unidentified_app_gets_one_provisional_refresh_with_failure_backoff(inventory, legacy):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    tenant = sensor["tenant_id"]
    post(client, token, snapshot([app("com.opensecura.openaidr.sensor", name="OpenAIDR", kind="application")]))
    application_review.sync(st, tenant, application_review.observed(st, tenant))
    claimed = classifier.claim(st, tenant)
    classifier.finish(st, claimed, provider_classifier.parse_result(response(None)))
    product = claimed["product_id"]
    st.execute("INSERT INTO ai_application_approvals(tenant_id,product_id,name,approved) VALUES($1,$2,'OpenAIDR',NULL)", tenant, product)
    st.execute("""UPDATE application_classifications SET
        assessment=CASE WHEN $1='capabilities_only' THEN assessment-'risk'
            WHEN $1='missing_report' THEN assessment-'report'
            ELSE jsonb_set(assessment,'{risk}',(assessment->'risk')-'provisional_score') END,
        next_attempt_at=now()+interval '30 days'""", legacy)
    row, = client.get(REVIEW).json()["items"]
    assert row["research_status"] == "queued" and row["category"] is None
    assert row["review_required"] and row["approval_status"] == "monitoring"
    claimed = classifier.claim(st, tenant)
    assert claimed is not None
    classifier.finish(st, claimed)
    assert classifier.claim(st, tenant) is None
    assert client.get(REVIEW).json()["items"][0]["research_status"] == "retry_pending"
    st.execute("UPDATE application_classifications SET next_attempt_at=now()")
    value = assessment((None,) * 4, "low")
    value["risk"].update(score=37, sources=[], reason="Metadata-only estimate; product identity is unresolved.")
    classifier.finish(st, classifier.claim(st, tenant), provider_classifier.parse_result(response(None, assessment=value)))
    row, = client.get(REVIEW).json()["items"]
    assert row["assessment"]["risk"]["score"] is None
    assert row["assessment"]["risk"]["provisional_score"] == 37
    assert row["assessment"]["confidence"] == "low" and row["category"] is None
    assert row["research_status"] == "complete" and row["review_required"]
    assert row["approval_status"] == "monitoring"
    assert st.scalar("SELECT next_attempt_at BETWEEN now()+interval '23 hours' AND now()+interval '25 hours' FROM application_classifications")
    assert classifier.claim(st, tenant) is None


@pytest.mark.parametrize("role", ["it_admin", "security_analyst"])
def test_explicit_monitoring_is_durable_scoped_and_audited(inventory, role):
    st, cfg, client, identities = inventory
    sensor, token, session = identities[0]
    other, _, other_session = identities[1]
    tenant = sensor["tenant_id"]
    software = app("private-tool", name="Unidentified tool", kind="application")
    assert post(client, token, snapshot([software])).status_code == 200
    item, = client.get(REVIEW).json()["items"]
    assert not item["review_required"]
    path = f"{REVIEW}/{item['id']}/approval"
    assert client.put(path, json={"approved": None}, headers=HEADERS).status_code == 403
    st.execute("UPDATE tenant_users SET roles=$2 WHERE tenant_id=$1", tenant, [role])
    assert client.put(path, json={"approved": None}).status_code == 403
    for invalid in ({}, {"approved": "monitoring"}, {"approved": 0}, {"approved": None, "extra": True}):
        assert client.put(path, json=invalid, headers=HEADERS).status_code == 400
    for decision in (True, None, False, None):
        saved = client.put(path, json={"approved": decision}, headers=HEADERS)
        assert saved.status_code == 200
        assert saved.json()["approved"] is decision
        current, = client.get(REVIEW).json()["items"]
        assert current["approval_status"] == ("monitoring" if decision is None else "approved" if decision else "unapproved")
        assert current["approval_updated_at"] == saved.json()["approval_updated_at"]
        assert current["review_required"] and not current["approval_conflict"]
    # A saved Monitoring choice survives removal and reinstallation.
    assert post(client, token, snapshot([], offset=1)).status_code == 200
    assert post(client, token, snapshot([software], offset=2)).status_code == 200
    current, = client.get(REVIEW).json()["items"]
    assert current["approval_status"] == "monitoring" and current["review_required"]
    legacy = next(row for row in client.get(AI_APPS).json()["items"] if row["id"] == item["id"])
    assert legacy["approved"] is False
    audit = st.many("SELECT details FROM audit_log WHERE action='ai-application.approval' ORDER BY at,id")
    assert [row["details"]["before_status"] for row in audit] == ["monitoring", "approved", "monitoring", "unapproved"]
    assert [row["details"]["approved"] for row in audit] == [True, None, False, None]
    st.execute("UPDATE tenant_users SET roles=$2 WHERE tenant_id=$1", other["tenant_id"], [role])
    client.cookies.set(CONSOLE_COOKIE, other_session)
    assert client.put(path, json={"approved": None}, headers=HEADERS).status_code == 404
    assert st.scalar("SELECT count(*) FROM ai_application_approvals WHERE tenant_id=$1", other["tenant_id"]) == 0
    client.cookies.set(CONSOLE_COOKIE, session)
    assert client.put(f"{REVIEW}/absent/approval", json={"approved": None}, headers=HEADERS).status_code == 404
    # Monitoring must roll back along with a failed audit write.
    assert client.put(path, json={"approved": True}, headers=HEADERS).status_code == 200
    st.execute("""CREATE FUNCTION reject_monitoring_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action='ai-application.approval' THEN RAISE EXCEPTION 'audit unavailable'; END IF;
        RETURN NEW; END; $$""")
    st.execute("CREATE TRIGGER reject_monitoring_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_monitoring_audit()")
    assert client.put(path, json={"approved": None}, headers=HEADERS).status_code == 500
    assert client.get(REVIEW).json()["items"][0]["approval_status"] == "approved"


def test_installed_packages_deduplicate_devices_and_preserve_choices(inventory, monkeypatch, api_service):
    from test_app_inventory_server import root, component, send_components

    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    _, other_token, other_session = identities[1]
    tenant = sensor["tenant_id"]
    st.record_heartbeat(sensor["id"], {"signed_in_user": {"name": "alice", "signed_in_at": "2026-01-01T00:00:00Z"}})
    roots = [root("/Users/private/env-one", source="osquery-npm-packages", components=[component("@openai/codex", ecosystem="npm")]),
             root("/Users/private/env-two", source="osquery-npm-packages", components=[component("@openai/codex", ecosystem="npm", version="2")])]
    assert send_components(client, token, roots).status_code == 200
    assert send_components(client, other_token, [root(components=[component("other-only")])]).status_code == 200
    data = client.get(REVIEW)
    assert data.headers["cache-control"] == "no-store"
    row, = data.json()["items"]
    assert row["id"] == "codex" and row["device_count"] == 1
    assert row["software_type"] == "command_line_tool" and row["review_required"]
    assert row["users"] == [{"user": "alice", "device_count": 1}]
    assert data.json()["device_count"] == 1
    device, = client.get(f"{REVIEW}/codex-cli/devices").json()["items"]
    assert device["versions"] == ["1.0", "2"]
    assert {entry["root"] for entry in device["installations"]} == {"/Users/private/env-one", "/Users/private/env-two"}
    assert all(entry["source"] == "osquery-npm-packages" and entry["ecosystem"] == "npm" for entry in device["installations"])
    for role in ("it_admin", "security_analyst"):
        st.execute("UPDATE tenant_users SET roles=$2 WHERE tenant_id=$1", tenant, [role])
        assert client.put(f"{REVIEW}/codex-cli/approval", json={"approved": True}, headers=HEADERS).status_code == 200
    client.cookies.set(CONSOLE_COOKIE, other_session)
    assert client.get(f"{REVIEW}/codex-cli/devices").status_code == 404
    assert client.put(f"{REVIEW}/codex-cli/approval", json={"approved": True}, headers=HEADERS).status_code == 403
    client.cookies.set(CONSOLE_COOKIE, identities[0][2])

    async def classified(request):
        encoded = json.loads(request.content)["input"]
        assert "private" not in encoded and "/Users" not in encoded and "alice" not in encoded
        return httpx.Response(200, json=response(True))

    api_service(cfg, tenant, classified, openai_key="tenant-secret")
    assert asyncio.run(classifier.run_once(st, cfg, tenant))
    row, = client.get(REVIEW).json()["items"]
    assert row["approval_status"] == "approved" and row["category"] == "coding_agent"
    # New metadata invalidates the classification, but does not reset approval.
    roots[0]["components"][0]["publisher"] = "New metadata"
    assert send_components(client, token, roots, offset=1).status_code == 200
    assert client.get(REVIEW).json()["items"][0]["approval_status"] == "approved"
    assert client.get(REVIEW).json()["items"][0]["classification_status"] == "pending"
    cfg.application_classification = False
    assert not asyncio.run(classifier.run_once(st, cfg, tenant))
    assert client.get(REVIEW).json()["classifier_configured"] is False


def test_refresh_failure_and_expired_claim_do_not_replace_current_result(inventory, monkeypatch, api_service):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    tenant = sensor["tenant_id"]
    post(client, token, snapshot([app("ordinary", name="Ordinary")]))
    application_review.sync(st, tenant, application_review.observed(st, tenant))
    first = classifier.claim(st, tenant)
    st.execute("UPDATE application_classifications SET lease_until=now()-interval '1 second'")
    replacement = classifier.claim(st, tenant)
    classifier.finish(st, replacement, provider_classifier.parse_result(response(False)))
    classifier.finish(st, first, provider_classifier.parse_result(response(True)))
    assert client.get(REVIEW).json()["items"][0]["needs_attention"] is False
    st.execute("UPDATE application_classifications SET next_attempt_at=now()")
    failed = classifier.claim(st, tenant)
    classifier.finish(st, failed)
    row, = client.get(REVIEW).json()["items"]
    assert row["needs_attention"] is False and row["classification_status"] == "stale"
    assert row["category"] == "ordinary" and row["sources"]
    assert row["display_name"] == "Example application" and row["software_type"] == "application"
    assert row["assessment"]["capability_score"] == 75 and row["assessment_status"] == "stale"


@pytest.mark.parametrize("helper_confidence", ["high", "low"])
def test_software_context_separates_apps_from_builtins_and_supporting_packages(inventory, helper_confidence):
    from test_app_inventory_server import root, component, send_components

    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    tenant = sensor["tenant_id"]
    native = [
        app("com.apple.imageplayground", name="Image Playground", kind="application",
            source="macos-spotlight", path="/System/Applications/Image Playground.app"),
        app("com.anthropic.claude-code-url-handler", name="Claude Code URL Handler",
            kind="application", source="macos-spotlight", path="/Applications/Claude Code URL Handler.app"),
        app("unknown-app", kind="application", source="macos-spotlight", path="/Applications/Unknown.app"),
        app("com.openai.sora", name="Sora", kind="application", source="macos-spotlight", path="/Applications/Sora.app"),
    ]
    assert post(client, token, snapshot(native, source="macos-spotlight") | {"platform": "darwin"}).status_code == 200
    packages = ["@mariozechner/clipboard", "@mariozechner/pi-agent-core", "@mariozechner/pi-coding-agent", "unidentified"]
    assert send_components(client, token, [root(
        "/Users/private/project", source="osquery-npm-packages", environment="private-environment",
        components=[component(name, ecosystem="npm", path="/Users/private/project/node_modules/" + name) for name in packages],
    )]).status_code == 200
    rows = {row["name"]: row for row in client.get(REVIEW).json()["items"]}
    assert rows["Image Playground"]["is_builtin"] and not rows["Image Playground"]["review_required"]
    assert rows["Claude Code URL Handler"]["software_type"] == "helper"
    assert not rows["Claude Code URL Handler"]["review_required"]
    assert not rows["unknown-app"]["review_required"]
    assert rows["Sora"]["review_required"] and rows["Sora"]["classification_status"] == "pending"
    assert not rows["unidentified"]["review_required"] and rows["unidentified"]["software_type"] == "package"
    application_review.sync(st, tenant, application_review.observed(st, tenant))
    results = {
        "Image Playground": response(True, category="other_ai", display_name="Image Playground"),
        "Claude Code URL Handler": response(True, software_type="application", assessment=assessment(confidence=helper_confidence)),
        "@mariozechner/clipboard": response(False, software_type="library", display_name="Clipboard utility"),
        "@mariozechner/pi-agent-core": response(True, category="other_ai", software_type="library", display_name="Pi agent library"),
        "@mariozechner/pi-coding-agent": response(True, software_type="command_line_tool", display_name="Pi coding agent"),
    }
    while claimed := classifier.claim(st, tenant):
        name = claimed["evidence"][0]["name"]
        assert "private" not in json.dumps(claimed["evidence"])
        classifier.finish(st, claimed, provider_classifier.parse_result(results.get(name, response(None, sources=[]))))
    rows = {row["name"]: row for row in client.get(REVIEW).json()["items"]}
    assert rows["Image Playground"]["needs_attention"] and not rows["Image Playground"]["review_required"]
    assert rows["Sora"]["review_required"] and rows["Sora"]["classification_status"] == "unknown"
    handler = rows["Claude Code URL Handler"]
    assert handler["software_type"] == "helper" and not handler["review_required"]
    assert handler["assessment"]["risk"]["score"] is None
    assert handler["assessment"]["risk"]["provisional_score"] is None
    stored = st.scalar("SELECT assessment->'risk' FROM application_classifications WHERE product_id=$1", handler["id"])
    assert (stored["score"] if helper_confidence == "high" else stored["provisional_score"]) == 72
    clipboard = rows["@mariozechner/clipboard"]
    assert clipboard["display_name"] == "Clipboard utility" and clipboard["software_type"] == "library"
    assert not clipboard["needs_attention"] and not clipboard["review_required"]
    assert rows["@mariozechner/pi-agent-core"]["needs_attention"] and not rows["@mariozechner/pi-agent-core"]["review_required"]
    assert rows["@mariozechner/pi-coding-agent"]["review_required"]
    device, = client.get(f"{REVIEW}/{clipboard['id']}/devices").json()["items"]
    installation, = device["installations"]
    assert installation["name"] == "@mariozechner/clipboard"
    assert installation["path"] == "/Users/private/project/node_modules/@mariozechner/clipboard"
    assert installation["root"] == "/Users/private/project" and installation["environment"] == "private-environment"
    # A deliberate organization decision remains visible, including for built-ins.
    st.execute("UPDATE tenant_users SET roles=ARRAY['it_admin']::text[] WHERE tenant_id=$1", tenant)
    builtin_id = rows["Image Playground"]["id"]
    assert client.put(f"{REVIEW}/{builtin_id}/approval", json={"approved": False}, headers=HEADERS).status_code == 200
    rows = {row["name"]: row for row in client.get(REVIEW).json()["items"]}
    assert rows["Image Playground"]["review_required"] and rows["Image Playground"]["approval_status"] == "unapproved"
    # Location changes affect local review context, not model input or cached classification.
    original_hash = application_review.observed(st, tenant)[builtin_id]["evidence_hash"]
    native.append(native[0] | {"path": "/System/../Applications/Image Playground.app"})
    assert post(client, token, snapshot(native, offset=1, source="macos-spotlight") | {"platform": "darwin"}).status_code == 200
    product = application_review.observed(st, tenant)[builtin_id]
    assert not product["is_builtin"] and product["evidence_hash"] == original_hash
    rows = {row["name"]: row for row in client.get(REVIEW).json()["items"]}
    assert rows["Image Playground"]["review_required"] and rows["Image Playground"]["classification_status"] == "complete"


def test_context_upgrade_preserves_legacy_classification_and_hash(inventory):
    from pathlib import Path

    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    tenant = sensor["tenant_id"]
    assert post(client, token, snapshot([app("ordinary", name="Ordinary")])).status_code == 200
    products = application_review.observed(st, tenant)
    item, = products.values()
    legacy_evidence = [{key: entry[key] for key in ("name", "publisher", "ecosystem", "source", "identifier")}
                       for entry in item["evidence"]]
    legacy_hash = hashlib.sha256(json.dumps(legacy_evidence, sort_keys=True).encode()).hexdigest()
    assert item["evidence_hash"] == legacy_hash
    application_review.sync(st, tenant, products)
    classifier.finish(st, classifier.claim(st, tenant), provider_classifier.parse_result(response(False)))
    # Simulate the pre-migration schema and a cached result with an old worker lease.
    st.execute("ALTER TABLE application_classifications DROP COLUMN software_type, DROP COLUMN display_name")
    st.execute("UPDATE application_classifications SET claim_token=gen_random_uuid(),lease_until=now()+interval '1 hour'")
    migration = Path(application_review.__file__).parent / "migrations/0093_application_context.sql"
    with st.transaction() as conn:
        conn.execute(migration.read_text())
    row, = client.get(REVIEW).json()["items"]
    assert not row["needs_attention"] and row["classification_status"] == "complete" and row["sources"]
    application_review.sync(st, tenant, application_review.observed(st, tenant))
    claim = classifier.claim(st, tenant)
    assert claim and claim["evidence_hash"] == legacy_hash
    classifier.finish(st, claim)
    row, = client.get(REVIEW).json()["items"]
    assert not row["needs_attention"] and row["classification_status"] == "stale"
    assert row["category"] == "ordinary" and row["sources"]


def test_assessment_upgrade_enriches_without_resetting_classification_or_approval(inventory):
    from pathlib import Path

    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    tenant = sensor["tenant_id"]
    post(client, token, snapshot([app("known", name="Known application")]))
    application_review.sync(st, tenant, application_review.observed(st, tenant))
    old = classifier.claim(st, tenant)
    classifier.finish(st, old, provider_classifier.parse_result(response(True)))
    st.execute("INSERT INTO ai_application_approvals(tenant_id,product_id,name,approved) VALUES($1,$2,'Known application',true)", tenant, old["product_id"])
    st.execute("ALTER TABLE application_classifications DROP COLUMN assessment, DROP COLUMN assessment_checked_at")
    st.execute("UPDATE application_classifications SET claim_token=$1,lease_until=now()+interval '1 hour'", old["claim_token"])
    migration = Path(application_review.__file__).parent / "migrations/0096_application_assessment.sql"
    with st.transaction() as conn:
        conn.execute(migration.read_text())
    classifier.finish(st, old, provider_classifier.parse_result(response(False)))
    application_review.sync(st, tenant, application_review.observed(st, tenant))
    row, = client.get(REVIEW).json()["items"]
    assert row["category"] == "coding_agent" and row["sources"]
    assert row["approval_status"] == "approved" and row["assessment"] is None
    # A legacy worker can claim after the migration, then finish without an
    # assessment and defer its next attempt by 30 days. New workers heal this.
    st.execute("UPDATE application_classifications SET checked_at=clock_timestamp(),next_attempt_at=now()+interval '30 days'")
    claimed = classifier.claim(st, tenant)
    assert claimed is not None
    assert claimed["evidence_hash"] == old["evidence_hash"]
    classifier.finish(st, claimed, provider_classifier.parse_result(response(assessment=assessment((0, 1, 0, 2)))))
    row, = client.get(REVIEW).json()["items"]
    assert row["assessment"]["capability_score"] == 25 and row["approval_status"] == "approved"
    # A legacy writer after upgrade cannot attach an old assessment to its result.
    st.execute("UPDATE application_classifications SET checked_at=clock_timestamp(),next_attempt_at=now()+interval '30 days'")
    assert client.get(REVIEW).json()["items"][0]["assessment"] is None
    claimed = classifier.claim(st, tenant)
    assert claimed is not None
    classifier.finish(st, claimed)
    # Missing assessments must not bypass the one-hour failure backoff.
    assert classifier.claim(st, tenant) is None
    st.execute("UPDATE application_classifications SET next_attempt_at=now()")
    classifier.finish(st, classifier.claim(st, tenant), provider_classifier.parse_result(response(assessment=assessment((None,) * 4, "low"))))
    row, = client.get(REVIEW).json()["items"]
    assert row["assessment"]["capability_score"] is None and row["approval_status"] == "approved"
    assert st.scalar("SELECT next_attempt_at < now()+interval '2 days' FROM application_classifications")
    # Old capability-only results are enriched without clearing identity or approval.
    st.execute("UPDATE application_classifications SET assessment=assessment-'risk'-'reputation',next_attempt_at=now()+interval '30 days'")
    row, = client.get(REVIEW).json()["items"]
    assert row["research_status"] == "queued" and row["approval_status"] == "approved"
    claimed = classifier.claim(st, tenant)
    assert claimed is not None
    classifier.finish(st, claimed)
    assert classifier.claim(st, tenant) is None  # Risk enrichment respects failure backoff.
    st.execute("UPDATE application_classifications SET next_attempt_at=now()")
    classifier.finish(st, classifier.claim(st, tenant), provider_classifier.parse_result(response(assessment=assessment((3, None, 2, 3), "medium"))))
    row, = client.get(REVIEW).json()["items"]
    assert row["research_status"] == "complete" and row["assessment"]["risk"]["score"] == 72
    assert row["assessment"]["capability_score"] is None and row["approval_status"] == "approved"
    assert st.scalar("SELECT next_attempt_at > now()+interval '29 days' FROM application_classifications")
    # Existing reports gain concise answers without losing prior research or approvals.
    st.execute("UPDATE application_classifications SET assessment=assessment-'report'")
    row, = client.get(REVIEW).json()["items"]
    assert row["research_status"] == "queued" and row["assessment"]["risk"]["score"] == 72
    claimed = classifier.claim(st, tenant)
    assert claimed is not None
    classifier.finish(st, claimed)
    assert classifier.claim(st, tenant) is None
    row, = client.get(REVIEW).json()["items"]
    assert row["research_status"] == "retry_pending" and row["approval_status"] == "approved"
    st.execute("UPDATE application_classifications SET next_attempt_at=now()")
    result = provider_classifier.parse_result(response())
    classifier.finish(st, classifier.claim(st, tenant), result)
    row, = client.get(REVIEW).json()["items"]
    assert row["assessment"]["report"] == result["assessment"]["report"]
    assert row["research_status"] == "complete" and row["approval_status"] == "approved"
    assert classifier.claim(st, tenant) is None
    # Do not spend additional research calls enriching ordinary or supporting software.
    for attention, software_type in ((False, "application"), (True, "library"), (True, "helper"), (True, "system_component")):
        st.execute("""UPDATE application_classifications SET needs_attention=$1,
            software_type=$2,category=$3,assessment=assessment-'report'""",
            attention, software_type, "other_ai" if attention else "ordinary")
        assert classifier.claim(st, tenant) is None
        assert client.get(REVIEW).json()["items"][0]["research_status"] == "complete"
    client.cookies.set(CONSOLE_COOKIE, identities[1][2])
    assert client.get(REVIEW).json()["items"] == []


def test_inventory_refresh_is_scheduled_across_workers_including_empty_tenants(inventory, monkeypatch, api_service):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    tenant = sensor["tenant_id"]
    calls = []

    async def classified(request):
        calls.append(json.loads(request.content)["input"])
        return httpx.Response(200, json=response(True))

    api_service(cfg, tenant, classified, openai_key="tenant-secret")

    async def workers():
        return await asyncio.gather(*(classifier.run_once(st, cfg, tenant) for _ in range(4)))

    assert asyncio.run(workers()) == [False] * 4
    first_scan = st.scalar("SELECT next_scan_at FROM application_classification_scans WHERE tenant_id=$1", tenant)
    assert post(client, token, snapshot([app("opencode", name="OpenCode")])).status_code == 200
    # A new worker shares the database schedule; idle passes do not sync even
    # when the previous inventory was empty. No provider request occurs yet.
    assert asyncio.run(workers()) == [False] * 4
    assert st.scalar("SELECT count(*) FROM application_classifications") == 0
    assert st.scalar("SELECT next_scan_at FROM application_classification_scans WHERE tenant_id=$1", tenant) == first_scan
    assert not calls
    st.execute("UPDATE application_classification_scans SET next_scan_at=now()")
    assert asyncio.run(workers()).count(True) == 1
    assert len(calls) == 1
    assert client.get(REVIEW).json()["items"][0]["classification_status"] == "complete"
    assert asyncio.run(workers()) == [False] * 4
    # A scanner already holding the tenant lock prevents another scan, without
    # waiting or advancing the shared schedule. Work resumes after its release.
    st.execute("UPDATE application_classification_scans SET next_scan_at=now()")
    with st.transaction() as conn:
        st.scalar("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                  "application-classification-scan:" + tenant, conn=conn)
        assert not classifier.refresh_inventory(st, tenant)
    assert classifier.refresh_inventory(st, tenant)
    assert not classifier.refresh_inventory(st, tenant)


def test_installed_app_user_counts_use_latest_login_and_distinct_devices(inventory):
    st, cfg, client, identities = inventory
    first, token, session = identities[0]
    other, other_token, other_session = identities[1]
    tenant = first["tenant_id"]
    shared = app("shared", name="Shared editor")
    single = app("single", name="Single-user tool")
    unknown = app("unknown", name="Unknown-user tool")
    enrollment = st.create_enrollment_token(tenant)["token"]
    devices = [(first, token)] + [st.enroll_sensor({
        "enrollment_token": enrollment, "hostname": f"device-{i}", "os": "linux", "user": "service",
    })[:2] for i in range(3)]
    for i, (device, bearer) in enumerate(devices):
        if i < 3:
            st.record_heartbeat(device["id"], {"signed_in_user": {
                "name": "Alice" if i < 2 else "alice_%", "signed_in_at": "2026-01-01T00:00:00Z",
            }})
        apps = [shared] + ([single] if i < 2 else []) + ([unknown] if i == 3 else [])
        assert post(client, bearer, snapshot(apps + [dict(shared, path="/other/shared")])).status_code == 200
    assert post(client, other_token, snapshot([shared])).status_code == 200
    st.record_heartbeat(other["id"], {"signed_in_user": {"name": "private-other-tenant", "signed_in_at": "2026-01-01T00:00:00Z"}})
    products = application_review.observed(st, tenant)
    application_review.sync(st, tenant, products)
    shared_id = next(item["id"] for item in products.values() if item["name"] == shared["name"])
    st.execute("UPDATE application_classifications SET needs_attention=false,category='ordinary',checked_at=now() WHERE tenant_id=$1 AND product_id=$2", tenant, shared_id)
    data = client.get(REVIEW).json()
    assert data["device_count"] == 4
    assert data["users"] == [{"user": "Alice", "device_count": 2}, {"user": "alice_%", "device_count": 1}, {"user": "", "device_count": 1}]
    assert [item["name"] for item in data["items"]] == ["Shared editor", "Single-user tool", "Unknown-user tool"]
    shared_row, single_row, unknown_row = data["items"]
    assert shared_row["users"] == data["users"] and not shared_row["needs_attention"]
    assert single_row["users"] == [{"user": "Alice", "device_count": 2}]
    assert unknown_row["users"] == [{"user": "", "device_count": 1}]
    detail = client.get(f"{REVIEW}/{shared_id}/devices").json()
    assert {row["id"]: row["user"] for row in detail["items"]} == {
        device["id"]: "Alice" if i < 2 else "alice_%" if i == 2 else ""
        for i, (device, _) in enumerate(devices)
    }
    assert "service" not in json.dumps(data) and "private-other-tenant" not in json.dumps(data)
    st.execute("UPDATE sensors SET deleted_at=now() WHERE id=$1", devices[1][0]["id"])
    data = client.get(REVIEW).json()
    assert data["device_count"] == 3 and data["users"][0] == {"user": "Alice", "device_count": 1}
    assert len(client.get(f"{REVIEW}/{shared_id}/devices").json()["items"]) == 3
    client.cookies.set(CONSOLE_COOKIE, other_session)
    data = client.get(REVIEW).json()
    assert data["device_count"] == 1 and data["users"] == [{"user": "private-other-tenant", "device_count": 1}]


@pytest.mark.parametrize("desktop_approved", [True, False])
def test_codex_product_approval_preserves_choices_and_installation_evidence(inventory, desktop_approved):
    from pathlib import Path
    from test_app_inventory_server import root, component, send_components

    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    other_sensor, other_token, other_session = identities[1]
    tenant = sensor["tenant_id"]
    windows_id = "OpenAI.Codex_examplepublisher"
    windows_product = "app-" + hashlib.sha256(("windows-appx:" + windows_id.lower()).encode()).hexdigest()
    mac = app("com.openai.codex", name="ChatGPT", source="macos-spotlight", kind="application", path="/Applications/ChatGPT.app")
    chat = app("com.openai.chat", name="ChatGPT", source="macos-spotlight", kind="application", path="/Applications/ChatGPT Classic.app")
    assert post(client, token, snapshot([mac, chat], source="macos-spotlight")).status_code == 200
    windows, windows_token, _ = st.enroll_sensor({"enrollment_token": st.create_enrollment_token(tenant)["token"], "hostname": "windows", "os": "windows"})
    win = app(windows_id, name="OpenAI.Codex", source="windows-appx", kind="application")
    lookalike = app("OpenAI.Codex.Helper_examplepublisher", name="OpenAI.Codex.Helper", source="windows-appx", kind="application")
    assert post(client, windows_token, snapshot([win, lookalike], source="windows-appx")).status_code == 200
    assert send_components(client, token, [root(source="osquery-npm-packages", components=[
        component("@openai/codex", ecosystem="npm"), component("com.openai.codex", ecosystem="npm"),
    ])]).status_code == 200
    # A package using the native bundle name is not a native Codex installation.
    observed = application_review.observed(st, tenant)
    unrelated = next(product for product, item in observed.items() if item["name"] == "com.openai.codex")
    application_review.sync(st, tenant, observed)
    assert post(client, other_token, snapshot([mac], source="macos-spotlight")).status_code == 200
    for item in (sensor, windows):
        st.record_heartbeat(item["id"], {"signed_in_user": {"name": "alice", "signed_in_at": "2026-01-01T00:00:00Z"}})
    # Simulate choices stored before product aliases existed. The old macOS
    # name fallback shared ChatGPT's key; future choices must be independent.
    st.execute("ALTER TABLE ai_application_approvals DROP COLUMN approval_conflict, DROP COLUMN previous_decisions")
    for product, name, approved in (("codex-cli", "Codex CLI", True), ("chatgpt", "ChatGPT", True),
                                     (windows_product, "OpenAI.Codex", desktop_approved), (unrelated, "com.openai.codex", False)):
        st.execute("INSERT INTO ai_application_approvals(tenant_id,product_id,name,approved) VALUES($1,$2,$3,$4)", tenant, product, name, approved)
    st.execute("INSERT INTO ai_application_approvals(tenant_id,product_id,name,approved) VALUES($1,'codex-cli','Codex CLI',false)", other_sensor["tenant_id"])
    migration = Path(application_review.__file__).parent / "migrations/0097_codex_product_approval.sql"
    with st.transaction() as conn:
        conn.execute(migration.read_text())
    rows = {row["id"]: row for row in client.get(REVIEW).json()["items"]}
    codex = rows["codex"]
    assert codex["display_name"] == "Codex" and codex["approval_scope"]
    assert codex["device_count"] == 2 and codex["users"] == [{"user": "alice", "device_count": 2}]
    assert codex["reported_names"] == ["@openai/codex", "ChatGPT", "OpenAI.Codex"]
    assert codex["approval_status"] == ("approved" if desktop_approved else "unapproved")
    assert codex["approval_conflict"] is (not desktop_approved)
    assert rows["chatgpt"]["approval_status"] == "approved" and not rows["chatgpt"]["approval_scope"]
    assert len(rows) == 4 and next(row for row in rows.values() if row["name"] == lookalike["name"])["approval_status"] == "monitoring"
    assert rows[unrelated]["approval_status"] == "unapproved" and not rows[unrelated]["approval_scope"]
    details = client.get(f"{REVIEW}/codex/devices").json()["items"]
    assert len(details) == 2 and sum(len(device["installations"]) for device in details) == 3
    assert {entry["identifier"] for device in details for entry in device["installations"]} == {"com.openai.codex", windows_id, "@openai/codex"}
    assert client.get(f"{REVIEW}/{windows_product}/devices").json()["id"] == windows_product
    assert client.get(f"{REVIEW}/codex-cli/devices").json()["id"] == "codex-cli"
    assert st.scalar("SELECT count(*) FROM ai_application_approvals WHERE tenant_id=$1", tenant) == 5
    # Model-provided names cannot split or rename the verified approval product.
    application_review.sync(st, tenant, application_review.observed(st, tenant))
    while claim := classifier.claim(st, tenant):
        classifier.finish(st, claim, provider_classifier.parse_result(response(display_name="ChatGPT desktop with Codex")))
    named = {row["id"]: row["display_name"] for row in client.get(REVIEW).json()["items"]}
    assert named["codex"] == "Codex" and named["chatgpt"] == "ChatGPT"
    for role in ("security_leadership", "it_admin"):
        st.execute("UPDATE tenant_users SET roles=$2 WHERE tenant_id=$1", tenant, [role])
        result = client.put(f"{REVIEW}/codex/approval", json={"approved": True}, headers=HEADERS)
        assert result.status_code == (403 if role == "security_leadership" else 200)
    assert not st.scalar("SELECT approval_conflict FROM ai_application_approvals WHERE tenant_id=$1 AND product_id='codex'", tenant)
    if not desktop_approved:
        audit = st.scalar("SELECT details FROM audit_log WHERE tenant_id=$1 AND action='ai-application.approval' ORDER BY at DESC LIMIT 1", tenant)
        assert any(not decision["approved"] for decision in audit["previous_decisions"])
    # A legacy worker can finish after migration. Its later denial must remain
    # visible until a new whole-product decision explicitly resolves it.
    st.execute("UPDATE ai_application_approvals SET approved=false,updated_at=clock_timestamp() WHERE tenant_id=$1 AND product_id='codex-cli'", tenant)
    late = next(row for row in client.get(REVIEW).json()["items"] if row["id"] == "codex")
    assert late["approval_status"] == "unapproved" and late["approval_conflict"]
    assert client.put(f"{REVIEW}/codex/approval", json={"approved": True}, headers=HEADERS).status_code == 200
    resolved = next(row for row in client.get(REVIEW).json()["items"] if row["id"] == "codex")
    assert resolved["approval_status"] == "approved" and not resolved["approval_conflict"]
    # The compatibility API and current API both write the same product choice.
    assert client.put(f"{AI_APPS}/codex-cli/approval", json={"approved": False}, headers=HEADERS).status_code == 200
    rows = {row["id"]: row for row in client.get(REVIEW).json()["items"]}
    assert rows["codex"]["approval_status"] == "unapproved" and rows["chatgpt"]["approval_status"] == "approved"
    assert client.put(f"{REVIEW}/codex/approval", json={"approved": True}, headers=HEADERS).status_code == 200
    assert client.put(f"{REVIEW}/chatgpt/approval", json={"approved": False}, headers=HEADERS).status_code == 200
    rows = {row["id"]: row for row in client.get(REVIEW).json()["items"]}
    assert rows["codex"]["approval_status"] == "approved" and rows["chatgpt"]["approval_status"] == "unapproved"
    # Monitoring keeps the canonical timestamp and aliases, so old decisions
    # cannot reappear and later approval writes still resolve the same product.
    assert client.put(f"{REVIEW}/{windows_product}/approval", json={"approved": None}, headers=HEADERS).status_code == 200
    rows = {row["id"]: row for row in client.get(REVIEW).json()["items"]}
    assert rows["codex"]["approval_status"] == "monitoring" and not rows["codex"]["approval_conflict"]
    assert rows["codex"]["review_required"] and rows["chatgpt"]["approval_status"] == "unapproved"
    assert client.get(f"{REVIEW}/{windows_product}/devices").status_code == 200
    assert client.put(f"{AI_APPS}/codex-cli/approval", json={"approved": True}, headers=HEADERS).status_code == 200
    assert next(row for row in client.get(REVIEW).json()["items"] if row["id"] == "codex")["approval_status"] == "approved"
    client.cookies.set(CONSOLE_COOKIE, other_session)
    other = next(row for row in client.get(REVIEW).json()["items"] if row["id"] == "codex")
    assert other["approval_status"] == "unapproved" and other["device_count"] == 1
    assert client.get(f"{REVIEW}/{windows_product}/devices").status_code == 404


def test_general_purpose_apps_stay_outside_ai_review_despite_cached_ai_classification(inventory):
    st, _, client, identities = inventory
    sensor, token, _ = identities[0]
    tenant = sensor["tenant_id"]
    records = [
        app("com.google.Chrome", name="Google Chrome", kind="application"),
        app("Microsoft.Paint_8wekyb3d8bbwe", name="Microsoft Paint", kind="application"),
        app("Microsoft.OutlookForWindows_8wekyb3d8bbwe", name="Microsoft Outlook", kind="application"),
        app("Microsoft.Copilot_8wekyb3d8bbwe", name="Microsoft Copilot", kind="application"),
        app("com.google.Chrome.assistant", name="Separate AI assistant", kind="application"),
        app("unknown-component", name="Unknown system component", kind="application"),
    ]
    assert post(client, token, snapshot(records)).status_code == 200
    application_review.sync(st, tenant, application_review.observed(st, tenant))
    while item := classifier.claim(st, tenant):
        unknown = item["evidence"][0]["name"] == "Unknown system component"
        classifier.finish(st, item, provider_classifier.parse_result(response(None if unknown else True)))
    st.execute("UPDATE tenant_users SET roles=ARRAY['it_admin']::text[] WHERE tenant_id=$1", tenant)
    rows = {row["name"]: row for row in client.get(REVIEW).json()["items"]}
    chrome = rows["Google Chrome"]["id"]
    assert client.put(f"{REVIEW}/{chrome}/approval", json={"approved": False}, headers=HEADERS).status_code == 200
    rows = {row["name"]: row for row in client.get(REVIEW).json()["items"]}
    assert len(rows) == len(records)
    for name in ("Google Chrome", "Microsoft Paint", "Microsoft Outlook"):
        row = rows[name]
        assert not row["needs_attention"] and not row["review_required"]
        assert row["category"] == "ordinary" and row["assessment"] is None
        assert row["research_status"] == "complete"
    assert rows["Google Chrome"]["approval_status"] == "unapproved"
    assert len(client.get(f"{REVIEW}/{chrome}/devices").json()["items"]) == 1
    assert rows["Microsoft Copilot"]["review_required"]
    assert rows["Separate AI assistant"]["review_required"]
    assert not rows["Unknown system component"]["review_required"]
    assert rows["Unknown system component"]["classification_status"] == "unknown"
