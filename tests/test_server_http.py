import os
from pathlib import Path
import shutil
import subprocess
import sys
from contextlib import nullcontext
from unittest.mock import Mock
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from openaidr.server import auth, store
from openaidr.server.app import create_app, validate_rule
from openaidr.server.config import Config, PLATFORM_AVAILABLE


def config(services=None):
    services = services or ("api,admin,ingest" if PLATFORM_AVAILABLE else "api,ingest")
    cfg = Config()
    cfg.set_services(services)
    return cfg


@pytest.fixture
def backend():
    st = Mock()
    st.ping.return_value = 0.001
    connection = Mock()
    connection.transaction.side_effect = lambda: nullcontext(connection)
    st.transaction.side_effect = lambda: nullcontext(connection)
    st.get_session.return_value = {
        "user": {
            "id": "user",
            "name": "User",
            "email": "user@example.com",
            "role": "owner",
            "status": "active",
        },
        "tenant": {
            "id": "tenant",
            "name": "Tenant",
            "slug": "tenant",
            "status": "active",
        },
    }
    return st


@pytest.fixture
def client(backend):
    return TestClient(create_app(config(), backend), headers={auth.CSRF_HEADER: "1"})


def test_health_ready_and_request_id(client, backend):
    result = client.get("/healthz", headers={"X-Request-Id": "chosen"})
    assert result.json()["status"] == "ok"
    assert result.headers["x-request-id"] == "chosen"
    backend.ping.side_effect = RuntimeError("down")
    assert client.get("/readyz").status_code == 503


def test_service_selection_does_not_fallthrough(backend):
    client = TestClient(create_app(config("api"), backend))
    assert (
        client.post("/ingest/v1/enroll", json={}).json()["error"]["code"] == "not_found"
    )
    assert client.get("/admin/v1/tenants").status_code == 404
    assert client.get("/api/unknown").status_code == 404


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_only_administrators_can_create_enrollment_links(client, backend, role):
    backend.get_session.return_value["user"]["role"] = role
    client.cookies.set(auth.CONSOLE_COOKIE, "session")
    assert client.post("/api/v1/sensors/enrollment-links", json={"label": "denied"}).status_code == 403
    backend.create_enrollment_token.assert_not_called()


def test_enrollment_preview_is_scoped_and_reports_required_device_auth(backend):
    cfg = config("ingest")
    cfg.database_url = "postgresql://unused/test"
    cfg.tenant_id = "01000000-0000-7000-8000-000000000001"
    app = create_app(cfg, backend)
    app.state.service.device_credentials = Mock()
    backend.preview_enrollment.return_value = {
        "tenant": {"id": cfg.tenant_id, "name": "Organization"},
        "expires_at": "2099-01-01T00:00:00Z",
    }
    client = TestClient(app)
    code = "oaet_" + "a" * 43
    reply = client.post("/ingest/v1/enrollment/preview", json={"enrollment_token": code})
    assert reply.status_code == 200
    assert reply.json()["auth_mode"] == "mtls"
    backend.preview_enrollment.assert_called_once_with(code, cfg.tenant_id)
    app.state.service.device_credentials.enroll.assert_not_called()
    backend.enroll_sensor.assert_not_called()
    assert client.get("/ingest/v1/enrollment/preview").status_code == 404
    assert client.post("/ingest/v1/enrollment/preview", json={"enrollment_token": "bad"}).status_code == 401


def test_auth_content_type_and_expired_cookie(client, backend):
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.post("/api/v1/auth/login", content="{}").status_code == 415
    assert (
        client.post(
            "/api/v1/auth/login",
            content="{",
            headers={"Content-Type": "application/json"},
        ).status_code
        == 400
    )
    backend.get_session.side_effect = store.NotFound()
    client.cookies.set(auth.CONSOLE_COOKIE, "expired")
    result = client.get("/api/v1/auth/me")
    assert result.status_code == 401
    assert "Max-Age=0" in result.headers["set-cookie"]


def test_local_auth_discovery_and_service_boundary(backend):
    client = TestClient(create_app(config(), backend))
    for prefix in (("/api/v1", "/admin/v1") if PLATFORM_AVAILABLE else ("/api/v1",)):
        result = client.get(prefix + "/auth/config")
        assert result.json() == {"version": 1, "mode": "local", "password_login": True}
        assert result.headers["cache-control"] == "no-store"
        assert "set-cookie" not in result.headers
        assert client.post(prefix + "/auth/renew", json={}, headers={auth.CSRF_HEADER: "1"}).status_code == 404
    tenant_only = TestClient(create_app(config("api"), backend))
    assert tenant_only.get("/admin/v1/auth/config").status_code == 404
    backend.get_session.assert_not_called()
    backend.get_admin_session.assert_not_called()


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/v1/auth/login"),
        ("POST", "/api/v1/auth/logout"),
        ("POST", "/api/v1/auth/accept-invite"),
        ("POST", "/admin/v1/auth/login"),
        ("POST", "/admin/v1/auth/logout"),
        ("POST", "/api/v1/users/invites"),
        ("PUT", "/api/v1/response/policy"),
        ("PATCH", "/admin/v1/tenants/tenant"),
        ("DELETE", "/api/v1/users/invites/invite"),
        ("DELETE", "/admin/v1/tenants/tenant"),
    ],
)
def test_human_mutations_require_csrf_header(backend, method, path):
    if path.startswith("/admin/") and not PLATFORM_AVAILABLE:
        pytest.skip("private platform route")
    client = TestClient(create_app(config(), backend))
    client.cookies.set(auth.CONSOLE_COOKIE, "session")
    client.cookies.set(auth.ADMIN_COOKIE, "admin-session")
    for headers in ({}, {"Origin": "http://localhost:8080"}):
        result = client.request(method, path, json={}, headers=headers)
        assert result.status_code == 403
        assert auth.CSRF_HEADER in result.json()["error"]["message"]
    assert backend.mock_calls == []


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://attacker.example"},
        {"Origin": "http://sibling.localhost:8080"},
        {"Origin": "http://localhost:8081"},
        {"Origin": "null"},
        {"Origin": ""},
        {"Origin": "http://localhost:8080/"},
        {"Origin": "http://localhost:8080 http://attacker.example"},
        {"Origin": "http://localhost:8080@attacker.example"},
        {"Origin": "http://localhost:bad"},
        {"Origin": "http://localhost:8080\\attacker"},
        {"Referer": "https://attacker.example/form"},
        {"Referer": "http://user@localhost:8080/form"},
        {"Referer": "http://localhost:8080/form#fragment"},
        {"Referer": "not a URL"},
        [("Origin", "http://localhost:8080"), ("Origin", "http://localhost:8080")],
        [("Referer", "http://localhost:8080/"), ("Referer", "http://localhost:8080/")],
    ],
)
def test_human_mutations_reject_untrusted_or_malformed_origin(backend, headers):
    client = TestClient(create_app(config(), backend), headers={auth.CSRF_HEADER: "1"})
    client.cookies.set(auth.CONSOLE_COOKIE, "session")
    result = client.post("/api/v1/auth/logout", json={}, headers=headers)
    assert result.status_code == 403
    backend.delete_session.assert_not_called()


def test_simple_cross_site_requests_and_preflights_are_denied(backend):
    client = TestClient(create_app(config(), backend))
    result = client.post(
        "/api/v1/auth/logout",
        data={"logout": "yes"},
        headers={"Origin": "https://attacker.example"},
    )
    assert result.status_code == 403
    result = client.options(
        "/api/v1/auth/logout",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": auth.CSRF_HEADER,
        },
    )
    assert result.status_code == 404
    assert "access-control-allow-origin" not in result.headers
    assert "access-control-allow-headers" not in result.headers
    backend.delete_session.assert_not_called()


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost:3000",
        "http://127.0.0.1:8080",
        "http://192.168.1.20:8080",
        "http://[::1]:8080",
        "https://console.example.test",
    ],
)
def test_configured_origin_and_native_mutations_succeed(backend, origin):
    cfg = config()
    cfg.public_url = origin
    client = TestClient(
        create_app(cfg, backend), base_url=origin, headers={auth.CSRF_HEADER: "1"}
    )
    cookie = auth.cookie_name(secure=origin.startswith("https://"))
    client.cookies.set(cookie, "session")
    for headers in (
        {"Origin": origin},
        {"Referer": origin + "/settings?tab=users"},
        {},
    ):
        result = client.post("/api/v1/auth/logout", json={}, headers=headers)
        assert result.status_code == 204
    assert backend.delete_session.call_count == 3


def test_same_origin_delete_with_session_succeeds(client, backend):
    ident = "01000000-0000-7000-8000-000000000001"
    client.cookies.set(auth.CONSOLE_COOKIE, "session")
    result = client.delete(
        "/api/v1/users/invites/" + ident,
        headers={"Origin": "http://localhost:8080"},
    )
    assert result.status_code == 204
    backend.delete_invite.assert_called_once_with("tenant", ident)


def test_origin_is_configured_not_taken_from_host_or_proxy_headers(backend):
    client = TestClient(create_app(config(), backend), headers={auth.CSRF_HEADER: "1"})
    result = client.post(
        "/api/v1/auth/logout",
        json={},
        headers={
            "Origin": "https://attacker.example",
            "Host": "attacker.example",
            "X-Forwarded-Host": "attacker.example",
            "X-Forwarded-Proto": "https",
            "Forwarded": "host=attacker.example;proto=https",
        },
    )
    assert result.status_code == 403


@pytest.mark.skipif(not PLATFORM_AVAILABLE, reason="private platform routes")
def test_admin_origin_is_separate_from_tenant_origin(backend):
    cfg = config()
    cfg.public_url = "http://localhost:5173"
    cfg.admin_public_url = "http://localhost:5174"
    client = TestClient(create_app(cfg, backend), headers={auth.CSRF_HEADER: "1"})
    for prefix, origin, other in (
        ("/api/v1", cfg.public_url, cfg.admin_public_url),
        ("/admin/v1", cfg.admin_public_url, cfg.public_url),
    ):
        assert (
            client.post(
                prefix + "/auth/logout", json={}, headers={"Origin": origin}
            ).status_code
            == 204
        )
        assert (
            client.post(
                prefix + "/auth/logout", json={}, headers={"Origin": other}
            ).status_code
            == 403
        )


@pytest.mark.parametrize(
    "tenant_origin,admin_origin",
    [
        ("https://tenant.example.test", "http://admin.example.test"),
        ("http://tenant.example.test", "https://admin.example.test"),
    ],
)
@pytest.mark.parametrize("force_secure", [None, "false", "true"])
@pytest.mark.skipif(not PLATFORM_AVAILABLE, reason="private platform routes")
def test_environment_mixed_origins_use_independent_login_cookies(
    backend, monkeypatch, tenant_origin, admin_origin, force_secure
):
    for key in tuple(os.environ):
        if key.startswith("OPENAIDR_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("OPENAIDR_PUBLIC_URL", tenant_origin)
    monkeypatch.setenv("OPENAIDR_ADMIN_PUBLIC_URL", admin_origin)
    monkeypatch.setenv("OPENAIDR_SERVICES", "api,admin")
    if force_secure is not None:
        monkeypatch.setenv("OPENAIDR_COOKIE_SECURE", force_secure)
    cfg = Config.from_env()
    password = auth.hash_password("password123")
    tenant = backend.get_session.return_value["tenant"]
    backend.get_user_by_email.return_value = {
        **backend.get_session.return_value["user"],
        "tenant_id": tenant["id"],
        "password_hash": password,
    }
    backend.get_tenant_brief.return_value = tenant
    backend.create_session.return_value = "tenant-session"
    backend.get_admin_by_email.return_value = {
        "id": "admin",
        "email": "admin@example.test",
        "name": "Admin",
        "password_hash": password,
    }
    backend.get_admin_session.return_value = {
        "id": "admin",
        "email": "admin@example.test",
        "name": "Admin",
    }
    backend.create_admin_session.return_value = "admin-session"
    app = create_app(cfg, backend)
    for prefix, origin, admin in (
        ("/api/v1", tenant_origin, False),
        ("/admin/v1", admin_origin, True),
    ):
        client = TestClient(
            app, base_url=origin, headers={auth.CSRF_HEADER: "1", "Origin": origin}
        )
        legacy = auth.cookie_name(admin=admin)
        client.cookies.set(legacy, "legacy-session", domain=urlsplit(origin).hostname, path="/")
        result = client.post(
            prefix + "/auth/login",
            json={"email": "user@example.test", "password": "password123"},
        )
        assert result.status_code == 200
        secure = force_secure == "true" or origin.startswith("https://")
        cookie = result.headers["set-cookie"]
        assert cookie.startswith(auth.cookie_name(admin=admin, secure=secure) + "=")
        assert ("Secure" in cookie) == secure
        legacy_headers = [h for h in result.headers.get_list("set-cookie") if h.startswith(legacy + "=")]
        if secure:
            assert len(legacy_headers) == 1 and "Max-Age=0" in legacy_headers[0]
            assert legacy not in client.cookies
        else:
            assert len(legacy_headers) == 1 and "Max-Age=0" not in legacy_headers[0]
            assert client.cookies.get(legacy) == ("admin-session" if admin else "tenant-session")
        # Explicit forcing must still prevent cookie delivery over plain HTTP.
        expected = 401 if secure and origin.startswith("http://") else 200
        assert client.get(prefix + "/auth/me").status_code == expected
        client.close()


def test_https_session_cookies_ignore_legacy_sibling_cookies(backend):
    cfg = config()
    cfg.public_url = "https://tenant.example.test"
    cfg.admin_public_url = "https://admin.example.test" if PLATFORM_AVAILABLE else ""
    client = TestClient(
        create_app(cfg, backend),
        base_url=cfg.public_url,
        headers={auth.CSRF_HEADER: "1"},
    )
    backend.get_admin_session.return_value = {
        "id": "admin",
        "email": "admin@example.test",
        "name": "Admin",
    }
    for prefix, legacy, admin in (
        ("/api/v1", auth.CONSOLE_COOKIE, False),
        ("/admin/v1", auth.ADMIN_COOKIE, True),
    ):
        if admin and not PLATFORM_AVAILABLE:
            continue
        result = client.get(
            prefix + "/auth/me", headers={"Cookie": legacy + "=injected"}
        )
        assert result.status_code == 401
        name = auth.cookie_name(admin=admin, secure=True)
        result = client.get(
            prefix + "/auth/me",
            headers={"Cookie": name + "=valid; " + legacy + "=injected"},
        )
        assert result.status_code == 200
        getter = backend.get_admin_session if admin else backend.get_session
        getter.assert_called_once_with("valid")
        client.cookies.set(legacy, "old-session", domain="tenant.example.test", path="/")
        result = client.post(
            prefix + "/auth/logout", json={}, headers={"Cookie": name + "=valid"}
        )
        header = result.headers["set-cookie"]
        assert header.startswith(name + "=")
        assert all(
            part in header
            for part in ("Secure", "HttpOnly", "SameSite=lax", "Path=/", "Max-Age=0")
        )
        assert "Domain=" not in header
        assert any(
            value.startswith(legacy + "=") and "Max-Age=0" in value
            for value in result.headers.get_list("set-cookie")
        )
        assert legacy not in client.cookies


def test_device_mutations_do_not_require_browser_proof(backend):
    client = TestClient(create_app(config(), backend))
    backend.get_sensor_by_token.return_value = {"id": "sensor", "disabled": False}
    backend.ingest_batch.return_value = {"accepted": 0, "duplicates": 0}
    result = client.post(
        "/ingest/v1/events",
        json={"events": []},
        headers={
            "Authorization": "Bearer sensor-token",
            "Origin": "null",
        },
    )
    assert result.status_code == 200


def test_role_and_tenant_guards(client, backend):
    client.cookies.set(auth.CONSOLE_COOKIE, "session")
    backend.get_session.return_value["user"]["role"] = "viewer"
    assert (
        client.post(
            "/api/v1/response/actions", json={"type": "note", "params": {"text": "hi"}}
        ).status_code
        == 403
    )
    backend.get_session.return_value["tenant"]["status"] = "suspended"
    assert client.get("/api/v1/events").status_code == 403
    backend.list_events.assert_not_called()


def test_pagination_validation(client, backend):
    client.cookies.set(auth.CONSOLE_COOKIE, "session")
    for query in (
        "limit=-1",
        "limit=wat",
        "cursor=broken",
        "sensor_id=broken",
        "since=wat",
        "since=2026-01-01T00:00:00",
    ):
        assert client.get("/api/v1/events?" + query).status_code == 400
    backend.list_events.return_value = ([], "")
    assert client.get("/api/v1/events").json() == {"items": [], "next_cursor": ""}


def test_evidence_search_filters_are_authenticated_and_validated(client, backend):
    params = {"username": "Alice_%", "hostname": "DEV", "session": "session-a", "kind": "command",
              "since": "2026-10-12T07:00:00Z", "before": "2026-10-13T07:00:00Z"}
    assert client.get("/api/v1/events", params=params).status_code == 401
    backend.list_events.assert_not_called()
    client.cookies.set(auth.CONSOLE_COOKIE, "session")
    backend.list_events.return_value = ([], "")
    assert client.get("/api/v1/events", params=params).status_code == 200
    tid, filters, _ = backend.list_events.call_args.args
    assert tid == "tenant"
    assert all(filters[key] == params[key] for key in ("username", "hostname", "session", "kind"))
    assert filters["before"].isoformat() == "2026-10-13T07:00:00+00:00"
    for key in ("username", "hostname", "session"):
        for value in ("a" * 1025, "a\x00b"):
            backend.list_events.reset_mock()
            assert client.get("/api/v1/events", params={key: value}).status_code == 400
            backend.list_events.assert_not_called()
    for value in ("invalid", "2026-10-12T00:00:00"):
        assert client.get("/api/v1/events", params={"before": value}).status_code == 400


def test_event_risks_are_authenticated_tenant_scoped_and_bounded(client, backend):
    from uuid import uuid4

    event_id = str(uuid4())
    assert client.get("/api/v1/events/risks", params={"ids": event_id}).status_code == 401
    client.cookies.set(auth.CONSOLE_COOKIE, "session")
    backend.event_risks.return_value = [{"id": event_id, "risk": None}]
    result = client.get("/api/v1/events/risks", params={"ids": event_id})
    assert result.status_code == 200 and result.json()["items"][0]["risk"] is None
    backend.event_risks.assert_called_once_with("tenant", [event_id])
    for ids in ("", "invalid", ",".join([event_id] * 101)):
        assert client.get("/api/v1/events/risks", params={"ids": ids}).status_code == 400


def test_live_events_validation_and_shape(client, backend):
    client.cookies.set(auth.CONSOLE_COOKIE, "session")
    backend.live_events.return_value = (
        [
            {
                "id": "01000000-0000-7000-8000-000000000001",
                "tenant_id": "tenant",
                "sensor_id": "sensor",
                "agent_id": None,
                "session_id": None,
                "time": "2026-09-29T10:00:00Z",
                "received_at": "2026-09-29T10:00:01Z",
                "kind": "prompt",
                "product": "codex-cli",
                "body": {"kind": "prompt", "text": "hello", "agent": {"product": "codex-cli"}},
            }
        ],
        "cursor-1",
        False,
    )
    result = client.get("/api/v1/events/live", params={"kind": "prompt", "limit": "5"})
    assert result.status_code == 200, result.text
    payload = result.json()
    assert payload["cursor"] == "cursor-1" and payload["more"] is False
    assert payload["items"][0]["text"] == "hello"
    assert payload["items"][0]["received_at"] == "2026-09-29T10:00:01Z"
    assert "body" not in payload["items"][0]
    args = backend.live_events.call_args.args
    assert args[0] == "tenant" and args[1] is None and args[2]["kind"] == "prompt"
    assert args[3] == 5
    assert client.get("/api/v1/events/live", params={"after": "???"}).status_code == 400
    assert (
        client.get("/api/v1/events/live", params={"source": "bogus"}).status_code
        == 400
    )
    assert (
        client.get("/api/v1/events/live", params={"sensor_id": "nope"}).status_code
        == 400
    )
    assert client.get("/api/v1/events/live", params={"limit": "x"}).status_code == 400
    valid = store.Cursor(store.now(), store.new_id()).encode()
    assert client.get("/api/v1/events/live", params={"after": valid}).status_code == 200
    assert backend.live_events.call_args.args[1] == store.decode_live_cursor(valid)
    live = store.LiveCursor(store.Cursor(store.now(), store.new_id()), (41, 42)).encode()
    assert client.get("/api/v1/events/live", params={"after": live}).status_code == 200
    assert backend.live_events.call_args.args[1].pending == (41, 42)
    assert backend.live_events.call_args.args[3] == 100
    assert client.get("/api/v1/events/live", params={"limit": "-1"}).status_code == 400


@pytest.mark.parametrize("captured_body", ["hello", None, [1, 2], {"message": "hello"}])
def test_event_routes_preserve_captured_payloads(client, backend, captured_body):
    from copy import deepcopy
    from openaidr.core.event import new_id, now, validate_event

    event_id, session_id, finding_id = new_id(), new_id(), new_id()
    payload = {
        "body": captured_body, "received_at": "customer timestamp", "username": "alice",
        "tenant_id": "customer tenant", "password_hash": "captured password field",
        "token_hash": "captured token field", "actor_id": "captured actor",
        "author_name": "captured author", "assignee_id": "captured assignee",
        "primary_event_id": "captured event", "host": "customer host",
        "hostname": "customer hostname", "os": "customer OS", "arch": "customer arch",
        "_sa_customer": "captured application field",
    }
    event = {
        "id": event_id, "time": now(), "kind": "tool.call",
        "agent": {"product": "claude-code"}, "session": {"id": "captured-session"},
        "tool": {"name": "webhook", "input": {"nested": [payload]}, "output": payload},
        # These are also valid top-level extension fields, not an event row.
        "body": captured_body, "received_at": "captured timestamp", "username": "alice",
    }
    assert validate_event(event) == ""
    backend.get_sensor_by_token.return_value = {"id": "sensor", "tenant_id": "tenant", "disabled": False}
    backend.get_tenant_brief.return_value = {"id": "tenant", "status": "active"}
    backend.ingest_batch.return_value = {"accepted": 1, "duplicates": 0}
    ingested = client.post("/ingest/v1/events", json={"events": [event]},
                           headers={"Authorization": "Bearer sensor-token"})
    assert ingested.status_code == 200 and ingested.json()["accepted"] == 1
    captured = backend.ingest_batch.call_args.args[1][0]
    row = {
        "id": event_id, "tenant_id": "tenant", "sensor_id": "sensor", "agent_id": None,
        "session_id": session_id, "time": event["time"], "received_at": now(),
        "kind": "tool.call", "body": captured, "risk": {"knowledge": payload},
        "token_hash": "internal row field",
    }
    original = deepcopy(row)
    backend.list_events.return_value = ([row], "next-event")
    backend.get_event.return_value = row
    backend.live_events.return_value = ([row], "live-cursor", False)
    backend.list_session_events.return_value = ([row], "next-session-event")
    backend.list_session_evidence.side_effect = lambda *args, **kwargs: {
        "items": [row], "next_cursor": "next-evidence", "coverage": {"status": "unknown"},
    }
    backend.get_finding.return_value = {
        "id": finding_id, "rule_id": "test-rule", "event_ids": [event_id],
        "investigation_evidence": payload, "primary_event_id": event_id,
    }
    backend.get_events.return_value = [row]
    backend.list_notes.return_value = []
    backend.actions_for_finding.return_value = []
    client.cookies.set(auth.CONSOLE_COOKIE, "session")
    for path in (
        "events", f"events/{event_id}", "events/live", f"sessions/{session_id}/events",
        f"sessions/{session_id}/evidence", f"me/sessions/{session_id}/evidence",
        f"findings/{finding_id}",
    ):
        result = client.get("/api/v1/" + path)
        assert result.status_code == 200, (path, result.text)
        data = result.json()
        if path.startswith("findings/"):
            assert data["finding"]["investigation_evidence"] == payload
            assert "primary_event_id" not in data["finding"]
            actual = data["events"][0]
        else:
            actual = data["items"][0] if "items" in data else data
        assert actual["tool"] == event["tool"]
        assert actual["body"] == captured_body
        assert actual["username"] == "alice"
        assert actual["received_at"] == row["received_at"]
        assert actual["risk"] == row["risk"]
        assert "token_hash" not in actual
    assert row == original


@pytest.mark.parametrize(
    "origin", ["http://localhost:8080", "https://admin.example.test"]
)
@pytest.mark.skipif(not PLATFORM_AVAILABLE, reason="private platform routes")
def test_password_hash_never_exposed(backend, origin):
    from openaidr.core.event import new_id

    cfg = config()
    cfg.public_url = origin
    client = TestClient(
        create_app(cfg, backend),
        base_url=origin,
        headers={auth.CSRF_HEADER: "1", "Origin": origin},
    )
    backend.get_admin_by_email.return_value = {
        "id": "admin",
        "email": "admin@example.com",
        "name": "Admin",
        "password_hash": auth.hash_password("password123"),
    }
    backend.create_admin_session.return_value = "session"
    result = client.post(
        "/admin/v1/auth/login",
        json={"email": "admin@example.com", "password": "password123"},
    )
    assert result.status_code == 200
    assert "password_hash" not in result.text
    assert "HttpOnly" in result.headers["set-cookie"]
    assert "SameSite=lax" in result.headers["set-cookie"]
    secure = origin.startswith("https://")
    assert result.headers["set-cookie"].startswith(
        auth.cookie_name(admin=True, secure=secure) + "="
    )
    assert ("Secure" in result.headers["set-cookie"]) == secure
    assert "Domain=" not in result.headers["set-cookie"]

    # Every endpoint that returns an account row must explicitly remove secrets.
    backend.get_admin_session.return_value = backend.get_admin_by_email.return_value
    backend.list_admins.return_value = [backend.get_admin_by_email.return_value]
    backend.create_admin.return_value = backend.get_admin_by_email.return_value
    account = {"id": new_id(), "name": "User", "role": "viewer", "status": "active", "tenant_id": new_id(),
               "password_hash": "private", "token_hash": "private"}
    backend.list_users.return_value = [account]
    backend.get_user.return_value = account
    backend.update_user.return_value = account
    backend.get_tenant.return_value = backend.get_session.return_value["tenant"]
    backend.list_invites.return_value = []
    backend.list_all_sensors.return_value = []
    backend.list_enrollment_tokens.return_value = []
    client.cookies.set(auth.cookie_name(admin=True, secure=secure), "session")
    client.cookies.set(auth.cookie_name(secure=secure), "session")
    for path in ("/admin/v1/auth/me", "/admin/v1/admins", "/api/v1/users",
                 "/admin/v1/tenants/" + account["tenant_id"]):
        result = client.get(path)
        assert result.status_code == 200, result.text
        assert "password_hash" not in result.text and "token_hash" not in result.text
    backend.transaction.side_effect = lambda: nullcontext(Mock())
    backend.get_user.side_effect = lambda tenant, ident, **options: (
        backend.get_session.return_value["user"] if ident == "user" else account
    )
    result = client.patch("/api/v1/users/" + account["id"], json={"role": "analyst"})
    assert result.status_code == 200
    assert "password_hash" not in result.text and "token_hash" not in result.text
    result = client.post("/admin/v1/admins", json={
        "email": "new@example.com", "name": "New", "password": "password123",
    })
    assert result.status_code == 201
    assert "password_hash" not in result.text


def test_ingest_auth_disabled_and_sensor_binding(client, backend):
    assert client.post("/ingest/v1/events", json={}).status_code == 401
    backend.get_sensor_by_token.return_value = {"id": "sensor", "disabled": True}
    headers = {"Authorization": "Bearer sensor-token"}
    assert client.post("/ingest/v1/events", json={}, headers=headers).status_code == 403
    backend.get_sensor_by_token.return_value["disabled"] = False
    assert (
        client.post(
            "/ingest/v1/events", json={"sensor_id": "different"}, headers=headers
        ).status_code
        == 403
    )


def test_policy_validation():
    with pytest.raises(Exception, match="match condition"):
        validate_rule({"name": "Bad", "action": "deny"})
    with pytest.raises(Exception, match="command_regex"):
        validate_rule(
            {"name": "Bad", "action": "deny", "match": {"command_regex": "["}}
        )
    rule = validate_rule(
        {"name": "Good", "action": "deny", "match": {"path_glob": "/secret"}}
    )
    assert rule["id"] and rule["source"] == "tenant"


@pytest.mark.parametrize("name", ["console", "admin"])
@pytest.mark.parametrize("location", ["checkout", "packaged", "override"])
def test_static_fallback_and_cache(tmp_path, monkeypatch, name, location):
    from openaidr.server import web

    monkeypatch.setattr(web, "__file__", str(tmp_path / "src/openaidr/server/web.py"))
    monkeypatch.delenv("OPENAIDR_WEB_ROOT", raising=False)
    root = tmp_path / "apps" / name / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("app")
    (root / "assets" / "main.js").write_text("js")
    if location == "packaged":
        script = tmp_path / "scripts/package_web.py"
        script.parent.mkdir()
        shutil.copyfile(Path(__file__).resolve().parents[1] / "scripts/package_web.py", script)
        subprocess.run([sys.executable, str(script)], check=True, capture_output=True)
        shutil.rmtree(tmp_path / "apps")
        package = tmp_path / "site-packages/openaidr"
        package.parent.mkdir()
        (tmp_path / "src/openaidr").rename(package)
        monkeypatch.setattr(web, "__file__", str(package / "server/web.py"))
        root = package / "web" / name / "dist"
    elif location == "override":
        source = root
        root = tmp_path / "custom-web" / name / "dist"
        shutil.copytree(source, root)
        (source / "index.html").write_text("fallback")
        monkeypatch.setenv("OPENAIDR_WEB_ROOT", str(tmp_path / "custom-web"))
    response = web.serve_app(name, "nested/route")
    assert response.path == root / "index.html"
    assert response.headers["cache-control"] == "no-cache"
    assert (
        "immutable" in web.serve_app(name, "assets/main.js").headers["cache-control"]
    )
    assert web.serve_app(name, "../../../etc/passwd").path == root / "index.html"


@pytest.mark.parametrize("services", ["admin", "api,admin", "api"])
def test_platform_admin_page_and_legacy_redirect(tmp_path, monkeypatch, backend, services):
    if "admin" in services and not PLATFORM_AVAILABLE:
        pytest.skip("private platform routes")
    monkeypatch.setenv("OPENAIDR_WEB_ROOT", str(tmp_path))
    for name in ("admin", "console"):
        root = tmp_path / name / "dist"
        (root / "assets").mkdir(parents=True)
        (root / "index.html").write_text(name + " app")
        (root / "assets/main.js").write_text(name + " script")
    cfg = config(services)
    client = TestClient(create_app(cfg, backend), follow_redirects=False)
    for path in ("/platform/admins", "/platform/admins/"):
        result = client.get(path)
        if not cfg.enabled("admin"):
            assert result.status_code == 404
            continue
        assert result.status_code == 200 and result.text == "admin app"
        assert result.headers["cache-control"] == "no-cache"
    if not cfg.enabled("admin"):
        return
    assert client.get("/admin/assets/main.js").text == "admin script"
    for path in ("/admin/admins", "/admin/admins/"):
        result = client.get(path + "?from=mail%2Fnotice")
        assert result.status_code == 307
        assert result.headers["location"] == "/platform/admins?from=mail%2Fnotice"
        assert client.get(result.headers["location"]).text == "admin app"
    assert client.get("/admin/v1/admins").status_code == 401
    if services == "admin":
        assert client.get("/platform/unknown").status_code == 404
        assert client.get("/api/v1/auth/me").status_code == 404
    else:
        assert client.get("/").text == "console app"


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_only_administrators_can_queue_sensor_commands(client, backend, role):
    client.cookies.set(auth.CONSOLE_COOKIE, "session")
    backend.get_session.return_value["user"]["role"] = role
    sensor_id = "01000000-0000-7000-8000-000000000002"
    backend.list_commands.return_value = []
    result = client.post(
        f"/api/v1/sensors/{sensor_id}/commands",
        json={"type": "install_hook", "agent": "all"},
    )
    assert result.status_code == 403
    backend.queue_command.assert_not_called()
    listing = client.get(f"/api/v1/sensors/{sensor_id}/commands")
    assert listing.status_code == 403
    backend.list_commands.assert_not_called()


def test_sensor_commands_validate_type_agent_and_sensor(client, backend):
    client.cookies.set(auth.CONSOLE_COOKIE, "session")
    backend.get_session.return_value["user"]["role"] = "admin"
    sensor_id = "01000000-0000-7000-8000-000000000002"
    path = f"/api/v1/sensors/{sensor_id}/commands"
    for body in (
        {"type": "disable"},
        {"type": "install_hook"},
        {"type": "uninstall_hook", "agent": "gemini"},
        {"type": "refresh_policy", "agent": "claude"},
        {},
    ):
        result = client.post(path, json=body)
        assert result.status_code == 400, (body, result.text)
    backend.queue_command.assert_not_called()
    assert client.post("/api/v1/sensors/not-a-uuid/commands", json={"type": "refresh_policy"}).status_code == 400
    assert client.get(f"{path}?limit=201").status_code == 400
    backend.queue_command.side_effect = store.NotFound("sensor")
    assert client.post(path, json={"type": "refresh_policy"}).status_code == 404
    backend.audit.assert_not_called()


@pytest.mark.parametrize("agent", ["codex", "copilot", "cursor", "antigravity", "opencode"])
def test_administrators_queue_hook_commands_and_see_outcomes(client, backend, agent):
    client.cookies.set(auth.CONSOLE_COOKIE, "session")
    backend.get_session.return_value["user"]["role"] = "admin"
    sensor_id = "01000000-0000-7000-8000-000000000002"
    queued = {
        "id": "01000000-0000-7000-8000-000000000003",
        "type": "install_hook",
        "params": {"agent": agent},
        "status": "pending",
        "message": "",
        "created_at": "2026-10-04T10:00:00+00:00",
        "delivered_at": None,
        "acked_at": None,
    }
    backend.queue_command.return_value = queued["id"]
    backend.get_command.return_value = dict(queued)
    result = client.post(
        f"/api/v1/sensors/{sensor_id}/commands",
        json={"type": "install_hook", "agent": agent},
    )
    assert result.status_code == 202, result.text
    assert result.json() == queued
    backend.queue_command.assert_called_once_with(
        "tenant", sensor_id, "install_hook", {"agent": agent}, ""
    )
    audit = backend.audit.call_args
    assert audit.args[2:4] == ("sensor.command", "sensor") and audit.args[5] == {
        "type": "install_hook",
        "agent": agent,
    }
    backend.queue_command.reset_mock()
    backend.get_command.return_value = {**queued, "type": "refresh_policy", "params": {}}
    assert client.post(f"/api/v1/sensors/{sensor_id}/commands", json={"type": "refresh_policy"}).status_code == 202
    backend.queue_command.assert_called_once_with("tenant", sensor_id, "refresh_policy", {}, "")
    backend.list_commands.return_value = [
        {**queued, "status": "failed", "message": "unknown hook agent", "acked_at": "2026-10-04T10:00:30+00:00"}
    ]
    listing = client.get(f"/api/v1/sensors/{sensor_id}/commands?limit=5")
    assert listing.status_code == 200
    assert listing.json()["items"][0]["message"] == "unknown hook agent"
    backend.list_commands.assert_called_once_with("tenant", sensor_id, 5)
