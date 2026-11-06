"""Support link validation and tenant authorization against PostgreSQL."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from openaidr.server import auth, support
from openaidr.server.httpx import APIError
from test_hook_policy import system as system, browser
from test_store import db as db


URL = "https://app.slack.com/client/T0123456789/C0123456789"
PATH = "settings/support"


@pytest.mark.parametrize("value,expected", [
    ("", ""), ("  \n", ""), (" " + URL + " ", URL),
    (URL + "/?thread_ts=123#thread", URL),
    ("https://acme.slack.com/archives/C0123456789", "https://acme.slack.com/archives/C0123456789"),
    ("https://ACME.slack.com/archives/G0123456789/?x=y", "https://acme.slack.com/archives/G0123456789"),
    ("https://app.slack.com/client/E0123456789/G0123456789", "https://app.slack.com/client/E0123456789/G0123456789"),
    ("https://slack.com/app_redirect?channel=C0123456789&team=T0123456789",
     "https://slack.com/app_redirect?team=T0123456789&channel=C0123456789"),
])
def test_channel_links_are_canonical(value, expected):
    assert support.channel_url(value) == expected


@pytest.mark.parametrize("value", [
    None, [], True, 3, "x" * 2049, "https://slack.com", "slack://channel?team=T123&id=C123",
    "javascript:alert(1)", URL.replace("https:", "http:"),
    URL.replace("app.slack.com", "app.slack.com.evil.test"),
    URL.replace("app.slack.com", "app.slack.com@evil.test"),
    URL.replace("app.slack.com", "user@app.slack.com"),
    URL.replace("app.slack.com", "app.slack.com:443"),
    URL.replace("app.slack.com", "127.0.0.1"),
    URL.replace("T012", "T0\n12"), URL + "\\evil", "https://[bad/client/T123/C123",
    "https://hooks.slack.com/services/T123/B123/SECRET",
    "https://acme.slack.com/archives/C0123456789/p1234567890",
    "https://join.slack.com/t/acme/shared_invite/SECRET",
    "https://slack.com/app_redirect?channel=C123",
    "https://slack.com/app_redirect?channel=C123&team=T123&team=T456",
    "https://slack.com/app_redirect?channel=C123&team=T123&redirect=https://evil.test",
    "https://slack.com/app_redirect?channel=support&team=T123",
])
def test_other_destinations_are_rejected(value):
    with pytest.raises(APIError) as error:
        support.channel_url(value)
    assert error.value.status == 400


def test_tenant_support_permissions_persistence_versions_and_audit(system):
    payload = {"slack_channel_url": URL, "version": 0}
    initial = browser(system, "GET", PATH)
    assert initial.status_code == 200 and initial.headers["cache-control"] == "no-store"
    assert initial.json() == {"slack_channel_url": "", "version": 0, "updated_at": None}
    assert system.client.get("/api/v1/" + PATH).status_code == 401
    assert browser(system, "PUT", PATH, payload, user="viewer").status_code == 403
    headers = {key: value for key, value in system.headers["admin"].items() if key != auth.CSRF_HEADER}
    assert system.client.put("/api/v1/" + PATH, json=payload, headers=headers).status_code == 403
    for invalid in [{**payload, "version": True}, {**payload, "tenant_id": system.tenant["id"]},
                    {**payload, "slack_channel_url": "https://evil.test"}]:
        assert browser(system, "PUT", PATH, invalid).status_code == 400
    saved = browser(system, "PUT", PATH, payload)
    assert saved.status_code == 200 and saved.json()["version"] == 1
    assert saved.json()["slack_channel_url"] == URL and saved.json()["updated_at"]
    analyst = system.db.create_user(system.tenant["id"], "analyst@example.test", "Analyst", "hash", "analyst")
    system.headers["analyst"] = {"Cookie": auth.CONSOLE_COOKIE + "=" + system.db.create_session(analyst["id"], analyst["tenant_id"]), auth.CSRF_HEADER: "1"}
    for role in ("admin", "viewer", "analyst"):
        result = browser(system, "GET", PATH, user=role)
        assert result.json() == saved.json()
        assert result.headers["cache-control"] == "no-store"
    assert browser(system, "PUT", PATH, {**payload, "version": 1}, user="analyst").status_code == 403
    assert browser(system, "GET", PATH, user="foreign").json() == initial.json()
    assert browser(system, "PUT", PATH, payload).status_code == 409
    assert browser(system, "PUT", PATH, {"slack_channel_url": "", "version": 1}).json()["version"] == 2
    assert browser(system, "GET", PATH, user="viewer").json()["slack_channel_url"] == ""
    rows = system.db.many("SELECT details FROM audit_log WHERE action='support.configure' ORDER BY (details->>'version')::int")
    assert [row["details"] for row in rows] == [
        {"before": "", "slack_channel_url": URL, "version": 1},
        {"before": URL, "slack_channel_url": "", "version": 2},
    ]


def test_concurrent_first_save_has_one_winner(system):
    def save(url):
        try:
            support.save(system.db, system.tenant["id"], {"slack_channel_url": url, "version": 0}, {})
            return 200
        except APIError as error:
            return error.status
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(save, [URL, URL.replace("C012", "C999")])) == [200, 409]
    assert support.read(system.db, system.tenant["id"])["version"] == 1
    assert system.db.scalar("SELECT count(*) FROM audit_log WHERE action='support.configure'") == 1
