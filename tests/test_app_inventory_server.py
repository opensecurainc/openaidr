"""Real PostgreSQL inventory boundaries and conservative source reconciliation."""

import json
import os
from pathlib import Path
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.conninfo import make_conninfo

from openaidr.server.app import create_app
from openaidr.server.app_inventory import encode_cursor, ingest_snapshot
from openaidr.server.component_inventory import ingest_snapshot as ingest_components
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server.config import Config
from openaidr.server.store import Store

INGEST = "/ingest/v1/inventory/applications"
APPS = "/api/v1/inventory/applications"
AI_APPS = "/api/v1/inventory/ai-applications"
COVERAGE = "/api/v1/inventory/sources"
CATEGORIES = "/api/v1/inventory/categories"
SNAPSHOTS = "/ingest/v1/inventory/snapshots"
COMPONENTS = "/api/v1/inventory/components"
ROOTS = "/api/v1/inventory/roots"
RELATIONSHIPS = "/api/v1/inventory/relationships"


@pytest.fixture
def inventory():
    url = os.environ.get("OPENAIDR_TEST_DATABASE_URL")
    if not url:
        pytest.skip("OPENAIDR_TEST_DATABASE_URL is not configured")
    schema = "app_inventory_" + uuid4().hex
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
    st = Store(make_conninfo(url, options=f"-c search_path={schema}"))
    st.migrate()
    identities = []
    for slug in ("first", "other"):
        tenant = st.bootstrap_tenant(slug, slug)
        sensor, token, _ = st.enroll_sensor(
            dict(enrollment_token=tenant["enrollment_token"], hostname=slug, os="linux")
        )
        user = st.create_user(
            sensor["tenant_id"], slug + "@example.com", slug, "unused", "viewer"
        )
        identities.append(
            (sensor, token, st.create_session(user["id"], sensor["tenant_id"]))
        )
    cfg = Config(database_url=st.url)
    cfg.set_services("ingest,api")
    client = TestClient(create_app(cfg, st))
    client.cookies.set(CONSOLE_COOKIE, identities[0][2])
    try:
        yield st, cfg, client, identities
    finally:
        client.close()
        st.close()
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(f"DROP SCHEMA {schema} CASCADE")


def app(identifier="one", source="linux-dpkg", **overrides):
    return dict(
        source=source,
        identifier=identifier,
        name=identifier,
        version="1",
        path="/opt/" + identifier,
        publisher="vendor",
        architecture="amd64",
        kind="package",
        scope="system",
        **overrides,
    )


def snapshot(apps=None, status="ok", offset=0, source="linux-dpkg"):
    return dict(
        schema_version=1,
        collected_at=(
            datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=offset)
        ).isoformat(),
        platform="linux",
        sources=[dict(source=source, status=status, message="scan")],
        applications=apps or [],
    )


def post(client, token, data):
    return client.post(INGEST, json=data, headers={"Authorization": "Bearer " + token})


def test_reconciliation_stale_replay_and_version_identity(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    initial = snapshot([app(), app("two"), app()])
    assert post(client, token, initial).status_code == 200
    rows = client.get(APPS).json()["items"]
    assert len(rows) == 2
    original_id = next(r["id"] for r in rows if r["identifier"] == "one")
    changed = app()
    changed["version"] = "2"
    assert (
        post(client, token, snapshot([changed], status="partial", offset=1)).status_code
        == 200
    )
    rows = client.get(APPS).json()["items"]
    assert len(rows) == 2
    assert next(r for r in rows if r["identifier"] == "one")["id"] == original_id
    assert rows[0]["version"] == "2"
    for offset, status in ((2, "error"), (3, "unavailable")):
        assert (
            post(client, token, snapshot(status=status, offset=offset)).status_code
            == 200
        )
        assert len(client.get(APPS).json()["items"]) == 2
    source = client.get(COVERAGE).json()["items"][0]
    assert source["application_count"] == 2
    assert source["last_success_at"] == "2025-01-01T00:00:00Z"
    assert source["status"] == "unavailable"
    assert post(client, token, initial).json()["sources_updated"] == 0
    assert post(client, token, snapshot(offset=3)).json()["sources_updated"] == 0
    assert (
        post(
            client,
            token,
            snapshot(
                [app("desktop", source="linux-desktop")],
                source="linux-desktop",
                offset=4,
            ),
        ).status_code
        == 200
    )
    assert post(client, token, snapshot(offset=5)).status_code == 200
    assert [r["source"] for r in client.get(APPS).json()["items"]] == ["linux-desktop"]
    assert len(client.get(COVERAGE).json()["items"]) == 2


def test_auth_tenant_identity_and_deleted_sensor(inventory):
    st, cfg, client, identities = inventory
    sensor, token, session = identities[0]
    other, other_token, other_session = identities[1]
    assert client.post(INGEST, json=snapshot()).status_code == 401
    assert (
        post(client, token, {**snapshot(), "sensor_id": other["id"]}).status_code == 403
    )
    data = {**snapshot([app()]), "tenant_id": other["tenant_id"]}
    assert post(client, token, data).status_code == 200
    assert post(client, other_token, snapshot([app("foreign")])).status_code == 200
    assert [r["name"] for r in client.get(APPS).json()["items"]] == ["one"]
    assert client.get(APPS, params={"sensor_id": other["id"]}).json()["items"] == []
    assert client.get(COVERAGE, params={"sensor_id": other["id"]}).json()["items"] == []
    client.cookies.clear()
    assert client.get(APPS).status_code == 401
    client.cookies.set(CONSOLE_COOKIE, other_session)
    assert [r["name"] for r in client.get(APPS).json()["items"]] == ["foreign"]
    cfg.tenant_id = sensor["tenant_id"]
    assert post(client, other_token, snapshot()).status_code == 403
    assert client.get(APPS).status_code == 403
    client.cookies.clear()
    client.cookies.set(CONSOLE_COOKIE, session)
    st.update_sensor(sensor["tenant_id"], sensor["id"], disabled=True)
    assert post(client, token, snapshot(offset=9)).status_code == 403
    st.delete_sensor(sensor["tenant_id"], sensor["id"])
    assert client.get(APPS).json()["items"] == []
    assert client.get(COVERAGE).json()["items"] == []
    assert post(client, token, snapshot()).status_code == 401


def test_validation_is_atomic_and_limits(inventory):
    st, cfg, client, identities = inventory
    token = identities[0][1]
    base = snapshot([app()])
    assert post(client, token, base).status_code == 200
    bad = []
    for field, value in (
        ("schema_version", True),
        ("schema_version", 2),
        ("platform", "freebsd"),
        ("platform", 5),
        ("collected_at", "bad"),
        ("collected_at", "2025-01-01"),
        ("collected_at", "2025-01-01T00:00:00+01:00"),
        (
            "collected_at",
            (datetime.now(timezone.utc) + timedelta(minutes=6)).isoformat(),
        ),
        ("sources", [{}] * 65),
        ("applications", [app()] * 10001),
    ):
        bad.append({**snapshot(offset=20), field: value})
    for field, value in (
        ("name", 3),
        ("path", "x" * 8193),
        ("identifier", ""),
        ("scope", "all"),
        ("kind", "tool"),
        ("name", "nul\x00"),
    ):
        row = app()
        row[field] = value
        bad.append(snapshot([row], offset=20))
    bad.extend(
        [
            snapshot([app()], status="error", offset=20),
            snapshot([app(source="linux-snap")], offset=20),
        ]
    )
    duplicate = snapshot(offset=20)
    duplicate["sources"] *= 2
    bad.append(duplicate)
    conflicting = app()
    conflicting["version"] = "different"
    bad.append(snapshot([app(), conflicting], offset=20))
    for data in bad:
        result = post(client, token, data)
        assert result.status_code == 400, result.text
    assert client.get(APPS).json()["items"][0]["version"] == "1"
    assert (
        client.get(COVERAGE).json()["items"][0]["collected_at"]
        == "2025-01-01T00:00:00Z"
    )
    assert (
        client.post(
            INGEST,
            content=b" " * ((8 << 20) + 1),
            headers={"Authorization": "Bearer " + token},
        ).status_code
        == 413
    )
    assert client.get(APPS, params={"sensor_id": "invalid"}).status_code == 400
    assert client.get(APPS, params={"source": "unknown"}).status_code == 400
    assert client.get(APPS, params={"kind": "unknown"}).status_code == 400
    assert client.get(APPS, params={"q": "a" * 1025}).status_code == 400
    assert client.get(APPS, params={"cursor": "invalid"}).status_code == 400
    # PostgreSQL text cannot hold NUL or lone surrogates: a crafted cursor is a 400.
    nul = encode_cursor("\x00", "00000000-0000-0000-0000-000000000000")
    assert client.get(APPS, params={"cursor": nul}).status_code == 400
    surrogate = encode_cursor("\ud800", "00000000-0000-0000-0000-000000000000")
    assert client.get(APPS, params={"cursor": surrogate}).status_code == 400
    numeric = encode_cursor("a", 10**31)  # valid_uuid accepts it once stringified
    assert client.get(APPS, params={"cursor": numeric}).status_code == 400
    urn = encode_cursor("a", "urn:uuid:00000000-0000-0000-0000-000000000000")
    assert client.get(APPS, params={"cursor": urn}).status_code == 200


def test_literal_search_keyset_and_response_shape(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    assert (
        post(
            client, token, snapshot([app("one%_"), app("other"), app("THREE")])
        ).status_code
        == 200
    )
    first = client.get(APPS, params={"limit": 1}).json()
    second = client.get(
        APPS, params={"limit": 1, "cursor": first["next_cursor"]}
    ).json()
    third = client.get(
        APPS, params={"limit": 1, "cursor": second["next_cursor"]}
    ).json()
    assert len({p["items"][0]["id"] for p in (first, second, third)}) == 3
    assert third["next_cursor"] == ""
    assert client.get(APPS, params={"q": "%_"}).json()["items"][0]["name"] == "one%_"
    assert len(client.get(APPS, params={"q": "%_"}).json()["items"]) == 1
    assert client.get(APPS, params={"q": "three"}).json()["items"][0]["name"] == "THREE"
    assert client.get(APPS, params={"kind": "application"}).json()["items"] == []
    row = first["items"][0]
    assert set(row) == {
        "id",
        "sensor_id",
        "hostname",
        "os",
        "source",
        "identifier",
        "name",
        "version",
        "path",
        "publisher",
        "architecture",
        "kind",
        "scope",
        "last_seen_at",
        "category",
    }
    assert row["sensor_id"] == sensor["id"]
    # Pages follow the name, case-insensitively.
    assert [p["items"][0]["name"] for p in (first, second, third)] == [
        "one%_",
        "other",
        "THREE",
    ]
    assert set(client.get(COVERAGE).json()["items"][0]) == {
        "sensor_id",
        "hostname",
        "os",
        "source",
        "status",
        "message",
        "collected_at",
        "last_success_at",
        "application_count",
    }


def test_concurrent_snapshots_keep_newest_source(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    # Completion order cannot make an older successful scan erase newer data.
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(
                lambda n: ingest_snapshot(
                    st, sensor, snapshot([app(str(n))], offset=n)
                ),
                [8, 2, 9, 3],
            )
        )
    assert all(r["accepted"] for r in results)
    rows = client.get(APPS).json()["items"]
    assert [r["name"] for r in rows] == ["9"]
    assert (
        client.get(COVERAGE).json()["items"][0]["collected_at"]
        == "2025-01-01T00:00:09Z"
    )


@pytest.mark.parametrize("source,platform", [("macos-spotlight", "darwin"), ("windows-registry", "windows")])
def test_workbuddy_installations_share_identity_without_claiming_activity(inventory, source, platform):
    _, _, client, identities = inventory
    _, token, _ = identities[0]
    records = [
        app("com.workbuddy.workbuddy-ai", source) | {"name": "Renamed installation"},
        app("domestic-install", source) | {"name": "WorkBuddy"},
        app("international-install", source) | {"name": "WorkBuddy AI"},
        app("codebuddy-install", source) | {"name": "CodeBuddy"},
        app("similar-name", source) | {"name": "WorkBuddy Notes"},
    ]
    response = post(client, token, snapshot(records, source=source) | {"platform": platform})
    assert response.status_code == 200, response.text
    apps = {r["name"]: r["category"] for r in client.get(APPS).json()["items"]}
    assert apps["WorkBuddy"] == apps["WorkBuddy AI"] == apps["Renamed installation"] == "ai"
    assert apps["CodeBuddy"] != "ai" and apps["WorkBuddy Notes"] != "ai"
    (product,) = client.get(AI_APPS).json()["items"]
    assert product["id"] == "workbuddy" and product["name"] == "WorkBuddy"
    assert product["activity_events"] == 0 and product["observed_users"] is None
    assert product["usage_status"] == "unavailable"


def test_categories_mark_ai_and_system_software(inventory):
    st, cfg, client, identities = inventory
    _, token, _ = identities[0]

    def mac(identifier, name, path):
        row = app(identifier, "macos-spotlight")
        return row | dict(name=name, path=path, kind="application", scope="user")

    apps = [
        mac("com.anthropic.claudefordesktop", "Claude", "/Applications/Claude.app"),
        mac(
            "COM.ANTHROPIC.CLAUDE-CODE-URL-HANDLER",
            "Claude Code URL Handler",
            "/Applications/Claude Code URL Handler.app",
        ),
        # AI wins over location: Claude Code installs under ~/Library.
        mac(
            "com.anthropic.claude-code",
            "Claude Code",
            "/Users/a/Library/Application Support/Claude/claude-code/2.1/claude.app",
        ),
        mac("org.example.ollama-themes", "OLLAMA", "/Applications/Ollama Themes.app"),
        mac("com.example.editor", "Editor", "/Applications/Editor.app"),
        # A Library folder deeper than the home directory is not ~/Library.
        mac("com.example.tool", "Tool", "/Users/a/Projects/Library/Tool.app"),
        mac(
            "com.example.claude-notes", "Claude Notes", "/Applications/Claude Notes.app"
        ),
        mac("com.apple.finder", "Finder", "/System/Library/CoreServices/Finder.app"),
        mac(
            "com.example.helper",
            "Helper",
            "/Applications/Editor.app/Contents/Helper.app",
        ),
        mac(
            "com.google.Chrome.app.abc",
            "Default abc",
            "/Users/a/Applications/Chrome Apps.localized/Default abc.app",
        ),
    ]
    data = snapshot(apps, source="macos-spotlight") | {"platform": "darwin"}
    assert post(client, token, data).status_code == 200
    categories = {
        row["name"]: row["category"]
        for row in client.get(APPS, params={"limit": 50}).json()["items"]
    }
    assert categories == {
        "Claude": "ai",
        "Claude Code": "ai",
        "Claude Code URL Handler": "ai",
        "OLLAMA": "ai",
        "Editor": "user",
        "Tool": "user",
        "Claude Notes": "user",
        "Finder": "system",
        "Helper": "system",
        "Default abc": "system",
    }
    ai = client.get(APPS, params={"category": "ai"}).json()["items"]
    assert [row["name"] for row in ai] == [
        "Claude",
        "Claude Code",
        "Claude Code URL Handler",
        "OLLAMA",
    ]
    assert client.get(CATEGORIES).json() == {
        "categories": {"ai": 4, "user": 3, "system": 3}
    }
    assert client.get(CATEGORIES, params={"q": "claude"}).json() == {
        "categories": {"ai": 3, "user": 1, "system": 0}
    }
    # Hide known helpers before counting and paging. Claude Code itself stays.
    params = {"category": "ai", "include_helpers": "false", "limit": 1}
    visible = []
    while True:
        result = client.get(APPS, params=params).json()
        visible.extend(row["name"] for row in result["items"])
        if not result["next_cursor"]:
            break
        params["cursor"] = result["next_cursor"]
    assert visible == ["Claude", "Claude Code", "OLLAMA"]
    assert client.get(CATEGORIES, params={"include_helpers": "false"}).json() == {
        "categories": {"ai": 3, "user": 3, "system": 3}
    }
    assert (
        client.get(APPS, params={"category": "ai", "include_helpers": "true"}).json()[
            "items"
        ]
        == ai
    )
    for url in (APPS, CATEGORIES):
        assert client.get(url, params={"include_helpers": "maybe"}).status_code == 400
    assert client.get(APPS, params={"category": "games"}).status_code == 400
    urn = "urn:uuid:" + identities[0][0]["id"]
    for url in (APPS, CATEGORIES):
        assert client.get(url, params={"sensor_id": urn}).status_code == 200
    # Another tenant's records never appear in its counts.
    client.cookies.set(CONSOLE_COOKIE, identities[1][2])
    assert client.get(CATEGORIES).json() == {
        "categories": {"ai": 0, "user": 0, "system": 0}
    }


def test_long_multibyte_names_index_and_page(inventory):
    st, cfg, client, identities = inventory
    _, token, _ = identities[0]
    # 1,024 varied four-byte characters (incompressible) exceed a B-tree entry
    # if the full name is the key; two names sharing the bounded sort key still
    # page without repeats.
    long = "".join(chr(0x20000 + i * 7919 % 40000) for i in range(1023))
    apps = [app("a") | {"name": long + "a"}, app("b") | {"name": long + "b"}]
    assert post(client, token, snapshot(apps)).status_code == 200
    first = client.get(APPS, params={"limit": 1}).json()
    second = client.get(
        APPS, params={"limit": 1, "cursor": first["next_cursor"]}
    ).json()
    assert {first["items"][0]["name"], second["items"][0]["name"]} == {
        long + "a",
        long + "b",
    }
    assert second["next_cursor"] == ""


def component(key="example", **changes):
    return (
        dict(
            key=key,
            identifier=key,
            name=key,
            kind="package",
            ecosystem="pypi",
            evidence="installed",
            version="1.0",
            path="/env/" + key,
        )
        | changes
    )


def root(path="/env/one", **changes):
    return (
        dict(
            source="osquery-python-packages",
            root=path,
            scope="user",
            user="alice",
            environment=path,
            status="ok",
            components=[component()],
            relationships=[],
        )
        | changes
    )


def component_snapshot(roots, offset=0):
    return dict(
        schema_version=1,
        platform="darwin",
        collected_at=snapshot(offset=offset)["collected_at"],
        roots=roots,
    )


def send_components(client, token, roots, offset=0):
    return client.post(
        SNAPSHOTS,
        json=component_snapshot(roots, offset),
        headers={"Authorization": "Bearer " + token},
    )


def test_osquery_apps_replace_legacy_inventory_and_survive_scan_failures(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    legacy = snapshot(
        [app("com.anthropic.claude", "macos-spotlight") | {"name": "Claude"}],
        source="macos-spotlight",
    ) | {"platform": "darwin"}
    assert post(client, token, legacy).status_code == 200
    discovery = root("discovery", source="osquery-apps", components=[])
    assert send_components(client, token, [discovery], 1).status_code == 200
    assert client.get(APPS).json()["items"][0]["source"] == "macos-spotlight"
    apps = root(
        "/Applications",
        source="osquery-apps",
        components=[],
        status="error",
        message="osquery unavailable",
    )
    assert send_components(client, token, [apps], 1).status_code == 200
    assert client.get(APPS).json()["items"][0]["source"] == "macos-spotlight"
    scans = client.get(COVERAGE).json()["items"]
    assert {row["source"]: row["status"] for row in scans} == {
        "macos-spotlight": "ok",
        "osquery-apps": "error",
    }

    claude = component(
        "Claude.app",
        identifier="com.anthropic.claude",
        name="Claude",
        path="/Applications/Claude.app",
        kind="application",
        ecosystem="",
    )
    # A partial scan with usable records can replace the old collector.
    apps.update(status="partial", components=[claude])
    assert send_components(client, token, [apps], 2).status_code == 200
    first = client.get(APPS).json()["items"]
    assert len(first) == 1 and first[0]["source"] == "osquery-apps"
    assert first[0]["category"] == "ai"
    assert client.get(CATEGORIES).json()["categories"] == {
        "ai": 1,
        "user": 0,
        "system": 0,
    }
    apps.update(status="ok", message="")
    assert send_components(client, token, [apps], 3).status_code == 200
    scans = client.get(COVERAGE).json()["items"]
    assert len(scans) == 1 and scans[0]["source"] == "osquery-apps"
    assert scans[0]["application_count"] == 1
    assert scans[0]["last_success_at"]
    last_seen = client.get(APPS).json()["items"][0]["last_seen_at"]
    for offset, status in enumerate(("partial", "error", "unavailable"), 4):
        apps.update(status=status, components=[])
        assert send_components(client, token, [apps], offset).status_code == 200
        retained = client.get(APPS).json()["items"]
        assert len(retained) == 1
        assert retained[0]["id"] == first[0]["id"]
        assert retained[0]["last_seen_at"] == last_seen
        assert client.get(COVERAGE).json()["items"][0]["status"] == status

    # A complete empty root clears apps without resurrecting old Spotlight rows.
    apps.update(status="ok")
    assert send_components(client, token, [apps], 7).status_code == 200
    assert client.get(APPS).json()["items"] == []
    assert client.get(COVERAGE).json()["items"][0]["application_count"] == 0
    assert client.get(AI_APPS).json()["items"] == []
    assert client.get(CATEGORIES).json()["categories"] == {
        "ai": 0,
        "user": 0,
        "system": 0,
    }

    # Rolling the sensor back to a newer legacy scan selects it without duplicates.
    legacy["collected_at"] = snapshot(offset=8)["collected_at"]
    legacy["sources"][0]["status"] = "partial"
    assert post(client, token, legacy).status_code == 200
    assert client.get(APPS).json()["items"][0]["source"] == "macos-spotlight"
    legacy["collected_at"] = snapshot(offset=9)["collected_at"]
    legacy["sources"][0]["status"] = "error"
    legacy["applications"] = []
    assert post(client, token, legacy).status_code == 200
    assert client.get(APPS).json()["items"][0]["source"] == "macos-spotlight"
    apps.update(components=[claude])
    assert send_components(client, token, [apps], 10).status_code == 200
    assert client.get(APPS).json()["items"][0]["source"] == "osquery-apps"
    assert post(client, token, legacy).json()["sources_updated"] == 0
    assert client.get(APPS).json()["items"][0]["source"] == "osquery-apps"


def test_osquery_app_filters_counts_paging_and_tenant_isolation(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    apps = root(
        "/Applications",
        source="osquery-apps",
        components=[
            component(
                name,
                name=name,
                identifier=identifier,
                path=path,
                kind="application",
                ecosystem="",
            )
            for name, identifier, path in (
                ("Claude Code", "com.anthropic.code", "/Users/a/Library/Claude.app"),
                ("Editor", "example.editor", "/Applications/Editor.app"),
                ("Finder", "com.apple.finder", "/System/Library/Finder.app"),
            )
        ],
    )
    missing = root(
        "/Volumes/Missing", source="osquery-apps", status="unavailable", components=[]
    )
    assert send_components(client, token, [apps, missing, root()], 1).status_code == 200
    # Unmigrated devices remain visible alongside osquery devices.
    _, other_token, _ = st.enroll_sensor(
        dict(
            enrollment_token=st.create_enrollment_token(sensor["tenant_id"])["token"],
            hostname="legacy",
            os="darwin",
        )
    )
    assert post(client, other_token, snapshot([app("Legacy")])).status_code == 200
    assert client.get(CATEGORIES).json()["categories"] == {
        "ai": 1,
        "user": 1,
        "system": 2,
    }
    params = {"source": "osquery-apps", "sensor_id": sensor["id"], "limit": 1}
    names, cursor = [], ""
    for _ in range(3):
        response = client.get(APPS, params=params | {"cursor": cursor})
        assert response.status_code == 200
        page = response.json()
        assert len(page["items"]) == 1
        names.append(page["items"][0]["name"])
        cursor = page["next_cursor"]
    assert names == ["Claude Code", "Editor", "Finder"] and not cursor
    assert (
        client.get(
            APPS, params={"source": "osquery-apps", "category": "user", "q": "Editor"}
        ).json()["items"][0]["name"]
        == "Editor"
    )
    assert client.get(CATEGORIES, params=params | {"q": "Claude"}).json() == {
        "categories": {"ai": 1, "user": 0, "system": 0}
    }
    assert client.get(APPS, params={"q": "%"}).json()["items"] == []
    assert (
        client.get(APPS, params={"kind": "package"}).json()["items"][0]["name"]
        == "Legacy"
    )
    scans = client.get(COVERAGE, params={"sensor_id": sensor["id"]}).json()["items"]
    assert len(scans) == 1
    assert scans[0]["application_count"] == 3
    assert scans[0]["status"] == "partial" and scans[0]["last_success_at"] is None

    client.cookies.set(CONSOLE_COOKIE, identities[1][2])
    for endpoint in (APPS, COVERAGE):
        assert (
            client.get(endpoint, params={"sensor_id": sensor["id"]}).json()["items"]
            == []
        )
    assert client.get(CATEGORIES, params=params).json()["categories"] == {
        "ai": 0,
        "user": 0,
        "system": 0,
    }
    st.delete_sensor(sensor["tenant_id"], sensor["id"])
    client.cookies.set(CONSOLE_COOKIE, identities[0][2])
    for endpoint in (APPS, COVERAGE):
        assert (
            client.get(endpoint, params={"sensor_id": sensor["id"]}).json()["items"]
            == []
        )


def relationship(source, target, **changes):
    return {
        "from": dict(source=source["source"], root=source["root"], key="example"),
        "to": dict(source=target["source"], root=target["root"], key="example"),
        "kind": "depends_on",
        "evidence": "declared",
        "path": "/project/requirements.txt",
    } | changes


def test_mcp_configuration_collection_reconciles_through_api(
    inventory, tmp_path, monkeypatch
):
    from openaidr.sensor import component_inventory as collector, mcp_inventory

    _, _, client, identities = inventory
    token = identities[0][1]
    config = tmp_path.resolve() / "mcp.json"
    other = tmp_path.resolve() / "other.json"
    config.write_text(
        '{"mcpServers":{"docs":{"env":{"TOKEN":"private-token"}},"removed":{}}}'
    )
    other.write_text('{"mcpServers":{"docs":{}}}')
    monkeypatch.setattr(collector.sys, "platform", "darwin")

    def rows(source, paths, **kw):
        context = {
            "constraints": [
                {"name": "path", "list": [{"op": 2, "expr": p} for p in paths]}
            ]
        }
        return [{**r, "directory": r["path"]} for r in mcp_inventory.mcp_rows(context)]

    monkeypatch.setattr(collector, "inventory_rows", rows)
    options = collector.settings(
        {
            "inventory": {
                "components": {
                    "include_default_roots": False,
                    "mcp_configs": [str(config), str(other)],
                }
            }
        }
    )

    def upload(offset):
        collected = collector.collect_inventory(options)
        collected["collected_at"] = component_snapshot([], offset)["collected_at"]
        assert "private-token" not in json.dumps(collected)
        result = client.post(
            SNAPSHOTS, json=collected, headers={"Authorization": "Bearer " + token}
        )
        assert result.status_code == 200, result.text
        return client.get(COMPONENTS).json()["items"]

    first = upload(0)
    assert len(first) == 3 and len({r["id"] for r in first}) == 3
    original = next(
        r for r in first if r["name"] == "docs" and r["path"] == str(config)
    )
    config.write_text(
        '{"mcpServers":{"docs":{"url":"https://example.com/private-token"}}}'
    )
    second = upload(1)
    assert len(second) == 2
    assert next(r for r in second if r["path"] == str(config))["id"] == original["id"]
    config.write_text('{"mcpServers":{"docs":false}}')
    other.unlink()
    assert len(upload(2)) == 2
    coverage = client.get(ROOTS).json()["items"]
    assert {r["status"] for r in coverage} == {"partial", "unavailable"}
    config.write_text('{"mcpServers":{}}')
    last = upload(3)
    assert len(last) == 1 and last[0]["path"] == str(other)


def test_plugin_manifest_collection_reconciles_through_api(
    inventory, tmp_path, monkeypatch
):
    from openaidr.sensor import (
        component_inventory as collector,
        plugin_inventory,
        skill_inventory,
    )

    _, _, client, identities = inventory
    token = identities[0][1]
    cache, other = tmp_path.resolve() / "cache", tmp_path.resolve() / "other"
    manifests = [
        cache / "one/.claude-plugin/plugin.json",
        cache / "two/.codex-plugin/plugin.json",
        other / ".cursor-plugin/plugin.json",
    ]
    for path in manifests:
        path.parent.mkdir(parents=True)
        path.write_text(
            json.dumps(
                {
                    "name": "example",
                    "version": "1.0",
                    "skills": "./skills",
                    "hooks": {"token": "private-token"},
                }
            )
        )
    skill = cache / "one/skills/review/SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: review\n---\nprivate-token\n")
    monkeypatch.setattr(collector.sys, "platform", "darwin")

    def rows(source, paths, **kw):
        context = {
            "constraints": [
                {"name": "directory", "list": [{"op": 2, "expr": p} for p in paths]}
            ]
        }
        collect = (
            skill_inventory.skill_rows
            if source == "openaidr-skills"
            else plugin_inventory.plugin_rows
        )
        return [{**r, "identifier": r["name"]} for r in collect(context)]

    monkeypatch.setattr(collector, "inventory_rows", rows)
    options = collector.settings(
        {
            "inventory": {
                "components": {
                    "include_default_roots": False,
                    "plugin_roots": list(map(str, [cache, other])),
                }
            }
        }
    )

    previous = []

    def upload(offset):
        nonlocal previous
        collected = collector.collect_inventory(options, previous)
        previous = collected["roots"]
        collected["collected_at"] = component_snapshot([], offset)["collected_at"]
        assert "private-token" not in json.dumps(collected)
        response = client.post(
            SNAPSHOTS, json=collected, headers={"Authorization": "Bearer " + token}
        )
        assert response.status_code == 200, response.text
        return client.get(COMPONENTS).json()["items"]

    first = upload(0)
    assert len(first) == 4 and len({r["id"] for r in first}) == 4
    assert {r["evidence"] for r in first} == {"declared", "installed"}
    original = next(r for r in first if r["path"] == str(manifests[0]))
    (link,) = client.get(RELATIONSHIPS, params={"component_id": original["id"]}).json()[
        "items"
    ]
    assert link["kind"] == "provides" and link["evidence"] == "declared"
    assert link["path"] == str(manifests[0])
    assert link["from_component"]["name"] == "example"
    assert link["to_component"]["name"] == "review"
    assert link["to_component"]["path"] == str(skill)
    assert client.get(
        RELATIONSHIPS, params={"component_id": link["to_component_id"]}
    ).json()["items"] == [link]
    manifests[0].write_text('{"name":"example","version":"2.0","skills":"./skills"}')
    manifests[1].unlink()
    second = upload(1)
    assert len(second) == 3
    updated = next(r for r in second if r["path"] == str(manifests[0]))
    assert updated["id"] == original["id"] and updated["version"] == "2.0"
    assert client.get(RELATIONSHIPS).json()["items"][0]["id"] == link["id"]
    skill.write_text("---\nname: [broken\n---\n")
    shutil.rmtree(other)
    assert len(upload(2)) == 3
    assert {r["status"] for r in client.get(ROOTS).json()["items"]} == {
        "partial",
        "unavailable",
    }
    (retained,) = client.get(RELATIONSHIPS).json()["items"]
    assert (
        retained["id"] == link["id"]
        and retained["last_seen_at"] == "2025-01-01T00:00:01Z"
    )
    assert (
        retained["root_status"] == retained["to_component"]["root_status"] == "partial"
    )
    manifests[0].write_text('{"name":false}')
    shutil.rmtree(skill.parent.parent)
    assert len(upload(3)) == 3
    assert (
        client.get(RELATIONSHIPS).json()["items"][0]["to_component"]["root_status"]
        == "unavailable"
    )
    # A complete empty skill location removes the skill and its incident link.
    manifests[0].write_text('{"name":"example","skills":"./skills"}')
    skill.parent.parent.mkdir()
    assert len(upload(4)) == 2
    assert client.get(RELATIONSHIPS).json()["items"] == []
    skill.parent.mkdir()
    skill.write_text("---\nname: renamed\n---\n")
    assert len(upload(5)) == 3
    assert client.get(RELATIONSHIPS).json()["items"][0]["id"] == link["id"]
    # Withdrawing a declaration removes its link while the known skill stays.
    manifests[0].write_text('{"name":"example"}')
    assert len(upload(6)) == 3
    assert client.get(RELATIONSHIPS).json()["items"] == []
    manifests[0].unlink()
    last = upload(7)
    assert {r["path"] for r in last} == {str(manifests[2]), str(skill)}


def test_component_roots_reconcile_independently_with_stable_ids(inventory):
    st, cfg, client, identities = inventory
    token = identities[0][1]
    first, second = root(), root("/env/two")
    first["components"].append(component("another"))
    first["relationships"] = [relationship(first, second)]
    assert send_components(client, token, [first, second]).json()["roots_updated"] == 2
    before = {
        row["key"]: row
        for row in client.get(COMPONENTS, params={"root": first["root"]}).json()[
            "items"
        ]
    }
    assert len(client.get(COMPONENTS).json()["items"]) == 3
    assert len(client.get(RELATIONSHIPS).json()["items"]) == 1
    changed = root(status="partial", components=[component(version="2.0")])
    assert send_components(client, token, [changed], 1).status_code == 200
    rows = {
        row["key"]: row
        for row in client.get(COMPONENTS, params={"root": first["root"]}).json()[
            "items"
        ]
    }
    assert rows["example"]["id"] == before["example"]["id"]
    assert rows["example"]["version"] == "2.0"
    assert rows["another"]["last_seen_at"] == before["another"]["last_seen_at"]
    assert rows["example"]["root_collected_at"] == rows["example"]["last_seen_at"]
    assert rows["another"]["root_collected_at"] == rows["example"]["root_collected_at"]
    assert rows["another"]["last_seen_at"] < rows["another"]["root_collected_at"]
    for offset, status in ((2, "error"), (3, "unavailable")):
        assert (
            send_components(
                client, token, [root(status=status, components=[])], offset
            ).status_code
            == 200
        )
        assert len(client.get(COMPONENTS).json()["items"]) == 3
        assert len(client.get(RELATIONSHIPS).json()["items"]) == 1
    coverage = client.get(ROOTS, params={"root": first["root"]}).json()["items"][0]
    assert coverage["status"] == "unavailable" and coverage["component_count"] == 2
    assert coverage["relationship_count"] == 1
    assert coverage["last_success_at"] == "2025-01-01T00:00:00Z"
    assert send_components(client, token, [first], 0).json()["roots_updated"] == 0
    assert (
        send_components(client, token, [root(components=[])], 3).json()["roots_updated"]
        == 0
    )
    # A fresh root in a mixed replay still applies independently.
    assert (
        send_components(
            client, token, [root(components=[]), root("/env/three")], 2
        ).json()["roots_updated"]
        == 1
    )
    assert send_components(client, token, [root(components=[])], 4).status_code == 200
    assert {row["root"] for row in client.get(COMPONENTS).json()["items"]} == {
        "/env/two",
        "/env/three",
    }
    assert client.get(RELATIONSHIPS).json()["items"] == []


def test_component_relationship_validation_is_atomic_and_sensor_scoped(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    other, other_token, _ = identities[1]
    first, second = root(), root("/env/two")
    assert send_components(client, other_token, [second]).status_code == 200
    first["relationships"] = [relationship(first, second)]
    # Another tenant's component cannot satisfy a reference.
    assert send_components(client, token, [first]).status_code == 400
    assert client.get(COMPONENTS).json()["items"] == []
    assert client.get(ROOTS).json()["items"] == []
    # Neither can another sensor in the same tenant.
    enrollment = st.create_enrollment_token(sensor["tenant_id"], "second", 0, 0)
    sibling, sibling_token, _ = st.enroll_sensor(
        dict(enrollment_token=enrollment["token"], hostname="sibling", os="darwin")
    )
    assert send_components(client, sibling_token, [second]).status_code == 200
    assert send_components(client, token, [first]).status_code == 400
    # Endpoints can be supplied later in the same upload or already stored.
    assert send_components(client, token, [first, second]).status_code == 200
    assert send_components(client, token, [first], 1).status_code == 200
    link = client.get(RELATIONSHIPS).json()["items"][0]
    assert link["from_component"]["id"] == link["from_component_id"]
    assert link["to_component"]["id"] == link["to_component_id"]
    assert link["from_component"]["name"] == first["components"][0]["name"]
    assert (
        client.get(RELATIONSHIPS, params={"sensor_id": other["id"]}).json()["items"]
        == []
    )
    assert (
        client.get(COMPONENTS, params={"component_id": link["to_component_id"]}).json()[
            "items"
        ][0]["sensor_id"]
        == sensor["id"]
    )
    before = client.get(ROOTS, params={"sensor_id": sensor["id"]}).json()
    # A simultaneous removal cannot leave a dangling relationship. Roll back all roots.
    assert (
        send_components(
            client, token, [first, root("/env/two", components=[])], 2
        ).status_code
        == 400
    )
    assert client.get(ROOTS, params={"sensor_id": sensor["id"]}).json() == before
    # A complete scan can withdraw only its links while retaining its components.
    assert send_components(client, token, [root()], 2).status_code == 200
    assert client.get(RELATIONSHIPS).json()["items"] == []
    assert send_components(client, token, [first], 3).status_code == 200
    # Removing a referenced component also removes incident links owned by other roots.
    assert (
        send_components(client, token, [root("/env/two", components=[])], 4).status_code
        == 200
    )
    assert client.get(RELATIONSHIPS).json()["items"] == []
    # Schema constraints also reject cross-tenant and cross-sensor endpoint IDs.
    foreign = st.one(
        "SELECT id FROM inventory_components WHERE sensor_id=$1", other["id"]
    )["id"]
    own = client.get(COMPONENTS, params={"sensor_id": sensor["id"]}).json()["items"][0]
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        st.execute(
            """INSERT INTO inventory_relationships(id,tenant_id,sensor_id,root_id,from_component_id,to_component_id,kind,evidence,last_seen_at)
        VALUES($1,$2,$3,$4,$5,$6,'depends_on','declared',now())""",
            str(uuid4()),
            sensor["tenant_id"],
            sensor["id"],
            own["root_id"],
            own["id"],
            foreign,
        )


def test_component_http_auth_disable_delete_and_legacy_migration(inventory):
    st, cfg, client, identities = inventory
    sensor, token, session = identities[0]
    other, other_token, other_session = identities[1]
    # Rehearse an additive upgrade against an existing legacy inventory.
    assert post(client, token, snapshot([app()])).status_code == 200
    legacy = client.get(APPS).json()
    st.execute(
        "DROP TABLE skill_installations,skill_bundles,inventory_relationships,inventory_components,inventory_roots"
    )
    st.execute("DELETE FROM schema_migrations WHERE version IN (20,88)")
    assert st.migrate() == ["0020_component_inventory.sql", "0088_skill_scanning.sql"]
    assert st.migrate() == []
    assert client.get(APPS).json() == legacy
    assert client.post(SNAPSHOTS, json=component_snapshot([root()])).status_code == 401
    headers = {"Authorization": "Bearer " + token}
    assert (
        client.post(
            SNAPSHOTS,
            json=component_snapshot([root()]) | {"sensor_id": other["id"]},
            headers=headers,
        ).status_code
        == 403
    )
    assert (
        client.post(
            SNAPSHOTS,
            json=component_snapshot([root()]) | {"tenant_id": other["tenant_id"]},
            headers=headers,
        ).status_code
        == 400
    )
    for bearer, path in ((token, "/env/one"), (other_token, "/foreign")):
        entry = root(path, components=[component(), component("dependency")])
        link = relationship(entry, entry)
        link["to"]["key"] = "dependency"
        entry["relationships"] = [link]
        assert send_components(client, bearer, [entry]).status_code == 200
    assert len(client.get(RELATIONSHIPS).json()["items"]) == 1
    assert client.get(APPS).json() == legacy
    for endpoint in (COMPONENTS, ROOTS, RELATIONSHIPS):
        assert (
            client.get(endpoint, params={"sensor_id": other["id"]}).json()["items"]
            == []
        )
    client.cookies.clear()
    for endpoint in (COMPONENTS, ROOTS, RELATIONSHIPS):
        assert client.get(endpoint).status_code == 401
    client.cookies.set(CONSOLE_COOKIE, other_session)
    assert client.get(COMPONENTS).json()["items"][0]["root"] == "/foreign"
    cfg.tenant_id = sensor["tenant_id"]
    assert send_components(client, other_token, [root()], 1).status_code == 403
    assert client.get(COMPONENTS).status_code == 403
    client.cookies.set(CONSOLE_COOKIE, session)
    st.update_sensor(sensor["tenant_id"], sensor["id"], disabled=True)
    assert send_components(client, token, [root()], 1).status_code == 403
    # A principal authenticated before disable is checked again under the lock.
    from openaidr.server.httpx import APIError

    with pytest.raises(APIError, match="disabled"):
        ingest_components(st, sensor, component_snapshot([root()], 1))
    st.delete_sensor(sensor["tenant_id"], sensor["id"])
    for endpoint in (COMPONENTS, ROOTS, RELATIONSHIPS):
        assert client.get(endpoint).json()["items"] == []
    assert send_components(client, token, [root()], 2).status_code == 401
    st.execute("DELETE FROM sensors WHERE id=$1", sensor["id"])
    assert (
        st.scalar(
            "SELECT count(*) FROM inventory_roots WHERE sensor_id=$1", sensor["id"]
        )
        == 0
    )


def test_component_validation_bounds_metadata_and_atomicity(inventory):
    st, cfg, client, identities = inventory
    token = identities[0][1]
    assert send_components(client, token, [root()]).status_code == 200
    bad = []
    for field, value in (
        ("schema_version", True),
        ("schema_version", 2),
        ("platform", "unknown"),
        ("collected_at", "bad"),
        ("collected_at", "2025-01-01"),
        ("collected_at", "2025-01-01T00:00:00+01:00"),
        (
            "collected_at",
            (datetime.now(timezone.utc) + timedelta(minutes=6)).isoformat(),
        ),
        ("roots", [root()] * 257),
    ):
        bad.append(component_snapshot([root()], 5) | {field: value})
    for field, value in (
        ("source", "unknown"),
        ("root", ""),
        ("root", "x" * 8193),
        ("status", "unknown"),
        ("scope", "all"),
        ("components", None),
        ("components", [component()] * 10001),
        ("relationships", [{}] * 20001),
        ("relationships", None),
        ("status", "error"),
        ("status", "unavailable"),
        ("config", {"secret": "should never persist"}),
    ):
        bad.append(component_snapshot([root(**{field: value})], 5))
    for field, value in (
        ("key", ""),
        ("name", 1),
        ("name", "nul\x00"),
        ("name", "\ud800"),
        ("kind", "skill"),
        ("ecosystem", "npm"),
        ("evidence", "trusted"),
        ("manifest", "secret"),
        ("metadata", {"environment": {"API_KEY": "secret"}}),
        ("metadata", {"tools": ["x"] * 129}),
        ("metadata", {"content_sha256": "abc"}),
        ("metadata", {"description": "x" * 2049}),
    ):
        bad.append(
            component_snapshot([root(components=[component(**{field: value})])], 5)
        )
    for url in (
        "https://token@example.com/a",
        "https://example.com/a?token=secret",
        "https://example.com/a#token",
        "file:///private/config",
        "https://[invalid",
        "https://example.com:invalid/a",
        "https://example.com/\nsecret",
    ):
        bad.append(
            component_snapshot(
                [root(components=[component(metadata={"source_url": url})])], 5
            )
        )
    bad.append(component_snapshot([root(), root()], 5))
    bad.append(
        component_snapshot(
            [root(components=[component(), component(version="other")])], 5
        )
    )
    link = relationship(root(), root())
    for field, value in (
        ("kind", "executes"),
        ("evidence", "installed"),
        ("from", None),
        ("to", {**link["to"], "sensor_id": identities[1][0]["id"]}),
    ):
        bad.append(component_snapshot([root(relationships=[link | {field: value}])], 5))
    headers = {"Authorization": "Bearer " + token}
    for payload in bad:
        result = client.post(
            SNAPSHOTS,
            content=json.dumps(payload).encode(),
            headers=headers | {"Content-Type": "application/json"},
        )
        assert result.status_code == 400, result.text
    assert client.get(COMPONENTS).json()["items"][0]["version"] == "1.0"
    assert (
        client.get(ROOTS).json()["items"][0]["collected_at"] == "2025-01-01T00:00:00Z"
    )
    assert (
        client.post(
            SNAPSHOTS, content=b" " * ((8 << 20) + 1), headers=headers
        ).status_code
        == 413
    )


def test_component_types_metadata_filters_and_pages(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    sources = [
        ("osquery-apps", "application", ""),
        ("osquery-npm-packages", "package", "npm"),
        ("osquery-python-packages", "package", "pypi"),
        ("openaidr-skills", "skill", ""),
        ("openaidr-mcp-servers", "mcp_server", ""),
        ("openaidr-plugins", "plugin", ""),
    ]
    data = [
        root(
            "/" + source,
            source=source,
            components=[
                component(
                    kind=kind,
                    ecosystem=ecosystem,
                    metadata={
                        "license": "MIT",
                        "repository_url": "https://example.com/repo",
                        "content_sha256": "a" * 64,
                        "tools": ["Read", "Read"],
                    },
                )
            ],
        )
        for source, kind, ecosystem in sources
    ]
    data[0]["relationships"] = [relationship(data[0], target) for target in data[1:]]
    assert send_components(client, token, data).status_code == 200
    for endpoint, expected in ((COMPONENTS, 6), (ROOTS, 6), (RELATIONSHIPS, 5)):
        rows, cursor = [], ""
        while True:
            response = client.get(endpoint, params={"limit": 2, "cursor": cursor})
            assert response.status_code == 200, response.text
            rows.extend(response.json()["items"])
            cursor = response.json()["next_cursor"]
            if not cursor:
                break
        assert len(rows) == len({row["id"] for row in rows}) == expected
        assert all(row["sensor_id"] == sensor["id"] for row in rows)
        assert (
            client.get(
                endpoint, params={"sensor_id": "urn:uuid:" + sensor["id"]}
            ).status_code
            == 200
        )
        for params in (
            {"cursor": "bad"},
            {"cursor": encode_cursor("\x00", str(uuid4()))},
            {"root_id": "bad"},
            {"sensor_id": "bad"},
            {"source": "bad"},
            {"q": "x" * 1025},
        ):
            assert client.get(endpoint, params=params).status_code == 400
    row = client.get(COMPONENTS, params={"kind": "skill"}).json()["items"][0]
    assert row["metadata"]["tools"] == ["Read"]
    assert row["metadata"]["content_sha256"] == "a" * 64
    assert (
        client.get(
            COMPONENTS,
            params={"ecosystem": "npm", "user": "alice", "root_id": row["root_id"]},
        ).json()["items"]
        == []
    )
    assert (
        len(
            client.get(
                COMPONENTS, params={"ecosystem": "npm", "evidence": "installed"}
            ).json()["items"]
        )
        == 1
    )
    assert (
        len(
            client.get(
                RELATIONSHIPS,
                params={
                    "component_id": row["id"],
                    "kind": "depends_on",
                    "evidence": "declared",
                },
            ).json()["items"]
        )
        == 1
    )
    long = "".join(chr(0x20000 + i * 7919 % 40000) for i in range(1023))
    variants = root(
        "/" + long,
        components=[
            component("one%_", name=long + "a"),
            component("two", name=long + "b"),
        ],
    )
    assert send_components(client, token, [variants], 1).status_code == 200
    first = client.get(COMPONENTS, params={"root": variants["root"], "limit": 1}).json()
    second = client.get(
        COMPONENTS,
        params={"root": variants["root"], "limit": 1, "cursor": first["next_cursor"]},
    ).json()
    assert {first["items"][0]["name"], second["items"][0]["name"]} == {
        long + "a",
        long + "b",
    }
    assert second["next_cursor"] == ""
    assert len(client.get(COMPONENTS, params={"q": "%_"}).json()["items"]) == 1


def test_component_concurrent_snapshots_keep_newest_root(inventory):
    st, cfg, client, identities = inventory
    sensor = identities[0][0]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(
                lambda n: ingest_components(
                    st,
                    sensor,
                    component_snapshot(
                        [root(components=[component(version=str(n))])], n
                    ),
                ),
                [8, 2, 9, 3],
            )
        )
    assert all(result["accepted"] for result in results)
    assert client.get(COMPONENTS).json()["items"][0]["version"] == "9"
    assert (
        client.get(ROOTS).json()["items"][0]["collected_at"] == "2025-01-01T00:00:09Z"
    )


def test_component_maximum_batch_roundtrip_and_removal(inventory):
    st, cfg, client, identities = inventory
    token = identities[0][1]
    batch = root(components=[component(f"package-{n:05}") for n in range(10000)])
    assert send_components(client, token, [batch]).status_code == 200
    assert client.get(ROOTS).json()["items"][0]["component_count"] == 10000
    page = client.get(COMPONENTS, params={"limit": 10000}).json()
    assert len(page["items"]) == 500 and page["next_cursor"]
    assert send_components(client, token, [root(components=[])], 1).status_code == 200
    assert client.get(ROOTS).json()["items"][0]["component_count"] == 0


def usage_event(product="claude-code", user="alice", **changes):
    return {
        "id": str(uuid4()),
        "time": datetime(2026, 9, 30, 12, tzinfo=timezone.utc).isoformat(),
        "agent": {"product": product},
        "host": {"user": user},
        "session": {"id": "approval-usage"},
        "kind": "prompt",
        **changes,
    }


def test_ai_applications_group_installs_and_count_only_attributed_recent_activity(
    inventory, monkeypatch
):
    from openaidr.server import ai_inventory

    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    other, other_token, _ = identities[1]
    end = datetime(2026, 10, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(ai_inventory, "now", lambda: end)
    installs = [
        app("com.anthropic.claude-code") | {"name": "Claude Code"},
        app("second-install") | {"name": "Claude Code", "version": "2"},
        app("com.openai.chat") | {"name": "ChatGPT"},
        app("com.anthropic.claude-code-url-handler")
        | {"name": "Claude Code URL Handler"},
        app("com.openai.new-product") | {"name": "New AI product"},
        app("ordinary-app"),
    ]
    assert post(client, token, snapshot(installs)).status_code == 200
    assert (
        post(
            client, other_token, snapshot([app("foreign") | {"name": "Ollama"}])
        ).status_code
        == 200
    )
    # A CLI installed through npm is the same product as its activity. A Python
    # SDK is a library and does not become an AI application.
    roots = [
        root(
            "/npm",
            source="osquery-npm-packages",
            components=[
                component("@openai/codex", ecosystem="npm"),
                component("@anthropic-ai/claude-code", ecosystem="npm"),
            ],
        ),
        root(components=[component("aider-chat"), component("openai")]),
    ]
    assert send_components(client, token, roots).status_code == 200
    events = [
        usage_event(),
        usage_event(),
        usage_event(user=" alice "),
        usage_event(user="Alice"),
        usage_event(user="bob"),
        usage_event(user="   "),
        usage_event(user="boundary", time=(end - timedelta(hours=24)).isoformat()),
        usage_event(time=end.isoformat()),
        usage_event("codex-cli"),
        usage_event("codex_cli_rs"),
        usage_event("cursor", user=""),
        usage_event("unknown", user="someone"),
        usage_event("gemini-cli", kind="sensor"),
        usage_event(
            user="old", time=(end - timedelta(hours=24, microseconds=1)).isoformat()
        ),
        usage_event("chatgpt", time=(end - timedelta(days=2)).isoformat()),
        usage_event("codex-cli", user="weekly", time=(end - timedelta(days=2)).isoformat()),
        usage_event("gemini-cli", user="weekly", time=(end - timedelta(days=2)).isoformat()),
        usage_event(user="future", time=(end + timedelta(microseconds=1)).isoformat()),
    ]
    assert st.ingest_batch(sensor, events)["accepted"] == len(events)
    # Historical bodies can lack a string username. Arrays must not unwrap into
    # attributed users, and missing fields must not fail the whole overview.
    unattributed_bodies = [
        {},
        {"host": None},
        {"host": []},
        {"host": "alice"},
        {"host": [{"user": "alice"}]},
        {"host": {}},
        *[
            {"host": {"user": value}}
            for value in (None, False, 12, [], ["alice"], {"name": "alice"})
        ],
    ]
    st.execute(
        """INSERT INTO events(id,tenant_id,sensor_id,agent_id,session_id,time,kind,product,body)
        SELECT md5(e.id::text||':unattributed:'||b.n::text)::uuid,e.tenant_id,e.sensor_id,
            e.agent_id,e.session_id,e.time,e.kind,e.product,(e.body-'host')||b.body
        FROM events e CROSS JOIN jsonb_array_elements($2::jsonb)
            WITH ORDINALITY b(body,n) WHERE e.id=$1""",
        events[0]["id"],
        json.dumps(unattributed_bodies),
    )
    st.ingest_batch(other, [usage_event(user="foreign"), usage_event("ollama")])
    # The same username on another device still counts once in this convention.
    enrollment = st.bootstrap_tenant("first", "first")
    second, _, _ = st.enroll_sensor(
        dict(enrollment_token=enrollment["enrollment_token"], hostname="second")
    )
    st.ingest_batch(second, [usage_event(user="alice")])
    deleted, _, _ = st.enroll_sensor(
        dict(enrollment_token=enrollment["enrollment_token"], hostname="deleted")
    )
    st.ingest_batch(deleted, [usage_event(user="deleted")])
    st.delete_sensor(sensor["tenant_id"], deleted["id"])

    response = client.get(AI_APPS)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    data = response.json()
    assert data["window"] == {
        "start": "2026-09-30T00:00:00Z",
        "end": "2026-10-01T00:00:00Z",
        "days": 1,
    }
    rows = {row["id"]: row for row in data["items"]}
    assert [row["id"] for row in data["items"][:2]] == ["claude-code", "codex"]
    assert rows["claude-code"]["observed_users"] == 4
    assert rows["claude-code"]["activity_events"] == 9 + len(unattributed_bodies)
    assert rows["claude-code"]["last_activity_at"] == "2026-10-01T00:00:00Z"
    assert rows["claude-code"]["usage_status"] == "partial"
    assert rows["claude-code"]["unattributed_events"] == 1 + len(unattributed_bodies)
    assert rows["codex"]["observed_users"] == 1
    assert rows["codex"]["activity_events"] == 2
    assert rows["codex"]["unattributed_events"] == 0
    assert rows["codex"]["usage_status"] == "observed"
    assert rows["codex"]["last_installed_at"] == "2025-01-01T00:00:00Z"
    for product in ("chatgpt", "cursor", "aider"):
        assert rows[product]["observed_users"] is None
        assert rows[product]["usage_status"] == "unavailable"
    assert rows["cursor"]["activity_events"] == 1
    assert rows["cursor"]["unattributed_events"] == 1
    assert rows["chatgpt"]["activity_events"] == 0
    assert rows["chatgpt"]["last_activity_at"] is None
    assert len(rows) == 6
    assert sum(row["name"] == "New AI product" for row in rows.values()) == 1
    assert not any(row["approved"] for row in rows.values())
    people = rows["claude-code"]["users"]
    assert {p["username"] for p in people} == {"alice", "Alice", "bob", "boundary"}
    alice = next(p for p in people if p["username"] == "alice")
    assert {d["id"] for d in alice["devices"]} == {sensor["id"], second["id"]}
    assert {d["name"] for d in alice["devices"]} == {"first", "second"}
    assert alice["last_activity_at"].startswith("2026-10-01T00:00:00")
    for days in (7, 30):
        extended = client.get(AI_APPS, params={"days": days})
        assert extended.status_code == 200, extended.text
        payload = extended.json()
        assert payload["window"]["days"] == days
        longer = {row["id"]: row for row in payload["items"]}
        assert longer["claude-code"]["observed_users"] == 5
        assert longer["chatgpt"]["observed_users"] is None
        assert longer["codex"]["observed_users"] == 2
        assert all(p["username"] not in ("foreign", "deleted", "future")
                   for row in longer.values() for p in row["users"])
    for invalid in ("0", "2", "31", "-1", "abc", "1.0"):
        assert client.get(AI_APPS, params={"days": invalid}).status_code == 400
    # An app observed only in a longer window can still be approved, but only
    # by a role allowed to write organization approvals.
    path = AI_APPS + "/gemini-cli/approval"
    headers = {"X-OpenAIDR-CSRF": "1"}
    assert client.put(path, json={"approved": True}, headers=headers).status_code == 403
    st.execute("UPDATE tenant_users SET role='admin' WHERE tenant_id=$1", sensor["tenant_id"])
    saved = client.put(path, json={"approved": True}, headers=headers)
    assert saved.status_code == 200, saved.text
    assert saved.json()["approved"] is True
    client.cookies.clear()
    assert client.get(AI_APPS).status_code == 401


def test_ai_application_usage_does_not_sort_event_payloads(inventory, monkeypatch):
    from openaidr.server import ai_inventory

    st, cfg, client, identities = inventory
    sensor = identities[0][0]
    monkeypatch.setattr(
        ai_inventory, "now", lambda: datetime(2026, 10, 1, tzinfo=timezone.utc)
    )
    first = usage_event()
    st.ingest_batch(sensor, [first])
    # Enough realistic event bodies to spill a payload sort at 4 MB, while
    # application, username and timestamp rows fit in memory.
    st.execute(
        """INSERT INTO events(id,tenant_id,sensor_id,agent_id,session_id,time,kind,product,body)
        SELECT md5(e.id::text||':'||n::text)::uuid,e.tenant_id,e.sensor_id,
            e.agent_id,e.session_id,e.time,e.kind,e.product,
            e.body||jsonb_build_object('payload',padding,'host',jsonb_build_object(
                'user',CASE n%3 WHEN 0 THEN 'alice' WHEN 1 THEN ' bob ' END))
        FROM events e CROSS JOIN generate_series(1,6000) n CROSS JOIN (
            SELECT string_agg(md5(i::text),'') AS padding FROM generate_series(1,40) i
        ) wide WHERE e.id=$1""",
        first["id"],
    )
    st.execute("ANALYZE events")
    st.execute("ANALYZE sensors")
    queries, many = [], st.many

    def capture_query(query, *args, **kwargs):
        if "AS observed_users" in query:
            queries.append((query, args))
        return many(query, *args, **kwargs)

    monkeypatch.setattr(st, "many", capture_query)
    response = client.get(AI_APPS)
    assert response.status_code == 200, response.text
    row, = response.json()["items"]
    assert row["observed_users"] == 2
    assert row["activity_events"] == 6001
    assert row["unattributed_events"] == 2000
    assert row["usage_status"] == "partial"
    assert row["last_activity_at"] == first["time"].replace("+00:00", "Z")
    query, args = queries[0]
    with st.transaction() as conn:
        st.execute("SET LOCAL work_mem='4MB'", conn=conn)
        st.execute("SET LOCAL max_parallel_workers_per_gather=0", conn=conn)
        plan = st.scalar(
            "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + query, *args, conn=conn
        )[0]["Plan"]
    assert plan["Temp Written Blocks"] == 0, json.dumps(plan, indent=2)


@pytest.mark.parametrize("allowed_role", ["admin", "analyst"])
def test_ai_application_approvals_are_role_scoped_and_durable(inventory, allowed_role):
    st, cfg, client, identities = inventory
    sensor, token, session = identities[0]
    other, other_token, other_session = identities[1]
    assert (
        post(
            client,
            token,
            snapshot(
                [
                    app("com.openai.chat") | {"name": "ChatGPT"},
                    app("com.anthropic.claudefordesktop") | {"name": "Claude"},
                ]
            ),
        ).status_code
        == 200
    )
    assert (
        post(
            client,
            other_token,
            snapshot(
                [
                    app("com.openai.chat") | {"name": "ChatGPT"},
                    app("com.openai.foreign-only") | {"name": "Foreign product"},
                ]
            ),
        ).status_code
        == 200
    )
    path = AI_APPS + "/chatgpt/approval"
    headers = {"X-OpenAIDR-CSRF": "1"}
    st.execute("UPDATE tenant_users SET role='viewer' WHERE tenant_id=$1", sensor["tenant_id"])
    assert client.put(path, json={"approved": True}, headers=headers).status_code == 403
    st.execute("UPDATE tenant_users SET role=$2 WHERE tenant_id=$1", sensor["tenant_id"], allowed_role)
    assert client.put(path, json={"approved": True}).status_code == 403
    assert (
        client.put(
            path,
            json={"approved": True},
            headers={**headers, "Origin": "https://foreign.example"},
        ).status_code
        == 403
    )
    for value in (
        {},
        {"approved": 1},
        {"approved": "true"},
        {"approved": None},
        {"approved": True, "tenant_id": other["tenant_id"]},
    ):
        assert client.put(path, json=value, headers=headers).status_code == 400
    assert (
        client.put(
            AI_APPS + "/invented/approval", json={"approved": True}, headers=headers
        ).status_code
        == 404
    )
    result = client.put(path, json={"approved": True}, headers=headers)
    assert result.status_code == 200, result.text
    assert result.headers["cache-control"] == "no-store"
    assert result.json()["approved"] is True
    assert result.json()["approval_updated_at"]
    assert (
        client.put(
            AI_APPS + "/claude/approval", json={"approved": True}, headers=headers
        ).status_code
        == 200
    )
    assert all(row["approved"] for row in client.get(AI_APPS).json()["items"])
    client.cookies.set(CONSOLE_COOKIE, other_session)
    rows = client.get(AI_APPS).json()["items"]
    foreign_id = next(row["id"] for row in rows if row["name"] == "Foreign product")
    assert not any(row["approved"] for row in rows)
    cfg.tenant_id = sensor["tenant_id"]
    assert client.get(AI_APPS).status_code == 403
    client.cookies.set(CONSOLE_COOKIE, session)
    assert (
        client.put(
            AI_APPS + f"/{foreign_id}/approval",
            json={"approved": True},
            headers=headers,
        ).status_code
        == 404
    )
    assert (
        client.put(path, json={"approved": False}, headers=headers).status_code == 200
    )
    # Choices persist when a successful scan removes the installations.
    assert post(client, token, snapshot([], offset=1)).status_code == 200
    rows = {row["id"]: row for row in client.get(AI_APPS).json()["items"]}
    assert rows["chatgpt"]["approved"] is False
    assert rows["claude"]["approved"] is True
    assert all(row["last_installed_at"] is None for row in rows.values())
    audit = st.many(
        "SELECT tenant_id,actor_id,target_id,details FROM audit_log WHERE action='ai-application.approval' ORDER BY at,id"
    )
    assert len(audit) == 3
    assert all(
        row["tenant_id"] == sensor["tenant_id"] and row["actor_id"] for row in audit
    )
    assert [row["details"] for row in audit if row["target_id"] == "chatgpt"] == [
        {"name": "ChatGPT", "before": False, "before_status": "monitoring", "approved": True},
        {"name": "ChatGPT", "before": True, "before_status": "approved", "approved": False},
    ]


def test_ai_application_approval_rolls_back_if_audit_fails(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    assert (
        post(
            client, token, snapshot([app("com.openai.chat") | {"name": "ChatGPT"}])
        ).status_code
        == 200
    )
    st.execute(
        "UPDATE tenant_users SET role='admin' WHERE tenant_id=$1", sensor["tenant_id"]
    )
    st.execute("""CREATE FUNCTION reject_approval_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action='ai-application.approval' THEN RAISE EXCEPTION 'audit unavailable'; END IF;
        RETURN NEW; END; $$""")
    st.execute(
        "CREATE TRIGGER reject_approval_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_approval_audit()"
    )
    result = client.put(
        AI_APPS + "/chatgpt/approval",
        json={"approved": True},
        headers={"X-OpenAIDR-CSRF": "1"},
    )
    assert result.status_code == 500
    assert client.get(AI_APPS).json()["items"][0]["approved"] is False
    assert st.scalar("SELECT count(*) FROM ai_application_approvals") == 0
    client.cookies.clear()
    assert (
        client.put(
            AI_APPS + "/chatgpt/approval",
            json={"approved": True},
            headers={"X-OpenAIDR-CSRF": "1"},
        ).status_code
        == 401
    )
