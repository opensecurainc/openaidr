"""Daily history against real PostgreSQL, inventory ingestion, and HTTP auth."""

from datetime import timedelta

from openaidr.server import inventory_history, osv
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server.store import now
from test_app_inventory_server import inventory, root, component, send_components

API = "/api/v1/inventory/attention-history"
PYTHON = "osquery-python-packages"
NPM = "osquery-npm-packages"


def assess(st, tenant):
    for row in osv.claim(st, tenant):
        osv.save(st, row, [{"id": "CVE-example"}])


def latest(client):
    reply = client.get(API)
    assert reply.status_code == 200, reply.text
    assert reply.headers["cache-control"] == "no-store"
    data = reply.json()
    assert len(data["days"]) == 30 and data["scope"] == "tenant" and data["timezone"] == "UTC"
    return data["days"][-1]


def test_counts_deduplicate_versions_copies_devices_and_keep_category_identity(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    second, second_token, _ = st.enroll_sensor(dict(
        enrollment_token=st.create_enrollment_token(sensor["tenant_id"], "second", 3600, 1)["token"],
        hostname="second", os="darwin"))
    records = [root(components=[component(), component("copy", identifier="example", version="2.0"), component("pending")]),
               root("/other", components=[component()]),
               root("/npm", source=NPM, components=[component(ecosystem="npm", version="1.0.0")])]
    assert send_components(client, token, records).status_code == 200
    assert send_components(client, second_token, [root()]).status_code == 200
    assess(st, sensor["tenant_id"])
    # One unassessed record and one retained finding demonstrate that assessment
    # availability and scan coverage are separate from the attention trigger.
    st.execute("DELETE FROM inventory_osv_packages WHERE identifier='pending'")
    assert send_components(client, token, [root(status="partial", components=[])], 1).status_code == 200
    st.execute("UPDATE inventory_osv_packages SET error='retry',checked_at=now()-interval '2 days'")
    inventory_history.tick(st, sensor["tenant_id"])
    day = latest(client)
    assert day["categories"][PYTHON] == {"components": 1, "device_weighted": 2}
    assert day["categories"][NPM] == {"components": 1, "device_weighted": 1}
    assert day["categories"]["openaidr-plugins"] == {"components": 0, "device_weighted": 0}
    assert day["categories"]["openaidr-mcp-servers"] == {"components": 0, "device_weighted": 0}
    # A successful rescan removes one device's copies, not the other device's.
    assert send_components(client, token, [root(components=[]), root("/other", components=[]),
                                         root("/npm", source=NPM, components=[])], 2).status_code == 200
    inventory_history.capture(st, sensor["tenant_id"])
    assert latest(client)["categories"][PYTHON] == {"components": 1, "device_weighted": 1}
    st.execute("UPDATE sensors SET deleted_at=now() WHERE id=$1", second["id"])
    inventory_history.capture(st, sensor["tenant_id"])
    assert all(value == {"components": 0, "device_weighted": 0} for value in latest(client)["categories"].values())


def test_history_gaps_persistence_retention_and_roll_forward(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    empty = latest(client)
    assert empty["captured_at"] is None and empty["categories"] is None
    assert send_components(client, token, [root()]).status_code == 200
    assess(st, sensor["tenant_id"])
    inventory_history.capture(st, sensor["tenant_id"])
    # Preserve an earlier observed day, then record today's changed inventory.
    st.execute("UPDATE inventory_attention_daily SET day=day-2,captured_at=captured_at-interval '2 days'")
    assert send_components(client, token, [root(components=[])], 1).status_code == 200
    inventory_history.capture(st, sensor["tenant_id"])
    days = client.get(API).json()["days"]
    assert days[-3]["categories"][PYTHON]["components"] == 1
    assert days[-2]["categories"] is None
    assert days[-1]["categories"][PYTHON]["components"] == 0
    assert days[-1]["date"] == now().date().isoformat()
    assert days[0]["date"] == (now().date() - timedelta(days=29)).isoformat()
    assert len([day for day in days if day["categories"] is not None]) == 2
    # Repeated captures replace this day's observation rather than adding it.
    inventory_history.capture(st, sensor["tenant_id"])
    assert st.scalar("SELECT count(*) FROM inventory_attention_daily") == 8
    st.execute("UPDATE inventory_attention_daily SET day=day-40,captured_at=captured_at-interval '40 days'")
    inventory_history.capture(st, sensor["tenant_id"])
    assert st.scalar("SELECT count(*) FROM inventory_attention_daily") == 4
    # An incomplete stored day is not shown as a complete zero-valued snapshot.
    st.execute("DELETE FROM inventory_attention_daily WHERE source=$1", NPM)
    assert latest(client)["categories"] is None


def test_http_tenant_isolation_auth_and_disabled_checks(inventory):
    st, cfg, client, identities = inventory
    first, token, session = identities[0]
    other, other_token, other_session = identities[1]
    for sensor, sensor_token, _ in identities:
        assert send_components(client, sensor_token, [root()]).status_code == 200
        assess(st, sensor["tenant_id"])
    inventory_history.tick(st, first["tenant_id"])
    assert latest(client)["categories"][PYTHON]["components"] == 1
    client.cookies.set(CONSOLE_COOKIE, other_session)
    assert latest(client)["categories"] is None
    # Caller-controlled tenant IDs cannot change the authenticated scope.
    assert client.get(API, params={"tenant_id": first["tenant_id"]}).json()["days"][-1]["categories"] is None
    inventory_history.tick(st)
    assert latest(client)["categories"][PYTHON]["components"] == 1
    cfg.osv_assessment = False
    reply = client.get(API).json()
    assert reply["checks_enabled"] is False
    assert reply["days"][-1]["categories"][PYTHON]["components"] == 1
    client.cookies.clear()
    assert client.get(API).status_code == 401
    assert client.get(API, headers={"Authorization": "Bearer " + token}).status_code in (401, 403)
    client.cookies.set(CONSOLE_COOKIE, session)
    assert latest(client)["categories"][PYTHON]["components"] == 1


def test_history_migration_is_additive_and_reentrant(inventory):
    st, cfg, client, identities = inventory
    assert send_components(client, identities[0][1], [root()]).status_code == 200
    before = client.get("/api/v1/inventory/components").json()
    st.execute("DROP TABLE inventory_attention_daily")
    st.execute("DELETE FROM schema_migrations WHERE version=101")
    assert st.migrate() == ["0101_inventory_attention_daily.sql"]
    assert st.migrate() == []
    assert client.get("/api/v1/inventory/components").json() == before
    assert latest(client)["categories"] is None
