"""Login attribution stays separate from sensor authentication and event users."""

from test_app_inventory_server import inventory


def test_login_heartbeat_is_monotonic_optional_and_sensor_scoped(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    other, other_token, _ = identities[1]
    st.execute("UPDATE sensors SET username='enrollment-service' WHERE id=$1", sensor["id"])

    def heartbeat(data, bearer=token):
        return client.post("/ingest/v1/heartbeat", json=data,
                           headers={"Authorization": "Bearer " + bearer})

    def latest(device=sensor):
        row = st.get_sensor(device["tenant_id"], device["id"])
        return row["latest_signed_in_user"], row["latest_signed_in_at"]

    alice = {"name": "Alice", "signed_in_at": "2026-01-01T00:00:00Z"}
    bob = {"name": "DOMAIN\\Bob", "signed_in_at": "2026-01-02T01:00:00+01:00"}
    assert latest() == ("", None)
    assert heartbeat({}).status_code == 200
    assert heartbeat({"signed_in_user": alice}, "invalid-token").status_code == 401
    assert latest() == ("", None)
    assert heartbeat({"signed_in_user": alice}).status_code == 200
    assert latest()[0] == "Alice"
    assert heartbeat({"signed_in_user": bob, "sensor_id": other["id"]}).status_code == 200
    assert latest()[0] == "DOMAIN\\Bob"
    assert latest()[1].isoformat() == "2026-01-02T00:00:00+00:00"
    assert latest(other) == ("", None)
    # A late heartbeat, a logout, and an older session left open after logout
    # cannot replace the newest observed login with an older or unknown one.
    for data in ({"signed_in_user": alice}, {}, {"signed_in_user": None},
                 {"signed_in_user": dict(bob, name="same-time-other-user")}):
        assert heartbeat(data).status_code == 200
        assert latest()[0] == "DOMAIN\\Bob"
    # Optional malformed evidence never prevents liveness or policy delivery.
    for invalid in ("alice", {}, {"name": 123}, dict(bob, name=" "),
                    dict(bob, name="bad\nname"), dict(bob, name="x" * 257),
                    dict(bob, signed_in_at="invalid"), dict(bob, signed_in_at="2026-01-03"),
                    dict(bob, signed_in_at="9999-12-31T00:00:00Z"),
                    dict(bob, signed_in_at="0001-01-01T00:00:00+14:00")):
        assert heartbeat({"signed_in_user": invalid}).status_code == 200
        assert latest()[0] == "DOMAIN\\Bob"
    assert st.get_sensor(sensor["tenant_id"], sensor["id"])["username"] == "enrollment-service"
    assert heartbeat({"signed_in_user": alice}, other_token).status_code == 200
    assert latest(other)[0] == "Alice"
    assert latest()[0] == "DOMAIN\\Bob"


def test_login_migration_preserves_existing_enrollment_without_backfill(inventory):
    st, cfg, client, identities = inventory
    sensor, _, _ = identities[0]
    st.execute("UPDATE sensors SET username='service-account' WHERE id=$1", sensor["id"])
    # Recreate the immediate predecessor schema with populated endpoint records.
    st.execute("ALTER TABLE sensor_activity DROP COLUMN latest_signed_in_user, DROP COLUMN latest_signed_in_at")
    st.execute("DELETE FROM schema_migrations WHERE version=89")
    assert st.migrate() == ["0089_endpoint_signed_in_user.sql"]
    assert st.migrate() == []
    for device, _, _ in identities:
        row = st.get_sensor(device["tenant_id"], device["id"])
        assert row["latest_signed_in_user"] == "" and row["latest_signed_in_at"] is None
    assert st.get_sensor(sensor["tenant_id"], sensor["id"])["username"] == "service-account"
