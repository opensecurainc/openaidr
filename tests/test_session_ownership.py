"""HTTP and PostgreSQL tests for authenticated session ownership."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import copy
import time

from fastapi.testclient import TestClient
import psycopg
from psycopg.types.json import Jsonb
import pytest

from openaidr.core.event import new_id, now
from openaidr.server import auth
from openaidr.server.app import create_app
from openaidr.server.config import Config
from test_store import db, sensor, tenant


@pytest.fixture
def system(db):
    own_tenant, other_tenant = tenant(db), tenant(db)
    users = {
        "owner": db.create_user(
            own_tenant["id"], "owner@example.test", "Owner", "hash", "viewer"
        ),
        "peer": db.create_user(
            own_tenant["id"], "peer@example.test", "Peer", "hash", "owner"
        ),
        "foreign": db.create_user(
            other_tenant["id"], "foreign@example.test", "Foreign", "hash", "analyst"
        ),
    }
    sensors = {
        "sensor": sensor(db, own_tenant["id"]),
        "peer_sensor": sensor(db, own_tenant["id"]),
        "foreign_sensor": sensor(db, other_tenant["id"]),
    }
    cfg = Config(database_url=db.url, public_url="http://testserver")
    cfg.set_services("api,ingest")
    app = create_app(cfg, db)
    with ExitStack() as stack:
        result = {"db": db, "users": users, "sensors": sensors, "tenant": own_tenant}
        for name, user in users.items():
            client = stack.enter_context(
                TestClient(app, headers={auth.CSRF_HEADER: "1"})
            )
            client.cookies.set(
                auth.CONSOLE_COOKIE, db.create_session(user["id"], user["tenant_id"])
            )
            result[name] = client
        for name, (_, token, _) in sensors.items():
            result[name] = stack.enter_context(
                TestClient(app, headers={"Authorization": "Bearer " + token})
            )
        result["anonymous"] = stack.enter_context(TestClient(app))
        yield result


def event(
    external_id,
    registration_id=None,
    *,
    product="codex-cli",
    user="reported-user",
    kind="prompt",
):
    ident = new_id()
    value = {
        "id": ident,
        "time": now(),
        "kind": kind,
        "agent": {"product": product, "account": "peer@example.test"},
        "host": {"user": user},
        "session": {"id": external_id},
        "text": "captured evidence",
        "evidence": {
            "version": 1,
            "logical_id": ident,
            "observation_id": ident,
            "stream_id": "stream",
            "sequence": 1,
            "part": 1,
            "gaps": [],
        },
    }
    if registration_id is not None:
        value["session"]["registration_id"] = registration_id
    return value


def reserve(client, product="codex-cli"):
    reply = client.post("/ingest/v1/session-registrations", json={"product": product})
    assert reply.status_code == 201, reply.text
    value = reply.json()
    assert value["status"] == "reserved" and value["product"] == product
    return value


def bind(client, registration, external_id="native-session"):
    reply = client.post(
        f"/ingest/v1/session-registrations/{registration['id']}/bind",
        json={"external_id": external_id},
    )
    assert reply.status_code == 200, reply.text
    return reply.json()


def confirm(client, token, **extra):
    return client.post(
        "/api/v1/session-registrations/confirm", json={"token": token, **extra}
    )


def status(client, registration):
    return client.post(
        f"/ingest/v1/session-registrations/{registration['id']}/status", json={}
    )


def ingest(client, *events):
    reply = client.post("/ingest/v1/events", json={"events": list(events)})
    assert reply.status_code == 200, reply.text
    return reply.json()


def test_registered_session_uses_browser_owner_and_preserves_operator_reads(system):
    st, device = system["db"], system["sensor"]
    assert (
        system["anonymous"]
        .post("/ingest/v1/session-registrations", json={"product": "codex-cli"})
        .status_code
        == 401
    )
    assert (
        device.post(
            "/ingest/v1/session-registrations", json={"product": "gemini-cli"}
        ).status_code
        == 400
    )
    registration = reserve(device)
    for name in ("peer_sensor", "foreign_sensor"):
        assert status(system[name], registration).status_code == 404
        assert (
            system[name]
            .post(
                f"/ingest/v1/session-registrations/{registration['id']}/bind",
                json={"external_id": "native-session"},
            )
            .status_code
            == 404
        )
        refused = ingest(system[name], event("native-session", registration["id"]))
        assert refused["accepted"] == 0 and refused["rejected"][0]["index"] == 0
        assert (
            st.scalar(
                "SELECT count(*) FROM agents WHERE sensor_id=$1",
                system["sensors"][name][0]["id"],
            )
            == 0
        )

    startup = event("native-session", registration["id"], kind="session.start")
    assert ingest(device, startup)["accepted"] == 1
    pending = status(device, registration).json()
    assert pending["status"] == "pending" and pending["session_id"]
    assert (
        not {"confirmation_token", "owner_user_id", "user_id", "email"} & pending.keys()
    )
    challenge = bind(device, registration)
    assert challenge["expires_at"] == registration["expires_at"]
    first = event("native-session", registration["id"], user="first-reported-user")
    second = event("native-session", registration["id"], user="peer@example.test")
    assert ingest(device, first, second)["accepted"] == 2
    session_id = pending["session_id"]
    for name in ("owner", "peer", "foreign"):
        assert system[name].get("/api/v1/me/sessions").json()["items"] == []
        assert (
            system[name].get(f"/api/v1/me/sessions/{session_id}/evidence").status_code
            == 404
        )

    token = challenge["confirmation_token"]
    assert (
        system["owner"]
        .post(
            "/api/v1/session-registrations/confirm",
            json={"token": token},
            headers={auth.CSRF_HEADER: ""},
        )
        .status_code
        == 403
    )
    assert (
        system["owner"]
        .post(
            "/api/v1/session-registrations/confirm",
            json={"token": token},
            headers={"Origin": "https://untrusted.example"},
        )
        .status_code
        == 403
    )
    accepted = confirm(
        system["owner"],
        token,
        user_id=system["users"]["peer"]["id"],
        tenant_id=system["users"]["foreign"]["tenant_id"],
    )
    assert accepted.status_code == 200, accepted.text
    row = st.one(
        "SELECT owner_user_id,verified_at FROM session_registrations WHERE id=$1",
        registration["id"],
    )
    assert (
        row["owner_user_id"] == system["users"]["owner"]["id"]
        and row["verified_at"] is not None
    )
    assert status(device, registration).json()["status"] == "verified"
    assert (
        st.scalar(
            "SELECT count(*) FROM agent_sessions WHERE registration_id=$1",
            registration["id"],
        )
        == 1
    )
    assert (
        st.scalar(
            "SELECT count(DISTINCT agent_id) FROM events WHERE session_id=$1",
            session_id,
        )
        == 1
    )
    assert (
        st.scalar("SELECT body #>> '{host,user}' FROM events WHERE id=$1", second["id"])
        == "peer@example.test"
    )
    assert (
        st.scalar(
            "SELECT a.username FROM agents a JOIN events e ON e.agent_id=a.id WHERE e.id=$1",
            second["id"],
        )
        == startup["host"]["user"]
    )
    assert [
        item["id"]
        for item in system["owner"].get("/api/v1/me/sessions").json()["items"]
    ] == [session_id]
    owned = system["owner"].get(f"/api/v1/me/sessions/{session_id}/evidence?limit=2")
    assert owned.status_code == 200, owned.text
    assert owned.json()["next_cursor"]
    next_page = system["owner"].get(
        f"/api/v1/me/sessions/{session_id}/evidence",
        params={"cursor": owned.json()["next_cursor"]},
    )
    assert {
        item["id"] for item in owned.json()["items"] + next_page.json()["items"]
    } == {startup["id"], first["id"], second["id"]}
    for name in ("peer", "foreign"):
        assert (
            system[name].get(f"/api/v1/me/sessions/{session_id}/evidence").status_code
            == 404
        )
    assert (
        system["peer"].get(f"/api/v1/sessions/{session_id}/evidence").status_code == 200
    )
    assert (
        system["foreign"].get(f"/api/v1/sessions/{session_id}/evidence").status_code
        == 404
    )
    st.update_user(
        system["tenant"]["id"], system["users"]["owner"]["id"], status="disabled"
    )
    assert (
        system["owner"].get(f"/api/v1/me/sessions/{session_id}/evidence").status_code
        == 403
    )
    assert status(device, registration).json()["status"] == "unavailable"
    assert (
        device.post(
            f"/ingest/v1/session-registrations/{registration['id']}/bind",
            json={"external_id": "native-session"},
        ).status_code
        == 404
    )
    assert confirm(system["peer"], token).status_code == 404
    assert (
        st.scalar(
            "SELECT verified_at FROM session_registrations WHERE id=$1",
            registration["id"],
        )
        == row["verified_at"]
    )


def test_challenge_rotation_replay_expiry_and_deleted_owner_cannot_reclaim(system):
    st, device = system["db"], system["sensor"]
    registration = reserve(device, "claude-code")
    first, second = bind(device, registration), bind(device, registration)
    assert first["confirmation_token"] != second["confirmation_token"]
    assert first["expires_at"] == second["expires_at"] == registration["expires_at"]
    assert confirm(system["owner"], first["confirmation_token"]).status_code == 404
    assert confirm(system["foreign"], second["confirmation_token"]).status_code == 404
    assert confirm(system["owner"], second["confirmation_token"]).status_code == 200
    assert confirm(system["peer"], second["confirmation_token"]).status_code == 404
    assert "confirmation_token" not in bind(device, registration)
    assert (
        device.post(
            f"/ingest/v1/session-registrations/{registration['id']}/bind",
            json={"external_id": "different-session"},
        ).status_code
        == 409
    )
    st.delete_user(system["tenant"]["id"], system["users"]["owner"]["id"])
    row = st.one(
        "SELECT owner_user_id,verified_at FROM session_registrations WHERE id=$1",
        registration["id"],
    )
    assert row["owner_user_id"] is None and row["verified_at"] is not None
    assert status(device, registration).json()["status"] == "unavailable"
    assert (
        device.post(
            f"/ingest/v1/session-registrations/{registration['id']}/bind",
            json={"external_id": "native-session"},
        ).status_code
        == 404
    )
    assert confirm(system["peer"], second["confirmation_token"]).status_code == 404

    expired = reserve(device)
    challenge = bind(device, expired, "expired-session")
    assert ingest(device, event("expired-session", expired["id"]))["accepted"] == 1
    expired_session = status(device, expired).json()["session_id"]
    st.execute(
        "UPDATE session_registrations SET expires_at=clock_timestamp() WHERE id=$1",
        expired["id"],
    )
    assert confirm(system["peer"], challenge["confirmation_token"]).status_code == 404
    assert status(device, expired).json()["status"] == "expired"
    assert system["peer"].get("/api/v1/me/sessions").json()["items"] == []
    assert (
        system["peer"]
        .get(f"/api/v1/me/sessions/{expired_session}/evidence")
        .status_code
        == 404
    )
    rejected = ingest(device, event("expired-session", expired["id"]))
    assert rejected["accepted"] == 0 and rejected["rejected"][0]["index"] == 0


def test_registered_native_tuple_rejects_spoofed_mixed_events_and_legacy_claims(system):
    st, device = system["db"], system["sensor"]
    legacy = event("legacy-session")
    assert ingest(device, legacy)["accepted"] == 1
    blocked = reserve(device)
    assert (
        device.post(
            f"/ingest/v1/session-registrations/{blocked['id']}/bind",
            json={"external_id": "legacy-session"},
        ).status_code
        == 409
    )
    assert ingest(device, event("legacy-session", blocked["id"]))["accepted"] == 0
    registration = reserve(device)
    bind(device, registration)
    foreign_registration = reserve(system["foreign_sensor"])
    bind(system["foreign_sensor"], foreign_registration)
    good = event("native-session", registration["id"])
    ordinary = event("another-legacy-session")
    batch = [
        {},
        good,
        event("unknown-registration-session", new_id(), user="invalid-user"),
        event("native-session"),
        ordinary,
        event(
            "foreign-registration-session",
            foreign_registration["id"],
            user="foreign-user",
        ),
        event("native-session", registration["id"], product="claude-code"),
        event("different-native-session", registration["id"]),
    ]
    result = ingest(device, *batch)
    assert result["accepted"] == 2 and result["duplicates"] == 0
    assert [item["index"] for item in result["rejected"]] == [0, 2, 3, 5, 6, 7]
    assert all(item["reason"] for item in result["rejected"])
    assert {row["id"] for row in st.many("SELECT id FROM events")} == {
        legacy["id"],
        good["id"],
        ordinary["id"],
    }
    assert {
        row["external_id"] for row in st.many("SELECT external_id FROM agent_sessions")
    } == {"legacy-session", "native-session", "another-legacy-session"}
    assert st.scalar("SELECT count(*) FROM agents") == 1
    legacy_session = st.scalar(
        "SELECT session_id FROM events WHERE id=$1", legacy["id"]
    )
    assert (
        system["peer"].get(f"/api/v1/sessions/{legacy_session}/evidence").status_code
        == 200
    )
    assert (
        system["peer"].get(f"/api/v1/me/sessions/{legacy_session}/evidence").status_code
        == 404
    )


def test_database_rejects_old_writer_scope_bypass_and_rolls_back_inventory(system):
    st, device = system["db"], system["sensor"]
    registration = reserve(device)
    bind(device, registration)
    registered = event("native-session", registration["id"])
    legacy = event("legacy-session", user="legacy-user")
    assert ingest(device, registered, legacy)["accepted"] == 2
    stored = st.one(
        "SELECT agent_id,session_id FROM events WHERE id=$1", registered["id"]
    )
    old = st.one("SELECT agent_id,session_id FROM events WHERE id=$1", legacy["id"])
    for value in (registered, legacy):
        value["text"] = "allowed content update"
        assert (
            st.execute(
                "UPDATE events SET body=$2 WHERE id=$1", value["id"], Jsonb(value)
            )
            == 1
        )
    inventory = st.many("SELECT id,events_total FROM agents ORDER BY id")
    without_tag = copy.deepcopy(registered)
    without_tag["session"].pop("registration_id")
    wrong_native = copy.deepcopy(registered)
    wrong_native["session"]["id"] = "different-native"
    wrong_product = copy.deepcopy(registered)
    wrong_product["agent"]["product"] = "claude-code"
    mutations = [
        ("UPDATE events SET body=$2 WHERE id=$1", registered["id"], Jsonb(without_tag)),
        (
            "UPDATE events SET body=$2 WHERE id=$1",
            registered["id"],
            Jsonb(wrong_native),
        ),
        (
            "UPDATE events SET body=$2 WHERE id=$1",
            registered["id"],
            Jsonb(wrong_product),
        ),
        (
            "UPDATE events SET tenant_id=$2 WHERE id=$1",
            registered["id"],
            system["users"]["foreign"]["tenant_id"],
        ),
        (
            "UPDATE events SET sensor_id=$2 WHERE id=$1",
            registered["id"],
            system["sensors"]["peer_sensor"][0]["id"],
        ),
        ("UPDATE events SET product=$2 WHERE id=$1", registered["id"], "claude-code"),
        (
            "UPDATE events SET agent_id=$2 WHERE id=$1",
            registered["id"],
            old["agent_id"],
        ),
        (
            "UPDATE events SET session_id=$2 WHERE id=$1",
            registered["id"],
            old["session_id"],
        ),
        ("UPDATE events SET body=$2 WHERE id=$1", legacy["id"], Jsonb(registered)),
    ]
    for query, ident, value in mutations:
        with pytest.raises(psycopg.errors.CheckViolation):
            with st.transaction() as conn:
                st.execute(
                    "UPDATE agents SET events_total=events_total+1 WHERE id=$1",
                    stored["agent_id"],
                    conn=conn,
                )
                st.execute(query, ident, value, conn=conn)
        assert st.many("SELECT id,events_total FROM agents ORDER BY id") == inventory
    forked_session = new_id()
    with pytest.raises(psycopg.errors.CheckViolation):
        with st.transaction() as conn:
            st.execute(
                "INSERT INTO agent_sessions(id,tenant_id,agent_id,sensor_id,external_id,product,started_at,last_event_at) "
                "SELECT $1,tenant_id,$2,sensor_id,external_id,product,started_at,last_event_at "
                "FROM agent_sessions WHERE id=$3",
                forked_session,
                old["agent_id"],
                stored["session_id"],
                conn=conn,
            )
            st.execute(
                "INSERT INTO events(id,tenant_id,sensor_id,agent_id,session_id,time,kind,product,body) "
                "SELECT $1,tenant_id,sensor_id,$2,$3,time,kind,product,$4 FROM events WHERE id=$5",
                new_id(),
                old["agent_id"],
                forked_session,
                Jsonb(registered),
                registered["id"],
                conn=conn,
            )
    assert (
        st.scalar("SELECT count(*) FROM agent_sessions WHERE id=$1", forked_session)
        == 0
    )
    assert (
        st.scalar("SELECT body FROM events WHERE id=$1", registered["id"]) == registered
    )
    assert st.scalar("SELECT body FROM events WHERE id=$1", legacy["id"]) == legacy


def wait_for_blocker(st, blocking_pid):
    deadline = time.monotonic() + 5
    while not st.scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
        blocking_pid,
    ):
        assert time.monotonic() < deadline, "request did not reach the database lock"
        time.sleep(0.01)


def test_concurrent_confirmation_has_one_owner(system):
    st, device = system["db"], system["sensor"]
    registration = reserve(device)
    token = bind(device, registration)["confirmation_token"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        with st.transaction() as gate:
            st.one(
                "SELECT id FROM session_registrations WHERE id=$1 FOR UPDATE",
                registration["id"],
                conn=gate,
            )
            blocking_pid = st.scalar("SELECT pg_backend_pid()", conn=gate)
            first = pool.submit(confirm, system["owner"], token)
            second = pool.submit(confirm, system["peer"], token)
            wait_for_blocker(st, blocking_pid)
        replies = [first.result(timeout=5), second.result(timeout=5)]
    assert sorted(reply.status_code for reply in replies) == [200, 404]
    winner = "owner" if replies[0].status_code == 200 else "peer"
    assert (
        st.scalar(
            "SELECT owner_user_id FROM session_registrations WHERE id=$1",
            registration["id"],
        )
        == system["users"][winner]["id"]
    )


def test_confirmation_checks_expiry_after_waiting_for_registration_lock(system):
    st, device = system["db"], system["sensor"]
    registration = reserve(device)
    token = bind(device, registration)["confirmation_token"]
    with ThreadPoolExecutor(max_workers=1) as pool:
        with st.transaction() as gate:
            st.one(
                "SELECT id FROM session_registrations WHERE id=$1 FOR UPDATE",
                registration["id"],
                conn=gate,
            )
            blocking_pid = st.scalar("SELECT pg_backend_pid()", conn=gate)
            pending = pool.submit(confirm, system["owner"], token)
            wait_for_blocker(st, blocking_pid)
            st.execute(
                "UPDATE session_registrations SET expires_at=clock_timestamp() WHERE id=$1",
                registration["id"],
                conn=gate,
            )
        reply = pending.result(timeout=5)
    assert reply.status_code == 404, reply.text
    row = st.one(
        "SELECT owner_user_id,verified_at FROM session_registrations WHERE id=$1",
        registration["id"],
    )
    assert row["owner_user_id"] is None and row["verified_at"] is None


def test_concurrent_legacy_batches_do_not_invert_scope_and_agent_locks(db):
    device = sensor(db, tenant(db)["id"])[0]
    first, second, other = event("native-a"), event("native-b"), event("native-b")
    with ThreadPoolExecutor(max_workers=1) as pool:
        with db.transaction() as writer_a:
            first_result = db.ingest_batch(device, [first], conn=writer_a)
            writer_b = pool.submit(db.ingest_batch, device, [other])
            wait_for_blocker(db, writer_a.info.backend_pid)
            second_result = db.ingest_batch(device, [second], conn=writer_a)
        other_result = writer_b.result(timeout=5)
    assert [
        result["accepted"] for result in (first_result, second_result, other_result)
    ] == [
        1,
        1,
        1,
    ]
    assert {row["id"] for row in db.many("SELECT id FROM events")} == {
        first["id"],
        second["id"],
        other["id"],
    }
    assert db.scalar("SELECT count(*) FROM agents") == 1
    assert db.scalar("SELECT events_total FROM agents") == 3
    assert db.scalar("SELECT count(*) FROM agent_sessions") == 2


def test_rebinding_does_not_invert_ingestion_locks_or_reassign_session(system):
    st, device = system["db"], system["sensor"]
    registration = reserve(device)
    bind(device, registration, "native-a")
    registered = event("native-a", registration["id"])
    legacy = event("native-b")
    with ThreadPoolExecutor(max_workers=1) as pool:
        with st.transaction() as writer:
            first = st.ingest_batch(
                system["sensors"]["sensor"][0], [registered], conn=writer
            )
            rebinding = pool.submit(
                device.post,
                f"/ingest/v1/session-registrations/{registration['id']}/bind",
                json={"external_id": "native-b"},
            )
            wait_for_blocker(st, writer.info.backend_pid)
            second = st.ingest_batch(
                system["sensors"]["sensor"][0], [legacy], conn=writer
            )
        reply = rebinding.result(timeout=5)
    assert first["accepted"] == second["accepted"] == 1
    assert reply.status_code == 409, reply.text
    assert {row["id"] for row in st.many("SELECT id FROM events")} == {
        registered["id"],
        legacy["id"],
    }
    assert st.one(
        "SELECT external_id,owner_user_id,verified_at FROM session_registrations WHERE id=$1",
        registration["id"],
    ) == {"external_id": "native-a", "owner_user_id": None, "verified_at": None}
    assert st.scalar("SELECT count(*) FROM agent_sessions") == 2
    assert (
        st.scalar(
            "SELECT external_id FROM agent_sessions WHERE registration_id=$1",
            registration["id"],
        )
        == "native-a"
    )


@pytest.mark.parametrize("operation", ["bind", "ingest"])
@pytest.mark.parametrize("owner_status", ["active", "disabled"])
def test_registration_rechecks_owner_after_row_lock(system, operation, owner_status):
    st, device = system["db"], system["sensor"]
    registration = reserve(device)
    challenge = bind(device, registration)
    assert confirm(system["owner"], challenge["confirmation_token"]).status_code == 200
    assert ingest(device, event("native-session", registration["id"]))["accepted"] == 1
    verified_at = st.scalar(
        "SELECT verified_at FROM session_registrations WHERE id=$1", registration["id"]
    )
    owner = system["users"]["owner"]
    st.update_user(
        owner["tenant_id"],
        owner["id"],
        status="disabled" if owner_status == "active" else "active",
    )
    observation = event("native-session", registration["id"], user="changed-user")
    path, payload = (
        (
            f"/ingest/v1/session-registrations/{registration['id']}/bind",
            {"external_id": "native-session"},
        )
        if operation == "bind"
        else ("/ingest/v1/events", {"events": [observation]})
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        with st.transaction() as gate:
            st.one(
                "SELECT id FROM session_registrations WHERE id=$1 FOR UPDATE",
                registration["id"],
                conn=gate,
            )
            blocking_pid = st.scalar("SELECT pg_backend_pid()", conn=gate)
            pending = pool.submit(device.post, path, json=payload)
            wait_for_blocker(st, blocking_pid)
            st.update_user(owner["tenant_id"], owner["id"], status=owner_status)
        reply = pending.result(timeout=5)
    if operation == "bind":
        assert reply.status_code == (200 if owner_status == "active" else 404), (
            reply.text
        )
        if owner_status == "active":
            assert reply.json()["status"] == "verified"
            assert "confirmation_token" not in reply.json()
    else:
        assert reply.status_code == 200, reply.text
        assert reply.json()["accepted"] == int(owner_status == "active")
        if owner_status == "disabled":
            assert reply.json()["rejected"][0]["id"] == observation["id"]
    accepted = int(operation == "ingest" and owner_status == "active")
    assert st.scalar("SELECT count(*) FROM events") == 1 + accepted
    assert st.scalar("SELECT count(*) FROM agents") == 1
    assert st.scalar("SELECT events_total FROM agents") == 1 + accepted
    assert st.scalar("SELECT count(*) FROM agent_sessions") == 1
    assert st.scalar("SELECT events_total FROM agent_sessions") == 1 + accepted
    assert (
        st.scalar(
            "SELECT events_total FROM sensor_activity WHERE sensor_id=$1",
            system["sensors"]["sensor"][0]["id"],
        )
        == 1 + accepted
    )
    assert (
        st.scalar(
            "SELECT verified_at FROM session_registrations WHERE id=$1",
            registration["id"],
        )
        == verified_at
    )
