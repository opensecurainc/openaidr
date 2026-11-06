import json

from fastapi.testclient import TestClient

from openaidr.server import auth
from openaidr.server.app import create_app
from openaidr.server.config import Config
from test_store import db, new_id, tenant


def source(revision=0):
    return {
        "revision": revision,
        "source_id": "omg-reference",
        "source_version": "1",
        "title": "OMG operations",
        "source_uri": "wiki://tools/omg",
        "scope_key": "",
        "kind": "command",
        "markdown": "# Drain\n\nThe omg drain operation drains a network zone.",
        "keys": [{
            "key_type": "operation", "lookup_value": "omg drain",
            "canonical_key": "omg drain",
        }],
    }


def test_import_api_authorization_tenant_isolation_and_revisions(db):
    first, other = tenant(db), tenant(db)
    cfg = Config()
    cfg.set_services("api")
    with TestClient(create_app(cfg, db), headers={auth.CSRF_HEADER: "1"}) as client:
        assert client.get("/api/v1/knowledge/sources").status_code == 401
        sessions = {}
        for tid, role in ((first["id"], "analyst"), (first["id"], "viewer"), (other["id"], "analyst")):
            user = db.create_user(tid, new_id() + "@test.invalid", role, "hash", role)
            sessions[tid, role] = db.create_session(user["id"], tid)

        client.cookies.set(auth.CONSOLE_COOKIE, sessions[first["id"], "analyst"])
        initial = client.get("/api/v1/knowledge/retrieval").json()
        assert initial["retrieval_mode"] == "legacy"
        denied = client.post("/api/v1/knowledge/sources", headers={auth.CSRF_HEADER: ""}, json=source())
        assert denied.status_code == 403
        result = client.post("/api/v1/knowledge/sources", json=source())
        assert result.status_code == 200, result.text
        imported = result.json()
        assert imported["passages"]
        assert imported["passages"][0]["keys"] == [dict(source()["keys"][0], scope_key="")]
        assert client.get("/api/v1/knowledge/sources/omg-reference").json() == imported
        assert client.post("/api/v1/knowledge/sources", json=source()).status_code == 409
        assert client.post("/api/v1/knowledge/sources/omg-reference/purge", json={
            "revision": imported["revision"],
        }).status_code == 409

        mode = client.put("/api/v1/knowledge/retrieval", json={
            "revision": imported["revision"], "retrieval_mode": "postgres",
        })
        assert mode.status_code == 200, mode.text
        revision = mode.json()["revision"]
        assert mode.json()["retrieval_mode"] == "postgres"
        assert client.get("/api/v1/knowledge").json()["documents"] == []

        client.cookies.set(auth.CONSOLE_COOKIE, sessions[first["id"], "viewer"])
        assert client.get("/api/v1/knowledge/sources/omg-reference").status_code == 403
        for path, payload in (
            ("knowledge/sources", source(revision)),
            ("knowledge/sources/omg-reference/revoke", {"revision": revision}),
            ("knowledge/sources/omg-reference/purge", {"revision": revision}),
        ):
            assert client.post("/api/v1/" + path, json=payload).status_code == 403
        assert client.put("/api/v1/knowledge/retrieval", json={
            "revision": revision, "retrieval_mode": "legacy",
        }).status_code == 403

        client.cookies.set(auth.CONSOLE_COOKIE, sessions[other["id"], "analyst"])
        assert client.get("/api/v1/knowledge/sources").json()["sources"] == []
        assert client.get("/api/v1/knowledge/sources/omg-reference").status_code == 404
        assert client.post("/api/v1/knowledge/sources/omg-reference/purge", json={"revision": 0}).status_code == 404
        assert client.post("/api/v1/knowledge/sources", json={
            **source(), "tenant_id": first["id"],
        }).status_code == 400

        client.cookies.set(auth.CONSOLE_COOKIE, sessions[first["id"], "analyst"])
        revoked = client.post("/api/v1/knowledge/sources/omg-reference/revoke", json={
            "revision": revision,
        })
        assert revoked.status_code == 200, revoked.text
        assert revoked.json()["passages"] == []
        assert imported["passages"]
        purge = "/api/v1/knowledge/sources/omg-reference/purge"
        assert client.post(purge, headers={auth.CSRF_HEADER: ""}, json={
            "revision": revoked.json()["revision"],
        }).status_code == 403
        assert client.post(purge, json={"revision": revision}).status_code == 409
        purged = client.post(purge, json={"revision": revoked.json()["revision"]})
        assert purged.status_code == 200, purged.text
        assert purged.json() == {"revision": revoked.json()["revision"] + 1,
                                 "source_id": "omg-reference", "purged": True}
        assert client.get("/api/v1/knowledge/sources/omg-reference").status_code == 404
        assert client.get("/api/v1/knowledge/sources").json()["sources"] == []
        rows, _ = db.list_audit(first["id"])
        actions = {row["action"] for row in rows}
        assert actions == {"knowledge.source.import", "knowledge.retrieval.update",
                           "knowledge.source.revoke", "knowledge.source.purge"}
        assert "drains a network zone" not in json.dumps(rows, default=str)
