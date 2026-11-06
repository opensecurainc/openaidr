"""Role combinations, revocation, and storage contracts through real HTTP and PostgreSQL."""

from itertools import combinations

import psycopg
import pytest

from openaidr.core.event import new_id
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server.permissions import ROLES, LEGACY_ROLES
from test_server_e2e import system
from test_store import db


@pytest.mark.parametrize("roles", [list(items) for size in (1, 2, 3) for items in combinations(ROLES, size)])
def test_role_combinations_enforce_categories_and_raw_evidence(system, roles):
    client, st, _, unique = system
    tenant = st.create_tenant("Roles", unique)
    user = st.create_user(tenant["id"], unique + "@example.test", "Operator", "unused", roles)
    client.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], tenant["id"]))
    assert client.get("/api/v1/auth/me").json()["user"]["roles"] == roles
    for paths, permitted in (
        (("overview", "inventory/ai-applications", "inventory/components", "inventory/roots", "inventory/attention-history", "telemetry/overview", "settings/support"), True),
        (("users", "users/invites", "audit", "sensors/health", "settings/model-keys", "settings/slack", "settings/session-detection"), "it_admin" in roles),
        (("costs/agents/summary", "credits"), bool(set(roles) & {"it_admin", "security_leadership"})),
        (("events", "events/live", "findings", "user-risk", "guardrail/devices", "detections/rules", "response/policy", "session-investigations", "users/assignees", "users/detection-owners"), "security_analyst" in roles),
    ):
        for path in paths:
            reply = client.get("/api/v1/" + path)
            assert reply.status_code == (200 if permitted else 403), (roles, path, reply.text)
    assert client.get("/api/v1/costs/detections").status_code == (
        410 if set(roles) & {"it_admin", "security_leadership"} else 403)
    for path in ("events/" + new_id(), "telemetry/exports/" + new_id(), "ingestion/retained-records/" + new_id(),
                 "sessions/" + new_id() + "/detection", "session-snapshots/" + new_id(),
                 "session-investigations/" + new_id(), "session-investigation-reads/" + new_id()):
        assert client.get("/api/v1/" + path).status_code == (404 if "security_analyst" in roles else 403)
    for path, permitted in (("/ai-inventory/preview", True), ("/ai-supply-chain/preview", True), ("/ai-skills/preview", True), ("/administration/users", "it_admin" in roles), ("/activity", "security_analyst" in roles), ("/detections/preview", "security_analyst" in roles), ("/guardrail/live/preview", False), ("/guardrail/configuration", "security_analyst" in roles), ("/guardrail/benchmarks", False), ("/detection-quality", False), ("/company-knowledge/preview/policy", "security_analyst" in roles), ("/company-knowledge/preview/guardrails", "security_analyst" in roles), ("/user-risk", "security_analyst" in roles),
                            ("/administration/app", "it_admin" in roles), ("/administration/sensors", "it_admin" in roles),
                            ("/costs/agents", bool(set(roles) & {"it_admin", "security_leadership"})),
                            ("/costs/openaidr", bool(set(roles) & {"it_admin", "security_leadership"})),
                            ("/costs/detections", bool(set(roles) & {"it_admin", "security_leadership"}))):
        assert client.post("/api/v1/audit/page-views", json={"path": path}).status_code == (204 if permitted else 403)
        if not permitted:
            assert client.post("/api/v1/chat", json={"page": {"path": path, "title": "Page", "text": "Visible data", "truncated": False}, "messages": [{"role": "user", "content": "Explain"}]}).status_code == 403
    assert client.post("/api/v1/users/invites", json={"email": "new@example.test", "roles": list(ROLES)}).status_code == (201 if "it_admin" in roles else 403)
    assert client.patch("/api/v1/users/" + user["id"], json={"roles": list(ROLES)}).status_code == (200 if "it_admin" in roles else 403)
    assert client.get("/api/v1/unclassified-endpoint").status_code == 403
    assert client.post("/api/v1/knowledge/mcp/" + new_id() + "/unclassified", json={}).status_code == 403


def test_tenant_name_edit_permissions_validation_isolation_and_audit(system):
    client, st, _, unique = system
    tenant = st.create_tenant("Original name", unique, "team")
    other = st.create_tenant("Other tenant", unique + "-other")
    endpoint = "/api/v1/settings/tenant"
    client.cookies.clear()
    assert client.patch(endpoint, json={"name": "Denied"}).status_code == 401
    for role in ("security_analyst", "security_leadership", "it_admin"):
        user = st.create_user(tenant["id"], role + "@example.test", role, "unused", [role])
        client.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], tenant["id"]))
        reply = client.patch(endpoint, json={"name": "  Acme Research & 开发  "})
        assert reply.status_code == (200 if role == "it_admin" else 403), reply.text
        if role != "it_admin":
            assert st.get_tenant_brief(tenant["id"])["name"] == "Original name"
    assert reply.json() == {"id": tenant["id"], "name": "Acme Research & 开发", "slug": unique}
    assert reply.headers["cache-control"] == "no-store"
    assert client.get("/api/v1/auth/me").json()["user"]["tenant"]["name"] == "Acme Research & 开发"
    request = client.build_request("PATCH", endpoint, json={"name": "No CSRF"})
    del request.headers["X-OpenAIDR-CSRF"]
    assert client.send(request).status_code == 403
    for payload in [
        {}, *[{"name": value} for value in (None, True, 1, [], {}, "", "   ", "x" * 201, "A\x00B", "A\nB")],
        *[{"name": "Denied", key: value} for key, value in (
            ("tenant_id", other["id"]), ("slug", "new-slug"), ("plan", "enterprise"), ("status", "suspended"),
        )],
    ]:
        assert client.patch(endpoint, json=payload).status_code == 400, payload
    saved = st.get_tenant_brief(tenant["id"])
    assert (saved["id"], saved["slug"], saved["plan"], saved["status"], saved["name"]) == (
        tenant["id"], unique, "team", "active", "Acme Research & 开发",
    )
    assert st.get_tenant_brief(other["id"])["name"] == "Other tenant"
    audit = st.one("SELECT actor_id,target_id,details FROM audit_log WHERE tenant_id=$1 AND action='tenant.update'", tenant["id"])
    assert audit == {"actor_id": user["id"], "target_id": tenant["id"], "details": {"name": "Acme Research & 开发"}}
    foreign = st.create_user(other["id"], "foreign@example.test", "Other admin", "unused", ["it_admin"])
    client.cookies.set(CONSOLE_COOKIE, st.create_session(foreign["id"], other["id"]))
    assert client.patch(endpoint, json={"name": "Other renamed"}).json()["id"] == other["id"]
    assert st.get_tenant_brief(tenant["id"])["name"] == saved["name"]


def test_role_updates_revoke_existing_sessions_and_audit_exact_tags(system):
    client, st, _, unique = system
    tenant = st.create_tenant("Roles", unique)
    admin = st.create_user(tenant["id"], "admin@example.test", "Admin", "unused", ["it_admin"])
    subject = st.create_user(tenant["id"], "subject@example.test", "Subject", "unused", list(ROLES))
    admin_session = st.create_session(admin["id"], tenant["id"])
    subject_session = st.create_session(subject["id"], tenant["id"])
    client.cookies.set(CONSOLE_COOKIE, admin_session)
    endpoint = "/api/v1/users/" + subject["id"]
    for payload in ({"roles": []}, {"roles": "it_admin"}, {"roles": ["owner"]}, {"roles": [None]},
                    {"roles": ["it_admin", "it_admin"]}, {"roles": list(ROLES), "role": "owner"}, {"roles": list(ROLES), "tenant_id": "x"}):
        assert client.patch(endpoint, json=payload).status_code == 400, payload
    reply = client.patch(endpoint, json={"roles": ["security_leadership"]})
    assert reply.status_code == 200, reply.text
    assert reply.json()["roles"] == ["security_leadership"]
    audit = st.one("SELECT details FROM audit_log WHERE action='user.update' AND target_id=$1", subject["id"])["details"]
    assert audit["roles_before"] == list(ROLES)
    assert audit["roles_after"] == ["security_leadership"]
    client.cookies.set(CONSOLE_COOKIE, subject_session)
    assert client.get("/api/v1/auth/me").json()["user"]["roles"] == ["security_leadership"]
    assert client.get("/api/v1/events").status_code == 403
    assert client.patch(endpoint, json={"roles": list(ROLES)}).status_code == 403
    client.cookies.set(CONSOLE_COOKIE, admin_session)
    assert client.patch("/api/v1/users/" + admin["id"], json={"roles": ["security_leadership"]}).status_code == 409
    assert client.patch(endpoint, json={"roles": list(reversed(ROLES))}).json()["roles"] == list(ROLES)
    assert client.patch("/api/v1/users/" + admin["id"], json={"roles": ["security_leadership"]}).status_code == 200
    assert client.get("/api/v1/users").status_code == 403


def test_multiple_invitation_roles_survive_acceptance(system):
    client, st, _, unique = system
    tenant = st.create_tenant("Roles", unique)
    user = st.create_user(tenant["id"], "admin@example.test", "Admin", "unused", ["it_admin"])
    client.cookies.set(CONSOLE_COOKIE, st.create_session(user["id"], tenant["id"]))
    for i, roles in enumerate((["it_admin", "security_analyst"], list(ROLES))):
        invite = client.post("/api/v1/users/invites", json={"email": f"new-{i}@example.test", "roles": roles})
        assert invite.status_code == 201, invite.text
        data = invite.json()
        assert data["roles"] == roles
        preview = client.get("/api/v1/auth/invite", params={"token": data["token"]})
        assert preview.json()["roles"] == roles
        accepted = client.post("/api/v1/auth/accept-invite", json={"token": data["token"], "name": "New user", "password": "password123"})
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["user"]["roles"] == roles


def test_role_migration_preserves_accounts_sessions_and_pending_invites(db):
    # Recreate the previous schema for the two affected tables before migration.
    for table, trigger in (("tenant_users", "tenant_user_roles"), ("invites", "invitation_roles")):
        db.execute(f"DROP TRIGGER {trigger} ON {table}")
        db.execute(f"ALTER TABLE {table} DROP COLUMN roles")
    db.execute("DROP FUNCTION synchronize_tenant_roles()")
    db.execute("DELETE FROM schema_migrations WHERE version=78")
    tenant = db.create_tenant("Migration", "role-migration")
    ids, tokens = {}, {}
    for role in LEGACY_ROLES:
        ident = new_id()
        db.execute("INSERT INTO tenant_users(id,tenant_id,email,name,password_hash,role) VALUES($1,$2,$3,'User','unused',$4)",
                   ident, tenant["id"], role + "@example.test", role)
        db.execute("INSERT INTO invites(id,tenant_id,token_hash,email,role,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 day')",
                   new_id(), tenant["id"], role, "invite-" + role + "@example.test", role)
        ids[role] = ident
        tokens[role] = db.create_session(ident, tenant["id"])
    assert db.migrate() == ["0078_dashboard_role_tags.sql"]
    assert db.migrate() == []
    for legacy, roles in LEGACY_ROLES.items():
        assert db.get_session(tokens[legacy])["user"]["roles"] == roles
        assert db.get_user(tenant["id"], ids[legacy])["role"] == legacy
        invite = db.one("SELECT * FROM invites WHERE token_hash=$1", legacy)
        assert db.accept_invite(invite, "Invited", "unused")["roles"] == roles
    db.execute("UPDATE tenant_users SET role='analyst' WHERE id=$1", ids["viewer"])
    assert db.get_user(tenant["id"], ids["viewer"])["roles"] == ["security_analyst"]
    for invalid in ([], ["unknown"], ["it_admin", "it_admin"], ["security_analyst", "it_admin"], [None]):
        with pytest.raises(psycopg.errors.CheckViolation):
            db.execute("UPDATE tenant_users SET roles=$1 WHERE id=$2", invalid, ids["viewer"])
