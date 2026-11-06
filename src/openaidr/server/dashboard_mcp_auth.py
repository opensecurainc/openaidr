"""Tenant-approved MCP clients, browser consent, and revocable OAuth grants."""

import hashlib
import math
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import anyio
from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizeError, RefreshToken, RegistrationError,
    TokenError, construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from psycopg.types.json import Jsonb

from .httpx import APIError, require
from .dashboard_mcp_lifecycle import request_deadline
from .permissions import ROLES, assigned_roles
from .store import NotFound, new_id, valid_uuid
from .dashboard_mcp_lifecycle import disable_deployment  # noqa: F401


SCOPES = (
    ("overview:read", "Overview", "Read activity, coverage, and risk summaries.", ROLES),
    ("inventory:read", "AI inventory", "Read AI applications, components, and skills.", ROLES),
    ("detections:read", "Detections", "Read findings, cases, and detection status.", ("security_analyst",)),
    ("evidence:read", "Captured evidence", "Read bounded captured session evidence, which may contain sensitive data.", ("security_analyst",)),
    ("guardrail:read", "Guardrail", "Read Guardrail decisions and configuration.", ("security_analyst",)),
    ("knowledge:read", "Company knowledge", "Read company policy and knowledge content.", ("security_analyst",)),
    ("costs:read", "Costs", "Read usage and cost estimates.", ("it_admin", "security_leadership")),
    ("administration:read", "Administration", "Read health and sanitized administration status.", ("it_admin",)),
    ("triage:write", "Finding triage", "Change finding status or add analyst notes.", ("security_analyst",)),
    ("configuration:propose", "Configuration proposals", "Propose configuration changes for separate dashboard approval.", ("it_admin", "security_analyst")),
)
SCOPE_IDS = tuple(item[0] for item in SCOPES)
READ_SCOPES = [scope for scope in SCOPE_IDS if scope.endswith(":read")]
DEFAULT_SCOPES = [scope for scope in READ_SCOPES if scope != "evidence:read"]
ACCESS_SECONDS = 600
GRANT_SECONDS = 20 * 60 * 60
REQUEST_SECONDS = 300
CODE_SECONDS = 120
HANDLE = re.compile(r"[A-Za-z0-9_-]{43}")
CLIENT_COLUMNS = "id,name,redirect_uris,scopes,created_at,revoked_at"


class _OAuthFailure(Exception):
    # The SDK's frozen exception dataclasses cannot cross contextlib transactions.
    def __init__(self, error, description):
        self.error, self.description = error, description
        super().__init__(description)


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _now():
    return datetime.now(timezone.utc)


def _provider_deadline():
    deadline = request_deadline.get()
    if deadline is not None and (type(deadline) not in (int, float) or not math.isfinite(deadline)
                                 or time.monotonic() >= deadline):
        raise TimeoutError("MCP request deadline expired")


def _available(user=None):
    roles = set(assigned_roles(user)) if user is not None else set(ROLES)
    return [dict(id=scope, label=label, description=description, roles=list(allowed))
            for scope, label, description, allowed in SCOPES if roles.intersection(allowed)]


def _scopes(value, *, empty=False):
    require(isinstance(value, list) and (empty or value) and len(value) <= len(SCOPE_IDS)
            and all(isinstance(item, str) and item in SCOPE_IDS for item in value)
            and len(set(value)) == len(value), "invalid MCP scopes")
    return [scope for scope in SCOPE_IDS if scope in value]


def _browser(cfg, principal, *, admin=False):
    tenant, user = principal["tenant"], principal["user"]
    require(bool(cfg.tenant_id) and tenant["id"] == cfg.tenant_id
            and user["tenant_id"] == cfg.tenant_id, "MCP tenant mismatch", 403)
    require(tenant["status"] == "active" and user["status"] == "active"
            and bool(assigned_roles(user)), "MCP access is unavailable", 403)
    if admin:
        require("it_admin" in assigned_roles(user), "IT administrator role required", 403)


def validate_browser(st, cfg, principal, *, conn, admin=False):
    """Refresh browser authority under the transaction that performs its action."""
    deadline = principal.get("mcp_deadline")
    require(deadline is None or (type(deadline) in (int, float) and math.isfinite(deadline)
                               and time.monotonic() < deadline), "MCP request deadline expired", 503)
    require(valid_uuid(principal.get("session_id", "")), "browser session expired", 401)
    tenant = st.one("SELECT * FROM tenants WHERE id=$1 FOR SHARE", cfg.tenant_id, conn=conn)
    st.one("SELECT id FROM tenant_users WHERE tenant_id=$1 AND id=$2 FOR SHARE",
           cfg.tenant_id, principal["user"]["id"], conn=conn)
    user = st.get_user(cfg.tenant_id, principal["user"]["id"], conn=conn)
    current = {**principal, "tenant": tenant, "user": user}
    _browser(cfg, current, admin=admin)
    sessions = st.many("SELECT * FROM auth_sessions WHERE id=$1 AND tenant_id=$2 AND user_id=$3 "
                       "AND expires_at>clock_timestamp() FOR SHARE", principal["session_id"], cfg.tenant_id,
                       user["id"], conn=conn)
    require(bool(sessions), "browser session expired", 401)
    session = sessions[0]
    require(session["expires_at"] > _now(), "browser session expired", 401)
    if cfg.auth_mode == "cloud_google":
        from openaidr.platform.cloud_identity import SESSION_MAX_SECONDS

        require(session["oidc_issuer"] == cfg.oidc_issuer and session["verified_at"] is not None
                and session["verified_at"] + timedelta(seconds=SESSION_MAX_SECONDS) > _now(),
                "browser session expired", 401)
    else:
        require(not session["oidc_issuer"], "browser session expired", 401)
    require(deadline is None or time.monotonic() < deadline, "MCP request deadline expired", 503)
    return current


def _settings(st, cfg, conn, *, lock="SHARE", create=False):
    if create:
        st.execute("INSERT INTO dashboard_mcp_settings(tenant_id,allowed_scopes,revision) "
                   "VALUES($1,$2,0) ON CONFLICT DO NOTHING", cfg.tenant_id, DEFAULT_SCOPES, conn=conn)
    rows = st.many("SELECT enabled,allowed_scopes,revision FROM dashboard_mcp_settings "
                   "WHERE tenant_id=$1 FOR " + lock, cfg.tenant_id, conn=conn)
    return rows[0] if rows else dict(enabled=False, allowed_scopes=DEFAULT_SCOPES.copy(), revision=0)


def _require_enabled(cfg, settings):
    require(getattr(cfg, "dashboard_mcp_enabled", False) and settings["enabled"], "MCP access is disabled", 403)


def _cleanup(st, tenant, conn):
    st.execute("DELETE FROM dashboard_mcp_authorizations WHERE tenant_id=$1 "
               "AND expires_at<clock_timestamp()-interval '1 day'", tenant, conn=conn)
    st.execute("DELETE FROM dashboard_mcp_grants WHERE tenant_id=$1 "
               "AND (expires_at<clock_timestamp()-interval '1 day' OR revoked_at<clock_timestamp()-interval '1 day')",
               tenant, conn=conn)
    st.execute("DELETE FROM dashboard_mcp_clients c WHERE tenant_id=$1 "
               "AND revoked_at<clock_timestamp()-interval '1 day' "
               "AND NOT EXISTS (SELECT 1 FROM dashboard_mcp_grants g WHERE (g.tenant_id,g.client_id)=(c.tenant_id,c.id)) "
               "AND NOT EXISTS (SELECT 1 FROM dashboard_mcp_authorizations a WHERE (a.tenant_id,a.client_id)=(c.tenant_id,c.id))",
               tenant, conn=conn)


def _audit(st, tenant, user, action, target, ident, details, conn, *, actor_type="user"):
    st.execute("INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details) "
               "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", new_id(), tenant, actor_type, user["id"], user["name"],
               action, target, ident, Jsonb(details), conn=conn)


def _settings_response(cfg, value):
    return {**value, "deployment_enabled": bool(getattr(cfg, "dashboard_mcp_enabled", False)),
            "available_scopes": _available()}


def get_settings(st, cfg, principal):
    _browser(cfg, principal, admin=True)
    with st.transaction(auth=True) as conn:
        value = _settings(st, cfg, conn)
        validate_browser(st, cfg, principal, conn=conn, admin=True)
        return _settings_response(cfg, value)


def update_settings(st, cfg, principal, data):
    _browser(cfg, principal, admin=True)
    require(set(data) == {"revision", "enabled", "allowed_scopes"}
            and type(data["revision"]) is int and type(data["enabled"]) is bool, "invalid MCP settings")
    scopes = _scopes(data["allowed_scopes"], empty=True)
    require(not data["enabled"] or (getattr(cfg, "dashboard_mcp_enabled", False) and scopes),
            "MCP deployment and at least one scope must be enabled")
    with st.transaction(auth=True) as conn:
        current = _settings(st, cfg, conn, lock="UPDATE", create=True)
        principal = validate_browser(st, cfg, principal, conn=conn, admin=True)
        require(current["revision"] == data["revision"], "MCP settings changed; reload before saving", 409)
        st.execute("UPDATE dashboard_mcp_settings SET enabled=$2,allowed_scopes=$3,revision=revision+1 "
                   "WHERE tenant_id=$1", cfg.tenant_id, data["enabled"], scopes, conn=conn)
        # Scope removal and disable revoke grants permanently, including their refresh tokens.
        st.execute("UPDATE dashboard_mcp_grants SET revoked_at=clock_timestamp() WHERE tenant_id=$1 "
                   "AND revoked_at IS NULL AND (NOT $2 OR NOT scopes <@ $3::text[])",
                   cfg.tenant_id, data["enabled"], scopes, conn=conn)
        _audit(st, cfg.tenant_id, principal["user"], "mcp.settings.update", "mcp_settings", cfg.tenant_id,
               {"enabled": data["enabled"], "allowed_scopes": scopes}, conn)
        validate_browser(st, cfg, principal, conn=conn, admin=True)
        return _settings_response(cfg, _settings(st, cfg, conn))


def _redirect(value):
    require(isinstance(value, str) and 0 < len(value) <= 2048
            and all(32 < ord(char) < 127 for char in value) and "\\" not in value,
            "invalid redirect URI")
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError:
        raise APIError(400, "invalid redirect URI") from None
    require(parsed.hostname and not parsed.username and not parsed.password and not parsed.fragment
            and (parsed.scheme == "https" or
                 (parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "[::1]", "::1", "localhost")))
            and not any(char in parsed.netloc for char in ("%", "*")), "redirect URI must use HTTPS or loopback HTTP")
    # Store the exact canonical form used by the SDK so matching never broadens a registered URI.
    from pydantic import AnyUrl, TypeAdapter

    canonical = str(TypeAdapter(AnyUrl).validate_python(value))
    require(canonical == value, "redirect URI must use its canonical URL form")
    return value


def list_clients(st, cfg, principal):
    _browser(cfg, principal, admin=True)
    with st.transaction(auth=True) as conn:
        value = _settings(st, cfg, conn)
        validate_browser(st, cfg, principal, conn=conn, admin=True)
        return {**_settings_response(cfg, value), "items": st.many(
            f"SELECT {CLIENT_COLUMNS} FROM dashboard_mcp_clients WHERE tenant_id=$1 "
            "ORDER BY created_at DESC LIMIT 100", cfg.tenant_id, conn=conn)}


def create_client(st, cfg, principal, data):
    _browser(cfg, principal, admin=True)
    require(set(data) == {"name", "redirect_uris", "scopes"}, "invalid MCP client fields")
    name = data["name"]
    require(isinstance(name, str) and name == name.strip() and 0 < len(name) <= 100
            and all(ord(char) >= 32 and ord(char) != 127 for char in name), "invalid MCP client name")
    uris = data["redirect_uris"]
    require(isinstance(uris, list) and 1 <= len(uris) <= 8, "register one to eight redirect URIs")
    uris = [_redirect(uri) for uri in uris]
    require(len(set(uris)) == len(uris), "register distinct redirect URIs")
    scopes = _scopes(data["scopes"])
    with st.transaction(auth=True) as conn:
        settings = _settings(st, cfg, conn, lock="UPDATE", create=True)
        principal = validate_browser(st, cfg, principal, conn=conn, admin=True)
        _cleanup(st, cfg.tenant_id, conn)
        require(set(scopes) <= set(settings["allowed_scopes"]), "client scopes exceed tenant policy")
        require(st.scalar("SELECT count(*) FROM dashboard_mcp_clients WHERE tenant_id=$1 AND revoked_at IS NULL",
                          cfg.tenant_id, conn=conn) < 32, "at most 32 active MCP clients are supported", 409)
        require(st.scalar("SELECT count(*) FROM dashboard_mcp_clients WHERE tenant_id=$1",
                          cfg.tenant_id, conn=conn) < 100, "too many recently registered MCP clients", 429)
        ident = new_id()
        st.execute("INSERT INTO dashboard_mcp_clients(tenant_id,id,name,redirect_uris,scopes) VALUES($1,$2,$3,$4,$5)",
                   cfg.tenant_id, ident, name, uris, scopes, conn=conn)
        _audit(st, cfg.tenant_id, principal["user"], "mcp.client.create", "mcp_client", ident,
               {"name": name, "scopes": scopes, "redirect_uris": uris}, conn)
        validate_browser(st, cfg, principal, conn=conn, admin=True)
        return {"client": st.one(f"SELECT {CLIENT_COLUMNS} FROM dashboard_mcp_clients WHERE tenant_id=$1 AND id=$2",
                                 cfg.tenant_id, ident, conn=conn)}


def revoke_client(st, cfg, principal, ident):
    _browser(cfg, principal, admin=True)
    require(valid_uuid(ident), "invalid client id")
    with st.transaction(auth=True) as conn:
        _settings(st, cfg, conn)
        st.one("SELECT id FROM dashboard_mcp_clients WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
               cfg.tenant_id, ident, conn=conn)
        principal = validate_browser(st, cfg, principal, conn=conn, admin=True)
        st.execute("UPDATE dashboard_mcp_clients SET revoked_at=COALESCE(revoked_at,clock_timestamp()) "
                   "WHERE tenant_id=$1 AND id=$2", cfg.tenant_id, ident, conn=conn)
        st.execute("UPDATE dashboard_mcp_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()) "
                   "WHERE tenant_id=$1 AND client_id=$2", cfg.tenant_id, ident, conn=conn)
        _audit(st, cfg.tenant_id, principal["user"], "mcp.client.revoke", "mcp_client", ident, {}, conn)
        validate_browser(st, cfg, principal, conn=conn, admin=True)
    return {"revoked": True}


def list_grants(st, cfg, principal, *, limit=50, offset=0):
    _browser(cfg, principal)
    values = []
    for value, minimum, maximum in ((limit, 1, 100), (offset, 0, 1000000)):
        require(type(value) is int or (isinstance(value, str) and re.fullmatch(r"[0-9]{1,7}", value)),
                "invalid grant pagination")
        value = int(value)
        require(minimum <= value <= maximum, "invalid grant pagination")
        values.append(value)
    limit, offset = values
    with st.transaction(auth=True) as conn:
        principal = validate_browser(st, cfg, principal, conn=conn)
        rows = st.many("SELECT g.id,g.client_id,c.name AS client_name,g.user_id,u.name AS user_name,"
                             "g.scopes,g.created_at,g.expires_at,g.revoked_at FROM dashboard_mcp_grants g "
                             "JOIN dashboard_mcp_clients c ON (c.tenant_id,c.id)=(g.tenant_id,g.client_id) "
                             "JOIN tenant_users u ON (u.tenant_id,u.id)=(g.tenant_id,g.user_id) "
                             "WHERE g.tenant_id=$1 AND ($2 OR g.user_id=$3) ORDER BY g.created_at DESC,g.id DESC LIMIT $4 OFFSET $5",
                             cfg.tenant_id, "it_admin" in assigned_roles(principal["user"]), principal["user"]["id"],
                             limit + 1, offset, conn=conn)
        return {"items": rows[:limit], "next_offset": offset + limit if len(rows) > limit else None}


def _grant_rows(st, cfg, ident, conn):
    require(valid_uuid(ident), "invalid MCP grant", 401)
    settings = _settings(st, cfg, conn)
    grant = st.one("SELECT * FROM dashboard_mcp_grants WHERE tenant_id=$1 AND id=$2", cfg.tenant_id, ident, conn=conn)
    client = st.one("SELECT * FROM dashboard_mcp_clients WHERE tenant_id=$1 AND id=$2 FOR SHARE",
                    cfg.tenant_id, grant["client_id"], conn=conn)
    grant = st.one("SELECT * FROM dashboard_mcp_grants WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                   cfg.tenant_id, ident, conn=conn)
    return settings, client, grant


def validate_grant(st, cfg, grant_id, *, conn=None):
    if conn is None:
        with st.transaction(auth=True) as connection:
            return validate_grant(st, cfg, grant_id, conn=connection)
    try:
        settings, client, grant = _grant_rows(st, cfg, grant_id, conn)
        _require_enabled(cfg, settings)
        require(not client["revoked_at"] and not grant["revoked_at"] and grant["expires_at"] > _now()
                and grant["resource"] == cfg.browser_origin() + "/mcp",
                "MCP grant is unavailable", 401)
        tenant = st.one("SELECT * FROM tenants WHERE id=$1 FOR SHARE", cfg.tenant_id, conn=conn)
        st.one("SELECT id FROM tenant_users WHERE tenant_id=$1 AND id=$2 FOR SHARE",
               cfg.tenant_id, grant["user_id"], conn=conn)
        user = st.get_user(cfg.tenant_id, grant["user_id"], conn=conn)
        _browser(cfg, {"tenant": tenant, "user": user})
        allowed = set(settings["allowed_scopes"]) & set(client["scopes"]) & {item["id"] for item in _available(user)}
        scopes = [scope for scope in grant["scopes"] if scope in allowed]
        require(scopes, "MCP grant has no current permissions", 403)
        require(grant["expires_at"] > _now(), "MCP grant is unavailable", 401)
        return dict(tenant=tenant, user=user, client_id=client["id"], grant_id=grant["id"], scopes=scopes)
    except NotFound:
        raise APIError(401, "MCP grant is unavailable") from None


def revoke_grant(st, cfg, principal, ident):
    _browser(cfg, principal)
    with st.transaction(auth=True) as conn:
        _, _, grant = _grant_rows(st, cfg, ident, conn)
        principal = validate_browser(st, cfg, principal, conn=conn)
        require(grant["user_id"] == principal["user"]["id"] or "it_admin" in assigned_roles(principal["user"]),
                "MCP grant is unavailable", 404)
        st.execute("UPDATE dashboard_mcp_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()) "
                   "WHERE tenant_id=$1 AND id=$2", cfg.tenant_id, ident, conn=conn)
        _audit(st, cfg.tenant_id, principal["user"], "mcp.grant.revoke", "mcp_grant", ident, {}, conn)
        validate_browser(st, cfg, principal, conn=conn)
    return {"revoked": True}


def _authorization(st, cfg, principal, request_id, conn):
    _browser(cfg, principal)
    require(isinstance(request_id, str) and HANDLE.fullmatch(request_id), "invalid authorization request", 404)
    settings = _settings(st, cfg, conn)
    _require_enabled(cfg, settings)
    row = st.one("SELECT * FROM dashboard_mcp_authorizations WHERE tenant_id=$1 AND request_hash=$2",
                 cfg.tenant_id, _hash(request_id), conn=conn)
    client = st.one("SELECT * FROM dashboard_mcp_clients WHERE tenant_id=$1 AND id=$2 FOR SHARE",
                    cfg.tenant_id, row["client_id"], conn=conn)
    row = st.one("SELECT * FROM dashboard_mcp_authorizations WHERE tenant_id=$1 AND request_hash=$2 FOR UPDATE",
                 cfg.tenant_id, _hash(request_id), conn=conn)
    principal = validate_browser(st, cfg, principal, conn=conn)
    require(row["expires_at"] > _now() and row["status"] == "pending" and not client["revoked_at"],
            "authorization request is unavailable", 404)
    require(principal.get("session_id") and (row["session_id"] is None or row["session_id"] == principal["session_id"]),
            "authorization request belongs to another browser session", 403)
    allowed = set(settings["allowed_scopes"]) & set(client["scopes"]) & {item["id"] for item in _available(principal["user"])}
    scopes = [scope for scope in row["scopes"] if scope in allowed]
    require(scopes, "no requested MCP permissions are available", 403)
    return row, client, scopes


def get_authorization(st, cfg, principal, request_id):
    with st.transaction(auth=True) as conn:
        row, client, scopes = _authorization(st, cfg, principal, request_id, conn)
        st.execute("UPDATE dashboard_mcp_authorizations SET session_id=$3,user_id=$4 "
                   "WHERE tenant_id=$1 AND request_hash=$2", cfg.tenant_id, _hash(request_id),
                   principal["session_id"], principal["user"]["id"], conn=conn)
        validate_browser(st, cfg, principal, conn=conn)
        return dict(client=dict(id=client["id"], name=client["name"], redirect_uri=row["redirect_uri"]),
                    scopes=[item for item in _available(principal["user"]) if item["id"] in scopes],
                    expires_at=row["expires_at"], request_id=request_id)


def decide_authorization(st, cfg, principal, request_id, data):
    require(set(data) == {"approve", "scopes"} and type(data["approve"]) is bool, "invalid authorization decision")
    scopes = _scopes(data["scopes"], empty=not data["approve"])
    with st.transaction(auth=True) as conn:
        row, client, allowed = _authorization(st, cfg, principal, request_id, conn)
        require(row["session_id"] == principal["session_id"] and row["user_id"] == principal["user"]["id"],
                "review authorization before deciding", 403)
        require(set(scopes) <= set(allowed), "requested scopes are not available", 403)
        if not data["approve"]:
            st.execute("UPDATE dashboard_mcp_authorizations SET status='denied' WHERE request_hash=$1",
                       _hash(request_id), conn=conn)
            _audit(st, cfg.tenant_id, principal["user"], "mcp.grant.deny", "mcp_client", client["id"], {}, conn)
            validate_browser(st, cfg, principal, conn=conn)
            return {"redirect_url": construct_redirect_uri(row["redirect_uri"], error="access_denied", state=row["state"],
                                                            iss=cfg.browser_origin())}
        require(st.scalar("SELECT count(*) FROM dashboard_mcp_grants WHERE tenant_id=$1 AND user_id=$2 "
                          "AND revoked_at IS NULL AND expires_at>clock_timestamp()", cfg.tenant_id,
                          principal["user"]["id"], conn=conn) < 128, "too many active MCP grants", 409)
        grant_id, code = new_id(), secrets.token_urlsafe(32)
        st.execute("INSERT INTO dashboard_mcp_grants(tenant_id,id,client_id,user_id,resource,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
                   cfg.tenant_id, grant_id, client["id"], principal["user"]["id"], row["resource"], scopes,
                   _now() + timedelta(seconds=GRANT_SECONDS), conn=conn)
        st.execute("UPDATE dashboard_mcp_authorizations SET status='approved',scopes=$2,code_hash=$3,grant_id=$4,expires_at=$5 "
                   "WHERE request_hash=$1", _hash(request_id), scopes, _hash(code), grant_id,
                   _now() + timedelta(seconds=CODE_SECONDS), conn=conn)
        _audit(st, cfg.tenant_id, principal["user"], "mcp.grant.create", "mcp_grant", grant_id,
               {"client_id": client["id"], "scopes": scopes}, conn)
        validate_browser(st, cfg, principal, conn=conn)
        return {"redirect_url": construct_redirect_uri(row["redirect_uri"], code=code, state=row["state"],
                                                        iss=cfg.browser_origin())}


class DashboardMCPAuth:
    """OAuth provider for pre-approved public clients using mandatory S256 PKCE."""

    def __init__(self, st, cfg, *, run=None):
        self.st, self.cfg = st, cfg
        self.resource = cfg.browser_origin() + "/mcp"
        self.run = run

    async def _run(self, operation, *args):
        def guarded():
            _provider_deadline()
            return operation(*args)

        if self.run is not None:
            return await self.run(guarded)
        return await anyio.to_thread.run_sync(guarded)

    def _client(self, client_id):
        if not isinstance(client_id, str) or not valid_uuid(client_id):
            return None
        with self.st.transaction(auth=True) as conn:
            settings = _settings(self.st, self.cfg, conn)
            if not getattr(self.cfg, "dashboard_mcp_enabled", False) or not settings["enabled"]:
                return None
            rows = self.st.many("SELECT * FROM dashboard_mcp_clients WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL",
                                self.cfg.tenant_id, client_id, conn=conn)
            if not rows:
                return None
            row = rows[0]
            return OAuthClientInformationFull(client_id=row["id"], client_name=row["name"],
                redirect_uris=row["redirect_uris"], token_endpoint_auth_method="none",
                grant_types=["authorization_code", "refresh_token"], response_types=["code"],
                scope=" ".join(scope for scope in row["scopes"] if scope in settings["allowed_scopes"]))

    async def get_client(self, client_id):
        return await self._run(self._client, client_id)

    async def register_client(self, client_info):
        raise RegistrationError("invalid_client_metadata", "An IT administrator must approve the MCP client")

    def _authorize(self, client, params):
        _provider_deadline()
        if params.resource != self.resource:
            raise AuthorizeError("invalid_target", "Use this tenant's MCP resource URL")
        if not params.redirect_uri_provided_explicitly or not HANDLE.fullmatch(params.code_challenge):
            raise AuthorizeError("invalid_request", "An explicit redirect URI and S256 challenge are required")
        if params.state is not None and (len(params.state) > 2048 or any(ord(c) < 32 for c in params.state)):
            raise AuthorizeError("invalid_request", "Invalid state")
        with self.st.transaction(auth=True) as conn:
            settings = _settings(self.st, self.cfg, conn, lock="UPDATE")
            _require_enabled(self.cfg, settings)
            current = self.st.one("SELECT * FROM dashboard_mcp_clients WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL FOR SHARE",
                                 self.cfg.tenant_id, client.client_id, conn=conn)
            scopes = params.scopes if params.scopes is not None else [scope for scope in current["scopes"] if scope in READ_SCOPES]
            if (not scopes or not set(scopes) <= set(current["scopes"]) & set(settings["allowed_scopes"])
                    or str(params.redirect_uri) not in current["redirect_uris"]):
                raise _OAuthFailure("invalid_scope", "Requested access is not approved for this client")
            _provider_deadline()
            _cleanup(self.st, self.cfg.tenant_id, conn)
            if self.st.scalar("SELECT count(*) FROM dashboard_mcp_authorizations WHERE tenant_id=$1 AND expires_at>clock_timestamp()",
                              self.cfg.tenant_id, conn=conn) >= 256:
                raise _OAuthFailure("temporarily_unavailable", "Too many pending authorizations")
            request_id = secrets.token_urlsafe(32)
            _provider_deadline()
            self.st.execute("INSERT INTO dashboard_mcp_authorizations(request_hash,tenant_id,client_id,scopes,redirect_uri,resource,state,"
                            "code_challenge,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                            _hash(request_id), self.cfg.tenant_id, client.client_id, scopes, str(params.redirect_uri), self.resource,
                            params.state, params.code_challenge, _now() + timedelta(seconds=REQUEST_SECONDS), conn=conn)
            _provider_deadline()
            return self.cfg.browser_origin() + "/mcp/authorize/" + request_id

    async def authorize(self, client, params):
        try:
            return await self._run(self._authorize, client, params)
        except TimeoutError:
            raise AuthorizeError("temporarily_unavailable", "MCP request deadline expired") from None
        except _OAuthFailure as exc:
            raise AuthorizeError(exc.error, exc.description) from None

    def _code(self, client, code):
        if not isinstance(code, str) or not HANDLE.fullmatch(code):
            return None
        rows = self.st.many("SELECT * FROM dashboard_mcp_authorizations WHERE tenant_id=$1 AND client_id=$2 "
                            "AND code_hash=$3 AND status='approved' AND expires_at>clock_timestamp()",
                            self.cfg.tenant_id, client.client_id, _hash(code), auth=True)
        if not rows:
            return None
        row = rows[0]
        return AuthorizationCode(code=code, client_id=row["client_id"], scopes=row["scopes"],
                                 expires_at=row["expires_at"].timestamp(), code_challenge=row["code_challenge"],
                                 redirect_uri=row["redirect_uri"], redirect_uri_provided_explicitly=True,
                                 resource=row["resource"], subject=row["user_id"])

    async def load_authorization_code(self, client, authorization_code):
        return await self._run(self._code, client, authorization_code)

    def _mint(self, principal, expires, conn, scopes=None):
        if self.st.scalar("SELECT count(*) FROM dashboard_mcp_tokens WHERE tenant_id=$1 AND grant_id=$2",
                          self.cfg.tenant_id, principal["grant_id"], conn=conn) >= 2048:
            raise _OAuthFailure("invalid_grant", "Refresh limit reached; authorize again")
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        until = min(_now() + timedelta(seconds=ACCESS_SECONDS), expires)
        for value, kind, end in ((access, "access", until), (refresh, "refresh", expires)):
            _provider_deadline()
            self.st.execute("INSERT INTO dashboard_mcp_tokens(token_hash,tenant_id,grant_id,kind,expires_at) VALUES($1,$2,$3,$4,$5)",
                            _hash(value), self.cfg.tenant_id, principal["grant_id"], kind, end, conn=conn)
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=max(1, int((until - _now()).total_seconds())),
                          refresh_token=refresh, scope=" ".join(scopes if scopes is not None else principal["scopes"]))

    def _exchange_code(self, client, code):
        _provider_deadline()
        try:
            with self.st.transaction(auth=True) as conn:
                row = self.st.one("SELECT * FROM dashboard_mcp_authorizations WHERE tenant_id=$1 AND client_id=$2 AND code_hash=$3",
                                  self.cfg.tenant_id, client.client_id, _hash(code.code), conn=conn)
                principal = validate_grant(self.st, self.cfg, row["grant_id"], conn=conn)
                row = self.st.one("SELECT * FROM dashboard_mcp_authorizations WHERE request_hash=$1 FOR UPDATE", row["request_hash"], conn=conn)
                if row["status"] != "approved" or row["expires_at"] <= _now() or row["resource"] != self.resource:
                    raise _OAuthFailure("invalid_grant", "Authorization code is unavailable")
                _provider_deadline()
                self.st.execute("UPDATE dashboard_mcp_authorizations SET status='used' WHERE request_hash=$1", row["request_hash"], conn=conn)
                self.st.execute("UPDATE dashboard_mcp_grants SET scopes=$3 WHERE tenant_id=$1 AND id=$2",
                                self.cfg.tenant_id, principal["grant_id"], principal["scopes"], conn=conn)
                expires = self.st.scalar("SELECT expires_at FROM dashboard_mcp_grants WHERE tenant_id=$1 AND id=$2",
                                         self.cfg.tenant_id, row["grant_id"], conn=conn)
                result = self._mint(principal, expires, conn)
                _provider_deadline()
                return result
        except (NotFound, APIError):
            raise TokenError("invalid_grant", "Authorization code is unavailable") from None

    async def exchange_authorization_code(self, client, authorization_code):
        try:
            return await self._run(self._exchange_code, client, authorization_code)
        except _OAuthFailure as exc:
            raise TokenError(exc.error, exc.description) from None

    def _load_token(self, token, kind, client=None):
        if not isinstance(token, str) or not HANDLE.fullmatch(token):
            return None
        try:
            with self.st.transaction(auth=True) as conn:
                row = self.st.one("SELECT * FROM dashboard_mcp_tokens WHERE tenant_id=$1 AND token_hash=$2 AND kind=$3 "
                                  "AND expires_at>clock_timestamp() AND revoked_at IS NULL", self.cfg.tenant_id, _hash(token), kind, conn=conn)
                principal = validate_grant(self.st, self.cfg, row["grant_id"], conn=conn)
                if client is not None and client.client_id != principal["client_id"]:
                    return None
                row = self.st.one("SELECT * FROM dashboard_mcp_tokens WHERE tenant_id=$1 AND token_hash=$2 AND kind=$3 "
                                  "AND expires_at>clock_timestamp() AND revoked_at IS NULL", self.cfg.tenant_id, _hash(token), kind, conn=conn)
                values = dict(token=token, client_id=principal["client_id"], scopes=principal["scopes"],
                              expires_at=int(row["expires_at"].timestamp()), resource=self.resource, subject=principal["user"]["id"])
                if kind == "refresh":
                    return RefreshToken(**values)
                return AccessToken(**values, claims={"iss": self.cfg.browser_origin(), "tenant_id": self.cfg.tenant_id,
                                                     "grant_id": principal["grant_id"]})
        except (NotFound, APIError):
            return None

    async def load_refresh_token(self, client, refresh_token):
        return await self._run(self._load_token, refresh_token, "refresh", client)

    async def load_access_token(self, token):
        return await self._run(self._load_token, token, "access")

    def _exchange_refresh(self, client, refresh_token, scopes):
        _provider_deadline()
        reused = False
        try:
            with self.st.transaction(auth=True) as conn:
                row = self.st.one("SELECT * FROM dashboard_mcp_tokens WHERE tenant_id=$1 AND token_hash=$2 AND kind='refresh'",
                                  self.cfg.tenant_id, _hash(refresh_token.token), conn=conn)
                principal = validate_grant(self.st, self.cfg, row["grant_id"], conn=conn)
                row = self.st.one("SELECT * FROM dashboard_mcp_tokens WHERE token_hash=$1 FOR UPDATE", _hash(refresh_token.token), conn=conn)
                if client.client_id != principal["client_id"] or row["revoked_at"] or row["expires_at"] <= _now():
                    raise _OAuthFailure("invalid_grant", "Refresh token is unavailable")
                if not scopes or not set(scopes) <= set(principal["scopes"]):
                    raise _OAuthFailure("invalid_scope", "Requested permissions are unavailable")
                _provider_deadline()
                if row["used_at"]:
                    self.st.execute("UPDATE dashboard_mcp_grants SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2",
                                    self.cfg.tenant_id, principal["grant_id"], conn=conn)
                    _audit(self.st, self.cfg.tenant_id, principal["user"], "mcp.refresh.reuse", "mcp_grant", principal["grant_id"], {}, conn)
                    reused = True
                else:
                    self.st.execute("UPDATE dashboard_mcp_tokens SET used_at=clock_timestamp() WHERE token_hash=$1", _hash(refresh_token.token), conn=conn)
                    self.st.execute("UPDATE dashboard_mcp_tokens SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND grant_id=$2 AND kind='access'",
                                    self.cfg.tenant_id, principal["grant_id"], conn=conn)
                    # Narrowing a refresh request narrows the persistent grant as well.
                    self.st.execute("UPDATE dashboard_mcp_grants SET scopes=$3 WHERE tenant_id=$1 AND id=$2",
                                    self.cfg.tenant_id, principal["grant_id"], scopes, conn=conn)
                    result = self._mint(principal, row["expires_at"], conn, scopes)
                    _provider_deadline()
                    return result
                _provider_deadline()
        except (NotFound, APIError):
            raise TokenError("invalid_grant", "Refresh token is unavailable") from None
        if reused:
            raise TokenError("invalid_grant", "Refresh token was already used; authorize again")

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        try:
            return await self._run(self._exchange_refresh, client, refresh_token, scopes)
        except _OAuthFailure as exc:
            raise TokenError(exc.error, exc.description) from None

    def _revoke_token(self, token):
        _provider_deadline()
        try:
            with self.st.transaction(auth=True) as conn:
                row = self.st.one("SELECT grant_id FROM dashboard_mcp_tokens WHERE tenant_id=$1 AND token_hash=$2",
                                  self.cfg.tenant_id, _hash(token.token), conn=conn)
                principal = validate_grant(self.st, self.cfg, row["grant_id"], conn=conn)
                if token.client_id == principal["client_id"]:
                    _provider_deadline()
                    self.st.execute("UPDATE dashboard_mcp_grants SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2",
                                    self.cfg.tenant_id, row["grant_id"], conn=conn)
                    _audit(self.st, self.cfg.tenant_id, principal["user"], "mcp.grant.revoke", "mcp_grant", row["grant_id"], {}, conn)
                _provider_deadline()
        except (NotFound, APIError):
            return

    async def revoke_token(self, token):
        await self._run(self._revoke_token, token)

    async def exchange_identity_assertion(self, client, params):
        raise TokenError("unsupported_grant_type", "Identity assertion grants are not supported")
