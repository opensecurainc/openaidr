"""MCP deployment boundary, available without the optional protocol SDK."""

from contextvars import ContextVar

from fastapi import Request
from psycopg.types.json import Jsonb
from starlette.responses import JSONResponse

from .httpx import APIError, require
from .permissions import authorize
from .store import new_id

MAX_BODY = 64 << 10
PROTOCOL_PATHS = frozenset((
    "/mcp", "/authorize", "/token", "/revoke",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource/mcp",
))
request_deadline = ContextVar("dashboard_mcp_deadline", default=None)


def disable_deployment(st, cfg):
    if cfg.dashboard_mcp_enabled or not cfg.tenant_id or not cfg.enabled("api"):
        return
    with st.transaction(auth=True) as conn:
        if not st.scalar("SELECT to_regclass('dashboard_mcp_settings')", conn=conn):
            return
        rows = st.many("SELECT enabled FROM dashboard_mcp_settings WHERE tenant_id=$1 FOR UPDATE", cfg.tenant_id, conn=conn)
        disabled = bool(rows and rows[0]["enabled"])
        if disabled:
            st.execute("UPDATE dashboard_mcp_settings SET enabled=false,revision=revision+1 WHERE tenant_id=$1", cfg.tenant_id, conn=conn)
        revoked = st.execute("UPDATE dashboard_mcp_grants SET revoked_at=clock_timestamp() WHERE tenant_id=$1 "
                             "AND revoked_at IS NULL AND expires_at>clock_timestamp()", cfg.tenant_id, conn=conn)
        if disabled or revoked:
            st.execute("INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details) "
                       "VALUES($1,$2,'system','','Dashboard MCP deployment','mcp.deployment.disable','mcp_settings',$2,$3)",
                       new_id(), cfg.tenant_id, Jsonb({"revoked_grants": revoked}), conn=conn)


class _DisabledMCP:
    app = None

    def __init__(self, service):
        self.service = service
        disable_deployment(service.st, service.cfg)

    def close(self):
        pass

    async def admit(self, request, call_next):
        if request.url.path in PROTOCOL_PATHS:
            return JSONResponse({"error": {"code": "not_found", "message": "MCP is disabled"}}, status_code=404)
        return await call_next(request)

    def install(self, app):
        @app.get("/api/v1/mcp/clients")
        @app.get("/api/v1/mcp/settings")
        def status(request: Request):
            try:
                require(self.service.cfg.enabled("api"), "No such route", 404)
                principal = self.service.principal(request)
                authorize(principal["user"], "GET", "mcp/settings")
                return JSONResponse({"deployment_enabled": False, "enabled": False,
                                     "revision": 0, "allowed_scopes": [], "available_scopes": [], "items": []},
                                    headers={"Cache-Control": "no-store"})
            except APIError as exc:
                return JSONResponse({"error": {"code": exc.code, "message": exc.message}}, status_code=exc.status)


def configure(service):
    if not service.cfg.dashboard_mcp_enabled:
        return _DisabledMCP(service)
    from .dashboard_mcp import DashboardMCP

    return DashboardMCP(service)
