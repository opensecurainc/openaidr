"""HTTP services for the console, platform administrators, and sensors."""

import asyncio
import json
import logging
import os
import re
import secrets
import socket
import threading
import time
import uuid
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timezone
from functools import partial

import anyio
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from psycopg.errors import LockNotAvailable
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect
from starlette.responses import JSONResponse, Response, RedirectResponse, PlainTextResponse, StreamingResponse

from openaidr_api_client.contracts.origin import browser_origin

from .version import __version__, build_metadata
from .config import PLATFORM_AVAILABLE
from openaidr.core.hook_protocol import PRODUCTS as HOOK_PRODUCTS
from openaidr.core.enrollment import TOKEN, enrollment_origin, make_enrollment_link
from openaidr.core.event import new_id
from openaidr.core.protocol import default_sensor_config
from openaidr.server import auth, knowledge, model_keys, store
from .query_sources import query_source, request_source, source_job
from .httpx import (
    APIError,
    body,
    listing,
    page,
    parse_time,
    require,
    response,
    uuid_param,
)
from .model import public_record
from .web import serve_app
from .page_chat import ChatResponse, PageChat, validate_input
from .permissions import assigned_roles, authorize, has_role, page_allowed, requested_roles

# Commands an administrator can queue for a sensor; disable/enable are queued
# by the sensor and response-action routes. The sensor runtime applies them.
SENSOR_COMMANDS = ("install_hook", "uninstall_hook", "refresh_policy")
HOOK_AGENTS = (*HOOK_PRODUCTS, "all")
log = logging.getLogger(__name__)


def default_policy_rules():
    specs = [
        (
            "Block recursive delete of root or home",
            "deny",
            "Recursive deletes of / or the home directory are never allowed.",
            {
                "kinds": ["command"],
                "command_regex": r"(?i)\brm\s+(-\w+\s+)*(/|/\*|~|~/\*?|\$HOME/?\*?)(\s|$)",
            },
        ),
        (
            "Block piping downloads into a shell",
            "deny",
            "Download the script, review it, then run it.",
            {
                "kinds": ["command"],
                "command_regex": r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|perl)\b",
            },
        ),
        (
            "Warn on force push",
            "warn",
            "Force pushes rewrite shared history.",
            {
                "kinds": ["command"],
                "command_regex": r"\bgit\s+push\b.*(\s-f|\s--force)(\s|$)",
            },
        ),
        # Last, one rule per directory, nested files included: policy globs
        # have no brace groups, and the earlier single brace rule never
        # matched, so these must not come before a rule that does. Migration
        # 0037 and every save split and place the earlier rule the same way.
        *(
            (
                f"Warn on credential file reads (.{directory})",
                "warn",
                "Credential stores should not be needed for coding tasks.",
                {"kinds": ["file.read"], "path_glob": f"**/.{directory}/**"},
            )
            for directory in ("aws", "ssh", "kube")
        ),
    ]
    return [
        dict(
            id=new_id(),
            name=n,
            action=a,
            reason=r,
            match=m,
            enabled=True,
            source="builtin",
        )
        for n, a, r, m in specs
    ]


# Actions a sensor applies when it does not advertise `policy_actions`.
LEGACY_POLICY_ACTIONS = ("allow", "deny", "warn")


def policy_for_sensor(policy, actions):
    """The policy as a sensor that supports ``actions`` must receive it. A
    sensor without `ask` would allow the call, so an approval rule is sent to
    it as a deny. The result records the actions it was prepared for, so an
    upgraded sensor knows to fetch it again."""
    supported = (
        {a for a in actions if isinstance(a, str)}
        if isinstance(actions, list)
        else set(LEGACY_POLICY_ACTIONS)
    )
    rules = []
    for rule in policy.get("rules", []):
        if rule.get("action") == "ask" and "ask" not in supported:
            rule = dict(
                rule,
                action="deny",
                reason="Requires approval, which this sensor version cannot request. "
                + (rule["reason"] if isinstance(rule.get("reason"), str) else ""),
            )
        rules.append(rule)
    return dict(policy, rules=rules, actions=sorted(supported))


def validate_rule(rule):
    require(isinstance(rule, dict), "invalid rule")
    rule["id"] = rule.get("id") or new_id()
    require(
        isinstance(rule.get("name"), str) and rule["name"].strip(),
        "rule name is required",
    )
    require(
        rule.get("action") in ("allow", "ask", "deny", "warn"),
        "rule action must be allow, ask, deny, or warn",
    )
    require(isinstance(rule.get("reason", ""), str), "rule reason must be a string")
    match = rule.get("match") or {}
    require(isinstance(match, dict), "invalid match")
    if match.get("command_regex"):
        try:
            re.compile(match["command_regex"])
        except (re.error, TypeError) as exc:
            raise APIError(400, "command_regex: " + str(exc)) from None
    kinds = match.get("kinds")
    require(
        kinds is None
        or isinstance(kinds, str)
        or (isinstance(kinds, list) and all(isinstance(k, str) for k in kinds)),
        "kinds must be an array of strings",
    )
    require(
        any(
            match.get(k)
            for k in (
                "command_regex",
                "path_glob",
                "host_glob",
                "tool_name",
                "kinds",
                "products",
            )
        ),
        "rule must have at least one match condition",
    )
    rule.setdefault("source", "tenant")
    return rule


LEGACY_CREDENTIAL_RULE_BYTES = 16 * 1024


def check_legacy_credential_rules(rules):
    # Saving splits a legacy credential-read rule into three copies, so a
    # policy may hold one, small enough that copying it stays cheap.
    legacy = [r for r in rules if store.legacy_credential_rules([r])]
    require(
        len(legacy) <= 1,
        "a policy may contain the legacy credential-read rule only once",
    )
    require(
        all(len(json.dumps(r)) <= LEGACY_CREDENTIAL_RULE_BYTES for r in legacy),
        "the legacy credential-read rule must be at most 16 KiB",
    )


class Service:
    def __init__(self, cfg, st, *, customer=False):
        from .agent_cost_summaries import CostCache
        from .telemetry_dashboard import OverviewCache
        from .database_diagnostics import Diagnostics
        from .skill_content import ContentBuffer
        from .overview_summary import OverviewSummary
        from openaidr_api_client.client import Connection

        self.cfg, self.st, self.customer = cfg, st, customer
        self.browser_origins = {
            admin: cfg.browser_origin(admin) for admin in (False, True)
        }
        self.engine = None
        self.inline_guardrail = None
        self.guardrail_clients = None
        self.link_checker = None
        self.cost_cache = CostCache()
        self.telemetry_cache = OverviewCache()
        self.database_diagnostics = Diagnostics()
        self.skill_content = ContentBuffer()
        from .uploads import UploadBuffer

        self.uploads = UploadBuffer()
        chat, summary = PageChat, OverviewSummary
        if customer:
            from .service_page_chat import CustomerPageChat
            from .service_summaries import CustomerOverviewSummary
            chat, summary = CustomerPageChat, CustomerOverviewSummary
        self.page_chat = chat(st, connection=Connection.from_config(cfg),
                                  connection_factory=lambda: model_keys.selected_connection(cfg, st))
        self.overview_summary = summary(st)
        self.cloud_identity = None
        self.staff_identity = None
        self.device_credentials = None
        self.management = None
        self.cicd_releases = None
        if PLATFORM_AVAILABLE:
            from openaidr.platform.service import initialize

            initialize(self)

    def customer_investigator(self, st):
        """Construct the same complete-job controller used by the lifespan."""
        if not self.customer:
            raise ValueError("Customer application required")
        from .investigation_controller import Investigator

        return Investigator(st, self.cfg)

    def browser_mutation(self, request, admin=False):
        require(
            request.headers.getlist(auth.CSRF_HEADER) == ["1"],
            f"{auth.CSRF_HEADER}: 1 is required",
            403,
        )
        # Native clients can omit Origin/Referer, but still need the custom header.
        # Browsers cannot attach that header cross-origin without a CORS preflight.
        for name in ("origin", "referer"):
            values = request.headers.getlist(name)
            if not values:
                continue
            require(len(values) == 1, "invalid request origin", 403)
            try:
                origin = browser_origin(values[0], referer=name == "referer")
            except ValueError:
                raise APIError(403, "invalid request origin") from None
            require(
                origin == self.browser_origins[admin], "untrusted request origin", 403
            )

    def guardrail_client(self, tenant, store=None):
        cls = model_keys.TenantAsyncGuardrailClient
        if self.customer:
            from .service_guardrail import WorkspaceClient
            cls = WorkspaceClient
        return cls(self.st if store is None else store, tenant, self.cfg, clients=self.guardrail_clients)

    def session_token(self, request, admin=False):
        return request.cookies.get(
            auth.cookie_name(admin=admin, secure=self.cfg.secure_cookie(admin))
        )

    def audit(self, tenant, actor, action, target, ident, details=None):
        try:
            self.st.audit(tenant, actor, action, target, ident, details)
        except Exception:
            log.exception("audit failed")

    def ensure_tenant(self, tenant_id):
        require(
            not self.cfg.tenant_id or tenant_id == self.cfg.tenant_id,
            "credential does not belong to this tenant backend",
            403,
        )

    def sensor_principal(self, request):
        if self.device_credentials:
            from openaidr.platform.device_credentials import gateway_fingerprint

            fingerprint = gateway_fingerprint(request)
            if fingerprint or self.cfg.device_auth_mode == "mtls":
                return self.device_credentials.authenticate(fingerprint)
        header = request.headers.get("authorization", "")
        require(header.startswith("Bearer "), "sensor token required", 401)
        try:
            sensor = self.st.get_sensor_by_token(header[7:].strip())
        except store.NotFound:
            raise APIError(401, "invalid sensor token") from None
        self.ensure_tenant(sensor.get("tenant_id"))
        return sensor

    def otlp(self, request, signal):
        from openaidr.core.telemetry import decode_export, count_records, response_bytes
        from .otlp import error_response

        content_type = (
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        )
        try:
            require(
                self.cfg.enabled("ingest")
                and signal in ("logs", "metrics", "traces")
                and request.method == "POST",
                "no such route",
                404,
            )
            sensor = self.sensor_principal(request)
            require(not sensor["disabled"], "sensor is disabled", 403)
            tenant = self.st.get_tenant_brief(sensor["tenant_id"])
            require(tenant["status"] == "active", "tenant is " + tenant["status"], 403)
            require(
                content_type in ("application/json", "application/x-protobuf"),
                "Content-Type must be application/json or application/x-protobuf",
                415,
            )
            batch_id = request.headers.get("x-openaidr-batch-id") or new_id()
            uuid_param(batch_id, "X-OpenAIDR-Batch-Id")
            try:
                payload = decode_export(
                    signal,
                    request.state.body,
                    content_type,
                    request.headers.get("content-encoding", ""),
                )
                records = count_records(signal, payload)
            except ValueError as exc:
                raise APIError(getattr(exc, "status", 400), str(exc)) from None
            inserted = self.st.ingest_telemetry(
                sensor, signal, batch_id, payload, records
            )
            return Response(
                response_bytes(signal, content_type),
                media_type=content_type,
                headers={
                    "X-OpenAIDR-Batch-Id": batch_id,
                    "X-OpenAIDR-Duplicate": "false" if inserted else "true",
                },
            )
        except APIError as exc:
            return error_response(exc.status, exc.message, content_type)
        except store.Conflict as exc:
            return error_response(409, str(exc), content_type)
        except Exception:
            log.exception("OTLP persistence failed")
            return error_response(
                503, "telemetry storage is temporarily unavailable", content_type
            )

    def cookie(self, result, token="", admin=False, max_age=None):
        secure = self.cfg.secure_cookie(admin)
        cookie = auth.cookie_name(admin=admin, secure=secure)
        if max_age is None:
            max_age = 3600 if (self.staff_identity if admin else self.cloud_identity) else 30 * 24 * 3600
        result.set_cookie(
            cookie,
            token,
            max_age=max_age if token else 0,
            httponly=True,
            secure=secure,
            samesite="lax",
            path="/",
        )
        if secure:
            result.delete_cookie(
                auth.cookie_name(admin=admin), path="/", httponly=True,
                secure=True, samesite="lax",
            )
        return result

    def principal(self, request, admin=False, role=None):
        token = self.session_token(request, admin)
        require(token, "sign in required", 401)
        try:
            if admin:
                require(PLATFORM_AVAILABLE, "no such route", 404)
                from openaidr.platform.service import admin_principal

                p = admin_principal(self, token)
            else:
                p = self.st.get_session(token)
        except store.NotFound:
            raise APIError(401, "session expired") from None
        if not admin:
            self.ensure_tenant(p["tenant"]["id"])
            if self.cloud_identity:
                from openaidr.platform.cloud_identity import SESSION_MAX_SECONDS

                require(
                    p.get("oidc_issuer") == self.cfg.oidc_issuer
                    and p.get("verified_at") is not None
                    and (datetime.now(timezone.utc) - p["verified_at"]).total_seconds() < SESSION_MAX_SECONDS,
                    "session expired", 401,
                )
            else:
                require(not p.get("oidc_issuer"), "session expired", 401)
            require(p["user"]["status"] == "active", "account disabled", 403)
            require(
                p["tenant"]["status"] == "active",
                "tenant is " + p["tenant"]["status"],
                403,
            )
            require(
                bool(assigned_roles(p["user"])) and (role is None or has_role(p["user"], role)),
                "requires role " + role if role else "no dashboard access",
                403,
            )
        return p

    @staticmethod
    def user_view(user, tenant):
        return {
            **{k: user[k] for k in ("id", "email", "name", "role")},
            "roles": assigned_roles(user),
            "tenant": {k: tenant[k] for k in ("id", "name", "slug")},
        }

    def auth_route(self, request, route, admin):
        if admin:
            require(PLATFORM_AVAILABLE, "no such route", 404)
            from openaidr.platform.service import admin_auth_route

            return admin_auth_route(self, request, route)
        st = self.st
        if route == "config":
            data = dict(version=1, mode="local", password_login=True)
            if self.cloud_identity:
                data.update(mode="cloud_google", password_login=False, login_start="/api/v1/auth/oidc/start")
            result = response(data)
            result.headers["cache-control"] = "no-store"
            return result
        if route == "logout":
            token = self.session_token(request)
            if token:
                if self.cfg.tenant_id:
                    try:
                        self.ensure_tenant(st.get_session(token)["tenant"]["id"])
                    except store.NotFound:
                        pass
                st.delete_session(token)
            result = self.cookie(Response(status_code=204))
            if self.cloud_identity:
                from openaidr.platform.cloud_identity import INVITE_COOKIE, LOGIN_COOKIE

                pending = request.cookies.get(INVITE_COOKIE, "")
                if pending:
                    st.execute("DELETE FROM oidc_pending_memberships WHERE token_hash=$1 AND tenant_id=$2", store.hash_token(pending), self.cfg.tenant_id, auth=True)
                binding = request.cookies.get(LOGIN_COOKIE, "")
                if binding:
                    st.execute("DELETE FROM oidc_login_transactions WHERE browser_hash=$1 AND tenant_id=$2", store.hash_token(binding), self.cfg.tenant_id, auth=True)
                self.cloud_cookie(result, INVITE_COOKIE)
                self.cloud_cookie(result, LOGIN_COOKIE)
            return result
        if route == "me":
            p = self.principal(request)
            return response({"user": self.user_view(p["user"], p["tenant"]),
                             **({"session_renewal": True} if self.cloud_identity else {})})
        if route == "renew" and self.cloud_identity:
            p = self.principal(request)
            token = self.session_token(request)
            try:
                max_age = self.cloud_identity.renew_session(token, p["user"]["id"])
            except store.NotFound:
                raise APIError(401, "session expired") from None
            return self.cookie(
                Response(status_code=204, headers={"Cache-Control": "no-store"}),
                token, max_age=max_age,
            )
        if self.cloud_identity:
            require(route.startswith("oidc/"), "password authentication is disabled", 403)
            return self.cloud_auth_route(request, route[5:])
        if route in ("invite", "accept-invite"):
            data = (
                body(request, 64 << 10)
                if route == "accept-invite"
                else request.query_params
            )
            require(data.get("token"), "token is required")
            inv = st.get_invite_by_token(data["token"])
            require(
                not inv.get("accepted_at")
                and parse_time(inv["expires_at"]) > datetime.now(timezone.utc),
                "invite is no longer valid",
                404,
            )
            self.ensure_tenant(inv["tenant_id"])
            tenant = st.get_tenant_brief(inv["tenant_id"])
            if route == "invite":
                return response(
                    dict(
                        email=inv["email"],
                        tenant_name=tenant["name"],
                        role=inv["role"],
                        roles=assigned_roles(inv),
                        expires_at=inv["expires_at"],
                    )
                )
            name = data.get("name", "").strip()
            require(name, "token and name are required")
            require(tenant["status"] == "active", "tenant is " + tenant["status"], 403)
            try:
                hashed = auth.hash_password(data.get("password", ""))
            except ValueError:
                raise APIError(400, "password must be at least 10 characters") from None
            user = st.accept_invite(inv, name, hashed)
            token = st.create_session(user["id"], user["tenant_id"])
            st.touch_login(user["id"])
            self.audit(
                tenant["id"],
                dict(type="user", id=user["id"], name=user["name"]),
                "invite.accept",
                "user",
                user["id"],
                {"email": user["email"], "roles": assigned_roles(user)},
            )
            return self.cookie(response({"user": self.user_view(user, tenant)}), token)
        if route != "login":
            raise APIError(404, "no such route")
        data = body(request, 64 << 10)
        try:
            user = st.get_user_by_email(
                data.get("email", "")
            )
        except store.NotFound:
            raise APIError(401, "invalid email or password") from None
        require(
            auth.check_password(user["password_hash"], data.get("password", "")),
            "invalid email or password",
            401,
        )
        require(user["status"] == "active", "account disabled", 403)
        self.ensure_tenant(user["tenant_id"])
        tenant = st.get_tenant_brief(user["tenant_id"])
        require(tenant["status"] == "active", "tenant is " + tenant["status"], 403)
        token = st.create_session(user["id"], user["tenant_id"])
        st.touch_login(user["id"])
        return self.cookie(response({"user": self.user_view(user, tenant)}), token)

    @staticmethod
    def cloud_cookie(result, name, token=""):
        result.set_cookie(name, token, max_age=600 if token else 0, httponly=True,
                          secure=True, samesite="lax", path="/")
        result.headers["cache-control"] = "no-store"
        result.headers["referrer-policy"] = "no-referrer"
        return result

    def cloud_auth_route(self, request, route):
        from openaidr.platform.service import cloud_auth_route

        return cloud_auth_route(self, request, route)

    def ingest(self, request, path):
        st = self.st
        if path == "enrollment/preview":
            data = body(request, 4 << 10)
            token = data.get("enrollment_token", "")
            require(isinstance(token, str) and TOKEN.fullmatch(token), "invalid enrollment link", 401)
            try:
                preview = st.preview_enrollment(token, self.cfg.tenant_id)
            except (store.NotFound, store.TokenRevoked, store.TokenExpired, store.TokenExhausted):
                raise APIError(403, "Enrollment link is invalid, expired, revoked, or already used") from None
            result = response(dict(preview, auth_mode="mtls" if self.device_credentials else "bearer"))
            result.headers["Cache-Control"] = "no-store"
            return result
        if self.device_credentials:
            from openaidr.platform.device_credentials import gateway_fingerprint

            fingerprint = gateway_fingerprint(request)
            if path == "enroll" or path.startswith("credentials/"):
                data = body(request, 64 << 10)
                credentials = self.device_credentials
                if path == "enroll":
                    require(not fingerprint, "new enrollment must omit a client certificate", 403)
                    result = credentials.enroll(data)
                    tenant = st.get_tenant_brief(self.cfg.tenant_id)
                    result = dict(result, tenant={k: tenant[k] for k in ("id", "name")},
                                  config=default_sensor_config())
                    if data.get("policy_delivery") == "backend":
                        result["policy_version"] = st.policy_version(tenant["id"])
                    else:
                        result["policy"] = st.get_policy(tenant["id"])
                elif path == "credentials/activate":
                    result = credentials.activate(fingerprint, data)
                elif path == "credentials/renew":
                    result = credentials.renew(fingerprint, data)
                elif path == "credentials/migrate":
                    require(self.cfg.device_auth_mode == "migration" and not fingerprint,
                            "legacy credential migration is not enabled", 403)
                    header = request.headers.get("authorization", "")
                    require(header.startswith("Bearer "), "sensor token required", 401)
                    result = credentials.migrate(header[7:].strip(), data)
                elif path == "credentials/recover":
                    require(not fingerprint, "recovery must omit a client certificate", 403)
                    result = credentials.recover(data)
                else:
                    raise APIError(404, "no such route")
                reply = JSONResponse(jsonable_encoder(result))
                reply.headers["cache-control"] = "no-store"
                return reply
        if path == "enroll":
            data = body(request, 64 << 10)
            require(data.get("enrollment_token"), "enrollment_token is required")
            require(data.get("hostname"), "hostname is required")
            require(
                data.get("host_kind", "") in ("", "workstation", "server"),
                "host_kind must be workstation or server",
            )
            try:
                sensor, token, tenant = (
                    st.enroll_sensor(data, self.cfg.tenant_id)
                    if self.cfg.tenant_id
                    else st.enroll_sensor(data)
                )
            except store.NotFound:
                raise APIError(401, "invalid enrollment token") from None
            except (
                store.TokenRevoked,
                store.TokenExpired,
                store.TokenExhausted,
            ) as exc:
                raise APIError(403, str(exc)) from None
            self.audit(
                tenant["id"],
                dict(type="sensor", id=sensor["id"], name=sensor["hostname"]),
                "sensor.enroll",
                "sensor",
                sensor["id"],
                {key: sensor.get(key, "") for key in ("hostname", "os", "host_kind")},
            )
            result = dict(
                sensor_id=sensor["id"],
                sensor_token=token,
                tenant={k: tenant[k] for k in ("id", "name")},
                config=default_sensor_config(),
            )
            if data.get("policy_delivery") == "backend":
                result["policy_version"] = st.policy_version(tenant["id"])
            else:
                result["policy"] = policy_for_sensor(
                    st.get_policy(tenant["id"]), data.get("policy_actions")
                )
            return response(result)
        sensor = self.sensor_principal(request)
        if path.startswith("uploads/"):
            target = path.removeprefix("uploads/")
            limits = {"events": 8 << 20, "inventory/applications": 8 << 20,
                      "inventory/snapshots": 8 << 20, "inventory/skills/manifest": 6 << 20,
                      "inventory/skills/content": 6 << 20,
                      **{"otlp/" + signal: 8 << 20 for signal in ("logs", "metrics", "traces")}}
            require(target in limits, "no such upload route", 404)
            require(not sensor["disabled"], "sensor is disabled", 403)
            tenant = self.st.get_tenant_brief(sensor["tenant_id"])
            require(tenant["status"] == "active", "tenant is " + tenant["status"], 403)
            if target.startswith("inventory/skills/"):
                require(bool(self.cfg.skill_scanner_token), "skill scanning is disabled", 404)
            pending = self.uploads.receive(request, ("sensor", sensor["tenant_id"], sensor["id"]), limits[target])
            if pending is not None:
                return pending
            result = (self.otlp(request, target.removeprefix("otlp/"))
                      if target.startswith("otlp/") else self.ingest(request, target))
            result.headers["X-OpenAIDR-Upload-Complete"] = "1"
            result.headers["Cache-Control"] = "no-store"
            return result
        if path == "alerts" or path.startswith("alerts/"):
            from . import endpoint_alerts

            require(not sensor["disabled"], "sensor is disabled", 403)
            data = body(request, 8 << 10)
            if path == "alerts":
                require(data == {}, "alert inbox requires an empty object")
                result = endpoint_alerts.inbox(st, sensor)
            elif path == "alerts/received":
                require(set(data) == {"ids"}, "ids is required")
                result = endpoint_alerts.receipt(st, sensor, endpoint_alerts.ids(data["ids"]))
            elif re.fullmatch(r"alerts/[^/]+/acknowledge", path):
                require(data == {}, "acknowledgement requires an empty object")
                result = endpoint_alerts.receipt(st, sensor, [uuid_param(path.split("/")[1], "alert id")], acknowledge=True)
            else:
                raise APIError(404, "no such route")
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path in ("guardrails/denials", "guardrails/check", "guardrails/review"):
            from .desktop_guardrails import review_request

            require(not sensor["disabled"], "sensor is disabled", 403)
            result = response(review_request(st, sensor, path.split("/")[1], body(request, 32 << 10)))
            result.headers["Cache-Control"] = "no-store"
            return result
        if path == "credits/summary":
            from .desktop_credits import overview

            require(not sensor["disabled"], "sensor is disabled", 403)
            require(body(request, 1024) == {}, "credit summary requires an empty object")
            require(st.get_tenant_brief(sensor["tenant_id"])["status"] == "active", "tenant is not active", 403)
            result = response(overview(st, self.cfg, sensor))
            result.headers["Cache-Control"] = "no-store"
            return result
        if path == "posture/summary":
            from .desktop_posture import overview

            require(not sensor["disabled"], "sensor is disabled", 403)
            require(body(request, 1024) == {}, "posture summary requires an empty object")
            result = response(overview(st, sensor, osv_enabled=self.cfg.osv_assessment,
                                       skills_enabled=bool(self.cfg.skill_scanner_token)))
            result.headers["Cache-Control"] = "no-store"
            return result
        if path == "guardrails/summary":
            from .desktop_guardrails import overview

            require(not sensor["disabled"], "sensor is disabled", 403)
            data = body(request, 1024)
            require(set(data) <= {"days"}, "unknown guardrails parameter")
            days = data.get("days", 1)
            require(type(days) is int and days in (1, 30), "days must be 1 or 30")
            result = response(overview(st, sensor, days))
            result.headers["Cache-Control"] = "no-store"
            return result
        if path == "usage/summary":
            from .desktop_usage import overview

            require(not sensor["disabled"], "sensor is disabled", 403)
            data = body(request, 1024)
            require(set(data) <= {"days"}, "unknown usage parameter")
            days = data.get("days", 30)
            require(type(days) is int and days in (7, 30), "days must be 7 or 30")
            result = response(overview(st, sensor, days))
            result.headers["Cache-Control"] = "no-store"
            return result
        if path == "managed-bootstrap":
            from .session_ownership import _active_sensor

            require(body(request, 1024) == {}, "managed bootstrap requires an empty object")
            with st.transaction() as conn:
                try:
                    _active_sensor(st, sensor, conn)
                except store.NotFound:
                    raise APIError(403, "sensor is unavailable") from None
                policy = st.get_policy(sensor["tenant_id"], conn=conn)
                result = JSONResponse(jsonable_encoder({
                    "version": 1,
                    "tenant_id": sensor["tenant_id"],
                    "sensor_id": sensor["id"],
                    "capture": default_sensor_config()["capture"],
                    "policy": {**policy, "actions": ["allow", "ask", "deny", "warn"]},
                }))
            result.headers["Cache-Control"] = "no-store"
            return result
        if path == "session-registrations" or path.startswith("session-registrations/"):
            from . import session_ownership

            data = body(request, 4 << 10)
            parts = path.split("/")
            if len(parts) == 1:
                result = session_ownership.reserve(
                    st, sensor, data.get("product"),
                    assessment_mode=data.get("assessment_mode", "legacy"),
                    inline_enabled=self.cfg.inline_guardrails,
                    delivery_protocol=data.get("delivery_protocol"),
                    delivery_epoch=data.get("delivery_epoch"),
                )
                code = 201
            elif len(parts) == 3 and parts[2] == "bind":
                result = session_ownership.bind(st, sensor, parts[1], data.get("external_id"))
                code = 200
            elif len(parts) == 3 and parts[2] == "status":
                include_policy = data.get("include_policy", False)
                require(type(include_policy) is bool, "include_policy must be a boolean")
                result = session_ownership.status(
                    st, sensor, parts[1], include_policy=include_policy,
                )
                code = 200
            else:
                raise APIError(404, "no such route")
            reply = response(result, code)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "version":
            # Sensors and the desktop app compare this with their own package
            # version to offer an update; the deployment ships both together.
            return response(dict(version=__version__, build=build_metadata()))
        if path == "inventory/applications":
            from .app_inventory import ingest_snapshot

            return response(ingest_snapshot(st, sensor, body(request, 8 << 20)))
        if path == "inventory/snapshots":
            from .component_inventory import ingest_snapshot

            result = ingest_snapshot(st, sensor, body(request, 8 << 20))
            result["skill_scanning"] = {"enabled": bool(self.cfg.skill_scanner_token)}
            return response(result)
        if path in ("inventory/skills/manifest", "inventory/skills/content"):
            from .skill_scanning import receive

            require(bool(self.cfg.skill_scanner_token), "skill scanning is disabled", 404)
            return response(receive(st, sensor, body(request, 6 << 20), self.skill_content, content=path.endswith("/content"), customer=self.customer))
        if path == "events":
            from .activity_ingestion import receive

            require(not sensor["disabled"], "sensor is disabled", 403)
            return response(receive(st, sensor, request.state.body))
        if path == "heartbeat":
            from .sensor_metrics import validate

            data = body(request)
            validate(data)
            depth = data.get("telemetry_queue_depth")
            require(
                depth is None
                or (type(depth) is int and 0 <= depth <= 9223372036854775807),
                "telemetry_queue_depth must be a nonnegative integer or null",
            )
            st.record_heartbeat(sensor["id"], data)
            result = dict(
                tenant_name=st.get_tenant_brief(sensor["tenant_id"])["name"],
                disabled=sensor["disabled"],
                commands=st.pending_commands(sensor["id"]) or [],
                config=default_sensor_config(),
            )
            from .free_tier import status as credit_status
            if self.customer:
                from .service_enrollment import status as credit_status
            if str(sensor["tenant_id"]) == self.cfg.tenant_id:
                result["cloud_protection"] = credit_status(self.cfg)
            if "project_metadata" in data:
                from .agent_projects import exchange_metadata

                try:
                    metadata = exchange_metadata(st, sensor, data["project_metadata"])
                    if metadata is not None:
                        result["project_metadata"] = metadata
                except Exception:
                    logging.getLogger(__name__).exception("Project metadata exchange failed")
            if data.get("policy_delivery") == "backend":
                result["policy_version"] = st.policy_version(sensor["tenant_id"])
                return response(result)
            actions = data.get("policy_actions")
            if st.policy_version(sensor["tenant_id"]) > data.get("policy_version", 0):
                result["policy"] = policy_for_sensor(
                    st.get_policy(sensor["tenant_id"]), actions
                )
            elif not (isinstance(actions, list) and "ask" in actions):
                # A sensor rolled back to a version without ask may hold the
                # same policy version with ask rules it would not enforce, so
                # it gets the deny form on every heartbeat while ask rules exist.
                policy = st.get_policy(sensor["tenant_id"])
                if any(r.get("action") == "ask" for r in policy.get("rules", [])):
                    result["policy"] = policy_for_sensor(policy, actions)
            return response(result)
        match = re.fullmatch(r"commands/([^/]+)/ack", path)
        if match:
            ident = uuid_param(match[1], "command id")
            data = body(request, 64 << 10)
            require(
                data.get("status") in ("applied", "failed"),
                "status must be applied or failed",
            )
            st.ack_command(sensor["id"], ident, data)
            return Response(status_code=204)
        raise APIError(404, "no such route")

    def console(self, request, path):
        method, st = request.method, self.st
        if path == "chat":
            require(method == "POST", "no such route", 404)
            principal = self.principal(request)
            data = body(request, 256 << 10)
            validate_input(data)
            require(page_allowed(principal["user"], data["page"]["path"]), "your roles do not allow this page", 403)
            tenant_id = principal["tenant"]["id"]
            if "text/event-stream" in request.headers.get("accept", ""):
                return ChatResponse(
                    self.page_chat.stream(tenant_id, data),
                    media_type="text/event-stream",
                    headers={"Cache-Control": "no-store, no-transform", "X-Accel-Buffering": "no"},
                )
            result = response(
                self.page_chat.answer(tenant_id, data)
            )
            result.headers["Cache-Control"] = "no-store"
            return result
        p = self.principal(request)
        return self._console_authenticated(request, path, p["tenant"]["id"], p["user"])

    def _console_authenticated(self, request, path, tenant, user):
        method, st, q = request.method, self.st, request.query_params
        fragmented = path == "knowledge/uploads/chunks" and method == "POST"
        if fragmented:
            path = "knowledge/uploads"
        self.ensure_tenant(tenant)
        authorize(user, method, path)
        if fragmented:
            pending = self.uploads.receive(request, ("user", tenant, user["id"]), 7 << 20)
            if pending is not None:
                return pending
        actor = dict(type="user", id=user["id"], name=user["name"])
        limit = (
            7 << 20
            if path == "knowledge/uploads"
            else 1 << 20
            if path in ("response/policy", "response/company-policy")
            else 256 << 10
            if path in ("knowledge/documents", "knowledge/sources") or path.startswith("knowledge/mcp") or path.endswith("/notes")
            else 64 << 10
            if path.startswith(
                ("findings/", "response/actions", "response/policy/rules")
            )
            else 32 << 10
            if path == "endpoint-alerts"
            else 4 << 10
        )
        data = body(request, limit) if method in ("POST", "PUT", "PATCH") else {}
        if path == "settings/cowork" or path.startswith("settings/cowork/"):
            from . import cowork

            if path == "settings/cowork" and method == "GET":
                result = {"connections": cowork.connections(st, tenant)}
            elif path == "settings/cowork" and method == "POST":
                result = cowork.create(st, tenant, data, actor, self.cfg)
            elif method == "DELETE" and len(path.split("/")) == 3:
                result = cowork.revoke(st, tenant, path.split("/")[-1], actor)
            else:
                raise APIError(404, "not found")
            return JSONResponse(jsonable_encoder(result), headers={"Cache-Control": "no-store"})
        parts = path.split("/")
        ident = parts[-1]
        if parts[0] == "gateways":
            from . import gateways

            result, status = gateways.console(st, tenant, method, path, data, q, actor)
            reply = response(result, status)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if parts[0] == "endpoint-alerts":
            from . import endpoint_alerts

            if path == "endpoint-alerts" and method == "POST":
                result, created = endpoint_alerts.create(st, tenant, data, actor)
                reply = response(result, 201 if created else 200)
            elif path == "endpoint-alerts" and method == "GET":
                reply = response(endpoint_alerts.listing(st, tenant, q))
            elif len(parts) == 2 and method == "GET":
                reply = response(endpoint_alerts.detail(st, tenant, uuid_param(ident, "alert id")))
            else:
                raise APIError(404, "no such route")
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if parts[0] == "risk-cases":
            from . import risk_cases

            if path == "risk-cases" and method == "GET":
                result = risk_cases.listing(st, tenant, q)
                from .session_activity_summaries import attach

                attach(self, tenant, result, customer=self.customer)
            elif len(parts) == 2 and method in ("GET", "PATCH"):
                result = (risk_cases.detail(st, tenant, ident, q.get("offset", "0")) if method == "GET"
                          else risk_cases.update(st, tenant, ident, data, actor))
            elif len(parts) == 3 and parts[2] == "download" and method == "GET":
                case_id = uuid_param(parts[1], "case id")
                return Response(risk_cases.download(st, tenant, case_id), media_type="text/html", headers={
                    "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                    "Content-Disposition": f'attachment; filename="case-{case_id}.html"',
                })
            else:
                raise APIError(404, "no such route")
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "overview/summary" and method in ("GET", "POST"):
            require(set(data) <= {"refresh"} and type(data.get("refresh", False)) is bool,
                    "provide only a boolean refresh flag")
            if method == "GET":
                reply = response(self.overview_summary.cached(tenant, user, self.page_chat))
                reply.headers["Cache-Control"] = "no-store"
                return reply

            def read_summary_source(endpoint):
                source_path, _, query = endpoint.partition("?")
                # Reuse the same authenticated GET route and its authorization.
                scope = {**request.scope, "method": "GET", "path": "/api/v1/" + source_path,
                         "query_string": query.encode("ascii")}
                reply = self.console(Request(scope), source_path)
                return json.loads(reply.body)

            result = self.overview_summary.generate(
                tenant, user, read_summary_source, self.page_chat, data.get("refresh", False),
            )
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if len(parts) == 3 and parts[0] == "sessions" and parts[2] == "detection-owner" and method in ("GET", "PUT"):
            from . import detection_history

            if method == "PUT":
                require(set(data) == {"owner_user_id"}, "owner_user_id is required")
                result = detection_history.save_owner(st, tenant, parts[1], data["owner_user_id"], actor)
            else:
                result = detection_history.read_owner(st, tenant, parts[1])
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "audit/page-views" and method == "POST":
            from .query_sources import PAGES

            require(set(data) == {"path"}, "only path is accepted")
            visited = data["path"]
            require(isinstance(visited, str) and len(visited) <= 200, "invalid dashboard path")
            require(page_allowed(user, visited), "your roles do not allow this page", 403)
            template = visited
            details = {"source": "browser"}
            session = re.fullmatch(
                r"/sessions/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
                visited,
            )
            if session:
                session_id = session[1].lower()
                st.get_session_row(tenant, session_id)
                visited = "/sessions/" + session_id
                template = "/sessions/:id"
                details.update(resource_type="session", resource_id=session_id)
            report = re.fullmatch(
                r"/detections/reports/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
                visited,
            )
            if report:
                job_id = report[1].lower()
                if not st.scalar("SELECT EXISTS(SELECT 1 FROM session_investigation_jobs WHERE tenant_id=$1 AND id=$2)", tenant, job_id):
                    raise APIError(404, "record unavailable")
                visited = "/detections/reports/" + job_id
                template = "/detections/reports/:id"
                details.update(resource_type="session_investigation", resource_id=job_id)
            gateway = re.fullmatch(
                r"/gateways/(instances|requests)/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
                visited,
            )
            if gateway:
                kind, resource_id = gateway[1], gateway[2].lower()
                table = "gateway_instances" if kind == "instances" else "gateway_requests"
                if not st.scalar(f"SELECT EXISTS(SELECT 1 FROM {table} WHERE tenant_id=$1 AND id=$2)", tenant, resource_id):
                    raise APIError(404, "record unavailable")
                visited = f"/gateways/{kind}/{resource_id}"
                template = f"/gateways/{kind}/:id"
                details.update(resource_type="gateway" if kind == "instances" else "gateway_request", resource_id=resource_id)
            require(template in PAGES and (template != "/sessions/:id" or session)
                    and (template != "/detections/reports/:id" or report)
                    and (template not in ("/gateways/instances/:id", "/gateways/requests/:id") or gateway), "invalid dashboard path")
            details["page"] = PAGES[template]
            st.audit(tenant, actor, "dashboard.page.view", "dashboard_page", visited, details)
            return Response(status_code=204)
        if len(parts) == 4 and parts[:2] == ["inventory", "skills"]:
            from .skill_scanning import devices, save_approval

            if parts[3] == "devices" and method == "GET":
                result = devices(st, tenant, parts[2])
            elif parts[3] == "approval" and method == "PUT":
                result = save_approval(st, tenant, parts[2], data, actor)
            else:
                raise APIError(404, "not found")
            return JSONResponse(jsonable_encoder(result), headers={"Cache-Control": "no-store"})
        if path == "inventory/skills/llm" and method in ("GET", "PUT"):
            from . import customer_views, skill_llm

            result = (skill_llm.read(st, tenant, self.cfg, self.skill_content, customer=self.customer) if method == "GET"
                      else skill_llm.save(st, tenant, self.cfg, self.skill_content, data, actor, customer=self.customer))
            reply = response(customer_views.skill_settings(result))
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "settings/model-keys" and method in ("GET", "PUT"):
            result = (model_keys.read(st, tenant, self.cfg) if method == "GET"
                      else model_keys.save(st, tenant, data, actor, self.cfg))
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "settings/intelligence" and method == "PUT":
            return JSONResponse(jsonable_encoder(model_keys.save_connection(st, tenant, data, actor, self.cfg)),
                                headers={"Cache-Control": "no-store"})
        if path == "settings/intelligence/key" and method == "PUT":
            return JSONResponse(jsonable_encoder(model_keys.save_environment_key(st, tenant, data, actor, self.cfg)),
                                headers={"Cache-Control": "no-store"})
        if path == "settings/intelligence/check" and method == "POST":
            return JSONResponse(jsonable_encoder(model_keys.check_capabilities(tenant, data, self.cfg, st)),
                                headers={"Cache-Control": "no-store"})
        if path == "settings/tenant" and method == "PATCH":
            require(set(data) == {"name"}, "provide name only")
            require(isinstance(data["name"], str), "name must be text")
            name = data["name"].strip()
            require(1 <= len(name) <= 200, "name must contain 1 to 200 characters")
            require(all(ord(char) >= 32 and ord(char) != 127 for char in name),
                    "name must not contain control characters")
            updated = st.update_tenant(tenant, name=name)
            self.audit(tenant, actor, "tenant.update", "tenant", tenant, {"name": name})
            reply = response({key: updated[key] for key in ("id", "name", "slug")})
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "settings/support" and method in ("GET", "PUT"):
            from . import support

            result = support.read(st, tenant) if method == "GET" else support.save(st, tenant, data, actor)
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "settings/slack" and method in ("GET", "PUT"):
            from . import slack_notifications

            result = (slack_notifications.read(st, tenant, self.cfg) if method == "GET"
                      else slack_notifications.save(st, tenant, data, actor, self.cfg))
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "settings/feedback" and method in ("GET", "PUT"):
            from . import feedback_delivery

            result = (feedback_delivery.read(st, tenant, self.cfg) if method == "GET"
                      else feedback_delivery.save(st, tenant, data, actor, self.cfg))
            return JSONResponse(jsonable_encoder(result), headers={"Cache-Control": "no-store"})
        if path == "settings/feedback/withdraw" and method == "POST":
            from .feedback_delivery import withdraw

            return JSONResponse(withdraw(st, tenant, data, actor), status_code=202, headers={"Cache-Control": "no-store"})
        if path == "settings/summary-reports" and method in ("GET", "PUT"):
            from . import summary_report_sharing

            result = (summary_report_sharing.read(st, tenant, self.cfg) if method == "GET"
                      else summary_report_sharing.save(st, tenant, data, actor, self.cfg))
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path in ("settings/summary-reports/preview", "settings/summary-reports/send") and method == "POST":
            from .summary_report_sharing import preview, queue

            send = path.endswith("/send")
            reply = response((queue if send else preview)(st, tenant, data, actor, self.cfg), 202 if send else 200)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "settings/slack/test" and method == "POST":
            from .slack_notifications import queue_test

            reply = response(queue_test(st, tenant, data, actor, self.cfg), 202)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "settings/telemetry-retention" and method in ("GET", "PUT"):
            from .telemetry_retention import get_settings, save_settings

            result = (get_settings(st, tenant, self.cfg) if method == "GET"
                      else save_settings(st, tenant, data, actor, self.cfg))
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "inventory/application-review" and method == "GET":
            from .application_review import overview

            reply = response(overview(st, tenant, self.cfg))
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if len(parts) == 4 and parts[:2] == ["inventory", "application-review"]:
            from .application_review import devices, save_approval

            if parts[3] == "devices" and method == "GET":
                reply = response(devices(st, tenant, parts[2]))
            elif parts[3] == "approval" and method == "PUT":
                reply = response(save_approval(st, tenant, parts[2], data, actor))
            else:
                raise APIError(404, "not found")
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "inventory/ai-applications" and method == "GET":
            from .ai_inventory import overview

            reply = response(overview(st, tenant, request.query_params.get("days", "1")))
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if (len(parts) == 4 and parts[:2] == ["inventory", "ai-applications"]
                and parts[3] == "approval" and method == "PUT"):
            from .ai_inventory import save_approval

            reply = response(save_approval(st, tenant, parts[2], data, actor))
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path in ("response/session-detection", "settings/session-detection") and method in ("GET", "PUT"):
            from . import customer_views
            from .detection_eligibility import availability
            from .session_aggregation import get_settings, save_settings
            if self.customer:
                from .investigation_settings import read as get_settings, save as save_settings

            administrative = path == "settings/session-detection"
            expected_version = None
            if administrative and method == "PUT":
                require(isinstance(data, dict) and set(data) == {"enabled", "version"}
                        and type(data["version"]) is int and data["version"] >= 0,
                        "provide enabled and the current settings version")
                expected_version = data["version"]
                data = {"enabled": data["enabled"]}
            result = (
                get_settings(st, tenant) if method == "GET"
                else save_settings(st, tenant, data, actor, expected_version=expected_version)
            )
            if administrative:
                result["availability"] = availability(st, tenant, None, result, customer=self.customer)
                selected = model_keys.selected_connection(self.cfg, st)
                configured = selected is not None and selected.tenant_id == tenant
                if result["enabled"] and not configured:
                    result["availability"].update(reason="provider_unavailable", worker_ready=False)
            reply = response(customer_views.detection_settings(result))
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "response/company-policy" and method in ("GET", "PUT"):
            from . import company_policy

            result = (company_policy.read(st, tenant) if method == "GET"
                      else company_policy.save(st, tenant, data, actor))
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "response/guardrails" and method in ("GET", "PUT"):
            from .guardrail.inline import get_settings, save_settings

            result = (
                get_settings(st, tenant) if method == "GET"
                else save_settings(st, tenant, data, actor)
            )
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "response/hook-settings" and method in ("GET", "PUT"):
            from .hook_policy import get_settings, save_settings

            result = (get_settings(st, tenant) if method == "GET"
                      else save_settings(st, tenant, data, actor))
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "guardrail/flow" and method == "GET":
            from .guardrail.flow import summary

            reply = response(summary(st, tenant, q))
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "guardrail/checks" and method == "GET":
            from .guardrail.activity import checks

            reply = response(checks(st, tenant, q))
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "hook-decisions" and method == "GET":
            from .hook_policy import list_decisions

            reply = response(listing(list_decisions(st, tenant, page(q), q.get("classified") == "true")))
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "session-registrations/confirm" and method == "POST":
            from . import session_ownership

            reply = response(session_ownership.confirm(st, tenant, user["id"], data.get("token")))
            reply.headers["Cache-Control"] = "no-store"
            return reply
        match = re.fullmatch(r"session-registrations/([^/]+)/context-scope", path)
        if match and method in ("GET", "PUT"):
            from .guardrail.inline import get_context_scope, save_context_scope

            registration_id = uuid_param(match[1], "registration id")
            result = (
                get_context_scope(st, tenant, registration_id)
                if method == "GET"
                else save_context_scope(st, tenant, registration_id, data, actor)
            )
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "me/sessions" and method == "GET":
            from . import session_ownership

            reply = response(listing(session_ownership.list_sessions(st, tenant, user["id"], page(q)), "session"))
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if len(parts) == 4 and parts[:2] == ["me", "sessions"] and parts[3] == "evidence" and method == "GET":
            session_id = str(uuid.UUID(uuid_param(parts[2], "session id")))
            limit = page({"limit": q.get("limit")})["limit"]
            try:
                result = st.list_session_evidence(
                    tenant, session_id, limit, q.get("cursor", ""), owner_user_id=user["id"],
                )
                result["items"] = [public_record(row, "event") for row in result["items"]]
                reply = response(result)
                reply.headers["Cache-Control"] = "no-store"
                return reply
            except ValueError:
                raise APIError(400, "invalid cursor") from None
        if path == "knowledge" and method == "GET":
            return response(knowledge.read(st, tenant))
        if path == "knowledge/library" and method in ("GET", "PUT"):
            from . import knowledge_library

            if method == "PUT":
                result = knowledge.update(st, tenant, data)
                self.audit(tenant, actor, "knowledge.update", "knowledge", tenant, {
                    "enabled": result["enabled"], "revision": result["revision"],
                })
            return response(knowledge_library.read(st, tenant))
        if path == "knowledge/uploads" and method == "POST":
            from . import knowledge_files

            result = knowledge_files.upload(st, tenant, data)
            self.audit(tenant, actor, "knowledge.source.upload", "knowledge", tenant, {
                "revision": result["revision"], "source_id": result["source"]["source_id"],
            })
            reply = response(result)
            if fragmented:
                reply.headers["X-OpenAIDR-Upload-Complete"] = "1"
                reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "knowledge/mcp" and method in ("GET", "POST"):
            from . import knowledge_mcp

            if method == "GET":
                return response(knowledge_mcp.list_connections(st, tenant))
            result = knowledge_mcp.connect(st, self.cfg, tenant, data)
            self.audit(tenant, actor, "knowledge.mcp.connect", "knowledge", tenant, {
                "revision": result["revision"], "connection_id": result["connection"]["connection_id"],
            })
            return response(result)
        match = re.fullmatch(r"knowledge/mcp/([^/]+)/(resources|preview|sync|disconnect)", path)
        if match and method == "POST":
            from . import knowledge_mcp

            ident, action = match.groups()
            if action == "resources":
                require(not data, "no resource discovery fields are accepted")
                return response(knowledge_mcp.resources(st, self.cfg, tenant, ident))
            if action == "preview":
                result = knowledge_mcp.preview(st, self.cfg, tenant, ident, data)
                self.audit(tenant, actor, "knowledge.mcp.preview", "knowledge", tenant, {"connection_id": ident})
                return response(result)
            result = (knowledge_mcp.sync(st, self.cfg, tenant, ident, data) if action == "sync"
                      else knowledge_mcp.disconnect(st, tenant, ident, data))
            self.audit(tenant, actor, "knowledge.mcp." + action, "knowledge", tenant, {
                "revision": result["revision"], "connection_id": ident,
            })
            return response(result)
        if path in ("knowledge", "knowledge/documents") and method == "PUT":
            result = knowledge.update(st, tenant, data, documents=path.endswith("/documents"))
            self.audit(tenant, actor, "knowledge.update", "knowledge", tenant, {
                "enabled": result["enabled"], "revision": result["revision"],
                "document_count": len(result["documents"]),
            })
            return response(result)
        if path == "knowledge/retrieval" and method in ("GET", "PUT"):
            from . import knowledge_ingest

            result = (
                knowledge_ingest.settings(st, tenant) if method == "GET"
                else knowledge_ingest.set_mode(st, tenant, data)
            )
            if method == "PUT":
                self.audit(tenant, actor, "knowledge.retrieval.update", "knowledge", tenant, {
                    "revision": result["revision"], "retrieval_mode": result["retrieval_mode"],
                })
            return response(result)
        if path == "knowledge/sources" and method in ("GET", "POST"):
            from . import knowledge_ingest

            if method == "GET":
                return response(knowledge_ingest.list_sources(st, tenant))
            result = knowledge_ingest.import_source(st, tenant, data)
            self.audit(tenant, actor, "knowledge.source.import", "knowledge", tenant, {
                "revision": result["revision"], "source_id": result["source"]["source_id"],
            })
            return response(result)
        match = re.fullmatch(r"knowledge/sources/([^/]+)(?:/(verify|revoke|purge))?", path)
        if match:
            from . import knowledge_ingest

            source_id, action = match.groups()
            if method == "GET" and action is None:
                return response(knowledge_ingest.read_source(st, tenant, source_id))
            if method == "POST" and action in ("verify", "revoke", "purge"):
                operation = {
                    "verify": knowledge_ingest.verify_source,
                    "revoke": knowledge_ingest.revoke_source,
                    "purge": knowledge_ingest.purge_source,
                }[action]
                result = operation(st, tenant, source_id, data)
                self.audit(tenant, actor, "knowledge.source." + action, "knowledge", tenant, {
                    "revision": result["revision"], "source_id": source_id,
                })
                return response(result)
        if method == "GET":
            if path == "credits":
                from .credits import RANGES, overview

                range_name = q.get("range") or "24h"
                require(range_name in RANGES, "range must be 24h, 30d, or 90d")
                reply = response(overview(tenant, self.cfg, range_name, st=st))
                reply.headers["Cache-Control"] = "no-store"
                return reply
            if path == "costs/hook-estimates":
                from .hook_estimates import RANGES, overview
                range_name = q.get("range", "24h")
                require(range_name in RANGES, "range must be 24h, 7d, or 30d")
                return response(overview(st, tenant, range_name))
            if path == "costs/cursor-estimates":
                from .cursor_costs import RANGES, overview
                range_name = q.get("range", "24h")
                require(range_name in RANGES, "range must be 24h, 7d, or 30d")
                return response(overview(st, tenant, range_name))
            if path == "costs/agent-sessions":
                from .agent_sessions import overview
                return response(overview(st, tenant))
            if path == "costs/billing":
                from .agent_billing import overview
                provider = q.get("provider", "")
                require(provider in ("", "copilot", "cursor"), "unsupported billing provider")
                return response(overview(st, tenant, provider))
            if path == "costs/detections":
                raise APIError(410, "Use /api/v1/credits for OpenAIDR service usage.")
            if path in ("costs/agents", "costs/agents/summary", "costs/agents/filters"):
                from .agent_costs import DIMENSIONS, RANGES
                from .agent_cost_summaries import filter_options, overview

                range_name = q.get("range") or "24h"
                require(range_name in RANGES, "range must be 24h, 7d, 30d, or 90d")
                if path.endswith("/filters"):
                    dimension = q.get("dimension", "")
                    search = q.get("search", "")
                    require(dimension in DIMENSIONS, "invalid cost dimension")
                    require(len(search) <= 1024, "cost search is too long")
                    return response(
                        self.cost_cache.get(
                            st,
                            tenant,
                            ("filters", range_name, dimension, search),
                            lambda: filter_options(st, tenant, range_name, dimension, search),
                        )
                    )
                filters = {key: q.get(key, "") for key in DIMENSIONS}
                require(
                    all(len(value) <= 1024 for value in filters.values()),
                    "cost filter is too long",
                )
                if path == "costs/agents":
                    from .agent_cost_usage import overview as legacy_overview

                    return response(legacy_overview(st, tenant, range_name, filters))
                pages = {}
                for dimension in DIMENSIONS:
                    sort = q.get(dimension + "_sort", "cost_usd")
                    order = q.get(dimension + "_order", "desc")
                    offset = q.get(dimension + "_offset", "0")
                    require(sort in ("cost_usd", "calls"), "invalid cost sort")
                    require(order in ("asc", "desc"), "invalid cost order")
                    require(
                        offset.isascii() and offset.isdigit() and len(offset) <= 7,
                        "invalid cost offset",
                    )
                    pages[dimension] = dict(sort=sort, order=order, offset=int(offset))
                result = self.cost_cache.get(
                    st,
                    tenant,
                    (
                        "overview",
                        range_name,
                        json.dumps(filters, sort_keys=True),
                        json.dumps(pages, sort_keys=True),
                    ),
                    lambda: overview(st, tenant, range_name, filters, pages),
                )
                pending = st.one(
                    """SELECT count(*) AS pending_exports,min(received_at) AS pending_since
                    FROM telemetry_exports WHERE tenant_id=$1 AND signal='logs' AND costs_processed_at IS NULL""",
                    tenant,
                )
                pending["pending_since"] = (
                    pending["pending_since"].isoformat() if pending["pending_since"] else None
                )
                return response({**result, "processing": pending})
            if path == "events/risks":
                ids = q.get("ids", "").split(",")
                require(1 <= len(ids) <= 100, "provide between 1 and 100 event ids")
                for event_id in ids:
                    uuid_param(event_id, "event id")
                from .customer_views import guardrail_assessment

                return response({"items": [{**item, "risk": guardrail_assessment(item["risk"])}
                                           for item in st.event_risks(tenant, list(dict.fromkeys(ids)))]})
            if path == "ingestion/retained-records":
                from . import ingest_evidence

                reply = response(listing(ingest_evidence.listing(st, tenant, page(q))))
                reply.headers["Cache-Control"] = "no-store"
                return reply
            if len(parts) in (3, 4) and parts[:2] == ["ingestion", "retained-records"]:
                from . import ingest_evidence

                require(len(parts) == 3 or parts[3] == "download", "no such route", 404)
                evidence_id = uuid_param(parts[2], "evidence id")
                retained = ingest_evidence.read(st, tenant, evidence_id)
                self.audit(tenant, actor, "ingestion_evidence.read", "ingestion_evidence", evidence_id,
                           {"source": retained["source"], "payload_sha256": retained["payload_sha256"]})
                if len(parts) == 4:
                    return Response(bytes(retained["payload"]), media_type="application/octet-stream",
                                    headers={"Cache-Control": "no-store",
                                             "Content-Disposition": f'attachment; filename="{evidence_id}.json"'})
                reply = response(ingest_evidence.public(retained))
                reply.headers["Cache-Control"] = "no-store"
                return reply
            if path == "inventory/skills" or (len(parts) == 3 and parts[:2] == ["inventory", "skills"]):
                from .skill_scanning import overview, details

                result = overview(st, tenant, q, bool(self.cfg.skill_scanner_token)) if len(parts) == 2 else details(st, tenant, parts[2])
                return JSONResponse(jsonable_encoder(result), headers={"Cache-Control": "no-store"})
            if path == "inventory/attention-history":
                from .inventory_history import history

                return JSONResponse(jsonable_encoder(history(st, tenant, self.cfg.osv_assessment)),
                                    headers={"Cache-Control": "no-store"})
            if path in (
                "inventory/components",
                "inventory/roots",
                "inventory/relationships",
            ):
                from .component_inventory import list_inventory

                limit = page({"limit": q.get("limit")})["limit"]
                result = list_inventory(st, tenant, parts[-1], q, limit, q.get("cursor", ""))
                if path == "inventory/components":
                    from .osv import enrich

                    enrich(st, tenant, result[0], self.cfg.osv_assessment)
                return response(
                    listing(result)
                )
            if path in (
                "inventory/applications",
                "inventory/sources",
                "inventory/categories",
            ):
                from .app_inventory import category_counts, list_applications, list_sources

                q = dict(q)
                if q.get("sensor_id"):
                    uuid_param(q["sensor_id"], "sensor_id")
                    # uuid.UUID accepts forms PostgreSQL does not (urn:uuid:).
                    q["sensor_id"] = str(uuid.UUID(q["sensor_id"]))
                if path.endswith("/sources"):
                    return response(
                        {"items": list_sources(st, tenant, q.get("sensor_id", ""))}
                    )
                if path.endswith("/categories"):
                    return response({"categories": category_counts(st, tenant, q)})
                # Inventory pages by name, so its cursor is not the shared time cursor.
                limit = page({"limit": q.get("limit")})["limit"]
                return response(
                    listing(
                        list_applications(st, tenant, q, limit, q.get("cursor", ""))
                    )
                )
            if path == "sensors/health":
                return response({"items": [public_record(row, "sensor") for row in st.list_all_sensors(tenant)]})
            if path == "guardrail/devices":
                return response({"items": st.many("""
                    SELECT s.id,s.hostname,s.label,
                           CASE WHEN s.disabled THEN 'disabled'
                                WHEN sa.last_heartbeat_at >= now()-interval '90 seconds' THEN 'online'
                                ELSE 'offline' END AS status
                    FROM sensors s JOIN sensor_activity sa ON sa.sensor_id=s.id
                    WHERE s.tenant_id=$1 AND s.deleted_at IS NULL ORDER BY s.hostname,s.id
                """, tenant)})
            if len(parts) == 3 and parts[0] == "sensors" and parts[2] == "metrics":
                from .sensor_metrics import RANGES, history

                sensor_id = str(uuid.UUID(uuid_param(parts[1], "sensor id")))
                range_name = q.get("range", "24h")
                require(range_name in RANGES, "range must be 1h, 6h, 24h, 7d, or 30d")
                return response(history(st, tenant, sensor_id, range_name))
            if path in ("telemetry/overview", "telemetry/exports"):
                from .telemetry_dashboard import overview, recent_exports

                range_name = q.get("range") or "24h"
                require(
                    range_name in ("24h", "7d", "30d"), "range must be 24h, 7d, or 30d"
                )
                service_filter = q.get("service", "")
                require(len(service_filter) <= 1024, "service filter is too long")
                if path.endswith("/overview"):
                    return response(
                        self.telemetry_cache.get(
                            tenant, range_name, service_filter,
                            lambda: overview(st, tenant, range_name, service_filter),
                        )
                    )
                return response(
                    listing(
                        recent_exports(st, tenant, range_name, service_filter, page(q))
                    )
                )
            if len(parts) == 3 and path.startswith("telemetry/exports/"):
                from openaidr.core.telemetry import flatten_records

                uuid_param(ident, "export id")
                export = st.get_telemetry_export(tenant, ident)
                self.audit(
                    tenant,
                    actor,
                    "telemetry_export.read",
                    "telemetry_export",
                    ident,
                    {"signal": export["signal"], "batch_id": export["batch_id"]},
                )
                export["records"] = flatten_records(export["signal"], export["payload"])
                return response(public_record(export, "telemetry_export"))
            if path in ("guardrail/active", "guardrail/stats"):
                from .guardrail import analytics as guardrail

                if path.endswith("/active"):
                    return response(guardrail.active(st, tenant))
                range_name = q.get("range") or "24h"
                require(
                    range_name in guardrail.RANGES, "range must be 1h, 24h, 7d, or 30d"
                )
                source = q.get("source") or "endpoints"
                require(source in ("all", "endpoints", "gateways"), "source must be all, endpoints, or gateways")
                view = q.get("view") or "sources"
                require(view in ("sources", "unified"), "view must be sources or unified")
                if view == "unified":
                    return response(guardrail.history(st, tenant, range_name, source))
                return response(guardrail.stats(st, tenant, range_name, source))
            if path == "detections/rankings":
                from . import detection_rankings

                reply = response(detection_rankings.listing(
                    st, tenant, q.get("group") or "sessions", q.get("band") or "all",
                    page({"limit": q.get("limit", "25")})["limit"], q.get("cursor", ""),
                ))
                reply.headers["Cache-Control"] = "no-store"
                return reply
            if path == "detections/eligibility":
                from . import detection_eligibility

                reply = response(detection_eligibility.listing(
                    st, tenant, q.get("range") or "30d", q.get("q", ""),
                    page({"limit": q.get("limit", "25")})["limit"], q.get("cursor", ""), customer=self.customer,
                ))
                reply.headers["Cache-Control"] = "no-store"
                return reply
            if path == "detections/pipeline":
                from .detection_pipeline import RANGES, overview

                range_name = q.get("range") or "30d"
                require(range_name in RANGES, "range must be 7d, 30d, or 90d")
                reply = response(overview(st, tenant, range_name, customer=self.customer))
                reply.headers["Cache-Control"] = "no-store"
                return reply
            if path == "user-risk":
                group = q.get("group", "username")
                require(group in ("username", "identity"), "group must be username or identity")
                reply = response(st.user_risk(tenant, group))
                reply.headers["Cache-Control"] = "no-store"
                return reply
            if path == "overview":
                require(
                    q.get("range", "") in ("", "24h", "7d", "30d"),
                    "range must be 24h, 7d, or 30d",
                )
                require(q.get("view", "") in ("", "risk"), "view must be risk or omitted")
                result = st.get_overview(
                    tenant, q.get("range", ""), risk_only=q.get("view") == "risk", include_evidence=False
                )
                # Only aggregates cross this shared reporting boundary.
                result = {key: result[key] for key in (
                    "range", "agents", "sessions", "sensors", "findings_open", "by_category",
                    "timeline", "events", "by_product",
                ) if key in result}
                return response({**result, "recent_findings": [], "top_agents": []})
            if path == "users/detection-owners":
                return response({"items": [
                    {key: row[key] for key in ("id", "name", "email")}
                    for row in st.list_users(tenant) if row["status"] == "active"
                ]})
            if path == "users/assignees":
                return response({"items": [
                    {"id": row["id"], "name": row["name"]}
                    for row in st.list_users(tenant)
                    if row["status"] == "active" and has_role(row, "security_analyst")
                ]})
            simple = {
                "users": ("list_users", "user"),
                "users/invites": ("list_invites", "invite"),
                "sensors/enrollment-tokens": ("list_enrollment_tokens", "enrollment"),
            }
            if path in simple:
                method_name, kind = simple[path]
                return response({"items": [
                    public_record(row, kind) for row in getattr(st, method_name)(tenant) or []
                ]})
            if path == "response/policy":
                return response(st.get_policy(tenant))
            if path == "detections/rules":
                from .detect import rule_list

                return response(
                    {
                        "items": rule_list(
                            st.disabled_rules(tenant), st.rule_finding_counts(tenant)
                        )
                    }
                )
            if path == "system/status":
                return response(self.system_status(tenant))
            if path in ("system/diagnostics", "system/database"):
                if not self.cfg.database_diagnostics or self.cfg.tenant_id != tenant:
                    result = {"status": "disabled", "message": "Database diagnostics have not been enabled for this dedicated tenant database."}
                elif path == "system/database":
                    result = st.database_health(tenant)
                else:
                    result = self.database_diagnostics.read()
                reply = response(result)
                reply.headers["Cache-Control"] = "no-store"
                return reply
            if path == "system/metrics":
                from .host_metrics import RANGES, read_metrics

                range_name = q.get("range", "24h")
                require(range_name in RANGES, "range must be 5m, 1h, 6h, 24h, 7d, or 30d")
                metrics = read_metrics(self.cfg.host_metrics_path, range_name)
                require(metrics["status"] != "unavailable", metrics["message"], 503)
                return response(metrics)
            if path == "audit":
                category = q.get("category", "all")
                require(category in ("all", "actions", "page_views"), "invalid audit category")
                return response(listing(st.list_audit(tenant, page(q), category=category), "audit"))
            if path == "events/live":
                filters = {
                    key: q.get(key, "")
                    for key in (
                        "kind",
                        "product",
                        "agent_id",
                        "sensor_id",
                        "session_id",
                        "source",
                    )
                }
                require(
                    filters["source"] in ("", "otlp", "collector"),
                    "source must be otlp or collector",
                )
                for key in ("agent_id", "sensor_id", "session_id"):
                    if filters[key]:
                        uuid_param(filters[key], key)
                after = None
                if q.get("after"):
                    try:
                        after = store.decode_live_cursor(q["after"])
                    except ValueError:
                        raise APIError(400, "invalid after cursor") from None
                try:
                    limit = int(q.get("limit") or 100)
                except ValueError:
                    raise APIError(400, "invalid limit") from None
                require(limit >= 0, "invalid limit")
                rows, cursor, more = st.live_events(tenant, after, filters, limit or 100)
                return response({"items": [public_record(row, "event") for row in rows or []], "cursor": cursor, "more": more})
            lists = {
                "agents": ("list_agents", "agent"),
                "events": ("list_events", "event"),
                "findings": ("list_findings", "finding"),
                "sensors": ("list_sensors", "sensor"),
                "response/actions": ("list_actions", "action"),
            }
            if path in lists:
                filters = dict(q)
                if path == "findings":
                    require(
                        filters.get("source", "") in ("", "incident", "policy"),
                        "source must be incident or policy",
                    )
                    for key in ("username", "account"):
                        require(len(filters.get(key, "")) <= 1024, key + " is too long")
                        require("\x00" not in filters.get(key, ""), "invalid " + key)
                if path == "events":
                    require(
                        filters.get("source", "") in ("", "otlp", "collector"),
                        "source must be otlp or collector",
                    )
                    for key in ("username", "hostname", "session"):
                        require(len(filters.get(key, "")) <= 1024, key + " is too long")
                        require("\x00" not in filters.get(key, ""), "invalid " + key)
                for key in (
                    "agent_id",
                    "sensor_id",
                    "session_id",
                    "assignee_id",
                    "finding_id",
                ):
                    if filters.get(key):
                        uuid_param(filters[key], key)
                for key in (("since", "until", "before") if path == "events" else ("since", "until")):
                    if filters.get(key):
                        try:
                            filters[key] = parse_time(filters[key])
                            require(filters[key].tzinfo is not None, "invalid " + key)
                        except ValueError:
                            raise APIError(400, "invalid " + key) from None
                method_name, kind = lists[path]
                result = listing(getattr(st, method_name)(tenant, filters, page(q)), kind)
                if path == "findings":
                    for finding in result["items"]:
                        self.finish_finding(finding)
                return response(result)
            if len(parts) == 3 and parts[0] == "agents" and parts[2] == "sessions":
                uuid_param(parts[1], "agent id")
                st.get_agent(tenant, parts[1])
                return response(
                    listing(st.list_agent_sessions(tenant, parts[1], page(q)), "session")
                )
            if len(parts) == 3 and parts[0] == "sessions" and parts[2] == "events":
                uuid_param(parts[1], "session id")
                st.get_session_row(tenant, parts[1])
                return response(
                    listing(
                        st.list_session_events(
                            tenant, parts[1], q.get("kind", ""), page(q)
                        ), "event",
                    )
                )
            if len(parts) == 3 and parts[0] == "sessions" and parts[2] == "evidence":
                uuid_param(parts[1], "session id")
                limit = page({"limit": q.get("limit")})["limit"]
                try:
                    result = st.list_session_evidence(
                        tenant, parts[1], limit, q.get("cursor", "")
                    )
                    result["items"] = [public_record(row, "event") for row in result["items"]]
                    return response(result)
                except ValueError:
                    raise APIError(400, "invalid cursor") from None
            if len(parts) == 3 and parts[0] == "sensors" and parts[2] == "commands":
                sensor_id = uuid_param(parts[1], "sensor id")
                limit = page({"limit": q.get("limit")})["limit"]
                require(limit <= 200, "limit must be at most 200")
                return response(
                    {"items": st.list_commands(tenant, sensor_id, limit or 50) or []}
                )
            getters = {
                "agents": ("get_agent", "agent"),
                "events": ("get_event", "event"),
                "sessions": ("get_session_row", "session"),
                "sensors": ("get_sensor", "sensor"),
                "findings": ("get_finding", "finding"),
            }
            if len(parts) == 2 and parts[0] in getters:
                uuid_param(ident)
                method_name, kind = getters[parts[0]]
                result = getattr(st, method_name)(tenant, ident)
                result = public_record(result, kind)
                if parts[0] == "sensors":
                    result["agents"] = [public_record(row, "agent") for row in st.agents_for_sensor(tenant, ident) or []]
                if parts[0] == "findings":
                    self.finish_finding(result)
                    result = dict(
                        finding=result,
                        events=[public_record(row, "event") for row in st.get_events(tenant, result["event_ids"]) or []],
                        notes=[public_record(row, "note") for row in st.list_notes(tenant, ident) or []],
                        actions=[public_record(row, "action") for row in st.actions_for_finding(tenant, ident) or []],
                    )
                return response(result)
        if path == "users/invites" and method == "POST":
            return self.invite(tenant, actor, data)
        if path == "sensors/enrollment-tokens" and method == "POST":
            return self.enrollment_token(tenant, actor, data)
        if len(parts) == 3 and parts[0] == "sensors" and parts[2] == "commands" and method == "POST":
            # The sensor applies these on its next heartbeat and acknowledges
            # the outcome; see openaidr.sensor.runtime.Sensor.apply.
            sensor_id = uuid_param(parts[1], "sensor id")
            typ = data.get("type")
            require(
                typ in SENSOR_COMMANDS,
                "type must be install_hook, uninstall_hook, or refresh_policy",
            )
            agent = data.get("agent")
            if typ == "refresh_policy":
                require(agent is None, "refresh_policy takes no agent")
                params = {}
            else:
                # Named explicitly: an omitted agent must not silently mean Claude Code.
                require(
                    agent in HOOK_AGENTS,
                    "agent must be one of: " + ", ".join(HOOK_AGENTS),
                )
                params = {"agent": agent}
            command_id = st.queue_command(tenant, sensor_id, typ, params, "")
            self.audit(
                tenant, actor, "sensor.command", "sensor", sensor_id, {"type": typ, **params}
            )
            return JSONResponse(
                jsonable_encoder(st.get_command(tenant, sensor_id, command_id)),
                status_code=202,
            )
        if path == "sensors/enrollment-links" and method == "POST":
            hours = data.get("expires_in_hours", 1)
            uses = data.get("max_uses", 100)
            require(type(hours) is int and 1 <= hours <= 168, "Link expiration must be between 1 hour and 7 days")
            require(type(uses) is int and 1 <= uses <= 2147483647, "Max uses must be a whole number between 1 and 2,147,483,647")
            try:
                origin = enrollment_origin(self.cfg.public_url)
            except ValueError as exc:
                raise APIError(400, str(exc)) from None
            token = self.st.create_enrollment_token(tenant, data.get("label", ""), hours * 3600, uses)
            self.audit(tenant, actor, "enrollment_token.create", "enrollment_token", token["id"],
                       {"label": data.get("label", ""), "expires_in_hours": hours, "max_uses": uses})
            link = make_enrollment_link(origin, token.pop("token"))
            result = response(public_record(dict(token, enrollment_url=link), "enrollment"), 201)
            result.headers["Cache-Control"] = "no-store"
            return result
        if len(parts) >= 3 and parts[0] == "sensors" and self.device_credentials:
            sensor_id = uuid_param(parts[1], "sensor id")
            if len(parts) == 3 and parts[2] == "recovery-tokens" and method == "POST":
                result = self.device_credentials.recovery_token(sensor_id)
                self.audit(tenant, actor, "sensor.recovery_token.create", "sensor", sensor_id)
                reply = JSONResponse(jsonable_encoder(result), status_code=201)
                reply.headers["cache-control"] = "no-store"
                return reply
            if parts[2:] == ["credentials", "revoke"] and method == "POST":
                self.device_credentials.revoke(sensor_id)
                self.audit(tenant, actor, "sensor.credentials.revoke", "sensor", sensor_id)
                return Response(status_code=204)
        if method == "DELETE" and (
            path.startswith("users/invites/")
            or path.startswith("sensors/enrollment-tokens/")
        ):
            uuid_param(ident)
            invite = path.startswith("users/")
            (st.delete_invite if invite else st.revoke_enrollment_token)(tenant, ident)
            self.audit(
                tenant,
                actor,
                "invite.delete" if invite else "enrollment_token.revoke",
                "invite" if invite else "enrollment_token",
                ident,
            )
            return Response(status_code=204)
        if len(parts) == 2 and parts[0] == "users" and method in ("PATCH", "DELETE"):
            uuid_param(ident, "user id")
            with st.transaction() as conn:
                # Serialize account changes across API instances. This lock comes
                # before the identity/membership locks used by account removal.
                st.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    "tenant-users:" + tenant, conn=conn,
                )
                user = st.get_user(tenant, user["id"], conn=conn)
                require(user["status"] == "active", "account disabled", 403)
                require(has_role(user, "it_admin"), "requires role it_admin", 403)
                target = st.get_user(tenant, ident, conn=conn)
                roles = None
                if method == "DELETE":
                    require(ident != user["id"], "cannot delete your own account", 409)
                else:
                    require(set(data).issubset({"roles", "role", "status"}), "unexpected user fields")
                    if "roles" in data or "role" in data:
                        roles = requested_roles(data)
                    require("status" not in data or data["status"] in ("active", "disabled"),
                            "status must be active or disabled")
                removes_active = target["status"] == "active" and (
                    method == "DELETE" or data.get("status") == "disabled"
                )
                removes_admin = target["status"] == "active" and has_role(target, "it_admin") and (
                    removes_active or (roles is not None and "it_admin" not in roles)
                )
                if removes_active or removes_admin:
                    counts = st.active_user_counts(tenant, conn=conn)
                    require(not removes_active or counts["users"] > 1,
                            "the tenant needs at least one active user", 409)
                    require(not removes_admin or counts["it_admins"] > 1,
                            "the tenant needs at least one active IT Admin", 409)
                result = (
                    st.delete_user(tenant, ident, conn=conn)
                    if method == "DELETE"
                    else st.update_user(
                        tenant, ident, status=data.get("status", ""), roles=roles, conn=conn,
                    )
                )
            self.audit(
                tenant,
                actor,
                "user.delete" if method == "DELETE" else "user.update",
                "user",
                ident,
                {**data, "roles_before": assigned_roles(target),
                 "roles_after": [] if method == "DELETE" else assigned_roles(result)},
            )
            return Response(status_code=204) if method == "DELETE" else response(public_record(result, "user"))
        if len(parts) == 2 and parts[0] == "sensors" and method in ("PATCH", "DELETE"):
            uuid_param(ident, "sensor id")
            if method == "DELETE":
                st.delete_sensor(tenant, ident)
                self.audit(tenant, actor, "sensor.delete", "sensor", ident)
                return Response(status_code=204)
            require(
                data.get("host_kind") is None
                or data["host_kind"] in ("workstation", "server"),
                "host_kind must be workstation or server",
            )
            result = st.update_sensor(
                tenant,
                ident,
                data.get("label"),
                data.get("host_kind"),
                data.get("disabled"),
            )
            if data.get("disabled") is not None:
                st.queue_command(
                    tenant,
                    ident,
                    "disable" if data["disabled"] else "enable",
                    {"reason": "changed by " + user["name"]},
                    "",
                )
            self.audit(tenant, actor, "sensor.update", "sensor", ident, data)
            return response(public_record(result, "sensor"))
        if len(parts) >= 2 and parts[0] == "findings":
            fid = uuid_param(parts[1], "finding id")
            current = st.get_finding(tenant, fid)
            if len(parts) == 3 and parts[2] == "notes" and method == "POST":
                require(
                    isinstance(data.get("body"), str) and data["body"].strip(),
                    "body is required",
                )
                note = st.add_note(tenant, fid, user["id"], data["body"])
                self.audit(
                    tenant,
                    actor,
                    "finding.note",
                    "finding",
                    fid,
                    {"note_id": note["id"]},
                )
                return response(public_record(note, "note"), 201)
            if len(parts) == 2 and method == "PATCH":
                update = {
                    k: v
                    for k, v in data.items()
                    if k in ("status", "assignee_id", "resolution")
                }
                for key, value in update.items():
                    require(
                        value is None or isinstance(value, str),
                        key + " must be a string",
                    )
                if update.get("status") is not None:
                    require(
                        update["status"]
                        in ("open", "triaged", "resolved", "false_positive"),
                        "invalid status",
                    )
                    if update["status"] in ("resolved", "false_positive"):
                        require(
                            (
                                update["resolution"]
                                if update.get("resolution") is not None
                                else current.get("resolution", "")
                            ).strip(),
                            "resolution is required for " + update["status"],
                        )
                if update.get("assignee_id"):
                    uuid_param(update["assignee_id"], "assignee_id")
                    try:
                        st.get_user(tenant, update["assignee_id"])
                    except store.NotFound:
                        raise APIError(
                            400, "assignee is not a user of this tenant"
                        ) from None
                if "assignee_id" in update and update["assignee_id"] is None:
                    update["assignee_id"] = ""
                result = st.update_finding(tenant, fid, update)
                self.finish_finding(result)
                self.audit(tenant, actor, "finding.update", "finding", fid, update)
                return response(public_record(result, "finding"))
        if path.startswith("detections/rules/") and method == "PATCH":
            from .detect import rule_list

            require(isinstance(data.get("enabled"), bool), "enabled is required")
            rules = rule_list({}, {})
            require(any(r["id"] == ident for r in rules), "no such rule", 404)
            st.set_rule_enabled(tenant, ident, data["enabled"])
            self.audit(
                tenant, actor, "detection_rule.update", "detection_rule", ident, data
            )
            return response(
                next(
                    r
                    for r in rule_list(
                        st.disabled_rules(tenant), st.rule_finding_counts(tenant)
                    )
                    if r["id"] == ident
                )
            )
        if path == "response/actions" and method == "POST":
            return self.create_action(tenant, actor, data)
        if path.startswith("response/policy/rules/") and method in ("POST", "PATCH"):
            from . import rule_authoring

            if path == "response/policy/rules/generate" and method == "POST":
                require(set(data) == {"intent"}, "provide only a description")
                result = rule_authoring.generate(
                    data["intent"], self.page_chat, tenant,
                )
            elif path == "response/policy/rules/preview" and method == "POST":
                require(set(data) == {"version", "draft", "rule_id"}
                        and isinstance(data["rule_id"], str), "provide version, draft, and rule_id")
                policy = st.get_policy(tenant)
                rule_authoring.check_version(policy, data["version"])
                result = rule_authoring.preview(policy, data["draft"], data["rule_id"])
            elif path == "response/policy/rules/drafts" and method == "POST":
                require(set(data) == {"version", "draft"}, "provide version and draft")
                result = rule_authoring.save(st, tenant, actor, data["version"], draft=data["draft"])
            elif method == "PATCH" and len(parts) == 4:
                require(set(data) == {"version", "enabled"}, "provide version and enabled")
                result = rule_authoring.save(st, tenant, actor, data["version"],
                                            rule_id=ident, enabled=data["enabled"])
            else:
                raise APIError(404, "no such route")
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        if path == "response/policy" and method == "PUT":
            rules = data.get("rules") or []
            require(isinstance(rules, list), "rules must be an array")
            check_legacy_credential_rules(rules)
            rules = [validate_rule(r) for r in rules]
            # Stored ask rules are identified by id, so an id must name one rule.
            ids = [r["id"] for r in rules]
            require(len(ids) == len(set(ids)), "rule ids must be unique")
            result = st.save_policy(tenant, rules)
            self.audit(
                tenant,
                actor,
                "policy.replace",
                "policy",
                tenant,
                # What was saved: a legacy credential rule is split on save.
                {"version": result["version"], "rules": len(result["rules"])},
            )
            return response(result)
        if path == "response/policy/rules" and method == "POST":
            data["id"] = ""
            rule = validate_rule(data)
            existing = st.get_policy(tenant)["rules"]
            rules = existing + [rule]
            check_legacy_credential_rules(rules)
            result = st.save_policy(tenant, rules)
            # Audit the rules actually saved: a legacy credential rule is
            # split into three with ids derived from the one requested.
            before = {r.get("id") for r in existing}
            for added in [r for r in result["rules"] if r.get("id") not in before]:
                self.audit(
                    tenant, actor, "policy.rule.add", "policy_rule", added["id"], added
                )
            return response(result)
        if path.startswith("response/policy/rules/") and method == "DELETE":
            rules = st.get_policy(tenant)["rules"]
            kept = [r for r in rules if r["id"] != ident]
            require(len(kept) != len(rules), "no such rule", 404)
            result = st.save_policy(tenant, kept)
            self.audit(tenant, actor, "policy.rule.delete", "policy_rule", ident)
            return response(result)
        raise APIError(404, "no such route")

    @staticmethod
    def finish_finding(finding):
        from .detect import rule_name

        finding["rule_name"] = rule_name(finding["rule_id"])

    def invite(self, tenant, actor, data):
        email = data.get("email", "").strip().lower()
        require("@" in email, "valid email is required")
        if self.cloud_identity:
            require(self.cloud_identity.approved_email(email), "email domain is not approved", 403)
        roles = requested_roles(data)
        try:
            self.st.get_user_by_email(email)
        except store.NotFound:
            pass
        else:
            raise APIError(409, "a user with this email already exists")
        inv = self.st.create_invite(
            tenant, email, roles, actor["type"], actor["id"], 7 * 86400,
            require_absent=bool(self.cloud_identity),
        )
        inv["accept_url"] = (
            self.cfg.public_url.rstrip("/") + "/accept-invite?token=" + inv["token"]
        )
        if self.cloud_identity:
            inv.pop("token")
            inv["accept_url"] = self.cfg.public_url + "/login"
        self.audit(
            tenant,
            actor,
            "invite.create",
            "invite",
            inv["id"],
            {"email": email, "roles": roles},
        )
        return response(public_record(inv, "invite"), 201)

    def enrollment_token(self, tenant, actor, data):
        hours, uses = data.get("expires_in_hours", 0), data.get("max_uses", 0)
        require(
            isinstance(hours, int)
            and isinstance(uses, int)
            and hours >= 0
            and uses >= 0,
            "expires_in_hours and max_uses must not be negative",
        )
        token = self.st.create_enrollment_token(
            tenant, data.get("label", ""), hours * 3600, uses
        )
        self.audit(
            tenant,
            actor,
            "enrollment_token.create",
            "enrollment_token",
            token["id"],
            data,
        )
        return response(public_record(token, "enrollment"), 201)

    def create_action(self, tenant, actor, data):
        st = self.st
        fid, kind, params = (
            data.get("finding_id") or None,
            data.get("type"),
            data.get("params") or {},
        )
        require(
            isinstance(params, dict)
            and all(isinstance(v, str) for v in params.values()),
            "params must contain strings",
        )
        if fid:
            uuid_param(fid, "finding_id")
            st.get_finding(tenant, fid)
        if kind in ("block_command", "block_path", "block_host"):
            key, kinds, label = {
                "block_command": ("command_regex", ["command"], "command"),
                "block_path": ("path_glob", ["file.read", "file.write"], "path"),
                "block_host": ("host_glob", ["network", "command"], "host"),
            }[kind]
            require(params.get(key), "params." + key + " is required")
            rule = validate_rule(
                dict(
                    name="Block " + label + ": " + params[key][:60],
                    action="deny",
                    enabled=True,
                    reason=params.get("reason")
                    or "Blocked by OpenAIDR response action",
                    source="response:" + fid if fid else "tenant",
                    match={key: params[key], "kinds": kinds},
                )
            )
            policy = st.save_policy(tenant, st.get_policy(tenant)["rules"] + [rule])
            params.update(rule_id=rule["id"], policy_version=str(policy["version"]))
            result = st.create_action(
                tenant, fid, kind, params, "applied", actor["id"], True
            )
        elif kind in ("disable_sensor", "enable_sensor"):
            sid = uuid_param(params.get("sensor_id"), "params.sensor_id")
            disabled = kind == "disable_sensor"
            st.update_sensor(tenant, sid, None, None, disabled)
            result = st.create_action(
                tenant, fid, kind, params, "pending", actor["id"], False
            )
            st.queue_command(
                tenant,
                sid,
                "disable" if disabled else "enable",
                {"reason": params.get("reason", "")},
                result["id"],
            )
        elif kind == "note":
            require(params.get("text", "").strip(), "params.text is required")
            result = st.create_action(
                tenant, fid, kind, params, "applied", actor["id"], True
            )
        else:
            raise APIError(400, "unknown action type")
        self.audit(
            tenant,
            actor,
            "response_action.create",
            "response_action",
            result["id"],
            data,
        )
        return response(public_record(result, "action"), 201)

    def admin(self, request, path):
        from openaidr.platform.service import admin

        return admin(self, request, path)

    def system_status(self, tenant):
        st = self.st
        heartbeats = {
            h.get("service", h.get("name")): h for h in st.list_service_heartbeats()
        }
        services = []
        for name in ("ingest", "api", "detect", "admin"):
            hb = heartbeats.get(name)
            row = dict(name=name, status="unknown", last_seen_at=None)
            if hb:
                row.update(
                    last_seen_at=hb["last_seen_at"],
                    status="ok"
                    if (
                        datetime.now(timezone.utc) - parse_time(hb["last_seen_at"])
                    ).total_seconds()
                    <= 60
                    else "stale",
                )
            if name == "detect":
                row["lag_events"] = st.detect_lag(tenant)
                if self.engine and self.engine.last_run:
                    row["last_run_at"] = self.engine.last_run
            services.append(row)
        try:
            latency = st.ping()
            database = dict(ok=True, latency_ms=int(latency * 1000))
        except Exception:
            database = dict(ok=False, latency_ms=0)
        return dict(
            version=__version__,
            services=services,
            database=database,
            ingest=dict(
                events_last_hour=st.events_last_hour(tenant),
                sensors_online=st.sensors_online(tenant),
            ),
        )

    def dispatch(self, request):
        path = request.url.path
        try:
            if not PLATFORM_AVAILABLE and path.startswith(("/admin/", "/management/", "/reporting/", "/platform/", "/website/")):
                raise APIError(404, "no such route")
            if path.startswith("/internal/v1/skill-scans/"):
                from .skill_scanning import worker_request

                require(request.method == "POST", "no such route", 404)
                limit = 12 << 20 if path.endswith("/inference-bundle") else 6 << 20
                result = worker_request(self.st, self.cfg, request.headers.get("authorization", ""), path.rsplit("/", 1)[1], body(request, limit), self.skill_content, customer=self.customer)
                return JSONResponse(jsonable_encoder(result), headers={"Cache-Control": "no-store"})
            if PLATFORM_AVAILABLE:
                from openaidr.platform.service import dispatch

                result = dispatch(self, request)
                if result is not None:
                    return result
            if path == "/enroll" and request.method in ("GET", "HEAD") and self.cfg.enabled("ingest"):
                return PlainTextResponse(
                    "OpenAIDR device enrollment\n\nOpen OpenAIDR and paste this full enrollment link into the main window. Review the organization, then choose Connect. Opening this page does not use the link.\n",
                    headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
                )
            if path.startswith("/otlp/"):
                signal = (
                    path.removeprefix("/otlp/v1/")
                    if path.startswith("/otlp/v1/")
                    else ""
                )
                return self.otlp(request, signal)
            if path == "/healthz" and request.method in ("GET", "HEAD"):
                return response(dict(status="ok", version=__version__))
            if path == "/readyz" and request.method in ("GET", "HEAD"):
                try:
                    self.st.ping()
                    if self.device_credentials:
                        self.device_credentials.check_issuer()
                except Exception:
                    return response(
                        dict(status="required service unavailable" if self.device_credentials else "database unavailable", version=__version__), 503
                    )
                return response(dict(status="ok", version=__version__))
            for prefix, service in (
                ("/ingest/", "ingest"),
                ("/api/", "api"),
                ("/admin/v1/", "admin"),
            ):
                if not path.startswith(prefix):
                    continue
                require(self.cfg.enabled(service), "no such route", 404)
                root = (
                    "/ingest/v1/"
                    if service == "ingest"
                    else "/api/v1/"
                    if service == "api"
                    else prefix
                )
                require(path.startswith(root), "no such route", 404)
                route = path[len(root) :]
                if service == "ingest":
                    require(request.method == "POST", "no such route", 404)
                    return self.ingest(request, route)
                if request.method in ("POST", "PUT", "PATCH", "DELETE"):
                    self.browser_mutation(request, admin=service == "admin")
                if request.method in ("POST", "PUT", "PATCH"):
                    require(
                        request.headers.get("content-type", "")
                        .lower()
                        .startswith("application/json"),
                        "Content-Type must be application/json",
                        415,
                    )
                if route.startswith("auth/"):
                    name = route[5:]
                    allowed = {
                        "config": "GET",
                        "login": "POST",
                        "logout": "POST",
                        "me": "GET",
                    }
                    if service != "admin":
                        allowed.update({"invite": "GET", "accept-invite": "POST"})
                    if self.cloud_identity and service == "api":
                        allowed.update({"oidc/start": "POST", "oidc/callback": "GET", "oidc/invite": "GET", "oidc/accept": "POST", "renew": "POST"})
                    if self.staff_identity and service == "admin":
                        allowed.update({"oidc/start": "POST", "oidc/callback": "GET"})
                    require(
                        request.method == allowed.get(name),
                        "no such route",
                        404,
                    )
                    return self.auth_route(request, name, service == "admin")
                return (
                    self.admin(request, route)
                    if service == "admin"
                    else self.console(request, route)
                )
            if path in ("/platform/admins", "/platform/admins/"):
                require(self.cfg.enabled("admin"), "no such route", 404)
                return serve_app("admin")
            if path in ("/admin/admins", "/admin/admins/") and self.cfg.enabled("admin"):
                target = "/platform/admins"
                if request.url.query:
                    target += "?" + request.url.query
                return RedirectResponse(target, status_code=307)
            if path == "/admin" and self.cfg.enabled("admin"):
                return RedirectResponse("/admin/", status_code=301)
            if path.startswith("/admin/") and self.cfg.enabled("admin"):
                return serve_app("admin", path[7:])
            if self.cfg.enabled("api"):
                return serve_app("console", path.lstrip("/"))
            raise APIError(404, "no such route")
        except store.NotFound:
            return response(
                {"error": {"code": "not_found", "message": "not found"}}, 404
            )
        except store.Conflict:
            return response(
                {"error": {"code": "conflict", "message": "already exists"}}, 409
            )
        except (store.Busy, LockNotAvailable):
            result = response(
                {
                    "error": {
                        "code": "unavailable",
                        "message": "database is temporarily unavailable",
                    }
                },
                503,
            )
            result.headers["Retry-After"] = "1"
            return result
        except APIError as exc:
            result = response(
                {"error": {"code": exc.code, "message": exc.message}}, exc.status
            )
            if exc.status == 401 and exc.message == "session expired":
                self.cookie(result, admin=path.startswith("/admin/"))
            return result
        except Exception:
            log.exception("request failed: %s %s", request.method, path)
            return response(
                {"error": {"code": "internal", "message": "internal error"}}, 500
            )


async def share_summary_reports(st, cfg, stop):
    from .summary_report_sharing import run_once

    while not stop.is_set():
        try:
            await run_in_threadpool(run_once, st, cfg)
        except Exception:
            log.warning("Summary report delivery deferred")
        try:
            await asyncio.wait_for(stop.wait(), timeout=30)
        except TimeoutError:
            pass


def create_app(cfg, st, *, customer=False):
    enrollment = None
    if customer:
        from .service_operations import contracts
        contracts()
        from .service_enrollment import prepare, pending_config
        enrollment = prepare(cfg)
        if enrollment is not None:
            cfg = pending_config(cfg, enrollment)
    if not PLATFORM_AVAILABLE and cfg.enabled("admin"):
        raise ValueError("Cloud administration requires the private platform package")
    if (cfg.tenant_id or cfg.require_tenant or cfg.deployment_registry is not None
            or cfg.auth_mode != "local" or cfg.oidc_issuer or cfg.oidc_client_id or cfg.oidc_client_secret
            or cfg.admin_auth_mode != "local" or cfg.admin_google_client_id or cfg.admin_google_client_secret or cfg.admin_google_hosted_domain
            or cfg.device_auth_mode != "bearer" or cfg.inline_guardrails
            or cfg.session_investigator_binary or cfg.cloud_management_enabled or cfg.api_cost_report_origin
            or cfg.api_operations_enabled or cfg.api_operations_origin or cfg.api_operations_alert_rules
            or cfg.summary_report_origin or cfg.summary_report_token or cfg.summary_report_tokens or cfg.summary_report_bucket
            or cfg.skill_scanner_token or cfg.dashboard_mcp_enabled or cfg.threat_intel_origin or cfg.threat_intel_api_key
            or cfg.intelligence_origin or cfg.intelligence_api_key or cfg.intelligence_ca_file):
        cfg.validate(customer=customer)
    service = Service(cfg, st, customer=customer)
    def investigation_runtime(store):
        from .service_runtime import investigation_readiness
        return investigation_readiness(store, cfg)
    if cfg.enabled("detect"):
        from .detect import Engine

        service.engine = Engine(st, tenant_id=cfg.tenant_id)

    async def reconcile_risks(bounded_store, risk_stop):
        from .guardrail.inline import expire_pending
        from .guardrail.approvals import expire_pending as expire_approvals

        while not risk_stop.is_set():
            try:
                await run_in_threadpool(bounded_store.expire_risk_events, cfg.tenant_id or None)
                await run_in_threadpool(expire_pending, bounded_store, tenant_id=cfg.tenant_id or None)
                await run_in_threadpool(expire_approvals, bounded_store, tenant_id=cfg.tenant_id or None)
            except Exception:
                log.warning("Risk reconciliation storage unavailable")
            try:
                await asyncio.wait_for(risk_stop.wait(), timeout=2)
            except TimeoutError:
                pass

    session_workers = anyio.CapacityLimiter(1)

    async def investigate(worker, stop, readiness):
        instance = socket.gethostname() + ":" + str(os.getpid())
        while not stop.is_set():
            worked = False
            try:
                worked = await worker.run_once(
                    instance, cfg.tenant_id or None,
                    worker_ready=bool(readiness.get("ready")) and cfg.session_detection_scheduling,
                )
            except Exception:
                # Runtime/provider/storage exceptions can contain evidence.
                log.warning("Session investigation unavailable")
            try:
                await asyncio.wait_for(stop.wait(), timeout=0.1 if worked else 2)
            except TimeoutError:
                pass

    async def background(session_store=None, investigator_readiness=None):
        from .sensor_metrics import prune

        instance = socket.gethostname() + ":" + str(os.getpid())
        ticks = 0
        while True:
            try:
                if ticks % 3 == 0 and investigator_readiness is not None:
                    probe = await anyio.to_thread.run_sync(lambda: investigation_runtime(st))
                    investigator_readiness.update(probe)
                if ticks % 3 == 0:
                    for name in cfg.services:
                        details = dict(version=__version__, listen=cfg.listen)
                        if name == "detect" and service.engine:
                            details["tenant_id"] = cfg.tenant_id
                            details["session_detection_scheduling"] = cfg.session_detection_scheduling
                            details["last_run_at"] = (
                                service.engine.last_run.isoformat()
                                if service.engine.last_run
                                else None
                            )
                            details["session_investigator"] = investigator_readiness or {
                                "ready": False, "reason": "runtime_unavailable", "supported_models": [],
                            }
                        await run_in_threadpool(
                            st.service_heartbeat, name, instance, details
                        )
                if service.engine:
                    await run_in_threadpool(service.engine.tick)
                if cfg.enabled("detect") and session_store:
                    from .session_aggregation import finalize_pending
                    from .ordinary_session_detection import finalize_pending as finalize_ordinary

                    readiness = investigator_readiness or {}
                    await anyio.to_thread.run_sync(
                        partial(finalize_pending, session_store, tenant_id=cfg.tenant_id or None,
                                limit=1, scheduling_enabled=cfg.session_detection_scheduling,
                                worker_ready=bool(readiness.get("ready")),
                                supported_models=readiness.get("supported_models", []), protocol_version=4 if customer else 1),
                        limiter=session_workers,
                    )
                    await anyio.to_thread.run_sync(
                        partial(finalize_ordinary, session_store, tenant_id=cfg.tenant_id or None,
                                scheduling_enabled=cfg.session_detection_scheduling,
                                worker_ready=bool(readiness.get("ready")),
                                supported_models=readiness.get("supported_models", []), protocol_version=4 if customer else 1),
                        limiter=session_workers,
                    )
                if ticks % 12 == 0 and cfg.enabled("api"):
                    await run_in_threadpool(prune, st, cfg.tenant_id or None)
                    from .telemetry_retention import tick

                    await run_in_threadpool(tick, st, cfg)
            except Exception:
                log.exception("background service failed")
            ticks += 1
            await asyncio.sleep(5)

    async def deliver_slack(stop):
        from .slack_notifications import collect, dispatch_one

        while not stop.is_set():
            worked = False
            try:
                await run_in_threadpool(collect, st, cfg)
                worked = await run_in_threadpool(dispatch_one, st, cfg)
            except Exception:
                log.warning("Slack delivery queue unavailable")
            try:
                await asyncio.wait_for(stop.wait(), timeout=1 if worked else 5)
            except TimeoutError:
                pass


    async def deliver_feedback(stop):
        from .feedback_delivery import run_once

        while not stop.is_set():
            worked = False
            try:
                worked = await run_in_threadpool(run_once, st, cfg)
            except Exception:
                log.warning("Feedback delivery queue unavailable")
            try:
                await asyncio.wait_for(stop.wait(), timeout=1 if worked else 5)
            except TimeoutError:
                pass

    async def summarize_telemetry(stop):
        from .telemetry_dashboard import backfill_summaries

        while not stop.is_set():
            try:
                await run_in_threadpool(backfill_summaries, st, cfg.tenant_id or None)
            except Exception:
                log.exception("Telemetry summary backfill failed")
            try:
                await asyncio.wait_for(stop.wait(), timeout=2)
            except TimeoutError:
                pass

    async def retire_telemetry_keys(stop):
        from .telemetry_retention import cleanup_keys
        from .gateways import cleanup as cleanup_gateways

        while not stop.is_set():
            worked = False
            try:
                worked = await run_in_threadpool(cleanup_keys, st, cfg)
                worked = await run_in_threadpool(cleanup_gateways, st, cfg) or worked
            except Exception:
                log.warning("Telemetry identity cleanup deferred")
            try:
                await asyncio.wait_for(stop.wait(), timeout=0.1 if worked else 60)
            except TimeoutError:
                pass




    async def project_costs(stop):
        from .agent_cost_usage import process_pending
        from .agent_cost_summaries import rebuild_pending
        from .agent_projects import process_pending as project_sessions

        while not stop.is_set():
            worked = False
            try:
                result = await run_in_threadpool(process_pending, st, cfg.tenant_id or None)
                projects = await run_in_threadpool(project_sessions, st, cfg.tenant_id or None)
                hours = await run_in_threadpool(rebuild_pending, st, cfg.tenant_id or None)
                worked = bool(result["exports"] or projects or hours)
            except Exception:
                log.exception("Cost projection worker failed")
            try:
                await asyncio.wait_for(stop.wait(), timeout=0.01 if worked else 2)
            except TimeoutError:
                pass

    @asynccontextmanager
    async def lifespan(app):
        risk_stop = asyncio.Event()
        cleanup = AsyncExitStack()
        cleanup.callback(dashboard_mcp.close)
        intelligence = None
        task = credit_task = risk_task = cost_task = osv_task = inventory_history_task = None
        investigator_task = telemetry_task = retention_task = slack_task = diagnostics_task = None
        summary_report_task = feedback_task = overview_summary_task = risk_activity_task = None
        session_summary_task = classification_task = skill_content_task = statistics_task = upload_task = None
        platform_tasks = []
        try:
            bounded_store = None
            inline_store = None
            from .guardrail.clients import AsyncGuardrailClients
            if customer:
                from openaidr_api_client.clients.guardrail import AsyncGuardrailClient
                from .service_guardrail import contract
                inline_client = AsyncGuardrailClients(AsyncGuardrailClient, error_factory=contract())
            else:
                inline_client = AsyncGuardrailClients()
            cleanup.push_async_callback(inline_client.aclose)
            service.guardrail_clients = inline_client
            intelligence = None
            from openaidr_api_client.client import Connection

            connection = Connection.from_config(cfg)
            if customer:
                from .service_threat_intel import WorkspaceClient
                intelligence = WorkspaceClient(st, cfg)
            elif connection:
                from .intelligence import WorkspaceThreatIntelClient
                intelligence = WorkspaceThreatIntelClient(st, cfg)
            if intelligence:
                cleanup.push_async_callback(intelligence.aclose)
            if cfg.enabled("ingest") and intelligence:
                service.link_checker = intelligence
            session_store = None
            investigator_store = None
            investigator = None
            investigator_readiness = None
            if (cfg.enabled("api") or cfg.enabled("detect")
                    or (cfg.inline_guardrails and cfg.enabled("ingest"))):
                try:
                    from .guardrail.storage import risk_store

                    bounded_store = await run_in_threadpool(risk_store, st)
                    cleanup.push_async_callback(run_in_threadpool, bounded_store.close)
                except Exception:
                    log.warning("Risk reconciliation unavailable: storage initialization failed")
            if cfg.inline_guardrails and cfg.enabled("ingest"):
                from .guardrail.inline import InlineGuardrail
                from .guardrail.storage import risk_store

                try:
                    inline_store = await run_in_threadpool(
                        risk_store, st, db_pool_size=cfg.inline_guardrail_concurrency,
                    )
                    cleanup.push_async_callback(run_in_threadpool, inline_store.close)
                    service.inline_guardrail = InlineGuardrail(
                        inline_store, None, cfg,
                        client_for_tenant=lambda tenant: service.guardrail_client(tenant, inline_store),
                        customer=customer,
                    )
                except Exception:
                    log.warning("Inline guardrails unavailable: storage initialization failed")
            if cfg.enabled("detect"):
                from .guardrail.storage import risk_store

                try:
                    session_store = await run_in_threadpool(risk_store, st)
                    cleanup.push_async_callback(run_in_threadpool, session_store.close)
                except Exception:
                    log.warning("Session finalization unavailable: storage initialization failed")
                if customer:
                    probe = await anyio.to_thread.run_sync(lambda: investigation_runtime(st), limiter=session_workers)
                    try:
                        investigator_readiness = probe
                        investigator_store = await anyio.to_thread.run_sync(
                            partial(risk_store, st, db_pool_size=1), limiter=session_workers,
                        )
                        cleanup.push_async_callback(run_in_threadpool, investigator_store.close)
                        investigator = service.customer_investigator(investigator_store)
                        cleanup.push_async_callback(investigator.aclose)
                    except Exception:
                        investigator_readiness = {
                            "ready": False, "reason": "runtime_unavailable",
                            "protocol_version": 4,
                        }
                        log.warning("Session investigation unavailable: initialization failed")
            task = asyncio.create_task(source_job("Detection and maintenance", background(session_store, investigator_readiness)))
            investigator_task = (
                asyncio.create_task(source_job("Session investigation", investigate(investigator, risk_stop, investigator_readiness)))
                if investigator else None
            )
            risk_task = (
                asyncio.create_task(source_job("Risk reconciliation", reconcile_risks(bounded_store, risk_stop)))
                if bounded_store else None
            )
            cost_task = (
                asyncio.create_task(source_job("Cost processing", project_costs(risk_stop)))
                if cfg.cost_processing and (cfg.enabled("api") or cfg.enabled("detect"))
                else None
            )
            from .osv import run as assess_inventory

            osv_task = (
                asyncio.create_task(source_job("Inventory vulnerabilities", assess_inventory(st, risk_stop, cfg.tenant_id,
                                                                                             intelligence=intelligence, customer=customer)))
                if cfg.osv_assessment and cfg.enabled("detect") else None
            )
            from .inventory_history import run as record_inventory_history

            inventory_history_task = (
                asyncio.create_task(source_job("Inventory attention history", record_inventory_history(st, risk_stop, cfg.tenant_id)))
                if cfg.osv_assessment and cfg.enabled("detect") else None
            )
            platform_tasks = []
            if PLATFORM_AVAILABLE:
                from openaidr.platform.background import start

                platform_tasks = start(st, cfg, risk_stop)
            from .overview_summary import run as refresh_overview_summaries

            overview_summary_task = (
                asyncio.create_task(source_job("Overview summaries", refresh_overview_summaries(service, risk_stop)))
                if cfg.enabled("api") else None
            )
            from .risk_activity import run as refresh_risk_activity

            risk_activity_task = (
                asyncio.create_task(source_job("Activity snapshots", refresh_risk_activity(st, cfg, risk_stop)))
                if cfg.enabled("api") else None
            )
            from .session_activity_summaries import run as summarize_session_activity

            session_summary_task = (
                asyncio.create_task(source_job("Session activity summaries", summarize_session_activity(service, risk_stop, customer=customer)))
                if cfg.enabled("api") else None
            )
            from .application_classifier import run as classify_applications
            classification_task = (
                asyncio.create_task(source_job("Application classification", classify_applications(st, cfg, risk_stop, customer=customer)))
                if cfg.application_classification and cfg.enabled("api") else None
            )
            telemetry_task = (
                asyncio.create_task(source_job("Telemetry summaries", summarize_telemetry(risk_stop)))
                if cfg.enabled("api") else None
            )
            from .database_maintenance import run as maintain_statistics
            statistics_task = (
                asyncio.create_task(source_job("Database statistics", maintain_statistics(st, risk_stop)))
                if cfg.enabled("api") else None
            )
            retention_task = asyncio.create_task(source_job("Telemetry retention", retire_telemetry_keys(risk_stop))) if cfg.enabled("api") else None
            slack_task = (asyncio.create_task(source_job("Slack notifications", deliver_slack(risk_stop)))
                          if cfg.slack_webhook_key and cfg.enabled("api") else None)
            diagnostics_task = (
                asyncio.create_task(source_job("Database diagnostics", service.database_diagnostics.run(st, cfg.tenant_id, risk_stop)))
                if cfg.database_diagnostics and cfg.tenant_id and cfg.enabled("api") else None
            )
            summary_report_task = (asyncio.create_task(source_job("Summary report sharing", share_summary_reports(st, cfg, risk_stop)))
                                   if cfg.summary_report_origin and cfg.enabled("api") else None)
            feedback_task = (asyncio.create_task(source_job("Feedback sharing", deliver_feedback(risk_stop)))
                             if cfg.tenant_id and cfg.enabled("api") else None)
            from . import free_tier
            if enrollment is not None:
                credit_task = asyncio.create_task(enrollment.run_configured(cfg, risk_stop))
            elif not customer and free_tier.active(cfg):
                credit_task = asyncio.create_task(free_tier.run(cfg, risk_stop))
            skill_content_task = asyncio.create_task(service.skill_content.run(risk_stop))
            upload_task = asyncio.create_task(service.uploads.run(risk_stop))
            async with AsyncExitStack() as stack:
                if dashboard_mcp.app is not None:
                    await stack.enter_async_context(dashboard_mcp.app.router.lifespan_context(dashboard_mcp.app))
                yield
        finally:
            risk_stop.set()
            tasks = [running for running in (task, credit_task, risk_task, cost_task, osv_task,
                inventory_history_task, investigator_task, telemetry_task, retention_task, slack_task,
                diagnostics_task, summary_report_task, feedback_task, *platform_tasks, overview_summary_task,
                risk_activity_task, session_summary_task, classification_task, skill_content_task,
                statistics_task, upload_task) if running]
            for running in (task, credit_task, osv_task, inventory_history_task, classification_task, investigator_task):
                if running:
                    running.cancel()
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            finally:
                with anyio.CancelScope(shield=True):
                    try:
                        if service.link_checker and service.link_checker is not intelligence:
                            await service.link_checker.aclose()
                    finally:
                        try:
                            await cleanup.aclose()
                        finally:
                            service.link_checker = None
                            service.inline_guardrail = None

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.service = service
    app.state.store = st
    from .dashboard_mcp_lifecycle import configure, MAX_BODY as MCP_MAX_BODY, PROTOCOL_PATHS as MCP_PATHS

    dashboard_mcp = configure(service)
    app.state.dashboard_mcp = dashboard_mcp
    ingest_slots = asyncio.Semaphore(cfg.ingest_concurrency)
    inline_slots = asyncio.Semaphore(cfg.ingest_concurrency)
    owner_slots = asyncio.Semaphore(cfg.ingest_concurrency)
    owner_workers = anyio.CapacityLimiter(cfg.inline_guardrail_concurrency)
    operator_slots = asyncio.Semaphore(cfg.ingest_concurrency)
    operator_workers = anyio.CapacityLimiter(cfg.inline_guardrail_concurrency)
    hook_slots = asyncio.Semaphore(cfg.ingest_concurrency)
    cowork_slots = asyncio.Semaphore(min(2, cfg.ingest_concurrency))
    hook_workers = anyio.CapacityLimiter(cfg.inline_guardrail_concurrency)
    # A cancelled HTTP wait must not admit an unlimited number of still-running
    # authentication calls when storage is unhealthy.
    hook_threads = threading.BoundedSemaphore(cfg.inline_guardrail_concurrency)
    gateway_slots = asyncio.Semaphore(8)
    gateway_workers = anyio.CapacityLimiter(4)
    gateway_threads = threading.BoundedSemaphore(4)
    gateway_paths = re.compile(r"/ingest/v1/gateway-(?:checks|heartbeats|outcomes)")
    hook_paths = re.compile(r"/ingest/v1/hook-checks(?:/[^/]+/delivery)?")
    cowork_paths = re.compile(r"/integrations/v1/cowork/[^/]+/(?:hooks|inference|otlp/v1/logs)")
    inline_paths = re.compile(
        r"/ingest/v1/(?:guardrail-checks(?:/[^/]+/consume)?|approvals/[^/]+/status|"
        r"guardrail-releases/[^/]+/outcome|session-registrations/[^/]+/(?:delivery|close|delivery-status))"
    )
    owner_paths = re.compile(
        r"/api/v1/me/(?:approvals/[^/]+(?:/(?:decision|revoke))?|sessions/[^/]+/detection|"
        r"session-snapshots/[^/]+|session-investigations/[^/]+|session-investigation-reads/[^/]+)"
    )
    operator_paths = re.compile(
        r"/api/v1/(?:sessions/[^/]+/(?:detection|guardrail-actions)|session-snapshots/[^/]+|"
        r"session-investigations(?:/[^/]+)?|session-investigation-reads/[^/]+)"
    )

    @app.middleware("http")
    async def middleware(request, call_next):
        request_id = request.headers.get("x-request-id") or secrets.token_hex(8)
        content = bytearray()
        guarded = bool(
            gateway_paths.fullmatch(request.url.path)
            or hook_paths.fullmatch(request.url.path)
            or cowork_paths.fullmatch(request.url.path)
            or inline_paths.fullmatch(request.url.path)
            or owner_paths.fullmatch(request.url.path)
            or operator_paths.fullmatch(request.url.path)
        )
        body_limit = (
            service.uploads.CHUNK_BYTES if request.url.path.startswith("/ingest/v1/uploads/")
            or request.url.path == "/api/v1/knowledge/uploads/chunks"
            else MCP_MAX_BODY if request.url.path in MCP_PATHS or request.url.path.startswith("/api/v1/mcp/")
            else 12 << 20 if request.url.path == "/internal/v1/skill-scans/inference-bundle"
            else 64 << 20 if cowork_paths.fullmatch(request.url.path) and request.url.path.endswith("/inference")
            else 8 << 20 if cowork_paths.fullmatch(request.url.path) and request.url.path.endswith("/logs")
            else 64 << 10 if cowork_paths.fullmatch(request.url.path)
            else 16 << 10 if request.url.path == "/reporting/v1/summary-reports"
            else 64 << 10 if gateway_paths.fullmatch(request.url.path)
            or request.url.path in ("/ingest/v1/guardrail-checks", "/ingest/v1/hook-checks")
            or request.url.path.startswith("/ingest/v1/session-registrations/") and request.url.path.endswith("/delivery")
            else 4 << 10 if guarded else 8 << 20
        )
        try:
            async for chunk in request.stream():
                content.extend(chunk)
                if len(content) > body_limit:
                    if request.url.path.startswith("/otlp/"):
                        from .otlp import error_response

                        result = error_response(
                            413,
                            "request body too large",
                            request.headers.get("content-type", ""),
                        )
                        result.headers["X-Request-Id"] = request_id
                        return result
                    result = response(
                        {
                            "error": {
                                "code": "bad_request",
                                "message": "request body too large",
                            }
                        },
                        413,
                    )
                    result.headers["X-Request-Id"] = request_id
                    if guarded:
                        result.headers["Cache-Control"] = "no-store"
                    return result
        except ClientDisconnect:
            if request.url.path not in MCP_PATHS and not request.url.path.startswith("/api/v1/mcp/"):
                raise
            return response({"error": {"code": "unavailable", "message": "MCP request interrupted"}}, 503)
        request.state.body = bytes(content)
        with query_source(request_source(request.method, request.url.path, request.headers)):
            result = await call_next(request)
        result.headers["X-Request-Id"] = request_id
        if guarded:
            result.headers["Cache-Control"] = "no-store"
        log.info(
            "%s %s %s request_id=%s",
            request.method,
            request.url.path,
            result.status_code,
            request_id,
        )
        return result

    @app.middleware("http")
    async def limit_ingestion(request, call_next):
        if request.url.path in MCP_PATHS or request.url.path.startswith("/api/v1/mcp/"):
            return await dashboard_mcp.admit(request, call_next)
        if cowork_paths.fullmatch(request.url.path):
            if cowork_slots.locked():
                return guardrail_error(APIError(503, "Cowork capacity exhausted", "unavailable"))
            request.state.hook_deadline = time.monotonic() + 4
            try:
                async with cowork_slots, asyncio.timeout(4):
                    return await call_next(request)
            except TimeoutError as exc:
                return guardrail_error(exc)
        if gateway_paths.fullmatch(request.url.path):
            from .gateways import WORK_SECONDS

            if gateway_slots.locked():
                return guardrail_error(APIError(503, "gateway capacity exhausted", "unavailable"))
            await gateway_slots.acquire()
            request.state.gateway_deadline = time.monotonic() + WORK_SECONDS
            try:
                async with asyncio.timeout(WORK_SECONDS):
                    return await call_next(request)
            except TimeoutError as exc:
                return guardrail_error(exc)
            finally:
                gateway_slots.release()
        if hook_paths.fullmatch(request.url.path):
            from .hook_policy import WORK_TIMEOUT_SECONDS

            request.state.hook_deadline = time.monotonic() + WORK_TIMEOUT_SECONDS
            try:
                async with asyncio.timeout(WORK_TIMEOUT_SECONDS):
                    async with hook_slots:
                        return await call_next(request)
            except TimeoutError as exc:
                return guardrail_error(exc)
        slots = (
            owner_slots if owner_paths.fullmatch(request.url.path) and cfg.enabled("api")
            else operator_slots if operator_paths.fullmatch(request.url.path) and cfg.enabled("api")
            else inline_slots if inline_paths.fullmatch(request.url.path)
            and cfg.enabled("ingest") and cfg.inline_guardrails else None
        )
        if slots is not None:
            # Bound retained requests before reading bodies or doing database
            # work. Inline bookkeeping has its own worker limiter as well.
            if slots.locked():
                result = response(
                    {"error": {"code": "unavailable", "message": "guardrail capacity exhausted"}},
                    503,
                )
                result.headers["Cache-Control"] = "no-store"
                result.headers["Retry-After"] = "1"
                result.headers["X-Request-Id"] = request.headers.get("x-request-id") or secrets.token_hex(8)
                return result
            await slots.acquire()
            try:
                return await call_next(request)
            finally:
                slots.release()
        if not (
            request.url.path in ("/ingest/v1/events", "/ingest/v1/uploads/events")
            or request.url.path.startswith("/otlp/")
            or request.url.path.startswith("/ingest/v1/uploads/otlp/")
        ):
            return await call_next(request)
        # Wait before reading the body or occupying a synchronous request worker.
        # Authentication and control routes can still obtain worker/pool slots.
        try:
            async with asyncio.timeout(cfg.db_pool_timeout):
                await ingest_slots.acquire()
        except TimeoutError:
            if request.url.path.startswith("/otlp/"):
                from .otlp import error_response

                result = error_response(
                    503,
                    "ingestion capacity exhausted",
                    request.headers.get("content-type", ""),
                )
            else:
                result = response(
                    {
                        "error": {
                            "code": "unavailable",
                            "message": "ingestion capacity exhausted",
                        }
                    },
                    503,
                )
            result.headers["Retry-After"] = "1"
            result.headers["X-Request-Id"] = request.headers.get(
                "x-request-id"
            ) or secrets.token_hex(8)
            return result
        try:
            return await call_next(request)
        finally:
            ingest_slots.release()

    def guardrail_request(request, limit=64 << 10):
        require(cfg.enabled("ingest") and cfg.inline_guardrails, "no such route", 404)
        require(
            request.headers.get("content-type", "").lower().startswith("application/json"),
            "Content-Type must be application/json", 415,
        )
        sensor = service.sensor_principal(request)
        require(not sensor["disabled"], "sensor is disabled", 403)
        tenant = st.get_tenant_brief(sensor["tenant_id"])
        require(tenant["status"] == "active", "tenant is " + tenant["status"], 403)
        try:
            payload = body(request, limit)
        except RecursionError:
            raise APIError(400, "invalid json") from None
        return sensor, payload

    def guardrail_error(exc, *, owner=False):
        if isinstance(exc, store.NotFound):
            reply = response({"error": {"code": "not_found", "message": "not found"}}, 404)
        elif isinstance(exc, store.Conflict):
            reply = response({"error": {"code": "conflict", "message": "already exists"}}, 409)
        elif isinstance(exc, APIError):
            reply = response({"error": {"code": exc.code, "message": exc.message}}, exc.status)
            if owner and exc.status == 401 and exc.message == "session expired":
                service.cookie(reply)
        else:
            # Storage exceptions can include captured content or credentials.
            log.warning("Guardrail request unavailable (%s)", type(exc).__name__)
            reply = response(
                {"error": {"code": "unavailable", "message": "guardrail service is unavailable"}}, 503,
            )
        reply.headers["Cache-Control"] = "no-store"
        return reply

    def ordinary_hook_request(request, payload, deadline, ident=None):
        from . import hook_policy

        if not hook_threads.acquire(timeout=max(0, deadline - time.monotonic())):
            raise APIError(503, "hook capacity exhausted", "unavailable")
        try:
            sensor = service.sensor_principal(request)
            require(not sensor["disabled"], "sensor is disabled", 403)
            tenant = st.get_tenant_brief(sensor["tenant_id"])
            require(tenant["status"] == "active", "tenant is " + tenant["status"], 403)
            if ident:
                return hook_policy.delivery(st, sensor, ident, payload, deadline), 200
            return hook_policy.prepare(st, sensor, payload, deadline,
                                       link_detection=service.link_checker is not None, customer=customer)
        finally:
            hook_threads.release()

    @app.post("/ingest/v1/gateway-checks")
    @app.post("/ingest/v1/gateway-heartbeats")
    @app.post("/ingest/v1/gateway-outcomes")
    async def gateway_ingest(request: Request):
        from . import gateways

        def bounded_work(fn, args):
            if not gateway_threads.acquire(blocking=False):
                raise APIError(503, "gateway storage capacity exhausted", "unavailable")
            try:
                return fn(*args)
            finally:
                gateway_threads.release()

        async def run_sync(fn, *args):
            return await anyio.to_thread.run_sync(
                partial(bounded_work, fn, args), limiter=gateway_workers, abandon_on_cancel=True,
            )

        try:
            require(cfg.enabled("ingest"), "no such route", 404)
            require(request.headers.get("content-type", "").lower().startswith("application/json"),
                    "Content-Type must be application/json", 415)
            payload = body(request, gateways.MAX_BODY)
            authorization = request.headers.get("authorization", "")
            require(authorization.startswith("Bearer "), "invalid gateway credential", 401)
            token = authorization[7:]
            deadline = request.state.gateway_deadline
            if request.url.path.endswith("gateway-checks"):
                gateways.validate_check(payload)
                deadline = min(deadline, time.monotonic() + payload["timeout_ms"] / 1000)
                async with asyncio.timeout(max(0, deadline-time.monotonic())):
                    result, status = await gateways.check(
                        st, cfg, token, payload, deadline, service.guardrail_clients, run_sync, customer=customer,
                    )
            else:
                fn = gateways.heartbeat if request.url.path.endswith("gateway-heartbeats") else gateways.outcome
                result = await run_sync(fn, st, cfg, token, payload, deadline)
                status = 200
            require(time.monotonic() < deadline, "gateway deadline exceeded", 503)
            reply = response(result, status)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        except (ValueError, RecursionError):
            return guardrail_error(APIError(400, "invalid gateway request"))
        except Exception as exc:
            return guardrail_error(exc)

    @app.post("/ingest/v1/hook-checks")
    @app.post("/ingest/v1/hook-checks/{ident}/delivery")
    async def ordinary_hook_check(request: Request, ident: str = None):
        from . import hook_policy

        try:
            require(cfg.enabled("ingest"), "no such route", 404)
            require(request.headers.get("content-type", "").lower().startswith("application/json"),
                    "Content-Type must be application/json", 415)
            payload = body(request, 4 << 10) if ident else hook_policy.parse(request.state.body)
            deadline = request.state.hook_deadline
            if ident is None:
                hook_policy.validate(payload)
            async with asyncio.timeout(max(0, deadline - time.monotonic())):
                result, status = await anyio.to_thread.run_sync(
                    partial(ordinary_hook_request, request, payload, deadline, ident),
                    limiter=hook_workers, abandon_on_cancel=True,
                )
                if ident is None:
                    async def run_sync(fn, *args):
                        return await anyio.to_thread.run_sync(
                            partial(fn, *args), limiter=hook_workers, abandon_on_cancel=True,
                        )
                    result, status = await hook_policy.check(
                        st, result, status, deadline,
                        service.guardrail_client(result["tenant_id"]),
                        run_sync, link_client=service.link_checker, customer=customer,
                    )
            if time.monotonic() >= request.state.hook_deadline:
                raise APIError(503, "hook deadline exceeded", "unavailable")
            reply = response(result, status)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        except Exception as exc:
            return guardrail_error(exc)

    @app.post("/integrations/v1/cowork/{ident}/hooks")
    @app.post("/integrations/v1/cowork/{ident}/inference")
    @app.post("/integrations/v1/cowork/{ident}/otlp/v1/logs")
    async def cowork_request(request: Request, ident: str):
        import hashlib

        from . import cowork, hook_policy
        from openaidr.core.telemetry import decode_export, response_bytes
        from openaidr.guardrail.hooks import native_response

        inference = request.url.path.endswith("/inference")
        telemetry = request.url.path.endswith("/logs")
        allow = {"action": "allow"} if inference else {}
        authenticated = False
        deadline = request.state.hook_deadline

        async def run_sync(fn, *args):
            def invoke():
                if not hook_threads.acquire(timeout=max(0, deadline - time.monotonic())):
                    raise TimeoutError("Cowork capacity exhausted")
                try:
                    return fn(*args)
                finally:
                    hook_threads.release()
            return await anyio.to_thread.run_sync(invoke, limiter=hook_workers, abandon_on_cancel=True)

        try:
            connection = await run_sync(partial(
                cowork.authenticate, service, ident, request.headers, request.state.body,
                inference=inference, deadline=deadline,
            ))
            authenticated = True
            media = request.headers.get("content-type", "").split(";", 1)[0].lower()
            if telemetry:
                require(media in ("application/json", "application/x-protobuf"), "unsupported OTLP type", 415)
                payload = await run_sync(decode_export, "logs", request.state.body, media, request.headers.get("content-encoding", ""))
                batch = request.headers.get("x-openaidr-batch-id") or hashlib.sha256(request.state.body).hexdigest()
                require(len(batch) <= 256, "invalid batch identity")
                await run_sync(cowork.telemetry, service, connection, payload, batch, deadline)
                return Response(response_bytes("logs", media), media_type=media,
                                headers={"Cache-Control": "no-store"})
            require(media == "application/json", "Content-Type must be application/json", 415)
            row, created, check, payload = await run_sync(
                cowork.prepare_hook, service, connection, request.headers, request.state.body, inference, deadline,
            )
            result = allow
            if row is not None:
                decision, status = await hook_policy.check(
                    st, row, created, deadline,
                    service.guardrail_client(row["tenant_id"]),
                    run_sync, link_client=service.link_checker, customer=customer,
                )
                if status == 200 and time.monotonic() < deadline:
                    action = returned = decision["returned_decision"]
                    if inference:
                        returned = "deny" if action in ("deny", "ask") else "allow"
                        if returned == "deny":
                            result = {"action": "deny", "deny_reason": decision["reason"][:500],
                                      "reference_id": decision["id"]}
                    elif not inference and check.get("control_supported", True):
                        returned, result = native_response("cowork", check["hook_event"], action, decision["reason"], payload)
                    if returned != action:
                        await run_sync(cowork.record_returned, st, row, returned, deadline)
            return JSONResponse(result, headers={"Cache-Control": "no-store"})
        except APIError as exc:
            if not authenticated or exc.status in (401, 403) or telemetry:
                return guardrail_error(exc)
        except Exception as exc:
            if not authenticated or telemetry:
                return guardrail_error(exc)
            log.warning("Cowork hook unavailable (%s)", type(exc).__name__)
        return JSONResponse(allow, headers={"Cache-Control": "no-store"})

    @app.post("/ingest/v1/guardrail-checks")
    async def guardrail_check(request: Request):
        try:
            require(cfg.enabled("ingest") and cfg.inline_guardrails, "no such route", 404)
            guardrail = service.inline_guardrail
            if guardrail is None:
                raise APIError(503, "guardrail service is unavailable", "unavailable")
            sensor, payload = await guardrail.run_sync(guardrail_request, request)
            result, status = await guardrail.check(sensor, payload)
            reply = response(result, status)
        except Exception as exc:
            return guardrail_error(exc)
        reply.headers["Cache-Control"] = "no-store"
        return reply

    def owner_approval_request(request, approval_id):
        from .guardrail import approvals

        require(cfg.enabled("api"), "no such route", 404)
        if request.method == "POST":
            service.browser_mutation(request)
            require(
                request.headers.get("content-type", "").lower().startswith("application/json"),
                "Content-Type must be application/json", 415,
            )
        principal = service.principal(request)
        tenant_id, user_id = principal["tenant"]["id"], principal["user"]["id"]
        if request.method == "GET":
            return approvals.owner_get(st, tenant_id, user_id, approval_id), 200
        handler = approvals.owner_revoke if request.url.path.endswith("/revoke") else approvals.owner_decide
        try:
            payload = body(request, 4 << 10)
        except RecursionError:
            raise APIError(400, "invalid json") from None
        return handler(st, tenant_id, user_id, approval_id, payload)

    @app.get("/api/v1/me/approvals/{approval_id}")
    @app.post("/api/v1/me/approvals/{approval_id}/decision")
    @app.post("/api/v1/me/approvals/{approval_id}/revoke")
    async def owner_approval(request: Request, approval_id: str):
        try:
            result, status = await anyio.to_thread.run_sync(
                partial(owner_approval_request, request, approval_id), limiter=owner_workers,
            )
            reply = response(result, status)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        except Exception as exc:
            return guardrail_error(exc, owner=True)

    @app.post("/ingest/v1/approvals/{ident}/status")
    @app.post("/ingest/v1/guardrail-checks/{ident}/consume")
    @app.post("/ingest/v1/guardrail-releases/{ident}/outcome")
    async def sensor_approval(request: Request, ident: str):
        from .guardrail import approvals

        try:
            require(cfg.enabled("ingest") and cfg.inline_guardrails, "no such route", 404)
            guardrail = service.inline_guardrail
            if guardrail is None:
                raise APIError(503, "guardrail service is unavailable", "unavailable")
            sensor, payload = await guardrail.run_sync(guardrail_request, request, 4 << 10)
            handler = {
                "status": approvals.sensor_status,
                "consume": approvals.consume,
                "outcome": approvals.record_outcome,
            }[request.url.path.rsplit("/", 1)[1]]
            result = await guardrail.run_sync(handler, guardrail.st, sensor, ident, payload)
            result, status = (result, 200) if handler is approvals.sensor_status else result
            reply = response(result, status)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        except Exception as exc:
            return guardrail_error(exc)

    @app.post("/ingest/v1/session-registrations/{ident}/delivery")
    @app.post("/ingest/v1/session-registrations/{ident}/close")
    @app.post("/ingest/v1/session-registrations/{ident}/delivery-status")
    async def session_delivery(request: Request, ident: str):
        from . import session_aggregation

        try:
            require(cfg.enabled("ingest") and cfg.inline_guardrails, "no such route", 404)
            guardrail = service.inline_guardrail
            if guardrail is None:
                raise APIError(503, "guardrail service is unavailable", "unavailable")
            action = request.url.path.rsplit("/", 1)[1]
            sensor, payload = await guardrail.run_sync(
                guardrail_request, request, 64 << 10 if action == "delivery" else 4 << 10,
            )
            if action == "delivery-status":
                require(payload == {}, "status body must be empty")
                result = await guardrail.run_sync(session_aggregation.status, guardrail.st, sensor, ident)
                status = 200
            else:
                handler = session_aggregation.receive if action == "delivery" else session_aggregation.close
                result, status = await guardrail.run_sync(handler, guardrail.st, sensor, ident, payload)
            reply = response(result, status)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        except Exception as exc:
            return guardrail_error(exc)

    def owner_session_request(request, ident):
        from . import session_aggregation

        require(cfg.enabled("api"), "no such route", 404)
        principal = service.principal(request)
        tenant_id, user_id = principal["tenant"]["id"], principal["user"]["id"]
        if request.url.path.startswith("/api/v1/me/session-investigation"):
            from . import session_investigator

            handler = (
                session_investigator.owner_read
                if request.url.path.startswith("/api/v1/me/session-investigation-reads/")
                else session_investigator.owner_job
            )
            return handler(st, tenant_id, user_id, uuid_param(ident))
        if request.url.path.startswith("/api/v1/me/session-snapshots/"):
            query = request.query_params
            return session_aggregation.read_snapshot(
                st, tenant_id, user_id, ident,
                limit=page({"limit": query.get("limit")})["limit"] or 100, cursor=query.get("cursor", ""),
            )
        return session_aggregation.owner_session_status(st, tenant_id, user_id, ident)

    @app.get("/api/v1/me/sessions/{ident}/detection")
    @app.get("/api/v1/me/session-snapshots/{ident}")
    @app.get("/api/v1/me/session-investigations/{ident}")
    @app.get("/api/v1/me/session-investigation-reads/{ident}")
    async def owner_session_detection(request: Request, ident: str):
        try:
            result = await anyio.to_thread.run_sync(
                partial(owner_session_request, request, ident), limiter=owner_workers,
            )
            reply = response(result)
            reply.headers["Cache-Control"] = "no-store"
            return reply
        except Exception as exc:
            return guardrail_error(exc, owner=True)

    def operator_session_request(request, ident):
        from . import session_operator

        require(cfg.enabled("api"), "no such route", 404)
        principal = service.principal(request, role="security_analyst")
        tenant_id = principal["tenant"]["id"]
        path, query = request.url.path, request.query_params
        if path == "/api/v1/session-investigations":
            return session_operator.investigations(
                st, tenant_id, limit=page({"limit": query.get("limit", "50")})["limit"],
                cursor=query.get("cursor", ""), outcome=query.get("outcome", "all"),
                session_id=query.get("session_id"),
            )
        if path.startswith("/api/v1/session-investigation-reads/"):
            return session_operator.investigation_read(st, tenant_id, ident)
        if path.startswith("/api/v1/session-investigations/"):
            return session_operator.investigation(st, tenant_id, ident, attempt_id=query.get("attempt_id"))
        default_limit = 100 if path.startswith("/api/v1/session-snapshots/") else (
            50 if path.endswith("/guardrail-actions") else 20
        )
        limit = page({"limit": query.get("limit", str(default_limit))})["limit"]
        cursor = query.get("cursor", "")
        if path.startswith("/api/v1/session-snapshots/"):
            return session_operator.read_snapshot(st, tenant_id, ident, limit=limit, cursor=cursor)
        if path.endswith("/guardrail-actions"):
            return session_operator.guardrail_actions(
                st, tenant_id, ident, limit=limit, cursor=cursor,
                view=query.get("view", "actions"), action_id=query.get("action_id"),
            )
        return session_operator.session_status(st, tenant_id, ident, limit=limit, cursor=cursor)

    @app.get("/api/v1/sessions/{ident}/detection")
    @app.get("/api/v1/sessions/{ident}/guardrail-actions")
    @app.get("/api/v1/session-snapshots/{ident}")
    @app.get("/api/v1/session-investigations/{ident}")
    @app.get("/api/v1/session-investigation-reads/{ident}")
    async def operator_session_archive(request: Request, ident: str):
        try:
            result = await anyio.to_thread.run_sync(
                partial(operator_session_request, request, ident), limiter=operator_workers,
            )
            # Retained evidence must preserve its JSON keys and nesting.
            return JSONResponse(result, headers={"Cache-Control": "no-store"})
        except Exception as exc:
            return guardrail_error(exc, owner=True)

    @app.get("/api/v1/session-investigations")
    async def operator_investigation_list(request: Request):
        return await operator_session_archive(request, "")

    dashboard_mcp.install(app)

    @app.api_route(
        "/{path:path}",
        methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )
    def dispatch(request: Request, path: str):
        return service.dispatch(request)

    return app
