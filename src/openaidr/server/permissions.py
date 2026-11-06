"""Tenant dashboard roles and explicit API access rules."""

import re

from .httpx import require

ROLES = ("it_admin", "security_analyst", "security_leadership")
LEGACY_ROLES = {
    "owner": list(ROLES),
    "admin": ["it_admin"],
    "analyst": ["security_analyst"],
    "viewer": ["security_leadership"],
}


def normalize_roles(value):
    require(
        isinstance(value, list) and 1 <= len(value) <= len(ROLES)
        and all(isinstance(role, str) and role in ROLES for role in value)
        and len(set(value)) == len(value),
        "roles must contain one or more distinct roles: " + ", ".join(ROLES),
    )
    return [role for role in ROLES if role in value]


def assigned_roles(user):
    # The legacy field supports the bundled console and pre-migration callers.
    # Once roles is present, the legacy projection cannot grant permissions.
    value = user.get("roles") if "roles" in user else LEGACY_ROLES.get(user.get("role"), [])
    if not isinstance(value, list) or not value or any(role not in ROLES for role in value):
        return []
    return [role for role in ROLES if role in value]


def requested_roles(data):
    require(not ("roles" in data and "role" in data), "provide roles only")
    if "roles" in data:
        return normalize_roles(data["roles"])
    # Existing console and platform clients can still send a single legacy role.
    role = data.get("role")
    require(isinstance(role, str) and role in LEGACY_ROLES, "roles are required")
    return list(LEGACY_ROLES[role])


def has_role(user, role):
    return role in assigned_roles(user)


# Full matches keep adjacent paths and new endpoints denied until classified.
# Personal session flows retain their separate ownership checks in the handler.
ACCESS = (
    (("it_admin",), "GET POST", r"settings/cowork"),
    (("it_admin",), "DELETE", r"settings/cowork/[^/]+"),
    (ROLES, "GET", r"gateways/overview"),
    (("it_admin", "security_analyst"), "GET", r"gateways|gateways/(?!overview$|requests(?:/|$))[^/]+"),
    (("it_admin",), "POST", r"gateways|gateways/[^/]+/credentials"),
    (("it_admin",), "PATCH", r"gateways/[^/]+"),
    (("it_admin",), "DELETE", r"gateways/[^/]+/credentials/[^/]+"),
    (("security_analyst",), "PUT", r"gateways/[^/]+/settings"),
    (("security_analyst",), "GET", r"gateways/requests(?:/[^/]+)?"),
    (("it_admin",), "GET PUT", r"mcp/settings"),
    (("it_admin",), "GET POST", r"mcp/clients"),
    (("it_admin",), "DELETE", r"mcp/clients/[^/]+"),
    (ROLES, "GET", r"mcp/grants|mcp/changes(?:/[^/]+)?"),
    (ROLES, "DELETE", r"mcp/grants/[^/]+"),
    (ROLES, "GET POST", r"mcp/authorizations/[^/]+"),
    (ROLES, "POST", r"mcp/changes/[^/]+"),
    (ROLES, "GET", r"endpoint-alerts(?:/[^/]+)?"),
    (("it_admin", "security_analyst"), "POST", r"endpoint-alerts"),
    (ROLES, "GET", r"overview(?:/summary)?|telemetry/overview"),
    (ROLES, "GET", r"settings/support"),
    (("it_admin",), "PUT", r"settings/support"),
    (("it_admin",), "PATCH", r"settings/tenant"),
    (ROLES, "POST", r"chat|overview/summary|audit/page-views|session-registrations/confirm"),
    (ROLES, "GET", r"me/sessions(?:/[^/]+/evidence)?"),
    (ROLES, "GET", r"inventory/(?:ai-applications|components|roots|relationships|applications|sources|categories|attention-history)"),
    (ROLES, "GET", r"inventory/skills(?:/[^/]+(?:/devices)?)?"),
    (("it_admin", "security_analyst"), "PUT", r"inventory/skills/[^/]+/approval"),
    (("it_admin",), "PUT", r"inventory/skills/llm"),
    (("it_admin", "security_analyst"), "PUT", r"inventory/(?:ai-applications|application-review)/[^/]+/approval"),
    (ROLES, "GET", r"inventory/application-review(?:/[^/]+/devices)?"),
    (("it_admin", "security_leadership"), "GET", r"costs/(?:detections|agent-sessions|billing|cursor-estimates|hook-estimates|agents(?:/summary|/filters)?)"),
    (("it_admin", "security_leadership"), "GET", r"credits"),
    (("it_admin",), "GET", r"users(?:/invites)?|audit|system/(?:status|metrics|diagnostics|database)"),
    (("it_admin",), "POST", r"users/invites|sensors/enrollment-(?:tokens|links)|sensors/[^/]+/(?:commands|recovery-tokens|credentials/revoke)"),
    (("it_admin",), "PATCH DELETE", r"users/[^/]+|sensors/[^/]+"),
    (("it_admin",), "DELETE", r"users/invites/[^/]+|sensors/enrollment-tokens/[^/]+"),
    (("it_admin",), "GET", r"sensors(?:/health|/enrollment-tokens|/[^/]+(?:/metrics|/commands)?)?|telemetry/exports"),
    (("it_admin",), "GET PUT", r"settings/(?:model-keys|telemetry-retention|slack|summary-reports|session-detection|feedback)"),
    (("it_admin",), "POST", r"settings/feedback/withdraw"),
    (("it_admin",), "POST", r"settings/intelligence/check"),
    (("it_admin",), "PUT", r"settings/intelligence(?:/key)?"),
    (("it_admin",), "POST", r"settings/summary-reports/(?:preview|send)"),
    (("it_admin",), "POST", r"settings/slack/test"),
    (("security_analyst",), "GET", r"users/(?:assignees|detection-owners)|user-risk|hook-decisions|guardrail/(?:active|devices|stats|checks|flow)|detections/(?:rankings|eligibility|pipeline|rules)"),
    (("security_analyst",), "GET", r"risk-cases(?:/[^/]+(?:/download)?)?"),
    (("security_analyst",), "PATCH", r"risk-cases/[^/]+"),
    (("security_analyst",), "GET", r"agents(?:/[^/]+(?:/sessions)?)?|events(?:/[^/]+)?|findings(?:/[^/]+)?|sessions/[^/]+(?:/events|/evidence)?"),
    (("security_analyst",), "GET", r"telemetry/exports/[^/]+|ingestion/retained-records(?:/[^/]+(?:/download)?)?"),
    (("security_analyst",), "GET PUT", r"sessions/[^/]+/detection-owner|session-registrations/[^/]+/context-scope"),
    (("security_analyst",), "PATCH", r"findings/[^/]+|detections/rules/[^/]+"),
    (("security_analyst",), "POST", r"findings/[^/]+/notes|response/actions|response/policy/rules"),
    (("security_analyst",), "POST", r"response/policy/rules/(?:generate|preview|drafts)"),
    (("security_analyst",), "PATCH", r"response/policy/rules/[^/]+"),
    (("security_analyst",), "GET", r"response/actions"),
    (("security_analyst",), "GET PUT", r"response/(?:policy|company-policy|session-detection|guardrails|hook-settings)"),
    (("security_analyst",), "DELETE", r"response/policy/rules/[^/]+"),
    (("security_analyst",), "GET PUT", r"knowledge(?:/library|/retrieval)?"),
    (("security_analyst",), "PUT", r"knowledge/documents"),
    (("security_analyst",), "GET POST", r"knowledge/(?:mcp|sources)"),
    (("security_analyst",), "POST", r"knowledge/uploads|knowledge/sources/[^/]+/(?:verify|revoke|purge)"),
    (("security_analyst",), "GET", r"knowledge/sources/[^/]+"),
    (("security_analyst",), "POST", r"knowledge/mcp/[^/]+/(?:resources|preview|sync|disconnect)"),
)


def authorize(user, method, path):
    roles = assigned_roles(user)
    require(any(
        set(roles).intersection(allowed) and method in methods.split()
        and re.fullmatch(pattern, path)
        for allowed, methods, pattern in ACCESS
    ), "your roles do not allow this action", 403)


def page_allowed(user, path):
    roles = assigned_roles(user)
    if not roles:
        return False
    if path == "/gateways/overview":
        return True
    if re.fullmatch(r"/gateways/instances(?:/[^/]+)?", path):
        return bool(set(roles).intersection(("it_admin", "security_analyst")))
    if re.fullmatch(r"/gateways/requests(?:/[^/]+)?", path):
        return "security_analyst" in roles
    if path in ("/", "/ai-inventory", "/ai-inventory/preview", "/ai-supply-chain",
                "/ai-supply-chain/preview", "/ai-skills", "/ai-skills/preview"):
        return True
    if path.startswith("/administration/") or path in ("/audit-logs", "/devices"):
        return "it_admin" in roles
    if path in ("/costs/agents", "/costs/openaidr", "/costs/detections"):
        return bool(set(roles).intersection(("it_admin", "security_leadership")))
    if path in ("/activity", "/user-risk", "/user-risk/findings", "/detections", "/evidence", "/telemetry",
                "/detections/preview", "/detection-rules", "/guardrail/live", "/guardrail/configuration", "/guardrail/history", "/company-knowledge",
                "/company-knowledge/preview/policy", "/company-knowledge/preview/guardrails",
                "/security-posture") or re.fullmatch(r"/(?:sessions|detections/reports)/[^/]+", path):
        return "security_analyst" in roles
    return False
