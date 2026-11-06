"""Scheduled and on-demand Overview summaries from role-scoped dashboard reads."""

from openaidr_api_client.validation.overview_summary import (
    TOPICS as TOPICS,
    TONES as TONES,
    ITEM_FIELDS as ITEM_FIELDS,
    COST_WINDOW as COST_WINDOW,
    validate_answer as validate_answer,
)

import asyncio
import hashlib
import json
import logging
import math
import threading
from concurrent.futures import Future
from datetime import datetime, timezone

from psycopg.types.json import Jsonb
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request

from .httpx import APIError, require
from .permissions import assigned_roles, page_allowed

CACHE_FRESH_SECONDS = 300
CACHE_RETAIN_SECONDS = 7 * 24 * 3600
REFRESH_SECONDS = 3600
RETRY_SECONDS = 300
log = logging.getLogger(__name__)


def numeric(value):
    """Copy numbers from aggregate objects, never strings, lists or identifiers."""
    if not isinstance(value, dict):
        raise ValueError("missing aggregate")
    return {key: val for key, val in value.items()
            if isinstance(val, (int, float)) and math.isfinite(val)}


def fields(data, *paths):
    result = {}
    for path in paths:
        value = data
        for key in path.split("."):
            value = value[key]
        if isinstance(value, dict):
            result[path] = numeric(value)
        elif value is None or isinstance(value, (bool, int, float)):
            result[path] = value
        else:
            raise ValueError("unexpected aggregate field")
    return result


def rows(data):
    items = data["items"]
    if not isinstance(items, list):
        raise ValueError("missing rows")
    return {"loaded_records": len(items), "has_more": bool(data.get("next_cursor"))}


def categories(data, field, values):
    return {**rows(data), **{json.dumps(value) if isinstance(value, bool) else value:
                           sum(item.get(field) == value for item in data["items"])
                           for value in values}}


def applications(data):
    return {**categories(data, "approval_status", ("approved", "unapproved", "monitoring")),
            "review_required": sum(item["review_required"] is True for item in data["items"])}


def components(data):
    assessments = [item["vulnerability"] for item in data["items"]]
    return {**rows(data),
            "current_assessments": sum(value["status"] == "complete" for value in assessments),
            "records_with_findings": sum(bool(value["findings"]) for value in assessments),
            **{f"records_with_{severity}_findings": sum(
                any(finding["severity"] == severity for finding in value["findings"])
                for value in assessments) for severity in ("critical", "high")}}


def hook_mode(data):
    require(data.get("mode") in ("shadow", "enforce"), "invalid hook mode", 502)
    return {"mode": data["mode"], "failure_behavior": "allow"}


def credit_summary(data):
    return {"status": data["status"], "credits_per_usd": data["credits_per_usd"],
            "summary": {key: data["summary"][key] for key in (
                "credits_charged", "operations", "pending_operations", "unrated_operations")}}


# Fixed endpoints only. The caller reuses ordinary console GET handlers, which
# enforce API authorization and tenant scope. Projections exclude raw evidence,
# host/user names, policy text, enrollment credentials and masked API keys.
SOURCES = (
    ("/", "Findings and coverage", "overview?range=30d&view=risk",
     "Open/triaged findings now; sensors now; agents and sessions in the last 30 days.",
     lambda d: fields(d, "findings_open", "sensors", "agents", "sessions")),
    ("/ai-inventory", "AI Apps", "inventory/application-review",
     "Current discovered application groups, across all loaded devices.", applications),
    ("/ai-supply-chain", "Supply chain coverage", "inventory/roots?limit=100",
     "First page of up to 100 scan locations only; not all locations when has_more is true.",
     lambda d: categories(d, "status", ("ok", "partial", "error", "unavailable"))),
    ("/ai-supply-chain", "Supply chain components", "inventory/components?limit=100",
     "First page of up to 100 component records only. Findings may be retained from stale assessments; current_assessments counts fresh results. Records are not unique vulnerabilities.", components),
    ("/ai-skills", "AI Skills", "inventory/skills",
     "Aggregate counts for all installed skills and their assessment coverage now.",
     lambda d: fields(d, "summary", "enabled", "total")),
    ("/user-risk", "User Risk", "overview?range=30d&view=risk",
     "All currently open or triaged findings, not confirmed incidents.",
     lambda d: fields(d, "findings_open")),
    ("/detections", "Detection Queue", "detections/pipeline?range=7d",
     "Detection pipeline counts over the last 7 days; current worker availability and settings.",
     lambda d: {**numeric(d), **fields(d, "availability")}),
    ("/evidence", "Evidence Search", "events?limit=1",
     "Availability of the latest evidence page only. Raw evidence and search results are not summarized.", rows),
    ("/detection-rules", "Detection Rules", "detections/rules",
     "Current built-in detection rules; rule counts are not investigation coverage.",
     lambda d: categories(d, "enabled", (True, False))),
    ("/guardrail/live", "Live Guardrail", "guardrail/active",
     "All organization Guardrail service operations started in the last 5 minutes; pending operations may be incomplete.",
     lambda d: {"guardrail": numeric(d["jev"])}),
    ("/guardrail/configuration", "Guardrail mode", "response/hook-settings",
     "Current saved hook mode. Returned restrictions do not prove enforcement.", hook_mode),
    ("/guardrail/configuration", "Fixed rules", "response/policy",
     "Current saved fixed rules only.", lambda d: {"fixed_rules": len(d["rules"])}),
    ("/guardrail/history", "Guardrail History", "guardrail/stats?range=24h",
     "Reported hook runs and evaluated decisions over the last 24 hours; failed checks allow actions.",
     lambda d: fields(d, "totals", "executions")),
    ("/company-knowledge", "Company policy", "response/company-policy",
     "Whether company policy text is saved now. Policy content is excluded.",
     lambda d: {"policy_saved": bool(d["prompt"].strip())}),
    ("/company-knowledge", "Company knowledge", "knowledge/library",
     "Current knowledge configuration; document and source contents are excluded.",
     lambda d: {"enabled": d["enabled"], "documents": len(d["documents"])}),
    ("/costs/agents", "AI Agent Costs", "costs/agents/summary?range=24h",
     "Last 24 hours, USD API-equivalent estimates; pricing and processing coverage included.",
     lambda d: fields(d, "summary", "processing")),
    ("/costs/openaidr", "Credits & Usage", "credits?range=24h",
     "Last 24 hours, customer service credits. Disabled, unavailable or unrated charges are unknown; 100 credits have a purchase value of 1 USD.",
     credit_summary),
    ("/administration/app", "App Health", "overview?range=24h&view=risk",
     "Current sensor records, not unique physical devices; includes separate enrollments.",
     lambda d: fields(d, "sensors")),
    ("/administration/server", "Server Health", "system/status",
     "Current database health and service heartbeat counts; detailed diagnostics and logs are excluded.",
     lambda d: {**fields(d, "database", "ingest"),
                **{state: sum(service["status"] == state for service in d["services"])
                   for state in ("ok", "stale", "unknown")}}),
    ("/administration/enrollment", "App Enrollment", "sensors/enrollment-tokens?limit=100",
     "Loaded enrollment token records only; credentials and token values are excluded.", rows),
    ("/administration/integrations", "Integrations", "settings/slack",
     "Current Slack integration enablement only; credentials and destinations are excluded.",
     lambda d: fields(d, "enabled")),
    ("/audit-logs", "Audit Logs", "audit?limit=100",
     "Latest page of up to 100 audit records only; event contents and actors are excluded.", rows),
    ("/administration/users", "Users and Roles", "users?limit=100",
     "Loaded user records only; names, email addresses and identities are excluded.", rows),
    ("/administration/settings", "Settings", "settings/model-keys",
     "Current model credential availability only; keys and masked key values are excluded.",
     lambda d: fields(d, "guardrail.configured", "detection.configured")),
)


def collect(user, read):
    sources = []
    reads = {}
    for index, (path, title, endpoint, scope, project) in enumerate(SOURCES, 1):
        if not page_allowed(user, path):
            continue
        source = dict(id=str(index), path=path, title=title, scope=scope,
                      captured_at=datetime.now(timezone.utc).isoformat())
        try:
            if endpoint not in reads:
                reads[endpoint] = read(endpoint)
            facts = project(reads[endpoint])
            if not facts:
                raise ValueError("no aggregate fields")
            source.update(status="available", facts=facts)
        except (APIError, ValueError, KeyError, TypeError):
            # A partial read is visible and never replaced by measured zeroes.
            source.update(status="unavailable", facts={})
        sources.append(source)
    return sources


class OverviewSummary:
    def __init__(self, st):
        self.st = st
        self._lock = threading.Lock()
        self._pending = {}

    @staticmethod
    def _key(tenant, user, chat, *, fingerprint=None):
        # Older generated summaries included private provider cost facts.
        # Keep those stored records out of the customer cache after cutover.
        if fingerprint is None:
            fingerprint = chat.cache_identity(tenant)
        identity = hashlib.sha256(("service-credits-v1:" + fingerprint).encode()).hexdigest()
        return tenant, tuple(assigned_roles(user)), identity

    def cached(self, tenant, user, chat):
        connection = chat.connection
        if connection is None or str(tenant) != connection.tenant_id:
            return {"summary": None, "stale": True}
        key = self._key(tenant, user, chat, fingerprint=chat.cache_identity(tenant, connection=connection))
        return self._cached(tenant, user, key)

    def _cached(self, tenant, user, key):
        _, roles, fingerprint = key
        rows = self.st.many("""SELECT summary,
                generated_at <= now() - $4 * interval '1 second' AS stale
            FROM overview_summaries WHERE tenant_id=$1 AND roles=$2 AND key_fingerprint=$3
                AND generated_at > now() - $5 * interval '1 second'""",
            tenant, list(roles), fingerprint, CACHE_FRESH_SECONDS, CACHE_RETAIN_SECONDS)
        # A permission change in a later deployment must not expose sources
        # retained under the previous page-access rules.
        if rows and all(page_allowed(user, source["path"]) for source in rows[0]["summary"]["sources"]):
            return rows[0]
        return {"summary": None, "stale": True}

    def claim_refresh(self, tenant, user):
        # The short lease coordinates API processes without holding a database
        # transaction open during source collection or a provider request.
        return bool(self.st.many("""INSERT INTO overview_summaries(tenant_id,roles,refresh_after)
            VALUES($1,$2,now() + $3 * interval '1 second')
            ON CONFLICT(tenant_id,roles) DO UPDATE SET refresh_after=EXCLUDED.refresh_after
            WHERE overview_summaries.refresh_after <= now()
            RETURNING tenant_id""", tenant, assigned_roles(user), RETRY_SECONDS))

    def generate(self, tenant, user, read, chat, refresh=False):
        connection = chat.connection
        key = self._key(tenant, user, chat, fingerprint=chat.cache_identity(tenant, connection=connection))
        with self._lock:
            saved = self._cached(tenant, user, key)
            if not refresh and not saved["stale"]:
                return saved["summary"]
            pending = self._pending.get(key)
            owner = pending is None
            if owner:
                pending = self._pending[key] = Future()
        if not owner:
            try:
                return pending.result(timeout=60)
            except TimeoutError:
                raise APIError(504, "The summary is still being generated. Try again shortly.") from None
        try:
            # Share chat's concurrency and tenant rate budget, including data reads.
            with chat._admit(tenant, connection=connection):
                sources = collect(user, read)
                require(any(s["status"] == "available" for s in sources),
                        "Summary sources are unavailable. Try again shortly.", 503)
                result = self._generate(tenant, key, chat, connection, sources)
            pending.set_result(result)
            return result
        except BaseException as error:
            pending.set_exception(error)
            raise
        finally:
            with self._lock:
                self._pending.pop(key, None)

    def _generate(self, tenant, key, chat, connection, sources):
        from openaidr_api_client.validation.page_chat import MODEL
        from .service_costs import Call

        call = Call(chat.store, tenant, "assistant", "openai", MODEL)
        failed = True
        try:
            answer = json.dumps(chat.request_generation("/v1/summaries/generate", {
                "kind": "overview", "sources": sources}, call, connection=connection))
            try:
                result = validate_answer(answer, sources)
            except (ValueError, TypeError, KeyError):
                raise APIError(502, "The summary was incomplete. Try again.") from None
            result.update(sources=sources, generated_at=datetime.now(timezone.utc).isoformat())
            failed = False
        finally:
            call.finish(failed)
        self._save(key, result)
        return result

    def _save(self, key, result, *, conn=None):
        tenant, roles, fingerprint = key
        return self.st.execute("""INSERT INTO overview_summaries
                (tenant_id,roles,key_fingerprint,summary,generated_at,refresh_after)
            VALUES($1,$2,$3,$4,$5,now() + $6 * interval '1 second')
            ON CONFLICT(tenant_id,roles) DO UPDATE SET key_fingerprint=EXCLUDED.key_fingerprint,
                summary=EXCLUDED.summary,generated_at=EXCLUDED.generated_at,
                refresh_after=EXCLUDED.refresh_after
            WHERE overview_summaries.generated_at IS NULL
                OR overview_summaries.generated_at < EXCLUDED.generated_at""",
            tenant, list(roles), fingerprint, Jsonb(result), result["generated_at"], REFRESH_SECONDS, conn=conn)


def refresh_due(service, stop):
    st, cfg = service.st, service.cfg
    # One representative of each currently assigned role set, even if nobody
    # has signed in. Never create sessions or broaden the representative's roles.
    users = st.many("""SELECT DISTINCT ON (u.tenant_id,u.roles) u.id,u.name,u.tenant_id,u.roles
        FROM tenant_users u JOIN tenants t ON t.id=u.tenant_id
        WHERE u.status='active' AND t.status='active'
            AND ($1::uuid IS NULL OR u.tenant_id=$1)
        ORDER BY u.tenant_id,u.roles,u.id""", cfg.tenant_id or None)
    for user in users:
        if stop.is_set():
            return
        tenant = user["tenant_id"]
        try:
            if not service.page_chat.configured(tenant) or not service.overview_summary.claim_refresh(tenant, user):
                continue

            def read(endpoint):
                path, _, query = endpoint.partition("?")
                request = Request({"type": "http", "method": "GET", "path": "/api/v1/" + path,
                                   "query_string": query.encode("ascii"), "headers": []})
                reply = service._console_authenticated(request, path, tenant, user)
                return json.loads(reply.body)

            service.overview_summary.generate(tenant, user, read, service.page_chat)
        except Exception:
            # Keep the previous result and retry after the lease expires. Do not
            # log provider diagnostics, source data or credentials.
            log.warning("Scheduled Overview summary refresh deferred")


async def run(service, stop):
    while not stop.is_set():
        try:
            await run_in_threadpool(refresh_due, service, stop)
        except Exception:
            log.warning("Overview summary scheduler unavailable")
        try:
            await asyncio.wait_for(stop.wait(), timeout=60)
        except TimeoutError:
            pass
