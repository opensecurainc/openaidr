"""Registration-bound inline assessments and immutable policy decisions."""

from .. import customer_views

import asyncio
import copy
import hashlib
import json
import re
import time
import uuid
from datetime import datetime, timezone
from functools import partial

import anyio
from psycopg.types.json import Jsonb

from openaidr.core.event import EVIDENCE_GAPS, validate_event, validate_evidence
from openaidr.core.policy import Policy
from . import approvals
from .storage import get_settings as get_settings, _bounded_transaction as _bounded_transaction
from .. import company_policy, session_ownership
from ..event_normalization import normalize_host
from ..httpx import APIError, parse_time, require
from ..knowledge import COVERAGE
from openaidr.core.redact import redact_value
from .evidence import MAX_EVENT_BYTES, MAX_STATE_BYTES, event_evidence
from contextlib import nullcontext
from ..store import new_id


KINDS = ("prompt", "response", "tool.call", "tool.result", "command", "file.read", "file.write", "network")


EVENT_FIELDS = frozenset(
    (
        "schema_version",
        "id",
        "time",
        "observed_at",
        "kind",
        "agent",
        "host",
        "session",
        "source",
        "evidence",
        "text",
        "tool",
        "command",
        "file",
        "network",
        "hook",
        "truncated",
        "redacted",
    )
)


def save_settings(st, tenant_id, payload, actor):
    require(isinstance(payload, dict), "invalid guardrail settings")
    require(
        set(payload)
        <= {
            "enabled",
            "ask_threshold",
            "block_threshold",
            "timeout_ms",
            "approvals_enabled",
            "approval_wait_seconds",
            "approval_use_seconds",
            "context_enabled",
            "context_required",
            "context_failure_action",
        },
        "unknown guardrail setting",
    )
    require(type(payload.get("enabled")) is bool, "enabled must be a boolean")
    for key, maximum, minimum in (
        ("ask_threshold", 100, 0),
        ("block_threshold", 100, 0),
        ("timeout_ms", 10000, 100),
    ):
        value = payload.get(key)
        require(
            value is None or (type(value) is int and minimum <= value <= maximum),
            "invalid " + key,
        )
        require(
            not payload["enabled"] or value is not None,
            key + " is required before enablement",
        )
    ask, block = payload.get("ask_threshold"), payload.get("block_threshold")
    require(
        ask is None or block is None or ask <= block,
        "ask_threshold must not exceed block_threshold",
    )
    with st.transaction() as conn:
        # Serialize read/merge/upsert, including the first row, so older callers
        # that omit approval fields cannot erase a concurrent configuration.
        st.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "guardrail-settings:" + tenant_id,
            conn=conn,
        )
        current = get_settings(st, tenant_id, conn=conn)
        context_settings = {
            key: payload.get(key, current[key])
            for key in ("context_enabled", "context_required", "context_failure_action")
        }
        require(
            type(context_settings["context_enabled"]) is bool
            and type(context_settings["context_required"]) is bool,
            "context settings must be booleans",
        )
        require(
            context_settings["context_failure_action"] in ("ask", "block"),
            "context_failure_action must be ask or block",
        )
        require(
            not context_settings["context_required"] or context_settings["context_enabled"],
            "required context must be enabled",
        )
        approval_settings = {
            key: payload.get(key, current[key])
            for key in (
                "approvals_enabled",
                "approval_wait_seconds",
                "approval_use_seconds",
            )
        }
        require(
            type(approval_settings["approvals_enabled"]) is bool,
            "approvals_enabled must be a boolean",
        )
        for key in ("approval_wait_seconds", "approval_use_seconds"):
            value = approval_settings[key]
            require(
                value is None or (type(value) is int and 1 <= value <= 86400),
                "invalid " + key,
            )
            require(
                not approval_settings["approvals_enabled"] or value is not None,
                key + " is required before approval enablement",
            )
        row = st.one(
            """INSERT INTO tenant_guardrail_settings
                   (tenant_id,enabled,ask_threshold,block_threshold,timeout_ms,
                    approvals_enabled,approval_wait_seconds,approval_use_seconds,
                    context_enabled,context_required,context_failure_action)
               VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(tenant_id) DO UPDATE SET
                   version=tenant_guardrail_settings.version+1,enabled=EXCLUDED.enabled,
                   ask_threshold=EXCLUDED.ask_threshold,block_threshold=EXCLUDED.block_threshold,
                   timeout_ms=EXCLUDED.timeout_ms,updated_at=clock_timestamp(),
                   approvals_enabled=EXCLUDED.approvals_enabled,
                   approval_wait_seconds=EXCLUDED.approval_wait_seconds,
                   approval_use_seconds=EXCLUDED.approval_use_seconds,
                   context_enabled=EXCLUDED.context_enabled,
                   context_required=EXCLUDED.context_required,
                   context_failure_action=EXCLUDED.context_failure_action
               RETURNING version,enabled,ask_threshold,block_threshold,timeout_ms,updated_at,
                         approvals_enabled,approval_wait_seconds,approval_use_seconds,
                         context_enabled,context_required,context_failure_action""",
            tenant_id,
            payload["enabled"],
            ask,
            block,
            payload.get("timeout_ms"),
            approval_settings["approvals_enabled"],
            approval_settings["approval_wait_seconds"],
            approval_settings["approval_use_seconds"],
            context_settings["context_enabled"],
            context_settings["context_required"],
            context_settings["context_failure_action"],
            conn=conn,
        )
        st.execute(
            """INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,
                   target_type,target_id,details)
               VALUES($1,$2,$3,$4,$5,'guardrails.configure','guardrails',$2,$6)""",
            new_id(),
            tenant_id,
            actor.get("type", "user"),
            actor.get("id", ""),
            actor.get("name", ""),
            Jsonb({**payload, **approval_settings, **context_settings, "version": row["version"]}),
            conn=conn,
        )
    return row


def _json(value):
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise APIError(400, "invalid guardrail JSON") from None


def _uuid(value, name):
    try:
        return str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError):
        raise APIError(400, "invalid " + name) from None


def _gaps(value):
    require(
        isinstance(value, list)
        and len(value) <= 32
        and all(isinstance(item, str) and item in EVIDENCE_GAPS for item in value),
        "invalid context gaps",
    )


def _event(event, registration_id):
    require(
        isinstance(event, dict) and set(event) <= EVENT_FIELDS, "invalid event fields"
    )
    require(
        len(_json(event)) <= MAX_EVENT_BYTES, "event exceeds inline evidence limit", 413
    )
    reason = validate_event(event) or validate_evidence(event.get("evidence"))
    require(not reason, reason or "invalid event")
    _uuid(event["id"], "event id")
    require(event["kind"] in KINDS, "unsupported inline event kind")
    for key in (
        "agent",
        "host",
        "session",
        "source",
        "tool",
        "command",
        "file",
        "network",
        "hook",
    ):
        require(
            key not in event or isinstance(event[key], dict), "invalid event " + key
        )
    for field, keys in (
        ("agent", ("product", "version", "model", "account")),
        ("host", ("hostname", "os", "arch", "user")),
        ("session", ("id", "registration_id", "cwd", "git_branch")),
        ("tool", ("name", "call_id")),
        ("command", ("text", "cwd")),
        ("file", ("path",)),
        ("network", ("url", "host")),
    ):
        for key in keys:
            require(
                key not in event.get(field, {}) or isinstance(event[field][key], str),
                "invalid event " + field + "." + key,
            )
    require("text" not in event or isinstance(event["text"], str), "invalid event text")
    require(
        _uuid(event["session"].get("registration_id"), "session registration")
        == registration_id,
        "context registration does not match",
        403,
    )
    for key in ("time", "observed_at"):
        if key not in event:
            continue
        try:
            require(
                isinstance(event[key], str)
                and parse_time(event[key]).tzinfo is not None,
                "invalid event " + key,
            )
        except (ValueError, TypeError, AttributeError):
            raise APIError(400, "invalid event " + key) from None


def _request(payload):
    require(isinstance(payload, dict), "invalid guardrail request")
    require(len(_json(payload)) <= 64 << 10, "guardrail request too large", 413)
    require(
        set(payload)
        <= {
            "request_id",
            "registration_id",
            "settings_version",
            "policy_version",
            "action_commitment",
            "target",
            "context",
            "policy_floor",
            "context_version",
        },
        "unknown guardrail field",
    )
    # Limit nesting before credential scanning traverses untrusted structures.
    pending = [(payload, 0)]
    while pending:
        item, depth = pending.pop()
        require(depth <= 32, "guardrail content is too deeply nested")
        if isinstance(item, dict):
            require(
                all(isinstance(key, str) and "\x00" not in key for key in item),
                "invalid guardrail field name",
            )
            pending.extend((value, depth + 1) for value in item.values())
        elif isinstance(item, list):
            pending.extend((value, depth + 1) for value in item)
        elif isinstance(item, str):
            require("\x00" not in item, "invalid guardrail text")
    data = copy.deepcopy(payload)
    require(
        "context_version" not in data
        or (type(data["context_version"]) is int and data["context_version"] == 1),
        "unsupported context protocol",
    )
    require(
        "policy_floor" not in data
        or isinstance(data["policy_floor"], str)
        and data["policy_floor"] in ("ask", "block"),
        "invalid policy_floor",
    )
    for key in ("request_id", "registration_id"):
        data[key] = _uuid(data.get(key), key)
    for key in ("settings_version", "policy_version"):
        require(
            type(data.get(key)) is int and 0 <= data[key] < 1 << 63, "invalid " + key
        )
    commitment = data.get("action_commitment")
    require(
        isinstance(commitment, str)
        and re.fullmatch(r"hmac-sha256-v1:[0-9a-f]{64}", commitment),
        "invalid action commitment",
    )
    target, context = data.get("target"), data.get("context")
    _event(target, data["registration_id"])
    require(
        isinstance(context, dict)
        and set(context)
        <= {"prior_events", "latest_prompt", "matched_tool_call", "gaps"},
        "invalid context",
    )
    prior = context.get("prior_events", [])
    require(
        isinstance(prior, list)
        and len(prior) <= 12
        and all(isinstance(item, dict) for item in prior),
        "context must contain at most 12 prior events",
    )
    _gaps(context.get("gaps", []))
    for item in [
        *prior,
        context.get("latest_prompt"),
        context.get("matched_tool_call"),
    ]:
        if item is not None:
            _event(item, data["registration_id"])
            require(
                item["agent"]["product"] == target["agent"]["product"]
                and item["session"]["id"] == target["session"]["id"],
                "context session does not match",
                403,
            )
    prompt, call = context.get("latest_prompt"), context.get("matched_tool_call")
    require(
        prompt is None or prompt["kind"] == "prompt", "latest_prompt must be a prompt"
    )
    if call is not None:
        require(
            call["kind"]
            in ("tool.call", "command", "file.read", "file.write", "network"),
            "matched_tool_call must be a tool call",
        )
        call_id = (call.get("tool") or {}).get("call_id")
        require(
            isinstance(call_id, str)
            and call_id
            and call_id == (target.get("tool") or {}).get("call_id"),
            "tool call does not match",
        )
    if target["kind"] == "tool.result" and call is None:
        require(
            "missing_tool_call" in context.get("gaps", [])
            or "missing_tool_call" in target["evidence"]["gaps"],
            "tool result requires its matching call or gap",
        )
    # This digest covers exactly the permitted submitted evidence, never a key
    # or a separate raw hidden-content digest. Defense redaction follows it.
    data["payload_sha256"] = hashlib.sha256(
        _json(
            {
                "target": payload["target"],
                "context": payload["context"],
                "action_commitment": commitment,
            }
        )
    ).hexdigest()
    return data


def _sanitize(event):
    result = redact_value(copy.deepcopy(event))
    # Identifiers bind the stored evidence to its registration and source.
    for key in ("id", "time", "kind"):
        result[key] = copy.deepcopy(event[key])
    # Preserve only validated identity/order fields. Future metadata can
    # contain captured values and must retain the defense redaction above.
    for key in (
        "version",
        "logical_id",
        "observation_id",
        "stream_id",
        "sequence",
        "part",
        "gaps",
    ):
        result["evidence"][key] = copy.deepcopy(event["evidence"][key])
    result["agent"]["product"] = event["agent"]["product"]
    for key in ("id", "registration_id"):
        result["session"][key] = event["session"][key]
    if "call_id" in event.get("tool", {}):
        result["tool"]["call_id"] = event["tool"]["call_id"]
    if result != event:
        result["redacted"] = True
        result["evidence"]["gaps"] = sorted(
            set(result["evidence"]["gaps"] + ["content_redacted"])
        )
    return result


def _prepare_evidence(data, sensor, defaults=None):
    target = _sanitize(
        normalize_host(copy.deepcopy(data["target"]), sensor, defaults=defaults)
    )
    original = data["context"]
    context = {
        "prior_events": [_sanitize(item) for item in original.get("prior_events", [])],
        "latest_prompt": _sanitize(original["latest_prompt"])
        if original.get("latest_prompt")
        else None,
        "matched_tool_call": _sanitize(original["matched_tool_call"])
        if original.get("matched_tool_call")
        else None,
        "gaps": sorted(set(original.get("gaps", []))),
    }

    def view(event):
        if event is None:
            return None
        result = event_evidence({"kind": event["kind"], "body": event})
        result["evidence_gaps"] = event["evidence"]["gaps"]
        if (
            result.get("truncated")
            and "content_truncated" not in result["evidence_gaps"]
        ):
            result["evidence_gaps"] = [*result["evidence_gaps"], "content_truncated"]
        return result

    state = {
        "target_event": view(target),
        "matched_tool_call": view(context["matched_tool_call"]),
        "latest_prompt": None,
        "prior_events": [],
        "context_limited": True,
        "gaps": list(context["gaps"]),
    }
    prompt = view(context["latest_prompt"])
    if prompt is not None:
        state["latest_prompt"] = prompt
        if len(_json(state)) > MAX_STATE_BYTES:
            state["latest_prompt"] = None
            state["gaps"] = sorted(set(state["gaps"] + ["content_truncated"]))
    for item in reversed(context["prior_events"]):
        if any(
            item["id"] == event["id"]
            for event in (
                target,
                context["latest_prompt"],
                context["matched_tool_call"],
            )
            if event
        ):
            continue
        state["prior_events"].insert(0, view(item))
        if len(_json(state)) > MAX_STATE_BYTES:
            state["prior_events"].pop(0)
            state["gaps"] = sorted(set(state["gaps"] + ["content_truncated"]))
            break
    require(
        len(_json(state)) <= MAX_STATE_BYTES,
        "prepared evidence exceeds inline limit",
        413,
    )
    return target, context, state


def _unavailable(reason):
    return {
        "status": "unavailable",
        "score": None,
        "category": "unknown",
        "level": None,
        "reason": reason,
    }


def _identity(row):
    return ({"profile": row["profile"]} if row["profile"] is not None
            else {"model": row["model"], "rubric_version": row["rubric_version"]})


def _unavailable_context(reason, *, status="unavailable", revision=None):
    return {
        "schema_version": 2, "mode": "postgres", "enabled": False,
        "status": status, "revision": revision, "retrieval_ms": 0,
        "coverage": COVERAGE, "truncated": False, "reference_only": True,
        "documents": [], "gaps": [reason],
        "category_coverage": {"operation": "unknown", "resource": "unknown"},
    }


def get_context_scope(st, tenant_id, registration_id, conn=None):
    registration_id = _uuid(registration_id, "registration id")
    return st.one(
        """SELECT s.scope_key,COALESCE(s.version,0) AS version,s.updated_at
           FROM session_registrations r LEFT JOIN session_knowledge_scopes s
             ON s.registration_id=r.id AND s.tenant_id=r.tenant_id
           WHERE r.tenant_id=$1 AND r.id=$2""",
        tenant_id, registration_id, conn=conn,
    )


def save_context_scope(st, tenant_id, registration_id, payload, actor):
    require(isinstance(payload, dict) and set(payload) == {"scope_key"}, "invalid context scope")
    scope_key = payload["scope_key"]
    try:
        valid = scope_key is None or (
            isinstance(scope_key, str) and 1 <= len(scope_key.encode()) <= 240
            and scope_key.isprintable()
            and not any(char.isspace() for char in scope_key)
            and redact_value(scope_key) == scope_key
        )
    except UnicodeError:
        valid = False
    require(
        valid,
        "invalid scope key",
    )
    registration_id = _uuid(registration_id, "registration id")
    with st.transaction() as conn:
        # Inline preparation and release hold this same registration lock.
        st.one(
            "SELECT id FROM session_registrations WHERE tenant_id=$1 AND id=$2 FOR NO KEY UPDATE",
            tenant_id, registration_id, conn=conn,
        )
        result = st.one(
            """INSERT INTO session_knowledge_scopes(registration_id,tenant_id,scope_key)
               VALUES($1,$2,$3) ON CONFLICT(registration_id) DO UPDATE
               SET scope_key=EXCLUDED.scope_key,version=session_knowledge_scopes.version+1,
                   updated_at=clock_timestamp()
               RETURNING scope_key,version,updated_at""",
            registration_id, tenant_id, scope_key, conn=conn,
        )
        st.execute(
            """INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,
                   target_type,target_id,details)
               VALUES($1,$2,$3,$4,$5,'guardrails.context_scope','session_registration',$6,$7)""",
            new_id(), tenant_id, actor.get("type", "user"), actor.get("id", ""),
            actor.get("name", ""), registration_id,
            Jsonb({"scope_key": scope_key, "version": result["version"]}), conn=conn,
        )
        return result


_ASSESSMENT_FIELDS = (
    "prepared_state", "model", "rubric_version", "profile", "status", "assessment", "claim_token",
    "deadline_at", "started_at", "completed_at", "context_enabled", "context_pinned",
    "knowledge_snapshot", "context_revision", "scope_key", "scope_version",
    "company_policy",
)


def assessment_for_check(st, event, check, conn):
    if event["assessment_generation"] == check["assessment_generation"]:
        return event
    row = st.one(
        "SELECT * FROM inline_guardrail_assessments WHERE tenant_id=$1 "
        "AND guardrail_event_id=$2 AND generation=$3",
        event["tenant_id"], event["id"], check["assessment_generation"], conn=conn,
    )
    return {**event, **{field: row[field] for field in _ASSESSMENT_FIELDS},
            "assessment_generation": row["generation"]}


def context_changed(st, event, settings, conn, check=None):
    """Check the release context while holding its registration and action locks."""
    if check is not None and check["assessment_generation"] != event["assessment_generation"]:
        return True
    policy = company_policy.read(st, event["tenant_id"], conn=conn, lock=True)
    if policy["revision"] != event["company_policy"]["revision"]:
        return True
    if event["context_enabled"] != settings.get("context_enabled", False):
        return True
    if not event["context_enabled"]:
        return False
    if not event["context_pinned"]:
        return event["status"] != "pending"
    # Source publishers lock this row before changing active revisions. Keep
    # this lock through the release insert so publication cannot pass a grant.
    rows = st.many(
        "SELECT revision FROM tenant_knowledge WHERE tenant_id=$1 FOR SHARE",
        event["tenant_id"], conn=conn,
    )
    revision = rows[0]["revision"] if rows else 0
    if revision != event["context_revision"]:
        return True
    scope = get_context_scope(st, event["tenant_id"], event["registration_id"], conn)
    if scope["version"] != event["scope_version"]:
        return True
    valid_until = (event["knowledge_snapshot"] or {}).get("valid_until")
    return bool(valid_until and st.scalar(
        "SELECT $1::timestamptz<=clock_timestamp()", valid_until, conn=conn,
    ))


def _decision(deterministic, settings, assessment, floor=None):
    static = {"deny": "block", "ask": "ask"}.get(deterministic["action"], "allow")
    dynamic = "allow"
    if settings["enabled"] and assessment["status"] == "scored":
        if assessment["score"] >= settings["block_threshold"]:
            dynamic = "block"
        elif assessment["score"] >= settings["ask_threshold"]:
            dynamic = "ask"
    preparation_timeout = assessment.get("reason") == "policy_preparation_timeout"
    if preparation_timeout:
        dynamic = "block"
    rank = {"allow": 0, "ask": 1, "block": 2}
    context_action = "allow"
    knowledge = assessment.get("knowledge") or {}
    if settings.get("context_required") and (
        knowledge.get("status") != "matched" or knowledge.get("sent") is False
        or assessment.get("status") != "scored"
    ):
        context_action = settings["context_failure_action"]
    action = max((static, dynamic, floor or "allow", context_action), key=rank.__getitem__)
    result = {
        "action": action,
        "reason": "No blocking rule or threshold matched",
        "warnings": [],
    }
    if deterministic["action"] == "warn":
        result["warnings"].append(deterministic.get("reason", "Policy warning"))
    if action != "allow":
        result["reason"] = (
            (deterministic.get("reason") or "Matched policy rule")
            if static == action
            else "Required by policy evaluation on the managed client"
            if floor == action
            else "Required company context or guardrail assessment is unavailable or incomplete"
            if context_action == action
            else "Guardrail assessment time was exhausted during policy preparation"
            if preparation_timeout
            else "Matched guardrail risk threshold"
        )
    if deterministic.get("rule", {}).get("id"):
        result["rule_id"] = deterministic["rule"]["id"]
    return result


def expire_pending(st, limit=100, tenant_id=None):
    with st.transaction() as conn:
        rows = st.many(
            """UPDATE inline_guardrail_events SET status='unavailable',
                   assessment=$2||CASE WHEN profile IS NULL
                       THEN jsonb_build_object('model',model,'rubric_version',rubric_version)
                       ELSE jsonb_build_object('profile',profile) END
                       ||jsonb_build_object('company_policy',jsonb_build_object('revision',company_policy->'revision'))
                       ||CASE WHEN context_enabled THEN jsonb_build_object('knowledge',COALESCE(knowledge_snapshot,$4))
                              ELSE '{}'::jsonb END,
                   completed_at=clock_timestamp()
               WHERE id IN (SELECT id FROM inline_guardrail_events
                   WHERE ($1::uuid IS NULL OR tenant_id=$1) AND status='pending'
                     AND deadline_at<=clock_timestamp()
                   ORDER BY deadline_at,id LIMIT $3 FOR UPDATE SKIP LOCKED)
               RETURNING id,tenant_id""",
            tenant_id, Jsonb(_unavailable("timeout")), max(1, min(int(limit), 500)),
            Jsonb({**_unavailable_context("retrieval_not_completed"), "sent": False}), conn=conn,
        )
        return len(rows)


class InlineGuardrail:
    def __init__(self, st, client, cfg, client_for_tenant=None, *, customer=False):
        self.customer = customer
        if customer:
            from ..service_guardrail import contract
            contract()
            self.model, self.rubric, self.profile = None, None, "guardrail.1"
        else:
            from .scoring import MODEL, RUBRIC_VERSION
            self.model, self.rubric, self.profile = MODEL, RUBRIC_VERSION, None
        self.st, self.client, self.cfg = st, client, cfg
        self.client_for_tenant = client_for_tenant
        self.capacity = asyncio.Semaphore(cfg.inline_guardrail_concurrency)
        self.thread_limiter = anyio.CapacityLimiter(cfg.inline_guardrail_concurrency)

    async def run_sync(self, function, *args, **kwargs):
        # Inline SQL waits must not consume the default request-worker tokens
        # needed for authentication and other control routes.
        return await anyio.to_thread.run_sync(
            partial(function, *args, **kwargs),
            limiter=self.thread_limiter,
        )

    def _authorize(self, sensor, registration_id, conn):
        return session_ownership.authorize_inline(
            self.st, sensor, registration_id, conn
        )

    def _versions(self, sensor, settings_version, policy_version, conn):
        settings = get_settings(self.st, sensor["tenant_id"], conn=conn)
        policy = self.st.get_policy(sensor["tenant_id"], conn=conn)
        if (
            settings["version"] != settings_version
            or policy["version"] != policy_version
        ):
            raise APIError(409, "guardrail policy changed", "policy_changed")
        return settings, policy

    def _prepare(self, sensor, data, evidence):
        st = self.st
        target, context, state = evidence
        with st.transaction() as conn:
            registration = self._authorize(sensor, data["registration_id"], conn)
            require(
                registration["product"] == target["agent"]["product"]
                and registration["external_id"] == target["session"]["id"],
                "target session does not match",
                403,
            )
            settings, policy = self._versions(
                sensor,
                data["settings_version"],
                data["policy_version"],
                conn,
            )
            if settings["context_enabled"] and data.get("context_version") != 1:
                raise APIError(409, "managed client requires context protocol support", "context_protocol_required")
            checks = st.many(
                """SELECT * FROM inline_guardrail_checks
                   WHERE tenant_id=$1 AND sensor_id=$2 AND request_id=$3""",
                sensor["tenant_id"],
                sensor["id"],
                data["request_id"],
                conn=conn,
            )
            if checks:
                check = checks[0]
                event = st.one(
                    "SELECT * FROM inline_guardrail_events WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                    sensor["tenant_id"],
                    check["guardrail_event_id"],
                    conn=conn,
                )
                if (
                    check["registration_id"] != data["registration_id"]
                    or event["payload_sha256"] != data["payload_sha256"]
                    or check["deterministic_result"].get("policy_floor")
                    != data.get("policy_floor")
                ):
                    raise APIError(409, "request payload changed", "payload_changed")
                if (
                    check["settings_version"] != data["settings_version"]
                    or check["policy_version"] != data["policy_version"]
                ):
                    raise APIError(409, "request policy changed", "policy_changed")
                approvals.check_action_state(st, event, conn)
                return check, event, False

            # Cold or replacement policy workers are preparation, not model
            # assessment time. Existing events still keep their own deadline.
            deterministic = Policy(policy=policy).evaluate(data["target"])
            events = st.many(
                """SELECT * FROM inline_guardrail_events
                   WHERE tenant_id=$1 AND registration_id=$2 AND logical_id=$3 FOR UPDATE""",
                sensor["tenant_id"],
                data["registration_id"],
                target["evidence"]["logical_id"],
                conn=conn,
            )
            created = not events
            if events:
                event = events[0]
                if event["payload_sha256"] != data["payload_sha256"]:
                    raise APIError(
                        409, "logical event payload changed", "payload_changed"
                    )
                # A cached assessment belongs to its original model and rubric.
                # A deployment must not silently relabel it with a new scorer.
                if (event["model"], event["rubric_version"], event["profile"]) != (self.model, self.rubric, self.profile):
                    raise APIError(
                        409, "assessment version changed", "assessment_version_changed"
                    )
                approvals.check_action_state(st, event, conn)
                if event["status"] != "pending" and context_changed(st, event, settings, conn):
                    # Only a server-observed context change can create another
                    # assessment. Request aliases alone never reset scoring.
                    event = st.one(
                        """UPDATE inline_guardrail_events
                           SET assessment_generation=assessment_generation+1,
                               prepared_state=$3,context_enabled=$4,context_pinned=false,
                               knowledge_snapshot=NULL,context_revision=NULL,scope_key=NULL,scope_version=0,
                               status='pending',assessment=NULL,started_at=NULL,completed_at=NULL,
                               claim_token=$5,deadline_at=clock_timestamp()+$6*interval '1 millisecond',
                               company_policy=$7
                           WHERE tenant_id=$1 AND id=$2 RETURNING *""",
                        sensor["tenant_id"], event["id"], Jsonb(state), settings["context_enabled"],
                        new_id(), self._remaining_ms(settings, data),
                        Jsonb({key: value for key, value in company_policy.read(
                            st, sensor["tenant_id"], conn=conn, lock=True,
                        ).items() if key != "updated_at"}), conn=conn,
                    )
                    created = True
            else:
                event_id = _uuid(target["id"], "event id")
                # Ingestion deduplicates IDs globally. Hold its ID lock and
                # verify an existing row before associating it with an action.
                st.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    target["id"],
                    conn=conn,
                )
                existing = st.many(
                    "SELECT tenant_id,sensor_id,body FROM events WHERE id=$1",
                    event_id,
                    conn=conn,
                )
                used = st.scalar(
                    "SELECT EXISTS(SELECT 1 FROM inline_guardrail_events WHERE event_id=$1)",
                    event_id,
                    conn=conn,
                )
                if used or (
                    existing
                    and (
                        existing[0]["tenant_id"] != sensor["tenant_id"]
                        or existing[0]["sensor_id"] != sensor["id"]
                    )
                ):
                    raise APIError(
                        409,
                        "event id already binds different evidence",
                        "payload_changed",
                    )
                if existing:
                    # Ordinary delivery may precede this check and fill host
                    # defaults that later changed on the sensor. Compare the
                    # exact permitted content before defense redaction, so two
                    # different credentials cannot collapse to the same marker.
                    stored_host = existing[0]["body"].get("host")
                    defaults = stored_host if isinstance(stored_host, dict) else None
                    submitted = normalize_host(
                        copy.deepcopy(data["target"]), sensor, defaults=defaults
                    )
                    if existing[0]["body"] != submitted:
                        raise APIError(
                            409,
                            "event id already binds different evidence",
                            "payload_changed",
                        )
                    target, context, state = _prepare_evidence(data, sensor, defaults)
                ingested = st.ingest_batch(sensor, [target], conn=conn)
                require(
                    not ingested.get("rejected"),
                    "target registration is unavailable",
                    403,
                )
                event = st.one(
                    """INSERT INTO inline_guardrail_events
                           (id,tenant_id,sensor_id,registration_id,owner_user_id,logical_id,
                            event_id,action_commitment,payload_sha256,target_body,captured_context,
                            prepared_state,model,rubric_version,status,claim_token,deadline_at,context_enabled,
                            company_policy,profile)
                       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'pending',$15,
                              clock_timestamp()+$16*interval '1 millisecond',$17,$18,$19) RETURNING *""",
                    new_id(),
                    sensor["tenant_id"],
                    sensor["id"],
                    data["registration_id"],
                    registration["owner_user_id"],
                    target["evidence"]["logical_id"],
                    event_id,
                    data["action_commitment"],
                    data["payload_sha256"],
                    Jsonb(target),
                    Jsonb(context),
                    Jsonb(state),
                    self.model,
                    self.rubric,
                    new_id(),
                    self._remaining_ms(settings, data),
                    settings["context_enabled"],
                    Jsonb({key: value for key, value in company_policy.read(
                        st, sensor["tenant_id"], conn=conn, lock=True,
                    ).items() if key != "updated_at"}),
                    self.profile,
                    conn=conn,
                )
            if (created and settings["enabled"] and settings["context_enabled"]
                    and self._remaining_ms(settings, data) <= 0):
                # Commit this failure with the event so aliases and expiry
                # cannot turn preparation exhaustion into an unscored allow.
                st.execute(
                    "INSERT INTO tenant_knowledge(tenant_id) VALUES($1) ON CONFLICT DO NOTHING",
                    sensor["tenant_id"], conn=conn,
                )
                revision = st.scalar(
                    "SELECT revision FROM tenant_knowledge WHERE tenant_id=$1 FOR SHARE",
                    sensor["tenant_id"], conn=conn,
                )
                scope = get_context_scope(st, sensor["tenant_id"], data["registration_id"], conn)
                knowledge = {**_unavailable_context("retrieval_not_completed"), "sent": False}
                event = st.one(
                    """UPDATE inline_guardrail_events SET status='unavailable',
                           assessment=$2,completed_at=clock_timestamp(),knowledge_snapshot=$3,
                           context_pinned=true,context_revision=$4,scope_key=$5,scope_version=$6
                       WHERE id=$1 RETURNING *""",
                    event["id"], Jsonb({
                        **_unavailable("policy_preparation_timeout"), **_identity(event), "knowledge": knowledge,
                        "company_policy": {"revision": event["company_policy"]["revision"]},
                    }), Jsonb(knowledge), revision, scope["scope_key"], scope["version"], conn=conn,
                )
                created = False
            snapshot = {
                "settings": {
                    key: value for key, value in settings.items() if key != "updated_at"
                },
                "policy": {"version": policy["version"], "rules": policy["rules"]},
            }
            if "policy_floor" in data:
                deterministic["policy_floor"] = data["policy_floor"]
            check = st.one(
                """INSERT INTO inline_guardrail_checks
                       (id,tenant_id,sensor_id,registration_id,owner_user_id,request_id,
                        guardrail_event_id,settings_version,policy_version,policy_snapshot,deterministic_result,
                        assessment_generation)
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *""",
                new_id(),
                sensor["tenant_id"],
                sensor["id"],
                data["registration_id"],
                registration["owner_user_id"],
                data["request_id"],
                event["id"],
                data["settings_version"],
                data["policy_version"],
                Jsonb(snapshot),
                Jsonb(deterministic),
                event["assessment_generation"],
                conn=conn,
            )
            return check, event, created

    @staticmethod
    def _remaining_ms(settings, data):
        timeout_ms = settings["timeout_ms"] or 100
        if not settings["context_enabled"]:
            return timeout_ms
        return max(0, timeout_ms - (time.monotonic() - data["received_at"]) * 1000)

    def _enrich(self, sensor, check, event):
        from ..knowledge_retrieval import augment_state, retrieve

        if not event["context_enabled"]:
            return event
        st = self.st
        deadline = time.monotonic() + 0.050
        with _bounded_transaction(st, deadline) as conn:
            self._authorize(sensor, event["registration_id"], conn)
            scope = get_context_scope(st, sensor["tenant_id"], event["registration_id"], conn)
            remaining = st.scalar(
                "SELECT extract(epoch FROM $1::timestamptz-clock_timestamp())",
                event["deadline_at"], conn=conn,
            )
        try:
            snapshot = retrieve(
                st, sensor["tenant_id"], event["prepared_state"]["target_event"],
                trusted_scope=scope["scope_key"],
                deadline=min(deadline - 0.010, time.monotonic() + max(0, float(remaining))),
            )
            if snapshot.get("schema_version") != 2:
                snapshot = _unavailable_context(
                    "postgres_context_disabled", status="disabled", revision=snapshot.get("revision")
                )
        except Exception:
            snapshot = _unavailable_context("retrieval_failed")
        prepared, snapshot = augment_state(event["prepared_state"], snapshot)
        with _bounded_transaction(st, deadline) as conn:
            self._authorize(sensor, event["registration_id"], conn)
            row = st.one(
                "SELECT * FROM inline_guardrail_events WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                sensor["tenant_id"], event["id"], conn=conn,
            )
            if row["claim_token"] != event["claim_token"] or row["status"] != "pending":
                return event
            if row["context_pinned"]:
                return row
            # A timeout snapshot can carry no corpus revision. Pin the current
            # version for invalidation without claiming retrieval succeeded.
            st.execute(
                "INSERT INTO tenant_knowledge(tenant_id) VALUES($1) ON CONFLICT DO NOTHING",
                sensor["tenant_id"], conn=conn,
            )
            revision = st.scalar(
                "SELECT revision FROM tenant_knowledge WHERE tenant_id=$1 FOR SHARE",
                sensor["tenant_id"], conn=conn,
            )
            event = st.one(
                """UPDATE inline_guardrail_events SET prepared_state=$3,knowledge_snapshot=$4,
                       context_pinned=true,context_revision=$5,scope_key=$6,scope_version=$7
                   WHERE tenant_id=$1 AND id=$2 RETURNING *""",
                sensor["tenant_id"], event["id"], Jsonb(prepared), Jsonb(snapshot),
                snapshot.get("revision") if snapshot.get("revision") is not None else revision,
                scope["scope_key"], scope["version"], conn=conn,
            )
            return event

    def _admit(self, sensor, check, event):
        st = self.st
        with st.transaction() as conn:
            self._authorize(sensor, check["registration_id"], conn)
            row = st.one(
                "SELECT * FROM inline_guardrail_events WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                sensor["tenant_id"],
                event["id"],
                conn=conn,
            )
            if (
                row["status"] != "pending"
                or row["started_at"]
                or row["claim_token"] != event["claim_token"]
                or row["assessment_generation"] != check["assessment_generation"]
            ):
                return None, None
            if row["context_enabled"] and not row["context_pinned"]:
                return None, "context_unavailable"
            now = st.scalar("SELECT clock_timestamp()", conn=conn)
            if row["deadline_at"] <= now:
                return None, "timeout"
            if st.scalar(
                "SELECT EXISTS(SELECT 1 FROM risk_provider_backoff WHERE provider='jev' AND retry_at>$1)",
                now,
                conn=conn,
            ):
                return None, "provider_backoff"
            window = st.scalar(
                "SELECT to_timestamp(floor(extract(epoch FROM $1::timestamptz)/3600)*3600)",
                now,
                conn=conn,
            )
            call_id = st.start_model_call(
                {
                    "id": row["event_id"],
                    "tenant_id": sensor["tenant_id"],
                    "sensor_id": sensor["id"],
                    "risk_attempts": row["assessment_generation"],
                },
                self.model,
                purpose="guardrail",
                guardrail_check_id=check["id"],
                conn=conn,
            )
            if call_id is None:
                return None, "dispatch_already_recorded"
            st.execute(
                """INSERT INTO risk_assessment_usage(tenant_id,sensor_id,window_start,attempts)
                   VALUES($1,$2,$3,1) ON CONFLICT(tenant_id,sensor_id) DO UPDATE SET
                       window_start=EXCLUDED.window_start,
                       attempts=CASE WHEN risk_assessment_usage.window_start=EXCLUDED.window_start
                           THEN risk_assessment_usage.attempts+1 ELSE 1 END""",
                sensor["tenant_id"],
                sensor["id"],
                window,
                conn=conn,
            )
            st.execute(
                "UPDATE inline_guardrail_events SET started_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2",
                sensor["tenant_id"],
                row["id"],
                conn=conn,
            )
            return (call_id, (row["deadline_at"] - now).total_seconds()), None

    def _finish(self, event, assessment, provider_delay=0, *, conn=None):
        st = self.st
        with nullcontext(conn) if conn is not None else st.transaction() as conn:
            row = st.one(
                "SELECT * FROM inline_guardrail_events WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                event["tenant_id"],
                event["id"],
                conn=conn,
            )
            if provider_delay:
                st.execute(
                    """INSERT INTO risk_provider_backoff(provider,retry_at)
                       VALUES('jev',clock_timestamp()+$1*interval '1 second')
                       ON CONFLICT(provider) DO UPDATE
                       SET retry_at=GREATEST(risk_provider_backoff.retry_at,EXCLUDED.retry_at)""",
                    min(3600, max(0, float(provider_delay))),
                    conn=conn,
                )
            if row["status"] != "pending" or row["claim_token"] != event["claim_token"]:
                return False
            now = st.scalar("SELECT clock_timestamp()", conn=conn)
            timely = row["deadline_at"] > now
            if not timely:
                assessment = _unavailable("timeout")
            assessment = {
                **assessment,
                **_identity(row),
                "company_policy": {"revision": row["company_policy"]["revision"]},
            }
            if row["context_enabled"]:
                assessment["knowledge"] = row["knowledge_snapshot"] or {
                    **_unavailable_context("retrieval_not_completed"), "sent": False,
                }
            st.execute(
                """UPDATE inline_guardrail_events SET status=$3,assessment=$4,completed_at=$5
                   WHERE tenant_id=$1 AND id=$2""",
                row["tenant_id"],
                row["id"],
                assessment["status"],
                Jsonb(assessment),
                now,
                conn=conn,
            )
            return timely

    def _response(self, sensor, check_id):
        st = self.st
        with (_bounded_transaction(st, time.monotonic()+.05, wait_for_capacity=True)
              if self.customer else st.transaction()) as conn:
            check = st.one(
                "SELECT * FROM inline_guardrail_checks WHERE tenant_id=$1 AND sensor_id=$2 AND id=$3",
                sensor["tenant_id"],
                sensor["id"],
                check_id,
                conn=conn,
            )
            registration = self._authorize(sensor, check["registration_id"], conn)
            event = st.one(
                "SELECT * FROM inline_guardrail_events WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                sensor["tenant_id"],
                check["guardrail_event_id"],
                conn=conn,
            )
            # Another response can attach an approval while this one waits for
            # its action lock. Read that immutable alias after the wait.
            check = st.one(
                "SELECT * FROM inline_guardrail_checks WHERE tenant_id=$1 AND sensor_id=$2 AND id=$3",
                sensor["tenant_id"],
                sensor["id"],
                check_id,
                conn=conn,
            )
            approvals.check_action_state(st, event, conn)
            event = assessment_for_check(st, event, check, conn)
            # A row-lock wait must not retain an earlier authorization or
            # policy snapshot. Sensor and tenant availability remain locked.
            require(
                st.scalar(
                    "SELECT EXISTS(SELECT 1 FROM tenant_users WHERE tenant_id=$1 AND id=$2 AND status='active')",
                    sensor["tenant_id"],
                    registration["owner_user_id"],
                    conn=conn,
                ),
                "session owner is unavailable",
                403,
            )
            settings, _ = self._versions(
                sensor, check["settings_version"], check["policy_version"], conn
            )
            now = st.scalar("SELECT clock_timestamp()", conn=conn)
            if event["status"] == "pending" and event["deadline_at"] <= now:
                event["assessment"] = {
                    **_unavailable("timeout"),
                    **_identity(event),
                    "company_policy": {"revision": event["company_policy"]["revision"]},
                }
                if event["context_enabled"]:
                    event["assessment"]["knowledge"] = event["knowledge_snapshot"] or {
                        **_unavailable_context("retrieval_not_completed"), "sent": False,
                    }
                st.execute(
                    """UPDATE inline_guardrail_events SET status='unavailable',assessment=$3,completed_at=$4
                       WHERE tenant_id=$1 AND id=$2""",
                    sensor["tenant_id"],
                    event["id"],
                    Jsonb(event["assessment"]),
                    now,
                    conn=conn,
                )
                event["status"] = "unavailable"
            result = {
                "id": check["id"],
                "registration_id": check["registration_id"],
                "event_id": event["event_id"],
                "logical_id": event["logical_id"],
                "action_commitment": event["action_commitment"],
                "settings_version": check["settings_version"],
                "policy_version": check["policy_version"],
                "assessment_generation": check["assessment_generation"],
            }
            if event["status"] == "pending":
                return {
                    **result,
                    "status": "pending",
                    "deadline_at": event["deadline_at"],
                }, 202
            if check["decision"] is None:
                decision = _decision(
                    check["deterministic_result"],
                    check["policy_snapshot"]["settings"],
                    event["assessment"],
                    approvals.policy_floor(st, check, conn),
                )
                check = st.one(
                    """UPDATE inline_guardrail_checks SET decision=COALESCE(decision,$4),
                           completed_at=COALESCE(completed_at,clock_timestamp())
                       WHERE tenant_id=$1 AND sensor_id=$2 AND id=$3 RETURNING *""",
                    sensor["tenant_id"],
                    sensor["id"],
                    check["id"],
                    Jsonb(decision),
                    conn=conn,
                )
            code = approvals.policy_floor_error(st, check, conn)
            if code:
                raise APIError(409, approvals._ERRORS[code], code)
            approval = approvals.ensure_for_check(st, check, event, settings, conn)
            return {
                **result,
                "status": "complete",
                "assessment": {
                    **customer_views.guardrail_assessment(event["assessment"]),
                    # Also bound older stored assessments on historical replay.
                    "company_policy": {"revision": event["company_policy"]["revision"]},
                },
                "decision": check["decision"],
                **({"approval": approval} if approval is not None else {}),
            }, 200

    async def check(self, sensor, payload):
        received_at = time.monotonic()
        data = _request(payload)
        data["received_at"] = received_at
        try:
            evidence = await self.run_sync(_prepare_evidence, data, sensor)
        except (RecursionError, ValueError, TypeError):
            raise APIError(400, "invalid captured evidence") from None
        check, event, created = await self.run_sync(
            self._prepare, sensor, data, evidence
        )
        if created:
            settings = check["policy_snapshot"]["settings"]
            event = await self.run_sync(self._enrich, sensor, check, event)
            client = (self.client_for_tenant(sensor["tenant_id"])
                      if self.client_for_tenant else self.client)
            if self.customer:
                from ..service_inline import assess
                await assess(self, sensor, check, event, client)
                return await self.run_sync(self._response, sensor, check["id"])
            from .scoring import JevError
            reason = None
            if not self.cfg.inline_guardrails or not settings["enabled"]:
                reason = "disabled"
            elif client is None or (
                self.client_for_tenant and not await self.run_sync(client.available)
            ):
                reason = "provider_unavailable"
            elif (
                event["target_body"]["kind"] == "tool.result"
                and not event["captured_context"]["matched_tool_call"]
            ):
                reason = "missing_tool_call"
            if reason:
                await self.run_sync(self._finish, event, _unavailable(reason))
            else:
                # Wait for provider capacity only within this action's deadline.
                seconds = max(0, (event["deadline_at"] - datetime.now(timezone.utc)).total_seconds())
                try:
                    await asyncio.wait_for(self.capacity.acquire(), seconds)
                except TimeoutError:
                    await self.run_sync(self._finish, event, _unavailable("timeout"))
                    return await self.run_sync(self._response, sensor, check["id"])
                try:
                    admitted, reason = await self.run_sync(
                        self._admit, sensor, check, event
                    )
                    if admitted:
                        call_id, seconds = admitted
                        usage, failed, delay = None, False, 0
                        try:
                            async with asyncio.timeout(seconds):
                                assessment = await client.assess(
                                    event["prepared_state"], company_policy=event["company_policy"]["prompt"],
                                    **({"timeout": seconds, "run_sync": self.run_sync} if self.client_for_tenant else {}),
                                )
                            usage = assessment.pop("usage", None)
                            if (
                                assessment.get("model") != self.model
                                or assessment.get("rubric_version") != self.rubric
                            ):
                                raise JevError("invalid_response")
                            if assessment.get("status") != "scored":
                                assessment = _unavailable("insufficient_evidence")
                        except JevError as exc:
                            usage, failed = exc.usage or usage, True
                            delay = exc.retry_after if exc.retryable else 0
                            assessment = _unavailable(exc.code)
                        except TimeoutError:
                            failed, assessment = True, _unavailable("timeout")
                        except asyncio.CancelledError:
                            await asyncio.shield(
                                self.run_sync(
                                    self._finish, event, _unavailable("cancelled")
                                )
                            )
                            await asyncio.shield(
                                self.run_sync(
                                    self.st.finish_model_call,
                                    sensor["tenant_id"],
                                    call_id,
                                    None,
                                    failed=True,
                                )
                            )
                            raise
                        except Exception:
                            failed, assessment = True, _unavailable("assessment_failed")
                        await self.run_sync(
                            self.st.finish_model_call,
                            sensor["tenant_id"],
                            call_id,
                            usage,
                            failed=failed,
                        )
                        await self.run_sync(self._finish, event, assessment, delay)
                    elif reason:
                        await self.run_sync(self._finish, event, _unavailable(reason))
                finally:
                    self.capacity.release()
        return await self.run_sync(self._response, sensor, check["id"])
