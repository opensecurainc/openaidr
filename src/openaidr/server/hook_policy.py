"""Backend policy decisions for ordinary hooks, independent of managed sessions."""

from .customer_views import guardrail_assessment

import asyncio
import hashlib
import time
from contextlib import nullcontext
from pathlib import PurePosixPath, PureWindowsPath

from psycopg.types.json import Jsonb

from openaidr.core.policy import ACTIONS, Policy, _could_apply
from openaidr.core.hook_protocol import PRODUCTS
from openaidr.core.protocol import HOOK_WORK_TIMEOUT_SECONDS
from openaidr.guardrail.hooks import PRECEDENCE
from . import company_policy, ingest_evidence
from .guardrail.storage import _bounded_transaction, get_settings as risk_settings
from openaidr.core.redact import redact_value
from .httpx import APIError, require, uuid_param
from .store import new_id


MAX_TIMEOUT_MS = 1800
# Resource limit for abandoned or stuck work, independent of client delivery.
WORK_TIMEOUT_SECONDS = HOOK_WORK_TIMEOUT_SECONDS
MAX_BODY_BYTES = 64 << 10
EVENT_KINDS = {
    "UserPromptSubmit": {"prompt"},
    "PreToolUse": {"tool.call", "command", "file.read", "file.write", "network"},
    "PostToolUse": {"tool.result"},
    "PostToolUseFailure": {"tool.result"},
}
UNAVAILABLE = {
    "capture_disabled", "unsupported_boundary", "content_redacted",
    "content_truncated", "unsupported_content",
}
POLICY_FAILURE_DETAILS = {
    "workers busy": "All policy workers were busy.",
    "evaluation or worker startup timed out": "Policy evaluation or worker startup timed out.",
    "worker unavailable": "A policy worker was unavailable.",
    "worker stopping": "A policy worker was still shutting down.",
    "an applicable rule has an invalid matcher": "An applicable policy rule has an invalid match expression.",
}
ACTION_FIELDS = {
    "agent": {"product"},
    "session": {"id", "cwd"},
    "tool": {"name", "input", "output", "call_id", "is_error"},
    "command": {"text", "cwd", "exit_code"},
    "file": {"path", "operation"},
    "network": {"host", "url"},
}
PUBLIC_FIELDS = (
    "id", "request_id", "product", "hook_event", "session_id", "tool_call_id",
    "mode", "settings_version", "policy_version", "status", "evaluated_decision",
    "returned_decision", "reason", "rule_id", "rule_name", "failure_reason", "created_at",
    "assessment", "completed_at",
)


def get_settings(st, tenant_id, conn=None):
    rows = st.many(
        "SELECT mode,version,updated_at FROM tenant_hook_settings WHERE tenant_id=$1",
        tenant_id, conn=conn,
    )
    return rows[0] if rows else {"mode": "shadow", "version": 0, "updated_at": None}


def save_settings(st, tenant_id, payload, actor, *, conn=None):
    require(set(payload) == {"mode", "version"}, "mode and version are required")
    require(payload["mode"] in ("shadow", "enforce"), "invalid hook mode")
    require(type(payload["version"]) is int and payload["version"] >= 0, "invalid version")
    with nullcontext(conn) if conn is not None else st.transaction() as conn:
        st.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "hook-settings:" + tenant_id, conn=conn,
        )
        current = get_settings(st, tenant_id, conn)
        require(current["version"] == payload["version"], "hook settings changed", 409)
        updated = st.one(
            """INSERT INTO tenant_hook_settings(tenant_id,mode) VALUES($1,$2)
               ON CONFLICT(tenant_id) DO UPDATE SET mode=EXCLUDED.mode,
                   version=tenant_hook_settings.version+1,updated_at=clock_timestamp()
               RETURNING mode,version,updated_at""",
            tenant_id, payload["mode"], conn=conn,
        )
        st.execute(
            """INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,
                   target_type,target_id,details)
               VALUES($1,$2,$3,$4,$5,'hooks.configure','hooks',$2,$6)""",
            new_id(), tenant_id, actor.get("type", "user"), actor.get("id", ""),
            actor.get("name", ""),
            Jsonb({"before": current["mode"], "mode": updated["mode"], "version": updated["version"]}),
            conn=conn,
        )
    return updated


def _string(value, name, maximum=65536, *, empty=True):
    require(isinstance(value, str) and (empty or bool(value)) and len(value) <= maximum,
            "invalid " + name)


def parse(raw):
    require(len(raw) <= MAX_BODY_BYTES, "hook check too large", 413)
    try:
        payload = ingest_evidence.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        raise APIError(400, "invalid hook JSON") from None
    require(isinstance(payload, dict), "hook check must be an object")
    return payload


def validate(payload):
    require(set(payload) <= {
        "request_id", "product", "hook_event", "session_id", "tool_call_id",
        "actions", "timeout_ms", "availability", "path_home", "control_supported",
    }, "unknown hook check field")
    uuid_param(payload.get("request_id"), "request_id")
    require(payload.get("product") in {*PRODUCTS.values(), "cowork", "claude-ai", "unknown"}, "invalid product")
    event = payload.get("hook_event")
    require(isinstance(event, str) and event in EVENT_KINDS, "invalid hook_event")
    require(event != "PostToolUseFailure" or payload["product"] != "codex-cli",
            "unsupported hook event")
    _string(payload.get("session_id"), "session_id", 256, empty=False)
    _string(payload.get("tool_call_id", ""), "tool_call_id", 256)
    if "timeout_ms" in payload:
        budget = payload["timeout_ms"]
        require(type(budget) is int and 1 <= budget <= MAX_TIMEOUT_MS, "invalid timeout_ms")
    available = payload.get("availability", "available")
    require(isinstance(available, str) and available in UNAVAILABLE | {"available"},
            "invalid availability")
    require(type(payload.get("control_supported", True)) is bool, "invalid control_supported")
    actions = payload.get("actions")
    require(isinstance(actions, list) and len(actions) <= 128, "invalid actions")
    require(bool(actions) if available == "available" else (actions == [] if available in {"capture_disabled", "unsupported_content"} else True),
            "capture-disabled checks must omit action content")
    if "path_home" in payload:
        home = payload["path_home"]
        _string(home, "path_home", 4096, empty=False)
        require("\x00" not in home and (PurePosixPath(home).is_absolute() or PureWindowsPath(home).is_absolute()),
                "path_home must be an absolute path")
        require(available == "available", "unavailable checks must omit path_home")
    for action in actions:
        require(isinstance(action, dict) and set(action) <= {"kind", "text", *ACTION_FIELDS},
                "invalid action fields")
        require(isinstance(action.get("kind"), str) and action["kind"] in EVENT_KINDS[event],
                "action kind does not match hook event")
        if "text" in action:
            _string(action["text"], "text")
        for field, keys in ACTION_FIELDS.items():
            if field not in action:
                continue
            value = action[field]
            require(isinstance(value, dict) and set(value) <= keys, "invalid action " + field)
            for key, item in value.items():
                if key == "input":
                    continue
                if key == "is_error":
                    require(type(item) is bool, "invalid tool.is_error")
                elif key == "exit_code":
                    require(type(item) is int, "invalid command.exit_code")
                else:
                    _string(item, field + "." + key)
        require(action.get("agent", {}).get("product", payload["product"]) == payload["product"],
                "action product does not match")
        require(action.get("session", {}).get("id", payload["session_id"]) == payload["session_id"],
                "action session does not match")
        for kind, field, key in (("command", "command", "text"),
                                 ("file.read", "file", "path"), ("file.write", "file", "path")):
            if action["kind"] == kind:
                require(bool(action.get(field, {}).get(key)), "missing action " + field + "." + key)
    require("path_home" not in payload or any(action.get("file", {}).get("path") for action in actions),
            "path_home requires a file target")
    try:
        encoded = ingest_evidence.encode(payload)
    except (ValueError, TypeError, RecursionError):
        raise APIError(400, "invalid hook JSON") from None
    require(len(encoded) <= MAX_BODY_BYTES, "hook check too large", 413)
    # A retry may have a smaller remaining time budget; it is still the same action.
    content = {key: value for key, value in payload.items() if key != "timeout_ms"}
    return hashlib.sha256(ingest_evidence.encode(content)).hexdigest()


def _reply(row):
    retained = row.get("risk_settings", {}).get("retained_evidence_id")
    extra = {"retained_id": retained} if retained else {}
    if row["status"] != "evaluated":
        return {
            "error": {"code": "unavailable", "message": "hook evaluation is unavailable"},
            "id": row["id"], "request_id": row["request_id"], **extra,
        }, 503
    return {**{key: row[key] for key in PUBLIC_FIELDS},
            "assessment": guardrail_assessment(row["assessment"]), "delivery_status": "unconfirmed",
            "availability": row["risk_settings"].get("availability", "available"), **extra}, 200


def prepare(st, sensor, payload, deadline, *, link_detection=False, customer=False):
    if customer:
        from .service_guardrail import contract
        contract()
    else:
        from .guardrail.scoring import MODEL, RUBRIC_VERSION

    digest = validate(payload)
    tenant_id = sensor["tenant_id"]
    redacted = redact_value(payload["actions"])
    storage_reason = ingest_evidence.storage_issue(redacted)
    identity_reason = next((reason for name in ("session_id", "tool_call_id")
                            if (reason := ingest_evidence.text_issue(payload.get(name, "")))), "")
    with _bounded_transaction(st, deadline, wait_for_capacity=True) as conn:
        st.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "hook-check:" + sensor["id"] + ":" + payload["request_id"], conn=conn,
        )
        existing = st.many(
            "SELECT * FROM ordinary_hook_checks WHERE tenant_id=$1 AND sensor_id=$2 AND request_id=$3",
            tenant_id, sensor["id"], payload["request_id"], conn=conn,
        )
        if existing:
            require(existing[0]["payload_sha256"] == digest, "request payload changed", 409)
            return existing[0], False
        retained = None
        if not identity_reason and not storage_reason:
            require(not st.scalar(
                """SELECT EXISTS(SELECT 1 FROM retained_ingest_evidence
                   WHERE tenant_id=$1 AND sensor_id=$2 AND source='hook-checks' AND record_key=$3)""",
                tenant_id, sensor["id"], payload["request_id"], conn=conn,
            ), "request payload changed", 409)
        if identity_reason or storage_reason:
            # Retain the same action redaction and metadata as the ordinary row.
            # The digest binds retries to original input without retaining secrets.
            retained = ingest_evidence.retain(
                st, sensor, "hook-checks", payload["request_id"],
                {**{key: payload[key] for key in
                    ("request_id", "product", "hook_event", "session_id", "tool_call_id") if key in payload},
                 "actions": redacted, "payload_sha256": digest},
                identity_reason or storage_reason, conn=conn,
            )
        if identity_reason:
            # An invalid identity cannot be bound to a session or delivery row.
            # Never replace its characters with a different identity.
            return {"id": retained["id"], "tenant_id": tenant_id,
                    "request_id": payload["request_id"], "status": "unavailable",
                    "risk_settings": {"retained_evidence_id": retained["id"]}}, True
        settings = get_settings(st, tenant_id, conn)
        policy = st.get_policy(tenant_id, conn=conn)
        failure = payload.get("availability", "available")
        failure_detail = ""
        decision = {"action": "allow"}
        if failure in ("available", "unsupported_boundary") and payload["actions"]:
            actions = [{**action, "agent": {"product": payload["product"]}}
                       for action in payload["actions"]]
            try:
                path_rules = [rule for rule in policy.get("rules", [])
                              if rule.get("match", {}).get("path_glob")
                              and any(_could_apply(rule, action) for action in actions)]
                source_os = (sensor.get("os") or "").lower()
                needs_home = any(rule["match"]["path_glob"].replace("\\", "/") == "~"
                                 or rule["match"]["path_glob"].replace("\\", "/").startswith("~/")
                                 for rule in path_rules)
                if path_rules and (source_os not in ("windows", "darwin", "linux")
                                   or needs_home and "path_home" not in payload):
                    failure = "path_context_unavailable"
                else:
                    decisions = Policy(
                        policy, path_windows=source_os == "windows",
                        path_home=payload.get("path_home", ""),
                    ).evaluate_many(actions)
                    matched = [result for _, result in decisions if "rule" in result]
                    unavailable = next((result for _, result in decisions
                                        if result.get("evaluation_unavailable")), None)
                    if unavailable:
                        # The shared matcher uses a synthetic deny when its worker
                        # cannot evaluate. Ordinary hooks must report unavailability.
                        failure = "evaluation_unavailable"
                        failure_detail = POLICY_FAILURE_DETAILS.get(
                            unavailable.get("evaluation_detail"), "Policy evaluation failed unexpectedly.",
                        )
                    elif any(not result["rule"].get("id") for result in matched):
                        failure = "evaluation_unavailable"
                        failure_detail = "A matched policy rule has no identifier."
                    elif matched:
                        decision = min(matched, key=lambda result: PRECEDENCE[result["action"]])
            except Exception:
                failure = "evaluation_unavailable"
                failure_detail = "Policy evaluation failed unexpectedly."
        assessable = failure in {"available", "unsupported_boundary", "content_redacted", "content_truncated"} and bool(payload["actions"])
        status = "pending" if assessable else "unavailable"
        rule = decision.get("rule", {})
        model_settings = risk_settings(st, tenant_id, conn)
        model_settings.pop("updated_at", None)
        model_settings["company_policy"] = {
            key: value for key, value in company_policy.read(st, tenant_id, conn=conn).items()
            if key != "updated_at"
        }
        model_settings["rule_decision"] = decision
        model_settings["policy_snapshot"] = {key: policy[key] for key in ("version", "rules")}
        model_settings["content_redacted"] = redacted != payload["actions"]
        model_settings["assessment_profile"] = ({"profile": "guardrail.1"} if customer
            else {"model": MODEL, "rubric_version": RUBRIC_VERSION})
        model_settings["link_detection_enabled"] = link_detection
        model_settings["availability"] = payload.get("availability", "available")
        model_settings["control_supported"] = (
            payload.get("availability") != "unsupported_boundary" and payload.get("control_supported", True)
        )
        if retained:
            model_settings["retained_evidence_id"] = retained["id"]
            model_settings["evidence_storage_reason"] = storage_reason
        seconds = max(0, deadline - time.monotonic())
        row = st.one(
            """INSERT INTO ordinary_hook_checks
               (id,tenant_id,sensor_id,request_id,payload_sha256,product,hook_event,session_id,
                tool_call_id,mode,settings_version,policy_version,status,evaluated_decision,
                returned_decision,reason,rule_id,rule_name,matched_rule,failure_reason,
                actions,risk_settings,deadline_at)
               VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
                      $21,$22,clock_timestamp()+$23*interval '1 second')
               RETURNING *""",
            new_id(), tenant_id, sensor["id"], payload["request_id"], digest, payload["product"],
            payload["hook_event"], payload["session_id"], payload.get("tool_call_id", ""),
            settings["mode"], settings["version"], policy["version"],
            status, None, None, failure_detail or decision.get("reason", ""),
            rule.get("id", ""), rule.get("name", ""), Jsonb(rule) if rule else None,
            "" if status == "pending" else failure,
            Jsonb([] if retained else redacted), Jsonb(model_settings), seconds, conn=conn,
        )
        from .agent_projects import observe

        for index, action in enumerate(row["actions"]):
            observe(conn, tenant_id, sensor["id"], payload["product"], action.get("session"),
                    f"hook:{row['id']}:{index}", row["created_at"])
    if time.monotonic() >= deadline:
        raise TimeoutError("hook response deadline")
    return row, True


def assessment_input(st, row, deadline, *, customer=False):
    if customer:
        from .service_guardrail import contract
        error = contract()
    else:
        from .guardrail.scoring import MODEL, JevError
        error = JevError

    with _bounded_transaction(st, deadline, wait_for_capacity=True) as conn:
        prior = st.many(
            """SELECT id,actions,risk_settings FROM ordinary_hook_checks
               WHERE tenant_id=$1 AND sensor_id=$2 AND product=$3 AND session_id=$4
                 AND (created_at,id)<($5,$6)
                 AND (actions<>'[]'::jsonb OR risk_settings ? 'retained_evidence_id')
               ORDER BY created_at DESC,id DESC LIMIT 12""",
            row["tenant_id"], row["sensor_id"], row["product"], row["session_id"],
            row["created_at"], row["id"], conn=conn,
        )
        prompts = st.many(
            """SELECT id,actions,risk_settings FROM ordinary_hook_checks
               WHERE tenant_id=$1 AND sensor_id=$2 AND product=$3 AND session_id=$4
                 AND (created_at,id)<($5,$6) AND hook_event='UserPromptSubmit'
                 AND (actions<>'[]'::jsonb OR risk_settings ? 'retained_evidence_id')
               ORDER BY created_at DESC,id DESC LIMIT 1""",
            row["tenant_id"], row["sensor_id"], row["product"], row["session_id"],
            row["created_at"], row["id"], conn=conn,
        )
        if any(item["risk_settings"].get("retained_evidence_id") for item in prior + prompts):
            raise error("unsupported_evidence_context")
        target = dict(row["actions"][0])
        if len(row["actions"]) > 1:
            target["mapped_actions"] = row["actions"]
        from .guardrail.evidence import assessment_state

        context = [{"kind": action["kind"], "body": action}
                   for item in reversed(prior) for action in item["actions"]]
        identities = [{"check_id": item["id"], "action_index": index}
                      for item in reversed(prior) for index, _ in enumerate(item["actions"])]
        prompt = prompts[0]["actions"][0] if prompts else None
        state = assessment_state(
            {"kind": target["kind"], "body": target}, context,
            {"kind": "prompt", "body": prompt} if prompt else None,
        )
        state["target_event"] = target
        state["evidence_status"] = row["risk_settings"].get("availability", "available")
        captured = {"state": state, "company_policy": row["risk_settings"].get("company_policy", {}).get("prompt", "")}
        selected_count = len(state["prior_events"])
        selected = identities[-selected_count:] if selected_count else []
        selected_ids = {item["check_id"] for item in selected}
        sources = [row, *prompts, *[item for item in prior if item["id"] in selected_ids]]
        manifest = {
            "prior_actions": selected,
            "latest_prompt_check_id": prompts[0]["id"] if prompts else None,
            "context_limited": True,
            "context_truncated": selected_count < len(context),
            "content_truncated": any(item.get("truncated") for item in [state["latest_prompt"] or {}, *state["prior_events"]]),
            "content_redacted": any(item["risk_settings"].get("content_redacted") for item in sources),
            "redaction_status_unknown": any("content_redacted" not in item["risk_settings"] for item in sources),
        }
        st.execute(
            """UPDATE ordinary_hook_checks SET assessment_input=$3,assessment_input_sha256=$4,assessment_context=$5
               WHERE id=$1 AND tenant_id=$2 AND assessment_input IS NULL""",
            row["id"], row["tenant_id"], Jsonb(captured),
            hashlib.sha256(ingest_evidence.encode(captured)).hexdigest(), Jsonb(manifest), conn=conn,
        )
        call_id = None if customer else st.start_model_call(
            {**row, "risk_attempts": 1}, MODEL, purpose="guardrail", conn=conn,
        )
    return call_id, state


def finish(st, row, assessment, call_id, usage, deadline, *, conn=None):
    settings = row["risk_settings"]
    assessment["company_policy"] = {"revision": settings.get("company_policy", {}).get("revision", 0)}
    decision = settings["rule_decision"]
    failure = "" if assessment.get("status") == "scored" else assessment.get("reason", "insufficient_evidence")
    if not failure and settings["enabled"]:
        score = assessment["score"]
        dynamic = ("deny" if score >= settings["block_threshold"] else
                   "ask" if score >= settings["ask_threshold"] else "allow")
        if PRECEDENCE[dynamic] < PRECEDENCE[decision["action"]]:
            decision = {"action": dynamic, "reason": "Matched Guardrail risk threshold"}
    from .malicious_links import restriction

    link_decision = restriction(assessment.get("links", {}))
    if link_decision and decision["action"] != "deny":
        decision = link_decision
    # A failed model contributes no restriction. A timely backend rule decision
    # remains valid; policy failures never reach this pending classification path.
    evaluated = decision["action"]
    returned = "allow" if row["mode"] == "shadow" or not settings["control_supported"] else evaluated
    with nullcontext(conn) if conn is not None else _bounded_transaction(st, deadline, wait_for_capacity=True) as conn:
        updated = st.one(
            """UPDATE ordinary_hook_checks SET status=$3,assessment=$4,
                   evaluated_decision=$5,returned_decision=$6,reason=$7,failure_reason=$8,
                   rule_id=$9,rule_name=$10,matched_rule=$11,
                   completed_at=clock_timestamp()
               WHERE id=$1 AND tenant_id=$2 AND status='pending' AND deadline_at>clock_timestamp()
               RETURNING *""",
            row["id"], row["tenant_id"], "evaluated", Jsonb(assessment),
            evaluated, returned, decision.get("reason", ""), failure,
            decision.get("rule", {}).get("id", ""), decision.get("rule", {}).get("name", ""),
            Jsonb(decision["rule"]) if decision.get("rule") else None, conn=conn,
        )
        if call_id:
            st.finish_model_call(row["tenant_id"], call_id, usage, failed=bool(failure), conn=conn)
        captured = st.many(
            """UPDATE events SET risk=$4 WHERE tenant_id=$1 AND sensor_id=$2
                 AND kind<>'sensor'
                 AND (body->'source'->>'hook_request_id'=$3 OR risk->>'hook_check_id'=$5)
               RETURNING id,tenant_id,sensor_id,agent_id,session_id,kind,product,time,body""",
            row["tenant_id"], row["sensor_id"], row["request_id"], Jsonb(event_risk(updated)), row["id"], conn=conn,
        )
        for event in captured:
            st.record_risk_detection(event, assessment, conn)
    return _reply(updated)


async def check(st, row, created, deadline, client, run_sync, *, link_client=None, customer=False):
    if customer:
        from .service_hook import check as customer_check
        return await customer_check(st, row, created, deadline, client, run_sync, link_client=link_client)
    from .guardrail.scoring import MODEL, RUBRIC_VERSION, JevError

    if row["status"] != "pending":
        return _reply(row)
    if not created:
        # A duplicate may wait for the first dispatch, but never starts another.
        while row["status"] == "pending" and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
            row = await run_sync(st.one, "SELECT * FROM ordinary_hook_checks WHERE id=$1 AND tenant_id=$2",
                                 row["id"], row["tenant_id"])
        return _reply(row)
    link_task = None
    if link_client and row["risk_settings"].get("link_detection_enabled"):
        link_task = asyncio.create_task(link_client.assess(
            row["tenant_id"], row["actions"],
            "unsupported_evidence" if row["risk_settings"].get("retained_evidence_id")
            else row["risk_settings"].get("availability", "available"),
            run_sync=run_sync,
        ))
    try:
        call_id, usage = None, None
        try:
            if row["risk_settings"].get("retained_evidence_id"):
                raise JevError("unsupported_evidence")
            if client is None:
                raise JevError("provider_unavailable")
            call_id, state = await run_sync(assessment_input, st, row, deadline)
            # Leave time to record the result within the backend resource limit.
            seconds = max(0, deadline - time.monotonic() - 0.05)
            async with asyncio.timeout(seconds):
                assessment = await client.assess(
                    state, company_policy=row["risk_settings"].get("company_policy", {}).get("prompt", ""),
                    timeout=seconds, run_sync=run_sync,
                )
            usage = assessment.pop("usage", None)
            if assessment.get("model") != MODEL or assessment.get("rubric_version") != RUBRIC_VERSION:
                raise JevError("invalid_response")
        except JevError as exc:
            usage = exc.usage or usage
            assessment = {"status": "unavailable", "reason": exc.code}
        except TimeoutError:
            assessment = {"status": "unavailable", "reason": "timeout"}
        if link_task:
            assessment["links"] = await link_task
        return await run_sync(finish, st, row, assessment, call_id, usage, deadline)
    finally:
        if link_task and not link_task.done():
            link_task.cancel()
            await asyncio.gather(link_task, return_exceptions=True)


def event_risk(row):
    if row["status"] == "evaluated" and row["assessment"].get("status") == "scored":
        return {**row["assessment"], "hook_check_id": row["id"]}
    result = {"status": "pending" if row["status"] == "pending" else "error",
              "reason": row.get("failure_reason") or "classification_pending", "hook_check_id": row["id"]}
    if row["status"] == "evaluated" and "links" in row["assessment"]:
        result["links"] = row["assessment"]["links"]
    return result


def captured_assessment(st, sensor, event, conn):
    """Share a completed assessment across copies of the same captured action."""
    if event.get("kind") == "sensor":
        return None
    source = event.get("source")
    request_id = source.get("hook_request_id") if isinstance(source, dict) else None
    args = [sensor["tenant_id"], sensor["id"]]
    if request_id:
        condition = "request_id::text=$3"
        args.append(request_id)
    else:
        call_id = (event.get("tool") or {}).get("call_id")
        kind = event.get("kind")
        boundary = "PostToolUse" if kind == "tool.result" else "PreToolUse"
        if not call_id or kind not in EVENT_KINDS[boundary]:
            return None
        condition = "product=$3 AND session_id=$4 AND tool_call_id=$5 AND hook_event=ANY($6)"
        args.extend([(event.get("agent") or {}).get("product", ""),
                     (event.get("session") or {}).get("id", ""), call_id,
                     ["PostToolUse", "PostToolUseFailure"] if kind == "tool.result" else [boundary]])
    rows = st.many(
        "SELECT * FROM ordinary_hook_checks WHERE tenant_id=$1 AND sensor_id=$2 "
        "AND deadline_at IS NOT NULL AND " + condition + " LIMIT 2", *args, conn=conn,
    )
    if len(rows) == 1:
        return event_risk(rows[0])
    # Never guess which occurrence a reused native call identifier describes.
    return {"status": "pending", "reason": "classification_pending"} if request_id else None


def delivery(st, sensor, ident, payload, deadline):
    uuid_param(ident)
    require(set(payload) == {"request_id", "delivery_status", "delivered_decision"},
            "invalid hook delivery fields")
    uuid_param(payload["request_id"], "request_id")
    status, action = payload["delivery_status"], payload["delivered_decision"]
    require(status in ("delivered", "timed_out", "failed"), "invalid delivery_status")
    require(action in ACTIONS, "invalid delivered_decision")
    require(status == "delivered" or action == "allow", "failed delivery must allow")
    with _bounded_transaction(st, deadline, wait_for_capacity=True) as conn:
        row = st.one(
            """SELECT * FROM ordinary_hook_checks
               WHERE tenant_id=$1 AND sensor_id=$2 AND id=$3 AND request_id=$4 FOR UPDATE""",
            sensor["tenant_id"], sensor["id"], ident, payload["request_id"], conn=conn,
        )
        require(status != "delivered" or row["status"] == "evaluated",
                "unavailable checks cannot confirm delivery")
        require(row["returned_decision"] != "allow" or action == "allow",
                "an allow response cannot deliver a restriction")
        stored = st.one(
            """INSERT INTO ordinary_hook_deliveries(check_id,delivery_status,delivered_decision)
               VALUES($1,$2,$3) ON CONFLICT(check_id) DO UPDATE SET check_id=EXCLUDED.check_id
               RETURNING delivery_status,delivered_decision,reported_at""",
            ident, status, action, conn=conn,
        )
        require(stored["delivery_status"] == status and stored["delivered_decision"] == action,
                "delivery report changed", 409)
    return {"id": ident, "request_id": payload["request_id"], **stored}


# Shared receipt validation for the dashboard and aggregate reports.
def delivery_receipt_match(*, projected=False):
    status = "e.delivery_status" if projected else "e.body->'hook'->>'delivery_status'"
    action = "e.delivered_decision" if projected else "e.body->'hook'->>'delivered_decision'"
    identity = (
        "e.request_id=c.request_id AND EXISTS (SELECT 1 FROM telemetry_partition_days p "
        "WHERE p.tenant_id=e.tenant_id AND p.storage_day=e.storage_day AND p.retired_at IS NULL) "
        if projected else
        "e.body->'source'->>'hook_request_id'=c.request_id::text "
        "AND e.body->'source'->>'collector'='hook-delivery' "
        "AND e.kind='sensor' AND e.export_id IS NULL "
    )
    return (
        "e.tenant_id=c.tenant_id AND e.sensor_id=c.sensor_id AND e.product=c.product AND "
        + identity +
        f"AND (({status} IN ('timed_out','failed') AND {action}='allow') "
        f"OR ({status}='delivered' AND c.status='evaluated' "
        f"AND ({action}=c.returned_decision "
        "OR ((c.product IN ('codex-cli','cursor','opencode') OR c.hook_event<>'PreToolUse') AND c.returned_decision='ask' "
        f"AND {action}='deny') "
        "OR (c.product IN ('github-copilot','cursor','antigravity','opencode','hermes-agent','workbuddy') AND c.returned_decision='warn' "
        f"AND {action}='allow')))) "
    )


DELIVERY_RECEIPT_MATCH = delivery_receipt_match()

DELIVERY_JOINS = (
    "LEFT JOIN ordinary_hook_deliveries d ON d.check_id=c.id "
    "LEFT JOIN LATERAL ("
    "SELECT e.body->'hook'->>'delivery_status' AS delivery_status,"
    "e.body->'hook'->>'delivered_decision' AS delivered_decision,e.received_at AS reported_at "
    "FROM events e WHERE " + DELIVERY_RECEIPT_MATCH +
    "ORDER BY e.received_at,e.id LIMIT 1) r ON true"
)


def decision_query(classified=False):
    fields = [field for field in PUBLIC_FIELDS if field not in {"id", "status", "failure_reason", "assessment"}]
    return (
        "c.id,c.sensor_id,s.hostname AS sensor_hostname,s.username AS sensor_username,c.actions,"
        "CASE WHEN c.status='pending' THEN 'unavailable' ELSE c.status END AS status,"
        "CASE WHEN c.status='pending' THEN 'timeout' ELSE c.failure_reason END AS failure_reason,"
        "CASE WHEN c.status='pending' THEN '{\"status\":\"unavailable\",\"reason\":\"timeout\"}'::jsonb "
        "ELSE c.assessment END AS assessment," + ",".join("c." + field for field in fields)
        + ",COALESCE(d.delivery_status,r.delivery_status,'unconfirmed') AS delivery_status,"
        "COALESCE(d.delivered_decision,r.delivered_decision) AS delivered_decision,"
        "COALESCE(d.reported_at,r.reported_at) AS reported_at",
        "ordinary_hook_checks c JOIN sensors s ON s.id=c.sensor_id AND s.tenant_id=c.tenant_id "
        + DELIVERY_JOINS,
        ["c.tenant_id=$1", "(c.status<>'pending' OR c.deadline_at<=clock_timestamp())"]
        + (["c.deadline_at IS NOT NULL"] if classified else []),
    )


def list_decisions(st, tenant_id, page, classified=False):
    rows, cursor = st._page(*decision_query(classified), [tenant_id], page, "c.created_at")
    return [{**row, "assessment": guardrail_assessment(row["assessment"])} for row in rows], cursor
