"""Tenant-controlled skill analysis. Only metadata and billing counters are durable."""

import json
import hashlib
import time
import uuid
from contextlib import closing
from dataclasses import replace
from decimal import Decimal, InvalidOperation

import httpx
from psycopg.types.json import Jsonb

from .httpx import require, uuid_param
from openaidr_api_client.client import Connection, SyncIntelligenceClient, Unavailable
from .intelligence import ORIGINS, connection_for_origin, selected_connection, switchable

from .config import PLATFORM_AVAILABLE

if PLATFORM_AVAILABLE:
    from openaidr.platform.provider_settings import SKILL_MODEL as MODEL
else:
    MODEL = None
LEGACY_PROTOCOL = "skills-assess-v1"
PILOT_SIZE = 5
MAX_REQUEST_BYTES = 1 << 20
MAX_OUTPUT_TOKENS = 8192
ACTIVE = """EXISTS (SELECT 1 FROM skill_installations i
    JOIN inventory_components c ON c.id=i.component_id AND c.tenant_id=i.tenant_id
    JOIN sensors s ON s.id=i.sensor_id AND s.tenant_id=i.tenant_id
    WHERE i.tenant_id=b.tenant_id AND i.sha256=b.sha256 AND i.observed_at=c.last_seen_at
    AND NOT s.disabled AND s.deleted_at IS NULL)"""


def totals(st, tenant, *, conn=None):
    return st.one("""SELECT COALESCE(sum(cost_usd),0) AS measured_usd,
        COALESCE(sum(CASE WHEN cost_usd IS NULL THEN reserved_cost_usd ELSE 0 END),0) AS reserved_usd,
        count(*) FILTER (WHERE cost_usd IS NULL)::int AS unpriced_calls,
        count(*)::int AS calls, COALESCE(sum(input_tokens),0) AS input_tokens,
        COALESCE(sum(output_tokens),0) AS output_tokens
        FROM model_usage WHERE tenant_id=$1 AND skill_scan_id IS NOT NULL""", tenant, conn=conn)


def read(st, tenant, cfg, buffer, *, customer=False):
    if customer:
        from .service_skill_settings import read as customer_read
        return customer_read(st, tenant, cfg, buffer)
    rows = st.many("SELECT mode,budget_usd,budget_blocked,updated_at FROM tenant_skill_llm_settings WHERE tenant_id=$1", tenant)
    settings = rows[0] if rows else {"mode": "off", "budget_usd": Decimal(5), "budget_blocked": False, "updated_at": None}
    usage = totals(st, tenant)
    jobs = st.one("""SELECT count(*) FILTER (WHERE status='pending')::int AS pending,
        count(*) FILTER (WHERE status='running')::int AS running,
        count(*) FILTER (WHERE status='complete')::int AS completed,
        count(*) FILTER (WHERE status='failed')::int AS failed FROM skill_llm_jobs WHERE tenant_id=$1""", tenant)
    return {**settings, **usage, **jobs, "model": MODEL, "pilot_size": PILOT_SIZE,
            "key_configured": bool(model_connection(cfg, tenant, st)),
            "worker_available": bool(cfg.tenant_id == tenant and cfg.skill_scanner_token and getattr(buffer, "llm_profile", None)
                                     and time.monotonic() - getattr(buffer, "llm_seen", 0) < 720),
            "remaining_usd": max(Decimal(0), settings["budget_usd"] - usage["measured_usd"] - usage["reserved_usd"])}


def compatible_profiles(profile):
    from .service_skill_worker import scanner_profile

    try:
        current = scanner_profile("llm") + ":metered-1"
    except Unavailable:
        return [profile]
    return [profile, scanner_profile("llm", legacy=True) + ":metered-1"] if profile == current else [profile]


# A result without final accounting must not authorize a new paid attempt.
SETTLED_SKILL = """NOT EXISTS(SELECT 1 FROM service_call_intents i
    LEFT JOIN service_credit_receipts r ON r.tenant_id=i.tenant_id AND r.request_id=i.request_id
        AND r.origin=i.origin AND r.api_tenant_id=i.api_tenant_id AND r.service=i.service
    WHERE i.tenant_id=j.tenant_id AND i.scope_id=j.lease_id AND i.service='skill_assessment'
    AND (i.outcome IS NULL OR r.state IS NULL OR r.state NOT IN ('settled','released','disabled')))"""


def schedule(st, tenant, profile, *, limit=10000, conn=None):
    # A hash/profile is attempted at most once. Failed scans require deliberate
    # future retry support; toggling a mode must never silently spend again.
    st.execute("""INSERT INTO skill_llm_jobs(id,tenant_id,sha256,profile)
        SELECT gen_random_uuid(),b.tenant_id,b.sha256,$2 FROM skill_bundles b
        WHERE b.tenant_id=$1 AND (b.manifest->>'complete')::boolean AND """ + ACTIVE + """
        AND NOT EXISTS(SELECT 1 FROM skill_llm_jobs j WHERE j.tenant_id=b.tenant_id AND j.sha256=b.sha256
            AND (j.profile=$2 OR j.profile=ANY($4::text[]) AND j.status='complete'
                AND COALESCE((j.report->>'complete')::boolean,false)))
        ORDER BY b.content_bytes,b.sha256 LIMIT $3 ON CONFLICT DO NOTHING""",
        tenant, profile, limit, compatible_profiles(profile), conn=conn)


def save(st, tenant, cfg, buffer, data, actor, *, customer=False):
    if customer:
        from .service_skill_settings import save as customer_save
        return customer_save(st, tenant, cfg, buffer, data, actor)
    require(isinstance(data, dict) and "mode" in data and set(data) <= {"mode", "budget_usd"}, "provide a scan mode")
    mode = data["mode"]
    require(mode in ("off", "pilot", "automatic"), "invalid scan mode")
    if mode != "off":
        current = read(st, tenant, cfg, buffer)
        require(current["worker_available"], "Update or start the skill scanner before enabling model analysis.", 409)
        require(current["key_configured"], "Configure the tenant Intelligence service connection first.", 409)
    with st.transaction() as conn:
        st.execute("INSERT INTO tenant_skill_llm_settings(tenant_id) VALUES($1) ON CONFLICT DO NOTHING", tenant, conn=conn)
        previous = st.one("SELECT mode,budget_usd FROM tenant_skill_llm_settings WHERE tenant_id=$1 FOR UPDATE", tenant, conn=conn)
        try:
            budget = Decimal(str(data.get("budget_usd", previous["budget_usd"])))
            require(budget.is_finite() and 0 <= budget <= 1000 and budget == budget.quantize(Decimal("0.01")), "invalid total budget")
        except (InvalidOperation, ValueError):
            require(False, "invalid total budget")
        if mode != "off":
            require(budget > 0, "Service analysis is unavailable with the current resource limit.", 409)
        st.execute("UPDATE tenant_skill_llm_settings SET mode=$2,budget_usd=$3,budget_blocked=false,updated_at=now() WHERE tenant_id=$1", tenant, mode, budget, conn=conn)
        if mode == "off" or (mode == "pilot" and previous["mode"] != "pilot"):
            st.execute("DELETE FROM skill_llm_jobs WHERE tenant_id=$1 AND status='pending'", tenant, conn=conn)
        if mode == "pilot":
            # An active pilot is idempotent; a second click cannot expand it.
            pending = st.scalar("SELECT count(*) FROM skill_llm_jobs WHERE tenant_id=$1 AND status IN ('pending','running')", tenant, conn=conn)
            if not pending:
                schedule(st, tenant, buffer.llm_profile, limit=PILOT_SIZE, conn=conn)
                require(st.scalar("SELECT count(*) FROM skill_llm_jobs WHERE tenant_id=$1 AND status='pending'", tenant, conn=conn),
                        "No eligible collected bundles. Wait for a sensor upload or select automatic scanning.", 409)
    st.audit(tenant, actor, "skill_scanning.llm.configure", "skill_scanning", tenant,
             {"mode": mode})
    return read(st, tenant, cfg, buffer)


def prepare(st, tenant, profile, static_profile, *, customer=False):
    if customer:
        from .service_skill_settings import expire
        expire(st, tenant, profile)
        # Inventory cleanup may remove the bundle row while an old job and its
        # receipt uncertainty remain. Reattach that original lease, never a new ID.
        with st.transaction() as conn:
            held = st.many("""SELECT b.sha256,j.lease_id,j.report,i.origin,i.api_tenant_id
                FROM skill_bundles b JOIN skill_llm_jobs j ON j.tenant_id=b.tenant_id AND j.sha256=b.sha256
                JOIN service_call_intents i ON i.tenant_id=j.tenant_id AND i.scope_id=j.lease_id
                    AND i.service='skill_assessment'
                WHERE b.tenant_id=$1 AND b.lease_id IS NULL AND b.status IN ('queued','awaiting_upload')
                AND j.profile=ANY($2::text[]) AND NOT """ + SETTLED_SKILL + """
                ORDER BY b.sha256,j.completed_at DESC FOR UPDATE OF b""", tenant, compatible_profiles(profile), conn=conn)
            for row in held:
                binding = hashlib.sha256(json.dumps(["intelligence", row["origin"], row["api_tenant_id"]]).encode()).hexdigest()
                st.execute("""UPDATE skill_bundles SET lease_id=$3,worker_protocol='skills-service-v1',
                    model_connection_binding=$4,status='failed',report=COALESCE($5,report),
                    error='An earlier skill request or receipt is unresolved.'
                    WHERE tenant_id=$1 AND sha256=$2 AND lease_id IS NULL""", tenant, row["sha256"], row["lease_id"],
                    binding, Jsonb({**row["report"], "complete": False}) if row["report"] else None, conn=conn)
    else:
        st.execute("""UPDATE skill_llm_jobs SET status='failed',completed_at=now()
            WHERE tenant_id=$1 AND status='running' AND lease_until<=now()""", tenant)
        st.execute("DELETE FROM skill_llm_jobs WHERE tenant_id=$1 AND status='pending' AND profile<>$2", tenant, profile)
    # Restore durable results when an identical bundle returns after inventory
    # cleanup. Preserve the original assessment time, including partial results.
    eligible = """(j.profile=$2 OR j.profile=ANY($5::text[]) AND j.status='complete'
        AND COALESCE((j.report->>'complete')::boolean,false) AND """ + SETTLED_SKILL + ")"
    restore = """UPDATE skill_bundles b SET report=j.report || '{"llm_cache":true}'::jsonb,
        completed_at=j.completed_at,scanner_profile=$3,status='complete',error='',attempts=0
        FROM (SELECT DISTINCT ON (j.tenant_id,j.sha256) j.* FROM skill_llm_jobs j WHERE j.tenant_id=$1
            AND """ + eligible + """ AND j.report->>'mode'='llm' AND j.status IN ('complete','failed')
            ORDER BY j.tenant_id,j.sha256,(j.profile=$2) DESC,j.completed_at DESC) j
        WHERE b.tenant_id=$1 AND j.tenant_id=b.tenant_id AND j.sha256=b.sha256
        AND (b.lease_until IS NULL OR b.lease_until<=now())
        AND (b.scanner_profile<>$3 OR NOT COALESCE((b.report->>'llm_cache')::boolean,false))
        AND ($4::text[] IS NULL OR b.sha256=ANY($4::text[]))"""
    if customer:
        from .skill_scanning import HELD_SCAN
        with st.transaction() as conn:
            rows = st.many("""SELECT b.sha256 FROM skill_bundles b JOIN skill_llm_jobs j
                ON j.tenant_id=b.tenant_id AND j.sha256=b.sha256 WHERE b.tenant_id=$1 AND j.profile=ANY($2::text[])
                AND j.report->>'mode'='llm' AND j.status IN ('complete','failed')
                AND (b.lease_until IS NULL OR b.lease_until<=clock_timestamp())
                ORDER BY b.sha256 FOR UPDATE OF b""", tenant, compatible_profiles(profile), conn=conn)
            st.execute(restore + f" AND NOT {HELD_SCAN}",
                       tenant, profile, static_profile, [row["sha256"] for row in rows], compatible_profiles(profile), conn=conn)
    else:
        st.execute(restore, tenant, profile, static_profile, None, [profile])
    if st.scalar("SELECT COALESCE((SELECT mode FROM tenant_skill_llm_settings WHERE tenant_id=$1),'off')", tenant) == "automatic":
        schedule(st, tenant, profile)


def pending(st, tenant, sha, *, conn=None, customer=False, profile=None):
    if customer and not profile:
        return False
    return bool(st.scalar("""SELECT EXISTS(SELECT 1 FROM skill_llm_jobs j
        JOIN tenant_skill_llm_settings s USING(tenant_id)
        WHERE j.tenant_id=$1 AND j.sha256=$2 AND j.status='pending' AND s.mode<>'off' AND ($3 OR NOT s.budget_blocked)
        AND ($4::text IS NULL OR j.profile=$4))""", tenant, sha, customer, profile, conn=conn))


def attach(st, tenant, job, profile, *, customer=False):
    rows = st.many("""UPDATE skill_llm_jobs j SET status='running',lease_id=$4,lease_until=now()+interval '660 seconds'
        FROM tenant_skill_llm_settings s WHERE j.tenant_id=$1 AND j.sha256=$2 AND j.profile=$3
        AND s.tenant_id=j.tenant_id AND s.mode<>'off' AND ($5 OR NOT s.budget_blocked) AND j.status='pending' RETURNING j.id""", tenant, job["sha256"], profile, job["lease_id"], customer)
    if rows:
        job["llm"] = True


def completed(st, tenant, sha, lease, report, *, conn):
    rows = st.many("""UPDATE skill_llm_jobs SET status=$4,report=$5,completed_at=now()
        WHERE tenant_id=$1 AND sha256=$2 AND lease_id=$3 AND status='running' RETURNING id""", tenant, sha, lease,
               "complete" if report and report["complete"] and report["mode"] == "llm" else "failed",
               Jsonb(report) if report else None, conn=conn)
    if rows and report and report["mode"] == "llm":
        report["llm_cache"] = True


def model_connection(cfg, tenant, st=None):
    connection = selected_connection(cfg, st)
    if connection:
        require(connection.tenant_id == str(tenant), "Intelligence tenant mismatch", 503)
        return connection
    return None


def connection_binding(connection):
    if connection is None:
        return None
    return hashlib.sha256(json.dumps(["intelligence", connection.origin, connection.tenant_id]).encode()).hexdigest()


def require_connection(st, tenant, data, binding, *, protocol=LEGACY_PROTOCOL, conn=None):
    rows = st.many("""SELECT model_connection_binding,worker_protocol FROM skill_bundles WHERE tenant_id=$1 AND sha256=$2
        AND lease_id=$3 AND status='running' AND lease_until>clock_timestamp() FOR UPDATE""",
        tenant, data["sha256"], data["lease_id"], conn=conn)
    require(bool(rows), "Scan lease expired.", 409)
    require(rows[0]["worker_protocol"] == protocol, "Scan worker protocol changed; finish the original lease.", 409)
    # NULL means an older lease with unknown prior dispatch history. Never
    # attach that paid attempt to the connection selected after a restart.
    require(rows[0]["model_connection_binding"] == binding, "Scan model connection changed; finish this lease before changing the connection.", 409)


def reserve(st, tenant, data, input_bound, output_limit, *, binding):
    from .service_costs import Call
    from .session_investigator import _quote, _rates

    # Reserve before dispatch using the same atomic tenant budget gate.
    ordinary, cached, write, output = _rates(_quote(MODEL, 0), input_bound)
    reservation = input_bound * max(ordinary, cached, write) + output_limit * output
    with st.transaction() as conn:
        settings = st.many("SELECT * FROM tenant_skill_llm_settings WHERE tenant_id=$1 FOR UPDATE", tenant, conn=conn)
        require(settings and settings[0]["mode"] != "off", "LLM scanning is paused.", 409)
        require(not settings[0]["budget_blocked"], "Skill scan budget limit reached.", 429)
        require_connection(st, tenant, data, binding, conn=conn)
        jobs = st.many("""SELECT id FROM skill_llm_jobs WHERE tenant_id=$1 AND sha256=$2 AND lease_id=$3
            AND status='running' AND lease_until>now()""", tenant, data.get("sha256"), data.get("lease_id"), conn=conn)
        require(bool(jobs), "LLM scan lease expired.", 409)
        usage = totals(st, tenant, conn=conn)
        blocked = usage["measured_usd"] + usage["reserved_usd"] + reservation > settings[0]["budget_usd"]
        if blocked:
            st.execute("UPDATE tenant_skill_llm_settings SET budget_blocked=true WHERE tenant_id=$1", tenant, conn=conn)
        else:
            call = Call(st, tenant, "asset_management", "openai", MODEL, conn=conn)
            require(call.id is not None, "Usage recording unavailable.", 503)
            st.execute("UPDATE model_usage SET skill_scan_id=$2,reserved_cost_usd=$3 WHERE id=$1 AND tenant_id=$4", call.id, jobs[0]["id"], reservation, tenant, conn=conn)
    require(not blocked, "Skill scan budget limit reached.", 429)
    return call


def service_inference(st, tenant, connection, data):
    from .service_costs import Call
    from openaidr_api_client.contracts.skills import MAX_RESPONSE, SkillRequest, SkillTask, validate_response

    require(set(data) == {"sha256", "lease_id", "task", "timeout_ms"}, "Use a pinned scanner task in Intelligence mode")
    try:
        task = SkillTask.model_validate(data["task"]).model_dump()
        encoded = json.dumps(task, ensure_ascii=False, allow_nan=False).encode()
        request = SkillRequest(**task, timeout_ms=data["timeout_ms"], input_token_bound=2 * len(encoded) + 65536).model_dump()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        require(False, "Invalid scanner task")
    require(task["bundle_sha256"] == data["sha256"], "Scanner task bundle mismatch")
    require(len(json.dumps(request).encode()) <= MAX_REQUEST_BYTES, "Scan task too large", 413)
    if st.scalar("SELECT EXISTS(SELECT 1 FROM skill_llm_jobs WHERE tenant_id=$1 AND sha256=$2 AND lease_id=$3)",
                 tenant, data["sha256"], data["lease_id"]):
        call = reserve(st, tenant, data, request["input_token_bound"], MAX_OUTPUT_TOKENS,
                       binding=connection_binding(connection))
    else:
        # Operator-managed scans still use typed tasks, with a durable usage
        # record committed before dispatch and the original lease binding.
        with st.transaction() as conn:
            require_connection(st, tenant, data, connection_binding(connection), conn=conn)
            require(not st.scalar("""SELECT EXISTS(SELECT 1 FROM skill_llm_jobs
                WHERE tenant_id=$1 AND sha256=$2 AND lease_id=$3)""",
                tenant, data["sha256"], data["lease_id"], conn=conn), "Use budgeted model inference for this scan.", 409)
            call = Call(st, tenant, "asset_management", "openai", MODEL, conn=conn)
            require(call.id is not None, "Usage recording unavailable.", 503)
            st.execute("UPDATE model_usage SET skill_scan_lease_id=$2 WHERE id=$1", call.id, data["lease_id"], conn=conn)
    failed = True
    try:
        with closing(SyncIntelligenceClient.from_connection(connection)) as client:
            value = client.request("/v1/skills/assess", request, MAX_RESPONSE, request["timeout_ms"] / 1000 + 5)
        call.payload = validate_response(request, value)
        failed = value["status"] != "completed"
        return value
    except (Unavailable, TimeoutError, httpx.HTTPError, ValueError, TypeError, KeyError, RecursionError):
        require(False, "Skill Intelligence service unavailable.", 502)
    finally:
        call.finish(failed=failed)


def lease_connection(st, tenant, cfg, data, *, protocol=LEGACY_PROTOCOL):
    require(isinstance(data, dict), "invalid inference request")
    sha, lease = data.get("sha256"), data.get("lease_id")
    require(isinstance(sha, str) and len(sha) == 64 and all(c in "0123456789abcdef" for c in sha), "invalid scan hash")
    try:
        uuid.UUID(lease)
    except (ValueError, TypeError, AttributeError):
        require(False, "invalid scan lease")
    rows = st.many("SELECT model_connection_binding FROM skill_bundles WHERE tenant_id=$1 AND sha256=$2 AND lease_id=$3",
                   tenant, sha, lease)
    require(bool(rows), "Scan lease expired.", 409)
    binding = rows[0]["model_connection_binding"]
    require_connection(st, tenant, data, binding, protocol=protocol)
    unavailable = 409 if protocol == LEGACY_PROTOCOL else 503
    require(binding is not None, "The original scan connection is unavailable.", unavailable)
    connection = Connection.from_config(cfg)
    require(connection is None or connection.tenant_id == str(tenant), "Intelligence tenant mismatch", 503)
    if switchable(cfg, connection):
        # Match the durable origin before reading any credential. The newly
        # selected origin may have no key or an undecryptable saved key.
        original = next((origin for origin in (*ORIGINS, connection.origin)
                         if connection_binding(replace(connection, origin=origin)) == binding), None)
        connection = connection_for_origin(cfg, st, original) if original else None
    require(connection is not None, "The original scan connection is unavailable.", unavailable)
    require_connection(st, tenant, data, connection_binding(connection), protocol=protocol)
    return connection


def inference(st, tenant, cfg, data):
    connection = lease_connection(st, tenant, cfg, data)
    return service_inference(st, tenant, connection, data)


def legacy_call(st, tenant, data):
    """Settle already admitted worker receipts without admitting another call."""
    from .service_costs import Call

    require(isinstance(data, dict), "invalid model call")
    uuid_param(data.get("lease_id"), "lease_id")
    if "usage_id" in data:
        require(set(data) == {"lease_id", "usage_id", "response", "failed"}
                and type(data["failed"]) is bool and isinstance(data["response"], dict), "invalid model completion")
        uuid_param(data["usage_id"], "usage_id")
        rows = st.many("""SELECT * FROM model_usage WHERE id=$1 AND tenant_id=$2
            AND purpose='asset_management' AND skill_scan_lease_id=$3 AND skill_scan_id IS NULL""",
            data["usage_id"], tenant, data["lease_id"])
        require(bool(rows), "Model call not found.", 404)
        call = Call.from_record(st, rows[0])
        call.payload = data["response"]
        call.finish(failed=data["failed"])
        require(st.scalar("SELECT completed_at IS NOT NULL FROM model_usage WHERE id=$1 AND tenant_id=$2",
                          call.id, tenant), "Usage recording unavailable.", 503)
        return {"accepted": True}
    require(False, "Use pinned tasks through the Intelligence service", 409)
