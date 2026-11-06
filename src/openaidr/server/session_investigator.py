"""Fenced, owner-scoped session investigation and measured provider accounting."""

import asyncio
import copy
from contextlib import contextmanager, nullcontext
from datetime import datetime
from decimal import Decimal, ROUND_DOWN
from functools import partial
from importlib import import_module
import hashlib
import json
import re
import threading
import time
import uuid

import anyio
from psycopg.errors import QueryCanceled
from psycopg.types.json import Jsonb

from . import session_aggregation as aggregation
from . import session_ownership, detection_history, customer_views
from .httpx import APIError
from .model import public, public_record
from openaidr.core.redact import redact_value
from .store import NotFound, new_id

RULE_ID = "codex-session-detection"
# Both retained reports and the complete-job contract use this public format.
# Execution protocol remains a separate persisted identity, never an SDK choice.
REPORT_VERSION = 4

try:
    _report = import_module("openaidr_api_client.contracts.service_investigation_runtime")
except ModuleNotFoundError as error:
    if error.name != "openaidr_api_client.contracts.service_investigation_runtime":
        raise
    _report = import_module("openaidr_api_client.contracts.investigation_runtime")

FRAGMENT_BYTES, CHUNK_BYTES = _report.FRAGMENT_BYTES, _report.CHUNK_BYTES
RESULT_BYTES, READ_BYTES, MAX_INTEGER = _report.RESULT_BYTES, _report.READ_BYTES, _report.MAX_INTEGER
GAPS = _report.GAPS
InvestigationStopped, canonical_json = _report.InvestigationStopped, _report.canonical_json
_digest, _need, _uuid = _report._digest, _report._need, _report._uuid
valid_result, valid_read_arguments = _report.valid_result, _report.valid_read_arguments


def _legacy_runtime():
    try:
        return import_module("openaidr_api_client.contracts.investigation_runtime")
    except ModuleNotFoundError as error:
        if error.name != "openaidr_api_client.contracts.investigation_runtime":
            raise
        raise InvestigationStopped("runtime_unavailable") from None


def _source_scope(st, job, session_id, conn):
    return detection_history.authorize(st, job, session_id, conn)


class _FenceDeadline(Exception):
    pass


@contextmanager
def _fence(st, claim, *, sources=(), conn=None, allow_expired=False):
    error = None
    with st.transaction() if conn is None else nullcontext(conn) as conn:
        st.execute("SET LOCAL statement_timeout='5s'", conn=conn)
        st.execute("SET LOCAL lock_timeout='3s'", conn=conn)
        candidate = st.one(
            "SELECT * FROM session_investigation_jobs WHERE id=$1",
            _uuid(claim["job_id"]),
            conn=conn,
        )
        _need(not allow_expired or candidate.get("protocol_version") == 4, "invalid_request")
        if candidate.get("protocol_version") == 4:
            _need(candidate["tenant_id"] == claim.get("tenant_id"), "scope_unavailable")
            _need(not allow_expired or st.scalar("""SELECT EXISTS(SELECT 1 FROM session_investigation_submissions
                WHERE attempt_id=$1 AND tenant_id=$2)""", claim["attempt_id"], candidate["tenant_id"], conn=conn),
                "invalid_request")
        registration, scoped = None, {}
        try:
            if candidate.get("session_id"):
                registration = aggregation._job_authority(st, candidate, conn)
            else:
                registration = session_ownership.authorize_inline(
                    st,
                    {"tenant_id": candidate["tenant_id"], "id": candidate["sensor_id"]},
                    candidate["registration_id"],
                    conn,
                    owner_user_id=candidate["owner_user_id"],
                    snapshot=True,
                )
                _need(
                    registration["owner_user_id"] == candidate["owner_user_id"],
                    "scope_unavailable",
                )
            for ident in sorted(set(sources)):
                try:
                    scoped[ident] = _source_scope(st, candidate, ident, conn)
                except NotFound:
                    scoped[ident] = None
                except APIError as exc:
                    if exc.status not in (403, 404):
                        raise
                    scoped[ident] = None
        except NotFound:
            error = "scope_unavailable"
        except APIError as exc:
            if exc.status not in (403, 404):
                raise
            error = "scope_unavailable"
        settings = aggregation._locked_settings(st, candidate["tenant_id"], conn)
        job = st.one(
            "SELECT * FROM session_investigation_jobs WHERE id=$1 FOR UPDATE",
            candidate["id"],
            conn=conn,
        )
        attempt = aggregation._attempt(
            st, job["id"], _uuid(claim["claim_token"]), _uuid(claim["attempt_id"]), conn
        )
        now = st.scalar("SELECT clock_timestamp()", conn=conn)
        if not attempt:
            error = "claim_expired"
        elif not allow_expired and aggregation._expired(st, job, attempt, conn, now):
            error = "claim_expired"
        elif (
            job["state"] != "running"
            or job["claim_token"] != claim["claim_token"]
            or attempt["state"] not in ("reserved", "dispatched")
        ):
            error = "claim_expired"
        elif not allow_expired and now >= min(job["lease_deadline"], attempt["deadline_at"]):
            error = "claim_expired"
        elif (
            not settings["enabled"]
            or settings["detector_config_version"] != job["detector_config_version"]
        ):
            error = "settings_changed"
        if error is None:
            try:
                remaining = 5 if allow_expired else (
                    min(job["lease_deadline"], attempt["deadline_at"]) - now
                ).total_seconds()
                phase_deadline = time.monotonic() + remaining
                st.scalar(
                    "SELECT set_config('statement_timeout',$1,true)",
                    str(max(1, min(5000, int(remaining * 1000)))),
                    conn=conn,
                )
                # Roll back a phase that crosses the persisted deadline, then
                # commit its expiry separately under the retained job lock.
                with conn.transaction():
                    yield {
                        "conn": conn,
                        "job": job,
                        "attempt": attempt,
                        "settings": settings,
                        "registration": registration,
                        "now": now,
                        "sources": scoped,
                        "deadline": phase_deadline,
                    }
                    now = st.scalar("SELECT clock_timestamp()", conn=conn)
                    if not allow_expired and now >= min(job["lease_deadline"], attempt["deadline_at"]):
                        raise _FenceDeadline()
            except (_FenceDeadline, QueryCanceled):
                now = st.scalar("SELECT clock_timestamp()", conn=conn)
                if not allow_expired:
                    aggregation._expired(st, job, attempt, conn, now)
                error = ("claim_expired" if not allow_expired and
                         now >= min(job["lease_deadline"], attempt["deadline_at"]) else "internal_error")
    # Expiry transitions above must commit before returning a controlled error.
    if error:
        raise InvestigationStopped(error)


def _step(st, context, step_id):
    row = st.one(
        "SELECT * FROM session_investigation_steps WHERE id=$1 AND attempt_id=$2 FOR UPDATE",
        _uuid(step_id),
        context["attempt"]["id"],
        conn=context["conn"],
    )
    _need(row["state"] == "prepared", "request_replayed")
    return row


def _checkpoint(c):
    if time.monotonic() >= c["deadline"]:
        raise _FenceDeadline()


def _remaining(st, c):
    now = st.scalar("SELECT clock_timestamp()", conn=c["conn"])
    return max(
        0,
        (
            min(c["job"]["lease_deadline"], c["attempt"]["deadline_at"]) - now
        ).total_seconds(),
    )


def _snapshot_rows(st, context, after=0):
    job, conn = context["job"], context["conn"]
    metadata = st.many(
        """SELECT ordinal AS id,octet_length(to_jsonb(i)::text) AS byte_size
        FROM session_snapshot_items i WHERE snapshot_id=$1 AND ordinal>$2 ORDER BY ordinal LIMIT 250""",
        job["snapshot_id"],
        after,
        conn=conn,
    )
    keys = next(aggregation._page_groups(metadata), [])
    if not keys:
        return []
    return st.many(
        """SELECT ordinal,kind,source_id,body FROM session_snapshot_items
                   WHERE snapshot_id=$1 AND ordinal=ANY($2::bigint[]) ORDER BY ordinal""",
        job["snapshot_id"],
        keys,
        conn=conn,
    )


def _fragment(data, start, bound):
    text = data[start : start + bound].decode("utf-8", errors="ignore")
    _need(bool(text), "incomplete_coverage")
    return text, start + len(text.encode())


def _step_input(st, context, manifest):
    conn, snapshot_id = context["conn"], context["job"]["snapshot_id"]
    if "children" in manifest:
        rows = st.many(
            """SELECT id,result FROM session_investigation_steps WHERE attempt_id=$1
                          AND id=ANY($2::uuid[]) AND state='completed' ORDER BY ordinal""",
            context["attempt"]["id"],
            manifest["children"],
            conn=conn,
        )
        _need(len(rows) == len(manifest["children"]), "incomplete_coverage")
        return {"children": rows}
    result, cached = [], {}
    for part in manifest["fragments"]:
        _checkpoint(context)
        ordinal = part["ordinal"]
        if ordinal not in cached:
            row = st.one(
                "SELECT ordinal,kind,source_id,body FROM session_snapshot_items WHERE snapshot_id=$1 AND ordinal=$2",
                snapshot_id,
                ordinal,
                conn=conn,
            )
            cached[ordinal] = canonical_json(row)
        data = cached[ordinal]
        _need(
            len(data) == part["total_bytes"]
            and hashlib.sha256(data).hexdigest() == part["sha256"],
            "incomplete_coverage",
        )
        result.append({**part, "text": data[part["start"] : part["end"]].decode()})
    return {"fragments": result}


def _insert_step(st, context, kind, manifest, data):
    _checkpoint(context)
    ident, conn = new_id(), context["conn"]
    ordinal = st.scalar(
        "SELECT COALESCE(max(ordinal),0)+1 FROM session_investigation_steps WHERE attempt_id=$1",
        context["attempt"]["id"],
        conn=conn,
    )
    st.execute(
        """INSERT INTO session_investigation_steps(id,attempt_id,ordinal,kind,input_manifest,input_sha256,input_bytes)
                  VALUES($1,$2,$3,$4,$5,$6,$7)""",
        ident,
        context["attempt"]["id"],
        ordinal,
        kind,
        Jsonb(manifest),
        _digest(data),
        len(canonical_json(data)),
        conn=conn,
    )
    return ident


def prepare_attempt(
    st,
    claim,
    runtime_metadata,
    *,
    fragment_bytes=FRAGMENT_BYTES,
    chunk_bytes=CHUNK_BYTES,
):
    legacy = _legacy_runtime()
    PROMPT_VERSION, SUPPORTED_MODELS = legacy.PROMPT_VERSION, legacy.SUPPORTED_MODELS
    _need(
        type(fragment_bytes) is int
        and 4 <= fragment_bytes <= FRAGMENT_BYTES
        and type(chunk_bytes) is int
        and fragment_bytes <= chunk_bytes <= CHUNK_BYTES
    )
    _need(isinstance(runtime_metadata, dict))
    runtime = {
        key: runtime_metadata.get(key)
        for key in ("version", "executable_sha256", "platform", "protocol_version")
    }
    _need(
        isinstance(runtime["version"], str)
        and 0 < len(runtime["version"]) <= 128
        and isinstance(runtime["executable_sha256"], str)
        and re.fullmatch(r"[a-f0-9]{64}", runtime["executable_sha256"])
        and isinstance(runtime["platform"], str)
        and 0 < len(runtime["platform"]) <= 64
        and type(runtime["protocol_version"]) is int
        and runtime["protocol_version"] == 1
    )
    runtime["prompt_version"] = PROMPT_VERSION
    with _fence(st, claim) as c:
        _need(
            c["job"]["configuration"]["model"] in SUPPORTED_MODELS, "model_unavailable"
        )
        _need(c["attempt"]["runtime"] is None, "request_replayed")
        snapshot = st.one(
            """SELECT * FROM session_snapshots WHERE id=$1 AND tenant_id=$2
               AND owner_user_id IS NOT DISTINCT FROM $3::uuid AND sealed_at IS NOT NULL
               AND session_id IS NOT DISTINCT FROM $4::uuid""",
            c["job"]["snapshot_id"],
            c["job"]["tenant_id"],
            c["job"]["owner_user_id"],
            c["job"].get("session_id"),
            conn=c["conn"],
        )
        st.execute(
            "UPDATE session_investigation_attempts SET runtime=$2 WHERE id=$1",
            c["attempt"]["id"],
            Jsonb(runtime),
            conn=c["conn"],
        )
    after = count = total = chunks = 0
    parts, delivered, size = [], [], 0
    while True:
        with _fence(st, claim) as c:
            rows = _snapshot_rows(st, c, after)
            for row in rows:
                data = canonical_json(row)
                digest, start = hashlib.sha256(data).hexdigest(), 0
                while start < len(data):
                    _checkpoint(c)
                    text, end = _fragment(data, start, fragment_bytes)
                    part = {
                        "ordinal": row["ordinal"],
                        "source_id": row["source_id"],
                        "start": start,
                        "end": end,
                        "total_bytes": len(data),
                        "sha256": digest,
                    }
                    if parts and size + end - start > chunk_bytes:
                        _insert_step(
                            st,
                            c,
                            "chunk",
                            {"fragments": parts},
                            {"fragments": delivered},
                        )
                        chunks += 1
                        parts, delivered, size = [], [], 0
                    parts.append(part)
                    delivered.append({**part, "text": text})
                    size += end - start
                    start = end
                total += len(data)
                count += 1
                after = row["ordinal"]
            if not rows:
                if parts:
                    _insert_step(
                        st, c, "chunk", {"fragments": parts}, {"fragments": delivered}
                    )
                    chunks += 1
                _need(count == snapshot["item_count"], "incomplete_coverage")
                st.execute(
                    """UPDATE session_investigation_attempts SET plan_sealed_at=clock_timestamp(),
                               target_item_count=$2,target_byte_count=$3,target_chunk_count=$4 WHERE id=$1""",
                    c["attempt"]["id"],
                    count,
                    total,
                    chunks,
                    conn=c["conn"],
                )
                return {
                    "snapshot_id": snapshot["id"],
                    "target_item_count": count,
                    "target_byte_count": total,
                    "target_chunk_count": chunks,
                    "runtime": runtime,
                    "remaining_seconds": _remaining(st, c),
                }


def _frontier(st, c, limit=250):
    return st.many(
        """SELECT s.id,octet_length(jsonb_build_object('id',s.id,'result',s.result)::text) AS byte_size
           FROM session_investigation_steps s WHERE s.attempt_id=$1 AND NOT EXISTS(
             SELECT 1 FROM session_investigation_steps parent WHERE parent.attempt_id=s.attempt_id
               AND parent.input_manifest @> jsonb_build_object('children',jsonb_build_array(s.id::text)))
           ORDER BY s.ordinal LIMIT $2""",
        c["attempt"]["id"],
        limit,
        conn=c["conn"],
    )


def next_step(st, claim):
    with _fence(st, claim) as c:
        _need(c["attempt"]["plan_sealed_at"] is not None, "incomplete_coverage")
        _need(
            not st.scalar(
                "SELECT EXISTS(SELECT 1 FROM session_investigation_steps WHERE attempt_id=$1 AND state='failed')",
                c["attempt"]["id"],
                conn=c["conn"],
            ),
            "incomplete_coverage",
        )
        rows = st.many(
            "SELECT * FROM session_investigation_steps WHERE attempt_id=$1 AND state='prepared' ORDER BY ordinal LIMIT 1",
            c["attempt"]["id"],
            conn=c["conn"],
        )
        prepared = rows[0] if rows else None
        if prepared is None:
            frontier = _frontier(st, c)
            if len(frontier) <= 1:
                return None
            group, size = [], 0
            for row in frontier:
                extra = row["byte_size"]
                if group and size + extra > CHUNK_BYTES:
                    break
                group.append(row["id"])
                size += extra
            _need(len(group) >= 2, "incomplete_coverage")
            manifest = {"children": group}
            data = _step_input(st, c, manifest)
            ident = _insert_step(st, c, "reduce", manifest, data)
            prepared = _step(st, c, ident)
        data = _step_input(st, c, prepared["input_manifest"])
        _need(_digest(data) == prepared["input_sha256"], "incomplete_coverage")
        context = {
            "company_policies": _company_policies(st, c["job"], c["conn"]),
            "trigger": c["job"]["routing_reason"],
            "history_window": [value.isoformat() for value in detection_history.bounds(c["job"])]
                if c["job"].get("owner_user_id") else None,
            "evidence": data,
        }
        step = {
            "id": prepared["id"], "ordinal": prepared["ordinal"], "kind": prepared["kind"],
            "remaining_seconds": _remaining(st, c),
        }
        return {**step, "context": context, "history_allowed": bool(c["job"].get("owner_user_id"))}



def _quote(model, tokens):
    SUPPORTED_MODELS = _legacy_runtime().SUPPORTED_MODELS
    # Shared service accounting also prices Luna; investigator admission still
    # requires SUPPORTED_MODELS independently of the pricing helper.
    _need(model in SUPPORTED_MODELS or model == "gpt-6-luna", "model_unavailable")
    quote = {
        "version": 1,
        "date": "2026-10-02",
        "currency": "USD",
        "model": model,
        "service_tier": "default",
        "input_per_million": "2",
        "cached_input_per_million": "0.1",
        "cache_write_per_million": "2.5",
        "output_per_million": "10",
        "long_context": tokens > 272000,
        "long_context_threshold": 272000,
        "long_input_multiplier": "2",
        "long_output_multiplier": "1.5",
    }
    if model == "gpt-6-luna":
        # https://developers.openai.com/api/docs/models/gpt-6-luna, 2026-10-21.
        quote.update(date="2026-10-21", input_per_million="0.1",
                     cached_input_per_million="0.01", cache_write_per_million="0.125",
                     output_per_million="0.5")
    return quote


def _rates(quote, tokens):
    long = tokens > quote["long_context_threshold"]
    multiplier = Decimal(quote["long_input_multiplier"]) if long else Decimal(1)
    return tuple(
        Decimal(quote[key]) * multiplier / 1_000_000
        for key in (
            "input_per_million",
            "cached_input_per_million",
            "cache_write_per_million",
        )
    ) + (
        Decimal(quote["output_per_million"])
        * (Decimal(quote["long_output_multiplier"]) if long else Decimal(1))
        / 1_000_000,
    )


def admit_call(st, claim, step_id, proposal, *, conn=None):
    legacy = _legacy_runtime()
    SUPPORTED_MODELS, MAX_OUTPUT_TOKENS = legacy.SUPPORTED_MODELS, legacy.MAX_OUTPUT_TOKENS
    MODEL_MAX_OUTPUT_TOKENS, MODEL_CONTEXT_TOKENS = legacy.MODEL_MAX_OUTPUT_TOKENS, legacy.MODEL_CONTEXT_TOKENS
    _need(
        isinstance(proposal, dict)
        and set(proposal)
        == {"request_id", "request", "input_tokens", "requested_output_tokens"}
    )
    request_id, request = (
        _uuid(proposal["request_id"]),
        copy.deepcopy(proposal["request"]),
    )
    counted, requested = proposal["input_tokens"], proposal["requested_output_tokens"]
    _need(
        type(counted) is int
        and 0 <= counted <= MAX_INTEGER
        and type(requested) is int
        and 0 < requested <= MAX_OUTPUT_TOKENS
    )
    _need(isinstance(request, dict) and len(canonical_json(request)) <= 8 << 20)
    _need(
        set(request)
        <= {
            "model",
            "service_tier",
            "store",
            "truncation",
            "input",
            "instructions",
            "tools",
            "text",
            "stream",
            "reasoning",
            "include",
            "tool_choice",
            "parallel_tool_calls",
        }
    )
    _need(
        request.get("service_tier") == "default"
        and request.get("store") is False
        and request.get("truncation") == "disabled"
        and request.get("stream") is True
    )
    input_hash = _digest(request)
    with _fence(st, claim, conn=conn) as c:
        step = _step(st, c, step_id)
        if not c["job"].get("owner_user_id"):
            _need(not request.get("tools"), "invalid_request")
        _need(c["attempt"]["plan_sealed_at"] is not None, "incomplete_coverage")
        model = c["job"]["configuration"]["model"]
        _need(
            request.get("model") == model and model in SUPPORTED_MODELS,
            "model_unavailable",
        )
        duplicate = st.scalar(
            """SELECT EXISTS(SELECT 1 FROM session_investigation_requests
            WHERE id=$1 OR (step_id=$2 AND input_sha256=$3))""",
            request_id,
            step["id"],
            input_hash,
            conn=c["conn"],
        )
        _need(not duplicate, "request_replayed")
        previous = _accounting(st, c["attempt"]["id"], c["conn"])
        _need(previous["sound"], "usage_unknown")
        config = c["job"]["configuration"]
        spent_tokens, spent_cost = int(previous["tokens"]), previous["cost"]
        quote = _quote(model, counted)
        rates = _rates(quote, counted)
        input_cost = counted * max(rates[:3])
        available_cost = (
            Decimal(config["max_cost_usd_per_attempt"]) - spent_cost - input_cost
        )
        output = min(
            requested,
            MODEL_MAX_OUTPUT_TOKENS,
            MODEL_CONTEXT_TOKENS - counted,
            config["max_tokens_per_attempt"] - spent_tokens - counted,
            int((available_cost / rates[3]).to_integral_value(rounding=ROUND_DOWN)),
        )
        _need(
            output > 0 and previous["calls"] < config["max_tokens_per_attempt"],
            "budget_exhausted",
        )
        if c["attempt"]["state"] == "reserved":
            _need(
                aggregation._job_current(st, c["job"], c["settings"], c["conn"])
                and aggregation._threshold_matches(
                    st, c["job"], c["settings"], c["conn"]
                ),
                "settings_changed",
            )
            _need(
                aggregation._dispatch_attempt(st, c["attempt"], c["conn"], c["now"]),
                "claim_expired",
            )
        request["max_output_tokens"] = output
        request_hash, usage_id = _digest(request), new_id()
        st.execute(
            """INSERT INTO session_investigation_requests(id,attempt_id,step_id,ordinal,input_sha256,request_sha256,
                       input_tokens_counted,max_output_tokens,reserved_tokens,reserved_cost_usd,price_quote,usage_id)
                      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)""",
            request_id,
            c["attempt"]["id"],
            step["id"],
            previous["calls"] + 1,
            input_hash,
            request_hash,
            counted,
            output,
            counted + output,
            input_cost + output * rates[3],
            Jsonb(quote),
            usage_id,
            conn=c["conn"],
        )
        st.execute(
            """INSERT INTO model_usage(id,tenant_id,sensor_id,event_id,attempt,purpose,provider,model,
                       investigation_job_id,investigation_attempt_id,investigation_request_id,price_quote,
                       input_rate_usd,output_rate_usd,price_date)
                      VALUES($1,$2,$3,NULL,$4,'detection','openai',$5,$6,$7,$8,$9,$10,$11,$12)""",
            usage_id,
            c["job"]["tenant_id"],
            c["job"]["sensor_id"],
            previous["calls"] + 1,
            model,
            c["job"]["id"],
            c["attempt"]["id"],
            request_id,
            Jsonb(quote),
            rates[0] * 1_000_000,
            rates[3] * 1_000_000,
            quote["date"],
            conn=c["conn"],
        )
        return {
            "request_id": request_id,
            "max_output_tokens": output,
            "request_sha256": request_hash,
            "price_quote": quote,
            "remaining_seconds": _remaining(st, c),
        }


def _accounting(st, attempt_id, conn, step_id=None):
    return st.one(
        """SELECT count(*) AS calls,
        COALESCE(bool_and(COALESCE(r.state='completed' AND u.cost_usd IS NOT NULL
          AND u.input_tokens<=r.input_tokens_counted AND u.output_tokens<=r.max_output_tokens
          AND u.cost_usd<=r.reserved_cost_usd,false)),true) AS sound,
        CASE WHEN count(u.input_tokens+u.output_tokens)=count(*) THEN COALESCE(sum(u.input_tokens+u.output_tokens),0) END AS tokens,
        CASE WHEN count(u.cost_usd)=count(*) THEN COALESCE(sum(u.cost_usd),0) END AS cost
        FROM session_investigation_requests r JOIN model_usage u ON u.id=r.usage_id
        WHERE r.attempt_id=$1 AND ($2::uuid IS NULL OR r.step_id=$2)""",
        attempt_id,
        step_id,
        conn=conn,
    )


def _totals(st, attempt_id, conn):
    totals = _accounting(st, attempt_id, conn)
    return int(totals["tokens"]) if totals["tokens"] is not None else None, totals[
        "cost"
    ]


def _save_totals(st, attempt_id, conn):
    tokens, cost = _totals(st, attempt_id, conn)
    st.execute(
        """UPDATE session_investigation_attempts SET actual_tokens=COALESCE(actual_tokens,$2),
                  actual_cost_usd=COALESCE(actual_cost_usd,$3) WHERE id=$1""",
        attempt_id,
        tokens,
        cost,
        conn=conn,
    )
    return {
        "actual_tokens": tokens,
        "actual_cost_usd": str(cost) if cost is not None else None,
    }


def finish_call(st, claim, step_id, receipt, *, conn=None):
    """Reconcile this dispatch even after revocation; the bool only permits continuation."""
    legacy = _legacy_runtime()
    _receipt, _USAGE_COUNTS = legacy._receipt, legacy._USAGE_COUNTS
    try:
        receipt = _receipt(receipt)
    except InvestigationStopped:
        return False
    current = False
    supplied_conn = conn
    with st.transaction() if conn is None else nullcontext(conn) as conn:
        rows = st.many(
            "SELECT * FROM session_investigation_jobs WHERE id=$1 FOR UPDATE",
            _uuid(claim["job_id"]),
            conn=conn,
        )
        if not rows:
            return False
        job = rows[0]
        attempt = aggregation._attempt(
            st, job["id"], _uuid(claim["claim_token"]), _uuid(claim["attempt_id"]), conn
        )
        if not attempt:
            return False
        rows = st.many(
            """SELECT * FROM session_investigation_requests WHERE id=$1 AND attempt_id=$2 AND step_id=$3 FOR UPDATE""",
            receipt["request_id"],
            attempt["id"],
            _uuid(step_id),
            conn=conn,
        )
        if not rows:
            return False
        request = rows[0]
        old = st.one(
            "SELECT * FROM model_usage WHERE id=$1 FOR UPDATE",
            request["usage_id"],
            conn=conn,
        )
        incoming = receipt["usage"]
        mapping = {
            **{key: key for key in _USAGE_COUNTS},
            "model": "reported_model",
            "service_tier": "service_tier",
        }
        if any(
            old[column] is not None
            and incoming.get(key) is not None
            and old[column] != incoming[key]
            for key, column in mapping.items()
        ):
            return False
        if (
            request["provider_response_id"] is not None
            and incoming.get("response_id") is not None
            and request["provider_response_id"] != incoming["response_id"]
        ):
            return False
        merged = {
            key: old[column] if old[column] is not None else incoming.get(key)
            for key, column in mapping.items()
        }
        cost = None
        if (
            merged["model"] == request["price_quote"]["model"]
            and merged["service_tier"] == "default"
            and all(merged[key] is not None for key in _USAGE_COUNTS[:4])
        ):
            ordinary, cached, write, output = _rates(
                request["price_quote"], merged["input_tokens"]
            )
            if (
                merged["cached_input_tokens"] + merged["cache_write_input_tokens"]
                > merged["input_tokens"]
            ):
                return False
            cost = (
                (
                    merged["input_tokens"]
                    - merged["cached_input_tokens"]
                    - merged["cache_write_input_tokens"]
                )
                * ordinary
                + merged["cached_input_tokens"] * cached
                + merged["cache_write_input_tokens"] * write
                + merged["output_tokens"] * output
            )
        if (
            merged["reasoning_output_tokens"] is not None
            and merged["output_tokens"] is not None
            and merged["reasoning_output_tokens"] > merged["output_tokens"]
        ):
            return False
        if old["cost_usd"] is not None and cost is not None and old["cost_usd"] != cost:
            return False
        now = st.scalar("SELECT clock_timestamp()", conn=conn)
        aggregation._expired(st, job, attempt, conn, now)
        request = st.one(
            "SELECT * FROM session_investigation_requests WHERE id=$1",
            request["id"],
            conn=conn,
        )
        # Only a pending call can acquire a terminal status. Late metadata never
        # converts an uncertain/error transport into successful execution.
        state = (
            receipt["status"] if request["state"] == "dispatched" else request["state"]
        )
        st.execute(
            """UPDATE session_investigation_requests SET state=$2,error_code=$3,completed_at=COALESCE(completed_at,$4),
                      provider_response_id=COALESCE(provider_response_id,$5) WHERE id=$1""",
            request["id"],
            state,
            receipt["error_code"]
            if request["state"] == "dispatched"
            else request["error_code"],
            now,
            incoming.get("response_id"),
            conn=conn,
        )
        st.execute(
            """UPDATE model_usage SET status=$2,completed_at=COALESCE(completed_at,$3),
                      input_tokens=$4,output_tokens=$5,cached_input_tokens=$6,cache_write_input_tokens=$7,
                      reasoning_output_tokens=$8,reported_model=$9,service_tier=$10,cost_usd=COALESCE(cost_usd,$11) WHERE id=$1""",
            old["id"],
            "completed" if state == "completed" else "error",
            now,
            *(merged[key] for key in _USAGE_COUNTS),
            merged["model"],
            merged["service_tier"],
            cost,
            conn=conn,
        )
        active = st.scalar(
            "SELECT state IN ('reserved','dispatched') FROM session_investigation_attempts WHERE id=$1",
            attempt["id"],
            conn=conn,
        )
        if not active:
            _save_totals(st, attempt["id"], conn)
        current = bool(
            active
            and state == "completed"
            and receipt["status"] == "completed"
            and cost is not None
            and merged["input_tokens"] <= request["input_tokens_counted"]
            and merged["output_tokens"] <= request["max_output_tokens"]
            and cost <= request["reserved_cost_usd"]
        )
    if not current:
        return False
    try:
        with _fence(st, claim, conn=supplied_conn) as c:
            _step(st, c, step_id)
            return True
    except InvestigationStopped:
        return False


def _position(st, c, arguments, name):
    cursor = arguments.get("cursor", "")
    if not cursor:
        return None
    rows = st.many(
        """SELECT * FROM session_investigation_reads WHERE id=$1 AND attempt_id=$2 AND tool_name=$3
                      AND status='delivered'""",
        _uuid(cursor),
        c["attempt"]["id"],
        name,
        conn=c["conn"],
    )
    if not rows:
        return False
    row = rows[0]
    old = {key: value for key, value in row["arguments"].items() if key != "cursor"}
    new = {key: value for key, value in arguments.items() if key != "cursor"}
    return (
        row["next_position"]
        if old == redact_value(new) and row["next_position"] is not None
        else False
    )


def _search(st, c, arguments, position):
    start, end = detection_history.bounds(c["job"])
    for key in ("since", "until"):
        if arguments.get(key):
            try:
                parsed = datetime.fromisoformat(arguments[key].replace("Z", "+00:00"))
                _need(parsed.tzinfo is not None)
            except ValueError:
                raise InvestigationStopped("invalid_request") from None
            if key == "since":
                start = max(start, parsed)
            else:
                end = min(end, parsed)
    rows = st.many(
        """SELECT s.id,s.registration_id,s.product,s.started_at,
             LEAST(s.last_event_at,$9) AS last_event_at,
             CASE WHEN s.ended_at<=$9 THEN s.ended_at END AS ended_at,
             (SELECT snap.id FROM session_snapshots snap
               WHERE (snap.registration_id=r.registration_id OR snap.session_id=s.id)
                 AND snap.tenant_id=r.tenant_id AND snap.owner_user_id=r.owner_user_id
                 AND snap.sealed_at<=$9
               ORDER BY snap.revision DESC LIMIT 1) AS snapshot_id
           FROM agent_sessions s
           JOIN detection_session_identities r ON r.session_id=s.id AND r.tenant_id=s.tenant_id
           JOIN tenants t ON t.id=s.tenant_id AND t.status='active'
           JOIN sensors sensor ON sensor.id=s.sensor_id AND sensor.tenant_id=s.tenant_id
             AND NOT sensor.disabled AND sensor.deleted_at IS NULL
           JOIN tenant_users u ON u.id=r.owner_user_id AND u.tenant_id=r.tenant_id AND u.status='active'
           WHERE s.tenant_id=$1 AND r.owner_user_id=$2
             AND ($3::text IS NULL OR s.product=$3)
             AND s.last_event_at>=$4 AND s.started_at<=$5
             AND ($6::timestamptz IS NULL OR (s.started_at,s.id)>($6::timestamptz,$7::uuid))
           ORDER BY s.started_at,s.id LIMIT $8""",
        c["job"]["tenant_id"], c["job"]["owner_user_id"], arguments.get("product") or None,
        start, end, position.get("time") if position else None,
        position.get("id") if position else None, arguments.get("limit", 20) + 1,
        c["job"]["created_at"], conn=c["conn"],
    )
    limit = arguments.get("limit", 20)
    more, rows = len(rows) > limit, rows[:limit]
    next_position = {"time": rows[-1]["started_at"].isoformat(), "id": rows[-1]["id"]} if more else None
    return {"sessions": [public_record(row, "session") for row in rows]}, next_position


def _read_page(st, c, source, arguments, position):
    snapshot_id = arguments.get("snapshot_id")
    if snapshot_id:
        snapshots = st.many(
            """SELECT snap.* FROM session_snapshots snap
            JOIN detection_session_identities r ON r.tenant_id=snap.tenant_id
              AND (r.registration_id=snap.registration_id OR r.session_id=snap.session_id)
            WHERE snap.id=$1 AND r.session_id=$2 AND snap.tenant_id=$3 AND snap.owner_user_id=$4
              AND r.owner_user_id=$4 AND snap.sealed_at<=$5""",
            snapshot_id, source["id"], c["job"]["tenant_id"], c["job"]["owner_user_id"],
            c["job"]["created_at"],
            conn=c["conn"],
        )
        if not snapshots:
            return None, None
        snapshot = snapshots[0]
        ordinal = position.get("ordinal", 1) if position else 1
        rows = st.many(
            """SELECT i.ordinal,i.kind,i.source_id,i.body FROM session_snapshot_items i
            JOIN session_snapshots snap ON snap.id=i.snapshot_id
            JOIN detection_session_identities r ON r.tenant_id=snap.tenant_id
              AND (r.registration_id=snap.registration_id OR r.session_id=snap.session_id)
            WHERE i.snapshot_id=$1 AND i.ordinal=$2 AND snap.tenant_id=$3 AND r.owner_user_id=$4
              AND snap.owner_user_id=$4 AND r.verified_at IS NOT NULL""",
            snapshot_id,
            ordinal,
            c["job"]["tenant_id"],
            c["job"]["owner_user_id"],
            conn=c["conn"],
        )
        item = rows[0] if rows else None
        following = (
            {"ordinal": ordinal + 1}
            if item and ordinal < snapshot["item_count"]
            else None
        )
        coverage = copy.deepcopy(snapshot["coverage"])
        coverage["scope"] = "returned_page"
    else:
        # This remains a live stream. An immutable receipt retains each delivered
        # fragment; a cursor never promises a snapshot of future observations.
        partial_id = position.get("partial_id") if position else None
        after = position.get("after") if position else None
        rows = st.many(
            """SELECT e.id,e.kind,e.body,e.evidence_stream,e.evidence_sequence,e.evidence_part,e.time
            FROM events e JOIN agent_sessions s ON s.id=e.session_id AND s.tenant_id=e.tenant_id
            JOIN detection_session_identities r ON r.session_id=s.id AND r.tenant_id=s.tenant_id
            WHERE e.tenant_id=$1 AND e.session_id=$2 AND r.owner_user_id=$3 AND r.verified_at IS NOT NULL
              AND e.time>=$10 AND e.time<=$11 AND e.received_at<=$11
              AND ($4::uuid IS NULL OR e.id=$4)
              AND ($5::text IS NULL OR (e.evidence_stream COLLATE "C",e.evidence_sequence,e.evidence_part,e.time,e.id)
                   >($5 COLLATE "C",$6::bigint,$7::bigint,$8::timestamptz,$9::uuid))
            ORDER BY e.evidence_stream COLLATE "C",e.evidence_sequence,e.evidence_part,e.time,e.id LIMIT 1""",
            c["job"]["tenant_id"],
            source["id"],
            c["job"]["owner_user_id"],
            partial_id,
            *(after if after else (None,) * 5),
            *detection_history.bounds(c["job"]),
            conn=c["conn"],
        )
        row = rows[0] if rows else None
        ordinal = position.get("ordinal", 1) if position else 1
        item = (
            {
                "ordinal": ordinal,
                "kind": "observation",
                "source_id": row["id"],
                "body": aggregation._capture(row["body"]),
            }
            if row
            else None
        )
        following = (
            {
                "ordinal": ordinal + 1,
                "after": [
                    row["evidence_stream"],
                    row["evidence_sequence"],
                    row["evidence_part"],
                    row["time"].isoformat(),
                    row["id"],
                ],
            }
            if row
            else None
        )
        gaps = item["body"].get("evidence", {}).get("gaps", []) if item else []
        coverage = {
            "scope": "returned_page",
            "status": "unknown",
            "gaps": gaps if isinstance(gaps, list) else [],
        }
    if item is None:
        if position and position.get("offset"):
            return None, None
        return {
            "session_id": source["id"],
            "version": {
                "kind": "snapshot" if snapshot_id else "live",
                "snapshot_id": snapshot_id,
                "observed_at": c["now"].isoformat(),
            },
            "items": [],
            "coverage": coverage,
        }, None
    raw = canonical_json(item)
    digest = hashlib.sha256(raw).hexdigest()
    offset = position.get("offset", 0) if position else 0
    if (
        position
        and position.get("sha256")
        and (position["sha256"] != digest or offset >= len(raw))
    ):
        return None, None
    text, end = _fragment(raw, offset, READ_BYTES // 4)
    result = {
        "session_id": source["id"],
        "version": {
            "kind": "snapshot" if snapshot_id else "live",
            "snapshot_id": snapshot_id,
            "observed_at": c["now"].isoformat(),
        },
        "items": [
            {
                "source_id": item["source_id"],
                "ordinal": item["ordinal"],
                "start": offset,
                "end": end,
                "total_bytes": len(raw),
                "text": text,
            }
        ],
        "coverage": coverage,
    }
    while len(canonical_json(result)) > READ_BYTES - 150:
        text, end = _fragment(raw, offset, max(4, len(text.encode()) // 2))
        result["items"][0].update(text=text, end=end)
    if end < len(raw):
        following = {
            **(position or {}),
            "ordinal": ordinal,
            "offset": end,
            "sha256": digest,
        }
        if not snapshot_id:
            following["partial_id"] = item["source_id"]
    return result, following


def _read_sources(session_id, sessions):
    return ({session_id} if session_id else set()) | {
        session["id"] for session in sessions or ()
    }


def read_tool(st, claim, step_id, call_id, name, arguments, *, conn=None):
    _need(
        valid_read_arguments(name, arguments)
        and len(canonical_json(arguments)) <= 4096
    )
    _need(isinstance(call_id, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", call_id))
    sources = {arguments["session_id"]} if name == "read_session" else set()
    # Search receipts represent several sources. Collect their identities before
    # the job lock so every replay uses the same authority lock order as reads.
    for prior in st.many(
        """SELECT session_id,response->'sessions' AS sessions FROM session_investigation_reads
           WHERE attempt_id=$1 AND step_id=$2 AND tool_call_id=$3 AND status='delivered'""",
        _uuid(claim["attempt_id"]),
        _uuid(step_id),
        call_id,
        conn=conn,
    ):
        sources.update(_read_sources(prior["session_id"], prior["sessions"]))
    with _fence(st, claim, sources=sources, conn=conn) as c:
        step = _step(st, c, step_id)
        if not c["job"].get("owner_user_id"):
            return {"error": {"code": "record_unavailable"}}
        prior = st.many(
            "SELECT * FROM session_investigation_reads WHERE step_id=$1 AND tool_call_id=$2",
            step["id"],
            call_id,
            conn=c["conn"],
        )
        safe_arguments = redact_value(arguments)
        if prior:
            _need(
                prior[0]["tool_name"] == name
                and prior[0]["arguments"] == safe_arguments,
                "request_replayed",
            )
            represented = _read_sources(
                prior[0]["session_id"], prior[0]["response"].get("sessions")
            )
            # A receipt committed while the fence waited must also be covered
            # by its pre-lock guards. Never return unguarded immutable metadata.
            if any(not c["sources"].get(ident) for ident in represented):
                return {"error": {"code": "record_unavailable"}}
            return prior[0]["response"]
        position = _position(st, c, arguments, name)
        source = c["sources"].get(arguments.get("session_id"))
        result, following = None, None
        if position is not False:
            if name == "search_sessions":
                result, following = _search(st, c, arguments, position)
            elif source:
                result, following = _read_page(st, c, source, arguments, position)
        ident = new_id()
        if result is not None:
            result.update(read_id=ident, next_cursor=ident if following else "")
            _need(len(canonical_json(result)) <= READ_BYTES, "invalid_result")
        else:
            result = {"error": {"code": "record_unavailable"}}
        st.execute(
            """INSERT INTO session_investigation_reads(id,attempt_id,step_id,tool_call_id,tool_name,arguments,status,
                      session_id,source_registration_id,source_sensor_id,source_snapshot_id,response,response_sha256,next_position)
                      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)""",
            ident,
            c["attempt"]["id"],
            step["id"],
            call_id,
            name,
            Jsonb(safe_arguments),
            "denied" if "error" in result else "delivered",
            source["id"] if source else None,
            source["registration_id"] if source else None,
            source["sensor_id"] if source else None,
            arguments.get("snapshot_id") if source else None,
            Jsonb(result),
            _digest(result),
            Jsonb(following) if following else None,
            conn=c["conn"],
        )
        return result


def _allowed_target(manifest, ref):
    ranges = sorted(
        (part["start"], part["end"])
        for part in manifest.get("fragments", [])
        if part["ordinal"] == ref["ordinal"]
    )
    reached = ref["start"]
    for start, end in ranges:
        if start <= reached < end:
            reached = end
    return ref["start"] < ref["end"] <= reached


def _action_facts(st, c, logical_id):
    snapshot_id = c["job"]["snapshot_id"]
    assessments = st.many(
        """SELECT source_id FROM session_snapshot_items WHERE snapshot_id=$1 AND kind='assessment'
                            AND body->>'logical_id'=$2""",
        snapshot_id,
        logical_id,
        conn=c["conn"],
    )
    assessment_ids = [row["source_id"] for row in assessments]
    observations = st.many(
        """SELECT body->'managed_outcome' AS outcome FROM session_snapshot_items
                             WHERE snapshot_id=$1 AND kind='observation' AND body->'managed_outcome'->>'logical_id'=$2""",
        snapshot_id,
        logical_id,
        conn=c["conn"],
    )
    approvals = st.many(
        """SELECT body->>'status' AS status,body->>'decision' AS decision FROM session_snapshot_items
                          WHERE snapshot_id=$1 AND kind='approval' AND body->>'guardrail_event_id'=ANY($2::text[])
                          ORDER BY (body->>'generation')::bigint DESC""",
        snapshot_id,
        assessment_ids,
        conn=c["conn"],
    )
    releases = st.many(
        """SELECT body->>'outcome' AS outcome FROM session_snapshot_items
                         WHERE snapshot_id=$1 AND kind='release' AND body->>'guardrail_event_id'=ANY($2::text[])""",
        snapshot_id,
        assessment_ids,
        conn=c["conn"],
    )
    target_exists = bool(assessments) or st.scalar(
        """SELECT EXISTS(SELECT 1 FROM session_snapshot_items
        WHERE snapshot_id=$1 AND kind='observation' AND body->'evidence'->>'logical_id'=$2)""",
        snapshot_id,
        logical_id,
        conn=c["conn"],
    )
    _need(target_exists, "invalid_result")
    outcomes = {
        row["outcome"]["outcome"]
        for row in observations
        if isinstance(row["outcome"], dict)
        and row["outcome"].get("outcome")
        in ("not_executed", "succeeded", "failed", "uncertain")
    }
    outcomes.update(row["outcome"] or "uncertain" for row in releases)
    # Contradictory observations stay uncertain; a release by itself does not
    # establish that a native action succeeded.
    execution = next(iter(outcomes)) if len(outcomes) == 1 else "uncertain"
    authorization = "not_recorded"
    if approvals:
        latest = approvals[0]
        if latest["status"] == "revoked":
            authorization = "revoked"
        elif latest["decision"] == "reject":
            authorization = "rejected"
        elif latest["decision"] == "approve":
            authorization = "approved"
    return {
        "logical_id": logical_id,
        "execution": execution,
        "authorization": authorization,
    }


def _company_policies(st, job, conn):
    policies = {}
    for row in st.many(
        """SELECT COALESCE(body->'company_policy',body->'risk'->'company_policy') AS policy,
           array_agg(ordinal ORDER BY ordinal) AS ordinals
           FROM session_snapshot_items WHERE snapshot_id=$1
             AND kind IN ('assessment','event_assessment') GROUP BY policy ORDER BY min(ordinal)""",
        job["snapshot_id"], conn=conn,
    ):
        policy = row["policy"]
        if not (isinstance(policy, dict) and type(policy.get("revision")) is int
                and policy["revision"] > 0 and isinstance(policy.get("prompt"), str)
                and policy["prompt"].strip()):
            continue
        key = (policy["revision"], policy["prompt"])
        record = policies.setdefault(key, {
            "revision": policy["revision"], "prompt": policy["prompt"],
            "source": "captured", "snapshot_ordinals": [],
        })
        record["snapshot_ordinals"].extend(row["ordinals"])
    return list(policies.values())


def _result_references(result):
    return [ref for section in [result, *result["findings"]] for ref in section["evidence"]]


def _validate_result(st, c, step, result, *, submitted=None):
    _need(
        valid_result(result) and len(canonical_json(result)) <= RESULT_BYTES,
        "invalid_result",
    )
    findings = result["findings"]
    _need((result["status"] == "finding") == bool(findings), "invalid_result")
    _need(result["verdict"] in {
        "finding": ("true_positive",),
        "no_finding": ("false_positive", "true_positive_non_malicious"),
        "inconclusive": (None,),
    }[result["status"]], "invalid_result")
    if result["verdict"] == "true_positive_non_malicious":
        _need(result["authorization"]["evidence_indices"] and any(
            ref["source"] == "target" for ref in result["evidence"]
        ), "invalid_result")
    references = _result_references(result)
    _need(
        len(references) <= 200
        and sum(len(item["action_outcomes"]) for item in findings) <= 100,
        "invalid_result",
    )
    inherited = set()
    if submitted is None and step["kind"] == "reduce":
        children = _step_input(st, c, step["input_manifest"])["children"]
        # A worker upgrade cannot silently reinterpret already-produced output.
        _need(all(valid_result(child["result"]) for child in children), "invalid_result")
        inherited = {_digest(ref) for child in children
                     for ref in _result_references(child["result"])}
    policies = _company_policies(st, c["job"], c["conn"])
    for section in [result, *findings]:
        _checkpoint(c)
        auth = section["authorization"]
        indices = [index for entry in section["timeline"] for index in entry["evidence_indices"]]
        _need(all(index < len(section["evidence"]) for index in [*indices, *auth["evidence_indices"]]),
              "invalid_result")
        if auth["policy_quote"] or auth["policy_revision"]:
            _need(auth["policy_quote"].strip() and any(
                policy["revision"] == auth["policy_revision"]
                and auth["policy_quote"] in policy["prompt"] for policy in policies
            ), "invalid_result")
        if section.get("category") == "acceptable_use" or "acceptable_use" in section.get("tags", []):
            _need(auth["policy_basis"].strip() and auth["policy_quote"].strip()
                  and auth["policy_revision"] > 0 and auth["evidence_indices"], "invalid_result")
            applicable_ordinals = {ordinal for policy in policies
                                   if policy["revision"] == auth["policy_revision"]
                                   and auth["policy_quote"] in policy["prompt"]
                                   for ordinal in policy["snapshot_ordinals"]}
            _need(any(section["evidence"][index]["source"] == "target"
                      and section["evidence"][index]["ordinal"] in applicable_ordinals
                      for index in auth["evidence_indices"]), "invalid_result")
        if "category" in section:
            _need(any(ref["source"] == "target" for ref in section["evidence"]), "invalid_result")
            _need(len(set(section["tags"])) == len(section["tags"])
                  and section["category"] not in section["tags"], "invalid_result")
    for ref in references:
        _checkpoint(c)
        if _digest(ref) in inherited:
            continue
        if submitted is not None:
            _need(c["job"].get("protocol_version") == 4, "invalid_request")
            if ref["source"] == "target":
                items = submitted["target"]["items"]
                _need(1 <= ref["ordinal"] <= len(items) and 0 <= ref["start"] < ref["end"]
                      <= len(canonical_json(items[ref["ordinal"] - 1])), "invalid_result")
            else:
                rows = st.many("""SELECT response FROM session_investigation_reads
                    WHERE id=$1 AND attempt_id=$2 AND submission_id=$2 AND status='delivered'""",
                    ref["read_id"], c["attempt"]["id"], conn=c["conn"])
                _need(rows and ref["item"] < len(rows[0]["response"]["items"]), "invalid_result")
        elif ref["source"] == "target":
            _need(step["kind"] == "chunk" and _allowed_target(step["input_manifest"], ref),
                  "invalid_result")
        else:
            rows = st.many(
                """SELECT response FROM session_investigation_reads WHERE id=$1 AND attempt_id=$2
                   AND step_id=$3 AND status='delivered' AND tool_name='read_session'""",
                ref["read_id"], c["attempt"]["id"], step["id"], conn=c["conn"],
            )
            _need(rows and ref["item"] < len(rows[0]["response"].get("items", [])), "invalid_result")
    for finding in findings:
        for outcome in finding["action_outcomes"]:
            _checkpoint(c)
            fact = _action_facts(st, c, outcome["logical_id"])
            _need(outcome["authorization"] == fact["authorization"] and (
                outcome["execution"] == "attempted" or outcome["execution"] == fact["execution"]
            ), "invalid_result")
    safe = copy.deepcopy(result)
    # Redact prose, preserving typed authorization enums and citation structure.
    # The generic redactor treats an authorization object as an HTTP credential.
    for section in [safe, *safe["findings"]]:
        for key in ("title", "conclusion", "summary", "explanation", "severity_rationale",
                    "impact", "recommended_actions", "recommendations", "uncertainties",
                    "alternative_explanations", "limitations"):
            if key in section:
                section[key] = redact_value(section[key])
        section["authorization"] = redact_value(section["authorization"])
        for entry in section["timeline"]:
            entry["description"] = redact_value(entry["description"])
    return safe


def complete_step(st, claim, step_id, structured_text, *, conn=None):
    _need(
        isinstance(structured_text, str)
        and len(structured_text.encode()) <= RESULT_BYTES,
        "invalid_result",
    )
    try:
        result = json.loads(structured_text)
    except (ValueError, RecursionError):
        raise InvestigationStopped("invalid_result") from None
    with _fence(st, claim, conn=conn) as c:
        step = _step(st, c, step_id)
        requests = _accounting(st, c["attempt"]["id"], c["conn"], step["id"])
        _need(requests["calls"] and requests["sound"], "usage_unknown")
        safe = _validate_result(st, c, step, result)
        st.execute(
            "UPDATE session_investigation_steps SET state='completed',result=$2,completed_at=clock_timestamp() WHERE id=$1",
            step["id"],
            Jsonb(safe),
            conn=c["conn"],
        )
        return safe


def _coverage(st, c):
    attempt_id, conn = c["attempt"]["id"], c["conn"]
    # Validate contiguous UTF-8 ranges in PostgreSQL without transferring all
    # manifests or all completed results into the worker at once.
    spans = st.one(
        """WITH fragments AS (
        SELECT s.ordinal AS step,n,(part->>'ordinal')::bigint AS item,
          (part->>'start')::bigint AS start_byte,(part->>'end')::bigint AS end_byte,
          (part->>'total_bytes')::bigint AS bytes,part->>'sha256' AS digest
        FROM session_investigation_steps s,
          jsonb_array_elements(s.input_manifest->'fragments') WITH ORDINALITY AS input(part,n)
        WHERE s.attempt_id=$1 AND s.kind='chunk'
      ), positioned AS (
        SELECT *,lag(end_byte,1,0::bigint) OVER(PARTITION BY item ORDER BY step,n) AS previous_end
        FROM fragments
      ), items AS (
        SELECT item,bool_and(start_byte=previous_end AND end_byte>start_byte) AS contiguous,
          max(end_byte)=min(bytes) AND min(bytes)=max(bytes) AND min(digest)=max(digest) AS complete,
          sum(end_byte-start_byte) AS bytes FROM positioned GROUP BY item
      ) SELECT count(*) AS items,COALESCE(sum(bytes),0) AS bytes,
          COALESCE(bool_and(contiguous AND complete),false) AS complete FROM items""",
        attempt_id,
        conn=conn,
    )
    totals = st.one(
        """SELECT count(*) AS steps,count(*) FILTER(WHERE state='completed') AS completed_steps,
        count(*) FILTER(WHERE kind='chunk') AS chunks,
        count(*) FILTER(WHERE kind='chunk' AND state='completed') AS completed_chunks,
        count(*) FILTER(WHERE result->>'status'='inconclusive') AS inconclusive_steps
        FROM session_investigation_steps WHERE attempt_id=$1""",
        attempt_id,
        conn=conn,
    )
    repeated = st.scalar(
        """SELECT count(*)<>count(DISTINCT child) FROM session_investigation_steps s,
        jsonb_array_elements_text(s.input_manifest->'children') AS input(child) WHERE s.attempt_id=$1""",
        attempt_id,
        conn=conn,
    )
    gaps = [
        row["gap"]
        for row in st.many(
            """SELECT DISTINCT gap FROM session_investigation_steps s,
        jsonb_array_elements_text(s.result->'gaps') AS input(gap) WHERE s.attempt_id=$1 ORDER BY gap""",
            attempt_id,
            conn=conn,
        )
    ]
    frontier = _frontier(st, c, 2)
    complete = bool(
        c["attempt"]["plan_sealed_at"]
        and not repeated
        and spans["complete"]
        and spans["items"] == c["attempt"]["target_item_count"]
        and spans["bytes"] == c["attempt"]["target_byte_count"]
        and totals["chunks"] == c["attempt"]["target_chunk_count"]
        and totals["steps"] == totals["completed_steps"]
        and len(frontier) == 1
    )
    coverage = {
        "status": "complete" if complete else "incomplete",
        "target_item_count": c["attempt"]["target_item_count"],
        "target_byte_count": c["attempt"]["target_byte_count"],
        "target_chunk_count": totals["chunks"],
        "completed_chunks": totals["completed_chunks"],
        "completed_steps": totals["completed_steps"],
        "inconclusive_steps": totals["inconclusive_steps"],
        "gaps": gaps,
    }
    final = (
        st.one(
            "SELECT id,result FROM session_investigation_steps WHERE id=$1 AND attempt_id=$2",
            frontier[0]["id"],
            attempt_id,
            conn=conn,
        )
        if complete
        else None
    )
    return coverage, final


def _anchor(st, c, finding):
    for ref in finding["evidence"]:
        if ref["source"] != "target":
            continue
        row = st.one(
            "SELECT kind,source_id,body FROM session_snapshot_items WHERE snapshot_id=$1 AND ordinal=$2",
            c["job"]["snapshot_id"],
            ref["ordinal"],
            conn=c["conn"],
        )
        event_id = (
            row["body"].get("id")
            if row["kind"] == "observation"
            else row["body"].get("event_id")
            if row["kind"] == "assessment"
            else None
        )
        if event_id:
            observations = st.many(
                """SELECT body FROM session_snapshot_items WHERE snapshot_id=$1 AND kind='observation'
                                      AND source_id=$2""",
                c["job"]["snapshot_id"],
                _uuid(event_id),
                conn=c["conn"],
            )
            if observations:
                return event_id, observations[0]["body"]
    raise InvestigationStopped("invalid_result")


def _history_sources(st, claim, conn=None):
    # The job fence later rechecks these sources before publication. No content
    # is returned or trusted by this preliminary identity-only query.
    sources = set()
    for row in st.many(
        """SELECT session_id,response->'sessions' AS sessions FROM session_investigation_reads
           WHERE attempt_id=$1 AND status='delivered'""",
        _uuid(claim["attempt_id"]),
        conn=conn,
    ):
        sources.update(_read_sources(row["session_id"], row["sessions"]))
    sources.update(row["session_id"] for row in st.many(
        """SELECT source->>'session_id' AS session_id FROM session_investigation_submissions,
           LATERAL json_array_elements(COALESCE(request::json#>'{history,sessions}','[]'::json)) source
           WHERE attempt_id=$1""", _uuid(claim["attempt_id"]), conn=conn,
    ))
    return sources


def _report_scope(st, job, attempt, snapshot, conn, *, complete):
    session = st.one(
        """SELECT s.id,s.sensor_id,s.product,u.name,u.email FROM agent_sessions s LEFT JOIN tenant_users u
             ON u.id=$3 AND u.tenant_id=s.tenant_id
           WHERE s.tenant_id=$1 AND (s.id=$2 OR s.registration_id=$4)""",
        job["tenant_id"], job.get("session_id"), job.get("owner_user_id"),
        job.get("registration_id"), conn=conn,
    )
    hosts = st.many(
        """SELECT DISTINCT body->'host' AS host FROM session_snapshot_items
           WHERE snapshot_id=$1 AND kind='observation' AND jsonb_typeof(body->'host')='object'""",
        snapshot["id"], conn=conn,
    )
    hosts = [row["host"] for row in hosts]
    captured = st.one(
        """SELECT min((body->>'time')::timestamptz) AS started_at,
           max((body->>'time')::timestamptz) AS ended_at,
           COALESCE(array_agg(DISTINCT body->'session'->>'cwd') FILTER (
             WHERE jsonb_typeof(body->'session'->'cwd')='string' AND body->'session'->>'cwd'<>''),
             ARRAY[]::text[]) AS projects
           FROM session_snapshot_items WHERE snapshot_id=$1 AND kind='observation'""",
        snapshot["id"], conn=conn,
    )
    target = {
        "session_id": session["id"], "snapshot_id": snapshot["id"],
        "revision": snapshot["revision"], "started_at": captured["started_at"],
        "ended_at": captured["ended_at"],
        "item_count": snapshot["item_count"], "coverage": snapshot["coverage"],
    }
    context = st.many(
        """SELECT id AS read_id,session_id,response->'version'->>'snapshot_id' AS snapshot_id,
           response->'version' AS version,response->'coverage' AS coverage,
           jsonb_array_length(COALESCE(response->'items','[]'::jsonb)) AS item_count
           FROM session_investigation_reads WHERE attempt_id=$1 AND status='delivered'
             AND tool_name='read_session' ORDER BY created_at,id""",
        attempt["id"], conn=conn,
    ) if attempt else []
    return public({
        "tenant_id": job["tenant_id"], "user_id": job.get("owner_user_id"),
        "ownership_verified": bool(job.get("owner_user_id")),
        "subject": {
            "name": session["name"] or "", "email": session["email"] or "",
            "reported_user": next((host.get("user") for host in hosts if host.get("user")), ""),
            "hostname": next((host.get("hostname") for host in hosts if host.get("hostname")), ""),
            "ownership_verified": bool(job.get("owner_user_id")),
        },
        "devices": hosts, "projects": captured["projects"],
        "target_sessions": [target], "reviewed_sessions": [target] if complete else [],
        "context_sessions": [{**row, "review_status": "context_only"} for row in context],
        "review_cutoff": snapshot["sealed_at"] or snapshot["created_at"],
        "history_cutoff": job["created_at"],
        "history_start": detection_history.bounds(job)[0], "trigger": job["routing_reason"],
        "detector_config_version": job["detector_config_version"],
    })


def terminal_report(st, job, attempt, reason, conn):
    """A bounded, evidence-scoped report for a run that could not finish."""
    snapshot = st.one("SELECT * FROM session_snapshots WHERE id=$1", job["snapshot_id"], conn=conn)
    unavailable = job.get("protocol_version") == 4 and reason in ("result_expired", "result_unavailable")
    return {
        "schema_version": REPORT_VERSION, "status": "inconclusive", "outcome": "inconclusive", "verdict": None,
        "title": "Completed result unavailable" if unavailable else "Investigation incomplete",
        "conclusion": "The service completed the investigation, but its result is unavailable." if unavailable else "The investigation stopped before it could classify this activity.",
        "summary": "The completed result could not be retrieved. Its recorded charge is unchanged." if unavailable else "The investigation stopped before it could determine what happened. Review the interruption and collect any missing evidence before investigating again.",
        "confidence": "low", "reason": reason, "findings": [], "finding_ids": [],
        "timeline": [], "evidence": [], "action_outcomes": [],
        "authorization": {"assessment": "Not established by this incomplete investigation.",
                          "policy_basis": "", "policy_quote": "", "policy_revision": 0,
                          "evidence_indices": []},
        "impact": {"observed": "This incomplete investigation establishes no additional impact.",
                   "potential": "Potential impact remains undetermined."},
        "recommendations": [{"priority": "normal", "action": "Review the interruption and evidence gaps before investigating again.",
                             "rationale": "An incomplete investigation cannot establish that activity was safe."}],
        "alternative_explanations": [], "limitations": [("Completed result unavailable: " if unavailable else "Investigation stopped: ") + reason],
        "gaps": snapshot["coverage"].get("gaps", []), "coverage": {"status": "incomplete"},
        "source_coverage": snapshot["coverage"], "snapshot_id": job["snapshot_id"],
        **({} if job.get("protocol_version") == 4 else {
            "runtime": attempt.get("runtime") if attempt else None, "model": job["configuration"]["model"]}),
        "detector_config_version": job["detector_config_version"],
        "scope": _report_scope(st, job, attempt, snapshot, conn, complete=False),
        "company_policies": _company_policies(st, job, conn),
    }


def publish_report(st, claim, *, conn=None):
    with _fence(st, claim, sources=_history_sources(st, claim, conn), conn=conn) as c:
        _need(c["job"].get("protocol_version") != 4, "invalid_request")
        _need(
            all(c["sources"].values())
            and _history_sources(st, claim, c["conn"]).issubset(c["sources"]),
            "scope_unavailable",
        )
        coverage, final = _coverage(st, c)
        _need(final is not None, "incomplete_coverage")
        _need(c["attempt"]["state"] == "dispatched", "incomplete_coverage")
        return _publish_validated(st, c, coverage, final["result"])


def _publish_validated(st, c, coverage, result):
    """Publish validated evidence while retaining legacy provider accounting."""
    complete = c["job"].get("protocol_version") == 4
    if not complete:
        tokens, cost = _totals(st, c["attempt"]["id"], c["conn"])
        _need(tokens is not None and cost is not None
              and _accounting(st, c["attempt"]["id"], c["conn"])["sound"], "usage_unknown")
    snapshot = st.one(
        "SELECT * FROM session_snapshots WHERE id=$1",
        c["job"]["snapshot_id"],
        conn=c["conn"],
    )
    _need(valid_result(result), "invalid_result")
    original_status = result["status"]
    result = copy.deepcopy(result)
    gaps = sorted(set(coverage["gaps"]) | set(snapshot["coverage"].get("gaps", [])))
    if result["status"] == "no_finding" and (
        snapshot["coverage"]["status"] != "complete"
        or gaps
        or coverage.get("inconclusive_steps", 0)
    ):
        result["status"] = "inconclusive"
        result["verdict"] = None
    facts = {
        item["logical_id"]: _action_facts(st, c, item["logical_id"])
        for finding in result["findings"]
        for item in finding["action_outcomes"]
    }
    report = {
        **result,
        "schema_version": REPORT_VERSION,
        "outcome": {"finding": "actionable_findings", "no_finding": "no_actionable_findings",
                    "inconclusive": "inconclusive"}[result["status"]],
        "scope": _report_scope(st, c["job"], c["attempt"], snapshot, c["conn"], complete=True),
        "company_policies": _company_policies(st, c["job"], c["conn"]),
        "gaps": gaps,
        "coverage": coverage,
        "source_coverage": snapshot["coverage"],
        "snapshot_id": snapshot["id"],
        **({} if complete else {"runtime": c["attempt"]["runtime"], "model": c["job"]["configuration"]["model"]}),
        "detector_config_version": c["job"]["detector_config_version"],
        "action_outcomes": list(facts.values()),
        **({} if complete else {"usage": {"actual_tokens": tokens, "actual_cost_usd": str(cost)}}),
    }
    if result["status"] == "inconclusive" and original_status == "no_finding":
        report["title"] = "Investigation incomplete: missing evidence"
        report["summary"] = "Some activity records are missing or could not be reviewed. The available records do not establish a threat, but they are not enough to classify this alert. Review the evidence gaps and collect the missing records."
        report["conclusion"] = "Missing evidence prevents a final verdict."
        report["confidence"] = "low"
    report["limitations"] = list(dict.fromkeys([
        *report["limitations"], *("Evidence gap: " + gap for gap in gaps),
        *(["Historical sessions were retrieved in bounded pages as context, not fully reviewed or cleared."]
           if report["scope"]["context_sessions"] else []),
        "Conclusions apply only to the listed reviewed snapshots; context-only sessions and future activity are not cleared.",
    ]))
    finding_ids = []
    disabled = st.disabled_rules(c["job"]["tenant_id"], conn=c["conn"])
    if RULE_ID not in disabled:
        for index, finding in enumerate(result["findings"]):
            _checkpoint(c)
            event_id, body = _anchor(st, c, finding)
            session = st.one(
                """SELECT * FROM agent_sessions WHERE tenant_id=$2
                   AND (registration_id=$1 OR (id=$3 AND registration_id IS NULL))""",
                c["job"]["registration_id"],
                c["job"]["tenant_id"],
                c["job"].get("session_id"),
                conn=c["conn"],
            )
            ident = str(uuid.uuid5(uuid.UUID(c["job"]["id"]), str(index)))
            host = body.get("host") or {}
            st.execute(
                """INSERT INTO findings(id,tenant_id,rule_id,category,severity,title,summary,agent_id,session_id,sensor_id,
                          hostname,os,arch,username,product,event_ids,primary_event_id,first_event_at,
                          investigation_job_id,investigation_attempt_id,snapshot_id,finding_index,investigation_evidence)
                          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)""",
                ident,
                c["job"]["tenant_id"],
                RULE_ID,
                finding["category"],
                finding["severity"],
                finding["title"],
                finding["explanation"],
                session["agent_id"],
                session["id"],
                c["job"]["sensor_id"],
                host.get("hostname", ""),
                host.get("os", ""),
                host.get("arch", ""),
                host.get("user", ""),
                c["registration"]["product"],
                [event_id],
                event_id,
                body.get("time") or snapshot["created_at"],
                c["job"]["id"],
                c["attempt"]["id"],
                snapshot["id"],
                index,
                Jsonb(
                    {
                        "references": finding["evidence"],
                        "action_outcomes": finding["action_outcomes"],
                        "source_coverage": snapshot["coverage"],
                    }
                ),
                conn=c["conn"],
            )
            finding_ids.append(ident)
    report["finding_ids"] = finding_ids
    st.execute(
        "UPDATE session_investigation_attempts SET report=$2 WHERE id=$1",
        c["attempt"]["id"],
        Jsonb(report),
        conn=c["conn"],
    )
    usage = {} if complete else _save_totals(st, c["attempt"]["id"], c["conn"])
    aggregation._complete_attempt(
        st,
        c["job"],
        c["attempt"],
        "inconclusive" if report["status"] == "inconclusive" else "completed",
        {"summary": report["summary"], "finding_ids": finding_ids, **usage},
        c["conn"],
        c["now"],
    )
    return {
        "job_id": c["job"]["id"],
        "attempt_id": c["attempt"]["id"],
        "state": "inconclusive"
        if report["status"] == "inconclusive"
        else "completed",
        "report_status": report["status"],
    }


def stop_attempt(st, claim, code, *, retryable=False, conn=None):
    with st.transaction() if conn is None else nullcontext(conn) as conn:
        rows = st.many(
            "SELECT * FROM session_investigation_jobs WHERE id=$1 FOR UPDATE",
            _uuid(claim["job_id"]),
            conn=conn,
        )
        if not rows:
            return {
                "job_id": claim["job_id"],
                "attempt_id": claim["attempt_id"],
                "state": "inconclusive",
                "report_status": "inconclusive",
            }
        job = rows[0]
        complete = job.get("protocol_version") == 4
        if complete:
            _need(job["tenant_id"] == claim.get("tenant_id"), "scope_unavailable")
        codes = (_report.STOP_CODES | {"result_expired", "result_unavailable"}) if complete else _legacy_runtime().STOP_CODES
        code = code if code in codes else "internal_error"
        attempt = aggregation._attempt(
            st, job["id"], _uuid(claim["claim_token"]), _uuid(claim["attempt_id"]), conn
        )
        if attempt:
            now = st.scalar("SELECT clock_timestamp()", conn=conn)
            expired = not complete and aggregation._expired(st, job, attempt, conn, now)
            active = (
                not expired
                and job["state"] == "running"
                and job["claim_token"] == claim["claim_token"]
                and attempt["state"] in ("reserved", "dispatched")
            )
            if active:
                if not complete:
                    aggregation._uncertain_requests(st, attempt["id"], conn, now)
                unused = attempt["dispatched_at"] is None
                retry = bool(
                    unused
                    and not complete
                    and retryable
                    and job["routing_reason"] != "sample"
                    and job["attempts"] < job["configuration"]["max_attempts"]
                )
                report = terminal_report(st, job, attempt, code, conn)
                st.execute(
                    """UPDATE session_investigation_attempts SET state=$2,completed_at=$3,report=$4,result=$5 WHERE id=$1""",
                    attempt["id"],
                    "released" if unused else "uncertain",
                    now,
                    Jsonb(report),
                    Jsonb({"reason": code}),
                    conn=conn,
                )
                st.execute(
                    """UPDATE session_investigation_steps SET state='failed',completed_at=$2
                              WHERE attempt_id=$1 AND state='prepared'""",
                    attempt["id"],
                    now,
                    conn=conn,
                )
                st.execute(
                    """UPDATE session_investigation_jobs SET state=$2,result=$3,claim_token=NULL,lease_deadline=NULL,
                              completed_at=$4,next_attempt_at=$5::timestamptz+$6*interval '1 second' WHERE id=$1""",
                    job["id"],
                    "queued" if retry else "inconclusive",
                    None if retry else Jsonb({"reason": code}),
                    None if retry else now,
                    now,
                    job["configuration"]["retry_delay_seconds"],
                    conn=conn,
                )
            if not complete:
                _save_totals(st, attempt["id"], conn)
        state = st.scalar(
            "SELECT state FROM session_investigation_jobs WHERE id=$1",
            job["id"],
            conn=conn,
        )
        return {
            "job_id": job["id"],
            "attempt_id": claim["attempt_id"],
            "state": state,
            "report_status": "inconclusive",
        }


def _owner(st, tenant_id, user_id, job_id, conn):
    job = st.one(
        "SELECT * FROM session_investigation_jobs WHERE id=$1 AND tenant_id=$2 AND owner_user_id=$3",
        job_id,
        tenant_id,
        user_id,
        conn=conn,
    )
    try:
        if job.get("session_id"):
            aggregation._job_authority(st, job, conn)
        else:
            session_ownership.authorize_inline(
                st,
                {"tenant_id": tenant_id, "id": job["sensor_id"]},
                job["registration_id"],
                conn,
                owner_user_id=user_id,
                snapshot=True,
            )
    except APIError as exc:
        if exc.status not in (403, 404):
            raise
        raise NotFound() from None
    return job


def owner_job(st, tenant_id, user_id, job_id):
    with st.transaction() as conn:
        job = _owner(st, tenant_id, user_id, _uuid(job_id), conn)
        latest = st.many(
            "SELECT id,report FROM session_investigation_attempts WHERE job_id=$1 ORDER BY ordinal DESC LIMIT 1",
            job["id"],
            conn=conn,
        )
        report = latest[0]["report"] if latest else None
        if report:
            sources = _history_sources(st, {"attempt_id": latest[0]["id"]}, conn)
            for session_id in sorted(sources):
                try:
                    _source_scope(st, job, session_id, conn)
                except APIError as exc:
                    if exc.status not in (403, 404):
                        raise
                    raise NotFound() from None
        attempts = st.many(
            """SELECT id,ordinal,state,created_at,dispatched_at,completed_at,actual_tokens,actual_cost_usd,runtime,
                             target_item_count,target_byte_count,target_chunk_count FROM session_investigation_attempts
                             WHERE job_id=$1 ORDER BY ordinal DESC LIMIT 100""",
            job["id"],
            conn=conn,
        )
        attempts.reverse()
        return public(
            {
                "id": job["id"],
                "job_id": job["id"],
                "snapshot_id": job["snapshot_id"],
                "registration_id": job["registration_id"],
                "state": job["state"],
                "detector_config_version": job["detector_config_version"],
                "configuration": customer_views.detection_settings(job["configuration"]),
                "created_at": job["created_at"],
                "completed_at": job["completed_at"],
                "report": customer_views.investigation_report(report),
                "attempts": [customer_views.investigation_attempt(item) for item in attempts],
                "attempt_count": job["attempts"],
                "attempts_truncated": job["attempts"] > len(attempts),
            }
        )


def owner_read(st, tenant_id, user_id, read_id):
    with st.transaction() as conn:
        row = st.one(
            """SELECT r.*,j.id AS job_id FROM session_investigation_reads r
                        JOIN session_investigation_attempts a ON a.id=r.attempt_id
                        JOIN session_investigation_jobs j ON j.id=a.job_id
                        WHERE r.id=$1 AND j.tenant_id=$2 AND j.owner_user_id=$3 AND r.status='delivered'""",
            _uuid(read_id),
            tenant_id,
            user_id,
            conn=conn,
        )
        job = _owner(st, tenant_id, user_id, row["job_id"], conn)
        for session_id in sorted(
            _read_sources(row["session_id"], row["response"].get("sessions"))
        ):
            try:
                _source_scope(st, job, session_id, conn)
            except APIError as exc:
                if exc.status not in (403, 404):
                    raise
                raise NotFound() from None
        view = customer_views.retained_read(st, tenant_id, row, conn=conn)
        if "representation" in view:
            return {**view["response"], "retained_response_sha256": view["retained_response_sha256"]}
        return row["response"]


class Investigator:
    """One bounded worker pool; each attempt owns and closes its remote connection."""

    def __init__(self, st, runtime_factory, *, db_concurrency=1,
                 tenant_runtime_factory=None):
        self.st = st
        self.runtime_factory = runtime_factory
        self.tenant_runtime_factory = tenant_runtime_factory
        self._limiter = anyio.CapacityLimiter(db_concurrency)
        self._close_limiter = anyio.CapacityLimiter(1)
        self._lock = threading.Lock()
        self._runtimes = set()
        self._workers = set()
        self._closed = False

    def _execute(self, claim, worker_id, tenant_id, cancelled):
        SUPPORTED_MODELS = _legacy_runtime().SUPPORTED_MODELS
        finished = threading.Event()
        with self._lock:
            if self._closed or cancelled.is_set():
                return None
            self._workers.add(finished)
        runtime = None

        def alive():
            with self._lock:
                _need(not self._closed and not cancelled.is_set(), "cancelled")

        def guarded(function, *args, **kwargs):
            alive()
            return function(*args, **kwargs)

        try:
            if claim is None and self.tenant_runtime_factory is not None:
                probe = self.runtime_factory()
                try:
                    ready = probe.ready()
                finally:
                    probe.close()
                supported = (SUPPORTED_MODELS & set(ready.get("supported_models", []))
                             if ready.get("ready") else set())
                if not supported:
                    return None
                claim = aggregation.claim_job(
                    self.st, worker_id, tenant_id, worker_ready=True,
                    supported_models=supported,
                )
                if claim is None:
                    return None
            runtime = (self.tenant_runtime_factory(claim["tenant_id"])
                       if self.tenant_runtime_factory is not None else self.runtime_factory())
            with self._lock:
                _need(not self._closed and not cancelled.is_set(), "cancelled")
                self._runtimes.add(runtime)
            ready = runtime.ready()
            supported = (
                SUPPORTED_MODELS & set(ready.get("supported_models", []))
                if ready.get("ready")
                else set()
            )
            if claim is None:
                if not supported:
                    return None
                claim = aggregation.claim_job(
                    self.st,
                    worker_id,
                    tenant_id,
                    worker_ready=True,
                    supported_models=supported,
                )
                if claim is None:
                    return None
            alive()
            model = claim["configuration"]["model"]
            _need(model in supported, "model_unavailable")
            ready = runtime.ready(model)
            _need(ready.get("ready"), "runtime_unavailable")
            prepared = prepare_attempt(self.st, claim, ready)
            deadline = time.monotonic() + prepared["remaining_seconds"]
            _need(getattr(runtime, "remote", False), "runtime_unavailable")
            runtime.bind_attempt(claim, prepared)
            while True:
                alive()
                step = next_step(self.st, claim)
                if step is None:
                    return runtime.finish(partial(guarded, publish_report, self.st, claim))
                deadline = min(deadline, time.monotonic() + step["remaining_seconds"])
                result = runtime.run(
                    tool_callback=partial(
                        guarded, read_tool, self.st, claim, step["id"]
                    ),
                    call_admission=partial(
                        guarded, admit_call, self.st, claim, step["id"]
                    ),
                    call_finish=partial(finish_call, self.st, claim, step["id"]),
                    deadline=deadline,
                    step=step,
                )
                _need(
                    isinstance(result, dict) and isinstance(result.get("text"), str),
                    "invalid_result",
                )
                runtime.accept_step(step, result, partial(guarded, complete_step, self.st, claim, step["id"]))
        except Exception as exc:
            if claim is None:
                return None
            code = getattr(exc, "code", "internal_error")
            return stop_attempt(
                self.st,
                claim,
                code,
                retryable=code in ("runtime_unavailable", "provider_unavailable"),
            )
        finally:
            try:
                if runtime is not None:
                    runtime.close()
            finally:
                with self._lock:
                    self._runtimes.discard(runtime)
                    self._workers.discard(finished)
                    finished.set()

    async def _run(self, claim=None, worker_id=None, tenant_id=None):
        cancelled = threading.Event()
        try:
            return await anyio.to_thread.run_sync(
                partial(self._execute, claim, worker_id, tenant_id, cancelled),
                limiter=self._limiter,
                abandon_on_cancel=True,
            )
        except asyncio.CancelledError:
            cancelled.set()
            await self.aclose()
            raise

    async def run_once(self, worker_id, tenant_id=None, *, worker_ready=False):
        if not worker_ready:
            return None
        return await self._run(worker_id=worker_id, tenant_id=tenant_id)

    async def run_claim(self, claim):
        return await self._run(claim=claim)

    async def aclose(self):
        with self._lock:
            self._closed = True
            runtimes = list(self._runtimes)
            workers = list(self._workers)

        def close_and_join():
            for runtime in runtimes:
                try:
                    runtime.close()
                except Exception:
                    # The attempt thread still owns its final cleanup. Do not
                    # let one close error skip other runtimes or completion.
                    pass
            for worker in workers:
                worker.wait()

        await anyio.to_thread.run_sync(close_and_join, limiter=self._close_limiter)
