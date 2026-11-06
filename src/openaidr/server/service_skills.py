"""Skill dispatch with durable lease binding and conservative retries."""

from contextlib import closing
import hashlib
import json
from uuid import UUID

import httpx
import psycopg
from openaidr_api_client.client import SyncIntelligenceClient, Unavailable

from . import service_billing
from .service_operations import ServiceOperation


MAX_REQUEST = 1 << 20
MAX_RESPONSE = 4 << 20


def _require(condition, message):
    if not condition:
        raise Unavailable(message, status_code=409)


def connection_binding(connection):
    # Keep the exact existing lease identity. A workspace change cannot retarget
    # a lease created before this adapter was installed.
    return hashlib.sha256(json.dumps(["intelligence", connection.origin, connection.tenant_id]).encode()).hexdigest()


def _request(data, *, bundle=False):
    try:
        if bundle:
            from openaidr_api_client.contracts import service_skill_scans as wire
        else:
            from openaidr_api_client.contracts import service_skills as wire
    except ImportError:
        raise Unavailable("Customer service SDK is unavailable") from None
    try:
        fields = {"sha256", "lease_id", "task"} | (set() if bundle else {"timeout_ms"})
        if (not isinstance(data, dict) or set(data) != fields
                or not isinstance(data["lease_id"], str) or str(UUID(data["lease_id"])) != data["lease_id"]
                or not isinstance(data["task"], dict) or not bundle and "timeout_ms" in data["task"]):
            raise ValueError
        request = (wire.ServiceSkillScanRequest(**data["task"]) if bundle else
                   wire.ServiceSkillRequest(**data["task"], timeout_ms=data["timeout_ms"])).model_dump()
        if request["bundle_sha256"] != data["sha256"]:
            raise ValueError
        if len(json.dumps(request, ensure_ascii=False, allow_nan=False).encode()) > (12 << 20 if bundle else MAX_REQUEST):
            raise ValueError
    except (ValueError, TypeError, AttributeError, UnicodeError, RecursionError):
        raise Unavailable("Invalid scanner task", status_code=400) from None
    return wire, request


def _reserve(store, tenant, connection, data, request, *, bundle=False):
    from . import service_skill_worker

    operation = ServiceOperation(store, tenant, "skill_assessment", connection)
    payload = {key: value for key, value in request.items() if key != "timeout_ms"}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    with store.transaction() as conn:
        leases = store.many("""SELECT model_connection_binding,scanner_profile,
            extract(epoch FROM lease_until-clock_timestamp())*1000 AS remaining_ms FROM skill_bundles
            WHERE tenant_id=$1 AND sha256=$2 AND lease_id=$3 AND status='running'
            AND worker_protocol='skills-service-v1' AND lease_until>clock_timestamp() FOR UPDATE""",
            tenant, data["sha256"], data["lease_id"], conn=conn)
        _require(bool(leases), "Scan lease expired")
        _require(leases[0]["model_connection_binding"] == connection_binding(connection),
                 "Scan connection changed; recover the original lease connection")
        current = {service_skill_worker.scanner_profile(mode, intel_origin=connection.origin) for mode in ("static", "llm")}
        _require((leases[0]["scanner_profile"] in current) == bundle,
                 "Use the service profile captured by this scan lease")
        if bundle:
            _require(leases[0]["remaining_ms"] > request["timeout_ms"] + 10000,
                     "Insufficient time remains in the original scan lease")
            _require(not store.scalar("""SELECT EXISTS(SELECT 1 FROM service_call_intents i
                LEFT JOIN service_credit_receipts r ON r.tenant_id=i.tenant_id AND r.request_id=i.request_id
                    AND r.origin=i.origin AND r.api_tenant_id=i.api_tenant_id AND r.service=i.service
                WHERE i.tenant_id=$1 AND i.service='skill_assessment' AND i.scope_id=$2
                AND (i.outcome IS DISTINCT FROM 'failed' OR r.state IS NULL
                    OR NOT (r.state='disabled' OR r.state='released' AND r.charged_microcredits=0)))""",
                tenant, data["lease_id"], conn=conn),
                "This skill was already dispatched; its result cannot be retried")
        jobs = store.many("""SELECT id FROM skill_llm_jobs
            WHERE tenant_id=$1 AND sha256=$2 AND lease_id=$3""", tenant, data["sha256"], data["lease_id"], conn=conn)
        _require(not bundle or jobs, "Whole-skill analysis requires an authorized running AI job")
        if jobs:
            settings = store.many("SELECT mode FROM tenant_skill_llm_settings WHERE tenant_id=$1 FOR UPDATE",
                                  tenant, conn=conn)
            _require(settings and settings[0]["mode"] != "off", "Service scanning is paused")
            _require(store.scalar("""SELECT EXISTS(SELECT 1 FROM skill_llm_jobs
                WHERE tenant_id=$1 AND sha256=$2 AND lease_id=$3 AND status='running'
                AND lease_until>clock_timestamp())""", tenant, data["sha256"], data["lease_id"], conn=conn),
                "Scan lease expired")
        previous = store.many("""SELECT outcome,attempt FROM service_call_intents
            WHERE tenant_id=$1 AND service='skill_assessment' AND scope_id=$2 AND request_sha256=$3
            ORDER BY attempt DESC LIMIT 1""", tenant, data["lease_id"], digest, conn=conn)
        _require(not previous or previous[0]["outcome"] == "failed",
                 "This scan task was already dispatched; its result cannot be retried")
        store.execute("""INSERT INTO service_call_intents
            (tenant_id,request_id,service,origin,api_tenant_id,request_sha256,scope_id,attempt)
            VALUES($1,$2,'skill_assessment',$3,$4,$5,$6,$7)""", tenant, operation.id, connection.origin,
            connection.tenant_id, digest, data["lease_id"], previous[0]["attempt"] + 1 if previous else 1, conn=conn)
    return operation


def assess(store, tenant, connection, data, *, transport=None, bundle=False):
    """Use the captured original connection; never resolve the current workspace here."""
    wire, request = _request(data, bundle=bundle)
    operation = _reserve(store, tenant, connection, data, request, bundle=bundle)
    try:
        with closing(SyncIntelligenceClient.from_connection(operation.connection, transport=transport)) as client:
            value = client.request("/v1/services/skills/scan-bundle" if bundle else "/v1/services/skills/assess",
                                   request, 8 << 20 if bundle else MAX_RESPONSE,
                                   request["timeout_ms"] / 1000 + 5, request_id=operation.id)
        operation.capture(value["billing"])
        parsed = None
        try:
            parsed = wire.validate_response(request, value)
        finally:
            # A bad task result cannot erase independently confirmed accounting.
            with store.transaction() as conn:
                intent = store.one("""SELECT origin,api_tenant_id FROM service_call_intents
                    WHERE tenant_id=$1 AND request_id=$2 FOR UPDATE""", tenant, operation.id, conn=conn)
                _require(intent["origin"] == connection.origin and intent["api_tenant_id"] == connection.tenant_id,
                         "Scan receipt connection changed")
                service_billing.record(store, operation.tenant, operation.connection, operation.receipt,
                                       request_id=operation.id, service=operation.service, conn=conn)
                # A pending release remains uncertain. Invalid results never
                # complete the task, even when their billing is already settled.
                if parsed is not None and (parsed.status == "completed" and (not bundle or parsed.billing.state in ("settled", "disabled"))
                                           or parsed.billing.state in ("disabled", "released")):
                    store.execute("""UPDATE service_call_intents SET outcome=$3,completed_at=clock_timestamp()
                        WHERE tenant_id=$1 AND request_id=$2 AND outcome IS NULL""", tenant, operation.id,
                        "completed" if parsed.status == "completed" else "failed", conn=conn)
        return parsed.model_dump()
    except (Unavailable, TimeoutError, httpx.HTTPError, psycopg.Error, ValueError, TypeError, KeyError, RecursionError):
        raise Unavailable("Skill Intelligence service unavailable", status_code=502) from None
