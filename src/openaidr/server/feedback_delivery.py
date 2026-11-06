"""Opt-in feedback delivery from retained review revisions, outside hook paths."""

import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone

import httpx
from openaidr_api_client.client import Unavailable

from psycopg.types.json import Jsonb

from . import intelligence
from .customer_views import investigation_report
from .httpx import APIError, require
from .store import new_id, valid_uuid


MAX_CONTENT = 256 << 10


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def stamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("UTC timestamp required")
    return parsed


def connection(st, cfg, origin=None):
    try:
        value = (intelligence.connection_for_origin(cfg, st, origin) if origin
                 else intelligence.selected_connection(cfg, st))
    except APIError:
        return None
    return value if value and value.tenant_id == cfg.tenant_id else None


def read(st, tenant, cfg, conn=None):
    rows = st.many("SELECT * FROM tenant_feedback_settings WHERE tenant_id=$1", tenant, conn=conn)
    setting = rows[0] if rows else dict(sharing_scope="none", retention_days=7, origin="", version=0, enabled_at=None)
    target = connection(st, cfg) if cfg.tenant_id == tenant else None
    counts = st.many("SELECT status,count(*) AS count FROM feedback_delivery WHERE tenant_id=$1 GROUP BY status",
                     tenant, conn=conn)
    return {**setting, "available": bool(target),
            "destination": target.origin if target else None,
            "delivery": {row["status"]: row["count"] for row in counts}}


def _lock(st, tenant, conn, wait=True):
    name = "feedback-sharing:" + tenant
    if wait:
        st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", name, conn=conn)
    elif not st.scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))", name, conn=conn):
        return False
    st.execute("INSERT INTO tenant_feedback_settings(tenant_id) VALUES($1) ON CONFLICT DO NOTHING", tenant, conn=conn)
    return True


def _audit(st, tenant, actor, action, target, details, conn):
    st.execute("""INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
        VALUES($1,$2,'user',$3,$4,$5,'feedback',$6,$7)""", new_id(), tenant,
        actor.get("id", ""), actor.get("name", ""), action, target, Jsonb(details), conn=conn)


def save(st, tenant, data, actor, cfg):
    require(set(data) == {"sharing_scope", "retention_days", "version"}
            and data["sharing_scope"] in ("none", "metadata", "evidence")
            and type(data["retention_days"]) is int and 1 <= data["retention_days"] <= 30
            and type(data["version"]) is int, "Provide sharing_scope, retention_days and version")
    target = connection(st, cfg) if cfg.tenant_id == tenant else None
    require(data["sharing_scope"] == "none" or target, "Feedback sharing requires a tenant connection", 409)
    with st.transaction() as conn:
        _lock(st, tenant, conn)
        previous = read(st, tenant, cfg, conn)
        require(previous["version"] == data["version"], "Feedback settings changed. Refresh and try again", 409)
        st.execute("""UPDATE tenant_feedback_settings SET sharing_scope=$2,retention_days=$3,origin=$4,
            enabled_at=clock_timestamp(),version=version+1 WHERE tenant_id=$1""", tenant,
            data["sharing_scope"], data["retention_days"], target.origin if target else "", conn=conn)
        # An ambiguous upload might already exist remotely. Reconcile it by deletion.
        st.execute("""UPDATE feedback_delivery SET status=CASE WHEN attempts>0 THEN 'deleting' ELSE 'cancelled' END,
            payload=NULL,next_attempt_at=clock_timestamp() WHERE tenant_id=$1 AND status='pending'""", tenant, conn=conn)
        _audit(st, tenant, actor, "feedback.configure", tenant, data, conn)
        return read(st, tenant, cfg, conn)


def withdraw(st, tenant, data, actor):
    require(set(data) == {"feedback_id"} and isinstance(data["feedback_id"], str)
            and valid_uuid(data["feedback_id"]), "feedback_id is required")
    with st.transaction() as conn:
        _lock(st, tenant, conn)
        require(st.scalar("SELECT EXISTS(SELECT 1 FROM feedback_delivery WHERE tenant_id=$1 AND feedback_id=$2)",
                          tenant, data["feedback_id"], conn=conn), "Shared feedback not found", 404)
        st.execute("""UPDATE feedback_delivery SET status='deleting',payload=NULL,next_attempt_at=clock_timestamp(),error_code=''
            WHERE tenant_id=$1 AND feedback_id=$2 AND status<>'deleted'""", tenant, data["feedback_id"], conn=conn)
        _audit(st, tenant, actor, "feedback.withdraw", data["feedback_id"], {}, conn)
    return {"feedback_id": data["feedback_id"], "status": "deleting"}


def _source(st, tenant, kind, ident, revision, conn):
    if kind == "hook_check":
        rows = st.many("""SELECT r.*,e.evidence FROM ordinary_hook_review_revisions r
            JOIN ordinary_hook_checks c ON c.id=r.check_id
            LEFT JOIN ordinary_hook_review_evidence e ON e.check_id=r.check_id AND e.sha256=r.evidence_sha256
            WHERE c.tenant_id=$1 AND r.check_id=$2 AND r.revision=$3""", tenant, ident, revision, conn=conn)
        if not rows:
            return None
        row = rows[0]
        return dict(label=row["label"], note=row["note"], reviewed_at=row["reviewed_at"],
                    attribution=dict(kind="device", source_id=row["source_id"], reviewer_id=None),
                    content=row["evidence"], reviewed_revision=row["evidence_sha256"],
                    gaps=list((row["evidence"] or {}).get("gaps", [])) if row["evidence_sha256"] else ["legacy_unbound"])
    rows = st.many("SELECT * FROM risk_case_review_revisions WHERE tenant_id=$1 AND case_id=$2 AND revision=$3",
                   tenant, ident, revision, conn=conn)
    if not rows:
        return None
    row = rows[0]
    context, reports = row["review_context"], []
    if context:
        for item in context["reports"]:
            if item["attempt_id"] is None:
                if not st.scalar("SELECT EXISTS(SELECT 1 FROM session_investigation_jobs WHERE tenant_id=$1 AND id=$2 AND snapshot_id=$3)",
                                 tenant, item["job_id"], item["snapshot_id"], conn=conn):
                    return None
                continue
            found = st.many("""SELECT a.report FROM session_investigation_attempts a
                JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
                WHERE a.tenant_id=$1 AND a.id=$2 AND a.job_id=$3 AND j.snapshot_id=$4""",
                tenant, item["attempt_id"], item["job_id"], item["snapshot_id"], conn=conn)
            if not found:
                return None
            report = investigation_report(found[0]["report"]) if item["report_sha256"] is not None else None
            if report is not None and digest(report) != item["report_sha256"]:
                return None
            if item["report_sha256"] is not None and report is None:
                return None
            reports.append({"attempt_id": item["attempt_id"], "report": report})
    return dict(label={"tp": "true_positive", "fp": "false_positive", "review": "under_review"}[row["outcome"]],
                note="", reviewed_at=row["reviewed_at"],
                attribution=dict(kind="analyst", source_id=None, reviewer_id=row["reviewer_id"]),
                content={"review_context": context, "reports": reports} if context else None,
                reviewed_revision=digest(context) if context else None, gaps=list(row["completeness"]))


def _payload(source, row, setting, expires):
    content = source["content"]
    checksum = digest(content) if content is not None else None
    gaps = set(source["gaps"]) | {"service_request_unavailable"}
    attribution, note = source["attribution"], source["note"]
    if setting["sharing_scope"] == "metadata":
        content, note = None, ""
        attribution = {**attribution, "source_id": None, "reviewer_id": None}
    elif content is not None and len(canonical(content)) > MAX_CONTENT:
        content = None
        gaps.add("evidence_oversized")
    if content is None:
        gaps.add("content_not_shared")
    if source["reviewed_revision"] is None:
        gaps.add("legacy_unbound")
    payload = dict(schema_version=1, feedback_id=row["feedback_id"], revision=row["revision"],
                   feedback_type="guardrail" if row["subject_type"] == "hook_check" else "detection",
                   subject=dict(type=row["subject_type"], id=row["feedback_id"], reviewed_revision=source["reviewed_revision"]),
                   label=source["label"], note=note, reviewed_at=source["reviewed_at"].astimezone(timezone.utc).isoformat(),
                   attribution=attribution, evidence=dict(snapshot_id=row["feedback_id"], sha256=checksum,
                   content=content, gaps=sorted(gaps)), service_request_ids=[], sharing_scope=setting["sharing_scope"],
                   expires_at=expires.astimezone(timezone.utc).isoformat())
    return payload


def _collect(st, cfg):
    tenant = cfg.tenant_id
    with st.transaction() as conn:
        if not _lock(st, tenant, conn, wait=False):
            return
        setting = read(st, tenant, cfg, conn)
        target = connection(st, cfg)
        if (setting["sharing_scope"] == "none" or not target or target.origin != setting["origin"]
                or st.scalar("SELECT status FROM tenants WHERE id=$1", tenant, conn=conn) != "active"):
            return
        rows = st.many("""WITH reviews AS (
            SELECT r.check_id AS feedback_id,r.revision,'hook_check' AS subject_type,r.reviewed_at
                FROM ordinary_hook_review_revisions r JOIN ordinary_hook_checks c ON c.id=r.check_id WHERE c.tenant_id=$1
            UNION ALL SELECT case_id,revision,'case',reviewed_at FROM risk_case_review_revisions WHERE tenant_id=$1
            ) SELECT * FROM reviews r WHERE reviewed_at>=$2
              AND NOT EXISTS(SELECT 1 FROM feedback_delivery d WHERE d.tenant_id=$1 AND d.feedback_id=r.feedback_id
                AND (d.revision=r.revision OR d.status IN ('deleting','deleted')))
            ORDER BY reviewed_at,feedback_id,revision LIMIT 20""", tenant, setting["enabled_at"], conn=conn)
        now = st.scalar("SELECT clock_timestamp()", conn=conn)
        for row in rows:
            expires = row["reviewed_at"] + timedelta(days=setting["retention_days"])
            source = _source(st, tenant, row["subject_type"], row["feedback_id"], row["revision"], conn)
            payload = _payload(source, row, setting, expires) if source and expires > now else None
            st.execute("""INSERT INTO feedback_delivery(tenant_id,feedback_id,revision,subject_type,origin,
                sharing_scope,settings_version,payload,status,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)""",
                tenant, row["feedback_id"], row["revision"], row["subject_type"], target.origin,
                setting["sharing_scope"], setting["version"], Jsonb(payload) if payload else None,
                "pending" if payload else "cancelled", expires, conn=conn)


async def send(target, row):
    async with asyncio.timeout(5), httpx.AsyncClient(base_url=target.origin, verify=target.verify(),
            timeout=5, follow_redirects=False, trust_env=False,
            headers={"Authorization": "Bearer " + target.api_key, "Accept-Encoding": "identity"}) as client:
        async def request(path, payload=None, *, method="POST", limit=4096):
            async with client.stream(method, path, json=payload) as response:
                if response.status_code != 200:
                    raise Unavailable("Feedback service unavailable", status_code=response.status_code)
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise ValueError("Invalid feedback encoding")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > limit:
                        raise ValueError("Invalid feedback response size")
            value = json.loads(body)
            if not isinstance(value, dict) or value.get("tenant_id") != target.tenant_id:
                raise ValueError("Invalid feedback tenant")
            return value

        if row["status"] == "deleting":
            value = await request("/v1/feedback/" + row["feedback_id"] + "/delete", {})
            if (type(value.get("schema_version")) is not int or value["schema_version"] != 1
                    or value.get("feedback_id") != row["feedback_id"] or value.get("status") != "deleted"):
                raise ValueError("Invalid feedback deletion receipt")
            stamp(value["deleted_at"])
            return value
        capabilities = await request("/v1/capabilities", method="GET", limit=16384)
        if not isinstance(capabilities.get("capabilities"), dict) or capabilities["capabilities"].get("feedback") != "configured":
            raise Unavailable("Feedback receiver is unavailable")
        payload = row["payload"]
        value = await request("/v1/feedback", payload)
        if (type(value.get("schema_version")) is not int or value["schema_version"] != 1
                or value.get("feedback_id") != row["feedback_id"]
                or type(value.get("revision")) is not int or value["revision"] != row["revision"]
                or value.get("request_sha256") != digest(payload)
                or not isinstance(value.get("receipt_id"), str) or not valid_uuid(value["receipt_id"])
                or stamp(value["expires_at"]) != stamp(payload["expires_at"])
                or stamp(value["received_at"]) >= stamp(value["expires_at"])):
            raise ValueError("Invalid feedback receipt")
        return value


def run_once(st, cfg):
    if not cfg.tenant_id:
        return False
    tenant = cfg.tenant_id
    with st.transaction() as conn:
        if not _lock(st, tenant, conn, wait=False):
            return False
        now = st.scalar("SELECT clock_timestamp()", conn=conn)
        # Raw content is discarded on acknowledgement, cancellation or local expiry.
        st.execute("""UPDATE feedback_delivery SET payload=NULL,status=CASE WHEN attempts>0 THEN 'deleting' ELSE 'cancelled' END
            WHERE tenant_id=$1 AND status='pending' AND expires_at<=$2""", tenant, now, conn=conn)
        st.execute("""UPDATE feedback_delivery d SET status='deleting',payload=NULL,next_attempt_at=$2
            WHERE d.tenant_id=$1 AND d.status IN ('pending','sent') AND (
              (d.subject_type='hook_check' AND NOT EXISTS(SELECT 1 FROM ordinary_hook_review_revisions r
                JOIN ordinary_hook_checks c ON c.id=r.check_id
                WHERE c.tenant_id=d.tenant_id AND r.check_id=d.feedback_id AND r.revision=d.revision)) OR
              (d.subject_type='case' AND NOT EXISTS(SELECT 1 FROM risk_case_review_revisions r
                WHERE r.tenant_id=d.tenant_id AND r.case_id=d.feedback_id AND r.revision=d.revision)))""", tenant, now, conn=conn)
        retained = st.many("""SELECT * FROM feedback_delivery WHERE tenant_id=$1 AND status='sent' AND expires_at>$2
            ORDER BY checked_at,feedback_id,revision LIMIT 20""", tenant, now, conn=conn)
        for item in retained:
            present = _source(st, tenant, item["subject_type"], item["feedback_id"], item["revision"], conn)
            st.execute("""UPDATE feedback_delivery SET checked_at=$4,status=CASE WHEN $5 THEN status ELSE 'deleting' END,
                next_attempt_at=CASE WHEN $5 THEN next_attempt_at ELSE $4 END
                WHERE tenant_id=$1 AND feedback_id=$2 AND revision=$3""",
                tenant, item["feedback_id"], item["revision"], now, present is not None, conn=conn)
    _collect(st, cfg)
    with st.transaction() as conn:
        if not _lock(st, tenant, conn, wait=False):
            return False
        now = st.scalar("SELECT clock_timestamp()", conn=conn)
        rows = st.many("""SELECT * FROM feedback_delivery d WHERE tenant_id=$1
            AND status IN ('pending','deleting') AND next_attempt_at<=$2
            AND (status='deleting' OR NOT EXISTS(SELECT 1 FROM feedback_delivery earlier
                WHERE earlier.tenant_id=d.tenant_id AND earlier.feedback_id=d.feedback_id AND earlier.revision<d.revision
                  AND earlier.status IN ('pending','deleting')))
            ORDER BY CASE WHEN status='deleting' THEN 0 ELSE 1 END,next_attempt_at,feedback_id,revision LIMIT 1""", tenant, now, conn=conn)
        if not rows:
            return False
        row = rows[0]
        # Persist that delivery may have started before network I/O. A crash can
        # lose the acknowledgement, but must not lose the need to withdraw it.
        st.execute("""UPDATE feedback_delivery SET attempts=attempts+1
            WHERE tenant_id=$1 AND feedback_id=$2 AND revision=$3""", tenant, row["feedback_id"], row["revision"], conn=conn)
    with st.transaction() as conn:
        if not _lock(st, tenant, conn, wait=False):
            return False
        row = st.one("SELECT * FROM feedback_delivery WHERE tenant_id=$1 AND feedback_id=$2 AND revision=$3",
                     tenant, row["feedback_id"], row["revision"], conn=conn)
        if row["status"] not in ("pending", "deleting"):
            return False
        target = connection(st, cfg, row["origin"])
        setting = read(st, tenant, cfg, conn)
        if row["status"] == "pending":
            authorized = (setting["version"] == row["settings_version"] and setting["sharing_scope"] == row["sharing_scope"]
                          and setting["origin"] == row["origin"] and setting["destination"] in (None, row["origin"])
                          and st.scalar("SELECT status FROM tenants WHERE id=$1", tenant, conn=conn) == "active")
            source = _source(st, tenant, row["subject_type"], row["feedback_id"], row["revision"], conn)
            if not authorized or source is None:
                st.execute("""UPDATE feedback_delivery SET payload=NULL,status=CASE WHEN attempts>0 THEN 'deleting' ELSE 'cancelled' END
                    WHERE tenant_id=$1 AND feedback_id=$2 AND revision=$3""", tenant, row["feedback_id"], row["revision"], conn=conn)
                return True
        attempts = row["attempts"]
        try:
            require(target is not None and (row["status"] == "deleting" or setting["destination"] is not None),
                    "Feedback credential unavailable", 503)
            receipt = asyncio.run(send(target, row))
        except Exception as exc:
            # Keep errors categorical. Provider bodies and credentials must not enter the queue.
            permanent = row["status"] != "deleting" and getattr(exc, "status_code", None) in (400, 409, 410, 413, 422)
            code = "receiver_rejected" if permanent else "delivery_unavailable"
            st.execute("""UPDATE feedback_delivery SET attempts=$4,error_code=$5,
                next_attempt_at=clock_timestamp()+make_interval(secs=>$6),status=CASE WHEN $7 THEN 'failed' ELSE status END,
                payload=CASE WHEN $7 THEN NULL ELSE payload END WHERE tenant_id=$1 AND feedback_id=$2 AND revision=$3""",
                tenant, row["feedback_id"], row["revision"], attempts, code, min(3600, 30 * 2 ** min(attempts - 1, 7)), permanent, conn=conn)
        else:
            if row["status"] == "deleting":
                st.execute("""UPDATE feedback_delivery SET status='deleted',payload=NULL,receipt=$3,error_code=''
                    WHERE tenant_id=$1 AND feedback_id=$2 AND origin=$4""", tenant, row["feedback_id"], Jsonb(receipt), row["origin"], conn=conn)
            else:
                st.execute("""UPDATE feedback_delivery SET status='sent',payload=NULL,attempts=$4,receipt=$5,error_code=''
                    WHERE tenant_id=$1 AND feedback_id=$2 AND revision=$3""",
                    tenant, row["feedback_id"], row["revision"], attempts, Jsonb(receipt), conn=conn)
        return True
