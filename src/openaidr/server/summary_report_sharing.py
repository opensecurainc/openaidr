"""Local report snapshots and opt-in delivery, independent of decision paths."""

import asyncio
import hashlib
import json
from datetime import timedelta, timezone

import httpx
from psycopg.types.json import Jsonb

from . import summary_report_contract as contract
from openaidr.server.guardrail.analytics import CTE, LATENCY
from openaidr.server.hook_policy import DELIVERY_JOINS
from openaidr.server.httpx import APIError, require
from openaidr.server.store import new_id, valid_uuid
from openaidr.server.version import __version__


def available(cfg, tenant):
    return bool(cfg.summary_report_origin and cfg.summary_report_token and cfg.tenant_id == tenant)


def destination(cfg):
    return hashlib.sha256((cfg.summary_report_origin + "\n" + cfg.summary_report_token).encode()).hexdigest()


def read(st, tenant, cfg, conn=None):
    rows = st.many("SELECT * FROM tenant_summary_report_settings WHERE tenant_id=$1", tenant, conn=conn)
    setting = rows[0] if rows else dict(automatic=False, version=0, destination_sha256="", next_report_at=None, last_sent_at=None)
    enabled = setting["automatic"] and setting["destination_sha256"] == destination(cfg)
    delivery = st.one("""SELECT count(*) FILTER (WHERE status='pending') AS pending,
        count(*) FILTER (WHERE status='failed') AS failed FROM summary_report_outbox WHERE tenant_id=$1""", tenant, conn=conn)
    return dict(automatic=enabled, version=setting["version"], available=available(cfg, tenant),
                destination=cfg.summary_report_origin if available(cfg, tenant) else None,
                next_report_at=setting["next_report_at"] if enabled else None,
                delivery={**delivery, "last_sent_at": setting["last_sent_at"]})


def _lock(st, tenant, conn, *, wait=True):
    name = "summary-sharing:" + tenant
    if wait:
        st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", name, conn=conn)
    elif not st.scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))", name, conn=conn):
        return False
    st.execute("INSERT INTO tenant_summary_report_settings(tenant_id) VALUES($1) ON CONFLICT DO NOTHING", tenant, conn=conn)
    return True


def _audit(st, tenant, actor, action, target, details, conn):
    st.execute("""INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
        VALUES($1,$2,$3,$4,$5,$6,'summary_report',$7,$8)""", new_id(), tenant,
        actor.get("type", "user"), actor.get("id", ""), actor.get("name", ""), action, target, Jsonb(details), conn=conn)


def save(st, tenant, data, actor, cfg):
    require(set(data) == {"automatic", "version"} and type(data["automatic"]) is bool
            and type(data["version"]) is int, "automatic and version are required")
    require(not data["automatic"] or available(cfg, tenant), "Report sharing requires server setup", 409)
    with st.transaction() as conn:
        _lock(st, tenant, conn)
        setting = read(st, tenant, cfg, conn)
        require(setting["version"] == data["version"], "Report settings changed. Refresh and try again", 409)
        st.execute("""UPDATE tenant_summary_report_settings SET automatic=$2,version=version+1,destination_sha256=$3,
            next_report_at=CASE WHEN $2 THEN clock_timestamp()+interval '1 day' ELSE NULL END WHERE tenant_id=$1""",
            tenant, data["automatic"], destination(cfg), conn=conn)
        if not data["automatic"]:
            st.execute("""UPDATE summary_report_outbox SET status='cancelled' WHERE tenant_id=$1
                AND source='automatic' AND status='pending'""", tenant, conn=conn)
        _audit(st, tenant, actor, "summary_report.configure", tenant, {"automatic": data["automatic"]}, conn)
        return read(st, tenant, cfg, conn)


def _counts(column, keys):
    return ",".join(f"count(*) FILTER (WHERE {column}='{key}') AS {key}" for key in keys)


def build(st, tenant, conn):
    until = st.scalar("SELECT clock_timestamp()", conn=conn).astimezone(timezone.utc)
    since = until - timedelta(days=1)
    # A single SQL statement gives all aggregates the same database snapshot.
    row = st.one(CTE + """, checks AS MATERIALIZED (
        SELECT c.status,c.mode,c.evaluated_decision,c.returned_decision,
            COALESCE(d.delivery_status,r.delivery_status) AS delivery_status,
            COALESCE(d.delivered_decision,r.delivered_decision) AS delivered_decision
        FROM ordinary_hook_checks c
    """ + DELIVERY_JOINS + """
        WHERE c.tenant_id=$1 AND c.created_at>=$2 AND c.created_at<$3
    ), reports AS MATERIALIZED (
        SELECT a.report->>'status' AS outcome,a.report->'source_coverage'->>'status' AS source_coverage
        FROM session_investigation_jobs j
        LEFT JOIN LATERAL (SELECT report FROM session_investigation_attempts a
            WHERE a.job_id=j.id AND a.tenant_id=j.tenant_id ORDER BY ordinal DESC LIMIT 1) a ON true
        WHERE j.tenant_id=$1 AND j.completed_at>=$2 AND j.completed_at<$3
          AND j.state IN ('completed','inconclusive')
    ) SELECT
        (SELECT row_to_json(v) FROM (SELECT count(*) AS total,"""
        + _counts("status", ("pending", "evaluated", "unavailable")) + ","
        + _counts("mode", ("shadow", "enforce")) + " FROM checks) v) AS checks,"
        + ",".join(f"(SELECT row_to_json(v) FROM (SELECT {_counts(col, contract.COUNTS[group])} FROM checks {where}) v) AS {group}"
                   for group, col, where in (
                       ("evaluated_decisions", "evaluated_decision", ""),
                       ("returned_decisions", "returned_decision", ""),
                       ("delivered_decisions", "delivered_decision", "WHERE delivery_status='delivered'")))
        + ", (SELECT row_to_json(v) FROM (SELECT "
        + _counts("delivery_status", ("delivered", "timed_out", "failed"))
        + ",count(*) FILTER (WHERE delivery_status IS NULL) AS unconfirmed FROM checks) v) AS delivery,"
        + "(SELECT row_to_json(v) FROM (SELECT count(*) AS total,"
        + _counts("severity", ("info", "low", "medium", "high", "critical"))
        + """,count(*) FILTER (WHERE status='false_positive') AS marked_false_positive
            FROM findings WHERE tenant_id=$1 AND created_at>=$2 AND created_at<$3) v) AS findings,
        (SELECT row_to_json(v) FROM (SELECT count(*) AS total,
            count(*) FILTER (WHERE outcome='finding') AS finding,
            count(*) FILTER (WHERE outcome='no_finding') AS no_finding,
            count(*) FILTER (WHERE outcome='inconclusive') AS inconclusive,
            count(*) FILTER (WHERE COALESCE(outcome,'') NOT IN ('finding','no_finding','inconclusive')) AS unknown,
            count(*) FILTER (WHERE source_coverage='complete') AS source_complete,
            count(*) FILTER (WHERE source_coverage='incomplete') AS source_incomplete,
            count(*) FILTER (WHERE COALESCE(source_coverage,'') NOT IN ('complete','incomplete')) AS source_unknown
            FROM reports) v) AS investigations,
        (SELECT row_to_json(v) FROM (SELECT count(policy_ms) AS policy,count(e2e_ms) AS e2e FROM measured) v) AS latency_samples,
        (SELECT row_to_json(v) FROM (SELECT """ + LATENCY + " FROM measured) v) AS latency_ms",
        tenant, since, until, conn=conn)
    payload = dict(schema_version=1, report_id=new_id(), tenant_id=tenant, generated_at=until.isoformat(),
                   window_start=since.isoformat(), window_end=until.isoformat(),
                   backend_version=__version__ if contract.VERSION.fullmatch(__version__) else None,
                   counts={key: row[key] for key in contract.COUNTS}, latency_ms=row["latency_ms"])
    contract.validate(payload)
    return payload


def _prune(st, tenant, conn):
    st.execute("""DELETE FROM summary_report_outbox WHERE tenant_id=$1 AND
        ((status='preview' AND created_at<clock_timestamp()-interval '1 hour') OR id IN
         (SELECT id FROM summary_report_outbox WHERE tenant_id=$1 AND status IN ('sent','failed','cancelled')
          ORDER BY created_at DESC,id DESC OFFSET 100))""", tenant, conn=conn)


def _insert(st, tenant, payload, source, status, cfg, conn):
    return st.scalar("""INSERT INTO summary_report_outbox(id,tenant_id,source,payload,destination_sha256,status)
        VALUES($1,$2,$3,$4,$5,$6) RETURNING created_at""",
        payload["report_id"], tenant, source, Jsonb(payload), destination(cfg), status, conn=conn)


def preview(st, tenant, data, actor, cfg):
    require(not data, "preview does not accept report content")
    with st.transaction() as conn:
        _lock(st, tenant, conn)
        _prune(st, tenant, conn)
        require(st.scalar("""SELECT count(*) FROM summary_report_outbox WHERE tenant_id=$1
            AND created_at>clock_timestamp()-interval '1 hour'""", tenant, conn=conn) < 12,
            "Report preview limit reached. Try again later", 429)
        payload = build(st, tenant, conn)
        created = _insert(st, tenant, payload, "manual", "preview", cfg, conn)
        return {"report": payload, "expires_at": (created + timedelta(hours=1)).isoformat()}


def queue(st, tenant, data, actor, cfg):
    require(set(data) == {"report_id"} and isinstance(data["report_id"], str) and valid_uuid(data["report_id"]),
            "report_id is required")
    require(available(cfg, tenant), "Report sharing requires server setup", 409)
    with st.transaction() as conn:
        _lock(st, tenant, conn)
        rows = st.many("""SELECT *,created_at>clock_timestamp()-interval '1 hour' AS fresh
            FROM summary_report_outbox WHERE tenant_id=$1 AND id=$2 AND source='manual'""", tenant, data["report_id"], conn=conn)
        require(bool(rows), "Report preview not found", 404)
        row = rows[0]
        require(row["destination_sha256"] == destination(cfg), "Report destination changed. Preview again", 409)
        if row["status"] == "preview":
            require(row["fresh"], "Report preview expired. Preview again", 409)
            st.execute("UPDATE summary_report_outbox SET status='pending' WHERE id=$1", row["id"], conn=conn)
            _audit(st, tenant, actor, "summary_report.send", row["id"], {}, conn)
        else:
            require(row["status"] in ("pending", "sent"), "Report cannot be sent again. Preview a new report", 409)
        return {"report_id": row["id"], "status": "sent" if row["status"] == "sent" else "pending"}


class DeliveryError(Exception):
    def __init__(self, code, retryable=True):
        super().__init__(code)
        self.retryable = retryable


async def send(cfg, payload):
    try:
        async with asyncio.timeout(5), httpx.AsyncClient(timeout=5, follow_redirects=False, trust_env=False) as client:
            async with client.stream("POST", cfg.summary_report_origin + contract.PATH,
                    content=contract.encoded(payload), headers={"Content-Type": "application/json",
                    "Authorization": f"Bearer {cfg.tenant_id}.{cfg.summary_report_token}"}) as reply:
                if reply.status_code != 200:
                    raise DeliveryError("receiver_rejected", reply.status_code in (408, 429) or reply.status_code >= 500)
                content = bytearray()
                async for chunk in reply.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > 1024:
                        raise DeliveryError("invalid_receipt", False)
                if json.loads(content) != {"report_id": payload["report_id"], "sha256": contract.digest(payload)}:
                    raise DeliveryError("invalid_receipt", False)
    except (httpx.HTTPError, OSError, TimeoutError):
        raise DeliveryError("network_error") from None
    except (ValueError, RecursionError):
        raise DeliveryError("invalid_receipt", False) from None


def _schedule(st, cfg):
    tenant = cfg.tenant_id
    if not available(cfg, tenant):
        return False
    with st.transaction() as conn:
        if not _lock(st, tenant, conn, wait=False):
            return False
        if st.scalar("SELECT status FROM tenants WHERE id=$1", tenant, conn=conn) != "active":
            return False
        _prune(st, tenant, conn)
        st.execute("""UPDATE summary_report_outbox SET status='cancelled' WHERE tenant_id=$1
            AND status IN ('pending','preview') AND destination_sha256<>$2""", tenant, destination(cfg), conn=conn)
        setting = st.one("""SELECT *,next_report_at<=clock_timestamp() AS due
            FROM tenant_summary_report_settings WHERE tenant_id=$1""", tenant, conn=conn)
        if setting["automatic"] and setting["destination_sha256"] != destination(cfg):
            st.execute("""UPDATE tenant_summary_report_settings SET automatic=false,version=version+1,
                next_report_at=NULL WHERE tenant_id=$1""", tenant, conn=conn)
        elif setting["automatic"] and setting["due"]:
            _insert(st, tenant, build(st, tenant, conn), "automatic", "pending", cfg, conn)
            st.execute("""UPDATE tenant_summary_report_settings SET next_report_at=clock_timestamp()+interval '1 day'
                WHERE tenant_id=$1""", tenant, conn=conn)
    return True


def run_once(st, cfg):
    # Commit automatic snapshots before network I/O so a crash cannot change their IDs.
    if not _schedule(st, cfg):
        return False
    tenant = cfg.tenant_id
    with st.transaction() as conn:
        if not _lock(st, tenant, conn, wait=False):
            return False
        if st.scalar("SELECT status FROM tenants WHERE id=$1", tenant, conn=conn) != "active":
            return False
        rows = st.many("""SELECT *,created_at>clock_timestamp()-interval '1 day' AS fresh
            FROM summary_report_outbox WHERE tenant_id=$1 AND status='pending'
            AND next_attempt_at<=clock_timestamp() ORDER BY created_at,id LIMIT 1""", tenant, conn=conn)
        if not rows:
            return False
        row = rows[0]
        attempts = row["attempts"] + 1
        try:
            if not row["fresh"]:
                raise DeliveryError("expired", False)
            try:
                contract.validate(row["payload"])
            except APIError:
                raise DeliveryError("invalid_snapshot", False) from None
            asyncio.run(send(cfg, row["payload"]))
        except DeliveryError as exc:
            st.execute("""UPDATE summary_report_outbox SET attempts=$2,status=$3,error_code=$4,
                next_attempt_at=clock_timestamp()+make_interval(secs=>$5) WHERE id=$1""",
                row["id"], attempts, "pending" if exc.retryable and attempts < 8 else "failed",
                str(exc), min(3600, 30 * 2 ** min(attempts - 1, 7)), conn=conn)
        else:
            st.execute("UPDATE summary_report_outbox SET status='sent',attempts=$2,error_code='' WHERE id=$1",
                       row["id"], attempts, conn=conn)
            st.execute("UPDATE tenant_summary_report_settings SET last_sent_at=clock_timestamp() WHERE tenant_id=$1", tenant, conn=conn)
        _prune(st, tenant, conn)
        return True
