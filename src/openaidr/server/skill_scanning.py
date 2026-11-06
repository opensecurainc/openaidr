"""Tenant-owned skill bundles, durable scan leases, and inventory summaries."""

from . import customer_views

import secrets
import re
import time
import uuid
from datetime import timedelta

from psycopg.types.json import Jsonb

from openaidr.core.skill_bundle import validate_manifest, validate_files
from .component_inventory import _object, _reference
from .httpx import require, parse_time
from .store import new_id, now
from . import skill_llm
from .skill_reports import validate_report as validate_report

MAX_TENANT_BUNDLES = 10000
LEASE_SECONDS = 660
# A published usable report permits a new scan. Until then, even settled
# accounting cannot make an earlier service task safe to dispatch again.
HELD_SCAN = """(b.worker_protocol='skills-service-v1'
    AND EXISTS(SELECT 1 FROM service_call_intents i WHERE i.tenant_id=b.tenant_id
        AND i.service='skill_assessment' AND i.scope_id=b.lease_id
        AND ((i.outcome IS DISTINCT FROM 'failed'
            AND (b.status<>'complete' OR NOT COALESCE((b.report->>'complete')::boolean,false)))
            OR i.outcome IS NULL OR NOT EXISTS(SELECT 1 FROM service_credit_receipts r
                WHERE r.tenant_id=i.tenant_id AND r.request_id=i.request_id AND r.origin=i.origin
                AND r.api_tenant_id=i.api_tenant_id AND r.service=i.service
                AND r.state IN ('settled','released','disabled')))))"""


def receive(st, sensor, data, buffer, *, content=False, customer=False):
    _object(
        data,
        ("reference", "collected_at", "manifest", "sha256", "files"),
        "skill upload",
    )
    ref = data.get("reference")
    cid = _reference(sensor["id"], ref)
    require(ref["source"] == "openaidr-skills", "not a skill installation")
    try:
        manifest = data.get("manifest")
        sha, size = validate_manifest(manifest)
        observed_at = parse_time(data.get("collected_at", ""))
        if content:
            validate_files(manifest, data.get("files"))
    except (ValueError, TypeError, AttributeError) as exc:
        require(
            False, str(exc) if isinstance(exc, ValueError) else "Invalid skill upload"
        )
    require(sha == data.get("sha256"), "skill bundle hash mismatch")
    require(observed_at.tzinfo is not None, "collected_at requires a timezone")
    # Serialize queue admission and claims in this tenant server process. The
    # database transaction never receives file contents, even temporarily.
    with buffer.lock:
        buffer.prune()
        return _receive(st, sensor, data, buffer, cid, sha, size, observed_at, content, customer=customer)


def _needs_content(row, buffer, key):
    if key in buffer.items:
        return False
    if not row:
        return True
    if row["status"] == "running" and row["lease_until"] and row["lease_until"] > now():
        return False
    same_profile = buffer.profile is None or row["scanner_profile"] == buffer.profile
    report = row.get("report") or {}
    expired_intel = (report.get("mode") == "static" and report.get("intel_expires_at")
                     and parse_time(report["intel_expires_at"]) <= now())
    if (same_profile and row["status"] == "complete" and not expired_intel
            and (row["completed_at"] > now() - timedelta(days=1) or report.get("llm_cache"))):
        return False
    if same_profile and row["status"] == "failed" and (row["attempts"] >= 3 or row["retry_after"] > now()):
        return False
    return True


def _receive(st, sensor, data, buffer, cid, sha, size, observed_at, content, *, customer=False):
    tenant, sid = sensor["tenant_id"], sensor["id"]
    manifest = data["manifest"]
    key = (tenant, sha)
    staged = None
    with st.transaction() as conn:
        # Same lock order as inventory ingestion. Recheck revocation inside the write.
        active = st.one(
            "SELECT disabled,deleted_at FROM sensors WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            tenant,
            sid,
            conn=conn,
        )
        require(
            not active["disabled"] and active["deleted_at"] is None,
            "sensor is unavailable",
            403,
        )
        rows = st.many(
            "SELECT * FROM inventory_components WHERE tenant_id=$1 AND sensor_id=$2 AND id=$3 AND kind='skill' FOR UPDATE",
            tenant,
            sid,
            cid,
            conn=conn,
        )
        require(bool(rows), "skill installation not found", 404)
        component = rows[0]
        require(
            component["last_seen_at"] == observed_at,
            "inventory changed; collect again",
            409,
        )
        instructions = next(
            (
                f
                for f in manifest["files"]
                if f["path"] in ("SKILL.md", "skill.md") and "skip" not in f
            ),
            None,
        )
        if instructions:
            require(
                instructions["sha256"] == component["metadata"].get("content_sha256"),
                "skill instructions changed; collect again",
                409,
            )
        else:
            require(not manifest["complete"], "skill instructions are missing")
        # Serialize quota admission across sensors, without granting worker DB access.
        st.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,88))", tenant, conn=conn
        )
        retired = st.many(
            """SELECT b.sha256 FROM skill_bundles b WHERE b.tenant_id=$1 AND b.updated_at < now()-interval '7 days'
            AND NOT EXISTS(SELECT 1 FROM skill_installations i WHERE i.tenant_id=b.tenant_id AND i.sha256=b.sha256)
            AND (b.lease_until IS NULL OR b.lease_until < now()) FOR UPDATE OF b SKIP LOCKED""",
            tenant,
            conn=conn,
        )
        # Recheck intents in a fresh statement after acquiring the same bundle
        # locks used by service reservation. Do not race a just-admitted call.
        st.execute(f"DELETE FROM skill_bundles b WHERE b.tenant_id=$1 AND b.sha256=ANY($2::text[]) AND NOT {HELD_SCAN}",
                   tenant, [item["sha256"] for item in retired], conn=conn)
        existing = st.many(
            "SELECT * FROM skill_bundles WHERE tenant_id=$1 AND sha256=$2 FOR UPDATE",
            tenant,
            sha,
            conn=conn,
        )
        row = existing[0] if existing else None
        held = row and st.scalar(f"SELECT {HELD_SCAN} FROM skill_bundles b WHERE b.tenant_id=$1 AND b.sha256=$2",
                                 tenant, sha, conn=conn)
        needs_content = not held and _needs_content(row, buffer, key)
        llm_profile = (getattr(buffer, "llm_profile", None)
                       if customer and getattr(buffer, "llm_protocol", None) == "skills-service-v1" else None)
        if (not held and key not in buffer.items and skill_llm.pending(st, tenant, sha, conn=conn,
                customer=customer, profile=llm_profile)
                and not (row and row["status"] == "running" and row["lease_until"] and row["lease_until"] > now())):
            needs_content = True
        if content and needs_content:
            staged = (time.monotonic() + buffer.TTL, buffer.check_capacity(data["files"]), dict(data["files"]))
        if not existing:
            quota = st.one(
                "SELECT count(*) AS bundles FROM skill_bundles WHERE tenant_id=$1",
                tenant,
                conn=conn,
            )
            require(
                quota["bundles"] < MAX_TENANT_BUNDLES,
                "skill metadata quota reached",
                429,
            )
            st.execute(
                "INSERT INTO skill_bundles(tenant_id,sha256,manifest,content_bytes) VALUES($1,$2,$3,$4)",
                tenant,
                sha,
                Jsonb(manifest),
                size,
                conn=conn,
            )
        if staged is not None:
            st.execute(
                """UPDATE skill_bundles SET attempts=CASE WHEN status='complete' THEN 0 ELSE attempts END,
                lease_id=CASE WHEN worker_protocol='skills-service-v1' AND status='complete'
                    AND (report->>'complete')::boolean THEN NULL ELSE lease_id END,
                status='queued',updated_at=now()
                WHERE tenant_id=$1 AND sha256=$2""",
                tenant,
                sha,
                conn=conn,
            )
        st.execute(
            """INSERT INTO skill_installations(component_id,tenant_id,sensor_id,sha256,observed_at)
            VALUES($1,$2,$3,$4,$5) ON CONFLICT(component_id) DO UPDATE SET sha256=EXCLUDED.sha256,observed_at=EXCLUDED.observed_at""",
            cid,
            tenant,
            sid,
            sha,
            observed_at,
            conn=conn,
        )
    if staged is not None:
        buffer.items[key] = staged
    return {
        "sha256": sha,
        "needs_content": not content and needs_content,
    }


def claim(st, tenant, profile, buffer, *, llm_profile=None, model_binding=None,
          worker_protocol=skill_llm.LEGACY_PROTOCOL, customer=False):
    require(
        isinstance(profile, str) and 0 < len(profile) <= 256, "invalid scanner profile"
    )
    with buffer.lock:
        buffer.prune()
        buffer.profile = profile
        if llm_profile is not None:
            require(isinstance(llm_profile, str) and 0 < len(llm_profile) <= 256, "invalid LLM profile")
            buffer.llm_profile, buffer.llm_seen, buffer.llm_protocol = llm_profile, time.monotonic(), worker_protocol
            skill_llm.prepare(st, tenant, llm_profile, profile, customer=customer)
        result = _claim(st, tenant, profile, buffer, model_binding=model_binding, worker_protocol=worker_protocol)
        if result["job"] is not None:
            if llm_profile:
                skill_llm.attach(st, tenant, result["job"], llm_profile, customer=customer)
            # Transfer the only queued copy to the worker. A lost response or
            # crashed scan needs another sensor upload after its lease expires.
            result["job"]["files"] = buffer.items.pop((tenant, result["job"]["sha256"]))[2]
        return result


def _claim(st, tenant, profile, buffer, *, model_binding=None, worker_protocol=skill_llm.LEGACY_PROTOCOL):
    hashes = [sha for owner, sha in buffer.items if owner == tenant]
    with st.transaction() as conn:
        expired = st.many(
            """SELECT sha256 FROM skill_bundles
            WHERE tenant_id=$1 AND NOT (sha256=ANY($3::text[]))
            AND (status='queued' OR status='running' AND lease_until<=now()
                 OR status='complete' AND (scanner_profile<>$2
                     OR completed_at<now()-interval '1 day' AND NOT COALESCE((report->>'llm_cache')::boolean,false)
                     OR report->>'mode'='static' AND (report->>'intel_expires_at')::timestamptz<=now())
                 OR status='failed' AND scanner_profile<>$2) FOR UPDATE SKIP LOCKED""",
            tenant, profile, hashes, conn=conn,
        )
        st.execute(f"""UPDATE skill_bundles b SET status='awaiting_upload',lease_id=NULL,lease_until=NULL,
            attempts=CASE WHEN status='complete' THEN 0 ELSE attempts END
            WHERE b.tenant_id=$1 AND b.sha256=ANY($2::text[]) AND NOT {HELD_SCAN}""",
            tenant, [item["sha256"] for item in expired], conn=conn)
        rows = st.many(
            f"""SELECT b.* FROM skill_bundles b WHERE b.tenant_id=$1 AND b.sha256=ANY($3::text[])
            AND NOT {HELD_SCAN}
            AND (b.lease_until IS NULL OR b.lease_until < now())
            AND (b.scanner_profile<>$2 OR b.status='queued' OR b.status='running'
                 OR b.status='failed' AND b.attempts<3 AND b.retry_after<=now()
                 OR b.status='complete' AND (
                     b.completed_at < now()-interval '1 day' AND NOT COALESCE((b.report->>'llm_cache')::boolean,false)
                     OR b.report->>'mode'='static' AND (b.report->>'intel_expires_at')::timestamptz<=now()))
            AND EXISTS(SELECT 1 FROM skill_installations i JOIN inventory_components c ON c.id=i.component_id
                JOIN sensors s ON s.id=i.sensor_id WHERE i.tenant_id=b.tenant_id AND i.sha256=b.sha256
                AND i.observed_at=c.last_seen_at AND NOT s.disabled AND s.deleted_at IS NULL)
            ORDER BY b.updated_at,b.sha256 LIMIT 1 FOR UPDATE OF b SKIP LOCKED""",
            tenant,
            profile,
            hashes,
            conn=conn,
        )
        if not rows:
            return {"job": None}
        row = rows[0]
        if st.scalar(f"SELECT {HELD_SCAN} FROM skill_bundles b WHERE b.tenant_id=$1 AND b.sha256=$2",
                     tenant, row["sha256"], conn=conn):
            return {"job": None}
        lease = str(uuid.uuid4())
        attempts = (
            row["attempts"] + 1
            if row["scanner_profile"] == profile and row["status"] != "complete"
            else 1
        )
        # A repeatedly killed process must eventually stop consuming the queue.
        if attempts > 3:
            st.execute(
                "UPDATE skill_bundles SET status='failed',lease_until=NULL,error='Scanner repeatedly stopped before completion.',updated_at=now() WHERE tenant_id=$1 AND sha256=$2",
                tenant,
                row["sha256"],
                conn=conn,
            )
            buffer.items.pop((tenant, row["sha256"]), None)
            return {"job": None}
        st.execute(
            """UPDATE skill_bundles SET status='running',scanner_profile=$3,lease_id=$4,
            lease_until=$5,attempts=$6,model_connection_binding=$7,worker_protocol=$8,error='',updated_at=now() WHERE tenant_id=$1 AND sha256=$2""",
            tenant,
            row["sha256"],
            profile,
            lease,
            now() + timedelta(seconds=LEASE_SECONDS),
            attempts,
            model_binding,
            worker_protocol,
            conn=conn,
        )
        return {
            "job": {
                "sha256": row["sha256"],
                "lease_id": lease,
                "manifest": row["manifest"],
            }
        }


def complete(st, tenant, data, *, worker_protocol=skill_llm.LEGACY_PROTOCOL, model_binding=None):
    _object(data, ("sha256", "lease_id", "report", "error"), "scan result")
    sha, lease = data.get("sha256"), data.get("lease_id")
    require(isinstance(sha, str) and len(sha) == 64, "invalid bundle hash")
    try:
        uuid.UUID(lease)
    except (ValueError, TypeError, AttributeError):
        require(False, "invalid scan lease")
    error = data.get("error", "")
    require(
        error in ("", "timeout", "invalid_report", "scanner_failed"),
        "invalid scan failure",
    )
    report = None if error else validate_report(data.get("report"))
    messages = {
        "timeout": "Scan timed out.",
        "invalid_report": "Scanner returned an invalid report.",
        "scanner_failed": "Scanner did not finish successfully.",
    }
    with st.transaction() as conn:
        rows = st.many(
            "SELECT * FROM skill_bundles WHERE tenant_id=$1 AND sha256=$2 FOR UPDATE",
            tenant,
            sha,
            conn=conn,
        )
        require(bool(rows), "scan not found", 404)
        row = rows[0]
        require(row["worker_protocol"] == worker_protocol, "Scan worker protocol changed; finish the original lease.", 409)
        if worker_protocol != skill_llm.LEGACY_PROTOCOL:
            require(model_binding is not None and row["model_connection_binding"] == model_binding,
                    "Scan connection changed; finish the original lease.", 409)
            require(report is None or not {"model", "inference_usage", "usage_incomplete"}.intersection(report),
                    "Customer scan reports cannot contain private accounting.")
        require(
            str(row["lease_id"]) == lease
            and row["status"] == "running"
            and row["lease_until"] > now(),
            "scan lease expired",
            409,
        )
        if report:
            report["complete"] = report["complete"] and row["manifest"]["complete"]
        skill_llm.completed(st, tenant, sha, lease, report, conn=conn)
        st.execute(
            """UPDATE skill_bundles SET status=$3,report=COALESCE($4,report),error=$5,lease_until=NULL,
            completed_at=CASE WHEN $3='complete' THEN now() ELSE completed_at END,updated_at=now(),
            retry_after=now()+interval '5 minutes' WHERE tenant_id=$1 AND sha256=$2""",
            tenant,
            sha,
            "failed" if error else "complete",
            Jsonb(report) if report else None,
            messages.get(error, ""),
            conn=conn,
        )
    return {"accepted": True}


def worker_request(st, cfg, authorization, operation, data, buffer, *, customer=False):
    require(
        cfg.enabled("api") and cfg.tenant_id and cfg.skill_scanner_token,
        "scanner is disabled",
        404,
    )
    require(
        secrets.compare_digest(
            authorization.encode(), ("Bearer " + cfg.skill_scanner_token).encode()
        ),
        "invalid worker credential",
        401,
    )
    protocol = skill_llm.LEGACY_PROTOCOL
    if customer:
        from openaidr_api_client.client import Unavailable
        from . import service_skill_worker, service_skills

        try:
            service_skill_worker.contracts()
        except Unavailable:
            require(False, "Customer service SDK is unavailable", 503)
        protocol = service_skill_worker.PROTOCOL
    if operation == "model-key":
        require(False, "Provider credentials belong to the Intelligence service", 409)
    selected = skill_llm.model_connection(cfg, cfg.tenant_id, st) if operation in ("model-mode", "claim") else None
    if operation == "model-mode":
        require(data == {}, "model mode requests do not accept tenant selection")
        require(selected is not None, "Intelligence service is not configured", 503)
        return ({"service": "intelligence", "profile": service_skill_worker.PROFILE} if customer
                else {"service": "intelligence", "model": skill_llm.MODEL})
    if operation == "claim":
        if customer and data.get("llm_profile") is not None:
            require(data["llm_profile"] in {service_skill_worker.scanner_profile("llm", legacy=legacy) + ":metered-1"
                                            for legacy in (False, True)},
                    "Update the scanner for the customer analysis profile", 409)
        if selected or customer:
            require(data.get("model_protocol") == protocol, "Update the scanner for Intelligence model tasks", 409)
            require(selected is not None, "Intelligence service is not configured", 503)
            stored = st.scalar("SELECT EXISTS(SELECT 1 FROM tenant_intelligence_keys WHERE tenant_id=$1 AND origin=$2)",
                               cfg.tenant_id, selected.origin)
            require(not stored or data.get("intelligence_credentials") is True,
                    "Update the scanner before using saved Intelligence keys", 409)
        result = claim(st, cfg.tenant_id, data.get("profile"), buffer, llm_profile=data.get("llm_profile"),
                       model_binding=skill_llm.connection_binding(selected), worker_protocol=protocol, customer=customer)
        if selected and result.get("job"):
            result["job"]["model_service"] = True
            result["job"]["intelligence_origin"] = selected.origin
            from .intelligence import switchable

            if data.get("intelligence_credentials") is True and switchable(cfg, selected):
                result["job"]["intelligence_key"] = selected.api_key
        return result
    if operation in ("inference", "inference-bundle"):
        if customer:
            connection = skill_llm.lease_connection(st, cfg.tenant_id, cfg, data, protocol=protocol)
            try:
                return service_skills.assess(st, cfg.tenant_id, connection, data, bundle=operation == "inference-bundle")
            except Unavailable as error:
                require(False, "Skill Intelligence service unavailable.", error.status_code or 502)
        require(operation == "inference", "Use customer service tasks for this worker", 409)
        return skill_llm.inference(st, cfg.tenant_id, cfg, data)
    if operation == "model-call":
        require(not customer, "Use customer service tasks for this worker", 409)
        # Finish receipts for already admitted legacy requests after a mode
        # switch, but do not authorize a new direct-provider attempt.
        require("usage_id" in data, "Use pinned tasks through the Intelligence service", 409)
        return skill_llm.legacy_call(st, cfg.tenant_id, data)
    require(operation == "complete", "no such route", 404)
    if customer:
        connection = skill_llm.lease_connection(st, cfg.tenant_id, cfg, data, protocol=protocol)
        return complete(st, cfg.tenant_id, data, worker_protocol=protocol,
                        model_binding=skill_llm.connection_binding(connection))
    return complete(st, cfg.tenant_id, data)


# Only a bundle with complete collection can establish identity across devices.
BASE = """WITH copies AS (
    SELECT c.id,c.name,c.path,c.version,c.publisher,c.metadata,c.sensor_id,c.last_seen_at,
        s.hostname,s.disabled,r.scope,r.status AS root_status,
        b.sha256,b.content_bytes AS size_bytes,(b.manifest->>'complete')::boolean AS bundle_complete,
        b.manifest,b.report,b.completed_at,b.error,b.scanner_profile,
        CASE WHEN b.sha256 IS NOT NULL AND (b.manifest->>'complete')::boolean THEN b.sha256 ELSE c.id::text END AS skill_id,
        CASE WHEN b.sha256 IS NULL THEN 'pending'
             WHEN b.status='complete' AND (NOT (b.report->>'complete')::boolean OR r.status<>'ok') THEN 'partial'
             WHEN b.status='complete' AND (
                 b.completed_at < now()-interval '1 day' AND NOT COALESCE((b.report->>'llm_cache')::boolean,false)
                 OR (b.report->>'intel_expires_at')::timestamptz<=now()) THEN 'stale'
             ELSE b.status END AS scan_status,
        COALESCE((b.report->>'needs_attention')::boolean,false) AS needs_attention
    FROM inventory_components c JOIN inventory_roots r ON r.id=c.root_id AND r.tenant_id=c.tenant_id
    JOIN sensors s ON s.id=c.sensor_id AND s.tenant_id=c.tenant_id
    LEFT JOIN skill_installations i ON i.component_id=c.id AND i.tenant_id=c.tenant_id AND i.observed_at=c.last_seen_at
    LEFT JOIN skill_bundles b ON b.tenant_id=i.tenant_id AND b.sha256=i.sha256
    WHERE c.tenant_id=$1 AND c.kind='skill' AND s.deleted_at IS NULL
), aggregated AS (
    SELECT skill_id AS id,min(name) AS name,count(*)::int AS installations,count(DISTINCT sensor_id)::int AS devices,
        max(last_seen_at) AS last_seen_at,bool_or(needs_attention) AS needs_attention,
        CASE WHEN bool_or(scan_status='partial') THEN 'partial' ELSE min(scan_status) END AS scan_status,
        min(sha256) AS sha256,min(size_bytes) AS size_bytes,bool_and(bundle_complete) AS bundle_complete,
        array_agg(DISTINCT scope) AS scopes,
        bool_or(root_status<>'ok') AS collection_incomplete,
        CASE WHEN bool_and(scan_status='complete') THEN max((report->>'score')::int) END AS risk_score,
        max((report->>'score')::int) AS retained_score,
        string_agg(name||' '||path||' '||hostname,' ') AS search
    FROM copies GROUP BY skill_id
), grouped AS (
    SELECT g.*,CASE WHEN a.skill_id IS NULL THEN 'unapproved'
        WHEN a.approved IS NULL THEN 'monitoring'
        WHEN a.approved THEN 'approved' ELSE 'unapproved' END AS approval_status,
        a.updated_at AS approval_updated_at
    FROM aggregated g LEFT JOIN skill_reviews a ON a.tenant_id=$1 AND a.skill_id=g.id
        AND a.sha256 IS NOT DISTINCT FROM g.sha256
) """


def overview(st, tenant, query, enabled):
    summary = st.one(
        BASE
        + """SELECT count(*)::int AS installed,COALESCE(sum(installations),0)::int AS installations,
        count(*) FILTER(WHERE needs_attention)::int AS attention,
        count(*) FILTER(WHERE scan_status='complete')::int AS assessed,
        count(*) FILTER(WHERE scan_status<>'complete')::int AS pending,
        count(*) FILTER(WHERE scan_status IN ('partial','failed','stale'))::int AS incomplete FROM grouped""",
        tenant,
    )
    mode = query.get("status", "all")
    require(mode in ("all", "attention", "assessed", "pending"), "invalid skill status")
    review = query.get("review", "all")
    require(review in ("all", "approved", "unapproved", "monitoring"), "invalid skill review status")
    scope = query.get("scope", "all")
    require(scope in ("all", "user", "project", "system"), "invalid skill scope")
    order = query.get("sort", "id")
    require(order in ("id", "risk_asc", "risk_desc"), "invalid skill sort")
    search = query.get("q", "")
    require(len(search) <= 256, "search too long")
    cursor = query.get("cursor", "")
    require(len(cursor) <= 100, "invalid skill cursor")
    filters = """WHERE ($2='all' OR $2='attention' AND needs_attention
        OR $2='assessed' AND scan_status='complete' OR $2='pending' AND scan_status<>'complete')
        AND position(lower($3) in lower(search))>0 AND ($4='all' OR $4=ANY(scopes))
        AND ($5='all' OR approval_status=$5)"""
    args = [tenant, mode, search, scope, review]
    total = st.scalar(BASE + f"SELECT count(*)::int FROM grouped {filters}", *args)
    # Normalize both score directions to ascending keys, with missing scores last.
    # Include the key in the cursor so deletion or rescanning of its row is safe.
    sort_key = {
        "id": "0",
        "risk_asc": "COALESCE(retained_score,101)",
        "risk_desc": "COALESCE(-retained_score,1)",
    }[order]
    after = ""
    if cursor:
        key, ident = 0, cursor
        if order != "id":
            parts = cursor.split(":")
            require(len(parts) == 3 and parts[0] == order, "invalid skill cursor")
            try:
                key = int(parts[1])
            except ValueError:
                require(False, "invalid skill cursor")
            require(-100 <= key <= 101, "invalid skill cursor")
            ident = parts[2]
        require(
            0 < len(ident) <= 64 and all(c in "0123456789abcdef-" for c in ident),
            "invalid skill cursor",
        )
        args.extend((key, ident))
        after = f"AND ({sort_key},id)>($6::int,$7)"
    items = st.many(
        BASE
        + f"""SELECT id,name,installations,devices,last_seen_at,needs_attention,scan_status,sha256,size_bytes,bundle_complete,scopes,collection_incomplete,risk_score,retained_score,
        approval_status,approval_updated_at,{sort_key} AS sort_key
        FROM grouped {filters} {after} ORDER BY sort_key,id LIMIT 51""",
        *args,
    )
    next_cursor = ""
    if len(items) > 50:
        last = items[49]
        next_cursor = (
            last["id"] if order == "id" else f"{order}:{last['sort_key']}:{last['id']}"
        )
    for item in items:
        del item["sort_key"]
    return {
        "summary": summary,
        "enabled": enabled,
        "items": items[:50],
        "total": total,
        "next_cursor": next_cursor,
    }


def details(st, tenant, ident):
    require(isinstance(ident, str) and len(ident) <= 64, "invalid skill id")
    rows = st.many(
        BASE
        + """SELECT copies.*,grouped.scan_status AS group_scan_status,approval_status,approval_updated_at
        FROM copies JOIN grouped ON grouped.id=copies.skill_id
        WHERE skill_id=$2 ORDER BY hostname,copies.id LIMIT 201""",
        tenant,
        ident,
    )
    require(bool(rows), "skill not found", 404)
    first = rows[0]
    return {
        "id": ident,
        "approval_status": first["approval_status"],
        "approval_updated_at": first["approval_updated_at"],
        "name": first["name"],
        "sha256": first["sha256"],
        "size_bytes": first["size_bytes"],
        "bundle_complete": first["bundle_complete"],
        "manifest": first["manifest"],
        "metadata": first["metadata"],
        "report": customer_views.skill_report(first["report"]),
        "scan_status": first["group_scan_status"],
        "completed_at": first["completed_at"],
        "error": first["error"],
        "installations_truncated": len(rows) > 200,
        "installations": [
            {
                k: r[k]
                for k in (
                    "id",
                    "sensor_id",
                    "hostname",
                    "path",
                    "scope",
                    "version",
                    "root_status",
                    "last_seen_at",
                )
            }
            for r in rows[:200]
        ],
    }


def devices(st, tenant, ident):
    require(isinstance(ident, str) and 0 < len(ident) <= 64, "invalid skill id")
    require(st.scalar(BASE + "SELECT EXISTS(SELECT 1 FROM grouped WHERE id=$2)", tenant, ident),
            "skill not found", 404)
    # The details panel caps installations at 200. Notification recipients must
    # include every eligible device, independently of that panel and list filters.
    items = st.many(
        BASE + """SELECT sensor_id AS id,min(hostname) AS name,
        array_agg(DISTINCT version) FILTER(WHERE version<>'') AS versions
        FROM copies WHERE skill_id=$2 AND NOT disabled GROUP BY sensor_id ORDER BY min(hostname),sensor_id""",
        tenant, ident,
    )
    return {"id": ident, "items": [{**item, "versions": item["versions"] or []} for item in items]}


def save_approval(st, tenant, ident, data, actor):
    require(isinstance(ident, str) and 0 < len(ident) <= 64, "invalid skill id")
    require(set(data) == {"approved", "sha256"}
            and (data["approved"] is None or type(data["approved"]) is bool)
            and (data["sha256"] is None or isinstance(data["sha256"], str)
                 and re.fullmatch(r"[0-9a-f]{64}", data["sha256"])),
            "provide only approved (boolean or null) and the displayed bundle sha256 (string or null)")
    with st.transaction() as conn:
        st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                   "skill-approval:" + tenant + ":" + ident, conn=conn)
        rows = st.many(BASE + "SELECT * FROM grouped WHERE id=$2", tenant, ident, conn=conn)
        require(bool(rows), "skill not found", 404)
        item = rows[0]
        require(item["sha256"] == data["sha256"], "skill content changed; refresh before reviewing", 409)
        require(data["approved"] is not True or (item["bundle_complete"] and ident == item["sha256"]),
                "collect the complete skill bundle before approving", 409)
        row = st.one(
            """INSERT INTO skill_reviews(tenant_id,skill_id,sha256,approved) VALUES($1,$2,$3,$4)
            ON CONFLICT(tenant_id,skill_id) DO UPDATE SET sha256=EXCLUDED.sha256,
                approved=EXCLUDED.approved,updated_at=clock_timestamp()
            RETURNING skill_id AS id,approved,sha256,updated_at AS approval_updated_at""",
            tenant, ident, item["sha256"], data["approved"], conn=conn,
        )
        st.execute(
            """INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
            VALUES($1,$2,$3,$4,$5,'skill.approval','skill',$6,$7)""",
            new_id(), tenant, actor["type"], actor["id"], actor["name"], ident,
            Jsonb({"name": item["name"], "sha256": item["sha256"],
                   "before_status": item["approval_status"], "approved": data["approved"]}), conn=conn,
        )
    return row
