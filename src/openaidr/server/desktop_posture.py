"""Bounded device inventory and retained assessments for the desktop app."""

import hashlib
import json
from types import SimpleNamespace

from . import ai_inventory, app_inventory, component_inventory, osv, skill_scanning

LIMIT = 200
MAX_BYTES = 600 << 10
COMPONENT_KINDS = ("package", "mcp_server", "plugin")
METADATA = ("description", "license", "repository_url", "source_url", "revision", "content_sha256", "tools")


def _item(row):
    return {
        **{key: row.get(key) or "" for key in
           ("id", "name", "kind", "source", "path", "version", "publisher", "scope", "last_seen_at")},
        "product": None,
        "root_status": row.get("root_status", "unavailable"),
        "attention": False,
        "approval_status": "unavailable",
        "assessment_status": "unsupported",
        "findings": [],
        "findings_truncated": False,
        "metadata": {key: value for key, value in (row.get("metadata") or {}).items() if key in METADATA},
    }


def _findings(item, rows, *, skill=False):
    item["findings"] = [
        {"title": row.get("title" if skill else "id") or "Assessment finding",
         "detail": row.get("description" if skill else "summary") or ""}
        for row in rows[:10]
    ]
    item["findings_truncated"] = len(rows) > 10


def _coverage(st, tenant, sensor_id):
    sources = app_inventory.list_sources(st, tenant, sensor_id)
    roots = st.many("""SELECT source,
        CASE WHEN bool_and(status='ok') THEN 'ok'
            WHEN bool_or(status IN ('ok','partial')) THEN 'partial'
            WHEN bool_or(status='error') THEN 'error' ELSE 'unavailable' END AS status,
        min(collected_at) AS collected_at,
        count(*) FILTER(WHERE status<>'ok') AS incomplete
        FROM inventory_roots WHERE tenant_id=$1 AND sensor_id=$2
        GROUP BY source ORDER BY source""", tenant, sensor_id)
    # Component coverage is more precise than the compatibility application view.
    by_source = {row["source"]: {key: row[key] for key in ("source", "status", "collected_at")}
                 | {"message": "" if row["status"] == "ok" else "Application collection is incomplete."}
                 for row in sources}
    for row in roots:
        by_source[row["source"]] = {key: row[key] for key in ("source", "status", "collected_at")}
        by_source[row["source"]]["message"] = (
            f"{row['incomplete']} scan locations could not be checked completely." if row["incomplete"] else ""
        )
    values = sorted(by_source.values(), key=lambda row: row["source"])
    status = ("unavailable" if not values else "complete" if all(row["status"] == "ok" for row in values)
              else "partial")
    return {"status": status, "sources": values}


def _apps(st, tenant, sensor_id, coverage):
    filters = {"sensor_id": sensor_id, "category": "ai", "include_helpers": "false"}
    rows, _ = app_inventory.list_applications(st, tenant, filters, LIMIT)
    total = app_inventory.category_counts(st, tenant, filters)["ai"]
    approvals = ai_inventory.approval_records(st, tenant)
    sources = {row["source"]: row["status"] for row in coverage["sources"]}
    items = []
    for row in rows:
        item = _item(row)
        product = ai_inventory.application_product(row["identifier"], row["name"], row["source"])
        product = product or "app-" + hashlib.sha256(row["identifier"].lower().encode()).hexdigest()
        decision = approvals.get(product)
        approval = ("unapproved" if decision is None else "monitoring" if decision["approved"] is None
                    else "approved" if decision["approved"] else "unapproved")
        item.update(product=product, root_status=sources.get(row["source"], "unavailable"), approval_status=approval)
        item["attention"] = item["approval_status"] == "unapproved" or item["root_status"] != "ok"
        items.append(item)
    return dict(items=items, total=total, truncated=total > len(items))


def _components(st, tenant, sensor_id, enabled):
    rows = []
    for kind in COMPONENT_KINDS:
        page, _ = component_inventory.list_inventory(
            st, tenant, "components", {"sensor_id": sensor_id, "kind": kind}, LIMIT,
        )
        rows.extend(page)
    rows.sort(key=lambda row: (row["name"].lower(), row["id"]))
    rows = rows[:LIMIT]
    total = st.scalar("""SELECT count(*) FROM inventory_components
        WHERE tenant_id=$1 AND sensor_id=$2 AND kind=ANY($3::text[])""", tenant, sensor_id, list(COMPONENT_KINDS))
    osv.enrich(st, tenant, rows, enabled)
    items = []
    for row in rows:
        item = _item(row)
        assessment = row["vulnerability"]
        item["assessment_status"] = (
            "disabled" if not enabled else
            {"not_assessed": "unsupported", "unavailable": "failed"}.get(assessment["status"], assessment["status"])
        )
        _findings(item, assessment["findings"])
        item["attention"] = bool(assessment["findings"]) or item["root_status"] != "ok" or item["assessment_status"] in ("failed", "stale")
        items.append(item)
    return dict(items=items, total=total, truncated=total > len(items))


def _skills(st, tenant, sensor_id, enabled):
    # Filter installation copies before projecting. Never return the dashboard's
    # tenant-wide aggregate, other devices' paths, report internals, or manifests.
    rows = st.many(skill_scanning.BASE + """SELECT c.*,a.approved,a.skill_id AS reviewed_id
        FROM copies c LEFT JOIN skill_reviews a ON a.tenant_id=$1 AND a.skill_id=c.skill_id
            AND a.sha256 IS NOT DISTINCT FROM c.sha256
        WHERE c.sensor_id=$2 ORDER BY left(lower(c.name),256),c.id LIMIT $3""", tenant, sensor_id, LIMIT)
    total = st.scalar("""SELECT count(*) FROM inventory_components
        WHERE tenant_id=$1 AND sensor_id=$2 AND kind='skill'""", tenant, sensor_id)
    items = []
    for row in rows:
        item = _item({**row, "kind": "skill", "source": "openaidr-skills"})
        current = row["sha256"] is not None and row["bundle_complete"] is True
        if current:
            item["approval_status"] = (
                "unapproved" if row["reviewed_id"] is None else "monitoring" if row["approved"] is None
                else "approved" if row["approved"] else "unapproved"
            )
        item["assessment_status"] = (
            "disabled" if not enabled else
            "pending" if row["scan_status"] in ("awaiting_upload", "queued", "running", "pending") else row["scan_status"]
        )
        report = row["report"] or {}
        _findings(item, report.get("issues", []), skill=True)
        item["attention"] = (bool(row["needs_attention"]) or item["approval_status"] == "unapproved"
                             or item["root_status"] != "ok" or item["assessment_status"] in ("partial", "failed", "stale"))
        items.append(item)
    return dict(items=items, total=total, truncated=total > len(items))


def _overview(st, sensor, osv_enabled, skills_enabled):
    tenant, sensor_id = sensor["tenant_id"], sensor["id"]
    coverage = _coverage(st, tenant, sensor_id)
    result = {
        "schema_version": 1,
        # The oldest scan is deliberate: a recent source cannot hide an older one.
        "collected_at": min((row["collected_at"] for row in coverage["sources"]), default=None),
        "groups": {
            "apps": _apps(st, tenant, sensor_id, coverage),
            "components": _components(st, tenant, sensor_id, osv_enabled),
            "skills": _skills(st, tenant, sensor_id, skills_enabled),
        },
        "coverage": coverage,
    }
    # Budget JSON as ASCII because the sensor bridge re-encodes the response.
    # Keep full fields intact and remove records instead of cutting evidence text.
    groups = list(result["groups"].values())
    size = len(json.dumps(result, default=str, ensure_ascii=True).encode())
    while size > MAX_BYTES:
        group = max(groups, key=lambda value: len(value["items"]))
        removed = group["items"].pop()
        size -= len(json.dumps(removed, default=str, ensure_ascii=True).encode()) + (2 if group["items"] else 0)
        group["truncated"] = True
    return result


def overview(st, sensor, *, osv_enabled=True, skills_enabled=False):
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        conn.execute("SET LOCAL statement_timeout='5s'")
        # Bind the existing inventory helpers to one snapshot so scan ingestion
        # cannot change counts or approval evidence between the page's queries.
        reader = SimpleNamespace(
            many=lambda query, *args, **kwargs: st.many(query, *args, conn=conn),
            one=lambda query, *args, **kwargs: st.one(query, *args, conn=conn),
            scalar=lambda query, *args, **kwargs: st.scalar(query, *args, conn=conn),
        )
        return _overview(reader, sensor, osv_enabled, skills_enabled)
