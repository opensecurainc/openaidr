"""Application review uses installed software and distinct endpoint identities."""

import hashlib
import json
import posixpath
from collections import Counter
from contextlib import nullcontext

from psycopg.types.json import Jsonb

from . import ai_inventory, ai_software, app_inventory
from .httpx import require
from .store import now


def _identity(row):
    identifier = row["identifier"].lower()
    if row["source"] == "openaidr-cli":
        ecosystem, _, package = identifier.partition(":")
        if ecosystem in ai_inventory.PACKAGE_PRODUCTS:
            return (ai_inventory.PACKAGE_PRODUCTS[ecosystem].get(package)
                    or "app-" + hashlib.sha256(identifier.encode()).hexdigest())
        return "app-" + hashlib.sha256(("cli:" + identifier).encode()).hexdigest()
    if row["ecosystem"]:
        known = ai_inventory.PACKAGE_PRODUCTS.get(row["ecosystem"], {}).get(identifier)
    else:
        known = ai_inventory.application_product(identifier, row["name"], row["source"])
    if known:
        return known
    # Preserve identities used by the existing AI approval API.
    if not row["ecosystem"] and identifier.startswith(ai_software.IDENTIFIER_PREFIXES):
        return "app-" + hashlib.sha256(identifier.encode()).hexdigest()
    namespace = row["ecosystem"] or ("macos" if row["source"] in ("macos-spotlight", "osquery-apps") else row["source"])
    return "app-" + hashlib.sha256((namespace + ":" + identifier).encode()).hexdigest()


def observed(st, tenant, *, conn=None):
    rows = st.many(
        f"""{app_inventory.APPLICATION_RECORDS}
        SELECT a.identifier,a.name,a.publisher,a.version,a.source,'' AS ecosystem,
            a.kind,a.path,a.scope,'' AS root,'' AS environment,
            a.sensor_id,s.hostname,s.os,a.last_seen_at,h.latest_signed_in_user AS endpoint_user
        FROM applications a JOIN sensors s ON s.id=a.sensor_id AND s.tenant_id=a.tenant_id
        JOIN sensor_activity h ON h.sensor_id=s.id
        WHERE a.tenant_id=$1 AND s.deleted_at IS NULL
        UNION ALL
        SELECT c.identifier,c.name,c.publisher,c.version,r.source,c.ecosystem,
            c.kind,c.path,r.scope,r.root,r.environment,
            c.sensor_id,s.hostname,s.os,c.last_seen_at,h.latest_signed_in_user AS endpoint_user
        FROM inventory_components c
        JOIN inventory_roots r ON r.id=c.root_id AND r.tenant_id=c.tenant_id AND r.sensor_id=c.sensor_id
        JOIN sensors s ON s.id=c.sensor_id AND s.tenant_id=c.tenant_id
        JOIN sensor_activity h ON h.sensor_id=s.id
        WHERE c.tenant_id=$1 AND s.deleted_at IS NULL AND c.kind='package' AND c.evidence='installed'
        ORDER BY name,identifier,source,version""",
        tenant, conn=conn,
    )
    products = {}
    for row in rows:
        product = _identity(row)
        item = products.setdefault(product, {
            "id": product, "name": ai_inventory.PRODUCT_NAMES.get(product, row["name"]),
            "evidence": [], "devices": {}, "is_builtin": True, "has_native_app": False, "general_purpose": True,
            "unidentified_cli": True,
        })
        # Collector identifiers can fall back to paths. Never send those paths,
        # device names, account identities, or installation locations to a model.
        identifier = row["identifier"]
        if identifier.startswith(("/", "~", "\\")) or ":\\" in identifier:
            identifier = ""
        evidence = {key: row[key] for key in ("name", "publisher", "ecosystem", "source")}
        evidence["identifier"] = identifier
        builtin = (row["source"] in ("macos-spotlight", "osquery-apps")
                   and posixpath.normpath(row["path"]).startswith("/System/"))
        item["is_builtin"] = item["is_builtin"] and builtin
        item["general_purpose"] = item["general_purpose"] and not row["ecosystem"] and (
            row["identifier"].lower() in ai_software.GENERAL_PURPOSE_IDENTIFIERS)
        item["has_native_app"] = item["has_native_app"] or (
            row["kind"] == "application" and row["source"] != "openaidr-cli")
        item["unidentified_cli"] = item["unidentified_cli"] and (
            row["source"] == "openaidr-cli" and row["identifier"].startswith("executable:"))
        if evidence not in item["evidence"]:
            item["evidence"].append(evidence)
        device = item["devices"].setdefault(str(row["sensor_id"]), {
            "id": str(row["sensor_id"]), "name": row["hostname"], "os": row["os"],
            "versions": set(), "last_seen_at": row["last_seen_at"], "user": row["endpoint_user"],
            "installations": [],
        })
        installation = {key: row[key] for key in (
            "name", "identifier", "publisher", "version", "source", "ecosystem",
            "kind", "path", "scope", "root", "environment",
        )}
        if installation not in device["installations"]:
            device["installations"].append(installation)
        if row["version"]:
            device["versions"].add(row["version"])
        device["last_seen_at"] = max(device["last_seen_at"], row["last_seen_at"])
    for item in products.values():
        item["evidence"].sort(key=lambda value: json.dumps(value, sort_keys=True))
        # Bound per-product metadata, independent of the number of installations.
        item["evidence"] = item["evidence"][:16]
        item["evidence_hash"] = hashlib.sha256(json.dumps(item["evidence"], sort_keys=True).encode()).hexdigest()
        item["devices"] = sorted(item["devices"].values(), key=lambda device: (device["name"].lower(), device["id"]))
        for device in item["devices"]:
            device["versions"] = sorted(device["versions"])
            device["installations"].sort(key=lambda value: json.dumps(value, sort_keys=True))
    return products


def sync(st, tenant, products, *, conn=None):
    # A command's filename alone cannot identify its publisher or AI purpose.
    products = {key: item for key, item in products.items() if not item["unidentified_cli"]}
    with st.transaction() if conn is None else nullcontext(conn) as conn:
        st.execute(
            """INSERT INTO application_classifications(tenant_id,product_id,evidence_hash,evidence)
            SELECT $1,p.id,p.evidence_hash,p.evidence FROM jsonb_to_recordset($2::jsonb)
                AS p(id text,evidence_hash text,evidence jsonb)
            ON CONFLICT(tenant_id,product_id) DO UPDATE SET
                evidence_hash=EXCLUDED.evidence_hash,evidence=EXCLUDED.evidence,
                needs_attention=NULL,category=NULL,software_type=NULL,display_name='',
                reason='',sources='[]',checked_at=NULL,assessment=NULL,assessment_checked_at=NULL,
                next_attempt_at=clock_timestamp(),claim_token=NULL,lease_until=NULL,last_error=''
            WHERE application_classifications.evidence_hash<>EXCLUDED.evidence_hash""",
            tenant, Jsonb([{key: item[key] for key in ("id", "evidence_hash", "evidence")}
                           for item in products.values()]), conn=conn,
        )
        # Do not keep researching software that is no longer observed. Approval
        # choices live separately and survive removal and later reinstallation.
        st.execute("DELETE FROM application_classifications WHERE tenant_id=$1 AND NOT(product_id=ANY($2::text[]))",
                   tenant, list(products), conn=conn)


def _user_counts(devices):
    counts = Counter(device["user"] for device in devices)
    return [{"user": user, "device_count": counts[user]}
            for user in sorted(counts, key=lambda user: (user == "", user.lower(), user))]


def _software_type(item, classification):
    evidence = item["evidence"]
    if evidence and all(row["identifier"].lower() in ai_software.HELPER_IDENTIFIERS
                        or row["name"].lower() in ai_software.HELPER_NAMES for row in evidence):
        return "helper"
    if classification and classification["software_type"]:
        return classification["software_type"]
    if item["has_native_app"]:
        return "application"
    if any(row["source"] == "openaidr-cli" for row in evidence):
        return "command_line_tool"
    if item["id"] in {product for products in ai_inventory.PACKAGE_PRODUCTS.values()
                       for product in products.values()}:
        return "command_line_tool"
    return "package"


def _review_context(item, software_type, attention, approval):
    if attention is False:
        return False, "The available evidence identifies ordinary software."
    if approval:
        return True, ("This software is monitored by the organization." if approval["approved"] is None
                      else "An organization approval decision is recorded for this software.")
    if item["is_builtin"]:
        return False, "Reported in the operating system's built-in application location."
    if software_type == "package":
        return False, "Package role is unconfirmed. Inspect its installation environment before taking action."
    if software_type in ("library", "helper", "system_component"):
        return False, "Review this supporting software in its installation or package environment."
    recognized_ai = item["id"] in ai_inventory.PRODUCT_NAMES or any(
        entry["identifier"].lower().startswith(ai_software.IDENTIFIER_PREFIXES)
        or entry["name"].lower() in ai_software.NAMES for entry in item["evidence"])
    if attention is None and not recognized_ai:
        return False, "AI purpose is unconfirmed. Inspect this software in the full inventory."
    return True, "Review whether this AI application is permitted by your organization."


def overview(st, tenant, cfg):
    from .intelligence import selected_connection

    products = observed(st, tenant)
    classifications = {row["product_id"]: row for row in st.many(
        "SELECT * FROM application_classifications WHERE tenant_id=$1", tenant,
    )}
    generated_at = now()
    approvals = ai_inventory.approval_records(st, tenant)
    items = []
    for product, item in products.items():
        classification = None if item["unidentified_cli"] else classifications.get(product)
        current = classification and classification["evidence_hash"] == item["evidence_hash"]
        attention = False if item["general_purpose"] else classification["needs_attention"] if current else None
        # Old workers can still write during rollout or rollback. Their newer
        # classification must not inherit an assessment from a different result.
        assessment = (classification["assessment"] if current and not item["general_purpose"] and classification["checked_at"]
                      and classification["assessment_checked_at"] == classification["checked_at"] else None)
        research_status = "queued"
        if current:
            risk = (classification["assessment"] or {}).get("risk", {})
            needs_enrichment = (classification["needs_attention"] is not False
                                and classification["software_type"] in (None, "application", "command_line_tool")
                                and ((risk.get("score") is None and "provisional_score" not in risk)
                                     or "report" not in (classification["assessment"] or {})))
            if classification["lease_until"] and classification["lease_until"] > generated_at:
                research_status = "researching"
            elif classification["last_error"]:
                research_status = "retry_pending"
            elif (classification["checked_at"] and classification["assessment"]
                  and classification["assessment_checked_at"] == classification["checked_at"]
                  and not needs_enrichment
                  and classification["next_attempt_at"] > generated_at):
                research_status = "complete"
        approval = approvals.get(product)
        software_type = _software_type(item, classification if current else None)
        if (assessment and any(assessment.get("risk", {}).get(key) is not None
                               for key in ("score", "provisional_score"))
                and software_type not in ("application", "command_line_tool")):
            # Exact helper identities override model type guesses at read time.
            assessment = {**assessment, "risk": {
                "score": None, "provisional_score": None, "sources": [],
                "reason": "This installation is supporting software, so an AI application risk score does not apply.",
            }}
        review_required, review_reason = _review_context(item, software_type, attention, approval)
        if item["unidentified_cli"]:
            research_status = "complete"
            review_required = bool(approval)
            review_reason = "Executable found; product identity is unconfirmed."
        items.append({
            "id": product, "name": item["name"], "device_count": len(item["devices"]),
            "display_name": item["name"] if product in ("codex", "chatgpt") else (classification["display_name"] if current else "") or item["name"],
            "reported_names": sorted({entry["name"] for device in item["devices"] for entry in device["installations"]}),
            "approval_scope": "Approval covers all recognized Codex desktop app and CLI installations." if product == "codex" else "",
            "approval_conflict": bool(approval and approval["approval_conflict"]),
            "software_type": software_type, "is_builtin": item["is_builtin"],
            "review_required": review_required, "review_reason": review_reason,
            "users": _user_counts(item["devices"]),
            "needs_attention": attention is not False,
            "category": "ordinary" if item["general_purpose"] else classification["category"] if current else None,
            "assessment": assessment,
            "research_status": research_status,
            "assessment_status": (
                "needs_identification" if item["unidentified_cli"] else
                ("stale" if classification["last_error"] else "complete")
                if assessment and assessment["capability_score"] is not None else
                "needs_identification" if assessment else
                "unavailable" if current and classification["last_error"] else "pending"),
            "classification_status": ("unknown" if item["unidentified_cli"] else
                                      "complete" if item["general_purpose"] else
                                      "stale" if attention is not None and classification["last_error"] else
                                      "complete" if attention is not None else
                                      "unavailable" if current and classification["last_error"] else
                                      "unknown" if current and classification["checked_at"] else "pending"),
            "reason": (review_reason if item["unidentified_cli"] else
                       "General-purpose software with optional AI features stays outside AI review."
                       if item["general_purpose"] else classification["reason"] if current else ""),
            "sources": classification["sources"] if current and not item["general_purpose"] else [],
            "checked_at": classification["checked_at"] if current else None,
            "approval_status": ("approved" if approval["approved"] else "unapproved")
                if approval and approval["approved"] is not None else "monitoring",
            "approval_updated_at": approval["updated_at"] if approval else None,
        })
    items.sort(key=lambda item: (-sum(bool(entry["user"]) for entry in item["users"]), item["name"].lower(), item["id"]))
    all_devices = {device["id"]: device for product in products.values() for device in product["devices"]}
    configured = False
    if cfg.application_classification:
        connection = selected_connection(cfg, st)
        configured = connection is not None and connection.tenant_id == str(tenant)
    return {
        "items": items, "generated_at": generated_at,
        "device_count": len(all_devices), "users": _user_counts(all_devices.values()),
        "classifier_configured": configured,
    }


def devices(st, tenant, product):
    requested = product
    product = ai_inventory.approval_product(st, tenant, product)
    item = observed(st, tenant).get(product)
    require(item is not None, "application not found", 404)
    return {"id": requested, "name": item["name"], "items": item["devices"]}


def save_approval(st, tenant, product, data, actor):
    require(isinstance(data, dict) and set(data) == {"approved"}
            and (data["approved"] is None or type(data["approved"]) is bool),
            "approved must be a boolean or null and the only request field")
    requested = product
    product = ai_inventory.approval_product(st, tenant, product)
    item = observed(st, tenant).get(product)
    require(item is not None, "application not found", 404)
    return ai_inventory.persist_approval(st, tenant, item, data["approved"], actor) | {"id": requested}
