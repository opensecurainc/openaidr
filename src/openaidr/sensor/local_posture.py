"""Read bounded local inventory without scanning or contacting a service."""

import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone

from openaidr.core import ai_software
from .inventory_service import InventoryService

LIMIT = 200
MAX_BYTES = 600 << 10
STATUSES = ("ok", "partial", "error", "unavailable")
METADATA = ("description", "license", "repository_url", "source_url", "revision", "content_sha256")


def record_id(source, root, row):
    identity = [source, root, row.get("key")] if root else [
        source, row.get("identifier"), row.get("path"), row.get("architecture"), row.get("scope"),
    ]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode()).hexdigest()


def _item(row, location, stamp, *, native):
    fields = ("name", "kind", "path", "version", "publisher", "identifier")
    if not isinstance(row, dict) or any(not isinstance(row.get(key, ""), str) for key in fields):
        raise ValueError("Invalid cached installation")
    if not row.get("name") or row.get("kind") not in ("application", "package", "skill", "mcp_server", "plugin"):
        raise ValueError("Invalid cached installation")
    kind, source = row["kind"], location["source"]
    group = "apps" if native or kind == "application" else "skills" if kind == "skill" else "components"
    if group == "apps" and not ai_software.known_application(row.get("identifier", ""), row["name"], source):
        return None
    metadata = row.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise ValueError("Invalid cached metadata")
    safe = {key: metadata[key] for key in METADATA if isinstance(metadata.get(key), str)}
    tools = metadata.get("tools")
    if isinstance(tools, list) and len(tools) <= 128 and all(isinstance(value, str) and len(value) <= 256 for value in tools):
        safe["tools"] = tools
    scope = row.get("scope", "unknown") if native else location.get("scope", "unknown")
    item = {key: row.get(key, "") for key in fields if key != "identifier"}
    item.update(id=record_id(source, location.get("root", ""), row), source=source,
                scope=scope if scope in ("system", "user", "project", "unknown") else "unknown",
                last_seen_at=stamp, root_status=location["status"], metadata=safe,
                product=ai_software.application_product(row.get("identifier", ""), row["name"], source) if group == "apps" else None,
                approval_status="unavailable", assessment_status="disabled" if group == "skills" or (group == "components" and kind == "package") else "unsupported",
                attention=location["status"] != "ok", findings=[], findings_truncated=False)
    return group, item


def _locations(snapshot, components):
    if components:
        return snapshot["roots"]
    sources = snapshot["sources"]
    if len(sources) > 64 or any(not isinstance(row, dict) for row in sources):
        raise ValueError("Invalid cached sources")
    locations = {row["source"]: {**row, "components": []} for row in sources}
    for row in snapshot["applications"]:
        locations[row["source"]]["components"].append(row)
    return list(locations.values())


def read(config):
    groups = {name: {"items": [], "total": 0, "truncated": False} for name in ("apps", "components", "skills")}
    sources = {}

    def coverage(source, status, stamp, message=""):
        existing = sources.get(source)
        if existing:
            statuses = {existing["status"], status}
            status = ("ok" if statuses == {"ok"} else "partial" if statuses & {"ok", "partial"}
                      else "error" if "error" in statuses else "unavailable")
            stamp = min(existing["collected_at"], stamp) if existing["collected_at"] and stamp else None
            message = existing["message"] or message
        sources[source] = dict(source=source, status=status, collected_at=stamp, message=message)

    for components in (False, True):
        if not components and sys.platform == "darwin":
            continue
        service = InventoryService(config, None, components=components)
        source = "local-components" if components else "local-applications"
        if not service.options["enabled"]:
            coverage(source, "unavailable", None, "Local inventory collection is disabled or unsupported on this platform.")
            continue
        snapshot = service.state.get("snapshot")
        if not snapshot:
            coverage(source, "unavailable", None, "Waiting for a usable local scan.")
            continue
        stamp = snapshot["collected_at"]
        age = (datetime.now(timezone.utc) - service._timestamp(stamp)).total_seconds()
        stale = age < 0 or age >= service.options["interval_s"]
        try:
            locations = _locations(snapshot, components)
            if not locations:
                coverage(source, "unavailable", stamp, "The saved scan has no source coverage.")
            for location in locations:
                name = location["source"]
                if not isinstance(name, str) or not 0 < len(name) <= 80 or location["status"] not in STATUSES:
                    raise ValueError("Invalid cached source")
                status = "partial" if stale and location["status"] == "ok" else location["status"]
                location = {**location, "status": status}
                message = ("The saved scan is outside the collection interval." if stale else
                           "Some scan locations could not be checked completely." if status != "ok" else "")
                items = []
                for row in location["components"]:
                    try:
                        projected = _item(row, location, stamp, native=not components)
                        if projected:
                            items.append(projected)
                    except (ValueError, TypeError, KeyError):
                        status, message = "partial", "Some saved installation records could not be read."
                for group, item in items:
                    item.update(root_status=status, attention=status != "ok")
                    groups[group]["items"].append(item)
                coverage(name, status, stamp, message)
        except (ValueError, TypeError, KeyError, AttributeError):
            coverage(source, "unavailable", None, "The saved scan could not be read completely.")
    values = sorted(sources.values(), key=lambda row: row["source"])
    status = ("complete" if values and all(row["status"] == "ok" for row in values) else
              "unavailable" if not values or all(row["status"] == "unavailable" for row in values) else "partial")
    result = dict(schema_version=1, source="local", groups=groups,
                  collected_at=min((row["collected_at"] for row in values if row["collected_at"]), default=None),
                  coverage=dict(status=status, sources=values))
    from .posture_assessments import enabled, enrich

    try:
        result["assessments"] = enrich(config, groups)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        result["assessments"] = dict(enabled=enabled(config), state="unavailable", billing=None, usage=None)
    for group in groups.values():
        group["items"].sort(key=lambda row: (row["name"].lower(), row["id"]))
        group["total"] = len(group["items"])
        group["truncated"] = group["total"] > LIMIT
        del group["items"][LIMIT:]
    size = len(json.dumps(result, ensure_ascii=True).encode())
    while size > MAX_BYTES:
        group = max(groups.values(), key=lambda row: len(row["items"]))
        removed = group["items"].pop()
        size -= len(json.dumps(removed, ensure_ascii=True).encode()) + (2 if group["items"] else 0)
        group["truncated"] = True
    return result
