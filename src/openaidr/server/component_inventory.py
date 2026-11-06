"""Component snapshots with coverage and reconciliation for each discovery root."""

import json
import uuid
from datetime import timedelta
from urllib.parse import urlsplit

from psycopg.types.json import Jsonb

from .app_inventory import FIELDS, STATUSES, _text, decode_cursor, encode_cursor
from .httpx import parse_time, require, uuid_param
from .store import now

# Sources describe the collector contract, not a claim about registry origin.
SOURCES = {
    "osquery-apps": ("application", ""),
    "osquery-npm-packages": ("package", "npm"),
    "osquery-python-packages": ("package", "pypi"),
    "openaidr-skills": ("skill", ""),
    "openaidr-mcp-servers": ("mcp_server", ""),
    "openaidr-plugins": ("plugin", ""),
    "openaidr-cli": ("application", ""),
}
EVIDENCE = ("installed", "declared", "configured", "observed")
RELATIONS = ("depends_on", "configured_with", "provides")
METADATA = {
    "description": 2048,
    "license": 1024,
    "repository_url": 2048,
    "source_url": 2048,
    "revision": 256,
    "integrity": 1024,
    "content_sha256": 64,
}
ROOT_FIELDS = {
    "source",
    "root",
    "scope",
    "user",
    "environment",
    "status",
    "message",
    "components",
    "relationships",
}


def _object(value, fields, label):
    require(isinstance(value, dict), f"invalid {label}")
    require(set(value) <= set(fields), f"unknown {label} field")
    return value


def _id(namespace, *parts):
    return str(uuid.uuid5(uuid.UUID(namespace), json.dumps(parts, ensure_ascii=True)))


def _reference(sensor_id, ref):
    _object(ref, ("source", "root", "key"), "component reference")
    source = _text(ref, "source", 64, True)
    require(source in SOURCES, "unknown inventory source")
    root = _text(ref, "root", 8192, True)
    key = _text(ref, "key", 2048, True)
    return _id(_id(sensor_id, "root", source, root), "component", key)


def _metadata(value):
    _object(value, (*METADATA, "tools"), "metadata")
    result = {key: _text(value, key, METADATA[key]) for key in value if key in METADATA}
    for key in ("repository_url", "source_url"):
        url = result.get(key, "")
        if not url:
            continue
        try:
            parts = urlsplit(url)
            valid = (
                parts.scheme in ("http", "https")
                and parts.hostname
                and parts.username is None
                and parts.password is None
                and not parts.query
                and not parts.fragment
                and not any(c.isspace() or ord(c) < 32 for c in url)
            )
            parts.port  # Validate the port before accepting the URL.
        except ValueError:
            valid = False
        require(valid, f"{key} must be HTTP(S) without credentials, query or fragment")
    digest = result.get("content_sha256", "")
    require(
        not digest
        or (len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)),
        "content_sha256 must be a lowercase SHA-256 digest",
    )
    if "tools" in value:
        tools = value["tools"]
        require(
            isinstance(tools, list) and len(tools) <= 128,
            "tools must contain at most 128 entries",
        )
        result["tools"] = list(
            dict.fromkeys(_text({"tool": tool}, "tool", 256, True) for tool in tools)
        )
    return result


def validate_snapshot(sensor_id, data):
    _object(
        data,
        ("schema_version", "collected_at", "platform", "roots", "sensor_id"),
        "snapshot",
    )
    require(
        type(data.get("schema_version")) is int and data["schema_version"] == 1,
        "schema_version must be 1",
    )
    try:
        collected_at = parse_time(_text(data, "collected_at", 64, True))
    except (ValueError, OverflowError):
        require(False, "collected_at must be a UTC timestamp")
    require(
        collected_at.tzinfo is not None and collected_at.utcoffset() == timedelta(0),
        "collected_at must be a UTC timestamp",
    )
    require(
        collected_at <= now() + timedelta(minutes=5),
        "collected_at is more than five minutes in the future",
    )
    platform = _text(data, "platform", 64, True)
    require(
        platform in ("darwin", "linux", "windows"), "unsupported inventory platform"
    )
    roots = data.get("roots")
    require(
        isinstance(roots, list) and len(roots) <= 256,
        "roots must contain at most 256 entries",
    )
    coverage = {}
    component_count = relationship_count = 0
    for row in roots:
        _object(row, ROOT_FIELDS, "root")
        source = _text(row, "source", 64, True)
        require(source in SOURCES, "unknown inventory source")
        root = _text(row, "root", 8192, True)
        root_id = _id(sensor_id, "root", source, root)
        require(root_id not in coverage, "duplicate inventory root")
        status = _text(row, "status", 32, True)
        require(status in STATUSES, "invalid root status")
        scope = _text(row, "scope", 32, True)
        require(scope in ("system", "user", "project", "unknown"), "invalid root scope")
        entry = dict(
            source=source,
            root=root,
            scope=scope,
            status=status,
            user=_text(row, "user", 256),
            environment=_text(row, "environment", 8192),
            message=_text(row, "message", 2048),
            components={},
            relationships={},
        )
        components, relationships = row.get("components"), row.get("relationships")
        require(
            isinstance(components, list) and isinstance(relationships, list),
            "components and relationships must be arrays",
        )
        component_count += len(components)
        relationship_count += len(relationships)
        require(
            component_count <= 10000 and relationship_count <= 20000,
            "snapshot exceeds component or relationship limit",
        )
        require(
            status in ("ok", "partial") or not (components or relationships),
            "failed or unavailable roots cannot report records",
        )
        for item in components:
            _object(
                item,
                (*FIELDS, "key", "kind", "ecosystem", "evidence", "metadata"),
                "component",
            )
            key = _text(item, "key", 2048, True)
            component = {
                field: _text(item, field, limit, field in ("identifier", "name"))
                for field, limit in FIELDS.items()
            }
            kind, ecosystem = (
                _text(item, "kind", 32, True),
                _text(item, "ecosystem", 32),
            )
            require(
                (kind, ecosystem) == SOURCES[source],
                "component kind and ecosystem must match its source",
            )
            evidence = _text(item, "evidence", 32, True)
            require(evidence in EVIDENCE, "invalid component evidence")
            component.update(
                key=key,
                kind=kind,
                ecosystem=ecosystem,
                evidence=evidence,
                metadata=_metadata(item.get("metadata", {})),
            )
            component_id = _id(root_id, "component", key)
            previous = entry["components"].get(component_id)
            require(
                previous is None or previous == component,
                "conflicting duplicate component key",
            )
            entry["components"][component_id] = component
        for item in relationships:
            _object(item, ("from", "to", "kind", "evidence", "path"), "relationship")
            relationship = dict(
                from_component_id=_reference(sensor_id, item.get("from")),
                to_component_id=_reference(sensor_id, item.get("to")),
                kind=_text(item, "kind", 32, True),
                evidence=_text(item, "evidence", 32, True),
                path=_text(item, "path", 8192),
            )
            require(relationship["kind"] in RELATIONS, "invalid relationship kind")
            require(
                relationship["evidence"] in ("declared", "configured", "observed"),
                "invalid relationship evidence",
            )
            identity = _id(root_id, "relationship", *relationship.values())
            entry["relationships"][identity] = relationship
        coverage[root_id] = entry
    return collected_at, platform, coverage


def ingest_snapshot(st, sensor, data):
    require(not sensor["disabled"], "sensor is disabled", 403)
    require(
        "sensor_id" not in data or data["sensor_id"] == sensor["id"],
        "snapshot sensor_id does not match the token",
        403,
    )
    tenant, sid = sensor["tenant_id"], sensor["id"]
    collected_at, platform, coverage = validate_snapshot(sid, data)
    with st.transaction() as conn:
        # Serialize with inventory uploads and sensor disable/delete operations.
        current = st.one(
            "SELECT disabled,deleted_at FROM sensors WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            tenant,
            sid,
            conn=conn,
        )
        require(
            not current["disabled"] and current["deleted_at"] is None,
            "sensor is disabled or deleted",
            403,
        )
        prior = {
            row["id"]: row["collected_at"]
            for row in st.many(
                "SELECT id,collected_at FROM inventory_roots WHERE tenant_id=$1 AND sensor_id=$2 AND id=ANY($3::uuid[])",
                tenant,
                sid,
                list(coverage),
                conn=conn,
            )
        }
        fresh = {
            rid: entry
            for rid, entry in coverage.items()
            if rid not in prior or prior[rid] < collected_at
        }
        for rid, entry in fresh.items():
            st.execute(
                """INSERT INTO inventory_roots
                (id,tenant_id,sensor_id,source,root,platform,scope,user_name,environment,status,message,collected_at,last_success_at)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CASE WHEN $10='ok' THEN $12::timestamptz ELSE NULL END)
                ON CONFLICT(id) DO UPDATE SET platform=EXCLUDED.platform,scope=EXCLUDED.scope,
                user_name=EXCLUDED.user_name,environment=EXCLUDED.environment,status=EXCLUDED.status,
                message=EXCLUDED.message,collected_at=EXCLUDED.collected_at,
                last_success_at=COALESCE(EXCLUDED.last_success_at,inventory_roots.last_success_at)""",
                rid,
                tenant,
                sid,
                entry["source"],
                entry["root"],
                platform,
                entry["scope"],
                entry["user"],
                entry["environment"],
                entry["status"],
                entry["message"],
                collected_at,
                conn=conn,
            )
            st.execute(
                """INSERT INTO inventory_components
                (id,tenant_id,sensor_id,root_id,key,kind,ecosystem,identifier,name,version,path,publisher,architecture,evidence,metadata,last_seen_at)
                SELECT c.id,$1,$2,$3,c.key,c.kind,c.ecosystem,c.identifier,c.name,c.version,c.path,c.publisher,c.architecture,c.evidence,c.metadata,$4
                FROM jsonb_to_recordset($5) AS c(id uuid,key text,kind text,ecosystem text,identifier text,
                name text,version text,path text,publisher text,architecture text,evidence text,metadata jsonb)
                ON CONFLICT(id) DO UPDATE SET identifier=EXCLUDED.identifier,name=EXCLUDED.name,
                version=EXCLUDED.version,path=EXCLUDED.path,publisher=EXCLUDED.publisher,architecture=EXCLUDED.architecture,
                evidence=EXCLUDED.evidence,metadata=EXCLUDED.metadata,last_seen_at=EXCLUDED.last_seen_at""",
                tenant,
                sid,
                rid,
                collected_at,
                Jsonb(
                    [dict(id=cid, **row) for cid, row in entry["components"].items()]
                ),
                conn=conn,
            )
            if entry["status"] == "ok":
                st.execute(
                    "DELETE FROM inventory_components WHERE tenant_id=$1 AND sensor_id=$2 AND root_id=$3 AND NOT(id=ANY($4::uuid[]))",
                    tenant,
                    sid,
                    rid,
                    list(entry["components"]),
                    conn=conn,
                )
        # Resolve references after all component updates and removals. Any missing
        # endpoint rejects the entire upload, including changes to coverage.
        endpoint_ids = {
            row[key]
            for entry in fresh.values()
            for row in entry["relationships"].values()
            for key in ("from_component_id", "to_component_id")
        }
        found = st.many(
            "SELECT id FROM inventory_components WHERE tenant_id=$1 AND sensor_id=$2 AND id=ANY($3::uuid[])",
            tenant,
            sid,
            list(endpoint_ids),
            conn=conn,
        )
        require(
            {row["id"] for row in found} == endpoint_ids,
            "relationship endpoints must exist on this sensor after reconciliation",
        )
        for rid, entry in fresh.items():
            st.execute(
                """INSERT INTO inventory_relationships
                (id,tenant_id,sensor_id,root_id,from_component_id,to_component_id,kind,evidence,path,last_seen_at)
                SELECT e.id,$1,$2,$3,e.from_component_id,e.to_component_id,e.kind,e.evidence,e.path,$4
                FROM jsonb_to_recordset($5) AS e(id uuid,from_component_id uuid,to_component_id uuid,kind text,evidence text,path text)
                ON CONFLICT(id) DO UPDATE SET last_seen_at=EXCLUDED.last_seen_at""",
                tenant,
                sid,
                rid,
                collected_at,
                Jsonb(
                    [dict(id=eid, **row) for eid, row in entry["relationships"].items()]
                ),
                conn=conn,
            )
            if entry["status"] == "ok":
                st.execute(
                    "DELETE FROM inventory_relationships WHERE tenant_id=$1 AND sensor_id=$2 AND root_id=$3 AND NOT(id=ANY($4::uuid[]))",
                    tenant,
                    sid,
                    rid,
                    list(entry["relationships"]),
                    conn=conn,
                )
    return {"accepted": True, "roots_updated": len(fresh)}


def list_inventory(st, tenant, resource, filters, limit=50, cursor=""):
    """Tenant-scoped keyset listings; resource is selected by the HTTP router."""
    require(
        resource in ("components", "roots", "relationships"),
        "invalid inventory resource",
    )
    conditions = ["r.tenant_id=$1", "s.tenant_id=$1", "s.deleted_at IS NULL"]
    args = [tenant]
    fields = {
        "source": ("r.source", 64),
        "root": ("r.root", 8192),
        "user": ("r.user_name", 256),
        "environment": ("r.environment", 8192),
    }
    identifiers = {"sensor_id": "r.sensor_id", "root_id": "r.id"}
    if resource == "components":
        fields.update(
            kind=("c.kind", 32),
            ecosystem=("c.ecosystem", 32),
            evidence=("c.evidence", 32),
        )
        identifiers["component_id"] = "c.id"
    elif resource == "relationships":
        fields.update(kind=("e.kind", 32), evidence=("e.evidence", 32))
        identifiers["component_id"] = (
            "(e.from_component_id={value} OR e.to_component_id={value})"
        )
    for key, (column, bound) in fields.items():
        if filters.get(key):
            value = _text(filters, key, bound, True)
            if key == "source":
                require(value in SOURCES, "unknown inventory source")
            if key == "kind":
                require(
                    value
                    in (
                        RELATIONS
                        if resource == "relationships"
                        else {kind for kind, _ in SOURCES.values()}
                    ),
                    "invalid inventory kind",
                )
            if key == "ecosystem":
                require(value in ("npm", "pypi"), "invalid ecosystem")
            if key == "evidence":
                require(
                    value in (EVIDENCE if resource == "components" else EVIDENCE[1:]),
                    "invalid evidence",
                )
            args.append(value)
            conditions.append(f"{column}=${len(args)}")
    for key, column in identifiers.items():
        if filters.get(key):
            value = _text(filters, key, 64, True)
            uuid_param(value, key)
            args.append(str(uuid.UUID(value)))
            placeholder = f"${len(args)}::uuid"
            conditions.append(
                column.format(value=placeholder)
                if "{value}" in column
                else f"{column}={placeholder}"
            )
    if filters.get("q"):
        value = _text(filters, "q", 1024, True)
        args.append(
            "%"
            + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            + "%"
        )
        search = {
            "components": ("c.name", "c.identifier", "c.path"),
            "roots": ("r.root", "r.environment", "r.user_name"),
            "relationships": ("e.path",),
        }[resource]
        conditions.append(
            "(" + " OR ".join(f"{column} ILIKE ${len(args)}" for column in search) + ")"
        )
    common = 'r.sensor_id,s.hostname,s.os,r.source,r.root,r.scope,r.user_name AS "user",r.environment'
    if resource == "components":
        select = f"c.id,c.root_id,c.key,c.kind,c.ecosystem,c.identifier,c.name,c.version,c.path,c.publisher,c.architecture,c.evidence,c.metadata,c.last_seen_at,r.status AS root_status,r.collected_at AS root_collected_at,{common}"
        tables = "inventory_components c JOIN inventory_roots r ON r.id=c.root_id AND r.tenant_id=c.tenant_id AND r.sensor_id=c.sensor_id"
        order, row_id = "left(lower(c.name),256)", "c.id"
    elif resource == "roots":
        select = f"""r.id,r.platform,r.status,r.message,r.collected_at,r.last_success_at,{common},
        (SELECT count(*) FROM inventory_components c WHERE c.root_id=r.id) AS component_count,
        (SELECT count(*) FROM inventory_relationships e WHERE e.root_id=r.id) AS relationship_count"""
        tables = "inventory_roots r"
        order, row_id = "left(lower(r.root),256)", "r.id"
    else:
        select = f"""e.id,e.root_id,e.from_component_id,e.to_component_id,e.kind,e.evidence,e.path,e.last_seen_at,r.status AS root_status,{common},
        jsonb_build_object('id',fc.id,'name',fc.name,'version',fc.version,'kind',fc.kind,'path',fc.path,'root_status',fr.status) AS from_component,
        jsonb_build_object('id',tc.id,'name',tc.name,'version',tc.version,'kind',tc.kind,'path',tc.path,'root_status',tr.status) AS to_component"""
        tables = """inventory_relationships e
        JOIN inventory_roots r ON r.id=e.root_id AND r.tenant_id=e.tenant_id AND r.sensor_id=e.sensor_id
        JOIN inventory_components fc ON fc.id=e.from_component_id AND fc.tenant_id=e.tenant_id AND fc.sensor_id=e.sensor_id
        JOIN inventory_components tc ON tc.id=e.to_component_id AND tc.tenant_id=e.tenant_id AND tc.sensor_id=e.sensor_id
        JOIN inventory_roots fr ON fr.id=fc.root_id AND fr.tenant_id=e.tenant_id AND fr.sensor_id=e.sensor_id
        JOIN inventory_roots tr ON tr.id=tc.root_id AND tr.tenant_id=e.tenant_id AND tr.sensor_id=e.sensor_id"""
        order, row_id = "''::text", "e.id"
    if cursor:
        name, ident = decode_cursor(cursor)
        args.extend((name, ident))
        conditions.append(f"({order},{row_id}) > (${len(args) - 1},${len(args)}::uuid)")
    limit = min(limit, 500) if limit > 0 else 50
    args.append(limit + 1)
    rows = st.many(
        f"""SELECT {select},{order} AS sort_name FROM {tables}
        JOIN sensors s ON s.id=r.sensor_id
        WHERE {" AND ".join(conditions)} ORDER BY {order},{row_id} LIMIT ${len(args)}""",
        *args,
    )
    more = len(rows) > limit
    rows = rows[:limit]
    cursor = encode_cursor(rows[-1]["sort_name"], rows[-1]["id"]) if more else ""
    for row in rows:
        del row["sort_name"]
    return rows, cursor
