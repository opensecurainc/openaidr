"""Authenticated application snapshots with conservative per-source reconciliation."""

import base64
import hashlib
import json
import uuid
from datetime import timedelta

from . import ai_software
from .httpx import require, parse_time
from .store import new_id, now

SOURCES = frozenset(
    (
        "macos-spotlight",
        "linux-dpkg",
        "linux-rpm",
        "linux-desktop",
        "linux-flatpak",
        "linux-snap",
        "windows-registry",
        "windows-appx",
    )
)
STATUSES = frozenset(("ok", "partial", "unavailable", "error"))
READ_SOURCES = SOURCES | {"osquery-apps", "openaidr-cli"}
# ai: a known AI product (ai_software.py). system: shipped with the operating
# system, a support or helper component, or a browser-generated web-app
# wrapper. user: everything else, the software a person chose to install.
CATEGORIES = ("ai", "user", "system")
# Listings sort by this key. It is bounded so its index entry stays under the
# B-tree size limit for any valid name (1,024 characters of up to 4 bytes);
# names that share the first 256 characters fall back to id order.
SORT_KEY = "left(lower(a.name), 256)"

# Select one macOS collector per device. Failed scans retain the last usable
# inventory; a newer legacy scan also supports rolling back the sensor.
APPLICATION_RECORDS = """WITH osquery_scans AS (
    SELECT r.sensor_id, GREATEST(max(r.last_success_at),max(c.last_seen_at)) AS observed_at
    FROM inventory_roots r LEFT JOIN inventory_components c
        ON c.root_id=r.id AND c.tenant_id=r.tenant_id AND c.sensor_id=r.sensor_id
    WHERE r.tenant_id=$1 AND r.source='osquery-apps' AND r.root<>'discovery'
    GROUP BY r.sensor_id
), osquery_devices AS (
    SELECT o.sensor_id FROM osquery_scans o
    LEFT JOIN application_inventory_sources l
        ON l.tenant_id=$1 AND l.sensor_id=o.sensor_id AND l.source='macos-spotlight'
    WHERE o.observed_at IS NOT NULL AND o.observed_at >= COALESCE(
        GREATEST(l.last_success_at,
            CASE WHEN l.status IN ('ok','partial') THEN l.collected_at END,
            (SELECT max(a.last_seen_at) FROM application_inventory a
                WHERE a.tenant_id=$1 AND a.sensor_id=o.sensor_id AND a.source='macos-spotlight')),
        '-infinity'::timestamptz)
), applications AS (
    SELECT a.id,a.tenant_id,a.sensor_id,a.source,a.identifier,a.name,a.version,a.path,
        a.publisher,a.architecture,a.kind,a.scope,a.last_seen_at
    FROM application_inventory a WHERE a.tenant_id=$1 AND (
        a.source<>'macos-spotlight' OR NOT EXISTS (
            SELECT 1 FROM osquery_devices o WHERE o.sensor_id=a.sensor_id))
    UNION ALL
    SELECT c.id,c.tenant_id,c.sensor_id,r.source,c.identifier,c.name,c.version,c.path,
        c.publisher,c.architecture,c.kind,r.scope,c.last_seen_at
    FROM inventory_components c JOIN inventory_roots r
        ON r.id=c.root_id AND r.tenant_id=c.tenant_id AND r.sensor_id=c.sensor_id
    JOIN osquery_devices o ON o.sensor_id=c.sensor_id
    WHERE c.tenant_id=$1 AND r.source='osquery-apps' AND c.kind='application'
    UNION ALL
    SELECT c.id,c.tenant_id,c.sensor_id,r.source,c.identifier,c.name,c.version,c.path,
        c.publisher,c.architecture,c.kind,r.scope,c.last_seen_at
    FROM inventory_components c JOIN inventory_roots r
        ON r.id=c.root_id AND r.tenant_id=c.tenant_id AND r.sensor_id=c.sensor_id
    WHERE c.tenant_id=$1 AND r.source='openaidr-cli' AND c.kind='application'
)"""


def _category(args):
    """SQL for a record's category; appends its parameters to args."""
    from .ai_inventory import PACKAGE_PRODUCTS

    args.append([p.replace("_", "\\_") + "%" for p in ai_software.IDENTIFIER_PREFIXES])
    prefixes = len(args)
    args.append(list(ai_software.NAMES))
    names = len(args)
    args.append([ecosystem + ":" + name for ecosystem, packages in PACKAGE_PRODUCTS.items() for name in packages])
    cli_packages = len(args)
    return f"""CASE
        WHEN a.source='openaidr-cli' AND a.identifier LIKE 'executable:%' THEN 'user'
        WHEN a.source='openaidr-cli' AND lower(a.identifier)=ANY(${cli_packages}::text[]) THEN 'ai'
        WHEN a.identifier ILIKE ANY(${prefixes}::text[]) OR lower(a.name)=ANY(${names}::text[]) THEN 'ai'
        WHEN a.source IN ('macos-spotlight','osquery-apps') AND (
            a.path LIKE '/System/%' OR a.path LIKE '/Library/%' OR a.path LIKE '/usr/%'
            OR a.path LIKE '/opt/%' OR a.path LIKE '/private/%'
            OR a.path ~ '^/Users/[^/]+/Library/'
            OR a.path ~ '^/Users/[^/]+/Applications/[^/]+ Apps\\.localized/'
            OR a.path ~ '\\.app/.+\\.app$'
        ) THEN 'system'
        WHEN a.source IN ('linux-dpkg','linux-rpm') THEN 'system'
        WHEN a.source='windows-appx' AND a.identifier ILIKE 'Microsoft.%' THEN 'system'
        ELSE 'user' END"""


FIELDS = {
    "identifier": 2048,
    "name": 1024,
    "version": 256,
    "path": 8192,
    "publisher": 1024,
    "architecture": 128,
}


def _text(row, key, limit, required=False):
    value = row.get(key, "")
    require(
        isinstance(value, str) and len(value) <= limit and "\x00" not in value,
        f"{key} must be a string of at most {limit} characters without NUL",
    )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        require(False, f"{key} must contain valid Unicode")
    require(not required or bool(value.strip()), f"{key} is required")
    return value


def validate_snapshot(data):
    require(
        type(data.get("schema_version")) is int and data["schema_version"] == 1,
        "schema_version must be 1",
    )
    raw_time = _text(data, "collected_at", 64, True)
    try:
        collected_at = parse_time(raw_time)
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
    sources, applications = data.get("sources"), data.get("applications")
    require(
        isinstance(sources, list) and len(sources) <= 64,
        "sources must contain at most 64 entries",
    )
    require(
        isinstance(applications, list) and len(applications) <= 10000,
        "applications must contain at most 10000 entries",
    )
    coverage = {}
    for row in sources:
        require(isinstance(row, dict), "invalid source entry")
        source = _text(row, "source", 64, True)
        status = _text(row, "status", 32, True)
        require(source in SOURCES, "unknown inventory source")
        require(source not in coverage, "duplicate inventory source")
        require(status in STATUSES, "invalid source status")
        coverage[source] = dict(
            source=source, status=status, message=_text(row, "message", 2048), apps={}
        )
    for row in applications:
        require(isinstance(row, dict), "invalid application entry")
        source = _text(row, "source", 64, True)
        require(source in coverage, "application source must appear in sources")
        require(
            coverage[source]["status"] in ("ok", "partial"),
            "failed or unavailable sources cannot report applications",
        )
        app = {
            key: _text(row, key, limit, key in ("identifier", "name"))
            for key, limit in FIELDS.items()
        }
        app.update(
            source=source,
            kind=_text(row, "kind", 32, True),
            scope=_text(row, "scope", 32, True),
        )
        require(app["kind"] in ("application", "package"), "invalid application kind")
        require(
            app["scope"] in ("system", "user", "unknown"), "invalid application scope"
        )
        identity = json.dumps(
            [app[k] for k in ("source", "identifier", "path", "architecture", "scope")],
            ensure_ascii=True,
            separators=(",", ":"),
        )
        key = hashlib.sha256(identity.encode()).hexdigest()
        previous = coverage[source]["apps"].get(key)
        require(
            previous is None or previous == app,
            "conflicting duplicate application identity",
        )
        coverage[source]["apps"][key] = app
    return collected_at, platform, coverage


def ingest_snapshot(st, sensor, data):
    require(not sensor["disabled"], "sensor is disabled", 403)
    require(
        "sensor_id" not in data or data["sensor_id"] == sensor["id"],
        "snapshot sensor_id does not match the token",
        403,
    )
    collected_at, platform, coverage = validate_snapshot(data)
    tenant, sid = sensor["tenant_id"], sensor["id"]
    applied = 0
    with st.transaction() as conn:
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
        for source, entry in coverage.items():
            prior = st.many(
                "SELECT collected_at FROM application_inventory_sources WHERE tenant_id=$1 AND sensor_id=$2 AND source=$3",
                tenant,
                sid,
                source,
                conn=conn,
            )
            if prior and prior[0]["collected_at"] >= collected_at:
                continue
            status = entry["status"]
            st.execute(
                """INSERT INTO application_inventory_sources
                (tenant_id,sensor_id,source,platform,status,message,collected_at,last_success_at)
                VALUES($1,$2,$3,$4,$5,$6,$7,CASE WHEN $5='ok' THEN $7::timestamptz ELSE NULL END)
                ON CONFLICT(sensor_id,source) DO UPDATE SET platform=EXCLUDED.platform,
                status=EXCLUDED.status,message=EXCLUDED.message,collected_at=EXCLUDED.collected_at,
                last_success_at=COALESCE(EXCLUDED.last_success_at,application_inventory_sources.last_success_at)""",
                tenant,
                sid,
                source,
                platform,
                status,
                entry["message"],
                collected_at,
                conn=conn,
            )
            for identity, app in entry["apps"].items():
                st.execute(
                    """INSERT INTO application_inventory
                    (id,tenant_id,sensor_id,source,identity_hash,identifier,name,version,path,publisher,architecture,kind,scope,last_seen_at)
                    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                    ON CONFLICT(sensor_id,source,identity_hash) DO UPDATE SET
                    name=EXCLUDED.name,version=EXCLUDED.version,publisher=EXCLUDED.publisher,
                    kind=EXCLUDED.kind,last_seen_at=EXCLUDED.last_seen_at""",
                    new_id(),
                    tenant,
                    sid,
                    source,
                    identity,
                    app["identifier"],
                    app["name"],
                    app["version"],
                    app["path"],
                    app["publisher"],
                    app["architecture"],
                    app["kind"],
                    app["scope"],
                    collected_at,
                    conn=conn,
                )
            if status == "ok":
                st.execute(
                    "DELETE FROM application_inventory WHERE tenant_id=$1 AND sensor_id=$2 AND source=$3 AND NOT(identity_hash=ANY($4::text[]))",
                    tenant,
                    sid,
                    source,
                    list(entry["apps"]),
                    conn=conn,
                )
            applied += 1
    return {"accepted": True, "sources_updated": applied}


def _filters(tenant, filters):
    """WHERE conditions, arguments, and the category expression for a listing."""
    conditions = ["a.tenant_id=$1", "s.tenant_id=$1", "s.deleted_at IS NULL"]
    args = [tenant]
    include_helpers = filters.get("include_helpers", "true")
    require(
        include_helpers in ("true", "false"), "include_helpers must be true or false"
    )
    if include_helpers == "false":
        args.extend(
            (list(ai_software.HELPER_IDENTIFIERS), list(ai_software.HELPER_NAMES))
        )
        conditions.append(
            f"NOT (lower(a.identifier)=ANY(${len(args) - 1}::text[]) "
            f"OR lower(a.name)=ANY(${len(args)}::text[]))"
        )
    for key in ("sensor_id", "source", "kind"):
        if filters.get(key):
            value = filters[key]
            if key == "source":
                require(value in READ_SOURCES, "unknown inventory source")
            if key == "kind":
                require(value in ("application", "package"), "invalid application kind")
            args.append(value)
            conditions.append(f"a.{key}=${len(args)}")
    if filters.get("q"):
        value = filters["q"]
        require(len(value) <= 1024 and "\x00" not in value, "invalid search query")
        args.append(
            "%"
            + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            + "%"
        )
        conditions.append(
            f"(a.name ILIKE ${len(args)} OR a.identifier ILIKE ${len(args)} OR a.path ILIKE ${len(args)})"
        )
    return conditions, args, _category(args)


def encode_cursor(name, id):
    raw = json.dumps([name, id], ensure_ascii=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_cursor(value):
    """The (lowercased name, id) after which the next page starts.

    Every part is checked to be something PostgreSQL can bind, so a crafted
    cursor is a 400 rather than a database error.
    """
    try:
        name, id = json.loads(
            base64.b64decode(
                value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
            )
        )
        if isinstance(name, str) and isinstance(id, str):
            name.encode("utf-8")  # rejects lone surrogates
            if len(name) <= 4096 and "\x00" not in name:
                return name, str(uuid.UUID(id))  # canonical form only
    except (ValueError, TypeError, UnicodeError):
        pass
    require(False, "invalid cursor")


def list_applications(st, tenant, filters, limit=50, cursor=""):
    """Records ordered by name, each with its category, filtered by category."""
    conditions, args, category = _filters(tenant, filters)
    if filters.get("category"):
        require(filters["category"] in CATEGORIES, "invalid software category")
        args.append(filters["category"])
        conditions.append(f"({category})=${len(args)}")
    if cursor:
        name, id = decode_cursor(cursor)
        args.extend((name, id))
        conditions.append(
            f"({SORT_KEY}, a.id) > (${len(args) - 1}, ${len(args)}::uuid)"
        )
    limit = min(limit, 500) if limit > 0 else 50
    args.append(limit + 1)
    rows = st.many(
        f"""{APPLICATION_RECORDS}
        SELECT a.id,a.sensor_id,s.hostname,s.os,a.source,a.identifier,a.name,a.version,a.path,
        a.publisher,a.architecture,a.kind,a.scope,a.last_seen_at,{category} AS category,
        {SORT_KEY} AS sort_name
        FROM applications a JOIN sensors s ON s.id=a.sensor_id
        WHERE {" AND ".join(conditions)}
        ORDER BY {SORT_KEY}, a.id LIMIT ${len(args)}""",
        *args,
    )
    more = len(rows) > limit
    rows = rows[:limit]
    # The cursor carries the database's lowercase form, which can differ from
    # Python's for some Unicode names.
    cursor = encode_cursor(rows[-1]["sort_name"], rows[-1]["id"]) if more else ""
    for row in rows:
        del row["sort_name"]
    return rows, cursor


def category_counts(st, tenant, filters):
    """Record counts per category under the same filters as the listing."""
    conditions, args, category = _filters(tenant, filters)
    rows = st.many(
        f"""{APPLICATION_RECORDS}
        SELECT {category} AS category, count(*) AS records
        FROM applications a JOIN sensors s ON s.id=a.sensor_id
        WHERE {" AND ".join(conditions)} GROUP BY 1""",
        *args,
    )
    counts = dict.fromkeys(CATEGORIES, 0)
    counts.update({row["category"]: row["records"] for row in rows})
    return counts


def list_sources(st, tenant, sensor_id=""):
    return st.many(
        f"""{APPLICATION_RECORDS}, sources AS (
            SELECT l.tenant_id,l.sensor_id,l.source,l.status,l.message,l.collected_at,l.last_success_at
            FROM application_inventory_sources l WHERE l.tenant_id=$1 AND (
                l.source<>'macos-spotlight' OR NOT EXISTS (
                    SELECT 1 FROM osquery_devices o WHERE o.sensor_id=l.sensor_id))
            UNION ALL
            SELECT r.tenant_id,r.sensor_id,r.source,
                CASE WHEN bool_and(r.status='ok') THEN 'ok'
                    WHEN bool_or(r.status='partial' OR (r.root<>'discovery' AND r.status='ok')) THEN 'partial'
                    WHEN bool_or(r.status='error') THEN 'error' ELSE 'unavailable' END,
                left(COALESCE(string_agg(DISTINCT NULLIF(r.message,''), ' '),''),2048),
                max(r.collected_at),
                CASE WHEN bool_and(r.last_success_at IS NOT NULL) FILTER (WHERE r.root<>'discovery')
                    THEN min(r.last_success_at) FILTER (WHERE r.root<>'discovery') END
            FROM inventory_roots r WHERE r.tenant_id=$1 AND r.source='osquery-apps'
            GROUP BY r.tenant_id,r.sensor_id,r.source
        )
        SELECT c.sensor_id,s.hostname,s.os,c.source,c.status,c.message,c.collected_at,c.last_success_at,
        (SELECT count(*) FROM applications a WHERE a.tenant_id=c.tenant_id AND a.sensor_id=c.sensor_id AND a.source=c.source) AS application_count
        FROM sources c JOIN sensors s ON s.id=c.sensor_id AND s.tenant_id=c.tenant_id
        WHERE c.tenant_id=$1 AND s.deleted_at IS NULL AND ($2='' OR c.sensor_id=NULLIF($2,'')::uuid)
        ORDER BY s.hostname,c.sensor_id,c.source""",
        tenant,
        sensor_id,
    )
