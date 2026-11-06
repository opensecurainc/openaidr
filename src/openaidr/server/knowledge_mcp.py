"""Tenant MCP connections and atomic imports into the local knowledge corpus."""

import hashlib
import json
import re
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken

from . import knowledge_ingest as ingest, knowledge_library
from .httpx import APIError, require
from .knowledge import _text
from .knowledge_mcp_transport import endpoint, run
from .knowledge_mcp_imports import selection, selection_key
from openaidr.core.redact import redact_value
from .store import new_id, valid_uuid

COLUMNS = "connection_id,name,endpoint,auth_type,imports,resource_uris,synced_at,created_at,(encrypted_token<>'') AS has_token"


def _credentials(data):
    require(isinstance(data, dict), "invalid MCP authentication")
    fields = {"none": {"type"}, "bearer": {"type", "token"},
              "basic": {"type", "username", "password"}, "header": {"type", "name", "value"}}
    kind = data.get("type")
    require(isinstance(kind, str) and kind in fields and set(data) == fields[kind], "invalid MCP authentication fields")
    for key in fields[kind] - {"type"}:
        value = data[key]
        require(isinstance(value, str) and 0 < len(value) <= 4096
                and all(32 <= ord(c) <= 126 for c in value), "invalid MCP credential")
    if kind == "basic":
        require(":" not in data["username"], "MCP username cannot contain a colon")
    if kind == "header":
        name = data["name"].lower()
        require(bool(re.fullmatch(r"[a-z][a-z0-9_-]{0,79}", name))
                and name not in {"host", "cookie", "connection", "accept", "accept-encoding", "te", "trailer", "upgrade", "transfer-encoding"}
                and not name.startswith(("content-", "mcp-", "proxy-", "sec-")), "This header cannot be used for MCP authentication")
    return data


def _cipher(cfg):
    try:
        return Fernet(cfg.knowledge_mcp_key.encode())
    except (ValueError, TypeError):
        raise APIError(
            503,
            "An operator must configure OPENAIDR_KNOWLEDGE_MCP_KEY to store MCP credentials",
        ) from None


def _token(cfg, tenant, connection):
    if not connection["encrypted_token"]:
        return ""
    try:
        value = json.loads(_cipher(cfg).decrypt(connection["encrypted_token"].encode()))
        require(
            value[:2] == [tenant, str(connection["connection_id"])],
            "MCP credential cannot be read",
            503,
        )
        credential = value[2]
        if isinstance(credential, str):
            credential = {"type": "bearer", "token": credential}
        return _credentials(credential)
    except (InvalidToken, ValueError, IndexError, TypeError):
        raise APIError(
            503,
            "MCP credential cannot be read. Restore the encryption key or reconnect the server",
        ) from None


def _connection(st, tenant, ident, *, conn=None):
    require(valid_uuid(ident), "invalid connection id")
    return st.one(
        "SELECT * FROM knowledge_mcp_connections WHERE tenant_id=$1 AND connection_id=$2",
        tenant,
        str(UUID(ident)),
        conn=conn,
    )


def list_connections(st, tenant):
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        connections = st.many(
            f"SELECT {COLUMNS} FROM knowledge_mcp_connections "
            "WHERE tenant_id=$1 ORDER BY created_at,connection_id",
            tenant,
            conn=conn,
        )
        for connection in connections:
            # Legacy replicas only write resource_uris, even after the migration.
            # It remains authoritative; retain recipes only for selected keys.
            recipes = {selection_key(source): source for source in connection["imports"]}
            connection["imports"] = [
                recipes.get(uri, {"kind": "resource", "uri": uri})
                for uri in connection["resource_uris"]
            ]
            if connection["auth_type"] == "none" and connection["has_token"]:
                connection["auth_type"] = "bearer"
        return {
            "revision": ingest.settings(st, tenant, conn=conn)["revision"],
            "connections": connections,
        }


def connect(st, cfg, tenant, data):
    require(
        set(data) in ({"revision", "name", "endpoint", "token"}, {"revision", "name", "endpoint", "auth"}),
        "invalid MCP connection fields",
    )
    ingest._revision(data)
    name = _text(data, "name", 160)
    url, _ = endpoint(data["endpoint"], cfg.knowledge_mcp_private_origins)
    if "token" in data:
        require(isinstance(data["token"], str), "invalid bearer token")
    credentials = _credentials(data["auth"] if "auth" in data else
                               ({"type": "bearer", "token": data["token"]} if data["token"] else {"type": "none"}))
    ident = new_id()
    # Keep bearer credentials readable by resource-only releases during rollback.
    stored = credentials["token"] if credentials["type"] == "bearer" else credentials
    encrypted = (
        _cipher(cfg).encrypt(json.dumps([tenant, ident, stored]).encode()).decode()
        if credentials["type"] != "none"
        else ""
    )
    catalog = run(str(url), credentials, cfg.knowledge_mcp_private_origins)
    with st.transaction() as conn:
        ingest._lock(st, tenant, conn, data["revision"])
        require(
            st.scalar(
                "SELECT count(*) FROM knowledge_mcp_connections WHERE tenant_id=$1",
                tenant,
                conn=conn,
            )
            < 16,
            "At most 16 MCP connections are supported",
            409,
        )
        st.execute(
            "INSERT INTO knowledge_mcp_connections(tenant_id,connection_id,name,endpoint,encrypted_token,auth_type) "
            "VALUES($1,$2,$3,$4,$5,$6)",
            tenant,
            ident,
            name,
            str(url),
            encrypted,
            credentials["type"],
            conn=conn,
        )
        revision = ingest._bump(st, tenant, conn)
        connection = st.one(
            f"SELECT {COLUMNS} FROM knowledge_mcp_connections WHERE tenant_id=$1 AND connection_id=$2",
            tenant,
            ident,
            conn=conn,
        )
    return {"revision": revision, "connection": connection, **catalog}


def resources(st, cfg, tenant, ident):
    connection = _connection(st, tenant, ident)
    return run(
        connection["endpoint"],
        _token(cfg, tenant, connection),
        cfg.knowledge_mcp_private_origins,
    )


def preview(st, cfg, tenant, ident, data):
    require(set(data) == {"source"}, "source is required")
    source = selection(data["source"])
    connection = _connection(st, tenant, ident)
    documents = run(connection["endpoint"], _token(cfg, tenant, connection),
                    cfg.knowledge_mcp_private_origins, [source])
    return {"document": redact_value(documents[0])}


def _source_id(ident, uri):
    return (
        "mcp:" + str(UUID(ident)) + ":" + hashlib.sha256(uri.encode()).hexdigest()[:24]
    )


def _revoke(st, tenant, ids, conn):
    st.execute(
        """UPDATE knowledge_sources SET generation=generation+1,status='revoked',
                      active_revision_id=NULL,verified_at=NULL,fresh_until=NULL,updated_at=clock_timestamp()
                  WHERE tenant_id=$1 AND source_id=ANY($2::text[]) AND status<>'revoked'""",
        tenant,
        ids,
        conn=conn,
    )


def sync(st, cfg, tenant, ident, data):
    require(set(data) in ({"revision", "uris"}, {"revision", "imports"}), "revision and imports are required")
    ingest._revision(data)
    if "uris" in data:
        require(isinstance(data["uris"], list), "uris must be a list")
        sources = [{"kind": "resource", "uri": uri} for uri in data["uris"]]
    else:
        sources = data["imports"]
    require(isinstance(sources, list) and len(sources) <= 20, "Select at most 20 MCP imports")
    sources = [selection(source) for source in sources]
    uris = [selection_key(source) for source in sources]
    require(len(set(uris)) == len(uris), "Select distinct MCP imports")
    connection = _connection(st, tenant, ident)
    ident = str(connection["connection_id"])
    documents = (
        run(
            connection["endpoint"],
            _token(cfg, tenant, connection),
            cfg.knowledge_mcp_private_origins,
            sources,
        )
        if uris
        else []
    )
    # Remote I/O completes before locking. Revision checks fence disconnects and concurrent edits.
    with st.transaction() as conn:
        revision = ingest._lock(st, tenant, conn, data["revision"])
        _connection(st, tenant, ident, conn=conn)
        for doc in documents:
            source_id = _source_id(ident, doc["uri"])
            result = knowledge_library.import_document(
                st,
                tenant,
                {
                    "revision": revision,
                    "source_id": source_id,
                    "source_version": hashlib.sha256(
                        json.dumps(doc, sort_keys=True).encode()
                    ).hexdigest(),
                    "title": doc["name"],
                    "source_uri": "wiki://mcp/" + source_id,
                    "scope_key": "",
                    "kind": "reference",
                    "keys": [],
                    "markdown": doc["text"],
                    "freshness_seconds": 86400,
                },
                source_type="mcp",
                conn=conn,
            )
            revision = result["revision"]
        _revoke(
            st,
            tenant,
            [
                _source_id(ident, uri)
                for uri in connection["resource_uris"]
                if uri not in uris
            ],
            conn,
        )
        st.execute(
            "UPDATE knowledge_mcp_connections SET resource_uris=$3::jsonb,imports=$4::jsonb,synced_at=clock_timestamp() "
            "WHERE tenant_id=$1 AND connection_id=$2",
            tenant,
            ident,
            json.dumps(uris),
            json.dumps(sources),
            conn=conn,
        )
        revision = ingest._bump(st, tenant, conn)
    return {"revision": revision, "imported": len(documents)}


def disconnect(st, tenant, ident, data):
    require(set(data) == {"revision"}, "revision is required")
    ingest._revision(data)
    with st.transaction() as conn:
        ingest._lock(st, tenant, conn, data["revision"])
        connection = _connection(st, tenant, ident, conn=conn)
        ident = str(connection["connection_id"])
        _revoke(
            st,
            tenant,
            [_source_id(ident, uri) for uri in connection["resource_uris"]],
            conn,
        )
        st.execute(
            "DELETE FROM knowledge_mcp_connections WHERE tenant_id=$1 AND connection_id=$2",
            tenant,
            ident,
            conn=conn,
        )
        revision = ingest._bump(st, tenant, conn)
    return {"revision": revision, "disconnected": True}
