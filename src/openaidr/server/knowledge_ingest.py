"""Versioned, tenant-shared reference imports for PostgreSQL retrieval.

Callers authenticate the administrator and supply the tenant separately. Import
payloads never choose a tenant or infer a resource scope from document text.
"""

import hashlib
import json
import re
import uuid
from urllib.parse import urlsplit

from .httpx import require
from .knowledge import TOKEN, _text
from .knowledge_retrieval import IDENTIFIER

# Bump for changes to section parsing, alias compilation, or redaction.
PARSER_VERSION = "markdown-sections-v4"
SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
MAX_MARKDOWN_BYTES = 256 << 10
MAX_PASSAGES = 256
CORPUS_LIMITS = {"sources": 1000, "revisions": 10000, "passages": 100000}
SOURCE_COLUMNS = """source_id,source_type,title,source_uri,scope_key,generation,
    source_version,active_revision_id,status,freshness_seconds,verified_at,
    fresh_until,updated_at,
    (status='current' AND fresh_until>clock_timestamp()) AS fresh"""


def settings(st, tenant, *, conn=None):
    return st.one(
        """SELECT COALESCE(k.enabled,false) AS enabled,
               COALESCE(k.revision,0) AS revision,
               COALESCE(k.retrieval_mode,'legacy') AS retrieval_mode,k.updated_at
           FROM (SELECT $1::uuid AS tenant_id) t
           LEFT JOIN tenant_knowledge k ON k.tenant_id=t.tenant_id""",
        tenant, conn=conn,
    )


def _lock(st, tenant, conn, expected=None):
    st.execute("INSERT INTO tenant_knowledge(tenant_id) VALUES($1) ON CONFLICT DO NOTHING",
               tenant, conn=conn)
    revision = st.scalar("SELECT revision FROM tenant_knowledge WHERE tenant_id=$1 FOR UPDATE",
                         tenant, conn=conn)
    if expected is not None:
        require(revision == expected, "knowledge changed; reload before saving", 409)
    return revision


def _bump(st, tenant, conn):
    return st.scalar(
        """UPDATE tenant_knowledge SET revision=revision+1,updated_at=clock_timestamp()
           WHERE tenant_id=$1 RETURNING revision""", tenant, conn=conn,
    )


def _capacity(st, tenant, conn, category, added=1):
    # All writers hold the tenant row lock until their inserts commit.
    limit = CORPUS_LIMITS[category]
    used = st.scalar(f"SELECT count(*) FROM knowledge_{category} WHERE tenant_id=$1",
                     tenant, conn=conn)
    require(used + added <= limit,
            f"tenant knowledge {category} limit ({limit}) reached; purge revoked sources", 409)


def _revision(data):
    require(type(data.get("revision")) is int and data["revision"] >= 0, "invalid revision")


def _source_id(value, *, manual=False, managed=False):
    require(isinstance(value, str) and SOURCE_ID.fullmatch(value)
            and (manual or not value.startswith("manual:"))
            and (managed or not value.startswith(("upload:", "mcp:"))), "invalid or reserved source_id")
    return value


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _content_hash(value):
    return _hash(json.dumps({key: value[key] for key in (
        "source_id", "source_type", "source_version", "title", "source_uri",
        "scope_key", "markdown", "kind", "keys",
    )}, sort_keys=True, ensure_ascii=False))


def _validate(payload, *, source_type="markdown"):
    fields = {"revision", "source_id", "source_version", "title", "source_uri", "scope_key",
              "markdown", "kind", "keys"}
    require(isinstance(payload, dict) and fields <= set(payload)
            and not set(payload) - fields - {"freshness_seconds"}, "invalid source fields")
    _revision(payload)
    source_id = _source_id(payload["source_id"], managed=source_type != "markdown")
    source_version = _text(payload, "source_version", 160)
    title = _text(payload, "title", 240)
    uri = _text(payload, "source_uri", 1024)
    try:
        parsed = urlsplit(uri)
        valid_uri = (parsed.scheme in ("https", "http", "wiki") and bool(parsed.hostname)
                     and not parsed.username and not parsed.password
                     and not any(ord(c) < 33 for c in uri))
    except ValueError:
        valid_uri = False
    require(valid_uri, "source_uri must be an http, https, or wiki URI without credentials")
    scope = payload["scope_key"]
    try:
        valid_scope = (isinstance(scope, str) and len(scope.encode()) <= 240
                       and (not scope or scope.isprintable()) and not any(c.isspace() for c in scope))
    except UnicodeError:
        valid_scope = False
    require(valid_scope, "invalid scope_key")
    require(payload["kind"] in ("command", "resource", "reference"), "invalid source kind")
    original_markdown = _text(payload, "markdown", MAX_MARKDOWN_BYTES).replace("\r\n", "\n")
    markdown = original_markdown.replace("\r", "\n")
    freshness = payload.get("freshness_seconds", 900)
    require(type(freshness) is int and 60 <= freshness <= 86400,
            "freshness_seconds must be between 60 and 86400")
    require(isinstance(payload["keys"], list) and len(payload["keys"]) <= 32,
            "keys must be an array of at most 32 entries")
    keys = []
    for key in payload["keys"]:
        require(isinstance(key, dict) and set(key) == {"key_type", "lookup_value", "canonical_key"},
                "invalid key fields")
        require(key["key_type"] in ("operation", "resource", "term"), "invalid key_type")
        require(key["key_type"] != "resource" or bool(scope), "resource keys require a scope_key")
        lookup = _text(key, "lookup_value", 160)
        canonical = _text(key, "canonical_key", 240)
        require(not any(ord(c) < 32 for c in lookup + canonical), "invalid key text")
        lookup = " ".join(lookup.split())
        if key["key_type"] in ("operation", "resource"):
            operation = key["key_type"] == "operation"
            words = lookup.split(" ")
            require(1 <= len(words) <= (2 if operation else 1)
                    and all(IDENTIFIER.fullmatch(word) and not word.startswith("-") for word in words),
                    "entity alias must match a supported operation or resource identifier")
            require(payload["kind"] in (("command", "reference") if operation else ("resource", "reference")),
                    "entity alias is incompatible with source kind")
        keys.append({"key_type": key["key_type"], "lookup_value": lookup,
                     "canonical_key": canonical})
    keys = sorted(keys, key=lambda key: (key["key_type"], key["lookup_value"], key["canonical_key"]))
    from openaidr.core.redact import redact_value

    identity = {"source_id": source_id, "source_version": source_version,
                "source_uri": uri, "scope_key": scope, "keys": keys}
    require(redact_value(identity) == identity, "source metadata must not contain credentials")
    value = {"source_id": source_id, "source_type": source_type, "source_version": source_version,
             "title": title, "source_uri": uri, "scope_key": scope,
             "markdown": markdown, "kind": payload["kind"], "keys": keys,
             "freshness_seconds": freshness}
    # Upstream identity excludes operational policy and processing output.
    # Keep only its digest so processing changes do not require a source edit.
    value["content_hash"] = _content_hash(value)
    # Older imports retained lone CR. Compare only bounded raw-input variants;
    # redacted text cannot prove an immutable upstream version is unchanged.
    value["compatible_hashes"] = list(dict.fromkeys(
        _content_hash(dict(value, markdown=text))
        for text in (markdown, original_markdown, markdown.replace("\n", "\r"))
    ))
    for key in keys:
        if key["key_type"] == "term":
            term = key["lookup_value"].casefold()
            require(TOKEN.fullmatch(term), "term aliases must be single words or identifiers")
            key["lookup_value"] = term
    value.update(title=redact_value(title), markdown=redact_value(markdown))
    _text(value, "title", 240)
    return value


def split_markdown(markdown, title):
    """Keep each section intact, including lists, tables, and fenced examples.

    Refuse an oversized section instead of dropping qualifications or splitting
    a table from its headers. The importer can add explicit section boundaries.
    """
    sections, headings, lines, fence = [], [], [], None

    def flush():
        text = "\n".join(lines).strip()
        if text:
            require(len(text.encode()) <= 2000,
                    "each Markdown section must fit in 2000 UTF-8 bytes; add section headings")
            sections.append({"section_path": " / ".join(h for _, h in headings) or title,
                             "body": text})

    for line in re.split(r"\r\n?|\n", markdown):
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker[1]
            if fence is None:
                if token[0] != "`" or "`" not in line[marker.end():]:
                    fence = token
            elif (token[0] == fence[0] and len(token) >= len(fence)
                  and not line[marker.end():].strip(" \t")):
                fence = None
        heading = re.match(r"^ {0,3}(#{1,6})[ \t]+(.+?)[ \t]*$", line) if fence is None else None
        if heading:
            flush()
            lines = []
            depth = len(heading[1])
            headings = [(level, text) for level, text in headings if level < depth]
            headings.append((depth, re.sub(r"[ \t]+#+$", "", heading[2])))
        lines.append(line)
    flush()
    require(fence is None, "Markdown contains an unclosed code fence")
    require(0 < len(sections) <= MAX_PASSAGES, f"source must contain between 1 and {MAX_PASSAGES} sections")
    return sections


def list_sources(st, tenant):
    # One transaction snapshot keeps the metadata and revision consistent.
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        result = settings(st, tenant, conn=conn)
        result["sources"] = st.many(
            f"SELECT {SOURCE_COLUMNS} FROM knowledge_sources WHERE tenant_id=$1 ORDER BY source_id",
            tenant, conn=conn,
        )
        return result


def read_source(st, tenant, source_id, *, conn=None):
    if conn is None:
        with st.transaction() as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            return read_source(st, tenant, source_id, conn=connection)
    source = st.one(f"SELECT {SOURCE_COLUMNS} FROM knowledge_sources WHERE tenant_id=$1 AND source_id=$2",
                    tenant, source_id, conn=conn)
    passages = st.many(
        """SELECT p.passage_id,p.kind,p.title,p.section_path,p.body,p.content_hash
           FROM knowledge_passages p JOIN knowledge_sources s
             ON s.tenant_id=p.tenant_id AND s.active_revision_id=p.revision_id
           WHERE s.tenant_id=$1 AND s.source_id=$2 AND s.status='current'
             AND s.fresh_until>clock_timestamp() ORDER BY p.ordinal""",
        tenant, source_id, conn=conn,
    )
    keys = st.many(
        """SELECT passage_id,key_type,scope_key,lookup_value,canonical_key
           FROM knowledge_passage_keys WHERE tenant_id=$1 AND passage_id=ANY($2::uuid[])
           ORDER BY passage_id,key_type,scope_key,lookup_value,canonical_key""",
        tenant, [passage["passage_id"] for passage in passages], conn=conn,
    )
    by_passage = {passage["passage_id"]: [] for passage in passages}
    for key in keys:
        by_passage[key.pop("passage_id")].append(key)
    for passage in passages:
        passage["keys"] = by_passage[passage["passage_id"]]
    return {"revision": settings(st, tenant, conn=conn)["revision"], "source": source,
            "passages": passages}


def _begin(st, tenant, value, conn):
    hashes = value.get("compatible_hashes", [value["content_hash"]])
    conflicting_version = st.scalar(
        """SELECT EXISTS(SELECT 1 FROM knowledge_revisions WHERE tenant_id=$1
               AND source_id=$2 AND source_version=$3)
           AND NOT EXISTS(SELECT 1 FROM knowledge_revisions WHERE tenant_id=$1
               AND source_id=$2 AND source_version=$3 AND content_hash=ANY($4::text[]))""",
        tenant, value["source_id"], value["source_version"], hashes, conn=conn,
    )
    require(not conflicting_version, "source_version already identifies different content", 409)
    existing = st.many(
        """SELECT s.*,r.parser_version FROM knowledge_sources s
           LEFT JOIN knowledge_revisions r ON r.tenant_id=s.tenant_id
               AND r.source_id=s.source_id AND r.generation=s.generation
           WHERE s.tenant_id=$1 AND s.source_id=$2""",
        tenant, value["source_id"], conn=conn,
    )
    if existing:
        old = existing[0]
        require(old["source_type"] == value["source_type"], "source type cannot change", 409)
        if old["source_version"] == value["source_version"]:
            require(old["desired_hash"] in hashes,
                    "source_version already identifies different content", 409)
            if (old["status"] != "revoked" and old["parser_version"] == PARSER_VERSION
                    and old["desired_hash"] == value["content_hash"]):
                changed = old["freshness_seconds"] != value["freshness_seconds"]
                if changed:
                    st.execute(
                        """UPDATE knowledge_sources SET freshness_seconds=$3,
                               fresh_until=verified_at+$3*interval '1 second',updated_at=clock_timestamp()
                           WHERE tenant_id=$1 AND source_id=$2""",
                        tenant, value["source_id"], value["freshness_seconds"], conn=conn,
                    )
                return old["generation"], old["status"] == "current", changed
    if not existing:
        _capacity(st, tenant, conn, "sources")
    _capacity(st, tenant, conn, "revisions")
    row = st.one(
        """INSERT INTO knowledge_sources(tenant_id,source_id,source_type,title,source_uri,scope_key,
                   generation,source_version,desired_hash,status,freshness_seconds)
           VALUES($1,$2,$3,$4,$5,$6,
             (SELECT revision+1 FROM tenant_knowledge WHERE tenant_id=$1),$7,$8,'pending',$9)
           ON CONFLICT (tenant_id,source_id) DO UPDATE SET
             title=EXCLUDED.title,source_uri=EXCLUDED.source_uri,scope_key=EXCLUDED.scope_key,
             generation=knowledge_sources.generation+1,source_version=EXCLUDED.source_version,
             desired_hash=EXCLUDED.desired_hash,status='pending',active_revision_id=NULL,
             freshness_seconds=EXCLUDED.freshness_seconds,verified_at=NULL,fresh_until=NULL,
             updated_at=clock_timestamp()
           RETURNING generation""",
        tenant, value["source_id"], value["source_type"], value["title"], value["source_uri"],
        value["scope_key"], value["source_version"], value["content_hash"], value["freshness_seconds"],
        conn=conn,
    )
    # Reserve the processing version with the generation. Staged revisions
    # stay invisible until publication sets the source's active pointer.
    st.execute(
        """INSERT INTO knowledge_revisions(tenant_id,revision_id,source_id,generation,
               source_version,content_hash,parser_version) VALUES($1,$2,$3,$4,$5,$6,$7)""",
        tenant, str(uuid.uuid4()), value["source_id"], row["generation"], value["source_version"],
        value["content_hash"], PARSER_VERSION, conn=conn,
    )
    return row["generation"], False, True


def begin_import(st, tenant, payload):
    """Record an observed source change before a worker parses or publishes it."""
    value = _validate(payload)
    with st.transaction() as conn:
        _lock(st, tenant, conn, payload["revision"])
        generation, reused, changed = _begin(st, tenant, value, conn)
        revision = _bump(st, tenant, conn) if changed else payload["revision"]
        return {"source_id": value["source_id"], "generation": generation,
                "revision": revision, "reused": reused}


def _publish(st, tenant, value, generation, passages, conn):
    current = st.one(
        """SELECT s.*,s.fresh_until>clock_timestamp() AS fresh,r.revision_id AS staged_revision_id,
                  r.parser_version,r.content_hash
           FROM knowledge_sources s LEFT JOIN knowledge_revisions r ON r.tenant_id=s.tenant_id
               AND r.source_id=s.source_id AND r.generation=s.generation
           WHERE s.tenant_id=$1 AND s.source_id=$2""",
        tenant, value["source_id"], conn=conn,
    )
    require(current["generation"] == generation and current["status"] != "revoked"
            and current["desired_hash"] == value["content_hash"]
            and current["content_hash"] == value["content_hash"]
            and current["parser_version"] == PARSER_VERSION,
            "source changed while importing; discard this generation", 409)
    revision_id = current["staged_revision_id"]
    if current["status"] != "current":
        _capacity(st, tenant, conn, "passages", len(passages))
        rows = [{"passage_id": str(uuid.uuid4()), "ordinal": ordinal,
                 "section_path": passage["section_path"], "body": passage["body"],
                 "content_hash": _hash(passage["body"])} for ordinal, passage in enumerate(passages)]
        st.execute(
            """INSERT INTO knowledge_passages(tenant_id,passage_id,revision_id,ordinal,kind,
                   title,section_path,body,content_hash)
               SELECT $1,p.passage_id,$2,p.ordinal,$3,$4,p.section_path,p.body,p.content_hash
               FROM jsonb_to_recordset($5::jsonb) AS p(passage_id uuid,ordinal integer,
                   section_path text,body text,content_hash text)""",
            tenant, revision_id, value["kind"], value["title"], json.dumps(rows), conn=conn,
        )
        st.execute(
            """INSERT INTO knowledge_passage_keys(tenant_id,passage_id,key_type,scope_key,
                   lookup_value,canonical_key)
               SELECT $1,p.passage_id,k.key_type,$3,k.lookup_value,k.canonical_key
               FROM unnest($2::uuid[]) AS p(passage_id)
               CROSS JOIN jsonb_to_recordset($4::jsonb) AS k(key_type text,lookup_value text,canonical_key text)
               ON CONFLICT DO NOTHING""",
            tenant, [row["passage_id"] for row in rows], value["scope_key"], json.dumps(value["keys"]), conn=conn,
        )
    st.execute(
        """UPDATE knowledge_sources SET active_revision_id=$3,status='current',
               verified_at=clock_timestamp(),fresh_until=CASE WHEN source_type IN ('manual','upload')
                   THEN '9999-12-31 00:00:00+00'::timestamptz
                   ELSE clock_timestamp()+freshness_seconds*interval '1 second' END,
               updated_at=clock_timestamp() WHERE tenant_id=$1 AND source_id=$2""",
        tenant, value["source_id"], revision_id, conn=conn,
    )
    return current["status"] != "current" or not current["fresh"]


def publish_import(st, tenant, payload, generation):
    """Publish only the generation returned by begin_import, in one transaction."""
    value = _validate(payload)
    passages = split_markdown(value["markdown"], value["title"])
    require(type(generation) is int and generation > 0, "invalid generation")
    with st.transaction() as conn:
        _lock(st, tenant, conn)
        if _publish(st, tenant, value, generation, passages, conn):
            _bump(st, tenant, conn)
        return read_source(st, tenant, value["source_id"], conn=conn)


def import_source(st, tenant, payload):
    """Import a normalized Markdown export after validating all section bounds."""
    value = _validate(payload)
    passages = split_markdown(value["markdown"], value["title"])
    with st.transaction() as conn:
        _lock(st, tenant, conn, payload["revision"])
        generation, _, changed = _begin(st, tenant, value, conn)
        published = _publish(st, tenant, value, generation, passages, conn)
        if changed or published:
            _bump(st, tenant, conn)
        return read_source(st, tenant, value["source_id"], conn=conn)


def verify_source(st, tenant, source_id, payload):
    """Refresh currentness only after a trusted importer verifies the same version."""
    _source_id(source_id, managed=True)
    require(not source_id.startswith("mcp:"), "Refresh MCP resources through their connection")
    require(isinstance(payload, dict) and set(payload) == {"revision", "source_version", "generation"},
            "revision, source_version, and generation are required")
    _revision(payload)
    _text(payload, "source_version", 160)
    require(type(payload["generation"]) is int and payload["generation"] > 0, "invalid generation")
    with st.transaction() as conn:
        _lock(st, tenant, conn, payload["revision"])
        source = st.one("SELECT *,fresh_until>clock_timestamp() AS fresh "
                        "FROM knowledge_sources WHERE tenant_id=$1 AND source_id=$2",
                        tenant, source_id, conn=conn)
        require(source["status"] == "current" and source["source_version"] == payload["source_version"]
                and source["generation"] == payload["generation"],
                "source changed; import the current version", 409)
        st.execute(
            """UPDATE knowledge_sources SET verified_at=clock_timestamp(),
                   fresh_until=CASE WHEN source_type='upload'
                     THEN '9999-12-31 00:00:00+00'::timestamptz
                     ELSE clock_timestamp()+freshness_seconds*interval '1 second' END,
                   updated_at=clock_timestamp() WHERE tenant_id=$1 AND source_id=$2""",
            tenant, source_id, conn=conn,
        )
        if not source["fresh"]:
            _bump(st, tenant, conn)
        return read_source(st, tenant, source_id, conn=conn)


def revoke_source(st, tenant, source_id, payload):
    _source_id(source_id, managed=True)
    require(not source_id.startswith("mcp:"), "Remove MCP resources through their connection")
    require(isinstance(payload, dict) and set(payload) == {"revision"}, "revision is required")
    _revision(payload)
    with st.transaction() as conn:
        _lock(st, tenant, conn, payload["revision"])
        st.one("SELECT source_id FROM knowledge_sources WHERE tenant_id=$1 AND source_id=$2",
               tenant, source_id, conn=conn)
        st.execute(
            """UPDATE knowledge_sources SET generation=generation+1,status='revoked',
                   active_revision_id=NULL,verified_at=NULL,fresh_until=NULL,updated_at=clock_timestamp()
               WHERE tenant_id=$1 AND source_id=$2""", tenant, source_id, conn=conn,
        )
        _bump(st, tenant, conn)
        return read_source(st, tenant, source_id, conn=conn)


def purge_source(st, tenant, source_id, payload):
    """Delete a revoked source and its retained history, including manual sources."""
    require(isinstance(payload, dict) and set(payload) == {"revision"}, "revision is required")
    _revision(payload)
    with st.transaction() as conn:
        _lock(st, tenant, conn, payload["revision"])
        source = st.one("SELECT status FROM knowledge_sources WHERE tenant_id=$1 AND source_id=$2",
                        tenant, source_id, conn=conn)
        require(source["status"] == "revoked", "only revoked sources can be purged", 409)
        # Cascades delete revisions, passages, and keys. Assessment snapshots
        # are stored as independent JSON and retain their original evidence.
        st.execute("DELETE FROM knowledge_sources WHERE tenant_id=$1 AND source_id=$2",
                   tenant, source_id, conn=conn)
        return {"revision": _bump(st, tenant, conn), "source_id": source_id, "purged": True}


def project_manual(st, tenant, pages, revision, *, conn):
    """Project legacy replacements in the caller's locked transaction.

    Legacy keyword matches are terms, not authoritative scoped resource keys.
    The manual API remains the only writer for this reserved source namespace.
    """
    source_ids = ["manual:" + page[0] for page in pages]
    st.execute(
        """UPDATE knowledge_sources SET status='revoked',active_revision_id=NULL,
               generation=generation+1,verified_at=NULL,fresh_until=NULL,updated_at=clock_timestamp()
           WHERE tenant_id=$1 AND source_type='manual' AND source_id<>ALL($2::text[])
             AND status<>'revoked'""", tenant, source_ids, conn=conn,
    )
    for ident, kind, title, keywords, body in pages:
        value = {"source_id": "manual:" + ident, "source_type": "manual", "source_version": str(revision),
                 "title": title, "source_uri": "wiki://manual/" + ident, "scope_key": "",
                 "markdown": body, "kind": kind, "freshness_seconds": 0,
                 "keys": [{"key_type": "term", "lookup_value": term, "canonical_key": ident}
                          for term in keywords]}
        current = st.many(
            """SELECT source_version,desired_hash FROM knowledge_sources
               WHERE tenant_id=$1 AND source_id=$2 AND source_type='manual' AND status='current'""",
            tenant, value["source_id"], conn=conn,
        )
        if current and current[0]["desired_hash"] == _content_hash(
            dict(value, source_version=current[0]["source_version"])
        ):
            continue
        value["content_hash"] = _content_hash(value)
        generation, _, _ = _begin(st, tenant, value, conn)
        # Legacy bodies are already bounded, and need not use Markdown syntax.
        _publish(st, tenant, value, generation,
                 [{"section_path": value["title"], "body": value["markdown"]}], conn)


def set_mode(st, tenant, payload):
    require(isinstance(payload, dict) and set(payload) == {"revision", "retrieval_mode"},
            "revision and retrieval_mode are required")
    _revision(payload)
    require(payload["retrieval_mode"] in ("legacy", "postgres"), "invalid retrieval_mode")
    with st.transaction() as conn:
        revision = _lock(st, tenant, conn, payload["revision"])
        if settings(st, tenant, conn=conn)["retrieval_mode"] == payload["retrieval_mode"]:
            return settings(st, tenant, conn=conn)
        if payload["retrieval_mode"] == "postgres":
            rows = st.many("SELECT id,kind,title,keywords,body FROM knowledge_documents WHERE tenant_id=$1",
                           tenant, conn=conn)
            project_manual(st, tenant, [(p["id"], p["kind"], p["title"], p["keywords"], p["body"])
                                       for p in rows], revision + 1, conn=conn)
        st.execute("UPDATE tenant_knowledge SET retrieval_mode=$2 WHERE tenant_id=$1",
                   tenant, payload["retrieval_mode"], conn=conn)
        _bump(st, tenant, conn)
        return settings(st, tenant, conn=conn)
