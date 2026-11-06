"""The dashboard library and ingestion of locally owned document snapshots."""

from . import knowledge, knowledge_ingest as ingest
from .httpx import require


def read(st, tenant):
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        result = knowledge.read(st, tenant, conn=conn)
        result.update(ingest.settings(st, tenant, conn=conn))
        result["sources"] = st.many(
            f"SELECT {ingest.SOURCE_COLUMNS} FROM knowledge_sources "
            "WHERE tenant_id=$1 ORDER BY updated_at DESC,source_id", tenant, conn=conn,
        )
        return result


def import_document(st, tenant, payload, *, source_type="upload", conn=None):
    if conn is None:
        with st.transaction() as connection:
            return import_document(st, tenant, payload, source_type=source_type, conn=connection)
    value = ingest._validate(payload, source_type=source_type)
    passages = split_text(value["markdown"], value["title"])
    revision = ingest._lock(st, tenant, conn, payload["revision"])
    generation, _, changed = ingest._begin(st, tenant, value, conn)
    published = ingest._publish(st, tenant, value, generation, passages, conn)
    if ingest.settings(st, tenant, conn=conn)["retrieval_mode"] != "postgres":
        rows = st.many("SELECT id,kind,title,keywords,body FROM knowledge_documents WHERE tenant_id=$1",
                       tenant, conn=conn)
        ingest.project_manual(st, tenant, [tuple(p[k] for k in ("id", "kind", "title", "keywords", "body"))
                                          for p in rows], revision + 1, conn=conn)
        st.execute("UPDATE tenant_knowledge SET retrieval_mode='postgres' WHERE tenant_id=$1", tenant, conn=conn)
        changed = True
    if changed or published:
        ingest._bump(st, tenant, conn)
    return ingest.read_source(st, tenant, value["source_id"], conn=conn)


def split_text(text, title):
    """Bound reference excerpts with overlap; they do not establish entity identity."""
    parts = []
    remaining = text.strip()
    while remaining:
        piece = remaining.encode()[:1800].decode("utf-8", errors="ignore")
        if len(piece) < len(remaining):
            boundary = max(piece.rfind("\n"), piece.rfind(" "))
            if boundary > len(piece) // 2:
                piece = piece[:boundary + 1]
        parts.append({"section_path": f"{title} / Part {len(parts) + 1}", "body": piece})
        if len(piece) == len(remaining):
            break
        overlap = piece[-200:]
        boundary = overlap.find(" ")
        overlap = overlap[boundary + 1:] if boundary >= 0 else ""
        remaining = overlap + remaining[len(piece):]
    require(0 < len(parts) <= ingest.MAX_PASSAGES,
            f"document must contain between 1 and {ingest.MAX_PASSAGES} passages")
    return parts
