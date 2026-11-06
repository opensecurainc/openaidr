"""Tenant-shared reference documents for contextual JEV assessments."""

import json
import re
import time

from .httpx import require

TOKEN = re.compile(r"[\w-]+")
COVERAGE = "Keyword matches are candidates; missing documentation does not establish safety."


def read(st, tenant, terms=None, *, conn=None):
    # Settings and documents share one database snapshot, including during updates.
    return st.one(
        """SELECT COALESCE(k.enabled,false) AS enabled,
               COALESCE(k.revision,0) AS revision, k.updated_at,
               COALESCE((SELECT jsonb_agg(d ORDER BY d.id) FROM (
                   SELECT id,kind,title,keywords,body FROM knowledge_documents
                   WHERE tenant_id=$1 AND ($2::text[] IS NULL OR
                       (k.enabled AND keywords && $2::text[]))
                   ORDER BY id LIMIT $3
               ) d),'[]'::jsonb) AS documents
           FROM (SELECT $1::uuid AS tenant_id) t
           LEFT JOIN tenant_knowledge k ON k.tenant_id=t.tenant_id""",
        tenant, terms, 64 if terms is None else 5, conn=conn,
    )


def _text(document, key, limit):
    value = document.get(key)
    try:
        size = len(value.encode()) if isinstance(value, str) else limit + 1
    except UnicodeError:
        size = limit + 1
    require(
        isinstance(value, str) and bool(value.strip()) and "\x00" not in value
        and size <= limit,
        f"{key} must be nonempty text of at most {limit} UTF-8 bytes",
    )
    return value


def update(st, tenant, data, *, documents=False):
    field = "documents" if documents else "enabled"
    require(set(data) == {"revision", field}, f"revision and {field} are required")
    require(type(data["revision"]) is int and data["revision"] >= 0, "invalid revision")
    pages = []
    if documents:
        require(isinstance(data[field], list) and len(data[field]) <= 64,
                "documents must be an array of at most 64 pages")
        ids = set()
        for page in data[field]:
            require(isinstance(page, dict) and set(page) == {"id", "kind", "title", "keywords", "body"},
                    "invalid document fields")
            ident = _text(page, "id", 80)
            require(TOKEN.fullmatch(ident) and ident not in ids, "invalid or duplicate document id")
            ids.add(ident)
            require(page["kind"] in ("command", "resource"), "invalid document kind")
            keywords = page["keywords"]
            require(isinstance(keywords, list) and 1 <= len(keywords) <= 32,
                    "keywords must contain between 1 and 32 terms")
            terms = []
            for keyword in keywords:
                term = _text({"keyword": keyword}, "keyword", 80).casefold()
                require(TOKEN.fullmatch(term), "keywords must be single words or identifiers")
                terms.append(term)
            pages.append((ident, page["kind"], _text(page, "title", 240),
                          sorted(set(terms)), _text(page, "body", 2000)))
    else:
        require(type(data[field]) is bool, "enabled must be a boolean")
    with st.transaction() as conn:
        st.execute("INSERT INTO tenant_knowledge(tenant_id) VALUES($1) ON CONFLICT DO NOTHING",
                   tenant, conn=conn)
        revision = st.scalar("SELECT revision FROM tenant_knowledge WHERE tenant_id=$1 FOR UPDATE",
                             tenant, conn=conn)
        require(revision == data["revision"], "knowledge changed; reload before saving", 409)
        if documents:
            st.execute("DELETE FROM knowledge_documents WHERE tenant_id=$1", tenant, conn=conn)
            for page in pages:
                st.execute("INSERT INTO knowledge_documents(tenant_id,id,kind,title,keywords,body) "
                           "VALUES($1,$2,$3,$4,$5,$6)", tenant, *page, conn=conn)
            from .knowledge_ingest import project_manual

            project_manual(st, tenant, pages, revision + 1, conn=conn)
        st.execute(
            """UPDATE tenant_knowledge SET revision=revision+1,updated_at=clock_timestamp(),
                   enabled=COALESCE($2,enabled) WHERE tenant_id=$1""",
            tenant, None if documents else data[field], conn=conn,
        )
        return read(st, tenant, conn=conn)


def evidence(snapshot):
    return {"kind": "tool.result", "body": {"tool": {
        "name": "company_knowledge.search", "output": snapshot,
    }}}


def lookup(st, row):
    from .guardrail.evidence import event_evidence
    from openaidr.core.redact import redact_value

    started = time.perf_counter()
    terms = []
    if row["kind"] in ("command", "tool.call", "file.read", "file.write", "network"):
        text = json.dumps(event_evidence(row), ensure_ascii=False)
        terms = list(dict.fromkeys(TOKEN.findall(text.casefold())))
    result = read(st, row["tenant_id"], terms[:128])
    snapshot = {
        "enabled": result["enabled"], "revision": result["revision"],
        "retrieval_ms": round((time.perf_counter() - started) * 1000, 3),
        "coverage": COVERAGE,
        "truncated": len(terms) > 128 or len(result["documents"]) > 4,
        "documents": [{
            "id": page["id"], "kind": page["kind"], "title": page["title"],
            "text": page["body"],
            "matched_keywords": sorted(set(page["keywords"]) & set(terms[:128])),
        } for page in result["documents"][:4]],
    }
    snapshot = redact_value(snapshot)
    # Reserve space for the target and prompt under the existing JEV state cap.
    # Drop whole documents so the stored citations match the evidence sent.
    while len(json.dumps(evidence(snapshot), ensure_ascii=False).encode()) > 6000:
        snapshot["documents"].pop()
        snapshot["truncated"] = True
    return snapshot
