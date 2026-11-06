"""Bounded PostgreSQL retrieval of tenant reference evidence."""

import copy
import json
import re
import shlex
import time
from urllib.parse import urlsplit

import psycopg
from psycopg_pool import PoolTimeout, TooManyRequests

from . import knowledge

MAX_REFERENCE_BYTES = 6000
MAX_CANDIDATES = 64
MAX_DOCUMENTS = 4
IDENTIFIER = re.compile(r"[\w./:@-]+")
UNRESOLVED = re.compile(r"[$`;&|<>*?\[\]{}~\n\r]")


def _size(value):
    return len(json.dumps(value, ensure_ascii=False).encode())


def _reference(snapshot):
    return {"kind": "tool.result", "tool": {
        "name": "company_knowledge.search", "output": snapshot,
    }}


def _terms(value, *, limit=16):
    return list(dict.fromkeys(knowledge.TOKEN.findall(value.casefold())))[:limit]


def _parse(target):
    """Extract identifiers without evaluating a shell or trusting scope in text."""
    kind = target.get("kind")
    result = {"operation": "", "resource": "", "terms": [], "lexical_query": "",
              "gaps": [], "intent": "unknown"}
    if kind in ("command", "tool.call", "file.read", "file.write", "network"):
        terms = _terms(json.dumps(target, ensure_ascii=False, default=str), limit=129)
        result["terms"] = terms[:128]
        if len(terms) > 128:
            result["gaps"].append("query_terms_truncated")
    if target.get("truncated") or target.get("evidence_gaps"):
        result["gaps"].append("target_evidence_incomplete")
    if kind == "prompt":
        result.update(intent="discussion", terms=_terms(str(target.get("text", ""))))
        result["lexical_query"] = " ".join(result["terms"])
        result["gaps"].append("discussion_only")
        return result
    if kind in ("file.read", "file.write", "network"):
        # Paths and hosts are useful search text, not canonical identities.
        details = target.get("network" if kind == "network" else "file") or {}
        if isinstance(details, dict):
            value = details.get("host") if kind == "network" else details.get("path")
            if kind == "network" and not value and isinstance(details.get("url"), str):
                try:
                    value = urlsplit(details["url"]).hostname or details["url"]
                except ValueError:
                    value = details["url"]
            if isinstance(value, str):
                result["lexical_query"] = value
        result["intent"] = "action"
        result["gaps"].append("unresolved_identity")
        return result
    if kind not in ("command", "tool.call"):
        result["gaps"].append("unsupported_target")
        return result
    result["intent"] = "action"
    command = target.get("command") or {}
    if isinstance(command, dict):
        if set(command) - {"text", "argv", "cwd", "description", "background"}:
            result["gaps"].append("unsupported_arguments")
        if "text" in command and "argv" in command:
            result["gaps"].append("ambiguous_arguments")
        command = command.get("argv", command.get("text"))
    tool = target.get("tool") or {}
    tool = tool if isinstance(tool, dict) else {}
    if isinstance(tool.get("name"), str):
        result["lexical_query"] = tool["name"]
    inputs = tool.get("input")
    input_command = None
    command_keys = []
    if isinstance(inputs, dict):
        command_keys = [key for key in ("argv", "command", "cmd") if key in inputs]
        if command is not None or command_keys:
            # Sensor command events also retain the original tool input.
            # Metadata does not override arguments; unknown execution fields do.
            if set(inputs) - {"command", "cmd", "argv", "cwd", "workdir", "directory",
                              "description", "justification", "run_in_background", "timeout",
                              "timeout_ms", "yield_time_ms", "max_output_tokens"}:
                result["gaps"].append("unsupported_arguments")
            if len(command_keys) > 1:
                result["gaps"].append("ambiguous_arguments")
            if command_keys:
                input_command = inputs[command_keys[0]]
                if command is None:
                    command = input_command
        if command is None:
            operation = inputs.get("operation", inputs.get("action"))
            resource = inputs.get("destination", inputs.get("resource"))
            name = tool.get("name", "")
            if isinstance(name, str) and IDENTIFIER.fullmatch(name):
                if name.startswith("-") or any(
                    not isinstance(value, str) or not IDENTIFIER.fullmatch(value) or value.startswith("-")
                    for value in inputs.values()
                ):
                    result["gaps"].append("unsupported_arguments")
                result["operation"] = name
                if isinstance(operation, str) and IDENTIFIER.fullmatch(operation):
                    result["operation"] += " " + operation
                if isinstance(resource, str) and IDENTIFIER.fullmatch(resource):
                    result["resource"] = resource
                if set(inputs) - {"operation", "action", "destination", "resource"}:
                    result["gaps"].append("unsupported_arguments")
                    result["resource"] = ""
                if ("operation" in inputs and "action" in inputs) or (
                    "destination" in inputs and "resource" in inputs
                ):
                    result["gaps"].append("ambiguous_arguments")
                    result["resource"] = ""
                return result
    if isinstance(command, str):
        result["lexical_query"] = " ".join(_terms(command))
        if UNRESOLVED.search(command):
            result["gaps"].append("unsupported_shell")
            return result
        try:
            words = shlex.split(command)
        except ValueError:
            result["gaps"].append("invalid_command")
            return result
    elif isinstance(command, list) and all(isinstance(word, str) for word in command):
        words = command
        result["lexical_query"] = " ".join(_terms(" ".join(words)))
    else:
        result["gaps"].append("missing_command")
        return result
    if not words or len(words) > 32 or any(not IDENTIFIER.fullmatch(word) for word in words):
        result["gaps"].append("unsupported_arguments")
        return result
    if command_keys:
        try:
            input_words = shlex.split(input_command) if isinstance(input_command, str) else input_command
        except ValueError:
            input_words = None
        if input_words != words:
            result["gaps"].append("ambiguous_arguments")
    if words[0].startswith("-") or len(words) < 2 or words[1].startswith("-"):
        result["gaps"].append("unknown_operation")
        return result
    result["operation"] = " ".join(words[:2])
    if any(word.startswith("-") for word in words[2:]):
        # Flag meaning depends on the executable. Keep the original action for
        # the classifier but never let an override resolve a different account.
        result["gaps"].append("unsupported_flags")
    elif len(words) == 3:
        result["resource"] = words[2]
    elif len(words) > 3:
        result["gaps"].append("ambiguous_resource")
    return result


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0.005:
        raise TimeoutError
    return remaining


def _query(st, conn, deadline, query, *args, many=False):
    # SET LOCAL prevents retrieval timeouts leaking into other pool users.
    milliseconds = max(1, min(25, int((_remaining(deadline) - 0.005) * 1000)))
    conn.execute(f"SET LOCAL statement_timeout = {milliseconds}; SET LOCAL lock_timeout = 3")
    return (st.many if many else st.one)(query, *args, conn=conn)


_SOURCE_JOINS = """
    JOIN knowledge_revisions r ON r.tenant_id=p.tenant_id AND r.revision_id=p.revision_id
    JOIN knowledge_sources s ON s.tenant_id=r.tenant_id AND s.source_id=r.source_id
       AND s.active_revision_id=p.revision_id AND s.status='current'
"""
_FIELDS = """p.passage_id,p.kind,p.title,p.body,p.section_path,p.content_hash,
    s.source_id,s.source_uri,r.source_version,s.fresh_until"""
_LEXICAL_QUERY = f"""WITH candidates AS MATERIALIZED (
        SELECT p.* FROM knowledge_passages p
        JOIN knowledge_sources s ON s.tenant_id=p.tenant_id AND s.active_revision_id=p.revision_id
        WHERE p.tenant_id=$1 AND p.kind=ANY($3::text[])
            AND p.search_vector @@ plainto_tsquery('english',$4)
            AND s.status='current' AND s.scope_key=ANY($2::text[])
            AND s.fresh_until>clock_timestamp()
        LIMIT {MAX_CANDIDATES + 1}
    ) SELECT {_FIELDS},ts_rank_cd(p.search_vector,plainto_tsquery('english',$4)) AS rank
      FROM candidates p {_SOURCE_JOINS} ORDER BY rank DESC,passage_id"""


def _candidates(st, conn, deadline, tenant, category, value, terms, scope, *, lexical_query=""):
    kinds = ["command", "reference"] if category == "operation" else ["resource", "reference"]
    scope_keys = ["", scope] if category == "operation" else [scope]
    scope_keys = list(dict.fromkeys(key for key in scope_keys if key is not None))
    missing_scope = category == "resource" and not scope
    gaps = ["missing_scope"] if missing_scope else []
    rows = []
    if value and scope_keys:
        matches = f"""FROM knowledge_passage_keys k
            JOIN knowledge_passages p ON p.tenant_id=k.tenant_id AND p.passage_id=k.passage_id
            {_SOURCE_JOINS}
            WHERE p.tenant_id=$1 AND k.key_type=$2 AND k.lookup_value=$3
                AND k.scope_key=ANY($4::text[]) AND s.scope_key=ANY($4::text[])
                AND p.kind=ANY($5::text[])
                AND s.fresh_until>clock_timestamp()"""
        # Keys fan out to every passage in a source. Detect conflicting
        # identities before capping passages, including identities beyond the
        # selected source. The statement deadline also bounds this scan.
        identities = _query(st, conn, deadline,
            f"SELECT DISTINCT k.canonical_key {matches} LIMIT 2",
            tenant, category, value, scope_keys, kinds, many=True)
        if len(identities) > 1:
            return [], "ambiguous", gaps + [f"ambiguous_{category}"]
        if identities:
            # One extra passage is an omission sentinel for the evidence
            # packer. A long source still supplies a stable partial reference.
            rows = _query(st, conn, deadline,
                f"""SELECT DISTINCT {_FIELDS},p.ordinal,ARRAY[$3::text] AS matched_keywords
                    {matches}
                    ORDER BY s.source_id,p.ordinal,p.passage_id
                    LIMIT {MAX_DOCUMENTS + 1}""",
                tenant, category, value, scope_keys, kinds, many=True)
    if rows:
        return rows, "exact", gaps
    # Shared sources can supply candidates in either category. Resource exact
    # lookup above remains restricted to the authenticated scope alone.
    scope_keys = ["", scope] if scope else [""]
    if terms:
        # Existing manual keywords remain candidate aliases. They never
        # establish an operation or resource's canonical identity.
        rows = _query(st, conn, deadline,
            f"""WITH candidates AS MATERIALIZED (
                    SELECT p.* FROM knowledge_passages p
                    JOIN knowledge_sources s ON s.tenant_id=p.tenant_id AND s.active_revision_id=p.revision_id
                    WHERE p.tenant_id=$1 AND p.kind=ANY($4::text[])
                        AND s.status='current' AND s.scope_key=ANY($3::text[])
                        AND s.fresh_until>clock_timestamp()
                        AND EXISTS (
                            SELECT 1 FROM knowledge_passage_keys k
                            WHERE k.tenant_id=p.tenant_id AND k.passage_id=p.passage_id
                                AND k.key_type='term' AND k.lookup_value=ANY($2::text[])
                                AND k.scope_key=ANY($3::text[]))
                    LIMIT {MAX_CANDIDATES + 1}
                ) SELECT {_FIELDS},ARRAY(
                    SELECT DISTINCT k.lookup_value FROM knowledge_passage_keys k
                    WHERE k.tenant_id=p.tenant_id AND k.passage_id=p.passage_id
                        AND k.key_type='term' AND k.lookup_value=ANY($2::text[])
                        AND k.scope_key=ANY($3::text[])
                    ORDER BY k.lookup_value) AS matched_keywords
                  FROM candidates p {_SOURCE_JOINS} ORDER BY p.passage_id""",
            tenant, terms, scope_keys, kinds, many=True)
        if len(rows) > MAX_CANDIDATES:
            return [], "overflow", gaps + [f"{category}_candidate_overflow"]
        if rows:
            return rows, "lexical", gaps + [f"{category}_lexical_only"]
    query = value or lexical_query
    if not query:
        return [], "unknown" if missing_scope else "missing", gaps + [f"no_{category}_match"]
    # Rank only a bounded candidate set. LIMIT on a fully ranked result does
    # not bound ranking work. Overflow explicitly means incomplete coverage.
    # Filter source eligibility before the cap; join revision provenance only
    # afterwards. This preserves selective GIN and scoped revision-index plans
    # without materializing all text matches that the scope later excludes.
    rows = _query(st, conn, deadline, _LEXICAL_QUERY,
        tenant, scope_keys, kinds, query, many=True)
    if len(rows) > MAX_CANDIDATES:
        return [], "overflow", gaps + [f"{category}_candidate_overflow"]
    return rows, "lexical" if rows else "unknown" if missing_scope else "missing", gaps + [
        f"{category}_lexical_only" if rows else f"no_{category}_match"]


def _drop_document(snapshot):
    page = snapshot["documents"].pop()
    snapshot["truncated"] = True
    if snapshot.get("schema_version") == 2:
        snapshot["status"] = "partial"
        snapshot["gaps"] = sorted(set(snapshot["gaps"] + ["evidence_truncated"]))
        for category in page.get("categories", []):
            snapshot["category_coverage"][category] = "unknown"


def _bound(snapshot):
    from openaidr.core.redact import redact_value

    redacted = redact_value(snapshot)
    if redacted != snapshot and snapshot.get("schema_version") == 2:
        redacted["status"] = "partial"
        redacted["gaps"] = sorted(set(redacted["gaps"] + ["evidence_redacted"]))
    while redacted["documents"] and _size(_reference(redacted)) > MAX_REFERENCE_BYTES:
        _drop_document(redacted)
    return redacted


def retrieve(st, tenant_id, target, *, trusted_scope=None, deadline=None):
    """Retrieve reference evidence. ``deadline`` is an absolute monotonic time.

    Only callers holding an authenticated server scope binding may supply
    ``trusted_scope``. Client arguments and natural language are not bindings.
    """
    started = time.monotonic()
    deadline = min(started + 0.050, deadline) if deadline is not None else started + 0.050
    snapshot = {
        "enabled": False, "revision": 0, "retrieval_ms": 0,
        "coverage": knowledge.COVERAGE, "truncated": False, "documents": [],
    }
    mode = None
    try:
        parsed = _parse(target)
        scope = trusted_scope if isinstance(trusted_scope, str) and 0 < len(trusted_scope) <= 240 else None
        with st.pools["data"].connection(timeout=min(0.005, _remaining(deadline))) as conn:
            with conn.transaction():
                # Scope, category, and alias selectivity vary sharply between
                # requests. A generic prepared plan can scan the whole corpus.
                conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
                             "SET LOCAL plan_cache_mode=force_custom_plan")
                settings = _query(st, conn, deadline,
                    """SELECT COALESCE(k.enabled,false) AS enabled,
                           COALESCE(k.revision,0) AS revision,
                           COALESCE(k.retrieval_mode,'legacy') AS retrieval_mode
                       FROM (SELECT $1::uuid AS tenant_id) t
                       LEFT JOIN tenant_knowledge k ON k.tenant_id=t.tenant_id""", tenant_id)
                mode = settings["retrieval_mode"]
                snapshot.update(enabled=settings["enabled"], revision=settings["revision"])
                if mode == "legacy":
                    terms = []
                    if target.get("kind") in ("command", "tool.call", "file.read", "file.write", "network"):
                        terms = list(dict.fromkeys(knowledge.TOKEN.findall(
                            json.dumps(target, ensure_ascii=False).casefold())))
                    result = _query(st, conn, deadline,
                        """SELECT id,kind,title,keywords,body FROM knowledge_documents
                           WHERE tenant_id=$1 AND $2 AND keywords && $3::text[]
                           ORDER BY id LIMIT 5""", tenant_id, settings["enabled"], terms[:128], many=True)
                    snapshot.update(truncated=len(terms) > 128 or len(result) > MAX_DOCUMENTS,
                        documents=[{
                            "id": page["id"], "kind": page["kind"], "title": page["title"],
                            "text": page["body"],
                            "matched_keywords": sorted(set(page["keywords"]) & set(terms[:128])),
                        } for page in result[:MAX_DOCUMENTS]])
                else:
                    snapshot.update(schema_version=2, mode="postgres", reference_only=True,
                        status="disabled" if not settings["enabled"] else "no_match",
                        scope={"key": scope}, intent=parsed["intent"], gaps=list(parsed["gaps"]),
                        category_coverage={"operation": "unknown", "resource": "unknown"}, valid_until=None)
                    if settings["enabled"]:
                        buckets = []
                        for category in ("operation", "resource"):
                            if (category == "resource" and parsed["intent"] == "action"
                                and any(gap != "query_terms_truncated" for gap in parsed["gaps"])):
                                # An argument override invalidates the execution
                                # scope. Shared reference candidates remain useful.
                                reference_scope = scope if target.get("kind") in (
                                    "file.read", "file.write", "network") else None
                                rows, coverage, gaps = _candidates(st, conn, deadline, tenant_id,
                                    category, "", parsed["terms"], reference_scope,
                                    lexical_query=parsed["lexical_query"])
                                gaps.append("unresolved_resource")
                            else:
                                rows, coverage, gaps = _candidates(st, conn, deadline, tenant_id,
                                    category, parsed[category], parsed["terms"], scope,
                                    lexical_query=parsed["lexical_query"])
                            snapshot["category_coverage"][category] = coverage
                            snapshot["gaps"].extend(gaps)
                            buckets.append((category, coverage, rows))
                        documents = {}
                        expiries = []
                        # Reserve the first passage for each category before extras.
                        for rank in range(MAX_DOCUMENTS):
                            for category, coverage, rows in buckets:
                                if rank >= len(rows):
                                    continue
                                row = rows[rank]
                                ident = row["passage_id"]
                                if ident in documents:
                                    documents[ident]["categories"].append(category)
                                    documents[ident]["matched_keywords"] = sorted(set(
                                        documents[ident]["matched_keywords"] + row.get("matched_keywords", [])))
                                    if coverage == "lexical" or (coverage == "ambiguous" and documents[ident]["match"] == "exact"):
                                        documents[ident]["match"] = coverage
                                elif len(documents) < MAX_DOCUMENTS:
                                    documents[ident] = {
                                        "id": ident, "kind": row["kind"], "title": row["title"],
                                        "text": row["body"], "section_path": row["section_path"],
                                        "source_id": row["source_id"], "source_uri": row["source_uri"],
                                        "source_revision": row["source_version"], "content_hash": row["content_hash"],
                                        "matched_keywords": row.get("matched_keywords", []),
                                        "categories": [category], "match": coverage,
                                    }
                                    expiries.append(row["fresh_until"])
                        snapshot["documents"] = list(documents.values())
                        snapshot["valid_until"] = min(expiries).isoformat() if expiries else None
                        for category, coverage, rows in buckets:
                            if any(row["passage_id"] not in documents for row in rows):
                                snapshot["truncated"] = True
                                snapshot["gaps"].append("evidence_truncated")
                                snapshot["category_coverage"][category] = "unknown"
                        if any(coverage == "ambiguous" for _, coverage, _ in buckets):
                            # Another category can select a reference from only
                            # one conflicting identity. Withhold the packet so
                            # its document limit cannot favor either identity.
                            snapshot["truncated"] = True
                            snapshot["gaps"].append("evidence_truncated")
                            while snapshot["documents"]:
                                _drop_document(snapshot)
                            snapshot["valid_until"] = None
                        snapshot["gaps"] = sorted(set(snapshot["gaps"]))
                        coverage = snapshot["category_coverage"].values()
                        if (snapshot["gaps"] == ["query_terms_truncated"] and not snapshot["truncated"]
                            and all(value == "exact" for value in coverage)):
                            # Lexical terms were not needed for these exact facts.
                            snapshot["gaps"] = []
                        if not snapshot["gaps"] and all(value == "exact" for value in coverage):
                            snapshot["status"] = "matched"
                        elif not documents and not parsed["gaps"] and all(value == "missing" for value in coverage):
                            snapshot["status"] = "no_match"
                        else:
                            snapshot["status"] = "partial"
        _remaining(deadline)
    except (TimeoutError, PoolTimeout, TooManyRequests, psycopg.Error):
        # The pool context rolls back failed transactions before reusing a
        # connection. No detached worker continues a canceled SQL request.
        snapshot.update(documents=[], schema_version=2, mode=mode or "unknown",
            status="unavailable", valid_until=None, reference_only=True,
            category_coverage={"operation": "unknown", "resource": "unknown"},
            gaps=["retrieval_unavailable"])
        if mode is None:
            snapshot["revision"] = None
    snapshot = _bound(snapshot)
    if time.monotonic() >= deadline:
        snapshot.update(documents=[], schema_version=2, mode=mode or "unknown",
            status="unavailable", valid_until=None, reference_only=True,
            category_coverage={"operation": "unknown", "resource": "unknown"},
            gaps=["retrieval_deadline"])
    snapshot["retrieval_ms"] = round((time.monotonic() - started) * 1000, 3)
    return snapshot


def augment_state(state, snapshot):
    """Return the bounded state and the exact snapshot sent to the classifier."""
    from .guardrail.evidence import MAX_STATE_BYTES

    prepared = copy.deepcopy(state)
    sent = _bound(copy.deepcopy(snapshot))
    if sent.get("schema_version") != 2 and (not sent["enabled"] or not sent["documents"]):
        return prepared, sent
    prior = prepared.setdefault("prior_events", [])
    reference = _reference(sent)
    prior.append(reference)
    while len(prior) > 1 and _size(prepared) > MAX_STATE_BYTES:
        prior.pop(0)
        prepared["context_limited"] = True
    while sent["documents"] and _size(prepared) > MAX_STATE_BYTES:
        _drop_document(sent)
    if _size(prepared) > MAX_STATE_BYTES:
        prior.pop()
        sent.update(documents=[], truncated=True)
        if sent.get("schema_version") == 2:
            sent.update(status="partial", category_coverage={"operation": "unknown", "resource": "unknown"},
                gaps=sorted(set(sent["gaps"] + ["evidence_omitted"])))
        # No fabricated claim that an omitted snapshot reached the classifier.
        sent["sent"] = False
    return prepared, sent
