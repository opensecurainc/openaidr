import copy

import psycopg
import pytest

from openaidr.server import knowledge, knowledge_ingest as ingest
from openaidr.server.httpx import APIError
from openaidr.server.store import NotFound
from test_store import db, sensor, tenant


def source(**changes):
    value = {
        "revision": 0, "source_id": "omg", "source_version": "17",
        "title": "Zone drain reference", "source_uri": "https://wiki.example.test/tools/omg",
        "scope_key": "account:core", "kind": "command",
        "markdown": "# Drain\nThe omg drain operation drains a network zone.\n\n"
                    "A drain on production requires approval.",
        "keys": [{"key_type": "operation", "lookup_value": "omg drain", "canonical_key": "omg:drain"}],
    }
    value.update(changes)
    return value


def test_import_is_tenant_scoped_with_immutable_content_and_native_search(db):
    first, other = tenant(db)["id"], tenant(db)["id"]
    assert ingest.settings(db, first)["retrieval_mode"] == "legacy"
    payload = source(markdown=source()["markdown"] + "\n\n# Audit\nRecord the change request.")
    saved = ingest.import_source(db, first, payload)
    assert saved["revision"] == 1 and saved["source"]["generation"] == 1
    assert saved["source"]["fresh"] and len(saved["passages"]) == 2
    assert all(passage["keys"] == [dict(payload["keys"][0], scope_key="account:core")]
               for passage in saved["passages"])
    assert knowledge.read(db, first)["documents"] == []
    again = ingest.import_source(db, first, dict(payload, revision=1))
    assert again["revision"] == saved["revision"]
    assert again["source"]["active_revision_id"] == saved["source"]["active_revision_id"]
    assert again["passages"] == saved["passages"]
    assert db.scalar("SELECT count(*) FROM knowledge_revisions WHERE tenant_id=$1", first) == 1
    assert db.scalar(
        "SELECT count(*) FROM knowledge_passages WHERE tenant_id=$1 "
        "AND search_vector @@ plainto_tsquery('english','drain production')", first,
    ) == 1
    assert ingest.list_sources(db, other)["sources"] == []
    with pytest.raises(NotFound):
        ingest.read_source(db, other, "omg")
    foreign = ingest.import_source(db, other, source(markdown="# Drain\nDevelopment only."))
    assert foreign["passages"][0]["body"] != saved["passages"][0]["body"]
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with db.transaction() as conn:
            db.execute(
                "INSERT INTO knowledge_passage_keys(tenant_id,passage_id,key_type,scope_key,lookup_value,canonical_key) "
                "VALUES($1,$2,'resource','account:core','other','other')",
                other, saved["passages"][0]["passage_id"], conn=conn,
            )


def test_observed_change_hides_old_revision_and_rejects_late_publication(db):
    tid = tenant(db)["id"]
    initial = ingest.import_source(db, tid, source())
    second = source(revision=1, source_version="18", markdown="# Drain\nChanged procedure.")
    pending = ingest.begin_import(db, tid, second)
    assert pending["generation"] == 2
    hidden = ingest.read_source(db, tid, "omg")
    assert hidden["passages"] == []
    third = source(revision=pending["revision"], source_version="19", markdown="# Drain\nCurrent procedure.")
    latest = ingest.begin_import(db, tid, third)
    with pytest.raises(APIError, match="discard this generation") as error:
        ingest.publish_import(db, tid, second, pending["generation"])
    assert error.value.status == 409
    published = ingest.publish_import(db, tid, third, latest["generation"])
    assert published["source"]["source_version"] == "19"
    assert published["passages"][0]["body"] == third["markdown"]
    assert db.scalar("SELECT body FROM knowledge_passages WHERE tenant_id=$1 AND passage_id=$2",
                     tid, initial["passages"][0]["passage_id"]) == initial["passages"][0]["body"]
    changed = source(revision=published["revision"], source_version="19", markdown="Different content")
    with pytest.raises(APIError, match="different content"):
        ingest.import_source(db, tid, changed)
    with pytest.raises(APIError, match="different content"):
        ingest.import_source(db, tid, source(revision=published["revision"], markdown="Reused old version"))
    assert ingest.read_source(db, tid, "omg")["passages"] == published["passages"]
    with pytest.raises(APIError, match="reload before saving"):
        ingest.import_source(db, tid, source(revision=0, source_version="20"))


def test_expiry_verification_and_revocation_cannot_revive_old_worker(db):
    tid = tenant(db)["id"]
    saved = ingest.import_source(db, tid, source())
    unchanged = ingest.verify_source(db, tid, "omg", {"revision": 1, "source_version": "17", "generation": 1})
    assert unchanged["revision"] == saved["revision"]
    db.execute("UPDATE knowledge_sources SET fresh_until=clock_timestamp()-interval '1 second' "
               "WHERE tenant_id=$1", tid)
    expired = ingest.read_source(db, tid, "omg")
    assert expired["passages"] == [] and not expired["source"]["fresh"]
    with pytest.raises(APIError, match="source changed"):
        ingest.verify_source(db, tid, "omg", {"revision": 1, "source_version": "16", "generation": 1})
    verified = ingest.verify_source(db, tid, "omg", {"revision": 1, "source_version": "17", "generation": 1})
    assert verified["revision"] == saved["revision"] + 1
    assert verified["source"]["fresh"] and verified["passages"] == saved["passages"]
    revoked = ingest.revoke_source(db, tid, "omg", {"revision": verified["revision"]})
    assert revoked["source"]["status"] == "revoked" and revoked["passages"] == []
    with pytest.raises(APIError, match="discard this generation"):
        ingest.publish_import(db, tid, source(), 1)
    with pytest.raises(APIError, match="source changed"):
        ingest.verify_source(db, tid, "omg", {"revision": revoked["revision"], "source_version": "17", "generation": 2})
    assert db.scalar("SELECT count(*) FROM knowledge_revisions WHERE tenant_id=$1", tid) == 1


def test_freshness_policy_changes_keep_passages_and_invalidate_context(db):
    tid = tenant(db)["id"]
    saved = ingest.import_source(db, tid, source())
    for seconds in (60, 1800):
        payload = source(revision=saved["revision"], freshness_seconds=seconds)
        updated = ingest.import_source(db, tid, payload)
        assert updated["revision"] == saved["revision"] + 1
        assert updated["source"]["source_version"] == saved["source"]["source_version"]
        assert updated["source"]["generation"] == saved["source"]["generation"]
        assert updated["source"]["active_revision_id"] == saved["source"]["active_revision_id"]
        assert updated["passages"] == saved["passages"]
        assert updated["source"]["freshness_seconds"] == seconds
        assert round((updated["source"]["fresh_until"] - updated["source"]["verified_at"]).total_seconds()) == seconds
        again = ingest.import_source(db, tid, dict(payload, revision=updated["revision"]))
        assert again["revision"] == updated["revision"]
        # A delayed publication cannot restore its earlier freshness policy.
        late = ingest.publish_import(db, tid, source(), saved["source"]["generation"])
        assert late["source"]["freshness_seconds"] == seconds
        assert late["revision"] == updated["revision"]
        saved = updated
    assert db.scalar("SELECT count(*) FROM knowledge_revisions WHERE tenant_id=$1", tid) == 1


def test_parser_upgrade_rebuilds_same_source_without_mutating_history(db, monkeypatch):
    from openaidr.core import redact

    tid = tenant(db)["id"]
    payload = source(kind="reference", markdown="# Drain\nPreserve the legacy-marker.", keys=[
        {"key_type": "operation", "lookup_value": "OMG Drain", "canonical_key": "OMG:Drain"},
        {"key_type": "resource", "lookup_value": "US-West-1", "canonical_key": "Core:Zone"},
        {"key_type": "term", "lookup_value": "CloudSweeper", "canonical_key": "Maintenance"},
    ])
    saved = ingest.import_source(db, tid, payload)
    # Earlier parsers stored term aliases without casefolding.
    db.execute("UPDATE knowledge_passage_keys SET lookup_value='CloudSweeper' "
               "WHERE tenant_id=$1 AND key_type='term'", tid)
    original_redact = redact.redact_value

    def new_redaction(value):
        result = original_redact(value)
        return result.replace("legacy-marker", "[REDACTED:updated]") if isinstance(result, str) else result

    monkeypatch.setattr(redact, "redact_value", new_redaction)
    monkeypatch.setattr(ingest, "PARSER_VERSION", ingest.PARSER_VERSION + "-next")
    rebuilt = ingest.import_source(db, tid, dict(payload, revision=saved["revision"]))
    assert rebuilt["revision"] == saved["revision"] + 1
    assert rebuilt["source"]["generation"] == saved["source"]["generation"] + 1
    assert rebuilt["source"]["source_version"] == saved["source"]["source_version"]
    assert rebuilt["source"]["active_revision_id"] != saved["source"]["active_revision_id"]
    assert rebuilt["passages"][0]["body"] == "# Drain\nPreserve the [REDACTED:updated]."
    assert db.scalar("SELECT body FROM knowledge_passages WHERE tenant_id=$1 AND passage_id=$2",
                     tid, saved["passages"][0]["passage_id"]) == saved["passages"][0]["body"]
    versions = db.many("SELECT parser_version,content_hash FROM knowledge_revisions "
                       "WHERE tenant_id=$1 ORDER BY generation", tid)
    assert versions[1]["parser_version"] == ingest.PARSER_VERSION
    assert versions[0]["content_hash"] == versions[1]["content_hash"]
    aliases = db.many("SELECT key_type,lookup_value,canonical_key FROM knowledge_passage_keys "
                      "WHERE tenant_id=$1 AND passage_id=$2 ORDER BY key_type",
                      tid, rebuilt["passages"][0]["passage_id"])
    assert aliases == [*payload["keys"][:2], dict(payload["keys"][2], lookup_value="cloudsweeper")]
    assert db.scalar("SELECT lookup_value FROM knowledge_passage_keys "
                     "WHERE tenant_id=$1 AND passage_id=$2 AND key_type='term'",
                     tid, saved["passages"][0]["passage_id"]) == "CloudSweeper"
    changed = copy.deepcopy(payload)
    changed["revision"] = rebuilt["revision"]
    changed["keys"][2]["lookup_value"] = "cloudsweeper"
    with pytest.raises(APIError, match="different content"):
        ingest.import_source(db, tid, changed)
    again = ingest.import_source(db, tid, dict(payload, revision=rebuilt["revision"]))
    assert again["revision"] == rebuilt["revision"] and again["passages"] == rebuilt["passages"]


def test_pending_import_pins_parser_version_and_rejects_late_workers(db, monkeypatch):
    tid = tenant(db)["id"]
    payload = source()
    previous_parser = ingest.PARSER_VERSION
    pending = ingest.begin_import(db, tid, payload)
    monkeypatch.setattr(ingest, "PARSER_VERSION", previous_parser + "-next")
    with pytest.raises(APIError, match="discard this generation"):
        ingest.publish_import(db, tid, payload, pending["generation"])
    replacement = ingest.begin_import(db, tid, dict(payload, revision=pending["revision"]))
    assert replacement["generation"] == pending["generation"] + 1
    assert ingest.read_source(db, tid, "omg")["passages"] == []
    with monkeypatch.context() as worker:
        worker.setattr(ingest, "PARSER_VERSION", previous_parser)
        for generation in (pending["generation"], replacement["generation"]):
            with pytest.raises(APIError, match="discard this generation"):
                ingest.publish_import(db, tid, payload, generation)
    published = ingest.publish_import(db, tid, payload, replacement["generation"])
    assert published["source"]["generation"] == replacement["generation"]
    assert published["passages"][0]["body"] == payload["markdown"]
    assert db.scalar("SELECT parser_version FROM knowledge_revisions WHERE tenant_id=$1 AND revision_id=$2",
                     tid, published["source"]["active_revision_id"]) == ingest.PARSER_VERSION


def test_same_version_rejects_changed_raw_content_that_redacts_identically(db):
    tid = tenant(db)["id"]
    first = source(markdown="# Credentials\nAPI_TOKEN=synthetic-first")
    second = source(markdown="# Credentials\nAPI_TOKEN=synthetic-second")
    assert ingest._validate(first)["markdown"] == ingest._validate(second)["markdown"]
    saved = ingest.import_source(db, tid, first)
    with pytest.raises(APIError, match="different content"):
        ingest.import_source(db, tid, dict(second, revision=saved["revision"]))
    assert ingest.read_source(db, tid, "omg")["passages"] == saved["passages"]


@pytest.mark.parametrize("markdown", [
    "# C#\rKeep the instructions.\r\r## Release###\rPreserve the suffix.",
    "# C#\rKeep the instructions.\n\n## Release###\r\nPreserve the suffix.",
])
def test_newline_normalization_repairs_legacy_hashes_without_changing_source_identity(db, markdown):
    tid = tenant(db)["id"]
    payload = source(markdown=markdown)
    value = ingest._validate(payload)
    legacy_hash = ingest._content_hash(dict(value, markdown=markdown.replace("\r\n", "\n")))
    saved = ingest.import_source(db, tid, payload)
    # Recreate a stored revision from the parser that retained lone CR in its input hash.
    db.execute("UPDATE knowledge_revisions SET content_hash=$2,parser_version='markdown-sections-v3' "
               "WHERE tenant_id=$1", tid, legacy_hash)
    db.execute("UPDATE knowledge_sources SET desired_hash=$2 WHERE tenant_id=$1", tid, legacy_hash)
    normalized = markdown.replace("\r\n", "\n").replace("\r", "\n")
    repair_text = normalized if "\n" not in markdown else markdown
    repaired = ingest.import_source(db, tid, dict(payload, revision=saved["revision"], markdown=repair_text))
    assert repaired["revision"] == saved["revision"] + 1
    assert repaired["source"]["generation"] == saved["source"]["generation"] + 1
    assert repaired["source"]["source_version"] == saved["source"]["source_version"]
    assert [passage["section_path"] for passage in repaired["passages"]] == ["C#", "C# / Release###"]
    hashes = db.many("SELECT content_hash FROM knowledge_revisions WHERE tenant_id=$1 ORDER BY generation", tid)
    assert [row["content_hash"] for row in hashes] == [legacy_hash, value["content_hash"]]
    canonical = dict(payload, revision=repaired["revision"], markdown=normalized)
    again = ingest.import_source(db, tid, canonical)
    assert again["revision"] == repaired["revision"] and again["passages"] == repaired["passages"]
    with pytest.raises(APIError, match="different content"):
        ingest.import_source(db, tid, dict(canonical, markdown=normalized.replace("Preserve", "Remove")))


@pytest.mark.parametrize("category", ["sources", "revisions", "passages"])
def test_corpus_limits_include_history_and_manual_projection_and_fail_atomically(db, monkeypatch, category):
    monkeypatch.setitem(ingest.CORPUS_LIMITS, category, 2)
    tid, other = tenant(db)["id"], tenant(db)["id"]
    first = ingest.import_source(db, tid, source())
    ingest.import_source(db, other, source())
    second_payload = source(revision=first["revision"], source_version="18",
                            source_id="second" if category == "sources" else "omg")
    second = ingest.import_source(db, tid, second_payload)
    before = ingest.list_sources(db, tid)
    next_payload = dict(second_payload, revision=second["revision"], source_version="19",
                        source_id="third" if category == "sources" else "omg")
    with pytest.raises(APIError, match=f"{category} limit") as error:
        ingest.import_source(db, tid, next_payload)
    assert error.value.status == 409
    manual = {"id": "manual", "kind": "command", "title": "Reference",
              "keywords": ["omg"], "body": "Require approval before draining."}
    with pytest.raises(APIError, match=f"{category} limit"):
        knowledge.update(db, tid, {"revision": second["revision"], "documents": [manual]}, documents=True)
    assert ingest.list_sources(db, tid) == before
    assert knowledge.read(db, tid)["documents"] == []
    assert ingest.read_source(db, tid, second_payload["source_id"])["passages"] == second["passages"]
    assert db.scalar(f"SELECT count(*) FROM knowledge_{category} WHERE tenant_id=$1", tid) == 2
    same = ingest.import_source(db, tid, dict(second_payload, revision=second["revision"]))
    assert same["revision"] == second["revision"]
    revoked = ingest.revoke_source(db, tid, second_payload["source_id"], {"revision": same["revision"]})
    purged = ingest.purge_source(db, tid, second_payload["source_id"], {"revision": revoked["revision"]})
    replacement = ingest.import_source(db, tid, source(revision=purged["revision"], source_id="replacement"))
    assert replacement["passages"] and ingest.read_source(db, other, "omg")["passages"]


def test_purge_preserves_assessment_history_and_fences_recreated_sources(db):
    from openaidr_api.providers.guardrail import parse_assessment
    from test_risk import reply
    from test_risk_store import event

    tid = tenant(db)["id"]
    saved = ingest.import_source(db, tid, source())
    device, _, _ = sensor(db, tid)
    captured = event(command={"text": "omg drain us-west-1"})
    db.ingest_batch(device, [captured])
    assessment = parse_assessment(reply("none", 0))
    assessment["knowledge"] = {"revision": saved["revision"], "documents": saved["passages"]}
    db.finish_risk_event(db.claim_risk_event(tid), assessment)
    history = db.get_event(tid, captured["id"])["risk"]
    with pytest.raises(APIError, match="only revoked"):
        ingest.purge_source(db, tid, "omg", {"revision": saved["revision"]})
    payload = source(revision=saved["revision"], source_version="18")
    pending = ingest.begin_import(db, tid, payload)
    with pytest.raises(APIError, match="only revoked"):
        ingest.purge_source(db, tid, "omg", {"revision": pending["revision"]})
    revoked = ingest.revoke_source(db, tid, "omg", {"revision": pending["revision"]})
    purged = ingest.purge_source(db, tid, "omg", {"revision": revoked["revision"]})
    for table in ("sources", "revisions", "passages", "passage_keys"):
        assert db.scalar(f"SELECT count(*) FROM knowledge_{table} WHERE tenant_id=$1", tid) == 0
    assert db.get_event(tid, captured["id"])["risk"] == history
    recreated = ingest.begin_import(db, tid, dict(payload, revision=purged["revision"]))
    assert recreated["generation"] > revoked["source"]["generation"]
    with pytest.raises(APIError, match="discard this generation"):
        ingest.publish_import(db, tid, payload, pending["generation"])
    published = ingest.publish_import(db, tid, payload, recreated["generation"])
    assert published["passages"] and db.get_event(tid, captured["id"])["risk"] == history


def test_manual_replacement_preserves_imported_sources_and_legacy_response(db):
    tid = tenant(db)["id"]
    imported = ingest.import_source(db, tid, source())
    manual = {"id": "zone", "kind": "resource", "title": "us-west-1",
              "keywords": ["us-west-1"], "body": "In account core, us-west-1 is production."}
    saved = knowledge.update(db, tid, {"revision": imported["revision"], "documents": [manual]}, documents=True)
    assert set(saved) == {"revision", "enabled", "updated_at", "documents"}
    assert saved["documents"] == [manual]
    projected = ingest.read_source(db, tid, "manual:zone")
    assert projected["source"]["source_type"] == "manual" and projected["source"]["fresh"]
    assert db.scalar("SELECT key_type FROM knowledge_passage_keys WHERE tenant_id=$1 AND passage_id=$2",
                     tid, projected["passages"][0]["passage_id"]) == "term"
    for function, payload in ((ingest.revoke_source, {"revision": 2}),
                              (ingest.verify_source, {"revision": 2, "source_version": "2", "generation": 1})):
        with pytest.raises(APIError, match="reserved"):
            function(db, tid, "manual:zone", payload)
    with pytest.raises(APIError, match="reserved"):
        ingest.import_source(db, tid, source(source_id="manual:zone", revision=2))
    removed = knowledge.update(db, tid, {"revision": saved["revision"], "documents": []}, documents=True)
    assert ingest.read_source(db, tid, "manual:zone")["passages"] == []
    ingest.purge_source(db, tid, "manual:zone", {"revision": removed["revision"]})
    with pytest.raises(NotFound):
        ingest.read_source(db, tid, "manual:zone")
    assert ingest.read_source(db, tid, "omg")["passages"] == imported["passages"]


def test_manual_removal_and_purge_can_recover_a_full_corpus(db, monkeypatch):
    for category in ingest.CORPUS_LIMITS:
        monkeypatch.setitem(ingest.CORPUS_LIMITS, category, 2)
    tid = tenant(db)["id"]
    pages = [{"id": ident, "kind": "resource", "title": ident,
              "keywords": [ident], "body": "A production resource."} for ident in ("first", "second")]
    saved = knowledge.update(db, tid, {"revision": 0, "documents": pages}, documents=True)
    retained = ingest.read_source(db, tid, "manual:first")
    removed = knowledge.update(db, tid, {"revision": saved["revision"], "documents": pages[:1]}, documents=True)
    assert removed["documents"] == pages[:1]
    assert ingest.read_source(db, tid, "manual:first")["passages"] == retained["passages"]
    assert ingest.read_source(db, tid, "manual:second")["source"]["status"] == "revoked"
    purged = ingest.purge_source(db, tid, "manual:second", {"revision": removed["revision"]})
    again = knowledge.update(db, tid, {"revision": purged["revision"], "documents": pages}, documents=True)
    assert again["documents"] == pages
    assert ingest.read_source(db, tid, "manual:first")["passages"] == retained["passages"]
    assert ingest.read_source(db, tid, "manual:second")["source"]["generation"] > 1
    for category in ingest.CORPUS_LIMITS:
        assert db.scalar(f"SELECT count(*) FROM knowledge_{category} WHERE tenant_id=$1", tid) == 2


def test_mode_opt_in_projects_existing_legacy_documents_without_enabling(db):
    tid = tenant(db)["id"]
    db.execute("INSERT INTO tenant_knowledge(tenant_id) VALUES($1)", tid)
    db.execute("INSERT INTO knowledge_documents(tenant_id,id,kind,title,keywords,body) "
               "VALUES($1,'old','command','Old reference',ARRAY['omg'],'A zone drain changes availability.')", tid)
    enabled = ingest.set_mode(db, tid, {"revision": 0, "retrieval_mode": "postgres"})
    assert enabled["revision"] == 1 and enabled["retrieval_mode"] == "postgres"
    assert enabled["enabled"] is False
    assert ingest.read_source(db, tid, "manual:old")["passages"]
    with pytest.raises(APIError, match="reload before saving"):
        ingest.set_mode(db, tid, {"revision": 0, "retrieval_mode": "legacy"})
    assert ingest.set_mode(db, tid, {"revision": 1, "retrieval_mode": "legacy"})["retrieval_mode"] == "legacy"


def test_markdown_sections_preserve_tables_qualifications_and_fenced_examples():
    markdown = "# Drain\nOnly drain production after approval.\n```sh\n# this is a comment\nomg drain us-west-1\n```\n\n" \
               "## Zones\n| Destination | Environment |\n| --- | --- |\n| us-west-1 | production |"
    sections = ingest.split_markdown(markdown, "Operations")
    assert len(sections) == 2
    assert sections[0]["body"].startswith("# Drain\nOnly drain production after approval.")
    assert "# this is a comment\nomg drain" in sections[0]["body"]
    assert sections[1]["section_path"] == "Drain / Zones"
    assert "| Destination | Environment |" in sections[1]["body"]
    suffixes = ingest.split_markdown("# C#\nKeep language facts.\n## Release###\nKeep release facts.\n"
                                     "### Closing hashes ### \t\nA section with optional closing marks.", "Reference")
    assert [section["section_path"] for section in suffixes] == [
        "C#", "C# / Release###", "C# / Release### / Closing hashes",
    ]
    for invalid in ("# Huge\n" + "x" * 2000, "# Broken\n```sh\nomg drain zone"):
        with pytest.raises(APIError):
            ingest.split_markdown(invalid, "Operations")


@pytest.mark.parametrize("fence", ["```", "~~~"])
def test_markdown_closing_fence_allows_only_trailing_spaces_and_tabs(fence):
    for suffix in ("code", " \tcode", "\v", "\f", "\u2028"):
        unclosed = f"# Example\n{fence}text\n{fence}{suffix}\n# This is code"
        for closing in (fence, fence + fence[0] + " \t"):
            markdown = unclosed + f"\n{closing}\n\n## Next\nAnother section."
            for newline in ("\n", "\r\n", "\r"):
                sections = ingest.split_markdown(markdown.replace("\n", newline), "Examples")
                assert len(sections) == 2
                assert sections[0]["body"] == unclosed + "\n" + closing.rstrip()
                assert sections[1]["section_path"] == "Example / Next"
        with pytest.raises(APIError, match="unclosed code fence"):
            ingest.split_markdown(unclosed, "Examples")


def test_markdown_backticks_in_info_string_do_not_open_backtick_fences():
    for literal in ("```literal```", "```language`literal", "````literal```"):
        sections = ingest.split_markdown(f"# Example\n{literal}\n\n## Next\nAnother section.", "Examples")
        assert len(sections) == 2
        assert sections[0]["body"] == f"# Example\n{literal}"
        assert sections[1]["section_path"] == "Example / Next"
    sections = ingest.split_markdown("# Example\n~~~language`literal\n# This is code\n~~~\n"
                                     "## Next\nAnother section.", "Examples")
    assert len(sections) == 2
    assert "# This is code" in sections[0]["body"]
    assert sections[1]["section_path"] == "Example / Next"


@pytest.mark.parametrize("changes", [
    {"tenant_id": "other"}, {"source_uri": "javascript:alert(1)"},
    {"source_uri": "https://user:password@example.test"}, {"source_id": "../escape"},
    {"source_id": "AKIAABCDEFGHIJKLMNOP"}, {"source_version": "API_TOKEN=synthetic-review-secret"},
    {"scope_key": "\ud800"}, {"freshness_seconds": True},
    {"scope_key": "account:core\x01"}, {"scope_key": "account:core\x7f"},
    {"scope_key": "account:core\u200b"}, {"scope_key": "account:core sandbox"},
    {"scope_key": "é" * 121},
    {"keys": [{"key_type": "term", "lookup_value": "two words", "canonical_key": "alias"}]},
    {"keys": [{"key_type": "term", "lookup_value": "host.example", "canonical_key": "alias"}]},
    {"keys": [{"key_type": "operation", "lookup_value": "omg drain zone", "canonical_key": "alias"}]},
    {"keys": [{"key_type": "operation", "lookup_value": "omg;drain", "canonical_key": "alias"}]},
    {"keys": [{"key_type": "operation", "lookup_value": "omg --drain", "canonical_key": "alias"}]},
    {"kind": "resource", "keys": [{"key_type": "operation", "lookup_value": "omg", "canonical_key": "alias"}]},
    {"kind": "reference", "keys": [{"key_type": "resource", "lookup_value": "us west", "canonical_key": "alias"}]},
    {"kind": "reference", "keys": [{"key_type": "resource", "lookup_value": "-prod", "canonical_key": "alias"}]},
    {"keys": [{"key_type": "resource", "lookup_value": "us-west-1", "canonical_key": "alias"}]},
    {"scope_key": "", "keys": [{"key_type": "resource", "lookup_value": "us-west-1", "canonical_key": "prod"}]},
    {"markdown": "# Too big\n" + "x" * 2000},
])
def test_invalid_import_fails_before_touching_storage(changes):
    with pytest.raises(APIError) as error:
        ingest.import_source(None, "tenant", source(**copy.deepcopy(changes)))
    assert error.value.status == 400
