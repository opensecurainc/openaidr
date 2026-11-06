import copy
import json
import time
from contextlib import ExitStack
from types import SimpleNamespace

import pytest

from openaidr.server import knowledge, knowledge_ingest, knowledge_retrieval
from openaidr.server.knowledge_retrieval import augment_state, retrieve
from openaidr.server.guardrail.evidence import MAX_STATE_BYTES, event_evidence
from openaidr.core.toolmap import map_tool
from test_store import db, new_id, tenant


@pytest.fixture
def functional_clock(monkeypatch):
    # Keep real PostgreSQL and its production pool/SQL timeouts. Scheduler
    # pauses must not change functional results through the elapsed budget.
    # The deadline test below and the benchmark retain the real clock.
    monkeypatch.setattr(knowledge_retrieval, "time", SimpleNamespace(monotonic=lambda: 1.0))


def source(db, tid, *, category="operation", scope="", value="omg drain",
           canonical=None, body="The omg drain operation drains a network zone.", keys=True,
           source_id=None, kind=None):
    """Publish through ingestion so retrieval uses the production schema."""
    current = knowledge_ingest.settings(db, tid)
    if not current["enabled"]:
        knowledge.update(db, tid, {"revision": current["revision"], "enabled": True})
        current = knowledge_ingest.settings(db, tid)
    if current["retrieval_mode"] != "postgres":
        knowledge_ingest.set_mode(db, tid, {"revision": current["revision"], "retrieval_mode": "postgres"})
        current = knowledge_ingest.settings(db, tid)
    source_id = source_id or new_id()
    kind = kind or ("command" if category == "operation" else "resource")
    result = knowledge_ingest.import_source(db, tid, {
        "revision": current["revision"], "source_id": source_id, "source_version": "v1",
        "title": value, "source_uri": "wiki://" + source_id, "scope_key": scope,
        "markdown": body, "kind": kind,
        "keys": keys if isinstance(keys, list) else [
            {"key_type": category, "lookup_value": value, "canonical_key": canonical or value}
        ] if keys else [],
    })
    return source_id, result["passages"][0]["passage_id"]


def action(text="omg drain us-west-1"):
    return {"kind": "command", "command": {"text": text}}


def test_exact_identity_requires_tenant_account_and_whole_identifier(db):
    first, other = tenant(db)["id"], tenant(db)["id"]
    operation, _ = source(db, first)
    prod, _ = source(db, first, category="resource", scope="account:core", value="us-west-1",
                     body="In account core, us-west-1 is a production network zone.")
    dev, _ = source(db, first, category="resource", scope="account:sandbox", value="us-west-1",
                    body="In account sandbox, us-west-1 is a development network zone.")
    source(db, other, category="resource", scope="account:core", value="us-west-1",
           body="Foreign tenant confidential context.")
    snapshot = retrieve(db, first, action(), trusted_scope="account:core")
    assert snapshot["status"] == "matched", snapshot
    assert snapshot["category_coverage"] == {"operation": "exact", "resource": "exact"}
    assert {doc["source_id"] for doc in snapshot["documents"]} == {operation, prod}
    assert snapshot["valid_until"] and snapshot["reference_only"]
    alternate = retrieve(db, first, action(), trusted_scope="account:sandbox")
    assert {doc["source_id"] for doc in alternate["documents"]} == {operation, dev}
    unbound = retrieve(db, first, {**action(), "account_id": "core"})
    assert unbound["category_coverage"]["resource"] == "unknown"
    assert "missing_scope" in unbound["gaps"]
    assert {doc["source_id"] for doc in unbound["documents"]} == {operation}
    distinct = retrieve(db, first, action("omg drain us-west-10"), trusted_scope="account:core")
    assert distinct["category_coverage"]["resource"] != "exact"


@pytest.mark.parametrize("category", ["operation", "resource"])
def test_exact_aliases_ignore_incompatible_passage_kinds_in_existing_corpus(db, functional_clock, category):
    tid = tenant(db)["id"]
    value = "omg drain" if category == "operation" else "us-west-1"
    incompatible, passage = source(db, tid, category=category, value=value, scope="account:core",
                                   kind="resource" if category == "operation" else "command", keys=False)
    # Simulate rows written before ingestion enforced the category/kind contract.
    db.execute("""INSERT INTO knowledge_passage_keys
        (tenant_id,passage_id,key_type,scope_key,lookup_value,canonical_key)
        VALUES($1,$2,$3,'account:core',$4,'wrong-kind')""", tid, passage, category, value)
    other_category = "resource" if category == "operation" else "operation"
    other, _ = source(db, tid, category=other_category, scope="account:core",
                      value="us-west-1" if other_category == "resource" else "omg drain")
    incomplete = retrieve(db, tid, action(), trusted_scope="account:core")
    assert incomplete["category_coverage"][category] == "missing"
    assert {doc["source_id"] for doc in incomplete["documents"]} == {other}
    compatible, _ = source(db, tid, category=category, value=value, scope="account:core", kind="reference")
    resolved = retrieve(db, tid, action(), trusted_scope="account:core")
    assert resolved["status"] == "matched" and resolved["gaps"] == []
    assert {doc["source_id"] for doc in resolved["documents"]} == {other, compatible}
    assert all(doc["source_id"] != incompatible for doc in resolved["documents"])


@pytest.mark.parametrize("target,gap", [
    (action("omg drain us-west-1 --dry-run"), "unsupported_flags"),
    (action("omg drain us-west-1 --account sandbox"), "unsupported_flags"),
    (action("omg drain $ZONE"), "unsupported_shell"),
    (action("omg drain $(lookup-zone)"), "unsupported_shell"),
    (action("omg drain us-west-1; echo done"), "unsupported_shell"),
    (action("omg drain us-west-1 other-zone"), "ambiguous_resource"),
    ({"kind": "prompt", "text": "Explain omg drain us-west-1"}, "discussion_only"),
    ({"kind": "tool.call", "tool": {"name": "omg", "input": {
        "operation": "drain", "destination": "us-west-1", "account": "sandbox"}}}, "unsupported_arguments"),
    ({"kind": "tool.call", "tool": {"name": "-omg", "input": {
        "operation": "drain", "destination": "us-west-1"}}}, "unsupported_arguments"),
    ({"kind": "tool.call", "tool": {"name": "omg", "input": {
        "operation": "--drain", "destination": "us-west-1"}}}, "unsupported_arguments"),
    ({"kind": "tool.call", "tool": {"name": "omg", "input": {
        "operation": "drain", "destination": "--us-west-1"}}}, "unsupported_arguments"),
    ({"kind": "tool.call", "tool": {"name": "Bash", "input": {
        "command": "omg drain us-west-1", "env": {"ACCOUNT": "sandbox"}}}}, "unsupported_arguments"),
    ({"kind": "command", "command": {"text": "omg drain us-west-1", "argv": ["omg", "drain", "other-zone"]}}, "ambiguous_arguments"),
    ({**action(), "truncated": True}, "target_evidence_incomplete"),
])
def test_uncertain_command_shape_never_proves_resource_identity(db, functional_clock, target, gap):
    tid = tenant(db)["id"]
    source(db, tid)
    source(db, tid, category="resource", scope="account:core", value="us-west-1")
    result = retrieve(db, tid, target, trusted_scope="account:core")
    assert result["status"] != "matched"
    assert result["category_coverage"]["resource"] != "exact"
    assert gap in result["gaps"]
    state = {"target_event": target, "prior_events": [], "latest_prompt": None}
    prepared, sent = augment_state(state, result)
    assert prepared["target_event"] == target
    assert prepared["prior_events"][-1]["tool"]["output"] == sent


def test_mapped_sensor_commands_allow_metadata_but_reject_overrides(db, functional_clock):
    tid = tenant(db)["id"]
    operation, _ = source(db, tid)
    resource, _ = source(db, tid, category="resource", scope="account:core", value="us-west-1")
    for product, name, inputs in (
        ("codex-cli", "exec_command", {"cmd": "omg drain us-west-1", "workdir": "/workspace",
                                      "justification": "Drain the zone", "yield_time_ms": 1000}),
        ("codex-cli", "shell", {"command": ["omg", "drain", "us-west-1"], "cwd": "/workspace"}),
        ("claude-code", "Bash", {"command": "omg drain us-west-1", "description": "Drain the zone",
                                 "run_in_background": True, "timeout": 1000}),
        ("gemini-cli", "run_shell_command", {"command": "omg drain us-west-1", "directory": "/workspace",
                                             "description": "Drain the zone"}),
    ):
        mapped = map_tool(product, name, inputs)[0]
        target = event_evidence({"kind": mapped["kind"], "body": {
            **mapped, "tool": {"name": name, "input": inputs},
        }})
        original = copy.deepcopy(target)
        assert retrieve(db, tid, target, trusted_scope="account:core")["status"] == "matched"
        for extra, gap in (({"env": {"ACCOUNT": "sandbox"}}, "unsupported_arguments"),
                           ({"argv": ["omg", "drain", "other-zone"]}, "ambiguous_arguments")):
            overridden = copy.deepcopy(target)
            overridden["tool"]["input"].update(extra)
            snapshot = retrieve(db, tid, overridden, trusted_scope="account:core")
            assert snapshot["status"] == "partial"
            assert snapshot["category_coverage"]["resource"] == "unknown"
            assert gap in snapshot["gaps"]
        assert target == original
    conflicting = copy.deepcopy(target)
    conflicting["tool"]["input"]["command"] = "omg drain other-zone"
    snapshot = retrieve(db, tid, conflicting, trusted_scope="account:core")
    assert snapshot["category_coverage"]["resource"] == "unknown"
    assert "ambiguous_arguments" in snapshot["gaps"]
    long_metadata = copy.deepcopy(target)
    long_metadata["command"]["description"] = " ".join(f"detail{index}" for index in range(130))
    complete = retrieve(db, tid, long_metadata, trusted_scope="account:core")
    assert complete["status"] == "matched" and complete["gaps"] == []
    assert complete["category_coverage"] == {"operation": "exact", "resource": "exact"}
    assert {doc["source_id"] for doc in complete["documents"]} == {operation, resource}
    long_metadata["command"]["env"] = {"ACCOUNT": "sandbox"}
    uncertain = retrieve(db, tid, long_metadata, trusted_scope="account:core")
    assert uncertain["status"] == "partial"
    assert uncertain["category_coverage"]["resource"] == "unknown"
    assert {"unsupported_arguments", "query_terms_truncated"} <= set(uncertain["gaps"])
    assert all(doc["source_id"] != resource for doc in uncertain["documents"])
    target["command"]["env"] = {"ACCOUNT": "sandbox"}
    assert "unsupported_arguments" in retrieve(db, tid, target, trusted_scope="account:core")["gaps"]


def test_structured_tool_fields_and_expired_or_ambiguous_sources(db, functional_clock):
    tid = tenant(db)["id"]
    operation_key = {"key_type": "operation", "lookup_value": "omg drain", "canonical_key": "omg drain"}
    resource_key = {"key_type": "resource", "lookup_value": "us-west-1", "canonical_key": "us-west-1"}
    source(db, tid, kind="reference", body="The omg drain operation affects us-west-1.", keys=[
        operation_key, {"key_type": "term", "lookup_value": "us-west-1", "canonical_key": "us-west-1"},
    ])
    prod, _ = source(db, tid, category="resource", kind="reference", scope="account:core", value="us-west-1",
                     keys=[operation_key, resource_key])
    target = {"kind": "tool.call", "tool": {"name": "omg", "input": {
        "operation": "drain", "destination": "us-west-1"}}}
    complete = retrieve(db, tid, target, trusted_scope="account:core")
    assert complete["status"] == "matched"
    assert any(doc["source_id"] == prod and set(doc["categories"]) == {"operation", "resource"}
               for doc in complete["documents"])
    db.execute("UPDATE knowledge_sources SET fresh_until=now()-interval '1 second' WHERE tenant_id=$1 AND source_id=$2", tid, prod)
    stale = retrieve(db, tid, target, trusted_scope="account:core")
    assert "resource_lexical_only" in stale["gaps"]
    assert all(doc["source_id"] != prod for doc in stale["documents"])
    assert stale["category_coverage"] == {"operation": "exact", "resource": "lexical"}
    assert len(stale["documents"]) == 1
    assert stale["documents"][0]["categories"] == ["operation", "resource"]
    assert stale["documents"][0]["matched_keywords"] == ["omg drain", "us-west-1"]
    assert stale["documents"][0]["match"] == "lexical" and stale["status"] == "partial"
    db.execute("UPDATE knowledge_sources SET fresh_until=now()+interval '1 hour' WHERE tenant_id=$1 AND source_id=$2", tid, prod)
    source(db, tid, category="resource", scope="account:core", value="us-west-1", canonical="different-zone")
    ambiguous = retrieve(db, tid, target, trusted_scope="account:core")
    assert ambiguous["category_coverage"] == {"operation": "unknown", "resource": "ambiguous"}
    assert ambiguous["status"] == "partial" and ambiguous["documents"] == []
    assert {"ambiguous_resource", "evidence_truncated"} <= set(ambiguous["gaps"])
    assert ambiguous["truncated"] and ambiguous["valid_until"] is None


def test_full_text_is_candidate_evidence_and_overflow_is_explicit(db, functional_clock):
    tid = tenant(db)["id"]
    source(db, tid, keys=False)
    result = retrieve(db, tid, action())
    assert result["category_coverage"]["operation"] == "lexical"
    assert result["documents"] and result["status"] == "partial"
    assert "operation_lexical_only" in result["gaps"]
    long_metadata = action()
    long_metadata["command"]["description"] = " ".join(f"detail{index}" for index in range(130))
    fallback = retrieve(db, tid, long_metadata, trusted_scope="account:core")
    assert fallback["category_coverage"]["operation"] == "lexical"
    assert fallback["status"] == "partial" and "query_terms_truncated" in fallback["gaps"]
    unbound = retrieve(db, tid, action("unknown inspect nowhere"))
    assert not unbound["documents"] and unbound["status"] == "partial"
    assert "missing_scope" in unbound["gaps"]
    missing = retrieve(db, tid, action("unknown inspect nowhere"), trusted_scope="account:core")
    assert not missing["documents"] and missing["status"] == "no_match"
    assert missing["category_coverage"] == {"operation": "missing", "resource": "missing"}
    for _ in range(64):
        source(db, tid, keys=False)
    overflow = retrieve(db, tid, action())
    assert overflow["category_coverage"]["operation"] == "overflow"
    assert "operation_candidate_overflow" in overflow["gaps"]
    assert overflow["documents"] == []
    assert overflow["status"] == "partial"


def test_full_text_filters_source_eligibility_before_candidate_limit(db, functional_clock):
    tid, other = tenant(db)["id"], tenant(db)["id"]
    sections = "\n\n".join(f"# Section {index}\n\nThe omg drain operation drains a zone." for index in range(65))
    source(db, other, scope="account:core", body=sections, keys=False)
    source(db, tid, scope="account:sandbox", body=sections, keys=False)
    expired, _ = source(db, tid, scope="account:core", body=sections, keys=False)
    revoked, _ = source(db, tid, scope="account:core", body=sections, keys=False)
    db.execute("UPDATE knowledge_sources SET fresh_until=now()-interval '1 second' WHERE tenant_id=$1 AND source_id=$2",
               tid, expired)
    db.execute("UPDATE knowledge_sources SET status='revoked',active_revision_id=NULL WHERE tenant_id=$1 AND source_id=$2",
               tid, revoked)
    current, _ = source(db, tid, scope="account:core", keys=False)
    snapshot = retrieve(db, tid, action(), trusted_scope="account:core")
    assert snapshot["category_coverage"] == {"operation": "lexical", "resource": "missing"}
    assert {doc["source_id"] for doc in snapshot["documents"]} == {current}
    db.execute("UPDATE knowledge_sources SET status='revoked',active_revision_id=NULL WHERE tenant_id=$1 AND source_id=$2",
               tid, current)
    missing = retrieve(db, tid, action(), trusted_scope="account:core")
    assert missing["status"] == "no_match" and not missing["documents"]
    unbound = retrieve(db, tid, action())
    assert unbound["status"] == "partial" and not unbound["documents"]
    assert unbound["category_coverage"] == {"operation": "missing", "resource": "unknown"}


def test_manual_keyword_only_alias_remains_a_candidate_in_postgres_mode(db, functional_clock):
    tid = tenant(db)["id"]
    knowledge.update(db, tid, {"revision": 0, "documents": [
        {"id": "maintenance", "kind": "command", "title": "Network maintenance",
         "keywords": ["cloudsweeper", "drain"], "body": "This maintenance operation drains a network zone."},
        {"id": "zone", "kind": "resource", "title": "Network zone",
         "keywords": ["us-west-1", "drain"], "body": "This resource serves production traffic."},
        {"id": "approval", "kind": "command", "title": "Reviewed changes",
         "keywords": ["approval-required"], "body": "A reviewed change requires an approved ticket."},
    ]}, documents=True)
    knowledge.update(db, tid, {"revision": 1, "enabled": True})
    knowledge_ingest.set_mode(db, tid, {"revision": 2, "retrieval_mode": "postgres"})
    other = tenant(db)["id"]
    knowledge.update(db, other, {"revision": 0, "documents": [
        {"id": "foreign", "kind": "resource", "title": "Foreign zone",
         "keywords": ["us-west-1"], "body": "Other tenant's private resource."},
    ]}, documents=True)
    for scope in (None, "account:core"):
        snapshot = retrieve(db, tid, action("cloudsweeper drain us-west-1"), trusted_scope=scope)
        assert snapshot["status"] == "partial"
        assert snapshot["category_coverage"] == {"operation": "lexical", "resource": "lexical"}
        assert {doc["source_id"] for doc in snapshot["documents"]} == {"manual:maintenance", "manual:zone"}
        assert {doc["source_id"]: doc["matched_keywords"] for doc in snapshot["documents"]} == {
            "manual:maintenance": ["cloudsweeper", "drain"], "manual:zone": ["drain", "us-west-1"],
        }
        assert all(doc["match"] == "lexical" for doc in snapshot["documents"])
        assert ("missing_scope" in snapshot["gaps"]) == (scope is None)
    prod, _ = source(db, tid, category="resource", scope="account:core", value="us-west-1")
    source(db, tid, category="resource", scope="account:sandbox", value="us-west-1")
    exact = retrieve(db, tid, action("cloudsweeper drain us-west-1"), trusted_scope="account:core")
    assert exact["category_coverage"]["resource"] == "exact"
    assert {doc["source_id"] for doc in exact["documents"]} == {"manual:maintenance", prod}
    for target in (
        action("cloudsweeper drain us-west-1 --ticket approval-required"),
        {"kind": "tool.call", "tool": {"name": "transfer", "input": {
            "cluster": "us-west-1", "ticket": "approval-required"}}},
    ):
        uncertain = retrieve(db, tid, target, trusted_scope="account:core")
        assert uncertain["status"] == "partial"
        assert uncertain["category_coverage"]["resource"] == "lexical"
        selected = {doc["source_id"] for doc in uncertain["documents"]}
        assert {"manual:approval", "manual:zone"} <= selected
        assert selected <= {"manual:maintenance", "manual:approval", "manual:zone"}
    generic = retrieve(db, tid, {"kind": "tool.call", "tool": {"name": "approval-required"}})
    assert {doc["source_id"] for doc in generic["documents"]} == {"manual:approval"}
    shell = retrieve(db, tid, action("echo us-west-1 | cat"), trusted_scope="account:core")
    assert {doc["source_id"] for doc in shell["documents"]} == {"manual:zone"}
    discussion = retrieve(db, tid, {"kind": "prompt", "text": "Explain cloudsweeper and us-west-1"})
    assert discussion["intent"] == "discussion" and discussion["status"] == "partial"
    for kind in ("response", "tool.result"):
        assert not retrieve(db, tid, {"kind": kind, "text": "cloudsweeper drain us-west-1"})["documents"]


def test_term_candidate_limit_counts_passages_and_keeps_all_matching_keywords(db, functional_clock):
    tid = tenant(db)["id"]
    knowledge.update(db, tid, {"revision": 0, "documents": [
        {"id": f"maintenance-{index}", "kind": "command", "title": "Network maintenance",
         "keywords": ["cloudsweeper", "drain"], "body": "This operation requires a maintenance window."}
        for index in range(64)
    ]}, documents=True)
    knowledge.update(db, tid, {"revision": 1, "enabled": True})
    knowledge_ingest.set_mode(db, tid, {"revision": 2, "retrieval_mode": "postgres"})
    bounded = retrieve(db, tid, action("cloudsweeper drain us-west-1"), trusted_scope="account:core")
    assert bounded["status"] == "partial" and bounded["truncated"]
    assert len(bounded["documents"]) == 4
    assert "operation_candidate_overflow" not in bounded["gaps"]
    assert all(doc["matched_keywords"] == ["cloudsweeper", "drain"] for doc in bounded["documents"])
    source(db, tid, source_id="extra", value="Maintenance", keys=[
        {"key_type": "term", "lookup_value": "drain", "canonical_key": "drain"},
    ])
    overflow = retrieve(db, tid, action("cloudsweeper drain us-west-1"), trusted_scope="account:core")
    assert overflow["category_coverage"]["operation"] == "overflow"
    assert "operation_candidate_overflow" in overflow["gaps"]
    assert overflow["status"] == "partial" and overflow["documents"] == []


@pytest.mark.parametrize("product,name,inputs,identifier", [
    ("claude-code", "Read", {"file_path": "/srv/payroll.csv"}, "/srv/payroll.csv"),
    ("codex-cli", "write_file", {"path": "/srv/payroll.csv", "content": "employee data"}, "/srv/payroll.csv"),
    ("codex-cli", "web_fetch", {"url": "https://payroll.internal/report"}, "payroll.internal"),
])
def test_file_and_network_actions_keep_manual_and_imported_lexical_context(db, functional_clock,
                                                                         product, name, inputs, identifier):
    tid = tenant(db)["id"]
    knowledge.update(db, tid, {"revision": 0, "documents": [
        {"id": "handling", "kind": "command", "title": "Data handling",
         "keywords": ["payroll"], "body": "Review requests to access employee data."},
        {"id": "archive", "kind": "resource", "title": "Employee archive",
         "keywords": ["payroll"], "body": "This archive contains sensitive employee data."},
    ]}, documents=True)
    knowledge.update(db, tid, {"revision": 1, "enabled": True})
    mapped = map_tool(product, name, inputs)[0]
    row = {"tenant_id": tid, "kind": mapped["kind"], "body": {
        **mapped, "tool": {"name": name, "input": inputs},
    }}
    assert {doc["id"] for doc in db.risk_knowledge(row)["documents"]} == {"handling", "archive"}
    knowledge_ingest.set_mode(db, tid, {"revision": 2, "retrieval_mode": "postgres"})
    projected = db.risk_knowledge(row)
    assert {doc["source_id"] for doc in projected["documents"]} == {"manual:handling", "manual:archive"}
    assert projected["status"] == "partial" and projected["intent"] == "action"
    assert projected["category_coverage"] == {"operation": "lexical", "resource": "lexical"}
    assert "unresolved_identity" in projected["gaps"]
    if mapped["kind"] == "file.read":
        for parts, matched in ((16, True), (130, False)):
            long_path = {"kind": "file.read", "file": {
                "path": "/" + "/".join(f"part{i}" for i in range(parts)) + "/payroll/config",
            }}
            result = retrieve(db, tid, long_path)
            assert bool(result["documents"]) == matched
            assert ("query_terms_truncated" in result["gaps"]) == (not matched)
            assert result["status"] == "partial"
    shared, _ = source(db, tid, category="resource", value=identifier, keys=False,
                       body=f"{identifier} contains employee data.")
    scoped, _ = source(db, tid, category="resource", scope="account:core", value=identifier)
    source(db, tid, category="resource", scope="account:sandbox", value=identifier)
    knowledge.update(db, tid, {"revision": knowledge_ingest.settings(db, tid)["revision"],
                               "documents": []}, documents=True)
    imported = db.risk_knowledge(row)
    assert {doc["source_id"] for doc in imported["documents"]} == {shared}
    bound = retrieve(db, tid, event_evidence(row), trusted_scope="account:core")
    assert {doc["source_id"] for doc in bound["documents"]} == {shared, scoped}
    assert bound["category_coverage"] == {"operation": "missing", "resource": "lexical"}
    assert bound["status"] == "partial" and all(doc["match"] == "lexical" for doc in bound["documents"])
    if mapped["kind"] == "network":
        row["body"]["network"].pop("host")
        assert {doc["source_id"] for doc in db.risk_knowledge(row)["documents"]} == {shared}


@pytest.mark.parametrize("category", ["operation", "resource"])
def test_large_keyed_source_retains_evidence_and_detects_identity_outside_passage_limit(db, category, functional_clock):
    tid = tenant(db)["id"]
    sections = "\n\n".join(f"# Section {index:03d}\n\nOperation detail {index}." for index in range(256))
    key = {"category": category, "scope": "" if category == "operation" else "account:core",
           "value": "omg drain" if category == "operation" else "us-west-1"}
    source(db, tid, source_id="a-large", body=sections, **key)
    other = "resource" if category == "operation" else "operation"
    source(db, tid, category=other, scope="account:core" if other == "resource" else "",
           value="us-west-1" if other == "resource" else "omg drain")
    snapshot = retrieve(db, tid, action(), trusted_scope="account:core")
    assert [doc["section_path"] for doc in snapshot["documents"] if doc["source_id"] == "a-large"] == [
        "Section 000", "Section 001", "Section 002",
    ]
    assert snapshot["status"] == "partial" and snapshot["truncated"]
    assert snapshot["category_coverage"] == {category: "unknown", other: "exact"}
    assert "evidence_truncated" in snapshot["gaps"]
    assert f"ambiguous_{category}" not in snapshot["gaps"]
    source(db, tid, source_id="z-conflicting", canonical="different-identity", **key)
    conflicting = retrieve(db, tid, action(), trusted_scope="account:core")
    assert f"ambiguous_{category}" in conflicting["gaps"]
    assert conflicting["status"] == "partial" and conflicting["documents"] == []
    assert conflicting["category_coverage"] == {category: "ambiguous", other: "unknown"}
    assert conflicting["truncated"] and "evidence_truncated" in conflicting["gaps"]
    assert conflicting["valid_until"] is None


def test_exact_passage_selection_is_ordered_by_source_and_section_after_heap_reorder(db, functional_clock):
    tid = tenant(db)["id"]
    for ident, count in (("b-second", 6), ("a-first", 2)):
        source(db, tid, source_id=ident, body="\n\n".join(
            f"# Section {index:03d}\n\nOperation detail {index}." for index in range(count)))
    source(db, tid, category="resource", scope="account:core", value="us-west-1")

    def selected():
        snapshot = retrieve(db, tid, action(), trusted_scope="account:core")
        assert snapshot["status"] == "partial" and snapshot["truncated"]
        return [(doc["source_id"], doc["section_path"]) for doc in snapshot["documents"]
                if "operation" in doc["categories"]]

    expected = [("a-first", "Section 000"), ("a-first", "Section 001"), ("b-second", "Section 000")]
    assert selected() == expected
    db.execute("CREATE INDEX passage_reverse_order ON knowledge_passages (tenant_id,revision_id,ordinal DESC)")
    db.execute("CLUSTER knowledge_passages USING passage_reverse_order")
    assert selected() == expected


def test_redaction_and_whole_passage_budgets_preserve_exact_sent_snapshot(db):
    tid = tenant(db)["id"]
    for category, scope, value in (("operation", "", "omg drain"), ("resource", "account:core", "us-west-1")):
        for _ in range(3):
            source(db, tid, category=category, scope=scope, value=value,
                   body='"' * 1750 + "\nAPI_TOKEN=private-credential")
    snapshot = retrieve(db, tid, action(), trusted_scope="account:core")
    assert snapshot["truncated"] and snapshot["status"] == "partial"
    assert "private-credential" not in json.dumps(snapshot)
    assert snapshot["documents"]
    assert all(doc["text"].startswith('"' * 1750) for doc in snapshot["documents"])
    state = {"target_event": action(), "matched_tool_call": {"kind": "tool.call", "text": "x" * 7500},
             "latest_prompt": {"kind": "prompt", "text": "p" * 7500},
             "prior_events": [{"kind": "response", "text": "r" * 3000} for _ in range(2)]}
    original = copy.deepcopy(state)
    prepared, sent = augment_state(state, snapshot)
    assert state == original
    assert prepared["target_event"] == original["target_event"]
    assert prepared["matched_tool_call"] == original["matched_tool_call"]
    assert prepared["latest_prompt"] == original["latest_prompt"]
    assert len(json.dumps(prepared, ensure_ascii=False).encode()) <= MAX_STATE_BYTES
    reference = prepared["prior_events"][-1]
    assert reference["tool"]["output"] == sent
    assert len(json.dumps(reference, ensure_ascii=False).encode()) <= 6000


def test_deadline_pool_pressure_and_sql_lock_leave_reusable_connections(db):
    def assert_pool_settings_restored():
        # Check every connection, including the one used by a failed lookup.
        with ExitStack() as held:
            for _ in range(db.pools["data"].max_size):
                conn = held.enter_context(db.pools["data"].connection())
                assert conn.execute("""SELECT current_setting('statement_timeout') AS statement_timeout,
                    current_setting('lock_timeout') AS lock_timeout,
                    current_setting('plan_cache_mode') AS plan_cache_mode""").fetchone() == {
                        "statement_timeout": "0", "lock_timeout": "0", "plan_cache_mode": "auto",
                    }

    tid = tenant(db)["id"]
    source(db, tid)
    source(db, tid, category="resource", scope="account:core", value="us-west-1")
    expired = retrieve(db, tid, action(), deadline=time.monotonic() - 1)
    assert expired["status"] == "unavailable"
    assert expired["revision"] is None
    prepared, sent = augment_state({"target_event": action()}, expired)
    assert prepared["prior_events"][0]["tool"]["output"] == sent
    with ExitStack() as occupied:
        for _ in range(db.pools["data"].max_size):
            occupied.enter_context(db.pools["data"].connection())
        started = time.monotonic()
        exhausted = retrieve(db, tid, action(), trusted_scope="account:core")
        assert time.monotonic() - started < 0.150
        assert exhausted["status"] == "unavailable"
    with db.transaction() as lock:
        lock.execute("LOCK TABLE knowledge_passages IN ACCESS EXCLUSIVE MODE")
        started = time.monotonic()
        blocked = retrieve(db, tid, action(), trusted_scope="account:core")
        assert time.monotonic() - started < 0.150
        assert blocked["status"] == "unavailable"
    assert_pool_settings_restored()
    assert retrieve(db, tid, action(), trusted_scope="account:core")["status"] == "matched"
    assert_pool_settings_restored()
