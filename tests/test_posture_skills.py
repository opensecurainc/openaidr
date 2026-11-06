"""Real descriptor capture and SDK task binding without a scanner dependency."""

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest
from openaidr_api_client.contracts.service_skill_bundles import ServiceSkillBundleRequest, request_hash

from openaidr.core.skill_bundle import digest
from openaidr.sensor import posture_skills as skills
from openaidr.sensor.inventory_service import InventoryService
from openaidr.sensor.posture_store import Store
from test_hooks_setup import sensor_config


def inventory(tmp_path, count=1, cfg=None):
    if cfg is None:
        cfg = sensor_config(tmp_path)
        cfg["connection_mode"] = "api_key"
        cfg.save()
    roots = tmp_path / "skills"
    rows = []
    for index in range(count):
        directory = roots / str(index)
        directory.mkdir(parents=True)
        path = directory / "SKILL.md"
        path.write_text("---\nname: example\n---\nReview the supplied instructions.\n")
        rows.append(dict(kind="skill", key=str(index), name="example", path=str(path),
                         metadata={"content_sha256": digest(path.read_bytes())}))
    service = InventoryService(cfg, None, components=True)
    service.path.parent.mkdir(parents=True, exist_ok=True)
    service.path.write_text(json.dumps(dict(identity=service.identity, snapshot=dict(schema_version=1,
        collected_at=datetime.now(timezone.utc).isoformat(), roots=[dict(source="openaidr-skills",
        root=str(roots), scope="user", status="ok", components=rows)]))))
    return cfg, [Path(row["path"]) for row in rows]


def response(task, request_id="00000000-0000-4000-8000-000000000001", findings=None):
    count = len(task["files"])
    size = sum(len(item["content"].encode()) for item in task["files"])
    findings = [{"file_path": task["files"][0]["path"], "location_verified": True,
                 "reported_start_line": value.get("start_line"), "reported_end_line": value.get("end_line"), **value}
                for value in findings or []]
    return dict(profile="skill-bundle-assessment.1", status="completed", request_hash=request_hash(task),
        result=dict(findings=findings, findings_complete=True, coverage=dict(files_submitted=count, files_completed=count,
            bytes_submitted=size, bytes_completed=size, batches_total=count, batches_completed=count, complete=True)), billing=dict(request_id=request_id,
        service="skill_assessment", state="settled", credits_reserved="1", credits_charged="1", rate_version="test.1"))


def test_all_text_in_each_skill_uses_one_content_bound_request(tmp_path, monkeypatch):
    cfg, paths = inventory(tmp_path, count=2)
    text = "line with context\n" * 5000 + "x" * (skills.CHUNK_CHARS+1)
    for path in paths:
        (path.parent / "script.py").write_text(text)
        (path.parent / "empty.txt").write_text("")
    candidates = list(skills.candidates(cfg))
    assert len(candidates) == 2 and len({value["installation_id"] for value in candidates}) == 2
    first, second = candidates
    assert [item["key"] for item in first["tasks"]] == [item["key"] for item in second["tasks"]]
    task, = [item["task"] for item in first["tasks"]]
    assert next(item["content"] for item in task["files"] if item["path"] == "script.py") == text
    assert {item["path"] for item in task["files"]} == {"SKILL.md", "script.py", "empty.txt"}
    assert ServiceSkillBundleRequest.model_validate(task).profile == "skill-bundle-assessment.1"
    assert len(json.dumps(task).encode()) < 9 << 20 and len(first["legacy_keys"]) > 1
    assert all(not item["path"].startswith("/") for item in task["files"])
    assert first["coverage"]["capture_complete"] and first["coverage"]["status"] == "partial"
    assert first["coverage"]["text_files"] == 3 and "Static scanning is not included" in first["coverage"]["scope"]
    (paths[0].parent / "script.py").write_text("Changed sibling content")
    changed, unchanged = list(skills.candidates(cfg))
    assert changed["content_sha256"] == first["content_sha256"]
    assert changed["bundle_sha256"] != first["bundle_sha256"] and changed["tasks"][0]["key"] != first["tasks"][0]["key"]
    assert unchanged == second
    monkeypatch.setattr(skills, "PROFILE", "local-skill-bundle.2")
    assert list(skills.candidates(cfg))[1]["tasks"][0]["key"] != second["tasks"][0]["key"]


def test_capture_privacy_binary_redaction_and_stale_inventory_are_explicit(tmp_path):
    cfg, (path,) = inventory(tmp_path)
    directory = path.parent
    secret = "sk-proj-" + "a"*60
    (directory / "notes.txt").write_text("Token: " + secret + "\r\nUse the tool.\rFinish.\n")
    (directory / ".env").write_text("DO_NOT_UPLOAD=private")
    (directory / "binary.bin").write_bytes(b"\x00\xffprivate")
    outside = tmp_path / "private.txt"
    outside.write_text("linked private file")
    (directory / "linked.txt").symlink_to(outside)
    candidate, = skills.candidates(cfg)
    assert candidate["coverage"]["skipped_entries"] == 3 and candidate["coverage"]["redacted_files"] == 1
    assert not candidate["coverage"]["capture_complete"] and "excluded" in candidate["coverage"]["message"]
    encoded = json.dumps(candidate["tasks"])
    assert secret not in encoded and "DO_NOT_UPLOAD" not in encoded and "linked private file" not in encoded
    note = next(item for item in candidate["tasks"][0]["task"]["files"] if item["path"] == "notes.txt")
    assert len(note["content"].splitlines()) == 3 and "\r" not in note["content"]
    path.write_text("Changed instructions")
    stale, = skills.candidates(cfg)
    assert stale["tasks"] == [] and "changed since collection" in stale["coverage"]["message"]
    path.unlink()
    missing, = skills.candidates(cfg)
    assert missing["tasks"] == [] and "could not be prepared" in missing["coverage"]["message"]
    with pytest.raises(InterruptedError):
        list(skills.candidates(cfg, cancelled=lambda: True))


def test_report_preserves_findings_and_receipt_without_persisting_skill_content(tmp_path):
    cfg, _ = inventory(tmp_path)
    candidate, = skills.candidates(cfg)
    entry, = candidate["tasks"]
    store = Store(cfg)
    request_id = store.claim("skill_assessment", [entry["key"]])
    value = response(entry["task"], request_id, [dict(rule_id="SSD-3", message="Suspicious instruction",
        severity="HIGH", start_line=4, end_line=4, confidence=.9, explanation="Explains the risk.", remediation="Remove the instruction.")])
    store.receipt(request_id, value["billing"])
    report = skills.report(entry["task"], value)
    store.complete(request_id, {entry["key"]: report})
    record = store.records()[entry["key"]]
    assert record["state"] == "complete" and report["status"] == "partial"
    assert report["findings"][0]["title"] == "SSD-3: Suspicious instruction"
    assert "Remove the instruction." in report["findings"][0]["detail"]
    assert store.claim("skill_assessment", [entry["key"]], now=datetime.now(timezone.utc).timestamp()+86400*365) is None
    assert store.summary() == dict(credits_charged="1", credits_reserved="0", unknown_attempts=0)
    assert b"Review the supplied instructions" not in store.path.read_bytes()


@pytest.mark.parametrize("invalid", ["hash", "status", "fields", "line", "rating", "coverage"])
def test_service_evidence_rejects_invalid_schema_and_labels_unverified_locations(tmp_path, invalid):
    cfg, _ = inventory(tmp_path)
    candidate, = skills.candidates(cfg)
    task = candidate["tasks"][0]["task"]
    finding = dict(rule_id="SSD-1", message="Captured evidence", severity="HIGH", start_line=1,
                   end_line=None, confidence=.8, explanation="", remediation="")
    value = response(task, findings=[deepcopy(finding)])
    if invalid == "hash":
        value["request_hash"] = "f"*64
    elif invalid == "status":
        value.update(status="error", code="invalid_response")
    elif invalid == "fields":
        value["result"]["findings"] = [{"summary": "Wrong synthetic schema"}]
    elif invalid == "line":
        for start, end in ((99999, None), (3, 2)):
            value["result"]["findings"][0].update(start_line=start, end_line=end, reported_start_line=start, reported_end_line=end)
            finding, = skills.report(task, value)["findings"]
            assert finding["title"] == "SSD-1: Captured evidence" and "Location unverified" in finding["detail"]
            assert not finding["location_verified"] and finding["start_line"] is None and finding["end_line"] is None
            assert finding["reported_start_line"] == start and finding["reported_end_line"] == end
        return
    elif invalid == "coverage":
        value["result"]["coverage"]["files_completed"] = 0
    else:
        value["result"]["findings"][0]["confidence"] = float("nan")
    with pytest.raises(ValueError):
        skills.report(task, value)


def test_bundle_accepts_large_complete_text_and_preserves_old_chunk_hashes(tmp_path):
    import hashlib
    from openaidr_api_client.contracts.service_skills import ServiceSkillRequest, request_hash as old_hash
    cfg, (path,) = inventory(tmp_path)
    original, = skills.candidates(cfg)
    # Recorded from the pre-bundle client for this unchanged SKILL.md fixture.
    assert original["legacy_keys"] == ["skill:44447d92e54c6f60b1ad6f2d93400d47c96fe94923a2704bcf97257386e6bf97"]
    for name in ("first.txt", "second.txt"):
        (path.parent/name).write_text("x"*800000)
    candidate, = skills.candidates(cfg)
    task = candidate["tasks"][0]["task"]
    assert len(task["files"]) == 3 and sum(len(row["content"]) for row in task["files"]) > 1600000
    old_keys = []
    for row in task["files"]:
        for text, start, end in skills.chunks(row["content"]):
            old = ServiceSkillRequest(revision=skills.REVISION, task="semantic_security_discovery",
                bundle_sha256=task["bundle_sha256"], batch=dict(file_path=row["path"], content=text, start_line=start, end_line=end))
            old_keys.append("skill:" + hashlib.sha256(("local-skill-instructions.1"+old_hash(old.model_dump())).encode()).hexdigest())
    assert candidate["legacy_keys"] == old_keys


@pytest.mark.parametrize("count, explanation, truncated", [(300, "Context", False), (80, "x"*16384, True)])
def test_large_successful_findings_keep_receipt_and_explicit_local_truncation(tmp_path, count, explanation, truncated):
    cfg, _ = inventory(tmp_path)
    candidate, = skills.candidates(cfg)
    entry, = candidate["tasks"]
    store = Store(cfg)
    request = store.claim("skill_assessment", [entry["key"]])
    findings = [dict(rule_id=f"SSD-{i}", message="Evidence", severity="LOW", start_line=1, end_line=1,
        confidence=.5, explanation=explanation, remediation="Review") for i in range(count)]
    value = response(entry["task"], request, findings)
    store.receipt(request, value["billing"])
    report = skills.report(entry["task"], value)
    store.complete(request, {entry["key"]: report})
    assert report["findings_truncated"] is truncated
    assert (len(report["findings"]) < count) is truncated
    assert all(explanation in item["detail"] for item in report["findings"])
    assert Store(cfg).summary() == dict(credits_charged="1", credits_reserved="0", unknown_attempts=0)
    from openaidr.sensor.posture_skill_state import enrich, prepare
    prepare(cfg, store, lambda: False)
    item = dict(id=candidate["installation_id"], metadata={"content_sha256":candidate["content_sha256"]}, attention=False)
    enrich(cfg, [item], store, True)
    assert item["findings_truncated"] and item["assessment_status"] == "partial"
