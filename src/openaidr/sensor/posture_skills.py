"""Prepare bounded semantic skill tasks without a local scanner or content ledger."""

from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re

from openaidr_api_client.contracts.service_skills import REVISION, ServiceSkillRequest, request_hash as legacy_hash
from openaidr_api_client.contracts.service_skill_bundles import ServiceSkillBundleRequest, request_hash, validate_response

from openaidr.core.redact import redact_string
from openaidr.core.skill_bundle import digest, validate_files
from .inventory_service import InventoryService
from .skill_bundles import capture

PROFILE = "local-skill-bundle.1"
LEGACY_PROFILE = "local-skill-instructions.1"
CHUNK_CHARS = 32768
SCOPE = "Instruction and content AI review only. Static scanning is not included. Lines refer to prepared text."


def chunks(text):
    """Keep all prepared text, including long single lines, without truncation."""
    offset, line = 0, 1
    while offset < len(text):
        end = min(offset + CHUNK_CHARS, len(text))
        if end < len(text):
            boundary = text.rfind("\n", offset, end)
            if boundary >= offset:
                end = boundary + 1
        content = text[offset:end]
        yield content, line, line + content.count("\n") - int(content.endswith("\n"))
        line += content.count("\n")
        offset = end


def candidates(config, cancelled=lambda: False):
    """Yield every discovered installation, with explicit capture gaps and task keys.

    Only this in-memory result contains request text. Callers persist the selected
    keys, hashes, coverage and projected reports, never tasks or captured files.
    """
    from .local_posture import record_id

    snapshot = InventoryService(config, None, components=True).state.get("snapshot", {})
    for root in snapshot.get("roots", []):
        if root.get("source") != "openaidr-skills":
            continue
        for row in root.get("components", []):
            if not isinstance(row, dict) or row.get("kind") != "skill":
                continue
            if cancelled():
                raise InterruptedError("Skill preparation cancelled")
            coverage = dict(scope=SCOPE, status="partial", capture_complete=False, text_files=0,
                            skipped_entries=0, redacted_files=0, task_count=0, message="")
            candidate = dict(installation_id=record_id(root["source"], root["root"], row),
                             content_sha256=None, bundle_sha256=None, coverage=coverage, tasks=[], legacy_keys=[])
            try:
                path = Path(row.get("path", ""))
                expected = (row.get("metadata") or {}).get("content_sha256", "")
                if not path.is_absolute() or path.name != "SKILL.md" or not re.fullmatch("[a-f0-9]{64}", expected):
                    raise ValueError("Missing current skill identity")
                bundle = capture(path, cancelled)
                files = validate_files(bundle["manifest"], bundle["files"])
                actual = digest(files["SKILL.md"])
                candidate.update(content_sha256=actual, bundle_sha256=bundle["sha256"])
                if actual != expected:
                    coverage["message"] = "Skill changed since collection. Waiting for updated inventory."
                    yield candidate
                    continue
                coverage["capture_complete"] = bundle["manifest"]["complete"]
                coverage["skipped_entries"] = sum("skip" in item for item in bundle["manifest"]["files"])
                prepared = []
                for name, data in files.items():
                    if cancelled():
                        raise InterruptedError("Skill preparation cancelled")
                    try:
                        text = data.decode("utf-8")
                    except UnicodeDecodeError:
                        coverage["skipped_entries"] += 1
                        continue
                    if any(ord(char) < 32 and char not in "\t\r\n" for char in text):
                        coverage["skipped_entries"] += 1
                        continue
                    text = text.replace("\r\n", "\n")
                    for separator in ("\r", "\x85", "\u2028", "\u2029"):
                        text = text.replace(separator, "\n")
                    text, redactions = redact_string(text)
                    file_path, path_redactions = redact_string(name)
                    coverage["redacted_files"] += bool(redactions or path_redactions)
                    coverage["text_files"] += 1
                    prepared.append(dict(path=file_path, content=text))
                    # Retain exact old identities only to reuse or hold ledger evidence.
                    for content, start, end in chunks(text):
                        legacy = ServiceSkillRequest(revision=REVISION, task="semantic_security_discovery",
                            bundle_sha256=bundle["sha256"], batch=dict(file_path=file_path, content=content,
                            start_line=start, end_line=end)).model_dump()
                        candidate["legacy_keys"].append("skill:" + hashlib.sha256((LEGACY_PROFILE + legacy_hash(legacy)).encode()).hexdigest())
                if prepared:
                    task = ServiceSkillBundleRequest(profile="skill-bundle-assessment.1", revision=REVISION,
                        bundle_sha256=bundle["sha256"], files=prepared).model_dump()
                    if len(json.dumps(task, ensure_ascii=False).encode()) > 9 << 20:
                        raise ValueError("Skill bundle exceeds service bounds")
                    key = "skill-bundle:" + hashlib.sha256((PROFILE + request_hash(task)).encode()).hexdigest()
                    candidate["tasks"] = [dict(key=key, task=task)]
                coverage["task_count"] = len(candidate["tasks"])
                gaps = []
                if not coverage["capture_complete"]:
                    gaps.append("Some skill content could not be captured.")
                if coverage["skipped_entries"]:
                    gaps.append(f"{coverage['skipped_entries']} entries excluded by privacy, file type, or collection limits.")
                if coverage["redacted_files"]:
                    gaps.append(f"Credentials redacted in {coverage['redacted_files']} files.")
                if not candidate["tasks"]:
                    gaps.append("No supported text was available for review.")
                coverage["message"] = " ".join(gaps)
            except InterruptedError:
                raise
            except (OSError, ValueError, TypeError, KeyError, AttributeError):
                candidate.update(tasks=[], legacy_keys=[])
                coverage.update(capture_complete=False, task_count=0,
                                message="Skill content could not be prepared within service limits with a current identity.")
            yield candidate


def report(task, response):
    """Project one completed semantic task after the caller saves its receipt.

    The service validates the pinned LLMAnalysisResult schema. Validate its fields
    and label locations outside the reviewed batch without discarding findings.
    """
    task = ServiceSkillBundleRequest.model_validate(task).model_dump()
    parsed = validate_response(task, response)
    if parsed.status != "completed" or parsed.result.get("findings_complete") is not True:
        raise ValueError("Skill assessment did not complete")
    coverage = parsed.result["coverage"]
    fields = ("files_submitted", "files_completed", "bytes_submitted", "bytes_completed", "batches_total", "batches_completed")
    if not isinstance(coverage, dict) or any(type(coverage.get(key)) is not int or coverage[key] < 0 for key in fields):
        raise ValueError("Invalid skill coverage")
    coverage = {key: coverage[key] for key in (*fields, "complete")}
    total = sum(len(item["content"].encode()) for item in task["files"])
    if (coverage["complete"] is not True or coverage["files_submitted"] != len(task["files"])
            or coverage["files_completed"] != len(task["files"]) or coverage["bytes_submitted"] != total
            or coverage["bytes_completed"] != total or coverage["batches_completed"] != coverage["batches_total"]):
        raise ValueError("Skill response does not cover the submitted bundle")
    values = parsed.result.get("findings")
    if not isinstance(values, list):
        raise ValueError("Invalid semantic findings")
    findings, retained_bytes, truncated = [], 0, False
    lines = {item["path"]: max(1, len(item["content"].splitlines())) for item in task["files"]}
    for value in values:
        if not isinstance(value, dict) or any(not isinstance(value.get(field, ""), str)
                or len(value.get(field, "")) > limit for field, limit in
                (("rule_id", 128), ("message", 4096), ("explanation", 16384), ("remediation", 16384))):
            raise ValueError("Invalid semantic finding text")
        start, end, confidence = value.get("start_line"), value.get("end_line"), value.get("confidence", .5)
        path, verified = value.get("file_path"), value.get("location_verified")
        reported_start, reported_end = value.get("reported_start_line"), value.get("reported_end_line")
        if (not value.get("rule_id") or not value.get("message")
                or value.get("severity") not in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
                or any(number is not None and type(number) is not int for number in (start, end, reported_start, reported_end))
                or path is not None and (not isinstance(path, str) or len(path) > 2048) or type(verified) is not bool
                or type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1):
            raise ValueError("Invalid semantic finding location or rating")
        limit = lines.get(path, 0)
        verified = verified and start is not None and 1 <= start <= limit and (end is None or start <= end <= limit)
        path = redact_string(path)[0] if path is not None else None
        title = redact_string(f"{value['rule_id']}: {value['message']}")[0]
        location = f"{path}:{start}" if verified else f"{path or 'Skill bundle'} · Location unverified"
        detail = redact_string("\n".join(filter(None, (f"{location} · {value['severity']}",
                              value.get("explanation"), value.get("remediation")))))[0]
        finding = dict(title=title, detail=detail, file_path=path,
            start_line=start if verified else None, end_line=end if verified else None, location_verified=verified,
            reported_start_line=reported_start, reported_end_line=reported_end, severity=value["severity"], confidence=confidence)
        size = len(json.dumps(finding, ensure_ascii=True).encode()) + 2
        if retained_bytes + size <= (1 << 20) - 8192:
            findings.append(finding)
            retained_bytes += size
        else:
            truncated = True
    result = dict(status="partial", profile=PROFILE, bundle_sha256=task["bundle_sha256"],
                  request_hash=request_hash(task), checked_at=datetime.now(timezone.utc).isoformat(),
                  expires_at=None, coverage=SCOPE, reviewed=coverage, findings=findings, findings_truncated=truncated)
    if len(json.dumps(result, ensure_ascii=True).encode()) > 1 << 20:
        raise ValueError("Semantic report exceeds local storage bounds")
    return result
