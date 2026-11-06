"""One redacted text upload, with original-file static evidence kept locally."""

from contextlib import nullcontext
import json
import math
import os
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace

from openaidr.core.redact import redact_string
from openaidr.core.skill_bundle import validate_files
from . import skill_scan_local, skill_worker


def prepare(job, raw):
    from openaidr_api_client.contracts.service_skill_scans import ServiceSkillScanRequest, REVISION, STATIC_ANALYZERS

    files, names, unmapped, omitted = [], {}, set(), 0
    for name, data in validate_files(job["manifest"], job["files"]).items():
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            omitted += 1
            continue
        if any(ord(char) < 32 and char not in "\t\r\n" for char in text):
            omitted += 1
            continue
        original_lines = text.count("\n")
        text = text.replace("\r\n", "\n")
        for separator in ("\r", "\x85", "\u2028", "\u2029"):
            text = text.replace(separator, "\n")
        path, _ = redact_string(name)
        normalized_lines = text.count("\n")
        text, _ = redact_string(text)
        if original_lines != normalized_lines or normalized_lines != text.count("\n"):
            unmapped.add(name)
        names[name] = path
        files.append({"path": path, "content": text})
    seeds, seed_bytes, skipped = [], 2, 0
    for issue in raw["issues"]:
        location = issue.get("location") or {}
        path = location.get("file")
        if path not in names or (issue.get("evidence") or {}).get("local_only") is True:
            continue
        source = raw.get("_local_sources", {}).get(issue["finding_id"])
        limit = max(1, len(next(item["content"] for item in files if item["path"] == names[path]).splitlines()))
        start, end = location.get("start_line"), location.get("end_line")
        if (source not in STATIC_ANALYZERS or path in unmapped or type(start) is not int or not 1 <= start <= limit
                or end is not None and (type(end) is not int or not start <= end <= limit)):
            skipped += 1
            continue
        seed = dict(rule_id=issue["id"], finding_id=issue["finding_id"], severity=issue["severity"],
                    file=names[path], start_line=location.get("start_line") or 1,
                    end_line=location.get("end_line"), confidence=issue.get("confidence", .5), source_analyzer=source)
        for key, value in (("message", issue.get("explanation") or issue.get("finding") or issue["id"]),
                           ("matched_text", issue.get("finding")), ("context", issue.get("code_snippet")),
                           ("explanation", issue.get("explanation")), ("remediation", issue.get("remediation"))):
            seed[key] = redact_string(value)[0] if isinstance(value, str) else value
        limits = dict(rule_id=128, finding_id=128, message=4096, matched_text=16384,
                      context=16384, explanation=4096, remediation=4096)
        size = len(json.dumps(seed, ensure_ascii=False).encode()) + 2
        if (seed["severity"] not in ("LOW", "MEDIUM", "HIGH", "CRITICAL") or len(seeds) == 500
                or seed_bytes + size > 1 << 20
                or any(seed[key] is not None and len(seed[key]) > limit for key, limit in limits.items())):
            skipped += 1
            continue
        seeds.append(seed)
        seed_bytes += size
    task = ServiceSkillScanRequest(profile="skill-full-scan.1", revision=REVISION, bundle_sha256=job["sha256"],
                                  files=files, static_findings=seeds).model_dump()
    return task, names, omitted, skipped, unmapped


def merge(local, cloud, *, binary, names, unmapped=()):
    """Keep local findings and cloud enrichment; score the union with the pin."""
    reverse = {value: key for key, value in names.items()}
    issues = {item["finding_id"]: item for item in local["issues"]}
    for item in cloud["issues"]:
        item = {**item, "location": dict(item.get("location") or {})}
        item["location"]["file"] = reverse.get(item["location"].get("file"), item["location"].get("file"))
        if item["location"]["file"] in unmapped:
            item["location"].update(start_line=None, end_line=None, start_column=None, end_column=None)
        confidence = item.get("confidence", .5)
        if type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("Invalid scanner finding confidence")
        issues.setdefault(item["finding_id"], item)
    # The cloud graph can rediscover seeded checks with a new opaque ID.
    unique = {}
    for issue in issues.values():
        location = issue.get("location") or {}
        match = issue.get("match_fingerprint") or (issue.get("finding"), issue.get("explanation"))
        identity = (issue["id"], location.get("file"), location.get("start_line"),
                    location.get("end_line"), match)
        unique.setdefault(identity, issue)
    combined = list(unique.values())
    payload = json.dumps({"issues": combined, "components": local["components"]}, allow_nan=False).encode()
    if len(payload) > 16 << 20:
        raise ValueError("Combined scanner report exceeds limits")
    result = subprocess.run([str(Path(binary).with_name("python")), "-I", skill_scan_local.__file__, "score"],
        input=payload, capture_output=True, check=True, timeout=30,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONUTF8": "1"})
    score = json.loads(result.stdout)["score"]
    return {**cloud, "issues": combined, "risk_assessment": {**cloud["risk_assessment"], "score": score}}


def deferred_only(raw, job, task, names):
    """Reconcile only known deferred lookups on unchanged submitted text."""
    coverage = raw.get("analysis_completeness") or {}
    exceptions = coverage.get("ledger_exceptions", [])
    original = validate_files(job["manifest"], job["files"])
    prepared = {item["path"]: item["content"].encode() for item in task["files"]}
    return bool(raw.get("execution_successful") is True and exceptions
        and coverage.get("scope_exclusions") == []
        and coverage.get("limitations") == ["Analyzer static_patterns_supply_chain status: degraded."]
        and all(item.get("error_class") == "IntelligenceDeferredToSkillService"
                and item.get("reason_code") == "analyzer_runtime_error" and item.get("phase") == "static"
                and item.get("fatal") is False and item.get("path") in names
                and original.get(item["path"]) == prepared.get(names[item["path"]]) for item in exceptions)
        and all(item.get("status") in ("completed", "not_applicable", "disabled")
                or item.get("analyzer_id") == "static_patterns_supply_chain" and item.get("status") == "degraded"
                and all(item.get(key) == 0 for key in ("failed", "skipped", "unaccounted"))
                for item in coverage.get("analyzer_statuses", [])))


def scan(job, *, client, binary, timeout=600):
    from openaidr_api_client.contracts.service_skill_scans import validate_response

    deadline = time.monotonic() + min(timeout, 600)
    raw = {}
    local = skill_worker.scan(job, binary=binary, mode="static", timeout=min(120, timeout),
        model_env={"SKILLSPECTOR_MAX_WORKFLOW_SECONDS": str(max(1, min(115, timeout - 5)))},
        bridge_factory=lambda _: nullcontext(SimpleNamespace(environment={}, expires_at=None)),
        adapter_script=skill_scan_local.__file__, raw_report=raw)
    try:
        task, names, omitted, skipped, unmapped = prepare(job, raw)
        remaining = deadline - time.monotonic() - 35
        if remaining <= 0:
            raise TimeoutError("No time remains for the skill service")
        task["timeout_ms"] = max(1, int(remaining * 1000))
        reply = client.post("/internal/v1/skill-scans/inference-bundle",
            json={"sha256": job["sha256"], "lease_id": job["lease_id"], "task": task}, timeout=remaining + 5)
        reply.raise_for_status()
        value = validate_response(task, reply.json())
        result = value.result
        seed_review = result["seed_review"]
        if (any(type(result.get(key)) is not int for key in ("files_submitted", "bytes_submitted", "seed_findings_submitted"))
                or result["scope"] != "redacted_text" or result["files_submitted"] != len(task["files"])
                or result["bytes_submitted"] != sum(len(item["content"].encode()) for item in task["files"])
                or result["seed_findings_submitted"] != len(task["static_findings"]) or not result.get("report")
                or seed_review["requested"] is not bool(task["static_findings"])
                or value.status == "completed" and seed_review["complete"] is not True):
            raise ValueError("Skill service coverage does not match the request")
        cloud = {**result["report"], "issues": [*result["report"]["issues"], *seed_review["issues"]]}
        combined = merge(raw, cloud, binary=binary, names=names, unmapped=unmapped)
        report = skill_worker.normalize(combined, job["manifest"], "llm", source_files=validate_files(job["manifest"], job["files"]))
        deferred = report["complete"] and deferred_only(raw, job, task, names)
        report["complete"] &= ((local["complete"] or deferred) and value.status == "completed"
                               and value.billing.state in ("settled", "disabled") and not omitted and not skipped)
        reasons = [*report.get("coverage", {}).get("reasons", []),
                   *(local.get("coverage", {}).get("reasons", []) if not deferred else [])]
        message = "Original files received local static checks. Cloud AI reviewed redacted text in one service request."
        if omitted or skipped:
            message += f" {omitted} non-text files stayed local; {skipped} static findings were outside cloud review limits."
        if unmapped:
            message += f" Cloud findings in {len(unmapped)} prepared files have no verified original line."
        reasons.append(dict(code="text_service_scope", message=message, file="", analyzer=""))
        report["coverage"] = {"reasons": reasons[:50], "truncated": len(reasons) > 50 or local.get("coverage", {}).get("truncated", False)
                              or report.get("coverage", {}).get("truncated", False)}
        return skill_worker.validate_report(report)
    except Exception:
        # Lost or invalid service replies stay held by the tenant's durable intent.
        # Preserve original-file findings even when cloud work cannot complete.
        local.update(complete=False, mode="llm")
        coverage = local.setdefault("coverage", {"reasons": [], "truncated": False})
        if len(coverage["reasons"]) < 50:
            coverage["reasons"].append(dict(code="text_service_unavailable", file="", analyzer="",
                message="Cloud text review did not complete. Local static findings are retained; no automatic paid retry is made."))
        else:
            coverage["truncated"] = True
        return skill_worker.validate_report(local)
