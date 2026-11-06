"""Keep preparation identities separate from ephemeral skill request content."""

import json
from pathlib import Path
import time

from openaidr.core.files import atomic_write
from . import posture_skills
from .usage import identity

MAX_BYTES = 8 << 20


def settled(record):
    return (record.get("state") == "complete" and record.get("report") is not None
            and record.get("billing_state") in ("settled", "released", "disabled"))


def prepare(config, store, cancelled):
    from .posture_assessments import eligible

    installations, selected = {}, None
    for candidate in posture_skills.candidates(config, cancelled):
        tasks = candidate.pop("tasks")
        keys = list(dict.fromkeys(task["key"] for task in tasks))
        legacy = list(dict.fromkeys(candidate["legacy_keys"]))
        records = store.records([*keys, *legacy])
        prior = [records.get(key, {}) for key in legacy]
        reused = bool(prior) and all(settled(row) for row in prior) and not any(key in records for key in keys)
        held = any(row.get("state") in ("pending", "unknown")
                   or row.get("state") == "complete" and not settled(row) for row in prior)
        candidate.update(legacy_complete=reused, legacy_held=held)
        if reused:
            keys = legacy
        installations[candidate.pop("installation_id")] = {**candidate, "keys": keys}
        if selected is None and not (reused or held):
            selected = next((task for task in tasks if eligible(records.get(task["key"]), time.time())), None)
    if cancelled():
        raise InterruptedError("Skill preparation cancelled")
    value = json.dumps(dict(scope=identity(config), prepared_at=time.time(), installations=installations), ensure_ascii=True)
    if len(value.encode()) > MAX_BYTES:
        raise ValueError("Skill preparation exceeds local storage bounds")
    atomic_write(Path(config["data_dir"]) / "posture-skills.json", value)
    return selected


def enrich(config, items, store, enabled):
    for item in items:
        item["assessment_status"] = "pending" if enabled else "disabled"
    try:
        with (Path(config["data_dir"]) / "posture-skills.json").open() as stream:
            value = json.loads(stream.read(MAX_BYTES + 1))
        if value["scope"] != identity(config):
            return
        installations = value["installations"]
    except (OSError, ValueError, KeyError, TypeError):
        return
    for item in items:
        prepared = installations.get(item["id"])
        if not prepared or prepared["content_sha256"] != item["metadata"].get("content_sha256"):
            item["assessment_status"] = "pending" if enabled else "disabled"
            continue
        keys = prepared["keys"]
        legacy = prepared.get("legacy_keys", [])
        records = store.records(list(dict.fromkeys([*keys, *legacy]))) if store else {}
        tasks = [records.get(key, {}) for key in keys]
        reports = [records[key]["report"] for key in dict.fromkeys([*keys, *legacy]) if records.get(key, {}).get("report")]
        findings = []
        for report in reports:
            for finding in report["findings"][:11]:
                projected = {key: finding[key] for key in ("title", "detail")}
                if projected not in findings and len(findings) < 11:
                    findings.append(projected)
        complete = sum(settled(row) for row in tasks)
        failed = any(row.get("state") in ("unknown", "retry") for row in tasks)
        held = prepared.get("legacy_held", False) or any(row.get("state") == "unknown"
            or row.get("state") == "complete" and not settled(row) for row in tasks)
        coverage = prepared["coverage"]
        item.update(assessment_status="failed" if failed or held else "partial" if reports or not keys else "pending" if enabled else "disabled",
                    findings=findings[:10],
                    findings_truncated=len(findings) > 10 or any(report.get("findings_truncated") or len(report["findings"]) > 10 for report in reports),
                    attention=item["attention"] or bool(findings) or failed or held or not keys or not coverage["capture_complete"])
        if "legacy_keys" not in prepared:
            review = f"Previous review: {complete} of {len(keys)} content batches. Whole-skill preparation pending."
        elif prepared.get("legacy_complete"):
            review = f"Previous review retained for this unchanged skill ({complete} of {len(keys)} content batches). No new charge."
        elif held:
            review = "Whole-skill review held: an earlier request or receipt is unresolved. Prior findings retained."
        elif complete:
            review = "Skill reviewed in one billed request."
        else:
            review = "Whole-skill review pending." if keys else "No supported text prepared for review."
            if reports:
                review += " Earlier partial findings retained."
        item["metadata"].update(assessment_scope=coverage["scope"],
            assessment_coverage=review + " " + coverage["message"],
            assessment_prepared_at=value["prepared_at"])
