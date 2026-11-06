"""Validate scanner reports without loading tenant storage or execution."""

from datetime import datetime, timedelta, timezone
import re

from openaidr_api_client.contracts.errors import require


def validate_report(value):
    require(isinstance(value, dict), "invalid scanner report")
    require(
        type(value.get("complete")) is bool and value.get("mode") in ("static", "llm"),
        "invalid scan coverage",
    )
    require(
        type(value.get("score")) is int and 0 <= value["score"] <= 100,
        "invalid scan score",
    )
    require(
        isinstance(value.get("scanner_version"), str)
        and 0 < len(value["scanner_version"]) <= 128,
        "invalid scanner version",
    )
    issues = value.get("issues")
    require(isinstance(issues, list) and len(issues) <= 500, "invalid scanner findings")
    clean = []
    for issue in issues:
        require(
            isinstance(issue, dict)
            and issue.get("severity") in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"),
            "invalid finding severity",
        )
        entry = {"severity": issue["severity"]}
        for key, limit in (
            ("rule", 128),
            ("title", 512),
            ("description", 4096),
            ("file", 2048),
            ("remediation", 4096),
        ):
            text = issue.get(key, "")
            require(
                isinstance(text, str) and len(text) <= limit, "invalid finding text"
            )
            entry[key] = text
        line = issue.get("line", 0)
        require(type(line) is int and 0 <= line <= 10000000, "invalid finding line")
        entry["line"] = line
        clean.append(entry)
    result = {
        "complete": value["complete"],
        "mode": value["mode"],
        "score": value["score"],
        "scanner_version": value["scanner_version"],
        "issues": clean,
        "needs_attention": any(i["severity"] in ("HIGH", "CRITICAL") for i in clean),
    }
    if "intel_expires_at" in value:
        stamp = value["intel_expires_at"]
        require(isinstance(stamp, str) and len(stamp) <= 64, "invalid intelligence expiry")
        try:
            expiry = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            require(expiry.tzinfo is not None and expiry <= datetime.now(timezone.utc) + timedelta(days=1), "invalid intelligence expiry")
            result["intel_expires_at"] = expiry.astimezone(timezone.utc).isoformat()
        except (ValueError, OverflowError):
            require(False, "invalid intelligence expiry")
    if "model" in value:
        model = value["model"]
        require(isinstance(model, str) and (not model or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,255}", model))
                and not model.startswith(("sk-", "sk_")), "invalid scan model")
        result["model"] = model
    if "usage_incomplete" in value:
        require(type(value["usage_incomplete"]) is bool, "invalid usage completeness")
        result["usage_incomplete"] = value["usage_incomplete"]
    if "finding_text_truncated" in value:
        require(type(value["finding_text_truncated"]) is bool, "invalid finding text truncation")
        result["finding_text_truncated"] = value["finding_text_truncated"]
    if "inference_usage" in value:
        usage = value["inference_usage"]
        require(isinstance(usage, list) and len(usage) <= 4096, "invalid inference usage")
        records = []
        for source in usage:
            require(isinstance(source, dict) and source.get("usage_source") == "provider_response",
                    "invalid usage source")
            entry = {}
            for key in ("provider", "model"):
                label = source.get(key)
                require(isinstance(label, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,255}", label)
                        and not label.startswith(("sk-", "sk_")), "invalid usage label")
                entry[key] = label
            for key in ("prompt_tokens", "completion_tokens", "cached_tokens", "cache_write_tokens", "reasoning_tokens"):
                if key in source:
                    counter = source[key]
                    require(type(counter) is int and 0 <= counter <= 1_000_000_000, "invalid usage counter")
                    entry[key] = counter
            if "prompt_tokens" in entry:
                require(entry.get("cached_tokens", 0) + entry.get("cache_write_tokens", 0) <= entry["prompt_tokens"],
                        "invalid cached token count")
            if "completion_tokens" in entry:
                require(entry.get("reasoning_tokens", 0) <= entry["completion_tokens"], "invalid reasoning token count")
            require(any(key.endswith("tokens") for key in entry), "missing usage counters")
            entry["usage_source"] = "provider_response"
            records.append(entry)
        result["inference_usage"] = records
    # Older workers and retained reports have no coverage diagnostics.
    if "coverage" in value:
        coverage = value["coverage"]
        require(isinstance(coverage, dict), "invalid coverage diagnostics")
        reasons = coverage.get("reasons")
        require(isinstance(reasons, list) and len(reasons) <= 50, "invalid coverage reasons")
        require(type(coverage.get("truncated")) is bool, "invalid coverage truncation")
        entries = []
        for reason in reasons:
            require(isinstance(reason, dict), "invalid coverage reason")
            entry = {}
            for key, limit in (("code", 128), ("message", 512), ("file", 2048), ("analyzer", 128)):
                text = reason.get(key, "")
                require(isinstance(text, str) and len(text) <= limit, "invalid coverage text")
                entry[key] = text
            require(bool(entry["message"]), "missing coverage explanation")
            if "line" in reason:
                require(type(reason["line"]) is int and 0 < reason["line"] <= 10_000_000, "invalid coverage line")
                entry["line"] = reason["line"]
            if "target" in reason:
                require(isinstance(reason["target"], str) and len(reason["target"]) <= 2048, "invalid coverage target")
                entry["target"] = reason["target"]
            entries.append(entry)
        result["coverage"] = {"reasons": entries, "truncated": coverage["truncated"]}
    return result
