"""Sensor capture filtering with the shared credential redactor."""

import json

from openaidr_common.redact import (
    SecretRedactor as SecretRedactor,
    _REDACTOR as _REDACTOR,
    contains_secret as contains_secret,
    is_secret_key as is_secret_key,
    redact_string as redact_string,
    redact_value as redact_value,
)


def redact_event(event, capture):
    limit = capture.get("max_text_bytes") or 16384
    evidence = event.get("evidence")

    def mark_gap(reason):
        if (
            isinstance(evidence, dict)
            and evidence.get("version") == 1
            and isinstance(evidence.get("gaps"), list)
            and reason not in evidence["gaps"]
        ):
            evidence["gaps"].append(reason)

    def omit(obj, key):
        if key in obj:
            obj.pop(key)
            mark_gap("capture_disabled")

    if event.get("kind") in ("prompt", "response") and not capture.get(
        event["kind"] + "_text"
    ):
        omit(event, "text")
    if not capture.get("raw"):
        omit(event, "raw")
    tool = event.get("tool", {})
    if not capture.get("tool_input"):
        omit(tool, "input")
    if not capture.get("tool_output"):
        omit(tool, "output")

    def redact(text):
        if capture.get("redact"):
            text, names = redact_string(text)
            if names:
                event["redacted"] = True
        return text

    def clean(text):
        text = redact(text)
        if len(text.encode()) > limit:
            event["truncated"] = True
            text = text.encode()[:limit].decode("utf-8", errors="ignore")
        return text

    for obj, key in (
        (event, "text"),
        (event.get("command", {}), "text"),
        (tool, "output"),
    ):
        if obj.get(key):
            obj[key] = clean(obj[key])
    for section, keys in (
        ("command", ("cwd", "description")),
        ("file", ("path",)),
        ("network", ("url", "host")),
        ("session", ("cwd",)),
    ):
        obj = event.get(section)
        if not isinstance(obj, dict):
            continue
        for key in keys:
            if isinstance(obj.get(key), str):
                obj[key] = redact(obj[key])
    if tool.get("input") is not None:
        text = json.dumps(tool["input"], ensure_ascii=False, separators=(",", ":"))
        redacted, names = redact_string(text) if capture.get("redact") else (text, [])
        if names:
            event["redacted"] = True
        if len(redacted.encode()) > limit:
            tool["input"] = {
                "_truncated": True,
                "prefix": redacted.encode()[:limit].decode("utf-8", errors="ignore"),
            }
            event["truncated"] = True
        else:
            try:
                tool["input"] = json.loads(redacted)
            except ValueError:
                tool["input"] = {"_redacted": True}
                event["redacted"] = True
    if "raw" in event:
        text = json.dumps(event["raw"])
        if capture.get("redact"):
            text, names = redact_string(text)
            if names:
                event["redacted"] = True
        try:
            if len(text.encode()) > 4 * limit:
                raise ValueError()
            event["raw"] = json.loads(text)
        except ValueError:
            event.pop("raw", None)
            event["truncated"] = True
    if event.get("redacted"):
        mark_gap("content_redacted")
    if event.get("truncated"):
        mark_gap("content_truncated")
