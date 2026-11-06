"""Validated, repeatable selections for MCP knowledge imports."""

import hashlib
import json

from openaidr.core.redact import redact_value
from .httpx import require
from .knowledge import _text


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def selection(value):
    require(isinstance(value, dict), "invalid MCP import selection")
    kind = value.get("kind")
    fields = {
        "resource": {"kind", "uri"},
        "template": {"kind", "uri_template", "parameters"},
        "tool": {"kind", "name", "arguments", "schema_hash"},
    }
    require(isinstance(kind, str) and kind in fields and set(value) == fields[kind], "invalid MCP import fields")
    for key in fields[kind] - {"kind", "parameters", "arguments"}:
        _text(value, key, 1024 if key in ("uri", "uri_template") else 240)
    params = value.get("arguments", value.get("parameters", {}))
    require(isinstance(params, dict), "MCP arguments must be a JSON object")
    try:
        encoded = canonical(value).encode()
        clean = redact_value(value) == value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        require(False, "MCP import selection must contain valid JSON text")
    require(len(encoded) <= 32768, "MCP import selection exceeds 32 KiB")
    require(clean, "Do not put credentials in MCP import arguments or URIs")
    return value


def selection_key(value):
    if value["kind"] == "resource":
        return value["uri"]
    return "mcp-import:" + hashlib.sha256(canonical(value).encode()).hexdigest()


def tool_hash(tool):
    return hashlib.sha256(canonical(tool.model_dump(mode="json", by_alias=True)).encode()).hexdigest()


def tool_readable(tool):
    hints = tool.annotations
    return not hints or (hints.read_only_hint is not False and hints.destructive_hint is not True)


def tool_content(result):
    require(not result.is_error, "The MCP tool reported a failure; no content was imported", 502)
    # Structured results are also commonly repeated in a text block. Index once.
    if result.structured_content is not None:
        return json.dumps(result.structured_content, ensure_ascii=False, indent=2)
    parts = []
    for item in result.content:
        if item.type == "text":
            parts.append(item.text)
        elif item.type == "resource" and hasattr(item.resource, "text"):
            parts.append(item.resource.text)
        else:
            require(False, "This tool result contains unsupported content; choose a text retrieval tool", 415)
    return "\n\n".join(parts)


def tool_title(result, text, fallback):
    content = result.structured_content
    if content is None:
        try:
            content = json.loads(text)
        except (ValueError, RecursionError):
            return fallback
    title = content.get("title") if isinstance(content, dict) else None
    if isinstance(title, str) and title.strip() and "\x00" not in title:
        try:
            if len(title.encode()) <= 240:
                return title
        except UnicodeError:
            pass
    return fallback
