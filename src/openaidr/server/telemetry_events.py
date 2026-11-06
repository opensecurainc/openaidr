"""Translate stored OTLP log records into normalized detection events.

Only log records become events. Every event carries ``source: "otlp"`` and an
``export`` reference (export id, record index into ``flatten_records`` and the
signal) so findings can cite the canonical evidence. Identifiers are UUIDv5 of
the export id and record index, which keeps retries and backfills idempotent.

Permitted Codex prompt text is copied from the filtered export. Tool output
and raw API bodies are never copied into events.
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from openaidr.core.event import validate_event
from openaidr.core.reasoning import reasoning_effort
from openaidr.core.telemetry import (
    CAPTURE_GAPS_ATTRIBUTE,
    attributes,
    flatten_records,
    records,
)

NAMESPACE = uuid.UUID("3f8b6a54-9d1e-4c2b-9b0e-7a1c5d2e8f40")
SESSION_KEYS = ("session.id", "conversation.id", "thread.id")
ACCOUNT_KEYS = (
    "user.email",
    "user.id",
    "user.account_id",
    "user.account_uuid",
    "user.name",
)
COMMAND_TOOLS = {
    "bash",
    "exec_command",
    "shell",
    "local_shell",
    "shell_command",
    "container.exec",
    "powershell",
}
READ_TOOLS = {
    "read",
    "glob",
    "grep",
    "notebookread",
    "read_file",
    "list_dir",
    "view_image",
}
WRITE_TOOLS = {
    "edit": "edit",
    "write": "write",
    "multiedit": "edit",
    "notebookedit": "edit",
    "apply_patch": "patch",
    "write_file": "write",
}
NETWORK_TOOLS = {"webfetch", "websearch", "web_search", "fetch_url"}
PATCH_FILE = re.compile(r"^\*\*\* (Update|Add|Delete) File: (.+?)\s*$", re.M)
SKIPPED_SUFFIXES = {"api_request", "api_error", "assistant_response", "response"}


def event_id(export_id, record, extra=0):
    name = f"{export_id}:{record}" + (f":{extra}" if extra else "")
    return str(uuid.uuid5(NAMESPACE, name))


def _first(mapping, keys):
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def _identity(mapping, keys):
    return next(
        (
            mapping[key]
            for key in keys
            if isinstance(mapping.get(key), str) and mapping[key]
        ),
        "",
    )


def _details(attrs):
    """Parse the tool argument JSON that Codex and Claude Code attach."""
    raw = _first(attrs, ("tool_parameters", "arguments", "tool_input", "input"))
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.lstrip().startswith("{"):
        return {}
    try:
        parsed = json.loads(raw)
    except (ValueError, RecursionError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _text(value):
    if isinstance(value, list):
        try:
            return shlex.join(str(item) for item in value)
        except (TypeError, ValueError):
            return " ".join(str(item) for item in value)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    return None


def _int(value):
    try:
        return int(value) if not isinstance(value, bool) else None
    except (TypeError, ValueError):
        return None


def _product(service_name):
    name = (service_name or "").lower()
    if name == "cowork":
        return "cowork"
    if "codex" in name:
        return "codex-cli"
    if "claude" in name:
        return "claude-code"
    return "unknown"


def _tool_events(tool_name, attrs):
    """Return (kind, fields) tuples for one tool_result record."""
    details = _details(attrs)
    key = tool_name.lower()
    tool = {"name": tool_name}
    if key in COMMAND_TOOLS:
        # Claude Code sends both `bash_command` (the first word only) and
        # `full_command`; detection needs the whole command line.
        # A key holding something that is not command text (an object, an
        # empty list) must not hide a later key that does.
        text = next(
            (
                value
                for value in (
                    _text(details.get(name))
                    for name in ("full_command", "command", "cmd", "bash_command")
                )
                if value
            ),
            None,
        )
        if text:
            command = {"text": text}
            cwd = _first(details, ("workdir", "cwd"))
            if isinstance(cwd, str) and cwd:
                command["cwd"] = cwd
            return [("command", {"tool": tool, "command": command})]
    elif key in READ_TOOLS:
        path = _first(details, ("file_path", "path", "dir_path", "notebook_path"))
        pattern = details.get("pattern")
        if (
            isinstance(path, str)
            and path
            and isinstance(pattern, str)
            and pattern
            and key == "glob"
        ):
            path = posixpath.join(path, pattern)
        if isinstance(path, str) and path:
            return [("file.read", {"tool": tool, "file": {"path": path}})]
    elif key in WRITE_TOOLS:
        op = WRITE_TOOLS[key]
        if key == "apply_patch":
            patch = _first(details, ("input", "patch"))
            if not isinstance(patch, str):
                patch = _first(attrs, ("input", "patch"))
            out = []
            for verb, path in PATCH_FILE.findall(patch or ""):
                out.append(
                    (
                        "file.write",
                        {
                            "tool": tool,
                            "file": {
                                "path": path,
                                "op": "delete" if verb == "Delete" else op,
                            },
                        },
                    )
                )
            if out:
                return out
        else:
            path = _first(details, ("file_path", "path", "notebook_path"))
            if isinstance(path, str) and path:
                return [
                    ("file.write", {"tool": tool, "file": {"path": path, "op": op}})
                ]
    elif key in NETWORK_TOOLS:
        url = details.get("url")
        if isinstance(url, str) and url:
            network = {"url": url}
            try:
                host = urlsplit(url).hostname
            except ValueError:
                host = None
            if host:
                network["host"] = host
            return [("network", {"tool": tool, "network": network})]
    return [("tool.call", {"tool": tool})]


def translate_export(export_id, sensor, signal, payload, received_at=None):
    """Normalized events for one stored export; empty for metrics and traces."""
    if signal != "logs":
        return []
    if isinstance(received_at, datetime):
        fallback = (
            received_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        )
    elif isinstance(received_at, str) and received_at:
        fallback = received_at
    else:
        fallback = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    events = []
    rows = flatten_records(signal, payload)
    for index, (row, (resource, _scope, _item)) in enumerate(
        zip(rows, records(signal, payload))
    ):
        resource_attrs = attributes(resource.get("attributes"))
        attrs = row.get("attributes") or {}
        name = row.get("event_name") or (
            row.get("body") if isinstance(row.get("body"), str) else ""
        )
        name = str(name or "")
        suffix = name.rsplit(".", 1)[-1]
        if suffix in SKIPPED_SUFFIXES or suffix not in (
            "tool_result",
            "tool_decision",
            "user_prompt",
        ):
            continue
        session_id = _first(attrs, SESSION_KEYS) or _first(resource_attrs, SESSION_KEYS)
        if not session_id:
            continue
        product = _product(resource_attrs.get("service.name"))
        agent = {"product": product}
        version = (
            resource_attrs.get("service.version")
            or attrs.get("service.version")
            or attrs.get("app.version")
        )
        if version:
            agent["version"] = str(version)
        model = attrs.get("model") or resource_attrs.get("model")
        if model:
            agent["model"] = str(model)
        if effort := reasoning_effort({**resource_attrs, **attrs}):
            agent["reasoning_effort"] = effort
        session = {"id": str(session_id)}
        registration_id = attrs.get("openaidr.session.registration_id")
        if registration_id is not None:
            session["registration_id"] = registration_id
        cwd = attrs.get("cwd") or resource_attrs.get("cwd")
        if isinstance(cwd, str) and cwd:
            session["cwd"] = cwd
        user = (
            _identity(attrs, ("os.user",))
            or _identity(resource_attrs, ("os.user",))
            or _identity(sensor, ("user", "username"))
        )
        account = _identity(attrs, ACCOUNT_KEYS) or _identity(resource_attrs, ACCOUNT_KEYS)
        if account:
            agent["account"] = account
        common = {
            "time": row.get("time") or fallback,
            "agent": agent,
            "session": session,
            "host": {
                "hostname": str(
                    resource_attrs.get("host.name") or sensor.get("hostname") or ""
                ),
                "user": user,
            },
            "event_name": name,
            "source": "otlp",
            "export": {"id": str(export_id), "record": index, "signal": signal},
        }
        if suffix == "user_prompt":
            body = {"kind": "prompt"}
            length = _int(_first(attrs, ("prompt_length", "prompt.length", "length")))
            if length is not None:
                body["prompt"] = {"length": length}
            prompt = attrs.get("prompt")
            if (product == "codex-cli" and isinstance(prompt, str)
                    and prompt.strip() not in ("", "[REDACTED]", "<redacted>")):
                body["text"] = prompt
            parts = [body]
        else:
            tool_name = _first(attrs, ("tool_name", "tool"))
            tool_name = str(tool_name) if tool_name else "unknown"
            if suffix == "tool_decision":
                hook = {"decision": str(attrs.get("decision") or "")}
                if attrs.get("source"):
                    hook["source"] = str(attrs["source"])
                parts = [
                    {"kind": "hook.decision", "tool": {"name": tool_name}, "hook": hook}
                ]
            else:
                parts = []
                # The agent's own call id lets one action observed both here
                # and by a hook be joined instead of counted twice.
                call_id = _first(attrs, ("tool_use_id", "call_id", "tool_call_id"))
                for kind, fields in _tool_events(tool_name, attrs):
                    part = {"kind": kind, **fields}
                    tool = part["tool"] = dict(part["tool"])
                    if call_id:
                        tool["call_id"] = str(call_id)
                    success = _bool(attrs.get("success"))
                    if success is not None:
                        tool["success"] = success
                    duration = _int(attrs.get("duration_ms"))
                    if duration is not None:
                        tool["duration_ms"] = duration
                    if attrs.get("error"):
                        part["error"] = str(attrs["error"])[:500]
                    parts.append(part)
        for extra, part in enumerate(parts):
            event = {"id": event_id(export_id, index, extra), **common, **part}
            if registration_id is not None:
                event["evidence"] = {
                    "version": 1,
                    "logical_id": event_id(export_id, index, 0),
                    "observation_id": event["id"],
                    "stream_id": str(export_id),
                    "sequence": index + 1,
                    "part": extra,
                    "gaps": attrs.get(CAPTURE_GAPS_ATTRIBUTE, []),
                }
            if not validate_event(event):
                events.append(event)
    return events
