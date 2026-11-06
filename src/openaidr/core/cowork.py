"""Cowork wire adapters. Native plugin hooks and Enterprise frames are distinct."""

import json
import uuid

from .toolmap import map_tool


def identifier(*parts):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(["openaidr-cowork", *parts])))


def tool_actions(name, arguments, call_id="", cwd=""):
    tool = {"name": name, "input": arguments, "call_id": call_id}
    out = []
    mapped_name = {key.lower(): key for key in ("Bash", "Read", "Write", "Edit", "Grep", "Glob", "WebFetch")}.get(name.lower(), name)
    for mapped in map_tool("cowork", mapped_name, arguments):
        action = {"kind": mapped["kind"], "tool": tool}
        for field, keys in (("command", ("text", "cwd")), ("file", ("path",)),
                            ("network", ("host", "url"))):
            if field in mapped:
                action[field] = {key: mapped[field][key] for key in keys if key in mapped[field]}
        if "command" in action and not action["command"].get("cwd"):
            action["command"]["cwd"] = cwd
        out.append(action)
    return out


def native_check(payload, request_id, *, capture_content=False):
    event = payload.get("hook_event_name")
    if event not in ("UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure"):
        return None
    session = payload.get("session_id")
    if not isinstance(session, str) or not session or len(session) > 256:
        raise ValueError("invalid Cowork session")
    check = {"request_id": request_id, "product": "cowork", "hook_event": event,
             "session_id": session, "tool_call_id": payload.get("tool_use_id", ""),
             "actions": [], "control_supported": event in ("UserPromptSubmit", "PreToolUse")}
    if not capture_content:
        check["availability"] = "capture_disabled"
    elif event == "UserPromptSubmit":
        if not isinstance(payload.get("prompt"), str):
            raise ValueError("invalid Cowork prompt")
        check["actions"] = [{"kind": "prompt", "text": payload["prompt"]}]
    else:
        name = payload.get("tool_name")
        if not isinstance(name, str) or not name:
            raise ValueError("invalid Cowork tool")
        if event == "PreToolUse":
            if not isinstance(payload.get("tool_input"), dict):
                raise ValueError("invalid Cowork tool input")
            check["actions"] = tool_actions(name, payload["tool_input"], check["tool_call_id"], payload.get("cwd", ""))
        else:
            output = payload.get("error", "") if event == "PostToolUseFailure" else payload.get("tool_response", "")
            check["actions"] = [{"kind": "tool.result", "tool": {
                "name": name, "call_id": check["tool_call_id"],
                "output": output if isinstance(output, str) else json.dumps(output),
                "is_error": event == "PostToolUseFailure",
            }}]
    return bounded(check)


def inference_check(payload, request_id, *, capture_content=False):
    kind = payload.get("type")
    if kind not in ("prompt", "tool_call"):
        return None
    session = payload.get("session_id")
    if session is not None and (not isinstance(session, str) or len(session) > 256):
        raise ValueError("invalid inference session")
    source = (payload.get("source") or {}).get("application")
    product = source if source in ("cowork", "claude-code", "claude-ai") else "unknown"
    check = {"request_id": request_id, "product": product,
             "hook_event": "PreToolUse" if kind == "tool_call" else "UserPromptSubmit",
             "session_id": session or request_id, "tool_call_id": "", "actions": []}
    if not capture_content:
        check["availability"] = "capture_disabled"
        return check
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError("invalid inference messages")
    if kind == "prompt":
        # The protocol governs the entire transcript, including tool results and
        # attachments. Preserve its structure and do not inspect only the last text.
        check["actions"] = [{"kind": "prompt", "text": json.dumps(messages, ensure_ascii=False)}]
    else:
        latest = messages[-1]
        if not isinstance(latest, dict) or not isinstance(latest.get("content"), list):
            raise ValueError("invalid tool call frame")
        for block in latest["content"]:
            if not isinstance(block, dict):
                raise ValueError("invalid content block")
            if block.get("type") != "tool_use":
                continue
            name, arguments = block.get("tool_name"), block.get("input")
            if not isinstance(name, str) or not isinstance(arguments, dict):
                check["availability"], check["actions"] = "unsupported_content", []
                break
            check["actions"].extend(tool_actions(name, arguments, block.get("id") or ""))
        if not check["actions"]:
            check["availability"] = "unsupported_content"
    return bounded(check)


def bounded(check):
    # Never enforce on a silently truncated subset of a transcript or tool batch.
    if len(check["actions"]) > 128 or len(json.dumps(check).encode()) > 60 << 10:
        check["actions"], check["availability"] = [], "content_truncated"
    return check
