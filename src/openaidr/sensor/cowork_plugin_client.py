"""Standalone, standard-library Cowork hook client copied into the plugin ZIP."""

import json
from pathlib import Path
import sys
import threading
import time
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def response(value, event):
    if not isinstance(value, dict):
        return {}
    if event == "PreToolUse":
        output = value.get("hookSpecificOutput")
        if (isinstance(output, dict) and output.get("hookEventName") == event
                and output.get("permissionDecision") in ("deny", "ask")
                and isinstance(output.get("permissionDecisionReason"), str)):
            return {"hookSpecificOutput": {key: output[key] for key in
                    ("hookEventName", "permissionDecision", "permissionDecisionReason")}}
    if event == "UserPromptSubmit" and value.get("decision") == "block" and isinstance(value.get("reason"), str):
        return {"decision": "block", "reason": value["reason"]}
    if isinstance(value.get("systemMessage"), str):
        return {"systemMessage": value["systemMessage"]}
    return {}


def run(input_stream, config, deadline):
    raw = input_stream.read((64 << 10) + 1)
    if len(raw) > 64 << 10:
        return {}
    payload = json.loads(raw)
    allowed = {"hook_event_name", "session_id", "tool_use_id", "tool_name"}
    if config.get("capture_content") is True:
        allowed |= {"cwd", "prompt", "tool_input", "tool_response", "error"}
    payload = {key: value for key, value in payload.items() if key in allowed}
    request = urllib.request.Request(config["hook_url"], json.dumps(payload).encode(), headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + config["token"],
        "X-OpenAIDR-Execution-Id": str(uuid.uuid4()),
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=max(0.01, deadline - time.monotonic())) as reply:
        body = reply.read((64 << 10) + 1)
        if reply.status != 200 or len(body) > 64 << 10 or time.monotonic() >= deadline:
            return {}
    return response(json.loads(body), payload.get("hook_event_name"))


def main():
    deadline = time.monotonic() + 2
    result = []

    def worker():
        try:
            config = json.loads(Path(__file__).with_name("connection.json").read_text())
            value = run(sys.stdin.buffer, config, deadline)
            if value:
                result.append(value)
        except Exception:
            pass

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(max(0, deadline - time.monotonic()))
    if not thread.is_alive() and result and time.monotonic() < deadline:
        print(json.dumps(result[0]), flush=True)


if __name__ == "__main__":
    main()
