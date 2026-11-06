"""Small Windows hook client. Policy and agent capability checks stay in the sensor."""

import argparse
from http.client import HTTPConnection
import ipaddress
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import urlencode, urlsplit

from openaidr.core.protocol import AGENT_HOOK_TIMEOUT_SECONDS, AGENT_HOOK_TIMEOUTS_NS
from openaidr.core.hook_protocol import PRODUCTS, ROUTES
from .config import Config


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def main(argv, *, started_ns):
    """Return failures only to the quiet launcher, never print diagnostics."""
    try:
        parser = Parser(add_help=False)
        parser.add_argument("event")
        parser.add_argument("--agent", choices=tuple(PRODUCTS), default="claude")
        parser.add_argument("--config")
        args = parser.parse_args(argv)
        if args.agent in ("claude", "codex") and os.environ.get("OPENAIDR_MANAGED_BRIDGE"):
            from openaidr.guardrail.hook_bridge import denied, forward_if_managed

            while sys.stdin.buffer.read(64 << 10):
                pass
            reply = forward_if_managed(args.agent, args.event, {})
            print(json.dumps(reply if reply is not None else denied(args.event)), flush=True)
            return 0

        config = Config.load(args.config or os.environ.get("OPENAIDR_SENSOR_CONFIG"))
        started_ns = int(os.environ.get("OPENAIDR_HOOK_STARTED_NS", started_ns))
        deadline_ns = int(os.environ.get(
            "OPENAIDR_HOOK_DEADLINE_NS", started_ns + AGENT_HOOK_TIMEOUT_SECONDS * 1_000_000_000,
        ))
        if (deadline_ns - started_ns not in AGENT_HOOK_TIMEOUTS_NS
                or time.time_ns() >= deadline_ns):
            raise ValueError("invalid or expired hook deadline")
        body = sys.stdin.buffer.read((4 << 20) + 1)
        if len(body) > 4 << 20:
            raise ValueError("hook input too large")
        address = urlsplit("http://" + config["listen"])
        if (not ipaddress.ip_address(address.hostname).is_loopback or address.username
                or address.password or address.path or address.query or address.fragment):
            raise ValueError("loopback listener required")
        query = dict(event=args.event, started=started_ns, deadline=deadline_ns,
                     execution=os.environ.get("OPENAIDR_HOOK_EXECUTION_ID", ""),
                     timeout_owner="agent", client_pid=os.getpid())
        if args.event == "PreToolUse":
            query["path_home"] = str(Path.home())
        headers = {"Content-Type": "application/json"}
        token = (config.get("telemetry") or {}).get("local_token")
        if token:
            headers["Authorization"] = "Bearer " + token
        route = ROUTES[PRODUCTS[args.agent]]
        # The native agent owns cancellation. No proxy, redirects, retries, or
        # second relative timeout may consume or extend its original deadline.
        connection = HTTPConnection(address.hostname, address.port, timeout=None)
        try:
            connection.request("POST", f"{route}?{urlencode(query)}", body, headers)
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError("hook request failed")
            content = response.read((4 << 20) + 1)
            if len(content) > 4 << 20:
                raise ValueError("hook response too large")
            reply = json.loads(content)
        finally:
            connection.close()
        if not isinstance(reply, dict) or reply.get("failed") or time.time_ns() >= deadline_ns:
            raise ValueError("hook response unavailable")
        output = reply.get("output", reply.get("claude_code", {}))
        if not isinstance(output, dict):
            raise ValueError("invalid hook response")
        if output:
            print(json.dumps(output), flush=True)
        return 0
    except Exception:
        return 1 if os.environ.get("OPENAIDR_HOOK_WRAPPED") == "1" else 0
