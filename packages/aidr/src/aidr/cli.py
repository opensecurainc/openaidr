"""Standalone credential management and advisory security checks."""

import argparse
from datetime import date, datetime
import getpass
import json
import math
from pathlib import Path
import sys
from uuid import UUID, uuid4
import warnings

import httpx

from . import __version__, credentials
from .client import AIDR, GuardrailError, Unavailable
from ._vendor.openaidr_api_client.contracts.service_guardrail import (
    MAX_EVENT_BYTES, MAX_PROMPT_CHARACTERS,
)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: invalid arguments; use --help.\n")


def _json_default(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError("Unsupported result value")


def main(argv=None) -> int:
    parser = _Parser(prog="aidr", description="OpenSecura dependency scans and advisory guardrail assessments.")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", type=Path, help="Path to aidr credentials")
    commands = parser.add_subparsers(dest="action")
    enroll = commands.add_parser("enroll", help="Enroll for free service access")
    enroll.add_argument("--free", action="store_true", required=True)
    login = commands.add_parser("login", help="Save an API key after verifying it")
    login.add_argument("--api-key-stdin", action="store_true", help="Read the API key from standard input")
    for command in (enroll, login):
        command.add_argument("--base-url", default=credentials.ORIGIN, help="Exact HTTPS service origin")
        command.add_argument("--ca-file", default="", help="PEM trust bundle")
    commands.add_parser("status", help="Show the saved connection and service status")
    commands.add_parser("logout", help="Remove active credentials and retain the free enrollment identity")
    scan = commands.add_parser("scan", help="Check one exact dependency version")
    scan.add_argument("--ecosystem", required=True, choices=("npm", "pypi"))
    scan.add_argument("--package", required=True)
    scan.add_argument("--version", required=True)
    guardrail = commands.add_parser("guardrail", help="Assess a command without executing it")
    guardrail.add_argument("--command", required=True)
    guardrail.add_argument("--policy", default="")
    guardrail.add_argument("--timeout", type=float)
    guardrail.add_argument("--max-credits")
    for command in (scan, guardrail):
        command.add_argument("--request-id", help="Canonical UUID; reuse only with identical input")
    args = parser.parse_args(argv)
    if args.action is None:
        parser.print_help()
        return 0

    try:
        path = args.config if args.config is not None else credentials.default_path()
        if args.action == "enroll":
            result = credentials.enroll_free(path, base_url=args.base_url, ca_file=args.ca_file)
        elif args.action == "login":
            if args.api_key_stdin:
                api_key = sys.stdin.readline(4096).strip()
            elif sys.stdin.isatty():
                with warnings.catch_warnings():
                    warnings.simplefilter("error", getpass.GetPassWarning)
                    api_key = getpass.getpass("API key: ")
            else:
                print("aidr: Use --api-key-stdin when input is not a terminal.", file=sys.stderr)
                return 2
            result = credentials.login(path, api_key, base_url=args.base_url, ca_file=args.ca_file)
        elif args.action == "status":
            result = credentials.status(path)
            if not result["authenticated"]:
                print("Run aidr enroll --free or aidr login first.", file=sys.stderr)
        elif args.action == "logout":
            result = credentials.logout(path)
        else:
            request_id = args.request_id if args.request_id is not None else str(uuid4())
            if str(UUID(request_id)) != request_id:
                raise ValueError("Invalid request ID")
            if args.action == "guardrail":
                if args.timeout is not None and (not math.isfinite(args.timeout) or args.timeout < .001):
                    raise ValueError("Invalid timeout")
                event = {"kind": "command", "command": {"text": args.command}}
                if (not args.command.strip() or len(args.policy) > MAX_PROMPT_CHARACTERS
                        or len(json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode()) > MAX_EVENT_BYTES):
                    raise ValueError("Invalid guardrail input")
                state = {"target_event": event, "latest_prompt": None,
                         "prior_events": [], "context_limited": True}
            connection = credentials.load_connection(path)
            with AIDR(api_key=connection.api_key, tenant_id=connection.tenant_id,
                      base_url=connection.origin, ca_file=connection.ca_file) as client:
                print(f"Request ID: {request_id}", file=sys.stderr, flush=True)
                if args.action == "scan":
                    result = client.scan_dependencies(
                        [{"ecosystem": args.ecosystem, "name": args.package, "version": args.version}],
                        request_id=request_id,
                    )
                else:
                    result = client.assess_guardrail(state, request_id=request_id,
                        company_policy=args.policy, timeout=args.timeout, max_credits=args.max_credits)
        print(json.dumps(result, default=_json_default, indent=2, sort_keys=True, allow_nan=False))
        return 0
    except (GuardrailError, Unavailable, httpx.HTTPError, TimeoutError):
        print("aidr: Request failed. Check credentials and service availability. "
              "Retry only with the same request ID and identical input.", file=sys.stderr)
        return 1
    except getpass.GetPassWarning:
        print("aidr: Hidden terminal input is unavailable. Use --api-key-stdin.", file=sys.stderr)
        return 2
    except credentials.CredentialError as error:
        print(f"aidr: {error}", file=sys.stderr)
        return 2
    except (ValueError, OSError, EOFError):
        print("aidr: Invalid input or credential configuration. Check the arguments and saved connection.", file=sys.stderr)
        return 2
