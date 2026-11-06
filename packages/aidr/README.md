# aidr

Command line and Python SDK for [OpenSecura](https://opensecura.ai/). Enroll for
free, save credentials, check npm and PyPI dependencies for known vulnerabilities,
and assess AI agent actions with guardrails. Detection and investigation methods
are deferred.

Install from PyPI:

```sh
python -m pip install aidr
```

Python 3.11 or later is required. The CLI and SDK do not require the desktop app,
sensor, database, or local server.

## Command line

Start without an account or API key:

```sh
aidr enroll --free
aidr status
aidr scan --ecosystem npm --package lodash --version 4.17.20
aidr scan --ecosystem pypi --package requests --version 2.31.0
aidr guardrail --command 'git status'
```

Enrollment saves a local installation identity before contacting the service.
Repeating `aidr enroll --free` recovers the same identity after an interrupted
request. Commands use the saved credentials without an API key or tenant ID on
the command line. The connected service controls the free allowance and available
capabilities; scans and assessments can consume service credits.

To use an API key, run `aidr login` and enter it at the hidden prompt. The CLI
discovers the tenant and verifies the connection before saving it. Automation can
pipe a key into `aidr login --api-key-stdin`. `aidr logout` removes the active
connection while retaining the free installation identity for later recovery.
Logout does not revoke an API key at the service.

Credentials are stored separately from the desktop app. On macOS the default
file is `~/Library/Application Support/aidr/credentials.json`; on Linux it is
`$XDG_CONFIG_HOME/aidr/credentials.json` or `~/.config/aidr/credentials.json`.
On Windows it is `%APPDATA%\aidr\credentials.json`.
Use `aidr --config /path/to/credentials.json` before the subcommand to select
another file. Credential files contain secrets and must not be shared or
committed. On POSIX systems the directory and file are restricted to their owner.
An existing directory selected with `--config` must also be private.

`enroll` and `login` accept `--base-url` for an exact HTTPS origin and `--ca-file`
for a PEM trust bundle. The saved origin is used by later commands. Credentials
are never sent through redirects or environment-configured HTTP proxies.

Scan one explicit package version per command. Guardrail commands assess the
supplied command text without executing it or installing agent hooks:

```sh
aidr guardrail --command 'git status' --policy 'Do not expose secrets.' --timeout 5
```

Results are JSON on stdout. Each scan or guardrail call prints its request ID to
stderr before sending the request. After an uncertain outcome, pass that ID with
`--request-id` and the exact same inputs to retry. The CLI does not retry calls
automatically. Request failures produce a nonzero exit code; successful advisory
results are not an allow or deny decision. Use `aidr COMMAND --help` for options.

## Python SDK

Use an OpenSecura API key and its assigned tenant UUID. The tenant UUID is
returned by `GET /v1/capabilities` for an assigned key. SDK construction does
not enroll a device or assign a key to a new tenant.

```python
import os
from uuid import uuid4

from aidr import AIDR

packages = [
    {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"},
    {"ecosystem": "pypi", "name": "requests", "version": "2.31.0"},
]
state = {
    "target_event": {"kind": "command", "command": {"text": "git status"}},
    "latest_prompt": {"kind": "prompt", "text": "Check the repository status."},
    "prior_events": [],
    "context_limited": True,
}

# Persist each ID and its exact input before calling if you need recovery.
scan_id, guardrail_id = str(uuid4()), str(uuid4())

with AIDR(
    api_key=os.environ["OPENSECURA_API_KEY"],
    tenant_id=os.environ["OPENSECURA_TENANT_ID"],
) as client:
    scan = client.scan_dependencies(packages, request_id=scan_id)
    for result in scan["results"]:
        print(result["query"], result["status"], result["findings"])

    assessment = client.assess_guardrail(
        state,
        request_id=guardrail_id,
        company_policy="Do not expose secrets or delete user data.",
        timeout=5,
    )
    print(assessment["status"], assessment["score"], assessment["category"])
```

`AsyncAIDR` accepts the same arguments and methods. Use `async with` and await
each call. Explicit cleanup is available through `AIDR.close()` and
`AsyncAIDR.aclose()`; both can be called more than once.

```python
from aidr import AsyncAIDR

async def scan_packages(api_key, tenant_id, packages, request_id):
    async with AsyncAIDR(api_key=api_key, tenant_id=tenant_id) as client:
        return await client.scan_dependencies(packages, request_id=request_id)
```

## API behavior

| Method | API route | Result |
| --- | --- | --- |
| `scan_dependencies` | `POST /v1/services/packages/check` | Package results and a billing receipt |
| `assess_guardrail` | `POST /v1/services/guardrail/assess` | Advisory risk assessment and a billing receipt |

Dependency scans accept 1 to 25 explicit package identities per request. Only
exact npm and supported PyPI versions are accepted. Resolve dependencies and
split larger inventories into batches before calling. The SDK does not parse
lockfiles, resolve version ranges, or discover transitive dependencies.

Each package has a `complete` or `unavailable` status. An unavailable result is
not a clean scan. Findings preserve vulnerability IDs, aliases, severity,
fixed versions, and source links. Successful `checked_at` and `expires_at`
values are timezone-aware Python datetimes. Both methods return dictionaries.

Guardrail state uses the existing API evidence format: a `target_event`, optional
`latest_prompt`, `prior_events`, and `context_limited`. Supported event kinds
include prompts, responses, tool calls and results, commands, file reads and
writes, and network actions. Evidence is sent as supplied; redact content
before calling when needed. The service limits state to 24,000 UTF-8 bytes and
individual events to 8,000 bytes.

A scored guardrail returns `score` (0 to 100), `level`, `category`, and confidence
values. An unscored result has no score or level. The SDK does not turn either
result into an allow or deny decision. Your application owns that policy and
its behavior when a check is unavailable. `timeout` is capped at 10 seconds.
The optional `max_credits` argument is an exact decimal string such as `"1"`.

Every call requires a canonical UUID string as `request_id`. Use a different ID
for each logical operation. After an uncertain outcome, reuse the saved ID and
identical inputs, including timeout and policy, when retrying. Calls do not retry
automatically. Service billing follows the connected API's configuration.

Invalid package inputs raise `ValueError` (including Pydantic validation errors).
Failed scans raise `aidr.ScanError`, which retains a validated `billing` receipt
when available, plus HTTP `status_code`, `retry_after`, and `error_code` when
provided. Failed guardrail assessments raise the existing `aidr.GuardrailError`
with `code`, `retryable`, `retry_after`, and any validated `billing` receipt.
Neither failure is returned as a successful assessment.

The default origin is `https://api.opensecura.ai`. Set `base_url` to another exact
HTTPS origin and optionally set `ca_file` for a PEM trust bundle. Credentials
are tenant-bound; redirects and environment proxy settings are disabled.

The reused client sends content-free latency reports only when the API advertises
support. Set `OPENAIDR_SDK_LATENCY=false` before creating a client to disable them.

## Development and code reuse

`setup.py` verifies the SDK wheel checksum recorded in
`dependencies/api-runtime/manifest.json`, then generates `aidr._vendor` from that
wheel and `packages/common/src/openaidr_common`. Only absolute import paths are
rewritten. HTTP transport, wire contracts, validation, and accounting remain the
existing implementations. Generated files are ignored by Git and included in
both the wheel and source distribution, with provenance and license files.
Do not edit generated vendor files. Repository builds require the manifest;
source distributions include the generated files and build independently.

Private namespaces avoid collisions with installed OpenAIDR clients. Public PyPI
dependencies are HTTPX, AnyIO, Pydantic, PyYAML, and tzdata on Windows. No private
package index or separate SDK wheel is needed at installation time.

From the repository root, with test and build tools installed:

```sh
python -m pip install -e ./packages/aidr
python -m pytest -q packages/aidr/tests
python -m build packages/aidr
```

Packaging tests build from a copy without generated files, rebuild the source
distribution independently, and test the installed wheel. Tests use simulated
HTTP responses. They do not consume service credits.
