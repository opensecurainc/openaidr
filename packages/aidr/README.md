# aidr

Python SDK for the [OpenSecura](https://opensecura.ai/) API. Check npm and PyPI
dependencies for known vulnerabilities and assess AI agent actions with guardrails.
Detection and investigation methods are deferred.

This checkout prepares version 0.1.0. Until it is published, PyPI still provides
the 0.0.1 placeholder. Install this implementation from the repository root:

```sh
python -m pip install ./packages/aidr
```

Python 3.11 or later is required. The SDK does not require the desktop app,
sensor, database, or local server.

## Usage

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
Do not edit generated vendor files.

Private namespaces avoid collisions with installed OpenAIDR clients. Public PyPI
dependencies are HTTPX, AnyIO, Pydantic, PyYAML, and tzdata on Windows. No private
package index or separate SDK wheel is needed at installation time.

From the repository root, with test and build tools installed:

```sh
python -m pip install -e ./packages/aidr
python -m pytest -q packages/aidr/tests
python -m build packages/aidr
```

Tests use simulated HTTP responses. They do not consume service credits.
