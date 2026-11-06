# Data handling

[Back to the overview](../README.md)

What leaves a machine that runs OpenAIDR, what the dashboard server keeps, and
what the OpenSecura Intelligence service receives and retains. This page
describes the software's behavior; it is not a legal privacy policy.

## What the sensor collects

The sensor on each enrolled device collects coding agent activity through two
inputs, installed agent hooks and native OpenTelemetry exports, and sends it to
the OpenAIDR server the device is enrolled with. Retained fields depend on the
agent and on the capture controls below.

| Information | Hooks | Native OpenTelemetry |
| --- | --- | --- |
| User prompts | Prompt text | Length only by default; optional text for Claude Code |
| Assistant responses | Final message text | Off by default |
| Tool activity | Inputs, result text, commands, paths, URLs | Tool metadata and allowed detail fields |
| Session context | Session id, working directory, model, device, OS user | Session, service, host, model, account |
| Usage and cost | Not collected | Tokens, costs, timings, metrics |
| Policy decisions | Backend decision at supported hook boundaries | The agent's own decision records |

The sensor also reports device identity on enrollment and every heartbeat (the
hardware serial number and UUID, the OS installation id, and how they were
read), inventories of installed AI applications, MCP servers, plugins, and
skills, and configuration posture findings about agent settings files. Posture
checks report file paths and matching rule ids, never credential values.

## Controls before anything leaves the machine

| Setting | Default | Effect |
| --- | --- | --- |
| `capture.prompt_text` | on | Prompt text in hook and transcript events |
| `capture.response_text` | on | Response text in hook and transcript events |
| `capture.tool_input`, `capture.tool_output` | on | Tool inputs and outputs |
| `capture.max_text_bytes` | 16384 | Upper bound on retained text per field |
| `capture.redact` | on | Secret redaction before an event is queued |
| `telemetry.capture_prompts` | off | Prompt and response content in OpenTelemetry exports |
| `telemetry.capture_tool_details` | on | Tool argument and output fields in OpenTelemetry exports |

The server sends the tenant's capture settings at enrollment and on every
heartbeat. A device can disable a field locally but cannot enable one the
tenant disabled, and cannot turn redaction off when the tenant requires it.
Secret redaction uses the patterns in `packages/common` and runs on the device
before the event enters the delivery queue; the native receiver always applies
it and removes raw API bodies. Transcript collectors are opt-in. Fields that
capture disables are sent as metadata-only records, never as altered content.

## What the dashboard server keeps

The server you run stores the delivered events, inventories, posture findings,
guardrail decisions, usage and cost records, audit logs, and user accounts in
its PostgreSQL database. Retention is configured under **Administration >
Settings**. Nothing is sent to OpenSecura by the server unless an Intelligence
service connection is configured. New local workspaces configure a free
connection automatically; existing workspaces keep their configured connection.

## What the OpenSecura Intelligence service receives

With a connection configured, the server calls the Intelligence service for
model-backed capabilities: guardrail assessments of prompts, tool calls, and
results, detection investigations, URL reputation, package vulnerability
lookups, application research, skill assessment, and the Overview, session,
and assistant summaries. Each request carries the content the capability
needs, after the capture controls and redaction above have been applied, and
the workspace's tenant id. Free enrollment also sends random installation and
device IDs and an enrollment secret. The service stores a hash of the secret,
not its original value.

- Request contents are not stored by the service.
- Account and request metadata is retained for accounting and abuse monitoring:
  installation and device identity, the source IP address, timestamps, the
  capability called, and usage and cost records. Request content is excluded.
- Guardrails fail open. If the service is unreachable, slow, or out of
  allowance, the action is allowed and the app shows that guardrails are
  inactive. Native agent permissions and sandboxes still apply.

The free usage allowance and its caps are described in the
[open source plan](open-source-plan.md). A privacy policy from OpenSecura
will state the legal terms for the service; until it is published, this page
is the authoritative description of the software's behavior.
