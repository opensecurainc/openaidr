# Gateways dashboard

Deploy the gateway backend API before this dashboard increment. The API contract
is in `docs/gateway-api.md` at the repository root. The existing backend and
database serve this UI. No additional dashboard or backend container is required.

The Gateways navigation group contains:

- Overview: aggregate gateway heartbeat and request-stage counts for all roles,
  with the Instances table for IT admins and security analysts. IT admins can
  connect a gateway here. Instance links open node heartbeats, versions, reported
  routes, and the Routes, Settings, and Setup tabs.

Guardrail History is the main request history. Its Source filter defaults to All and
shows endpoint and gateway metric groups under one time-range control. Select
Gateways for policy decision rates, backend policy latency, policy availability,
and the request ledger with filters, pagination, and retained evidence. Overview
and instance View requests links select Gateways; instance links also select the
gateway. The source and initial gateway selection are stored in the URL.
Legacy `/gateways/requests` links redirect there and preserve `gateway_id`.
Individual `/gateways/requests/{id}` detail links remain valid and link back to
Guardrail History. Decisions evaluated by the backend, decisions returned to
plugins, and reported outcomes remain separate.

The former `/gateways/instances` list URL redirects to `/gateways/overview`.
Instance detail URLs remain unchanged and return to Overview. Creating a
connection refreshes the instance list and aggregate health counts. The list
and aggregate metrics retain independent refresh, loading, and error states.
This navigation change needs only a dashboard deployment, with no API or schema
change. Deploying the prior dashboard restores the separate Instances page.

Live Guardrail combines endpoint and gateway checks in one activity flow with
All, Endpoints and Gateways source filters. History uses the same source choices;
Evidence Search retains its source tabs. Gateway records use the shared request detail pages.
They do not create endpoint devices, endpoint sessions, or investigation reports. Gateway session detection and routed-model usage/cost consolidation are
not implemented by this increment. Null usage is displayed as unavailable.

IT admins create connections, edit connectivity, and create/rotate/revoke scoped
credentials. Security analysts manage gateway policy/capture settings and inspect
requests. Both roles can inspect instances. Security leadership can inspect only
the aggregate gateway overview. Existing shared-page access restrictions remain.
The backend enforces these permissions and tenant isolation independently.

Kong and LiteLLM share all connection, policy, request and activity views. Each
plugin has its own setup instructions. The LiteLLM setup explicitly reports that
live host-runtime validation has not been performed.

The Connect gateway dialog reads its plugin choices and labels from the same
`src/openaidr/core/gateway-plugins.json` registry as the backend. The kind is
immutable after creation. Shared node views use `gateway_version`, falling back
to `kong_version` for legacy Kong responses. Unsupported setup types show an
unavailable notice rather than instructions for a different gateway.

New connections start in Shadow with no selected static rules and content capture
off. The gateway mode does not change endpoint mode. Capture requires both backend
permission and the plugin's local opt-in. Only enabled allow/deny rules with nonempty
prompt-kind or matching gateway-product selectors are eligible. Literal policy
selectors and reasons are preserved. Provider/model labels are reported or requested identities,
not verified upstream routing. No request establishes local tool execution.

This pilot evaluates static rules only after a successful Guardrail content
assessment. Both capture permissions, complete supported content, configured
Guardrail model credentials, and a successful classifier response are required.
Metadata-only, redacted, truncated, unsupported, or failed assessments are
unavailable and fail open, including in Enforce with a selected deny rule.

Credential creation and rotation show the token once in component memory. Tokens
are not persisted in browser storage, URLs, or configuration examples. Leaving
the credential view clears the token. Setup examples use a Kong vault reference.
Rotation invalidates the prior credential immediately. Revocation stops
authenticated collection/checks, but the plugin still fails open for model traffic.

Report only observed route coverage. An idle gateway can have current heartbeats.
Missing latency, heartbeat, assessment, and usage data must not appear as zero or
healthy. A missing outcome is unconfirmed; fail open does not prove upstream
completion. Evidence is displayed exactly as returned by the server, including
its redactions and retained reasons.

## Validation

The focused Playwright suite mocks the canonical API boundary. It covers role
restrictions, credential lifecycle, optimistic settings conflicts, rule selection,
request filters and pagination, evidence preservation, source switching, and
populated desktop/narrow layouts using the real scroll containers.

Run the dashboard development server, then run:

```sh
OPENAIDR_DEMO_URL=http://127.0.0.1:3137 pnpm --filter openaidr-dashboard exec playwright test tests/gateways.spec.ts --browser chromium
OPENAIDR_DEMO_URL=http://127.0.0.1:3137 pnpm --filter openaidr-dashboard exec playwright test tests/gateways.spec.ts --browser webkit
pnpm --filter openaidr-dashboard typecheck
pnpm --filter openaidr-dashboard check:design
pnpm --filter openaidr-dashboard check:colors
```

Set `OPENAIDR_GATEWAY_SCREENSHOTS` to an absolute output directory to capture the
running UI during these tests. Fixtures stay in tests; production pages only use
API data. These browser tests do not replace backend authorization/integration
tests or the Kong deployment smoke test.

The [overview screenshot](../../../docs/images/gateway-overview.png) and
[request detail screenshot](../../../docs/images/gateway-request-detail.png)
show the running production build from source `9551df2`, using deterministic API
fixtures with motion disabled. The overview shows the leadership role, while the
request detail shows the analyst role. Neither image contains a credential. The [Connect gateway screenshot](../../../docs/images/gateway-connect.png)
shows the plugin selector in the running production build from source `f9f29ee`,
using synthetic API fixtures before any credential is created.

The [gateway history screenshot](../../../docs/images/gateway-request-history.png)
shows the running production build from source `a844d851`, using synthetic API
fixtures for an analyst. The Gateways navigation contains Overview and Instances;
request history appears under Guardrail History with the Gateways source selected.

The [integrated overview screenshot](../../../docs/images/gateway-overview-instances.png)
shows the running production build from source `b026e942`, using synthetic API
fixtures for an IT admin and security analyst. Instances appear below gateway
health, and Overview is the only page in the Gateways navigation group.

For rollout, deploy the backend receiver first, then dashboard and gateway plugins.
Verify a nonproduction connection in Shadow before selecting Enforce. To roll
back the UI, deploy the prior dashboard. Preserve the additive backend schema and
retained evidence; use credential revocation or disable the plugin to stop checks.

## History metrics

The Source filter controls one set of four charts: Decisions, Policy decision
rates, End-to-end latency, and Failure rate. All combines endpoint and gateway
samples; its Decisions chart shows one line per populated source. An empty source
appears as a compact notice. Not evaluated and Pending or unconfirmed counts
appear below Failure rate and do not imply success. Missing measurements remain
unavailable. The endpoint rule table and gateway request ledger remain below the
charts.

`view=unified` opts into a shared statistics response for the selected source.
It returns combined `totals` and `series`, per-source breakdowns in `sources`,
and the endpoint rule table. Counts and percentiles use underlying samples in
one snapshot; source percentages and percentiles are never averaged.
Omitting this parameter preserves the legacy response described below. The
dashboard reports unavailable statistics if the backend does not support the
unified response; it does not substitute the old failure or latency metrics.

The unified response uses **Failure rate**: `failed / attempted`, where attempted
counts confirmed successful or failed checks. A valid allow, ask, warn, or deny
is successful when delivery is confirmed. Backend evaluation errors, expired
checks, and confirmed delivery failures count as failures. Disabled capture,
unsupported content, and unavailable evidence are counted as `not_evaluated`.
Pending checks and missing delivery receipts are `unconfirmed` and excluded
from the failure denominator. Hook startup failures without a backend check
remain in the legacy runtime statistics; they cannot be correlated to these
check outcomes. Neither metric claims complete coverage of unreported attempts.

E2e percentiles use recorded durations for completed evaluated checks, excluding
failed delivery and missing timing. Endpoint reports retain their existing
hook-start-to-sensor-decision measurement, before local response delivery.
Gateway plugins measure callback start through decision validation, before model
execution. Backend-only policy latency and full model request duration are never
substituted for missing e2e samples. Gateway timings require updated plugins and
the receiver's `guardrail_metrics` capability. See the
receipt contract for rollout and rollback.

The legacy `GET /api/v1/guardrail/stats` response, with `view=sources` or no view,
accepts `source=endpoints|gateways|all` and
`range=1h|24h|7d|30d`. Omitting source preserves the endpoint response. A single
source returns its statistics with a `source` field. All returns
`{sources: {endpoints: ..., gateways: ...}}` with one database snapshot and
identical time buckets. The existing analyst permission and tenant scope apply.

Both decision rates count evaluated policy decisions, before Shadow changes the
returned action. Endpoint reports retain their legacy-record exclusion. Gateway
latency uses measured backend policy duration for evaluated checks, excluding
missing or invalid samples. It is separate from hook end-to-end latency and model
request duration. Gateway policy unavailable rate uses unavailable or expired
checks divided by evaluated, unavailable, and expired checks. Checks still pending
and pending records without a deadline are excluded. This does not measure
confirmed blocking, upstream completion, or unreported plugin failures. No data
remains unavailable; it is never displayed as a zero failure rate.

Charts include all gateways when Source is All or Gateways. Ledger filters, including `gateway_id`
in an instance link, scope only the ledger. Its time window follows the charts unless custom ledger times are supplied;
Clear filters restores the shared window. History refreshes when the source,
range, or Refresh control changes, so pagination stays stable while reading.
When statistics cannot load, the ledger remains accessible with its existing
24-hour default and independent time filters.

Deploy the unified stats API and migration 0128 before the dashboard, and update
gateway plugins to collect e2e timing. This dashboard change does not alter
enforcement. Roll back the dashboard before the API; the previous stats contract
and retained request records remain valid.

The [History source filter screenshot](../../../docs/images/guardrail-history-sources.png)
shows the metric layout in the running production build from source `8e74a9d`,
using deterministic API fixtures. It contains no customer data or credentials.

The [shared charts screenshot](../../../docs/images/guardrail-history-unified.png)
and [empty gateway screenshot](../../../docs/images/guardrail-history-empty-gateway.png)
show the running production build `2026.10.27+47c0725`, using synthetic API
fixtures. They demonstrate the combined metrics and compact empty-source notice
without customer data or credentials.
