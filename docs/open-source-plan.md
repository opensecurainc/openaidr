# Open source plan

[Back to the overview](../README.md)

OpenAIDR open-sources the client and runs the decisions as a service. The
sensor and agent hooks, the desktop app, the dashboard, and an SDK that calls
the OpenSecura API are published under Apache 2.0. Detection and model-backed
guardrail decisions come from the OpenSecura API, with a free usage allowance
for every install and no keys to configure.

This page describes where the project is going and what is already here.

## What is public and what runs behind the API

The boundary is the API gateway. Everything on the endpoint and in the
dashboard is public. Model execution and provider prompts run behind the API.
Local rule-based detection and the policy matcher remain public.

```
Public repository (Apache-2.0)            OpenSecura API

  Sensor and agent hooks  ──┐
  Desktop app             ──┤   HTTPS    ┌─ API gateway ─────────────┐
  Dashboard               ──┼──────────▶ │ auth, usage allowance,    │
  OpenAIDR SDK            ──┘            │ rate limits               │
                                         └──┬────────────────────────┘
                                            ├─▶ Decision and detection models
                                            ├─▶ Language models
                                            └─▶ Threat intelligence
```

Public:

- Sensor and agent hooks, which collect AI app and agent activity.
- Desktop app: the Tauri app and the endpoint guardrail.
- Dashboard: inventory, posture, guardrails, detections, and costs.
- Local detection rules and policy evaluation.
- OpenAIDR SDK source: the typed API client, contracts, and response validation.
- The API contract.

Behind the API:

- Decision and detection models that produce guardrail verdicts and
  detections.
- Language models used for investigation and summaries.
- Threat intelligence feeds.
- The multi-tenant cloud and the centralized management of many installs,
  which are part of the paid offering.

## Free usage allowance

- New local workspaces enroll with a persisted random device and installation ID, with
  no sign-up. The initial allowance is 200 customer credits per UTC calendar
  week, resetting Monday at 00:00 UTC. Customer credit rates and allowances
  are configured separately from provider costs. The operator can adjust
  them without a client release; the app displays the allowance and reset
  period returned by the connected API.
- The random device ID is saved in the local user profile and reused by setup.
  It does not contain or derive from a hardware identifier.
- Provider calls reserve credit before execution. Confirmed usage settles once;
  missing receipts retain their reservation until reconciled. Late receipts apply
  to the period in which the call was admitted.
- The allowance is capped per install and the number of device IDs per IP
  address is capped at five by default, with one IPv6 /64 treated as one address.
  Offices behind shared NAT or VPN addresses can reach this cap.
- Usage above the allowance needs a paid key. The app shows and notifies you
  when the cap is reached.
- The API applies rate limits and abuse monitoring.

## Privacy

- The hosted API must provide zero data retention for request content. Local
  client storage may retain activity, evidence, and investigation results.
- Request metadata, including the IP address and installation
  ID, is retained for accounting and abuse monitoring.
- A privacy policy will state what leaves the machine and what OpenSecura
  keeps.

## Availability

Guardrails fail open. When the API is unreachable or the allowance is used up,
actions are allowed, and the app shows and notifies you that guardrails are
inactive. Native agent permissions and sandboxes still apply.

## What this repository is

This repository is the complete client, published from OpenSecura's
development repository. `PUBLICATION.json` records the source commit. The
earlier feature-reduced export and its `SOURCE.json` provenance are retired.

Decisions recorded with this publication:

- The cloud control plane (multi-tenant deployments, provisioning, release
  operations, platform identity and email) is a separate private package that
  the published server loads only when cloud management is enabled; it is not
  in this repository.
- The SDK that calls the Intelligence service is published whole, as the
  vendored wheels under `dependencies/api-runtime/`.
- Internal model identifiers that remain in server code are mapped to
  "Guardrail" wherever the dashboard displays them; stored values keep their
  names so history stays readable.
- Shared SQL migrations and API types remain public for database and client
  compatibility. Platform account/session operations and cross-tenant admin
  queries live in the private package. Its retained provider settings are
  private too; public service calls use the customer SDK and service receipts.
- Public dependency manifests contain only the distributed SDK/common wheels,
  checksums, and source identities. Private promotion and service-wheel records
  stay in the internal build system.
- [Data handling](data-handling.md) states what leaves the machine and what
  the service keeps.

The source implements free enrollment, accounting, and desktop notices. Before
public launch, deploy the API ZDR and free-tier releases, verify provider-side
retention settings, publish the privacy policy, and publish a complete client
release. Historical reduced releases are rejected by the quick-start installer.
