# OpenAIDR dashboard

The shared version naming policy defines
`YYYY.M.D+<commit>` for the dashboard, app, sensor, and backend. Build support is
pending; the dashboard currently displays its build time and commit separately.

A standalone Next.js App Router frontend for the authenticated OpenAIDR API.
It provides 20 navigation pages across Overview, AI Asset Management, Detection
and Response, Real-time Guardrail, Cost Management, and Administration,
plus session detail, enrollment, invitation, registration,
and approval routes. Views use API data without a browser-generated demo
dataset. Cost views distinguish reported costs, priced estimates, and unpriced
usage. Exports marked `demo` by the backend receive a **Synthetic** badge.

The application uses Next.js 16, React 19, Tailwind CSS 4, Recharts 3, Lucide, and locally owned shadcn/ui components built on Radix. The root `pnpm-lock.yaml` pins the tested dependency graph. The interface uses Geist and Geist Mono, the shadcn/ui defaults, bundled from the pinned `geist` package by `next/font`; builds and page rendering do not fetch fonts or runtime assets from a CDN.

The OpenSecura mark and palette come from the `brand/` git submodule at the repository root (opensecurainc/brand). `scripts/sync-brand.mjs` runs before `next dev` and `next build`: it copies the mark into `public/icon.svg` and `public/icon-dark.svg` and generates `src/app/brand.css` with `--brand-*` custom properties from the palette constants in `brand.py`, and it copies the Geist font license to `public/fonts/Geist-OFL.txt` plus the shared Geist font files and CSS for static previews. All dashboard pages and previews use Geist Sans for interface text and Geist Mono for technical content. Those files are generated and ignored by git. To pick up a brand change, update the submodule and commit the new pointer.

## Shared page design

Open [preview.htm](preview.htm) in a browser for the approved OpenSecura palette and a comparison with the previous colors. It is a self-contained offline design reference with illustrative data, embedded fonts and marks, and a [palette.json](palette.json) download. The application uses the shared tokens in `src/app/globals.css`; the color check keeps the downloadable palette aligned with them.

[DESIGN.md](DESIGN.md) defines the shared page layouts, typography, spacing, tables, forms, states, and accessibility requirements. Its [chart standard](DESIGN.md#charts) is mandatory across the dashboard, including the line/area visual reference and review checklist; [COLORS.md](COLORS.md#data) defines the chart palette and permitted fills. New pages register their title, description, route, and category in `src/lib/navigation.ts`, then compose the shared components in `src/components/page-layout.tsx`. The shell provides the page title and breadcrumb, grouped desktop navigation, and the same navigation in a mobile drawer.

The Overview's **Live activity** card is a master-detail view that fits one viewport (see DESIGN.md, Activity views). On the left, sessions are grouped by device; each device header shows the sensor's reported status and session count, and each session row shows the agent, its state (Active within five minutes, Idle, or Ended), its latest prompt, its last activity, and its event count. A session keeps its row and latest prompt after its events leave the 300-event live window, until it has been inactive for one hour; on a fresh load, a session with no prompt in the window asks for its newest collector prompt (`GET /api/v1/events?kind=prompt&session_id=…&source=collector&limit=1`). Sessions with no event in the window since the page loaded appear when they next have activity. On the right is the selected session's timeline (the most recently active by default, kept in `?session=`): its header names the agent, state, user and host, and working directory, with counts of events, accepted policy checks, and merged native records, and legend chips select which categories show. The timeline is grouped into turns headed by each prompt. Every other event is one line: a dot in its category color, the time, the category and tool, and a one-line summary (the first line of a command with a "+N lines" count, or a description such as "PNG image, 18 KB" for binary output), followed by the call's duration, a failure or nonzero exit code, a denied or warned decision, and a risk badge only at Low and above. A tool result is folded into its call. Clicking a row expands it in place to its input and output (12 lines, then "Show all", with copy), its assessments, and **View details**, which opens the event dialog. Below `lg` the session list comes first and a session opens its timeline with a back control. Each pane scrolls on its own and the timeline follows new activity unless you scroll up. The panel polls `GET /api/v1/events/live` every second while the page is visible, asks only for events that arrived after the last cursor, and highlights new rows briefly. Legend chips select categories: with none selected every category shows, pressing chips shows only the selected ones, a tool call stays visible while its attached result's category is selected, and **Show all kinds** clears the selection; the chips keep their positions. Sessions are keyed by the agent's own session id on a sensor, so a session reported both by a hook or transcript collector and by native telemetry is one session in the list. In such a session the collector events carry the content, whichever arrived first: the native record of the same tool call (matched by call id) is attached to that call and supplies the agent's duration and outcome, native prompt records, which carry only a length, are counted in the header ("native records merged") rather than drawn, and a tool result rides on its call. Accepted sensor policy checks are counted in the header instead of taking a row each; a native agent permission decision (OTLP `tool_decision`) is not a policy check, so it keeps its own row labeled "Agent permission" with the agent's reported value. The sensor's own lifecycle events are not sessions. Polling pauses while the tab is hidden or **Pause** is pressed and resumes from the same cursor, so nothing that arrived meanwhile is skipped; a failed poll keeps the rows on screen with a visible warning and keeps retrying. Rows show the stored content (prompt text, command, tool output) for events whose collector kept it, and a length-only note for native telemetry prompts, which never carry text. App Health uses native telemetry overview snapshots. AI Inventory uses reported software installations, classification evidence, and organization approvals. Evidence Search queries retained agent events and opens telemetry payloads from linked events. Other data-backed views use existing tenant APIs for findings, policy, users, service heartbeats, enrollment, and audit records. Reported-user finding details list each evidence event with a source badge (**Native telemetry** for events derived from OTLP exports, **Collector** for legacy collector events) and its action summary (command, file path, URL, or tool name). An event that carries an `export` reference offers **Open telemetry record**, which opens the stored export in the same **Export evidence** dialog and marks the exact record (`export.record`, an index into the export's flattened records) with a left accent bar and a **Matched record** badge, scrolling it into view even when it lies beyond the 250-row table cap. Enrollment provides credential creation/revocation controls. Users and Roles provides user invitations; existing user roles and general settings are read-only. Audit and enrollment require an owner or administrator.

Enrollment links default to a 1-hour expiration, with 24-hour and 7-day options.
The label is optional. When it is blank, the dashboard generates
`YYYYMMDDHHmm_rollout` using the administrator's local time at submission.

Supply-chain inventory lists npm packages, Python packages, configured MCP servers,
and declared plugins. Skills inventory lists installed skill metadata and declared
tools. `/ai-skills` uses the preview overview, table, tool matrix and detail drawer
with tenant records. Counts cover loaded pages, and unavailable coverage and agent
usage remain unknown; empty or failed collection never falls back
to sample data. The separate `/ai-skills/preview` route remains a labeled design
preview with illustrative data. Both inventory pages use the component inventory API
and show scan coverage, retained records, and missing metadata explicitly.
AI Inventory reads `inventory/application-review`. A summary strip leads into
Approved, Unapproved, and Monitoring columns, followed by the ranked All installed
software table. Search, category, and endpoint-user filters scope the software
table; the review cards retain organization scope. Device and user counts open
their respective lists. The Report column and application names open risk evidence,
classification sources, approval actions, and installation details; approval
actions retain organization scope. Counts represent installations and
reported usernames, not observed usage or verified people. See
application review for behavior and rollout.
Supply Chain and Skills retain the four summary cards and component metadata
workflows described in inventory restoration.
Unavailable approval and risk assessments stay explicitly unavailable, not zero.
AI Agent Costs reports request usage from native telemetry.
Credits & Usage at `/costs/openaidr` reports the API service's credit balance,
reservations, and usage by feature. `$1 = 100 credits`; amounts retain up to six
fractional places. The 24h, 30d, and 90d views use `GET /api/v1/credits`, with
explicit disabled, unconfigured, unavailable, and exhausted states. Pausing new
charging preserves recorded customer credit charges; unavailable balances remain
null. Prior model costs are not converted to credit charges. Deploy the backend credit endpoint
and customer-safe settings/detail projections before this dashboard. The legacy
`/costs/detections` bookmark redirects to the credit page. A backend without the
credit endpoint shows unavailable data, with no provider-cost fallback. Rollback
to a provider-cost dashboard can expose historical private accounting and must
not be used after the customer privacy cutover. No purchasing or automatic reload
controls are offered until those operations are supported. Native AI Agent Costs
and captured action evidence retain the customer's original model information.
Risky Sessions/Users shows
top observed sessions and reported users, including activity below the
investigation threshold. Both activity and case lists compare scores with the
current configured high-risk action threshold, so a setting of 70 displays
`89 / 70` for a score of 89. Missing or inapplicable thresholds display `N/A`.
Deploy the API's additive threshold metadata before or with this dashboard;
older responses remain usable without inventing a threshold. The threshold metadata needs no migration, and rollback does not change detection settings or case history.
The Cases view retains daily outcome charts, saved
analyst verdicts, report previews, and HTML downloads. Top activity reads saved
rankings refreshed every 15 minutes, with an update timestamp and explicit
preparation and stale-result states. Search and paging use the saved population;
Refresh reloads its latest version. Case outcomes remain current.
Unused snapshots stop refreshing after 30 minutes and are removed after 24 hours.
Each tenant has at most 16 time-zone snapshots; new zones reuse idle slots, or
return a capacity error when all slots are active.
Deploy migration 0124 and the API snapshot worker with this dashboard change.
Activity rankings do not open cases. Session descriptions use the separate,
bounded summary worker described below. Its collapsed Policy
findings and user totals section preserves the complete finding totals used by
Overview. Deploy backend risk-case support and migration 0099 before this UI,
and the `view=activity` API extension before enabling Top activity.
See the case API for lifecycle and rollback details.

The running dashboard below uses illustrative browser-test data and a configured
threshold of 70.

![Risk lists use the configured detection threshold](../../docs/images/risk-configured-threshold.png)

Session activity rows whose measured peak is at or above the current configured
threshold show an amber score, a row accent, and **Threshold reached**. Below-threshold
and unscored sessions, and sessions with an unavailable or legacy threshold, keep
their neutral display. This comparison updates with the settings returned on
refresh and is independent of case creation and analyst verdicts. Deploy or roll
back the dashboard alone; no API or migration change is needed.
[Threshold highlights with synthetic browser-test data](../../docs/images/risk-threshold-highlight.png).

Session rows also show a short **AI summary** of captured work below the agent
title, with the session ID retained as secondary metadata. The summary describes
the activity, independently of scores and investigation reports. It is based on
a bounded sample of retained prompts and actions, so it does not establish complete
coverage or successful execution. Its tooltip gives the evidence cutoff.
The existing 15-second activity poll loads completed summaries; pending work shows
**Summarizing captured activity…**, and missing evidence, missing model configuration,
or failed generation shows **Summary unavailable**. Older APIs also show this fallback.
Deploy migration 0126 and the API summary worker before or with the dashboard.
Revert the dashboard and worker to roll back; the additive cache table can remain.
See summary generation and limits.
[Session summaries with synthetic browser-test data](../../docs/images/session-activity-summary.png).

Security Posture is temporarily hidden from desktop and mobile navigation until
it can show effective enforcement mode and verified coverage. Existing
`/security-posture` links still show prevention policy with explicit coverage
limitations; policy configuration remains under Company Policy and Knowledge.
Detection Rules, after Evidence Search under Detection and
Response, lists configured rules and 30-day finding counts with a notice that
configuration does not establish coverage. Integrations documents supported
sources without claiming they are connected.

Guardrail Benchmarks and Detection Quality are private engineering evaluations in
[`openaidr-api`](https://github.com/opensecurainc/openaidr-api/tree/main/benchmarks).
Their dashboard pages and tenant execution endpoints are removed. See
rollout and retained history.

Live Guardrail shows completed backend checks and Guardrail assessments.
Guardrail History uses All, Endpoints, and Gateways source filters for one set of
four charts: decisions, policy decision rates, end-to-end latency, and failure
rate. All combines recorded checks and shows an empty source as a short notice.
The gateway request ledger remains below the charts. See
[History metrics](docs/gateways.md#history-metrics). Endpoint counts exclude native agent permissions and historical
managed approvals. Session detail pages show managed records only when a
registration exists; an approval does not prove execution. Registration and
approval pages remain available for older running clients during the
managed-session phaseout.

App Health uses `/administration/app`. Existing `/administration/sensors` and
`/devices` links redirect there; `/telemetry` redirects to `/evidence`.
Existing `/costs/detections` links redirect to `/costs/openaidr`.

## Build and run

Use Node 22.12+ and pnpm 9.15.9, pinned by `packageManager` in the root
`package.json`. Run from the repository root:

```sh
git submodule update --init
corepack enable
pnpm install --frozen-lockfile
NEXT_TELEMETRY_DISABLED=1 pnpm --filter openaidr-dashboard build
HOSTNAME=0.0.0.0 PORT=3000 pnpm --filter openaidr-dashboard start
```

Use the dashboard filter explicitly. The root `pnpm build` command builds the
Vite console and admin apps for Python packaging, not this Next.js service.

`next.config.ts` produces `output: 'standalone'` with the repository as its tracing
root. `apps/dashboard/.next/standalone/` contains shared dependencies and the
nested entry `apps/dashboard/server.js`. The build script stages `public/` and
`.next/static/` under that nested `apps/dashboard/` directory. For a minimal
container, copy the entire standalone tree and start from its copied root:

```sh
HOSTNAME=0.0.0.0 PORT=3000 node apps/dashboard/server.js
```

`GET /healthz` returns HTTP 200 with `{"status":"ok","service":"dashboard"}`. This only checks the frontend process; authenticated API fetches report backend connectivity separately.

Production ingress should route `/api/*`, `/ingest/*`, `/otlp/*`, and the exact
paths `/mcp`, `/authorize`, `/token`, `/revoke`,
`/.well-known/oauth-authorization-server`, and
`/.well-known/oauth-protected-resource/mcp` to Python. Keep frontend routes and
assets on this service, including `/mcp/authorize/*`, `/mcp/access`, and
`/mcp/changes/*`. A blanket `/mcp/*` backend route would hide these browser pages.

For local development, an optional server-side rewrite keeps browser cookies and requests on the same origin:

```sh
DASHBOARD_API_PROXY=http://127.0.0.1:8080 pnpm --filter openaidr-dashboard dev
```

Start the API with `OPENAIDR_PUBLIC_URL=http://localhost:3000`, matching the
browser address exactly. The proxy target is separate from this trusted browser
origin. Use the configured hostname or IP consistently, including its port.

Only configure this environment variable to a trusted API server. It is a build-time Next configuration value, not a browser-supplied destination. For production, prefer the deployment's Caddy routing and leave it unset.

The proxy forwards the API, ingest, OpenTelemetry, MCP, and OAuth paths listed
above to that backend. Sensors
enrolled through the dashboard origin use `/otlp/v1/logs`, `/otlp/v1/metrics`,
and `/otlp/v1/traces` to upload their queued telemetry. Restart `next dev` after
changing the proxy configuration, or rebuild and restart a standalone dashboard.
Existing sensors retry retained exports through the same origin when routing
recovers; their enrollment and credentials do not need to change. Removing the
telemetry routes can leave exports queued with HTTP 404 responses until routing
is restored.

Run `pnpm --filter openaidr-dashboard test:proxy` to check the real Next.js proxy against an isolated
backend. It covers binary request and response bodies, device authentication,
batch IDs, and backend authentication failures for all three telemetry signals.

## API and behavior

### Public detection names

Dashboard product labels use **Guardrail** for the internal detection name,
including tooltips, accessibility labels, and API errors. Apply `displayText`
from `src/lib/display.ts` to product labels at their display boundary. Use
`displayModel` for separately displayed model/provider names: internal and
Guardrail model identifiers display only **Guardrail**, with no version,
suffix, or derived reference. Other model names retain their original labels.

Captured action evidence is an explicit exception. Prompts, commands,
executable tool names, arguments, paths, URLs, output, and raw retained records
keep their original names, including in previews, tooltips, and accessibility
text. The action shown for approval must match the action that will run.
Generic code blocks and evidence components must not rename their contents.
Stored findings, investigation reports, assessment and decision narratives,
analyst notes, and historical knowledge can quote commands, paths, and hosts.
Preserve these complete fields, including titles, summaries, reasons, and
warnings. Do not guess which part is a product label from a colon or spacing;
apply the alias to separately typed rule, product, and model/provider labels.
Literal policy match expressions also remain exact, including product filters,
tool names, command regexes, paths, and hosts. The displayed conditions must
match the values evaluated by the sensor; only the separate rule labels use
the public alias.
Configured policy reasons also remain exact because runtime decisions use that
text verbatim.
Observed organization, account, device, and project identities also stay exact.
Chat messages keep the exact submitted and returned text. Current knowledge
document titles and indexed keywords also remain exact so the visible lookup
terms match the backend configuration.
Request identifiers, model filters, stored records, and raw copy/download
actions also keep their original values. Cost filter and agent inventory
searches match both stored names and public aliases, including partial and
mixed-case input; returned values retain their original identifiers.
Model cost rows and filter options can share the **Guardrail** label. Each
filter still selects one stored identifier, and costs are not combined merely
because display names match. This is display masking; API responses and
retained evidence still contain original identifiers.

[Model labels in the running dashboard](../../docs/images/guardrail-model-privacy.png)
use synthetic browser-test data.

No database migration is needed. Deploy the API's additive search support before
the dashboard so public-name searches work when the new labels appear. Existing
clients can still search stored names. Revert the dashboard first to roll back
the labels, then revert the API search change if needed.

### Time display

The header's **Local / UTC** control changes timestamp displays across the dashboard.
Local uses the browser's time zone and is the default. An explicit choice is saved
in `localStorage` as `openaidr.time-zone` and synchronized across tabs. If storage
is unavailable, the control still works in the current tab. The preference is
specific to the browser, not the account.

Midnight-aligned daily aggregates retain their UTC day boundaries and labels.
Rolling 24-hour buckets retain their start times in the selected zone. Changing
the display does not change API queries, filters, counts, relative durations, or
stored evidence.
This is a frontend-only change with no migration or new dependency. Deploy the
dashboard normally; reverting the dashboard restores the previous display behavior
and leaves only an unused browser preference.

Screenshots from the running dashboard with synthetic browser-test data:
[Local](../../docs/images/dashboard-time-zone-local.png),
[UTC](../../docs/images/dashboard-time-zone-utc.png), and
[phone](../../docs/images/dashboard-time-zone-phone.png).

### User invitations

Owners and administrators can choose **Users and Roles → Invite user**, enter an
email address, and select a role. Viewer is the default; administrators cannot
invite an owner. **Create invitation** returns a link to copy and share manually.
The dashboard does not send email. Closing the dialog clears the link.

On password-based workspaces, `/accept-invite?token=…` shows the organization,
invited email, role, and expiration before asking for a name and matching
passwords of at least 10 characters. Opening a link does not accept it. Submitting
creates the account and signs the recipient in. Invalid, expired, revoked, and
used invitations cannot create an account. Existing Google workspaces return
the sign-in URL and use their existing invited-account confirmation flow.

Invitations use the existing seven-day API expiration and permission checks.
No backend change, dependency, or migration is needed. Deploy this dashboard to
enable the flow; reverting it removes these screens without changing accounts
or invalidating pending invitations. The acceptance page suppresses referrer
headers, and invitation secrets are not saved to localStorage or sessionStorage.

Screenshots from the running production build:
[Invite user](../../docs/images/invite-user.png) and
[accept invitation on a phone](../../docs/images/accept-invitation-mobile.png).

### Company policy and knowledge

**Real-time Guardrail > Company Policy and Knowledge** (`/company-knowledge`)
shows a flow diagram, a company policy editor, document uploads, and MCP server
connections. Owners and administrators can save policy instructions and enable
or disable knowledge enrichment; other roles can inspect the configuration.
The policy editor uses the company policy API.
It starts empty, offers an explicit example, preserves drafts on save failures,
and requires a reset to the latest saved revision after a conflict. Clearing the
prompt removes the instructions from new model assessments. Policy text remains
literal, including product names and paths. Documents are loaded through the
knowledge API. An empty index cannot be enabled
from the dashboard. Conflicting edits reload the latest revision before another
save, and failed requests retain the last confirmed setting with an error.

The live event evidence dialog shows the stored knowledge snapshot: whether it
was enabled for that assessment, its revision, lookup time, matched keywords,
and the exact command and resource excerpts supplied to Guardrail. It distinguishes
missing matches from disabled enrichment and reports context truncation. This
is source evidence, not a model-generated explanation. Changing the setting
does not rewrite historical assessments. The existing live event and pending
risk polling paths are unchanged.

Screenshots of the running UI with synthetic browser-test data:
[company policy on desktop](../../docs/images/company-policy-desktop.png),
[company policy on a phone](../../docs/images/company-policy-mobile.png),
[desktop evidence](../../docs/images/knowledge-evidence-desktop.png), and
[phone evidence](../../docs/images/knowledge-evidence-mobile.png).

Apply migration `0046_company_policy.sql` and upgrade all receiving servers and
scoring workers before deploying this dashboard and configuring a policy.
No new dependency is required. Older assessments without knowledge metadata still
render normally. Policy instructions apply independently of the knowledge toggle
and do not change deterministic rules or enable enforcement. See
rollout and rollback.

### OpenAIDR Assistant

The circular sparkles icon, labeled **Ask about this page**, opens a
keyboard-accessible panel in the authenticated dashboard. Only the icon is shown
until clicked. The **Current page** label identifies the page being discussed.
Clicking a starter question sends it immediately with the current page text;
keyboard activation does the same. Opening the panel alone sends nothing.
Icon badges distinguish **You** from **OpenAIDR Assistant** in the conversation.
User messages appear on the right in white bubbles with a subtle border;
assistant replies appear on the left in light gray bubbles. Both use existing
dashboard color tokens and wrap long text within the panel.
Assistant replies render Markdown, including headings, emphasis, lists, quotes,
tables, and code. Headings use the panel's body size and semibold weight; tables
and code blocks scroll within the bubble. Formatting updates as text streams in,
so unfinished Markdown may change shape until its closing marker arrives. User
messages remain plain text, and conversation history keeps the original Markdown.
The renderer uses `react-markdown` and `remark-gfm` instead of parsing markup by
hand. HTML stays escaped, images show only their alt text, and only HTTP(S) links
are clickable. Links open a new tab without a referrer; no links are prefetched.
Deploy the dashboard before the backend's Markdown instruction for formatted
replies from the first answer. Either order remains functional, but old dashboards
show literal Markdown. For rollback, restore the plain-text backend instruction
before reverting the dashboard; no schema or API contract changes are needed.
[Screenshot from the running dashboard with a simulated provider reply](../../docs/images/assistant-markdown.png).
The rounded composer grows with a custom draft, with Send or Cancel inside it.
Enter sends a message; Shift+Enter adds a line break.
Replies appear incrementally in the assistant bubble. The panel shows
"Reading this page…" until the first text arrives, then "Responding…" until
the answer completes.
FastAPI's `POST /api/v1/chat` authorizes the page and forwards bounded context to
the configured Intelligence API. That service owns the OpenAI provider and model
selection in [the API page-chat provider](https://github.com/opensecurainc/openaidr-api/blob/main/src/openaidr_api/providers/page_chat.py). Configure the canonical connection on
the tenant and the provider on the API service. Without a connection, the panel
reports that chat is unavailable.

**Settings > Intelligence service** shows the service origin and certificate trust.
IT administrators can check authenticated capability configuration. The check does
not verify provider quota or worker liveness. Provider keys and automatic key import
are managed outside the tenant dashboard. Historical keys remain stored for rollback.
See the tenant setup.

Each send captures up to 20,000 characters of rendered text inside the current
page's main content, including scrollable page content. It excludes navigation,
hidden or collapsed content, clipped text, form values, scripts, attributes,
browser storage, and API caches. Chart pixels and hidden data tables are not
read. Where a chart provides a data table, open it to include its visible values;
otherwise, include the values in your message. Components may use
`data-page-chat-exclude` to exclude sensitive rendered content. The panel warns
when its context is truncated. This is the rendered page, not just the viewport.

The browser retains at most four prior turns on the current page. Live updates,
filter changes, and expanded details preserve those turns; every send captures
fresh visible page text. Earlier replies provide conversation context, not
factual evidence for the current page. Navigation, account changes, and
**New chat** clear conversation state; navigation also cancels the browser
request and ignores late answers. Each request uses the page as it appeared
when sent, so a live page may have changed by the time its answer arrives.
Closing the panel or **Cancel** aborts the stream and closes the provider
connection. Only completed answers enter conversation history. Cancellation or
an interrupted stream discards the partial reply and restores the question for
retry, preserving earlier completed turns. Requests have a 45-second provider
deadline and a 55-second browser deadline.

The browser requests `Accept: text/event-stream`. The server emits `data:` JSON
events with `type: "delta"` and `text`, followed by `type: "done"` and the
validated full `answer`, or `type: "error"` and a safe `message`. A closed stream
without `done` is a failure. Authentication and input errors still use HTTP
error responses; provider errors and admission limits after streaming starts
use an error event. `Cache-Control: no-store, no-transform` prevents caching and
compression that would buffer small chunks in the Next.js proxy;
`X-Accel-Buffering: no` also disables buffering in compatible proxies. Requests
without the streaming header retain the JSON `{ "answer": "..." }` contract,
and the new frontend accepts JSON from older backends. This permits either
deployment order or rollback of either component without breaking chat; older
components use complete replies until both are updated. Reload open dashboard
tabs after updating the frontend.

The endpoint requires an active tenant session, including for viewers, and the
same CSRF header and trusted browser origin as other API mutations. It never
queries application records or fetches the supplied page path, and it exposes
no model tools. Page text is untrusted data, not model instructions. The server
validates bounded text-only messages and fixes the provider, model, reasoning,
and instructions. It does not persist chat or page content, log prompt bodies,
or use provider conversation IDs; requests set `store: false`. This does not
change OpenAI's applicable data retention policy. The browser snapshot is not
an authorization proof: a caller can supply their own text, but cannot use this
endpoint to retrieve backend data. Answers are grounded by instructions and can
still be mistaken. Raw HTML is escaped by React; replies cannot load remote
images or execute scripts.

Limits per backend process are four concurrent provider calls and 20 attempts
per tenant per minute, plus 4,096 output tokens per call. Limits reset on process
restart and are not shared across replicas. Configure provider project budgets
for an additional spend boundary. Questions are capped at 4,000 characters and
conversation input at 24,000 characters. Provider errors are sanitized. No schema
migration is required.

References: [OpenAI models](https://developers.openai.com/api/docs/models),
[Responses conversation state](https://developers.openai.com/api/docs/guides/conversation-state).

### Existing APIs

- `POST /api/v1/auth/login` accepts email/password; `GET /api/v1/auth/me` returns the current user and tenant; `POST /api/v1/auth/logout` ends the server session. The frontend relies on the server's HttpOnly session cookie, never browser-stored bearer tokens.
- The shared API client adds `X-OpenAIDR-CSRF: 1` to every mutation. HTTPS sessions
  use `__Host-openaidr_session`; existing HTTPS users sign in again after upgrading.
  See browser request security.
- `GET /api/v1/telemetry/overview?range=24h|7d|30d&service=...` provides counters, activity buckets, source breakdown, devices, and recent export metadata.
- `GET /api/v1/telemetry/exports` accepts the same filters plus `limit` and opaque `cursor` for additional export pages.
- `GET /api/v1/events/live` returns collected agent events in server arrival order with a `cursor`; `after=<cursor>` returns later arrivals, including transactions that committed late. Overview's live activity feed and Live Guardrail both use it.
- Timeline prompts, tool calls, tool results, and responses show Guardrail risk scores (0 to 100), severity levels, and the primary risk category. The evidence dialog includes separate assessments for attached results and native records, with valid confidence values when supplied for scored or uncertain completed assessments. Events without an assessment show **Risk not assessed**. Pending, unavailable, and insufficient-context states never display a fabricated zero.
- `GET /api/v1/events/risks?ids=...` refreshes stored assessments in batches of at most 100 retained event IDs. These requests run separately from arrival polling, so provider or assessment-refresh delays do not hold up activity. Deploy the Guardrail backend and migration before this UI; no provider API key belongs in the dashboard environment.
- Absent assessments start with a one-second retry; retryable errors start at 30 seconds. Both back off to a five-minute cap. Pending assessments refresh promptly and known terminal errors stop polling. Each successful batch is retained if a later batch fails. Oversized evidence is explicitly labeled unscored rather than model uncertainty.
- Pending exports are the nullable `telemetry_queue_depth` reported on sensor heartbeats. An absent value displays **Not reported**, rather than the legacy event queue or a fabricated zero.
- App Health separates connection status from diagnostic health. Its fleet summary
  and **Needs attention** filter include online devices that report upload,
  stalled queue, telemetry receiver, collection, or activity loss faults.
  Offline devices show **Health unknown** and are excluded from attention counts,
  as are disabled devices. The **Health unknown** filter also includes online
  sensors without current diagnostics. Attention rows sort first within each
  connection group and open
  details with both queue counts and the last successful upload times. Older
  sensors show **Health not reported**. Deploy backend migration 0074 before
  updating sensors; see the heartbeat contract.
  [Offline health screenshot with synthetic test data](../../docs/images/offline-sensor-health.png).
- Record totals distinguish log records, metric data points, and trace spans. Export counts represent accepted batches. A selected service filters matching resource groups inside batches; totals follow that filter.

Source services shows the six largest record totals in the selected range and
service filter, with alphabetical service names breaking ties. Shares use all
matching services, including those outside the top six. Nonzero shares below
1% display as `<1%`; other shares round to whole percentages. The service filter
remains alphabetical. This is a dashboard-only change with no API or migration
dependency; reverting the dashboard restores the previous display.
[Screenshot with synthetic browser-test data](../../docs/images/source-services-ranked.png).

The telemetry overview refreshes every 30 seconds while visible on App Health. AI Inventory separately refreshes its application review every 30 seconds. Polls and manual refreshes skip an in-flight request. Changing filters cancels superseded browser requests; the backend bounds running telemetry statements to 10 seconds and caches overview snapshots for 30 seconds. The displayed update time is the snapshot generation time. See query bounds and recovery for backend concurrency limits, rollout, and rollback. Failed refreshes visibly retain the last successful overview; authentication failures return to sign in. Other pages provide their own data controls; server health and enrollment inventories also refresh every 30 seconds. App Enrollment also refreshes when its browser tab becomes visible. Its header has only **Create enrollment link**; failed requests retain a **Retry** action. [Enrollment screenshot with synthetic test data](../../docs/images/enrollment-auto-refresh.png). Telemetry activity and Detection and Guardrail model cost history display charts directly, with pointer, keyboard, and touch readouts and no chart/table switch. Device search and status filters act on the backend's returned device inventory.

Telemetry activity hides the trace series, legend entry, and tooltip row when the selected time and service contain no spans. Historical spans remain visible, including zero-span buckets in a period that contains trace activity.

[Telemetry chart without spans, using synthetic browser-test data](../../docs/images/telemetry-no-traces.png).

Evidence Search provides one activity table with user name, device name, session ID, date, and optional activity type filters. Search submits them together to `GET /api/v1/events`; names match literal substrings without case, and session IDs match case-sensitive substrings of native IDs or server session UUIDs. The date defaults to today in Local or UTC time. Clearing filters includes all retained dates. Calendar boundaries account for daylight-saving changes. Changing the time display preserves the applied window until Search is submitted again. Filter changes and Refresh reset pagination; a failed refresh retains the last successful rows with an error.

**Group by session ID** groups loaded matches by the native session ID within its sensor and agent product, with a server session UUID fallback. Unknown sessions stay separate. Group counts cover loaded matches, not complete sessions. Recent groups appear first with activities oldest first inside each group. Every stored record keeps its own row. The table shows recorded user and device identities, agent, activity type, source, and a one-line evidence summary. Expand an activity to read captured content, open the raw event, or select **Open telemetry record**. Binary output stays summarized by type and size, with its original stored value available for download. Raw telemetry metric and trace batches are not agent activities.

[Evidence Search screenshot from the production build with synthetic data](../../docs/images/evidence-search.png).

Opening a linked export loads `GET /api/v1/telemetry/exports/{id}`: a records table and the raw OTLP payload with copy and download. The dialog highlights the exact referenced record. Its metadata header comes from that response, with a loading skeleton until it arrives. Viewers see the metadata and an explanation that payload contents require the analyst role. Deploy the event filter API additions before this dashboard or deploy both together; roll back the dashboard first. No migration or new dependency is required.

App Health loads `GET /api/v1/sensors/health` independently every 30 seconds
while visible. Device status, pending exports, CPU and memory history, and
guardrail controls remain available while the telemetry overview is pending or
unavailable. Missing telemetry totals display `N/A`; failed refreshes retain the
last successful data with a warning. **Refresh apps** refreshes the device
inventory separately from telemetry and resource-history refreshes. Sensor
health includes all enrolled devices; time and service filters apply to telemetry
totals, while device search and status filters select devices and the resource
chart has its own range. Deploy the backend endpoint before the dashboard. An
older backend produces a visible health warning and the page can still use a
successful overview's device list; rolling back the dashboard restores its
previous dependency on overview availability. No migration is required.

The device inventory lists online devices first, then offline devices, then
disabled devices. Within each connection group, devices needing attention come
first, followed by larger record totals. Unknown totals follow known totals,
and ties retain the API order. Sorting uses the displayed heartbeat status,
health, and telemetry totals, including after refreshes and filter changes.
Deploy the dashboard to apply this ordering; reverting this change restores
health priority ahead of connection status. No backend change or migration is
required.

[Online-first inventory screenshot](../../docs/images/sensor-inventory-online-first.png)
from the running dashboard with synthetic browser-test data.

The **Relative App version age** summary groups sensors into eleven buckets:
0 through 9 days, then more than 9 days behind the newest version date reported
by any enrolled sensor in the workspace, including disabled sensors. It uses
the calendar date in `YYYY.M.D+commit`, not today's date or the number of
releases. Builds from the same day share a bucket regardless of commit suffix;
0d means the build date matches the newest reported date.
The chart shows the full version identifiers reported for that newest date,
including their commit suffixes. Multiple versions on that date are listed
together because their hashes do not establish release order. The label wraps
on narrow screens and is absent when no valid version date is available.
Online sensors are teal and offline sensors are grey. Disabled sensors and
unreadable or legacy version dates are counted separately as excluded from
the bars. The plotted total and legend count only sensors with known ages.
Telemetry and device-table filters do not change the fleet or reference date.
An unavailable health inventory is not replaced with a filtered telemetry
inventory; a failed refresh retains the chart with a stale warning. The chart
provides pointer, keyboard, and touch readouts and a screen-reader data table.
This is a dashboard-only change using the existing sensor health endpoint;
no migration is needed, and reverting the dashboard removes the summary.

[Desktop version age chart](../../docs/images/relative-app-age-desktop.png) and
[phone version age chart](../../docs/images/relative-app-age-mobile.png), captured
from the running dashboard with synthetic browser-test data.

Server Health includes host CPU, memory, filesystem space, and disk I/O
charts for owners and admins. Disk space measures `/` on Linux hosts and
Docker Desktop's persistent data filesystem (`/var/lib`) in its Linux VM.
The range selector covers 1, 6, or 24 hours. Charts display directly without
a data table; pointer, keyboard, and touch readouts expose sample values.
The four host charts fit one row at desktop widths and stack on smaller screens.
Their time cursors and readouts stay synchronized by timestamp.
Disk I/O uses solid lines for both Read and Write. Failed refreshes keep the
previous response visible, delayed samples are labeled, and missing metrics never
appear as zero usage. See host monitoring
for collection, deployment, metric definitions, and rollback.

## Enrollment installers

The public `/enroll` page guides recipients through installation and connection.
By default it links each platform to the latest public OpenAIDR installer, using
the fixed links that the desktop release publisher
maintains for the active release. To offer your own approved installers, set
them in the dashboard server's runtime environment:

| Variable | Installer | Default |
| --- | --- | --- |
| `OPENAIDR_DESKTOP_MAC_ARM64_URL` | Apple Silicon DMG | `https://releases.opensecura.ai/openaidr/latest/OpenAIDR-aarch64.dmg` |
| `OPENAIDR_DESKTOP_WINDOWS_X64_URL` | 64-bit Windows: a zip holding the signed setup program, or the setup program itself | `https://releases.opensecura.ai/openaidr/latest/OpenAIDR-windows-x64.zip` |
| `OPENAIDR_DESKTOP_LINUX_X64_URL` | 64-bit (amd64) Ubuntu or Debian DEB | `https://releases.opensecura.ai/openaidr/latest/OpenAIDR-linux-amd64.deb` |

The recipient's browser downloads directly from the release host. Tenant
dashboard servers have no internet access, and the page never fetches release
data or installers on the server.

The page reads the request's `User-Agent` operating system token to show the
Mac, Windows, or Linux installer and instructions first. The other platforms
stay available in a collapsed section, and browsers that report another or no
recognizable desktop operating system, such as phones and ChromeOS, see all
three. Mac installation requires Apple Silicon; the page states that Intel
Macs are not supported. Browsers do not report a reliable processor
architecture, so detection only orders the page. It never hides a supported
installer, and the response is not cached. The legacy
`OPENAIDR_DESKTOP_MAC_X64_URL` setting is ignored.

[Enrollment page screenshot](../../docs/images/enrollment-install-desktop.png)
from a running production build with example installer URLs.

Use HTTPS URLs for installers that your organization has published and verified.
The values appear on a public page: do not include private credentials or secrets.
URLs containing credentials, fragments, whitespace, or more than 2048 characters
are rejected. A missing or invalid value uses that platform's latest public
installer instead. The page does not download files on the server or send the
enrollment code to a download host. Visiting it leaves the enrollment link unused.

For tenant Compose deployments, set these values in `deploy/tenant.env` and
recreate the dashboard container. Keep the example's single quotes around each
URL so Compose preserves literal dollar signs, such as
`OPENAIDR_DESKTOP_MAC_ARM64_URL='https://downloads.example/app.dmg?channel=$stable'`.
Encode any apostrophe inside the URL as `%27`.
Cloud deployments use the optional `desktop_mac_arm64_url`,
`desktop_windows_x64_url`, and `desktop_linux_x64_url`
fields in the bootstrap JSON configuration,
which preserves the values across upgrades and ignores inherited shell variables.
Other deployments pass the environment variables to the dashboard process.
Values are read at request time, so changing
them needs a process restart but no image rebuild. Configure them only after
verifying installation, and updates where the platform supports them, on each
advertised platform and architecture. Windows and Linux builds have no automatic
desktop updater, and the page tells recipients to ask for later versions. Leave
a value empty to offer the latest public installer. To withdraw your own
download, clear its value and recreate the dashboard container; existing
enrolled devices are unaffected. This change requires no backend deployment or
database migration.

The page explains managed-Mac approval, Windows SmartScreen confirmation, and how to choose an administrator's
public CA file under **Private server certificate (optional)** in the desktop
app. It directs older apps without this option to administrator-assisted CLI
setup. See
[enrollment](../../docs/guide.md#personal-and-enterprise-setup) and the
desktop release signing mode.

## Validation

Run from the repository root:

```sh
pnpm --filter openaidr-dashboard sync-brand
pnpm --filter openaidr-dashboard check:design
pnpm --filter openaidr-dashboard check:colors
pnpm --filter openaidr-dashboard typecheck
pnpm --filter openaidr-dashboard build
pnpm --filter openaidr-dashboard test:proxy
```

The default Playwright configuration does not start the dashboard. Install its
browser once with
`pnpm --filter openaidr-dashboard exec playwright install chromium`, start a
dashboard with the required API routing, then select the matching spec files.
`OPENAIDR_DEMO_URL` selects the browser origin and defaults to
`https://127.0.0.1:8443`. `OPENAIDR_DEMO_ARTIFACTS` selects the output directory;
the default is `.demo/browser-results` at the repository root. Use absolute paths
for environment variables naming files or executables because pnpm runs these
scripts from `apps/dashboard`.

For chart stability checks, build from a clean checkout, then run:

```sh
pnpm --filter openaidr-dashboard exec playwright install chromium webkit
pnpm --filter openaidr-dashboard exec playwright test --config playwright.charts.config.ts
```

This configuration starts the production build on port 43174 and uses populated
API fixtures. It covers every Recharts component and the Live Guardrail flow
diagram at four window widths. It checks zero-width and space-consuming
scrollbars in Chromium and WebKit at 150% CSS zoom, including the original
shaking reproduction. Chromium also runs at actual browser zoom levels of
100%, 125%, 150%, 175%, and 200%, with 15px scrollbars and display scaling fixed
at 100%. Each test verifies the scrollbar and zoom environment before checking
consecutive layout frames. This models the suspected Windows Chrome layout
behavior; it does not replace native Windows validation. Reports and screenshots
go to `.demo/chart-report` and `.demo/chart-results`.

`tests/demo.spec.ts` and `tests/navigation.spec.ts` use a real same-origin API
with seeded demo telemetry. They read an `email` and `password` from the JSON
file named by `OPENAIDR_DEMO_CREDENTIALS`, defaulting to the repository's
`.demo/login.json`. Keep that file private and use a disposable demo tenant.
The demo spec requires HTTPS and a trusted certificate; TLS verification remains
enabled. Other specs, such as `tests/design.spec.ts`, mock API responses in the
browser to exercise layout, failed requests, and restricted roles. Do not run
all specs against one live deployment: the fixture-backed tests below start
different local API servers.

The public enrollment tests need only a running dashboard, without login or an
API. Run `OPENAIDR_DEMO_URL=http://127.0.0.1:3000 pnpm --filter openaidr-dashboard test:e2e tests/enrollment-landing.spec.ts`.
Use the same installer URL environment variables for the server and test process.
Run once with approved test URLs and once with empty or invalid values to check
the download and administrator-assistance paths. Installer requests are intercepted;
the tests do not download or run real installers.

For the fixture-backed specs, set `OPENAIDR_TEST_DATABASE_URL` to a disposable
PostgreSQL database whose user can create and drop schemas. Install this
repository's dev dependencies in a Python environment, then set
`OPENAIDR_TEST_PYTHON` to its absolute executable path, for example
`export OPENAIDR_TEST_PYTHON="$PWD/.venv/bin/python"` from the repository root.
Each spec starts and stops its own API and removes its isolated schema on exit.

For `tests/page-chat.spec.ts`, start the dashboard in one terminal:

```sh
DASHBOARD_API_PROXY=http://127.0.0.1:8773 pnpm --filter openaidr-dashboard dev --hostname 127.0.0.1 --port 3000
```

In another terminal with the test environment variables set, run:

```sh
OPENAIDR_DEMO_URL=http://127.0.0.1:3000 pnpm --filter openaidr-dashboard test:e2e tests/page-chat.spec.ts
```

This spec simulates OpenAI and never uses the real provider key.

For `tests/user-invitations.spec.ts`, use proxy port 8787 and dashboard port 3121:

```sh
DASHBOARD_API_PROXY=http://127.0.0.1:8787 pnpm --filter openaidr-dashboard dev --hostname 127.0.0.1 --port 3121
```

Then run in the other terminal:

```sh
OPENAIDR_DEMO_URL=http://127.0.0.1:3121 pnpm --filter openaidr-dashboard test:e2e tests/user-invitations.spec.ts
```

For `tests/agent-costs.spec.ts`, use proxy port 8769 and follow the
cost validation commands.
`OPENAIDR_CHAT_TEST_API_PORT`, `OPENAIDR_INVITATION_TEST_API_PORT`, and
`OPENAIDR_COST_TEST_API_PORT` can override the respective API port. Keep the
dashboard's `DASHBOARD_API_PROXY` in sync and restart it when switching fixtures.

Implementation references: [Next standalone output](https://nextjs.org/docs/app/api-reference/config/next-config-js/output), [shadcn/ui Next installation](https://ui.shadcn.com/docs/installation/next), and [Recharts installation](https://recharts.github.io/en-US/guide/installation/).
