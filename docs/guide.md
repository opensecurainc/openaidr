# Setup and development guide

[Back to the overview](../README.md)

Detailed setup, configuration, build, and test instructions for OpenAIDR.

For desktop installation, start with the connection choices below. For
command-line setup or builds, first clone the repository as described under
[local server setup](#start-the-local-server).

- [Personal and enterprise setup](#personal-and-enterprise-setup)
- [Supported agents](#supported-agents)
- [Coverage](#coverage)
- [Local server setup](#start-the-local-server)
- [Desktop builds](#build-the-app)
- [GitHub builds](#manual-github-builds)
- [Guardrails, posture, and overview](#guardrails-posture-and-overview)
- [Tests](#contribute-and-test)
- [macOS end-to-end reports](#macos-end-to-end-report)

## Personal and enterprise setup

Use the [current desktop download](../README.md#download-the-app) for the setup
choices below. These installers contain the sensor; Git, Python, and a local
server are not needed for personal use. Source builds have the separate
[build prerequisites](#build-the-app).

### Personal: free allowance

1. Open the app and choose **Sign in with Google** for 200 weekly credits, or
   **Continue without signing in** for a starter allowance. No API key is required.
2. Let setup start the sensor and configure detected supported agents.
3. Restart agent sessions, then review usage and guardrail activity in the app.

If you skip sign-in or cancel it, you can sign in later by opening sensor status
at the top of the app and selecting **Sign in with Google**. Your local history
is kept when you connect your account.

Personal guardrails use **Shadow** mode by default: checks are recorded and
actions continue. [Local rules](#personal-local-rules-and-enforce) can
switch them to Enforce. Usage stays on the device; bounded, redacted evidence needed for a
cloud check is sent to OpenSecura. Review **How your data is used** during setup.
The service retains request metadata, not request content.

### Personal: paid API key

[Contact OpenSecura](mailto:contact@opensecura.ai) for an OpenSecura service key
and credits. The current onboarding exposes **Use an API key** after free setup
is rate limited. Enter the key there to connect. If you are already connected
or do not see that option, ask OpenSecura for the supported upgrade path for
your build. A model provider key cannot be used for this connection.

API-key connections keep usage local and run checks in Shadow mode, like free
personal connections. A successful connection does not guarantee available
credits or that every check can complete.

### Personal: local rules and Enforce

Personal connections can apply their own rules without a workspace. Create
`guardrail-rules.yaml` next to the sensor configuration file `sensor.yaml`:
`~/Library/Application Support/OpenAIDR` on macOS, `~/.config/openaidr` on
Linux, and the per-user OpenAIDR state folder on Windows.

```yaml
mode: enforce
rules:
  - id: no-force-delete
    name: Block recursive deletes
    action: deny
    reason: Recursive deletes are blocked on this device
    match:
      kinds: [command]
      command_regex: "^rm -rf "
  - id: ask-ssh-keys
    name: Ask before reading SSH keys
    action: ask
    match:
      kinds: [file.read]
      path_glob: "~/.ssh/**"
```

`mode` is `shadow` (the default) or `enforce`. Rules use the workspace
Guardrail Configuration format: a unique `id`, an `action` of `allow`, `warn`,
`ask`, or `deny`, and a `match` with at least one of `kinds`, `products`,
`tool_name`, `command_regex`, `path_glob`, or `host_glob`. `name`, `reason`,
and `enabled` are optional. Action kinds are `prompt`, `command`, `file.read`,
`file.write`, `network`, and `tool.call`.

In Shadow mode, rule decisions are recorded as would-be decisions and actions
continue. In Enforce mode, the strongest decision among the matching rules and
the cloud assessment (deny at risk 80 and above, ask at 60 and above) is
returned to the agent at supported hooks. An action a rule denies is not sent
for assessment. When the cloud check is unavailable, rule decisions still
apply and other checks allow the action. The file is re-read when it changes.
An invalid file records checks as unavailable with the reason "The local
rules file could not be loaded." and actions continue. **Guardrails** in the
app shows the mode and each check's returned response.

### Enterprise: local evaluation

Choose **Connect organization > Set up local runtime**. Setup creates the
database, server, and dashboard, enrolls this device, and registers the free
service allowance. On macOS, it can install and start Docker Desktop; approve
its prompts and complete Docker's setup. Windows and Linux require Docker with
Compose already running. Keep Docker running, then use **Open dashboard** in
the app. AI checks use OpenSecura's cloud service.

The local runtime is for development and evaluation. It does not include
managed hosting. See [local server setup](#start-the-local-server) for manual
configuration, storage, and connecting another computer.

### Enterprise: paid deployment or existing workspace

[Request a demo](https://forms.gle/FxMfNgBoM9NHkUmQA) to arrange a managed
workspace, deployment support, or paid service access for your own runtime.
Administrators configure the OpenSecura service key under **Administration >
Settings > Intelligence service**. Credits belong to the workspace and are
shared by its connected devices. The [manual setup](#start-the-local-server)
also supports a service origin and API key in `.env`.

To join a workspace:

1. An administrator creates a link under **Administration > App Enrollment**.
2. In the app, choose **Connect organization**, paste the enrollment link, and
   confirm the organization.
3. Restart your agent sessions and confirm that the app shows **Connected**.

Start in Shadow mode to review decisions before enabling Enforce for supported
hooks. Cloud checks use service credits, separate from your AI tools'
subscriptions, tokens, and costs. The connected service defines the free
allowance and reset period. If credits run out or the service is unavailable,
OpenAIDR allows actions and the app shows that cloud guardrails are inactive.
Native agent behavior still applies; see [guardrail exceptions](#guardrails-posture-and-overview).

## Install downloaded Windows and Linux apps

Download the installer from the [downloads page](https://releases.opensecura.ai/openaidr-oss/).
Check its SHA-256 against the value shown there before opening it.

**Windows x64.** Run the EXE. The installer uses your Windows account and
installs WebView2 if it is missing. Current prereleases are unsigned, so
SmartScreen can show an unknown-publisher warning. For a verified download,
**More info > Run anyway** may be available. Smart App Control or company
policy can block the app without an override; contact your administrator in
that case. Do not disable system-wide protection. A verified Windows signing
identity is still required to sign future releases; self-signing does not
remove these warnings. See [Microsoft's guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation).

**Debian/Ubuntu x64.** Prefer the DEB package and install it with APT so its
runtime dependencies are installed too:

```sh
sudo apt install ./OpenAIDR_VERSION_amd64.deb
```

Replace `VERSION` with the downloaded version. Open OpenAIDR from the app menu.
The compatibility checks cover Ubuntu 22.04, Ubuntu 24.04, and Debian 12.

**Linux AppImage.** Allow the downloaded file to run, then launch it:

```sh
chmod +x ./OpenAIDR_VERSION_amd64.AppImage
./OpenAIDR_VERSION_amd64.AppImage
```

Use a graphical Linux session with the system's graphics drivers installed.
On a minimal Debian/Ubuntu system, install the required desktop libraries:

```sh
sudo apt install libgtk-3-0 libayatana-appindicator3-1 libegl1 libgbm1 libgl1 libgles2 libgl1-mesa-dri
```

If FUSE is unavailable, use the runtime's extraction option:

```sh
./OpenAIDR_VERSION_amd64.AppImage --appimage-extract-and-run
```

This needs temporary disk space and can make startup slower. It does not
require FUSE or administrator access. See [AppImage's instructions](https://docs.appimage.org/user-guide/troubleshooting/fuse.html).

## Supported agents

Usage tracking and guardrail coverage are separate. This table covers the local
coding-agent integrations; agent versions and configuration affect availability.

| Agent | Usage tracking | Guardrail checks |
| --- | --- | --- |
| Codex, Claude Code | Reported tokens and estimated costs | Prompts, tools, supported results |
| GitHub Copilot | Hook-text estimates; optional CLI telemetry | Tool calls |
| Cursor | Hook-text estimates; optional Enterprise telemetry | Prompts and tool calls |
| Antigravity | CLI session totals | Tool calls |
| OpenCode 1.x | Plugin-reported tokens and costs | Tool calls |
| Hermes Agent | Optional telemetry; costs may be unknown | Tool calls after native approval |
| WorkBuddy | Reported tokens; costs may be unknown | Tool calls |

The [hook protocol](hook-protocol.md) documents the events, payloads, backend
check, and native responses behind this table.

Inventorying an app does not establish usage or guardrail coverage. Hook-text
estimates are partial, and estimated costs are not subscription bills. The
following limits apply to the local coding-agent integrations:

- **Codex and Claude Code:** setup configures hooks and native OpenTelemetry.
  Tool-result controls require a capable installation; native telemetry and
  hook capture have separate settings.
- **GitHub Copilot and Cursor:** local hooks estimate captured text, not total
  model inference. Copilot CLI telemetry and Cursor Enterprise telemetry need
  separate configuration. Hidden context, cache use, and uncaptured content
  are outside hook estimates.
- **Antigravity:** the CLI status-line adapter supplies session usage totals.
  This does not establish usage coverage for every editor session.
- **OpenCode 1.x:** the bundled plugin supplies tool-call hooks and usage.
  Missing or ambiguous zero costs remain unpriced.
- **Hermes Agent:** tool-call hooks require native approval in a new chat.
  Optional telemetry needs separate plugin setup; missing costs remain unknown.
- **WorkBuddy:** tool-call hooks and native usage collection are supported.
  Missing costs remain unknown. Its native hook failures have the exception
  described under [guardrail behavior](#guardrails-posture-and-overview).

Installed configuration does not prove a running agent loaded it. Start new
sessions after setup and check **Guardrails > Agent setup** for each agent's
state. Coverage is limited to supported local hooks; cloud agents and inline
completions are not covered by these hook adapters. Additional usage sources,
such as imported Gemini CLI history, do not imply ongoing collection or hook
protection. See the [desktop guide](../apps/desktop/README.md).

## Coverage

| Capability | This repository | Needs the Intelligence service |
| --- | --- | --- |
| Desktop | macOS Apple Silicon, Windows x64, Linux x64 source and local builds | No |
| Overview | Live activity and a model-written summary of posture, detections, guardrails, and costs | Summary only |
| AI Asset Management | AI Apps with observed users and approvals, AI Supply Chain with vulnerability lookups, AI Skills, gateways | Application research and skill assessment |
| Detection and Response | User risk, detection queue, evidence search, detection rules, detection quality, investigation reports | Yes |
| Guardrails | Live guardrail, decision history, manual command, text, path, and host rules with Shadow and Enforce modes, benchmarks, Company Policy and Knowledge | Inline model assessments and URL reputation |
| Costs | AI agent token usage and estimated costs by user and agent; OpenAIDR model costs | No |
| Administration | App health, server health, enrollment, integrations, audit logs, users and roles, settings | No |
| Deployment | Local development Docker Compose: PostgreSQL, server, dashboard. Not a production deployment | No |

Model-backed capabilities call the OpenSecura Intelligence service through the
vendored SDK. Without a configured service the pages that need it report the
service as not configured and the rest of the product works. The
[open source plan](open-source-plan.md) describes the public client and hosted
service boundary. New local workspaces enroll automatically when the hosted
free service is enabled. Cloud checks use service credits; the connected service
sets the allowance and reset period. Existing workspaces preserve their identity
and API credentials. The desktop reports exhausted credit and API connection failures.

Signing, automatic updates, and OpenSecura's hosted multi-tenant cloud are not
part of this repository.

## Start the local server

Clone the repository first. Run the commands from its root unless a section
says otherwise.

```sh
git clone https://github.com/opensecurainc/openaidr.git
cd openaidr
```

For an Apple Silicon Mac, `setup.sh` installs the published desktop app and
starts the backend and dashboard without building them:

```sh
./setup.sh
```

Install Docker Desktop and Python 3.11+ before running setup. The script starts Docker
Desktop, downloads the newest complete full-client release (including prereleases),
checks its source and artifact manifest, verifies SHA-256 checksums, and uses
AppleScript to copy OpenAIDR into `/Applications`. macOS may ask to allow Finder
automation or opening the unsigned app. Reduced releases are rejected even when
an explicit tag is supplied. If no complete full-client release exists, build
the current source with Compose below.

The script opens the desktop app and signs the browser into the local dashboard
through a one-use localhost link. The password stays out of browser URLs.
Create an enrollment link in the dashboard and paste it into the app to connect
the sensor. Configuration, credentials, and cached downloads are stored in
`~/Library/Application Support/OpenAIDR/local`. Reruns preserve credentials and
database contents; an existing `.env` beside `setup.sh` is reused on first setup.
New setups choose a free localhost port starting at 8080 and save it for later runs.
If an existing account's password has changed, sign in manually. The backend
images use Docker's Linux x64 emulation on Apple Silicon.
To inspect or stop this installation, run `docker compose logs` or
`docker compose down` from that configuration directory.

For a source build or a server on another platform, use Compose directly.
Requirements: Docker with Compose and Python 3.11 or later. Start from a clean
committed checkout so every build has a verifiable source identity. A downloaded
archive has no Git history: before any build or configure step, set
`OPENAIDR_BUILD_COMMIT` to the full source commit SHA and
`OPENAIDR_COMMIT_TIMESTAMP` to that commit's committer time as a Unix epoch.
Both are shown on the GitHub release the archive came from, and
`git show -s --format='%H %ct'` prints them on a checkout. The scripts stop with
a message naming these variables when they are missing.

```sh
python3 scripts/local_stack.py configure
docker compose up --build -d
```

Open <http://localhost:8080>. Log in as `admin@localhost` with the generated
`OPENAIDR_ADMIN_PASSWORD` in `.env`. Keep this file private. The `bootstrap`
service creates one workspace and its owner on first start and reuses them
afterwards; restarting does not reset users or passwords.

Open **Administration > App Enrollment** and create an enrollment link. Open the
built app and paste that full link into its connection dialog. The sensor and
dashboard use the same local server. New workspaces use their saved free
enrollment identity. For a paid connection or an existing workspace, add
`OPENAIDR_INTELLIGENCE_ORIGIN` and `OPENAIDR_INTELLIGENCE_API_KEY` to `.env` and
run `docker compose up -d` again. Explicit credentials take precedence over free
enrollment. Local collection and rules continue when credit is exhausted or the
API cannot be reached.

The workspace connection settings offer only the Production Intelligence
service. Explicit deployment-configured endpoints remain supported, and saved
Production selections still apply when the deployment specifies another
endpoint. Deployments configured for another endpoint do not gain a new switch
to Production; configure the Production endpoint and its own key in the
deployment first. A previously saved Production selection can still be verified
and its key replaced in Settings. With Production configured, a retired saved
selection is unavailable until Production is explicitly selected. Credentials
and request history remain bound to their original endpoint. Free-installation
and private-CA connections cannot switch endpoints.
New databases accept only Production for saved environment selections and keys;
existing database rows and constraints are not rewritten. Restoring multiple
saved environments on a new database requires both a code and schema change.

Compose binds the dashboard to loopback by default. To enroll a different
computer, set `OPENAIDR_PUBLIC_URL`, `OPENAIDR_BIND_ADDRESS`, and `OPENAIDR_PORT`
in `.env` to a reachable address and restart Compose. Use HTTPS through your own
reverse proxy before exposing credentials outside a trusted local environment.

```sh
docker compose logs server dashboard
docker compose down
```

The database volume persists across restarts. `docker compose down --volumes`
deletes the local workspace and its data.

## Build the app

Build on the target operating system. Install Python 3.11+, Node.js 22+, pnpm
9.15.9, and Rust. On macOS, use Apple Silicon with Xcode command-line tools.
Windows needs Visual Studio C++ Build Tools and WebView2. Linux needs the Tauri
WebKitGTK 4.1, GTK 3, librsvg, patchelf, OpenSSL, and appindicator development
packages. See [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

```sh
python3 -m venv .venv
# macOS/Linux:
. .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install -e '.[desktop]'
pnpm install --frozen-lockfile
python scripts/build_desktop.py
# On macOS, use this instead to sign the complete app without an Apple certificate:
# python scripts/build_desktop.py --signing-mode ad-hoc
```

Artifacts are under `apps/desktop/src-tauri/target/release/bundle/`. Local builds
contain no hosted updater configuration and require no release credentials.
Without `--signing-mode ad-hoc`, the app bundle is unsigned. Platform security
warnings are expected for both unsigned and ad hoc builds.
Versions use `YYYY.M.D+commit`, based on the source commit's date in
`America/Los_Angeles` and its first seven SHA characters. Builds require a clean
committed checkout; `python scripts/build_version.py` prints its version.

The public builder supports `--sidecar-only`, `--no-bundle`, `--simulation`,
Windows `--bundle-only`, and macOS `--signing-mode ad-hoc`. Ad hoc signing
requires no Apple certificate or updater credentials. It seals the app and
its bundled frameworks, then checks the app signature and the copy inside
the DMG. These builds are not notarized and do not identify a verified developer.
After trying to open a trusted download, use **System Settings > Privacy &
Security > Open Anyway**, where permitted. See
[Apple's instructions](https://support.apple.com/en-us/102445).
Developer ID, notarization, and Authenticode release configuration is not part
of the public build flow. Leave `APPLE_SIGNING_IDENTITY` unset for a public build.

On macOS, copy the built app to `/Applications` or `~/Applications` before
opening it. Enrollment starts the sensor and connects supported installed
agents. Review content-capture controls before collecting prompts or tool
content. Use a separate test environment if OpenAIDR is already installed.

## Manual GitHub builds

Under **Actions**, select **App** or **Backend**, then **Run workflow**.
Both build the selected branch or tag:

- **App:** uploads a macOS Apple Silicon DMG containing an ad hoc signed app,
  plus unsigned Windows x64 and Linux x64 DEB and AppImage installers as
  Actions artifacts. The macOS app is not notarized and requires user approval.
- **Backend:** publishes a GitHub prerelease with Linux x64 backend and dashboard
  Docker images in `openaidr-backend.tar.gz`, plus `build.json`. The release tag
  uses the same `YYYY.M.D+commit` version as the app.

The App workflow also installs the EXE on a fresh Windows runner and the Linux
packages in fresh Ubuntu 22.04, Ubuntu 24.04, and Debian 12 containers. It checks
that the first-run screen renders, then removes the app. AppImage checks use
the extraction option without FUSE. The checks disable system timezone lookup
to verify that the bundled sensor carries its timezone data.
These checks validate packaging and startup;
they do not establish SmartScreen reputation or simulate a browser download.
The release publisher requires the entire workflow, including these checks,
to pass before it will upload installers.

For a complete prerelease, maintainers run `scripts/publish_app_assets.py` to
attach all four installers from the matching App run. It also uploads
`client-release.json`, which records the source commit and SHA-256 checksums
of the installers, backend archive, and build metadata. See
[Publishing a release](#publishing-a-release) for the verification steps.

Download both Backend assets from **Releases** to a directory outside the
repository. Check out the source commit recorded in `build.json`, then run
from that clean checkout:

```sh
docker load -i /path/to/openaidr-backend.tar.gz
python3 scripts/local_stack.py configure
docker compose -p openaidr up -d --no-build
```

These workflows run only when started manually. Backend prereleases are not
marked as latest. Existing releases are not overwritten; publishing the same
version again fails. Neither workflow pushes images to a registry or deploys
services.

### Measured build times

All builds passed on their first run on 2026-10-20 (UTC), using source commit
[`29a54de`](https://github.com/opensecurainc/openaidr-private-archive-20261105/commit/29a54de37fae0d4a8fde18b97f5e7358ea6b5805).
These historical records are kept in the private archive and require access.
These measurements used fresh GitHub-hosted runners with no workflow caches.
Full job time includes setup, build, export, and upload, but excludes queue time.

| Build | Runner | Build step | Full job |
| --- | --- | --- | --- |
| [macOS ARM64](https://github.com/opensecurainc/openaidr-private-archive-20261105/actions/runs/39376816428/job/118476715020) | `macos-15` | 2m 27s | 2m 51s |
| [Windows x64](https://github.com/opensecurainc/openaidr-private-archive-20261105/actions/runs/39376816428/job/118476714976) | `windows-2025` | 13m 17s | 14m 57s |
| [Linux x64](https://github.com/opensecurainc/openaidr-private-archive-20261105/actions/runs/39376816428/job/118476714773) | `ubuntu-22.04` | 8m 42s | 9m 50s |
| [Backend and dashboard](https://github.com/opensecurainc/openaidr-private-archive-20261105/actions/runs/39376819447/job/118476715740) | `ubuntu-24.04` | 55s | 1m 24s |

The three App jobs run in parallel. Dispatch to final job completion took
**15m 03s** for App and **1m 28s** for Backend, including queue time.
The two workflows can run together; Compose also builds the backend and
dashboard images concurrently. Times vary with runner capacity and downloads.

## Guardrails, posture, and overview

Guardrails start in **Shadow** mode: matched decisions are recorded and actions
are allowed. Switch to **Enforce** in **Guardrail Configuration** to apply timely
backend decisions at supported hooks. **Live Guardrail** shows decisions as they
arrive and **Guardrail History** lists past decisions. Failed checks and unavailable backends
allow the action. Native agent permissions and sandboxes still apply.
WorkBuddy has an agent-native exception: a hook timeout, shell-start failure,
or signal termination can block an action even in Shadow mode. Failures handled
by OpenAIDR still return success without a decision. This exception does not
change other agents' behavior.

Security Analysts can edit manual rules in **Guardrail Configuration**, or
through the policy API. The rule editor saves a JSON array. Default rules
include destructive root deletion, downloaded shell scripts, credential reads,
and AWS access-key patterns. Prompt rules operate on captured, redacted text.
A literal key is replaced with `[REDACTED:aws-access-key]` on the endpoint before
submission. Disabled content capture prevents content-based checks. Rules match
patterns; they do not infer intent or establish that an action is safe.

Posture checks read known user-level Codex, Claude Code, Cursor, and Claude
Desktop configuration locations. They report the file path, collection time,
readability, and matching rule identifiers. They do not send credential values.
Missing, unreadable, and old snapshots are coverage limits. Project-specific
files, custom homes, inherited permissions, and arbitrary tools are not covered.

The **Overview** page writes a short summary from the app health, guardrail,
inventory, detection, and cost pages. It needs the Intelligence service; without
one the page says so. Prompts sent to the model contain page aggregates, not
captured content. **Administration > Settings** shows the service connection
and which capabilities it provides.

Manual guardrail rules need no service. Inline model assessments of prompts,
tool calls, and results, and URL reputation checks, run only with the service
connected and still fail open.

## Contribute and test

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution requirements.

```sh
python -m pip install --no-index --no-deps dependencies/api-runtime/*.whl
python -m pip install -e '.[dev]'
python -m pip install --no-deps -e packages/common
pytest -q
pnpm --filter openaidr-dashboard typecheck
pnpm --filter openaidr-dashboard test:e2e
pnpm --filter openaidr-desktop typecheck
pnpm --filter openaidr-desktop test:web
```

`packages/common` is the Apache 2.0 source of the shared `openaidr-common`
helpers. The vendored Intelligence SDK wheel pins the reviewed
`openaidr-common` wheel, so install the wheels and the application first, then
replace the helpers with the editable source install; edits under
`packages/common` are live from then on. Desktop and local-runtime builds keep
the reviewed wheels from `dependencies/api-runtime/`.
Editable installs accept uncommitted changes; wheels, source archives, and
desktop builds require a clean checkout.
Set `OPENAIDR_TEST_DATABASE_URL` to a disposable PostgreSQL database to run the
server integration tests. They create and drop their own isolated schema.
Without that setting, database tests are skipped. Test modules that need the
private Intelligence service wheel are skipped at collection.
Dashboard and desktop browser tests use Chromium and WebKit; native runtime
tests are under `apps/desktop/src-tauri/tests`.
Dashboard tests start a local development server and use synthetic API responses.

### macOS end-to-end report

Run **Actions > E2E macOS > Run workflow** on a trusted branch. Select `claude`
(the default), `codex`, or `both`. Claude requires the repository Actions secret
`CLAUDE_CODE_OAUTH_TOKEN`; Codex requires `OPENAI_API_KEY`. Missing credentials
for a selected agent fail the run. Unselected agents appear as skipped tests.
The workflow uses pinned CLI versions and makes real model requests. Each
invocation has a three-minute timeout; Claude also has a $1 request budget.
Codex has no per-invocation dollar cap in this harness.

The disposable `macos-15` VM builds and installs the unsigned DMG, starts a
private PostgreSQL database plus the real backend and built dashboard, and
connects through the installed sensor's desktop enrollment bridge. The native
app must start its background sensor and configure the selected agents. Tests
check an allowed command, token usage, and a harmless command blocked by an
Enforce policy. A pass requires a matching sensor/session hook delivery and the
expected filesystem effect. Browser errors and sensor delivery errors fail the
test. This initial suite does not automate typing an enrollment link into the
native window, or cover outages, upgrades, or reboot recovery.

Download the **macos-e2e-report** artifact, extract it, and open `index.html`.
It includes real Terminal and native app window screenshots, dashboard
screenshots, redacted agent streams, sensor/backend logs, correlated policy
decisions, and JSON/JUnit results. Screenshots are taken for successful tests
as well as failures. Native app captures wait for visible enrollment, connection,
or agent usage text, using macOS text recognition. Dashboard captures cover app health
and policy configuration. The report attaches individual hook decisions from
the backend API.

Screen capture requires a logged-in desktop on the hosted runner. Missing
windows or failed captures fail the test. Setup/build failures still produce
an HTML report explaining which stage failed. Reports are retained for 14 days.
Credentials and enrollment links are excluded from attachments; network traces
are disabled because they retain authentication headers. The suite refuses
to install or enroll on a developer's Mac or a persistent self-hosted runner.

Dependencies retain their own licenses. Bundled osquery notices are in
`apps/desktop/licenses`; the dashboard includes the Geist font license during
its build. Secret-redaction patterns retain their bundled source license.

## Publishing a release

### Public desktop downloads

The official desktop installers are published at
[OpenAIDR downloads](https://releases.opensecura.ai/openaidr-oss/).
The private `opensecurainc/openaidr-oss-publish` repository owns their build,
signing, verification, and publication procedure. Application source stays in
this repository. Maintainers should follow that repository's current runbook.

Select one full source commit that is merged into this repository's `main`.
Build all platforms from that commit and require the complete native installer
checks to pass. Retain the exact workflow run, attempt, artifact checksums,
source identity, and signing evidence before preparing a publication.

Publish versioned files without replacing existing bytes. Verify their public
HTTPS downloads against the retained checksums before promoting the download
page, release manifest, and fixed-name installer copies. The four README links
use `openaidr-oss/latest/` and stay unchanged between releases. Their targets
must advance together to the verified release.

The download manifest records whether automatic updates are enabled. A download
page or a new `latest/` copy alone does not configure the updater. Existing
manual-only builds need one manual installation of an update-enabled release.
Windows updates require timestamped OpenSecura Authenticode signatures. Linux
in-app updates use the managed AppImage; DEB installations remain managed by
the package manager. Keep update signing keys and release credentials out of
this source repository.

### GitHub packages used by setup.sh

`setup.sh` still selects complete GitHub releases that include the local backend.
This is a separate publication path from the public desktop downloads above.
A GitHub package needs both workflows on the same `main` commit. **Backend** creates
the prerelease with `build.json` and `openaidr-backend.tar.gz`; **App** only
keeps its installers as Actions artifacts. `scripts/publish_app_assets.py`
downloads those artifacts, checks their names, uploads them to the release, and
confirms the SHA-256 digests GitHub records. `setup.sh` installs the newest
release that has `build.json`, the backend archive, and the macOS installer, so
a release is live for Macs as soon as the script finishes.

```sh
gh workflow run Backend --ref main
gh workflow run App --ref main
# After both runs succeed, from a checkout of that commit:
python3 scripts/publish_app_assets.py --dry-run
python3 scripts/publish_app_assets.py
```

Pass `--tag` to publish a different version, `--run` to pick a specific App run,
and `--no-download` to reuse artifacts already under `build/app-assets`.

The release publisher writes `client-release.json` only after all installers and
backend assets for the exact source commit have verified checksums. The manifest
binds the full client and the private cloud exclusion recorded in `PUBLICATION.json`.
Run `scripts/publish_app_assets.py --dry-run` to review the selected artifacts
before publication. Existing assets with different bytes are rejected.
Publishing a GitHub package does not change the public desktop download links
or promote an OSS update feed.

### Publish a Python package to PyPI

The `PyPI` workflow publishes `packages/aidr` and `packages/opensecura`
through PyPI trusted publishing, so no token is stored. Push a tag named
`aidr-v<version>` or `opensecura-v<version>` whose version matches the
`version` in that package's `pyproject.toml`, or run **Actions > PyPI > Run
workflow** and choose the package. The build job checks the tag against the
declared version, builds and checks the distributions, and the publish job
uploads them from the `pypi` environment with an OpenID Connect token.

Each PyPI project lists this repository as its publisher: owner
`opensecurainc`, repository `openaidr`, workflow `pypi.yml`, environment
`pypi`. PyPI rejects a version that was already uploaded, so raise the
version before tagging.
