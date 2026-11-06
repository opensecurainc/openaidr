# OpenAIDR desktop changelog

Notes for published versions are attached to each
[GitHub release](https://github.com/opensecurainc/openaidr/releases) as
`release-notes.md`. After a release is published, remove its entries from
`Unreleased`.

## Unreleased

- Offer only the Production Intelligence service in the bundled local dashboard connection settings.

- Select the release channel at build time with `OPENAIDR_RELEASE_CHANNEL`, so open-source builds can read their own signed update feed and key instead of the enterprise channel.
- Keep Refresh usage visible when Connected credit details fail to load or become stale.
- Give temporary cloud connection errors 15 seconds to recover after recent successful contact before showing warnings or notifications. Keep persistent failures, credential errors, and exhausted credits visible.

- Review all captured text in each skill with one billed request. Reuse completed unchanged reviews and preserve prior findings and receipts.

- Scroll long agent lists within the setup panel so additional profiles do not stretch the window.

- Recheck cold Posture services briefly and show unavailable services correctly when no assessment can run.

- Add explicit enable/pause controls for automatic Posture checks, account credit balances, and this device's confirmed Posture charges. Show partial skill review coverage and keep unavailable billing explicit.

- Automatically review discovered skill content when cloud assessments are enabled. Reuse unchanged results, show partial review coverage, and retain confirmed credit usage.

- Add an opt-in background package assessment worker for personal connections, with retained findings and credit receipts. Hold uncertain paid requests to avoid duplicate charges.

- Show locally collected AI apps, supply-chain components, and skills in Posture for free and API-key connections, including while the cloud is unavailable. Keep collection status separate from security assessment.

- Add Posture to review this device's reported AI apps, supply-chain components, and skills. Show organization review, assessment findings, and collection gaps separately; search and filter loaded records without changing approvals or agent configuration.

- Add WorkBuddy guardrail setup, tool-call checks, and captured prompt, result, and session activity. WorkBuddy native hook timeouts and process failures can block actions, including in Shadow mode.

- Include usage history from every discovered Codex profile, including profiles sharing a configuration file. Count copied sessions and directory aliases once.

- Discover additional Codex profiles in `~/.codex*` directories with `config.toml`. Show each profile with its own Codex icon, configuration path, and guardrail controls.

- Keep sensor status responsive while usage history is imported or activity is saved. Show unavailable queue counts as N/A while the database is busy.

- Move service credits to Connected for personal and enterprise free and paid plans. Show paid credits used this month and available on one line, keep enterprise dashboard links, and collapse routine sensor details. Remove Last successful contact.
- Accept local usage reports without a telemetry token, including reports from agents holding older credentials. Updating and starting the sensor clears the credential-related restart warning without restarting those agents. Local control endpoints retain authentication.
- Show free credits and the server-provided reset date without a monthly label, supporting the 200-credit weekly allowance.

- Keep Codex hook commands stable across app updates on macOS and Linux. After one restart to migrate existing sessions, launcher updates take effect on the next hook call without changing the command's trust record.

- Install the signed Mac app on Intel Macs as well as Apple Silicon, with macOS 12 (Monterey) or later. The installer is now one universal DMG. Intel installations do not yet receive in-app updates; install a newer DMG to update them.

- Click Would ask or Ask decisions to inspect checks, captured actions, and retained assessments. Free-plan and API-key connections retain details for new ask checks; older checks identify missing evidence.

- Remove the redundant cloud protection banner when cloud guardrails are active. Keep connecting, unavailable, and exhausted notices, with Shadow mode shown in the Guardrails summary.

- Keep Usage compact with a shorter restart reminder and less space around usage warnings. Keep cloud failure details expanded and controls reachable in small windows.

- Label local data deletion after uninstall as "Delete data and move to Trash" in the removal screen and confirmation dialog.

- Keep an explicit Open dashboard link in sensor status details during usage warnings, connection failures, and sensor downtime.

- Sign in automatically when opening a desktop-managed local dashboard, without copying a password.

- Send large organization inventory, skill, activity, and telemetry uploads in smaller requests so they work through proxies with a 1 MiB upload limit. Requires a backend with upload fragment support.

- Recover retained WorkBuddy token usage automatically into the local Usage view when complete input, output, and cache counts are available. Keep costs unknown and count copied or repeated responses once without changing WorkBuddy settings or uploading session history.

- Show WorkBuddy in detected tools and label verified usage records.

- Stop the local dashboard and backend created by the desktop app during macOS uninstall. Delete their containers, database, and saved configuration when Delete local data is selected. Keep separately installed runtimes unchanged.

- Find Docker Desktop's credential helper during local runtime setup when OpenAIDR is opened from Finder or the Dock on macOS.

- Align Back to the right of the organization connection heading.

- Start local runtime setup automatically when selected, including Docker preparation, runtime creation, device connection, and sensor setup. Ask for an existing runtime's password when needed and offer retry if setup fails.

- Show the uninstall result and Move app to Trash action when uninstalling from local runtime setup. Keep incomplete removal errors and retry controls visible.

- Install and start Docker Desktop from local runtime setup on macOS, then continue into dashboard creation and device connection. Keep Docker's license and macOS permission prompts visible, with retry after a cancelled or incomplete setup.

- Recover retained Codex and Claude usage missed after installation or during collection outages. Match request IDs to avoid duplicates, reconcile delayed reports, and retry paused or stopped scans without marking files inaccessible.

- Set up a local runtime and dashboard from organization connection without an enrollment link. Docker with Compose is required; AI checks use the cloud. Setup keeps existing local data and supports retrying interrupted setup.

- Show additional recovered calls, the last history check, and incomplete sources in Usage.

- Recover retained Fable 5.1 cost estimates with its published cache prices. Import history again when a recorded coding-agent profile or bundled history pricing changes, without adding the same calls twice.

- Show when coding-agent usage reports are rejected and explain how to reload connection settings. Hide the restart reminder one minute after successful setup.

- Connect with a new API key without entering a tenant ID. The service records its tenant on first use.

- Show safe failure reasons for unavailable cloud checks in Guardrails activity, including timeouts, missing evidence, and service errors. Older checks remain marked when their reason was not recorded.

- Show monthly free-plan credits used, reserved, and available in Guardrails, with the reset time and last update. Report cloud guardrail availability separately from the sensor connection.

- Reduce Linux installer size by removing debug symbols from the bundled sensor runtime.

- Connect with an OpenSecura API key when free setup reaches its enrollment limit. Keep usage local and run cloud guardrail checks in Shadow mode.

- Finish macOS uninstall when edited or unrecorded Codex and Claude Code telemetry settings still point to OpenAIDR. Preserve other collector endpoints and unrelated settings.

- Start installation immediately when Reinstall is clicked, with progress and retry errors shown in the main window.

- Import local usage history faster on first installation. Show the last 24 hours first, then fill older days from newest to oldest.

- Keep free cloud protection status tied to the service status response so individual failed checks do not make the banner switch between active and inactive. Continue to report service outages, exhausted allowance, and stale status.

- Choose between free setup and organization enrollment. Free setup requires no account, keeps usage local, and runs hosted guardrail checks in Shadow mode. Connect an organization later in Settings.

- Keep successful empty hook responses from being reported as delivery failures when the client closes after receiving the headers.
- Show cleanup stages and elapsed time during macOS local-data deletion, retain safe failure diagnostics, and retry moving to Trash after data is deleted. Clarify that desktop diagnostic logs are kept.

- Keep local data by default on the compact macOS uninstall screen, with a confirmed option to delete managed activity, enrollment, and recovery files before moving the app to Trash.
- Show the recorded decision reason and Guardrail assessment separately, with valid retained risk scores, configured deny thresholds, and the captured user request in the full evidence.
- Focus denied-check reviews on the decision, matched rule or assessment explanation, two-line request preview, and one "This is incorrect" action. Keep notes optional and metadata under Details. Restore activity totals and agent setup when leaving a check.
- Remove the tracking start marker from usage charts. Keep the historical cost note beside Estimated cost.
- Preserve 30-day usage totals and app, model, and reasoning-effort breakdowns when older call details are summarized. Keep at least 24 hours of details for exact rolling totals.
- Show captured commands and request fields in a readable layout, with complete raw requests available.
- Keep denied-check titles and details readable in light and dark mode, including hover and keyboard focus.
- Review retained policy, earlier request context, assessments, and evidence gaps for denied checks. Keep each report bound to the evidence you reviewed when your organization server supports it.
- Keep local usage and estimated costs when changing tenants or reconnecting. Recover retained usage from previous enrollments and run history imports that were skipped after re-enrollment.
- Click the denied-check count to review requests and report incorrect decisions with optional notes.
- Move the historical cost note into an info tooltip beside Estimated cost to keep the usage card compact.
- Show agents that are not detected at the bottom of Agent setup.
- Show cloud guardrail availability without private provider costs or allowance amounts. Keep notices when free protection is exhausted or the service is unavailable.

- Switch between compact Usage and Guardrails pages in the app header. View this device's reported guardrail decisions and manage installation and configuration for seven coding agents.
- Import retained Gemini CLI usage from local JSON and JSONL files. Note that historical cost may be incomplete.
- Automatically show retained Codex and Claude Code usage from the last 30 days after installation. Keep zero totals when no local history is available.
- Show partial Copilot and Cursor hook estimates separately from reported usage, including unknown costs and model assumptions.
- Collect partial token and model-cost estimates from Copilot and Cursor hooks without vendor admin access.
- Fix missed clicks on the update button during background status refreshes.

- Keep long update errors in a scrollable details panel so footer controls remain reachable.
- Keep the usage graph visible with zero totals when the selected period has no recorded usage.
