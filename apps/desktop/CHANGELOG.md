# OpenAIDR desktop changelog

Notes for published versions are attached to each
[GitHub release](https://github.com/opensecurainc/openaidr/releases) as
`release-notes.md`. After a release is published, remove its entries from
`Unreleased`.

## Unreleased

- Enable signed OSS update builds to check their own update feed. Existing builds without update support need one manual installation of an update-enabled release.
- Reduce background CPU use when maintaining large local usage histories and checking retained agent history.
- Connect a free installation to a Google account through the system browser. Sign-in preserves local history and shares the account's weekly credits across devices.
- Distinguish one-time starter credits from a Google account's weekly free allowance. Show the account and reset date when connected.
- Fix WorkBuddy on Windows blocking every prompt and tool call with `spawn pwsh ENOENT` when PowerShell 7 is not installed. WorkBuddy guardrails now run in Git Bash or Windows PowerShell. If WorkBuddy cannot start either shell, OpenAIDR leaves WorkBuddy without guardrails instead of blocking it. Restart WorkBuddy after OpenAIDR updates its guardrails.
- Add a Network proxy setting to the sensor status and Settings so the OpenAIDR sensor and app updates can reach your organization through an HTTP or HTTPS proxy.
- Add an enterprise desktop edition that requires organization enrollment and omits free, personal API-key, and local runtime setup. Existing personal data is kept when switching editions.
- Open fresh setup without an extra Reinstall click after uninstalling with all local data deleted on macOS.
- Remove the redundant "This device" label beside the Guardrails heading.
- Make all Posture pages more compact with shorter copy, tighter rows, inline asset metadata, and expandable collection details. Partial inventory counts remain visible.
- Offer only the Production Intelligence service in the bundled local dashboard connection settings.
- Select the release channel at build time with `OPENAIDR_RELEASE_CHANNEL`, so open-source builds can read their own signed update feed and key instead of the enterprise channel.
