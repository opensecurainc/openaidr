# OpenAIDR desktop changelog

Notes for published versions are attached to each
[GitHub release](https://github.com/opensecurainc/openaidr/releases) as
`release-notes.md`. After a release is published, remove its entries from
`Unreleased`.

## Unreleased

- Connect a free installation to a Google account through the system browser. Sign-in preserves local history and shares the account's weekly credits across devices.
- Distinguish one-time starter credits from a Google account's weekly free allowance. Show the account and reset date when connected.
- Offer only the Production Intelligence service in the bundled local dashboard connection settings.
- Select the release channel at build time with `OPENAIDR_RELEASE_CHANNEL`, so open-source builds can read their own signed update feed and key instead of the enterprise channel.
