# Contributing

Bug reports and fixes to the desktop, sensor, hooks, policy engine, server, and
dashboard improve the implementation OpenSecura ships. Include the build
version, operating system, reproduction steps, and expected and actual
behavior. Remove credentials, prompts, and private files from reports.

This repository is the complete OpenAIDR client, published from OpenSecura's
development repository. `PUBLICATION.json` records the source commit of the
current publication. Make fixes in this checkout and include a focused
regression test; maintainers carry accepted changes into the next publication
so they are not lost.

The shared helper package `openaidr-common`, which holds the policy pattern
compiler, credential redaction, and the event vocabulary, is Apache 2.0 source
under `packages/common/`. Install it editable, in the order the
[development guide](docs/guide.md#contribute-and-test) shows, so changes there
take effect without rebuilding a wheel. The Intelligence service that produces
model-backed decisions is private; its Python SDK wheel is vendored under
`dependencies/api-runtime/` and is installed from there. Tests that need the
service itself are skipped at collection when its wheel is absent, so `pytest`
passes on a plain checkout and reports fewer tests than the upstream run. See
the [open source plan](docs/open-source-plan.md).

Run the relevant checks in the [development guide](docs/guide.md#contribute-and-test).

Before publication, run `python scripts/verify_public_dependencies.py` and
`python scripts/check_publication.py`. The latter checks source and nested
tar/zip/wheel contents for known private implementations, provider settings,
and promotion records. It permits shared migrations, API types, SDK validation,
and provider behavior tests. These checks cover the current distribution, not
Git history or a complete secret audit. Rebuild the pinned runtime with
`scripts/bundle_local_runtime.py` after changing its source snapshot, and update
the source commit, timestamp, and archive checksum together.

Use the same Apache 2.0 license for contributions. Do not add signing keys,
hosted deployment infrastructure, proprietary dependencies, or real customer
fixtures. Do not add GitHub Actions workflows without maintainer direction.

## Claude code review

A maintainer with write access can request a review by posting a new pull
request comment that starts with `@claude review`. Pushes do not start reviews.
The `Review: Run Claude` workflow posts inline findings and a tracking comment
with the reviewed commit SHA and an `OK` or `NOT OK` verdict. Reviews are advisory
and do not replace tests or maintainer approval.

Before using the workflow, merge `.github/workflows/claude-review.yml` into
`main` and configure the `CLAUDE_CODE_OAUTH_TOKEN` Actions secret for this
repository. Generate a token with `claude setup-token`, then add it through
GitHub repository settings or this interactive command:

```sh
gh secret set CLAUDE_CODE_OAUTH_TOKEN --repo opensecurainc/openaidr
```

Do not put the token in source files, comments, or pull requests.
