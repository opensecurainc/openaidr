# Repository instructions

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for contribution requirements.

## Pull request review

1. After creating a PR or pushing new commits to its branch, post a new PR
   comment containing only `@claude review`. Pushes alone do not trigger the review.
2. Wait for the review to finish. Check that the tracking comment's reviewed
   commit SHA matches the latest PR commit, and read all inline findings.
3. Fix actionable findings and run the relevant checks. If a finding does not
   warrant a change, reply with concrete reasoning.
4. Push the fixes and post a new `@claude review` comment. Repeat until the latest
   commit has been reviewed and all actionable findings have been addressed.
5. If the review cannot run or a finding remains unresolved, report the blocker
   and the remaining work. Do not report the PR as ready before this review
   process is complete.
