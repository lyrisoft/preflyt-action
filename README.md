# Preflyt policy check

Connect one PR workflow to your published Preflyt branch policy. GitHub runs your
checks; Preflyt verifies the completed jobs, evaluates the exact commit, performs
configured advisory AI reviews and publishes the results on the PR. The final job
waits for verification and publication before the workflow can pass.

No Preflyt API key, manual report upload or separate publication workflow is needed.
Authentication uses short-lived GitHub Actions OIDC tokens. The Action supports
same-repository, non-draft pull requests on Linux runners with Python 3, Git and Docker.

Version **v2.1.1** uses the policy-only execution contract. Upgrading from v1.1.0
requires removing the old `checks` input.

## Existing workflow

Copy the generated YAML from your policy or standard. Keep dependency installation
in the check job. Configure project and custom check commands in Standards. Use one policy step per workflow.
Make the final gate depend on every check job, including matrix and reusable jobs.
It must be terminal: do not put additional jobs after it.

```yaml
name: CI
on:
  pull_request:
    branches: [development]
permissions:
  contents: read
jobs:
  checks:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v7
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      # Keep your project dependency installation here.
      - name: Preflyt policy
        if: ${{ always() && !cancelled() && github.event.pull_request.head.repo.full_name == github.repository }}
        uses: lyrisoft/preflyt-action@6a9348428e8c0a71f7d2ae465166ab8fb0909774
        with:
          api-url: ${{ vars.PREFLYT_API_URL }}
  preflyt_gate:
    name: Preflyt final gate
    needs: [checks]
    if: ${{ always() && !cancelled() && github.event.pull_request.head.repo.full_name == github.repository }}
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: lyrisoft/preflyt-action@6a9348428e8c0a71f7d2ae465166ab8fb0909774
        with:
          mode: gate
          api-url: ${{ vars.PREFLYT_API_URL }}
```

The workflow has no check list or report mappings. Each run fetches the latest
published policy for the PR target branch and executes that revision's commands.
Adding a standard or changing a check takes effect after publishing a new policy
revision. Editing an unpublished standard cannot alter an approved policy.

Built-in security recipes provision **Semgrep**, **Gitleaks** and **Trivy** using
reviewed image digests. Scans mount source read-only, receive no GitHub/OIDC
credentials or Docker socket, and suppress raw logs. Gitleaks has no network;
Semgrep and Trivy use the network for rules and vulnerability databases. Set
`CONTAINER_IMAGE` in the job for a built container image scan.

Project build, type checking, tests and lint reuse dependencies installed before
Preflyt. Custom commands require their tools in that job. Configure the command
and genuine JUnit/SARIF result path in Standards once, then publish the policy.
Unknown controls, missing tools, absent/empty reports and timed-out commands stay
incomplete. No check can reuse an earlier successful report. Limits remain 10
reports, 256 KiB per regular report and 900,000 bytes per submission; commands have a 285-second limit.
Optional `proofs` associate existing signed bundles with report paths. Pin both
Action steps to the same tested immutable commit.

Upgrade the one existing integration by removing `with.checks` and updating both
Action pins. Explicit mappings and report-only execution are no longer supported.

## Gate behavior

Built-in SAST uses **Preflyt SAST v1**, an MIT-licensed set of 18 owned,
review-oriented rules with a checked SHA-256 digest, executed by pinned Semgrep
1.179.0. It checks specific JavaScript/TypeScript, Python and shell patterns;
it does not provide exhaustive, interfile or full Semgrep registry coverage.
The real scanner tests include a vulnerable example of every rule and safe cases.
The scanner container is offline and never downloads registry rules. See
`rules/sast-v1.yaml` for the exact checks and two narrowly documented fixture
exceptions. Configure a custom SARIF command for a separately licensed scanner.

Keep the display name **Preflyt final gate**. Preflyt verifies every other job in
the exact run attempt directly with GitHub and waits while another job is active.
Skipped conditional jobs are allowed; missing, cancelled or failed check execution
cannot establish a passing result. The workflow fails when required checks fail,
verification is incomplete, AI execution is unavailable, or PR publishing fails.
AI findings remain advisory and cannot override deterministic checks.

Check mode completes after genuine reports are submitted, even when a check fails
or is incomplete. This separates successful report collection from policy approval
and lets Preflyt verify each report independently. Always require **Preflyt final
gate** in branch protection; that job fails for failed or incomplete required checks.
Transport and execution infrastructure errors still fail the check job.

Gate mode defaults to the current run and attempt. It polls for up to 15 minutes,
refreshing its OIDC token on each request. `source-run` and `source-attempt`, if
supplied, must refer to this same run/attempt. Forks and merge queues are not supported.

Delete the old `.github/workflows/preflyt-gate.yml` from the branch running this
workflow when upgrading. Setup PRs include that deletion automatically. No file
needs to be installed on the repository default branch.

The Action is MIT licensed; the Preflyt application has a separate license.

### Gate progress and safe diagnostics

Policy fetch and result submission failures also report safe categories:
`API_HTTP_<status>`, `API_TIMEOUT`, `API_UNAVAILABLE`,
`TRANSPORT_INVALID_RESPONSE`, or `TRANSPORT_UNCONFIRMED`. These retain the
nonzero exit status without printing tokens, URLs, API bodies or report content.

The gate prints its current waiting stage when it changes, with a heartbeat every 30 seconds while the same stage remains pending. Stages distinguish completed CI jobs, result submission/verification, GitHub check publication, AI review and AI feedback publication. Older Preflyt servers without stage fields keep the generic waiting label.

Failure logs use local allowlisted reasons or an HTTP status code. Tokens, API bodies, raw exceptions, provider responses and PR text are never printed. Unknown responses and failures remain unconfirmed; the fifteen-minute limit and all gate requirements are preserved.

## Optional same-run coverage (unreleased)

This change requires the companion Preflyt API update. It does not add a policy
check, coverage threshold or second test execution. Enable your framework's
coverage provider in the existing policy test command so it emits fresh LCOV.
Pin both check/gate steps to the same released immutable commit before use;
published v2.1.1 does not support these inputs.

```yaml
# On the existing policy step, after upgrading its Action pin:
env:
  PREFLYT_COLLECT_COVERAGE: 'true' # Preflyt repository's Vitest opt-in
with:
  api-url: ${{ vars.PREFLYT_API_URL }}
  coverage-reports: '[{"path":"apps/web/coverage/lcov.info","prefix":"apps/web"}]'
  # Optional LCOV artifact from a parallel job in this run/attempt:
  coverage-artifact: api-coverage-${{ github.run_id }}-${{ github.run_attempt }}
```

`coverage-reports` is a JSON array of objects with exactly `path` and `prefix`.
Paths stay inside the checkout, must be fresh from this execution, and package
prefixes disambiguate API/web source. Empty LCOV, incomplete records, inconsistent
LF/LH/DA counters, unsafe paths and stale files fail attachment. Zero-line files
contribute no measured lines. Repeated physical lines are unioned once. Coverage
uses the configured source scope; include untested files in the test framework
configuration when that is the intended denominator.

`coverage-artifact` requires job permission `actions: read` and uses `github-token`
(default `github.token`) only for read-only artifact lookup and the pinned official
GitHub download action. The token is not added to the policy command environment.
Lookup is bounded to 120 seconds. The artifact must contain `lcov.info` and
`metadata.json` with version 1, repositoryId/runId strings, numeric runAttempt,
sourceSha equal to the PR head, prefix, and sha256 of the original LCOV bytes.
Only the current run's artifact is accepted; the manifest also binds the attempt.
Never restore test reports or this artifact from caches. Producer test jobs must
remain prerequisites of the final gate.

Attachment runs only after a passing policy execution. It appends optional
`tests.coverage` with deterministic gzip/base64 content and SHA-256 over the
decoded canonical LCOV; original policy results remain unchanged. Bounds are
8 MiB per raw input, 2 MiB merged/decoded LCOV, 256 KiB compressed, 10 reports and
900,000 bytes per submission. Missing requested artifacts, mismatched context or
excess limits fail the check job rather than silently reporting partial coverage.
No source file bodies are attached; LCOV includes paths and measured counters.

Health projects the exact assessed commit after the server verifies the GitHub
workflow execution and original report digest. A different merge/squash SHA never
inherits this percentage. Explicit organization-key deployments still require
a valid report signature; unsigned automatic coverage cannot satisfy that mode.
The existing `proofs` mapping continues to apply to regular policy reports.
