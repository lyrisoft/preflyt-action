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
        uses: lyrisoft/preflyt-action@v2.1.1
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
      - uses: lyrisoft/preflyt-action@v2.1.1
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
reports, 256 KiB each and 900 KiB per submission; commands have a 285-second limit.
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

The gate prints its current waiting stage when it changes, with a heartbeat every 30 seconds while the same stage remains pending. Stages distinguish completed CI jobs, result submission/verification, GitHub check publication, AI review and AI feedback publication. Older Preflyt servers without stage fields keep the generic waiting label.

Failure logs use local allowlisted reasons or an HTTP status code. Tokens, API bodies, raw exceptions, provider responses and PR text are never printed. Unknown responses and failures remain unconfirmed; the fifteen-minute limit and all gate requirements are preserved.
