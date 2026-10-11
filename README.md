# Preflyt policy check

Connect one PR workflow to your published Preflyt branch policy. GitHub runs your
checks; Preflyt verifies the completed jobs, evaluates the exact commit, performs
configured advisory AI reviews and publishes the results on the PR. The final job
waits for verification and publication before the workflow can pass.

No Preflyt API key, manual report upload or separate publication workflow is needed.
Authentication uses short-lived GitHub Actions OIDC tokens. The Action supports
same-repository, non-draft pull requests on Linux runners with Python 3 and Git.

## Existing workflow

Copy the generated YAML from your policy or standard. Keep dependency installation
and report-producing steps in the check job. Use one policy step per workflow.
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
      # Keep your dependency installation and actual check/report steps here.
      - name: Preflyt policy
        if: ${{ always() && !cancelled() && github.event.pull_request.head.repo.full_name == github.repository }}
        uses: lyrisoft/preflyt-action@v1.1.0
        with:
          api-url: ${{ vars.PREFLYT_API_URL }}
          checks: |
            {"tests.required":{"report":"reports/tests.xml"}}
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
      - uses: lyrisoft/preflyt-action@v1.1.0
        with:
          mode: gate
          api-url: ${{ vars.PREFLYT_API_URL }}
```

Replace the report configuration with the generated policy IDs and paths.
`checks` accepts inline JSON or a repository JSON file. An optional `argv` array
runs a real check command; built-in recipes use `preflyt-recipe` as the executable.
Optional `proofs` can associate existing signed reports; signatures are not required
for normal GitHub job verification. Pin both Action steps to the same immutable
release SHA in production.

## Gate behavior

Keep the display name **Preflyt final gate**. Preflyt verifies every other job in
the exact run attempt directly with GitHub and waits while another job is active.
Skipped conditional jobs are allowed; missing, cancelled or failed check execution
cannot establish a passing result. The workflow fails when required checks fail,
verification is incomplete, AI execution is unavailable, or PR publishing fails.
AI findings remain advisory and cannot override deterministic checks.

Gate mode defaults to the current run and attempt. It polls for up to 15 minutes,
refreshing its OIDC token on each request. `source-run` and `source-attempt`, if
supplied, must refer to this same run/attempt. Forks and merge queues are not supported.

Delete the old `.github/workflows/preflyt-gate.yml` from the branch running this
workflow when upgrading. Setup PRs include that deletion automatically. No file
needs to be installed on the repository default branch.

The Action is MIT licensed; the Preflyt application has a separate license.
