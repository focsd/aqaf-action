# AQAF architecture review — GitHub Action

A composite GitHub Action that runs a local, offline, **heuristic** AQAF architecture scan on your repository and writes a JSON report. It bundles the AQAF engine and its data-only profile registry (the same engine as the `aqaf` package on PyPI, npm and Homebrew), makes no network requests and never executes your code. The quality index is a provisional heuristic, not a security or compliance certification.

The action's version is the AQAF version it bundles. It is not listed on the GitHub Marketplace; use it by repository and tag. Pin a tag or, better, a full commit SHA.

## Use

```yaml
name: AQAF Review
on: [pull_request]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: focsd/aqaf-action@v1.1.3   # pin a tag or a full commit SHA
        with:
          output: aqaf-report.json
```

To fail a job only on findings that are *new* compared with a saved baseline report:

```yaml
      - uses: focsd/aqaf-action@v1.1.3
        with:
          baseline: aqaf-baseline.json
          fail-on: new-high        # or new-medium; requires a baseline
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `output` | `aqaf-report.json` | Report path, relative to the workspace |
| `profile` | `auto` | Explicit AQAF profile, or `auto` |
| `pack` | `auto` | `web`, `mobile`, `systems`, `automation` or `auto` |
| `baseline` | empty | Baseline report (JSON), relative to the workspace |
| `fail-on` | `off` | `off`, `new-high` or `new-medium`; the latter two require `baseline` |
| `gitignore` | `true` | Respect root and nested `.gitignore` patterns; `false` opts out |
| `review-signals` | `false` | Experimental unscored multi-language source observations |

The output `report` is the path of the generated JSON report. Inputs are validated or passed as literal arguments and are never evaluated by the shell.

## Requirements and limits

- A Linux or macOS runner with `bash` and Python 3.9+ available as `python3` (GitHub-hosted `ubuntu-latest` and `macos-latest` runners have it). Windows runners are not covered: the step is bash and expects `python3` on `PATH`.
- The action installs no dependencies and uploads no artifacts; use `actions/upload-artifact` yourself if you want the report kept. GitHub SARIF upload has separate feature entitlements.
- Findings are heuristic observations to review, not verdicts. See the AQAF documentation for coverage by profile.

## Using the code locally

Copy this directory to `.github/actions/aqaf` in your repository and use `uses: ./.github/actions/aqaf` after checkout.

## Provenance

This repository is generated from the AQAF release builder, which checks the bundle against an allowlist (only the action, its README, the launcher and the engine), verifies that the bundled engine is byte-identical to the canonical one, and runs the action's step in tests and on hosted runners. The `aqaf/` folder is a snapshot: do not edit it here.

Marketplace rules, if you want to list your own fork: https://docs.github.com/en/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace
