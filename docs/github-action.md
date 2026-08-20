# Official PolicyAware GitHub Action

`ktirupati/policyaware-action` is the official GitHub Actions integration for
PolicyAware policy CI/CD.

Use it when you want GitHub-native pull-request checks for local code scanning,
governance findings, GitHub annotations, SARIF output, and report artifacts
without writing a full workflow by hand.

The action turns `policyaware scan` into an offline AI governance linter. It can block pull requests that introduce unvetted LLM provider calls, unmapped MCP tools, missing PII protection, missing token budgets, weak audit coverage, or policy YAML mistakes before the application is deployed.

Repository: <https://github.com/ktirupati/policyaware-action>

## Recommended PR Gate

Copy `docs/ci/policyaware-scan-github-actions.yml` into your repository's
`.github/workflows/` folder, or start with this minimal workflow:

```yaml
name: PolicyAware Governance

on:
  pull_request:
  push:
    branches: [main]

jobs:
  policyaware:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ktirupati/policyaware-action@v1
```

Check the action README for the current optional inputs supported by the
published action release.

## What The Action Handles

The official action is a thin, GitHub-native adapter around the PolicyAware CLI.
It is designed to:

- install a tested PolicyAware release
- run `policyaware scan`
- surface findings as GitHub annotations
- upload HTML, JSON, Markdown, or SARIF report artifacts when configured
- make governance findings visible during pull-request review

Scanner behavior, rules, report schemas, baselines, and configuration remain
owned by the PolicyAware Python package. The action has an independent release
lifecycle and verifies a published PolicyAware package before advancing its
tested default.

## Advanced Policy CI/CD Workflow

For larger teams, combine the official action with explicit CLI validation for
policy-as-code, policy composition, contract checks, and deployment packaging:

Copy `docs/ci/policyaware-policy-cicd.yml` into `.github/workflows/`, or use
the pattern below:

```yaml
name: PolicyAware Policy CI

on:
  pull_request:

jobs:
  policy-cicd:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install PolicyAware
        run: python -m pip install policyaware
      - name: Validate local policy
        run: policyaware policy validate policyaware.yaml
      - name: Check hierarchical policy stack
        run: policyaware policy compose-check policy-stack.yaml
      - name: Compile policy bundle
        run: policyaware policy compose policy-stack.yaml --out policyaware.composed.yaml
      - name: Check tool-policy contract drift
        run: policyaware contract check ./src --policy tool-governance.yaml --fail-on high
      - name: Scan repository
        run: policyaware scan ./src --format html,json,sarif,markdown --fail-on high
```

This pattern catches YAML syntax mistakes, hierarchical policy conflicts,
tool/action drift, hardcoded sensitive data, missing governance wrappers, and
scan findings before they reach production.

## Why This Matters

Many AI safety and gateway tools only run at application runtime. That is useful, but it means teams may discover policy gaps only after an application path is live.

PolicyAware adds a pre-deployment control: repository scanning. A pull request can fail before it introduces a new autonomous tool, direct model call, hardcoded prompt, plaintext secret, missing budget, or unreviewed policy change.

## Which CI Option Should I Use?

| Need | Recommended Path |
| --- | --- |
| Quick GitHub PR scan | Use `ktirupati/policyaware-action@v1`. |
| Full policy-as-code validation | Use CLI commands such as `policyaware policy validate` and `policyaware policy compose-check`. |
| YAML/tool signature drift detection | Use `policyaware contract check`. |
| Central policy publishing to S3, GCS, ADLS, or HTTP storage | Compose and validate with the CLI, then upload with your cloud deployment tooling. |
| GitHub code scanning integration | Emit SARIF from the action or from `policyaware scan --format sarif`. |

## Release Order

1. Test and publish PolicyAware to PyPI.
2. Verify the installed CLI from PyPI.
3. Update and test `policyaware-action` against that exact release.
4. Publish the action and Marketplace release.

The PolicyAware package never depends on or publishes the action.
