# Policy-As-Code For LLMs

PolicyAware lets AI platform teams manage LLM governance as YAML policy files that can be reviewed, tested, scanned, composed, and shipped through GitOps workflows.

This page is for searches like policy-as-code for LLMs, scan GitHub repository for AI security leaks, fail-closed LLM security gateway architecture, and CI validation for AI governance YAML.

## Install

```bash
pip install policyaware
```

## Copy-Paste Baseline Policy

```yaml
name: enterprise-llm-policy
version: 1
default_decision: deny

data_protection:
  redact_pii: true
  redact_phi: true
  redact_secrets: true

regions:
  allowed: ["us", "eu"]

rules:
  - id: allow-public-low-risk
    effect: allow
    when:
      data_sensitivity_in: ["public"]
      risk_in: ["low"]
      role_in: ["employee", "developer", "admin"]

  - id: require-approval-for-regulated
    effect: require_approval
    when:
      domain_in: ["healthcare", "finance", "legal"]

  - id: deny-unapproved-sensitive-export
    effect: deny
    when:
      data_sensitivity_in: ["restricted", "confidential"]
      destination_in: ["external"]
```

## CI Commands

```bash
policyaware policy validate policyaware.yaml
policyaware policy compose-check examples/policy-composition/policy-stack-safe.yaml
policyaware contract check ./src --policy tool-governance.yaml
policyaware scan . --format html,json,sarif,markdown --fail-on high
```

## GitHub Actions Example

```yaml
name: PolicyAware AI Governance Checks

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
        with:
          scan-path: "."
          fail-on: "high"
          output-formats: "html,json,sarif,markdown"
```

## Why Policy-As-Code Matters

| Governance Need | PolicyAware Support |
| --- | --- |
| Review policy changes in PRs | YAML files and GitHub checks |
| Prevent unsafe local overrides | Deny-wins policy composition |
| Catch YAML/tool drift | Contract checks |
| Produce compliance evidence | Audit bundles and scan reports |
| Fail closed on bad policy load | Emergency fallback policies |

## FAQ

### Are YAML policies fixed?

No. Teams can create their own YAML policies, compose global and local layers, and use policy packs as starting points.

### Can a local service override a global deny?

PolicyAware policy composition uses deny-wins behavior. A local allow cannot silently bypass an explicit global deny.

### Should I validate policies before deployment?

Yes. Run `policyaware policy validate`, `policyaware policy compose-check`, `policyaware contract check`, and `policyaware scan` in CI.
