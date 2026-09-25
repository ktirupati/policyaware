# PolicyAware 0.4.8 Release Notes

PolicyAware `0.4.8` adds a zero-config onboarding demo for the policy doctor workflow.

## Highlights

- Added `policyaware demo doctor` to create a tiny deny-by-default demo policy and immediately run the real policy doctor report.
- The demo policy includes PII redaction, secrets denial, MCP/tool approval gating, token-budget control, role constraints, and risk constraints.
- Added JSON support for the demo output so users can capture first-run evidence in CI logs or docs.
- Updated README, docs, tests, and wiki references with copy-paste demo commands.

## Install

```bash
pip install --upgrade policyaware
```

## Quick Verification

```bash
policyaware demo doctor
policyaware demo doctor --json
policyaware policy checklist .policyaware/demo/policyaware.demo.yaml
policyaware policy normalize .policyaware/demo/policyaware.demo.yaml --out .policyaware/demo/policyaware.demo.normalized.yaml
```

## Why This Release Matters

First-time users can now verify PolicyAware policy-as-code behavior without creating a YAML file by hand. The command is lightweight, local-only, and does not call external services or install optional ML dependencies.
