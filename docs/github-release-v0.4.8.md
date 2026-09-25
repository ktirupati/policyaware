# GitHub Release Draft: PolicyAware 0.4.8

Use this as the GitHub Releases body for tag `v0.4.8`.

## PolicyAware 0.4.8

PolicyAware `0.4.8` adds a zero-config onboarding demo for the policy doctor workflow.

### Highlights

- Added `policyaware demo doctor` to create a tiny deny-by-default demo policy and immediately run the real policy doctor report.
- The demo policy covers PII redaction, secrets denial, MCP/tool approval gating, token-budget control, role constraints, and risk constraints.
- Added `--json`, `--out`, and `--force` options for screenshots, CI logs, and repeatable local demos.
- Updated README, docs, tests, and wiki references with copy-paste demo commands.

### Install

```bash
pip install --upgrade policyaware
```

### Try The New Demo

```bash
policyaware demo doctor
policyaware demo doctor --json
policyaware policy checklist .policyaware/demo/policyaware.demo.yaml
policyaware policy normalize .policyaware/demo/policyaware.demo.yaml --out .policyaware/demo/policyaware.demo.normalized.yaml
```

### Links

- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
- CLI usability: https://github.com/ktirupati/policyaware/blob/main/docs/cli-usability.md
- GitHub Wiki: https://github.com/ktirupati/policyaware/wiki

### Notes

PolicyAware remains lightweight by default with `pip install policyaware`. The new demo is local-only and does not call external services or require optional ML, privacy, provider, dashboard, or guardrails extras.
