# PolicyAware 0.4.7 Release Notes

PolicyAware `0.4.7` focuses on lightweight policy-as-code review commands for teams adopting AI governance in local development and CI.

## Highlights

- Added `policyaware policy doctor` for a one-command validation, summary, lint, and readiness rollup.
- Added `policyaware policy checklist` for production-readiness checks covering deny-by-default posture, schema validity, PII/secrets, approval gates, budget controls, MCP/tool coverage, role constraints, and risk constraints.
- Added `policyaware policy normalize` for deterministic YAML ordering and cleaner Git diffs.
- Updated README, docs, and wiki CLI references with copy-paste examples.

## Install

```bash
pip install --upgrade policyaware
```

## Quick Verification

```bash
policyaware init --profile mcp --out mcp-policy.yaml
policyaware policy doctor mcp-policy.yaml
policyaware policy checklist mcp-policy.yaml --json
policyaware policy normalize mcp-policy.yaml --out mcp-policy.normalized.yaml
policyaware policy lint mcp-policy.yaml --fail-on high
```

## Why This Release Matters

These commands help developers and reviewers inspect policy quality without adding heavy dependencies. Teams can use one command for a policy health snapshot, gate risky policy changes in CI, and keep YAML policy diffs readable during GitOps review.
