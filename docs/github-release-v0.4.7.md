# GitHub Release Draft: PolicyAware 0.4.7

Use this as the GitHub Releases body for tag `v0.4.7`.

## PolicyAware 0.4.7

PolicyAware `0.4.7` adds lightweight policy-as-code review commands for governed LLM, RAG, MCP/tool, and AI-agent workflows.

### Highlights

- Added `policyaware policy doctor` for a one-command validation, summary, lint, and readiness rollup.
- Added `policyaware policy checklist` for deny-by-default, schema, PII/secrets, approval, budget, MCP/tool, role, and risk readiness checks.
- Added `policyaware policy normalize` for deterministic YAML ordering and cleaner Git diffs.
- Updated README, docs, and wiki CLI references with copy-paste command examples.

### Install

```bash
pip install --upgrade policyaware
```

### Try The New Commands

```bash
policyaware init --profile mcp --out mcp-policy.yaml
policyaware policy doctor mcp-policy.yaml
policyaware policy doctor mcp-policy.yaml --json
policyaware policy checklist mcp-policy.yaml --fail-on high
policyaware policy normalize mcp-policy.yaml --out mcp-policy.normalized.yaml
```

### Links

- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
- CLI usability: https://github.com/ktirupati/policyaware/blob/main/docs/cli-usability.md
- GitHub Wiki: https://github.com/ktirupati/policyaware/wiki

### Notes

PolicyAware remains lightweight by default with `pip install policyaware`. Optional stacks such as Presidio, Transformers/Torch, NeMo Guardrails, Guardrails AI, Haystack, and cloud provider helpers should be installed only when the target service needs them.
