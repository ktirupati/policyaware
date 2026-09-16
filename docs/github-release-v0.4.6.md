# GitHub Release Draft: PolicyAware 0.4.6

Use this as the GitHub Releases body for tag `v0.4.6`.

## PolicyAware 0.4.6

PolicyAware `0.4.6` adds lightweight CLI ergonomics for AI policy-as-code, MCP governance, PII protection, and developer onboarding.

### Highlights

- Added `policyaware init --profile mcp|rag|pii|agent` for focused deny-by-default starter policies.
- Added `policyaware policy summarize` for audit-friendly policy summaries.
- Added `policyaware policy lint` for lightweight design warnings beyond schema validation.
- Added `policyaware policy diff` for GitOps policy review and CI checks.
- Added `policyaware protect inspect` for sensitive-data category checks without redaction.
- Added `policyaware protect redact` for deterministic PII/PHI/secret redaction previews.
- Added `policyaware examples copy` for copying runnable examples into local projects.
- Updated README, docs, and wiki CLI references with copy-paste command examples.

### Install

```bash
pip install --upgrade policyaware
```

### Try The New Commands

```bash
policyaware init --profile mcp --out mcp-policy.yaml
policyaware policy validate mcp-policy.yaml
policyaware policy summarize mcp-policy.yaml
policyaware policy lint mcp-policy.yaml
policyaware policy diff old-policy.yaml new-policy.yaml --fail-on-relaxed
policyaware protect inspect "Email jane@example.com" --json
policyaware protect redact "Email jane@example.com"
policyaware examples copy mcp-policy-proxy-demo ./policyaware-mcp-demo
```

### Links

- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
- CLI usability: https://github.com/ktirupati/policyaware/blob/main/docs/cli-usability.md
- MCP policy proxy demo: https://github.com/ktirupati/policyaware/tree/main/examples/mcp-policy-proxy-demo

### Notes

PolicyAware remains lightweight by default with `pip install policyaware`. Optional stacks such as Presidio, Transformers/Torch, NeMo Guardrails, Guardrails AI, Haystack, and cloud provider helpers should be installed only when the target service needs them.
