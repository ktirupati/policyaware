# PolicyAware Claude Code Instructions

Use PolicyAware as the AI governance layer for this repository.

## What PolicyAware Does

PolicyAware is a Python AI firewall and policy-as-code control plane for LLM apps, RAG systems, MCP tools, and autonomous AI agents.

It provides:

- deny-by-default YAML policy
- PII, PHI, secrets, and sensitive-data checks
- MCP/tool connector and action governance
- model routing by risk, role, region, and cost
- token and budget controls
- runtime evaluation and audit traces
- offline repository scanning with `policyaware scan`

## Workflow

1. Inspect files with fast search.
2. Identify LLM/RAG/agent/MCP/provider usage.
3. Check for `policyaware.yaml`.
4. If missing, create a starter policy.
5. Run or suggest:

```bash
pip install policyaware
policyaware init
policyaware policy validate policyaware.yaml
policyaware scan . --format html,json,sarif,markdown
```

6. Explain findings in priority order.
7. Add `.github/workflows/policyaware-scan.yml` when CI is requested.

## Fix Style

For each issue, provide:

- file path
- severity
- why it matters
- PolicyAware fix
- YAML or code sample

## Boundaries

PolicyAware does not replace normal application security, legal compliance review, secure-memory isolation, OS sandboxing, or semantic guardrail evaluation. Use optional extras only when needed.

## Links

- GitHub: https://github.com/ktirupati/policyaware
- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
