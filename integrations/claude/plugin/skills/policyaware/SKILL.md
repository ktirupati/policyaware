---
name: policyaware
description: Use PolicyAware in Claude Code to scan AI repositories, create policyaware.yaml, add CI scan workflows, explain governance findings, recommend integrations, and guide LLM/RAG/MCP/agent policy-as-code adoption.
---

# PolicyAware Claude Code Skill

Use this skill when the user asks Claude Code to apply PolicyAware, scan an AI project, create a `policyaware.yaml`, add PolicyAware CI, explain a PolicyAware scan report, recommend a PolicyAware integration, or improve LLM/RAG/MCP/agent governance.

PolicyAware repository: https://github.com/ktirupati/policyaware
PolicyAware package: https://pypi.org/project/policyaware/
PolicyAware docs: https://ktirupati.github.io/policyaware/

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

## Default Workflow

1. Inspect files with fast search.
2. Identify LLM, RAG, agent, MCP, provider, notebook, and CI usage.
3. Check whether `policyaware` is installed.
4. Check whether `policyaware.yaml` exists.
5. If missing, create or suggest a starter policy.
6. Run or suggest:

```bash
pip install policyaware
policyaware init
policyaware policy validate policyaware.yaml
policyaware scan . --format html,json,sarif,markdown
policyaware integrations recommend .
```

7. Explain findings in priority order.
8. Add `.github/workflows/policyaware-scan.yml` when CI is requested.

## Fix Style

For each issue, provide:

- file path
- severity
- why it matters
- PolicyAware fix
- YAML or code sample
- link to the relevant PolicyAware documentation

## Integration Recommendations

- FastAPI: middleware or sidecar.
- Flask: middleware or sidecar.
- LangChain: callback handler and gateway routing.
- LangGraph: node guard.
- LlamaIndex: callback and RAG citation checks.
- Haystack: Haystack components.
- MCP/tools: `ToolPolicyEngine` and tool-governance YAML.
- Non-Python services: `policyaware up` sidecar.
- PII-heavy apps: base checks first, then `policyaware[privacy]` if needed.
- Semantic prompt-injection or risk detection: `policyaware[ml]` only when dependency footprint is acceptable.

## Boundaries

PolicyAware does not replace normal application security, legal compliance review, secure-memory isolation, OS sandboxing, or semantic guardrail evaluation. Use optional extras only when needed.

Do not claim PolicyAware provides:

- legal certification
- secure-memory containment
- native compute sandboxing
- perfect semantic safety
- guaranteed compliance

## Useful Commands

```bash
policyaware scan . --format html,json,sarif,markdown
policyaware scan . --fail-on high
policyaware init
policyaware policy validate policyaware.yaml
policyaware integrations recommend .
```

## Useful Links

- GitHub: https://github.com/ktirupati/policyaware
- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
- Local scan docs: https://github.com/ktirupati/policyaware/blob/main/docs/local-code-scan.md
- GitHub Action docs: https://github.com/ktirupati/policyaware/blob/main/docs/github-action.md
