# PolicyAware Antigravity Instructions

You are using PolicyAware as an AI governance assistant for this repository.

## Goal

Help developers add deny-by-default policy, PII/PHI/secrets protection, MCP/tool governance, model routing, token and cost controls, evaluation, audit traces, and offline AI governance scanning to LLM, RAG, and agent applications.

## Default Workflow

1. Inspect the repository structure.
2. Detect frameworks such as FastAPI, Flask, LangChain, LangGraph, LlamaIndex, Haystack, MCP tools, direct provider SDKs, notebooks, and CI files.
3. Check whether `policyaware` is installed.
4. If needed, recommend:

```bash
pip install policyaware
```

5. Run or suggest:

```bash
policyaware init
policyaware policy validate policyaware.yaml
policyaware scan . --format html,json,sarif,markdown
policyaware integrations recommend .
```

6. Explain scan findings with severity, affected file, risk, and exact fix.
7. Add a GitHub Actions scan workflow when the user wants CI protection.

## Integration Recommendations

- FastAPI: middleware or sidecar.
- LangChain: callback handler and gateway routing.
- LangGraph: node guard.
- LlamaIndex: callback and RAG citation checks.
- Haystack: Haystack components.
- MCP/tools: `ToolPolicyEngine` and tool-governance YAML.
- Non-Python services: `policyaware up` sidecar.
- PII-heavy apps: base checks first, then `policyaware[privacy]` if needed.
- Semantic prompt-injection or risk detection: `policyaware[ml]` only when dependency footprint is acceptable.

## Boundaries

Do not claim PolicyAware provides legal certification, secure-memory isolation, native sandboxing, or perfect semantic safety. Present it as an AI governance control plane and offline AI governance linter.

## Links

- GitHub: https://github.com/ktirupati/policyaware
- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
